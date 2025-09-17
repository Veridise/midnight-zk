use std::collections::HashMap;

use ff::Field;
use midnight_circuits::{
    compact_std_lib::{Relation, ZkStdLib, ZkStdLibArch},
    instructions::*,
    types::Instantiable,
};
use midnight_curves::JubjubExtended;
use midnight_proofs::{
    circuit::{Layouter, Value},
    plonk::Error,
};

use crate::{
    instructions::Instruction as I,
    types::{
        get_bit, get_byte, get_bytes, get_jubjub_point, get_jubjub_scalar, get_native, parse_bit,
        parse_byte, parse_bytes, parse_native, type_of, CircuitType, OffCircuitType, ValType,
    },
    IrSource,
};

type F = midnight_curves::Fq;

type AssignedBit = midnight_circuits::types::AssignedBit<F>;
type AssignedByte = midnight_circuits::types::AssignedByte<F>;
type AssignedNative = midnight_circuits::types::AssignedNative<F>;
type AssignedJubjubPoint = midnight_circuits::types::AssignedNativePoint<JubjubExtended>;
type AssignedJubjubScalar = midnight_circuits::types::ScalarVar<JubjubExtended>;

pub(crate) struct Parser<'a> {
    std_lib: &'a ZkStdLib,
    memory: HashMap<String, CircuitType>,
}

impl<'a> Parser<'a> {
    fn new(std_lib: &'a ZkStdLib) -> Self {
        Self {
            std_lib,
            memory: HashMap::new(),
        }
    }

    pub fn insert(&mut self, name: &str, value: &CircuitType) -> Result<(), Error> {
        self.memory.insert(name.to_owned(), value.clone()).map_or(Ok(()), |_| {
            Err(Error::SynthesisWithMsg(format!(
                "variable {} already exists",
                name
            )))
        })
    }

    pub fn insert_many(&mut self, names: &[String], values: &[CircuitType]) -> Result<(), Error> {
        if names.len() != values.len() {
            return Err(Error::Synthesis);
        }
        (names.iter().zip(values.iter())).try_for_each(|(name, value)| self.insert(name, value))
    }

    pub fn get(&self, name: &String) -> Option<CircuitType> {
        self.memory.get(name).cloned()
    }

    /// Returns the type of the variables associated with the given names.
    /// Names that do not appear in memory (supposedly corresponding to
    /// hard-coded constants) are skipped.
    ///
    /// Results in an error if non-skipped names have inconsistent types or if
    /// all of them are skipped (thus no type can be inferred).
    pub fn infer_type(&self, names: &[String]) -> Result<ValType, Error> {
        let mut inferred_type = None;
        for name in names.iter() {
            if let Some(v) = self.get(name) {
                let t = inferred_type.get_or_insert_with(|| type_of(&v));
                if &type_of(&v) != t {
                    return Err(Error::Synthesis);
                }
            }
        }
        inferred_type.ok_or(Error::SynthesisWithMsg(format!(
            "type {:?} not be inferred",
            names
        )))
    }

    /// Parses the given name as a constant of the given type and assigns it
    /// in-circuit as a fixed value.
    pub fn assign_constant(
        &mut self,
        layouter: &mut impl Layouter<F>,
        val_t: ValType,
        name: &str,
    ) -> Result<(), Error> {
        match val_t {
            ValType::Bit => {
                let bit_val = parse_bit(name).ok_or(Error::Synthesis)?;
                let bit = self.std_lib.assign_fixed(layouter, bit_val)?;
                self.insert(name, &CircuitType::Bit(bit))
            }
            ValType::Byte => {
                let byte_val = parse_byte(name).ok_or(Error::Synthesis)?;
                let byte = self.std_lib.assign_fixed(layouter, byte_val)?;
                self.insert(name, &CircuitType::Byte(byte))
            }
            ValType::Bytes(n) => {
                let byte_vals = parse_bytes(name).ok_or(Error::Synthesis)?;
                let bytes = self.std_lib.assign_many_fixed(layouter, &byte_vals)?;
                if bytes.len() != n {
                    return Err(Error::SynthesisWithMsg(format!(
                        "expected {} bytes, {} given",
                        n,
                        bytes.len()
                    )));
                }
                self.insert(name, &CircuitType::Bytes(bytes))
            }
            ValType::Native => {
                let x_val = parse_native(name).ok_or(Error::Synthesis)?;
                let x = self.std_lib.assign_fixed(layouter, x_val)?;
                self.insert(name, &CircuitType::Native(x))
            }
            ValType::JubjubPoint => todo!(),
            ValType::JubjubScalar => todo!(),
        }
    }

    /// Takes a list of names and parses those that are do not appear in the
    /// memory as constants of the given type. It assigns them in-circuit as
    /// fixed values.
    pub fn assign_constants(
        &mut self,
        layouter: &mut impl Layouter<F>,
        val_t: ValType,
        names: &[String],
    ) -> Result<(), Error> {
        for name in names.iter() {
            if self.get(name).is_none() {
                self.assign_constant(layouter, val_t, name)?;
            }
        }
        Ok(())
    }
}

impl Relation for IrSource {
    type Instance = Vec<OffCircuitType>;

    type Witness = HashMap<String, OffCircuitType>;

    fn format_instance(instance: &Self::Instance) -> Vec<F> {
        instance
            .iter()
            .flat_map(|x| match x {
                OffCircuitType::Bit(b) => AssignedBit::as_public_input(b),
                OffCircuitType::Byte(b) => AssignedByte::as_public_input(b),
                OffCircuitType::Bytes(v) => {
                    v.iter().flat_map(AssignedByte::as_public_input).collect()
                }
                OffCircuitType::Native(x) => AssignedNative::as_public_input(x),
                OffCircuitType::JubjubPoint(p) => AssignedJubjubPoint::as_public_input(p),
                OffCircuitType::JubjubScalar(s) => AssignedJubjubScalar::as_public_input(s),
            })
            .collect()
    }

    fn circuit(
        &self,
        std_lib: &ZkStdLib,
        layouter: &mut impl Layouter<F>,
        _instance: Value<Self::Instance>,
        witness: Value<Self::Witness>,
    ) -> Result<(), Error> {
        let parser = &mut Parser::new(std_lib);

        for instruction in self.instructions.iter() {
            match instruction {
                I::Load { val_t, names } => load(parser, layouter, val_t, names, &witness),
                I::AssertEqual { vals } => assert_equal(parser, layouter, vals),
                I::IsEqual { vals, output } => is_equal(parser, layouter, vals, output),
                I::Add { vals, output } => add(parser, layouter, vals, output),
                I::Mul { vals, output } => mul(parser, layouter, vals, output),
                I::Neg { val, output } => neg(parser, layouter, val, output),
                I::Not { val, output } => not(parser, layouter, val, output),
                I::Msm {
                    bases,
                    scalars,
                    output,
                } => msm(parser, layouter, bases, scalars, output),
                I::Select { cond, vals, output } => select(parser, layouter, cond, vals, output),
                I::FromBytes {
                    val_t,
                    bytes,
                    output,
                } => from_bytes(parser, layouter, val_t, bytes, output),
            }?
            // I::Assert { cond } => {
            //     std.assert_equal_to_fixed(layouter, get(&memory, *cond)?,
            // F::ONE)? }
            // I::CondSelect { bit, a, b } => {
            //     let bit: AssignedBit<F> = std.convert(layouter, get(&memory,
            // *bit)?)?;     let result =
            //         std.select(layouter, &bit, get(&memory, *a)?,
            // get(&memory, *b)?)?;     memory.push(result);
            // }
            // I::CondSwap { bit, a, b } => {
            //     let bit: AssignedBit<F> = std.convert(layouter, get(&memory,
            // *bit)?)?;     let (fst, snd) =
            //         std.cond_swap(layouter, &bit, get(&memory, *a)?,
            // get(&memory, *b)?)?;     memory.push(fst);
            //     memory.push(snd);
            // }
            // I::ConstrainBits { var, bits } => std.assert_lower_than_fixed(
            //     layouter,
            //     get(&memory, *var)?,
            //     &(BigUint::from(1u64) << bits),
            // )?,
            // I::ConstrainEq { a, b } => {
            //     std.assert_equal(layouter, get(&memory, *a)?, get(&memory,
            // *b)?)? }
            // I::ConstrainToBoolean { var } => {
            //     let _: AssignedBit<F> = std.convert(layouter, get(&memory,
            // *var)?)?; }
            // I::ConstrainToBooleanMany { vars } => {
            //     let mut variables = Vec::with_capacity(vars.len());
            //     for v in vars.iter() {
            //         variables.push(get(&memory, *v)?.clone())
            //     }
            //     let values = variables
            //         .iter()
            //         .map(|v| v.value().copied().map(|v| v == F::ONE))
            //         .collect::<Vec<_>>();
            //     let bits: Vec<AssignedBit<F>> = std.assign_many(layouter,
            // &values)?;     variables.iter().zip(bits.iter()).
            // try_for_each(|(v, b)| {         let b_as_f =
            // std.convert(layouter, b)?;         std.
            // assert_equal(layouter, v, &b_as_f)     })?;
            // }
            // I::ConstrainToByteMany { vars } => {
            //     let mut variables = Vec::with_capacity(vars.len());
            //     for v in vars.iter() {
            //         variables.push(get(&memory, *v)?.clone())
            //     }
            //     let values = variables
            //         .iter()
            //         .map(|v| v.value().copied().map(|v| v.to_bytes_le()[0]))
            //         .collect::<Vec<_>>();
            //     let bytes: Vec<AssignedByte<F>> = std.assign_many(layouter,
            // &values)?;     variables.iter().zip(bytes.iter()).
            // try_for_each(|(v, b)| {         let b_as_f =
            // std.convert(layouter, b)?;         std.
            // assert_equal(layouter, v, &b_as_f)     })?;
            // }
            // I::Copy { var } => memory.push(get(&memory, *var)?.clone()),
            // I::DeclarePubInput { var } => {
            //     std.constrain_as_public_input(layouter, get(&memory, *var)?)?
            // }
            // I::PiSkip { .. } => {}
            // I::LoadImm { imm } => memory.push(std.assign_fixed(layouter,
            // *imm)?), I::Output { .. } => unimplemented!(),
            // I::TransientHash { inputs } => {
            //     let inputs = inputs
            //         .iter()
            //         .map(|inp| get(&memory, *inp).cloned())
            //         .collect::<Result<Vec<_>, _>>()?;
            //     memory.push(std.poseidon(layouter, &inputs)?)
            // }
            // I::TestEq { a, b } => {
            //     let bit = std.is_equal(layouter, get(&memory, *a)?,
            // get(&memory, *b)?)?;     memory.push(std.
            // convert(layouter, &bit)?); }
            // I::Add { a, b } => {
            //     memory.push(std.add(layouter, get(&memory, *a)?, get(&memory,
            // *b)?)?) }
            // I::Mul { a, b } => {
            //     memory.push(std.mul(layouter, get(&memory, *a)?, get(&memory,
            // *b)?, None)?) }
            // I::Neg { a } => memory.push(std.neg(layouter, get(&memory,
            // *a)?)?), I::Not { a } => {
            //     let bit = std.is_zero(layouter, get(&memory, *a)?)?;
            //     memory.push(std.convert(layouter, &bit)?)
            // }
            // I::LessThan { a, b, bits } => {
            //     let bit = std.lower_than(
            //         layouter,
            //         get(&memory, *a)?,
            //         get(&memory, *b)?,
            //         u32::max(*bits + *bits % 2, 4),
            //     )?;
            //     memory.push(std.convert(layouter, &bit)?);
            // }
            // I::PublicInput { guard } | I::PrivateInput { guard } => {
            //     // TODO: This is not how it should be done, but it is
            // circuit-size equivalent.
            // assert!(guard.is_none());     let x =
            // std.assign(layouter, Value::unknown())?;     memory.
            // push(x); }
            // I::DivModPowerOfTwo { var, bits } => {
            //     let (q, r) = std.div_rem(
            //         layouter,
            //         get(&memory, *var)?,
            //         BigUint::from(1u64) << bits,
            //         None,
            //     )?;
            //     memory.push(q);
            //     memory.push(r);
            // }
            // I::ReconstituteField {
            //     divisor,
            //     modulus,
            //     bits,
            // } => {
            //     let divisor_bits = std.assigned_to_le_bits(
            //         layouter,
            //         get(&memory, *divisor)?,
            //         Some((F::NUM_BITS - *bits) as usize),
            //         true,
            //     )?;
            //     let modulus_bits = std.assigned_to_le_bits(
            //         layouter,
            //         get(&memory, *modulus)?,
            //         Some(*bits as usize),
            //         true,
            //     )?;
            //     let reconstituted = std
            //         .assigned_from_le_bits(layouter, &[modulus_bits,
            // divisor_bits].concat())?;     memory.push(reconstituted);
            // }
            // I::EcAdd { a_x, a_y, b_x, b_y } => {
            //     let a =
            //         ecc_from_parts(std, layouter, get(&memory, *a_x)?,
            // get(&memory, *a_y)?)?;     let b =
            //         ecc_from_parts(std, layouter, get(&memory, *b_x)?,
            // get(&memory, *b_y)?)?;     let c =
            // std.jubjub().add(layouter, &a, &b)?;     memory.
            // push(std.jubjub().x_coordinate(&c));     memory.
            // push(std.jubjub().y_coordinate(&c)); }
            // I::EcMul { a_x, a_y, scalar } => {
            //     let a =
            //         ecc_from_parts(std, layouter, get(&memory, *a_x)?,
            // get(&memory, *a_y)?)?;     let scalar =
            // std.jubjub().convert(layouter, get(&memory, *scalar)?)?;
            //     let b = std.jubjub().msm(layouter, &[scalar], &[a])?;
            //     memory.push(std.jubjub().x_coordinate(&b));
            //     memory.push(std.jubjub().y_coordinate(&b));
            // }
            // I::EcMulGenerator { scalar } => {
            //     let g: AssignedNativePoint<JubjubExtended> = std
            //         .jubjub()
            //         .assign_fixed(layouter, JubjubSubgroup::generator())?;
            //     let scalar = std.jubjub().convert(layouter, get(&memory,
            // *scalar)?)?;     let b = std.jubjub().msm(layouter,
            // &[scalar], &[g])?;     memory.push(std.jubjub().
            // x_coordinate(&b));     memory.push(std.jubjub().
            // y_coordinate(&b)); }
            // I::HashToCurve { inputs } => {
            //     let inputs = inputs
            //         .iter()
            //         .map(|input| get(&memory, *input).cloned())
            //         .collect::<Result<Vec<_>, _>>()?;
            //     let point = std.hash_to_curve(layouter, &inputs)?;
            //     memory.push(std.jubjub().x_coordinate(&point));
            //     memory.push(std.jubjub().y_coordinate(&point));
            // }
        }
        Ok(())
    }

    fn used_chips(&self) -> ZkStdLibArch {
        fn loads_type(instruction: &I, target_t: ValType) -> bool {
            matches!(instruction, I::Load { val_t, .. } if *val_t == target_t)
        }

        // let hash_to_curve = self
        //     .instructions
        //     .iter()
        //     .any(|op| matches!(op, I::HashToCurve { .. }));
        // let poseidon = self
        //     .instructions
        //     .iter()
        //     .any(|op| matches!(op, I::TransientHash { .. }));

        ZkStdLibArch {
            jubjub: self.instructions.iter().any(|op| {
                loads_type(op, ValType::JubjubPoint) || loads_type(op, ValType::JubjubScalar)
            }),
            poseidon: false,
            sha256: None,
            secp256k1: false,
            bls12_381: false,
            nr_pow2range_cols: 4,
            automaton: false,
            base64: false,
        }
    }

    fn write_relation<W: std::io::Write>(&self, _writer: &mut W) -> std::io::Result<()> {
        unimplemented!()
    }

    fn read_relation<R: std::io::Read>(_reader: &mut R) -> std::io::Result<Self> {
        unimplemented!()
    }
}

fn load(
    parser: &mut Parser,
    layouter: &mut impl Layouter<F>,
    val_t: &ValType,
    names: &[String],
    witness: &Value<HashMap<String, OffCircuitType>>,
) -> Result<(), Error> {
    let std = parser.std_lib;
    match val_t {
        ValType::Bit => {
            let vals = witness
                .as_ref()
                .map(|m| names.iter().map(|name| get_bit(m, name)).collect::<Vec<_>>());
            let bits = std.assign_many(layouter, &vals.transpose_vec(names.len()))?;
            let bits = bits.into_iter().map(CircuitType::Bit).collect::<Vec<_>>();
            parser.insert_many(names, &bits)
        }
        ValType::Byte => {
            let vals = witness
                .as_ref()
                .map(|m| names.iter().map(|name| get_byte(m, name)).collect::<Vec<_>>());
            let bytes = std.assign_many(layouter, &vals.transpose_vec(names.len()))?;
            let bytes = bytes.into_iter().map(CircuitType::Byte).collect::<Vec<_>>();
            parser.insert_many(names, &bytes)
        }
        ValType::Bytes(n) => {
            let vals = witness
                .as_ref()
                .map(|m| names.iter().flat_map(|name| get_bytes(m, name, *n)).collect::<Vec<_>>());
            let flatten_bytes = std.assign_many(layouter, &vals.transpose_vec(names.len() * *n))?;
            let chunks = flatten_bytes
                .chunks(*n)
                .map(|chunk| CircuitType::Bytes(chunk.to_vec()))
                .collect::<Vec<_>>();
            parser.insert_many(names, &chunks)
        }
        ValType::Native => {
            let vals = witness
                .as_ref()
                .map(|m| names.iter().map(|name| get_native(m, name)).collect::<Vec<_>>());
            let xs = std.assign_many(layouter, &vals.transpose_vec(names.len()))?;
            let xs = xs.into_iter().map(CircuitType::Native).collect::<Vec<_>>();
            parser.insert_many(names, &xs)
        }
        ValType::JubjubPoint => {
            let vals = witness
                .as_ref()
                .map(|m| names.iter().map(|name| get_jubjub_point(m, name)).collect::<Vec<_>>());
            let points = std.jubjub().assign_many(layouter, &vals.transpose_vec(names.len()))?;
            let points = points.into_iter().map(CircuitType::JubjubPoint).collect::<Vec<_>>();
            parser.insert_many(names, &points)
        }
        ValType::JubjubScalar => {
            let vals = witness
                .as_ref()
                .map(|m| names.iter().map(|name| get_jubjub_scalar(m, name)).collect::<Vec<_>>());
            let scalars = std.jubjub().assign_many(layouter, &vals.transpose_vec(names.len()))?;
            let scalars = scalars.into_iter().map(CircuitType::JubjubScalar).collect::<Vec<_>>();
            parser.insert_many(names, &scalars)
        }
    }
}

fn assert_equal(
    parser: &mut Parser,
    layouter: &mut impl Layouter<F>,
    (x, y): &(String, String),
) -> Result<(), Error> {
    let val_t = parser.infer_type(&[x.into(), y.into()])?;
    parser.assign_constants(layouter, val_t, &[x.into(), y.into()])?;

    match val_t {
        ValType::Bit => {
            parser.std_lib.assert_equal(layouter, &parser.get_bit(x)?, &parser.get_bit(y)?)
        }
        ValType::Byte => {
            parser
                .std_lib
                .assert_equal(layouter, &parser.get_byte(x)?, &parser.get_byte(y)?)
        }
        ValType::Bytes(n) => {
            let x_bytes = parser.get_bytes(x, n)?;
            let y_bytes = parser.get_bytes(y, n)?;
            (x_bytes.iter().zip(y_bytes.iter()))
                .try_for_each(|(x, y)| parser.std_lib.assert_equal(layouter, x, y))
        }
        ValType::Native => {
            parser
                .std_lib
                .assert_equal(layouter, &parser.get_native(x)?, &parser.get_native(y)?)
        }
        ValType::JubjubPoint => parser.std_lib.jubjub().assert_equal(
            layouter,
            &parser.get_jubjub_point(x)?,
            &parser.get_jubjub_point(y)?,
        ),
        ValType::JubjubScalar => panic!("assert_equal is not supported on Jubjub scalars"),
    }
}

fn is_equal(
    parser: &mut Parser,
    layouter: &mut impl Layouter<F>,
    (x, y): &(String, String),
    output: &str,
) -> Result<(), Error> {
    let val_t = parser.infer_type(&[x.into(), y.into()])?;
    parser.assign_constants(layouter, val_t, &[x.into(), y.into()])?;

    let b = match val_t {
        ValType::Bit => parser.std_lib.is_equal(layouter, &parser.get_bit(x)?, &parser.get_bit(y)?),
        ValType::Byte => {
            parser.std_lib.is_equal(layouter, &parser.get_byte(x)?, &parser.get_byte(y)?)
        }
        ValType::Bytes(n) => {
            let x_bytes = parser.get_bytes(x, n)?;
            let y_bytes = parser.get_bytes(x, n)?;
            let bits: Vec<_> = (x_bytes.iter().zip(y_bytes.iter()))
                .map(|(x, y)| parser.std_lib.is_equal(layouter, x, y))
                .collect::<Result<_, Error>>()?;
            parser.std_lib.and(layouter, &bits)
        }
        ValType::Native => {
            parser
                .std_lib
                .is_equal(layouter, &parser.get_native(x)?, &parser.get_native(y)?)
        }
        ValType::JubjubPoint => parser.std_lib.jubjub().is_equal(
            layouter,
            &parser.get_jubjub_point(x)?,
            &parser.get_jubjub_point(y)?,
        ),
        ValType::JubjubScalar => panic!("is_equal is not supported on Jubjub scalars"),
    }?;

    parser.insert(output, &CircuitType::Bit(b))
}

fn add(
    parser: &mut Parser,
    layouter: &mut impl Layouter<F>,
    vals: &[String],
    output: &str,
) -> Result<(), Error> {
    let val_t = parser.infer_type(vals)?;
    parser.assign_constants(layouter, val_t, vals)?;
    match val_t {
        ValType::Native => {
            let mut terms = vec![];
            for name in vals {
                terms.push((F::ONE, parser.get_native(name)?))
            }
            let r = (parser.std_lib).linear_combination(layouter, &terms, F::ZERO)?;
            parser.insert(output, &CircuitType::Native(r))
        }
        t => Err(Error::SynthesisWithMsg(format!("add unsupported: {:?}", t))),
    }
}

fn mul(
    parser: &mut Parser,
    layouter: &mut impl Layouter<F>,
    vals: &[String],
    output: &str,
) -> Result<(), Error> {
    if vals.is_empty() {
        return Err(Error::SynthesisWithMsg(
            "mul expects at least one variable".into(),
        ));
    }

    let val_t = parser.infer_type(vals)?;
    parser.assign_constants(layouter, val_t, vals)?;

    match val_t {
        ValType::Native => {
            let mut acc = parser.get_native(&vals[0])?;
            for name in vals.iter().skip(1) {
                acc = (parser.std_lib).mul(layouter, &acc, &parser.get_native(name)?, None)?;
            }
            parser.insert(output, &CircuitType::Native(acc))
        }
        t => Err(Error::SynthesisWithMsg(format!("mul unsupported: {:?}", t))),
    }
}

fn neg(
    parser: &mut Parser,
    layouter: &mut impl Layouter<F>,
    val: &String,
    output: &str,
) -> Result<(), Error> {
    match parser.infer_type(&[val.into()])? {
        ValType::Native => {
            let r = parser.std_lib.neg(layouter, &parser.get_native(val)?)?;
            parser.insert(output, &CircuitType::Native(r))
        }
        t => Err(Error::SynthesisWithMsg(format!("neg unsupported: {:?}", t))),
    }
}

fn not(
    parser: &mut Parser,
    layouter: &mut impl Layouter<F>,
    val: &String,
    output: &str,
) -> Result<(), Error> {
    match parser.infer_type(&[val.into()])? {
        ValType::Bit => {
            let b = parser.std_lib.not(layouter, &parser.get_bit(val)?)?;
            parser.insert(output, &CircuitType::Bit(b))
        }
        t => Err(Error::SynthesisWithMsg(format!("not unsupported: {:?}", t))),
    }
}

/// # Panics
///
/// If `|bases| != |scalars|`.
fn msm(
    parser: &mut Parser,
    layouter: &mut impl Layouter<F>,
    bases: &[String],
    scalars: &[String],
    output: &str,
) -> Result<(), Error> {
    if bases.len() != scalars.len() {
        return Err(Error::SynthesisWithMsg(format!(
            "|bases| != |scalars| ({:?} vs {:?})",
            bases.len(),
            scalars.len()
        )));
    }

    let bases_t = parser.infer_type(bases)?;
    let scalars_t = parser.infer_type(scalars)?;
    parser.assign_constants(layouter, bases_t, bases)?;
    parser.assign_constants(layouter, scalars_t, scalars)?;

    match (bases_t, scalars_t) {
        (ValType::JubjubPoint, ValType::JubjubScalar) => {
            let bases = bases
                .iter()
                .map(|b| parser.get_jubjub_point(b))
                .collect::<Result<Vec<_>, Error>>()?;
            let scalars = scalars
                .iter()
                .map(|s| parser.get_jubjub_scalar(s))
                .collect::<Result<Vec<_>, Error>>()?;
            let p = parser.std_lib.jubjub().msm(layouter, &scalars, &bases)?;
            parser.insert(output, &CircuitType::JubjubPoint(p))
        }
        _ => Err(Error::SynthesisWithMsg(format!(
            "msm invalid input types( bases: {:?}, scalars: {:?} )",
            bases_t, scalars_t
        ))),
    }
}

fn select(
    parser: &mut Parser,
    layouter: &mut impl Layouter<F>,
    cond: &String,
    (x, y): &(String, String),
    output: &str,
) -> Result<(), Error> {
    let val_t = parser.infer_type(&[x.into(), y.into()])?;
    parser.assign_constants(layouter, val_t, &[x.into(), y.into()])?;

    let cond = parser.get_bit(cond)?;

    match val_t {
        ValType::Bit => {
            let x = parser.get_bit(x)?;
            let y = parser.get_bit(y)?;
            let z = parser.std_lib.select(layouter, &cond, &x, &y)?;
            parser.insert(output, &CircuitType::Bit(z))
        }
        ValType::Byte => {
            let x = parser.get_byte(x)?;
            let y = parser.get_byte(y)?;
            let z = parser.std_lib.select(layouter, &cond, &x, &y)?;
            parser.insert(output, &CircuitType::Byte(z))
        }
        ValType::Bytes(n) => {
            let x_bytes = parser.get_bytes(x, n)?;
            let y_bytes = parser.get_bytes(y, n)?;
            let z_bytes = (x_bytes.into_iter().zip(y_bytes.into_iter()))
                .map(|(x, y)| parser.std_lib.select(layouter, &cond, &x, &y))
                .collect::<Result<Vec<_>, Error>>()?;
            parser.insert(output, &CircuitType::Bytes(z_bytes))
        }
        ValType::Native => {
            let x = parser.get_native(x)?;
            let y = parser.get_native(y)?;
            let z = parser.std_lib.select(layouter, &cond, &x, &y)?;
            parser.insert(output, &CircuitType::Native(z))
        }
        ValType::JubjubPoint => {
            let x = parser.get_jubjub_point(x)?;
            let y = parser.get_jubjub_point(y)?;
            let z = parser.std_lib.jubjub().select(layouter, &cond, &x, &y)?;
            parser.insert(output, &CircuitType::JubjubPoint(z))
        }
        ValType::JubjubScalar => panic!("select is not supported on Jubjub scalars"),
    }
}

fn from_bytes(
    parser: &mut Parser,
    layouter: &mut impl Layouter<F>,
    val_t: &ValType,
    bytes_name: &String,
    output: &str,
) -> Result<(), Error> {
    let n = match parser.infer_type(&[bytes_name.into()])? {
        ValType::Bytes(n) => n,
        _ => panic!("TODO"),
    };
    let bytes = parser.get_bytes(bytes_name, n)?;

    match val_t {
        ValType::Native => {
            let x = parser.std_lib.assigned_from_le_bytes(layouter, &bytes)?;
            parser.insert(output, &CircuitType::Native(x))
        }
        ValType::JubjubScalar => {
            let x = parser.std_lib.jubjub().assigned_from_le_bytes(layouter, &bytes)?;
            parser.insert(output, &CircuitType::JubjubScalar(x))
        }
        t => Err(Error::SynthesisWithMsg(format!(
            "from_bytes is unsupported on {:?}",
            t
        ))),
    }
}
