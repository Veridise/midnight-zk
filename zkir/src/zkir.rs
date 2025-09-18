use std::collections::HashMap;

use midnight_circuits::{
    compact_std_lib::{Relation, ZkStdLib, ZkStdLibArch},
    types::Instantiable,
};
use midnight_curves::JubjubExtended;
use midnight_proofs::{
    circuit::{Layouter, Value},
    plonk::Error,
};
use serde::Deserialize;

use crate::{
    instructions::{Instruction as I, Instruction},
    parser::{
        add, affine_coordinates, assert_equal, from_bytes, into_bytes, is_equal, load, msm, mul,
        neg, poseidon, publish, select, Parser,
    },
    parser_cpu::public_inputs,
    types::{OffCircuitType, ValType},
};

type F = midnight_curves::Fq;

type AssignedBit = midnight_circuits::types::AssignedBit<F>;
type AssignedByte = midnight_circuits::types::AssignedByte<F>;
type AssignedNative = midnight_circuits::types::AssignedNative<F>;
type AssignedJubjubPoint = midnight_circuits::types::AssignedNativePoint<JubjubExtended>;
type AssignedJubjubScalar = midnight_circuits::types::AssignedScalarOfNativeCurve<JubjubExtended>;

/// TODO
#[derive(Clone, Debug, Deserialize)]
pub struct IrSource {
    instructions: Vec<Instruction>,
}

impl IrSource {
    /// Read an IrSource from JSON.
    pub fn read(raw: &'static str) -> Self {
        let ir: Self = serde_json::from_str(raw).unwrap();
        ir
    }

    /// TODO
    pub fn public_inputs(
        &self,
        witness: HashMap<&'static str, OffCircuitType>,
    ) -> Vec<OffCircuitType> {
        public_inputs(witness, &self.instructions)
    }
}

impl Relation for IrSource {
    type Instance = Vec<OffCircuitType>;

    type Witness = HashMap<&'static str, OffCircuitType>;

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

        let witness = witness.map(|m| m.into_iter().map(|(k, v)| (k.to_string(), v)).collect());

        for instruction in self.instructions.iter() {
            match instruction {
                I::Load { val_t, names } => load(parser, layouter, val_t, names, &witness),
                I::Publish { vals } => publish(parser, layouter, vals),
                I::AssertEqual { vals } => assert_equal(parser, layouter, vals),
                I::IsEqual { vals, output } => is_equal(parser, layouter, vals, output),
                I::Add { vals, output } => add(parser, layouter, vals, output),
                I::Mul { vals, output } => mul(parser, layouter, vals, output),
                I::Neg { val, output } => neg(parser, layouter, val, output),
                I::Msm {
                    bases,
                    scalars,
                    output,
                } => msm(parser, layouter, bases, scalars, output),
                I::AffineCoordinates { val, output } => {
                    affine_coordinates(parser, layouter, val, output)
                }
                I::Select { cond, vals, output } => select(parser, layouter, cond, vals, output),
                I::IntoBytes {
                    val,
                    nb_bytes,
                    output,
                } => into_bytes(parser, layouter, val, *nb_bytes as usize, output),
                I::FromBytes {
                    val_t,
                    bytes,
                    output,
                } => from_bytes(parser, layouter, val_t, bytes, output),
                I::Poseidon { vals, output } => poseidon(parser, layouter, vals, output),
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
        let loading_type = |target_t: ValType| -> bool {
            self.instructions
                .iter()
                .any(|op| matches!(op, I::Load { val_t, .. } if val_t == &target_t))
        };

        // let hash_to_curve = self
        //     .instructions
        //     .iter()
        //     .any(|op| matches!(op, I::HashToCurve { .. }));
        // let poseidon = self
        //     .instructions
        //     .iter()
        //     .any(|op| matches!(op, I::TransientHash { .. }));

        ZkStdLibArch {
            jubjub: loading_type(ValType::JubjubPoint) || loading_type(ValType::JubjubScalar),
            poseidon: self.instructions.iter().any(|op| matches!(op, I::Poseidon { .. })),
            sha256: false,
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
