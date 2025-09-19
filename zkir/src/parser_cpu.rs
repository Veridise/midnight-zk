use std::collections::HashMap;

use ff::PrimeField;
use group::Group;
use midnight_circuits::{hash::poseidon::PoseidonChip, instructions::hash::HashCPU};
use midnight_curves::{Fr as JubjubScalar, JubjubAffine, JubjubExtended, JubjubSubgroup};

use crate::{
    instructions::Instruction as I,
    types::{parse_bit, parse_byte, parse_bytes, parse_native, OffCircuitType, ValType},
};

type F = midnight_curves::Fq;

pub fn type_of(v: &OffCircuitType) -> ValType {
    match v {
        OffCircuitType::Bit(_) => ValType::Bit,
        OffCircuitType::Byte(_) => ValType::Byte,
        OffCircuitType::Native(_) => ValType::Native,
        OffCircuitType::JubjubPoint(_) => ValType::JubjubPoint,
        OffCircuitType::JubjubScalar(_) => ValType::JubjubScalar,
        OffCircuitType::Array(array) => {
            let t = type_of(&array[0]);
            array.iter().skip(1).for_each(|x| assert_eq!(type_of(x), t));
            ValType::Array(Box::new(t), array.len())
        }
    }
}

pub(crate) struct ParserCPU {
    memory: HashMap<String, OffCircuitType>,
    public_inputs: Vec<OffCircuitType>,
}

impl ParserCPU {
    fn new(witness: HashMap<&'static str, OffCircuitType>) -> Self {
        Self {
            memory: witness.into_iter().map(|(k, v)| (k.to_string(), v)).collect(),
            public_inputs: vec![],
        }
    }

    fn insert(&mut self, name: &str, value: impl Into<OffCircuitType>) {
        assert!(
            self.memory.insert(name.to_owned(), value.into()).is_none(),
            "variable already exists"
        );
    }

    fn get(&self, name: &str) -> OffCircuitType {
        self.memory.get(name).cloned().expect("variable not found")
    }

    fn get_t<T: TryFrom<OffCircuitType>>(&self, name: &str) -> T {
        match self.memory.get(name) {
            Some(x) => x.clone().try_into().ok().unwrap(),
            None => panic!("variable {} is not in memory", name),
        }
    }

    /// Returns the type of the variables associated with the given names.
    /// Names that do not appear in memory (supposedly corresponding to
    /// hard-coded constants) are skipped.
    ///
    /// # Panics
    ///
    /// If non-skipped names have inconsistent types or if all of them are
    /// skipped (thus no type can be inferred).
    pub fn infer_type(&self, names: &[String]) -> ValType {
        let mut inferred_type = None;
        for name in names.iter() {
            if let Some(v) = self.memory.get(name) {
                let t = inferred_type.get_or_insert_with(|| type_of(v));
                if &type_of(v) != t {
                    panic!("");
                }
            }
        }
        inferred_type.expect("type could not be inferred")
    }

    /// Parses the given name as a constant of the given type and adds it to the
    /// memory.
    pub fn load_constant(&mut self, val_t: &ValType, str: &str) {
        match val_t {
            ValType::Bit => self.insert(str, parse_bit(str).expect("0 or 1")),
            ValType::Byte => self.insert(str, parse_byte(str).expect("byte")),
            ValType::Native => self.insert(str, parse_native(str).expect("native")),
            ValType::JubjubPoint => {
                let p = match str {
                    "Jubjub::GENERATOR" => JubjubSubgroup::generator(),
                    _ => todo!(),
                };
                self.insert(str, p)
            }
            ValType::JubjubScalar => todo!(),
            ValType::Array(t, n) if **t == ValType::Byte => {
                let bytes = parse_bytes(str).expect("bytes");
                assert_eq!(bytes.len(), *n);
                self.insert(str, bytes)
            }
            _ => unimplemented!(),
        }
    }

    /// Takes a list of names and parses as constants (of the given type) those
    /// that are do not appear in the memory. It adds them to the memory.
    pub fn load_constants(&mut self, val_t: &ValType, names: &[String]) {
        for name in names.iter() {
            if !self.memory.contains_key(name) {
                self.load_constant(val_t, name);
            }
        }
    }
}

/// TODO
pub fn public_inputs(
    witness: HashMap<&'static str, OffCircuitType>,
    instructions: &[I],
) -> Vec<OffCircuitType> {
    let mut parser = ParserCPU::new(witness);

    for instruction in instructions.iter() {
        match instruction {
            I::Load { val_t, names } => load(&parser, val_t, names),
            I::Publish { vals } => publish(&mut parser, vals),
            I::AssertEqual { vals } => assert_equal(&mut parser, vals),
            I::IsEqual { vals, output } => is_equal(&mut parser, vals, output),
            I::Add { vals, output } => add(&mut parser, vals, output),
            I::Mul { vals, output } => mul(&mut parser, vals, output),
            I::Neg { val, output } => neg(&mut parser, val, output),
            I::Msm {
                bases,
                scalars,
                output,
            } => msm(&mut parser, bases, scalars, output),
            I::AffineCoordinates { val, output } => affine_coordinates(&mut parser, val, output),
            I::Select { cond, vals, output } => select(&mut parser, cond, vals, output),
            I::IntoBytes {
                val,
                nb_bytes,
                output,
            } => into_bytes(&mut parser, val, *nb_bytes as usize, output),
            I::FromBytes {
                val_t,
                bytes,
                output,
            } => from_bytes(&mut parser, val_t, bytes, output),
            I::Poseidon { vals, output } => poseidon(&mut parser, vals, output),
        };
    }

    parser.public_inputs
}

fn load(parser: &ParserCPU, val_t: &ValType, names: &[String]) {
    assert_eq!(val_t, &parser.infer_type(names))
}

fn publish(parser: &mut ParserCPU, vals: &[String]) {
    vals.iter().for_each(|v| parser.public_inputs.push(parser.get(v)))
}

fn assert_equal(parser: &mut ParserCPU, (x, y): &(String, String)) {
    let val_t = parser.infer_type(&[x.into(), y.into()]);
    parser.load_constants(&val_t, &[x.into(), y.into()]);
    assert_eq!(parser.get(x), parser.get(y));
}

fn is_equal(parser: &mut ParserCPU, (x, y): &(String, String), output: &str) {
    let val_t = parser.infer_type(&[x.into(), y.into()]);
    parser.load_constants(&val_t, &[x.into(), y.into()]);
    parser.insert(output, parser.get(x) == parser.get(y));
}

fn add(parser: &mut ParserCPU, vals: &[String], output: &str) {
    let val_t = parser.infer_type(vals);
    parser.load_constants(&val_t, vals);
    match val_t {
        ValType::Native => {
            let r: F = vals.iter().map(|v| parser.get_t::<F>(v)).sum();
            parser.insert(output, r)
        }
        t => panic!("add unsupported on {:?}", t),
    }
}

fn mul(parser: &mut ParserCPU, vals: &[String], output: &str) {
    let val_t = parser.infer_type(vals);
    parser.load_constants(&val_t, vals);
    match val_t {
        ValType::Native => {
            let r: F = vals.iter().map(|v| parser.get_t::<F>(v)).product();
            parser.insert(output, r)
        }
        t => panic!("mul unsupported on {:?}", t),
    }
}

fn neg(parser: &mut ParserCPU, val: &String, output: &str) {
    match parser.infer_type(std::slice::from_ref(val)) {
        ValType::Native => parser.insert(output, -parser.get_t::<F>(val)),
        ValType::Bit => parser.insert(output, !parser.get_t::<bool>(val)),
        t => panic!("neg unsupported on {:?}", t),
    }
}

/// # Panics
///
/// If `|bases| != |scalars|`.
fn msm(parser: &mut ParserCPU, bases: &[String], scalars: &[String], output: &str) {
    assert_eq!(bases.len(), scalars.len());

    let bases_t = parser.infer_type(bases);
    let scalars_t = parser.infer_type(scalars);
    parser.load_constants(&bases_t, bases);
    parser.load_constants(&scalars_t, scalars);

    match (bases_t, scalars_t) {
        (ValType::JubjubPoint, ValType::JubjubScalar) => {
            let bases: Vec<_> = bases.iter().map(|b| parser.get_t::<JubjubSubgroup>(b)).collect();
            let scalars: Vec<_> = scalars.iter().map(|s| parser.get_t::<JubjubScalar>(s)).collect();
            let p: JubjubSubgroup = bases.into_iter().zip(scalars).map(|(b, s)| b * s).sum();
            parser.insert(output, p)
        }
        t => panic!("msm unsupported on {:?}", t),
    }
}

fn affine_coordinates(
    parser: &mut ParserCPU,
    input: &String,
    (x_output, y_output): &(String, String),
) {
    match parser.infer_type(std::slice::from_ref(input)) {
        ValType::JubjubPoint => {
            let p = parser.get_t::<JubjubSubgroup>(input);
            let p: JubjubExtended = p.into();
            let p: JubjubAffine = p.into();
            parser.insert(x_output, p.get_u());
            parser.insert(y_output, p.get_v())
        }
        t => panic!("affine_coordinates unsupported on {:?}", t),
    }
}

fn select(parser: &mut ParserCPU, cond: &str, (x, y): &(String, String), output: &str) {
    let val_t = parser.infer_type(&[x.into(), y.into()]);
    parser.load_constants(&val_t, &[x.into(), y.into()]);

    let cond = parser.get_t::<bool>(cond);
    parser.insert(output, parser.get(if cond { x } else { y }));
}

fn into_bytes(parser: &mut ParserCPU, input: &String, nb_bytes: usize, output: &str) {
    match parser.infer_type(std::slice::from_ref(input)) {
        ValType::Native => {
            let bytes = parser.get_t::<F>(input).to_bytes_le();
            assert!(nb_bytes <= F::NUM_BITS.div_ceil(8) as usize);
            assert!(bytes[nb_bytes..].iter().all(|&b| b == 0));
            parser.insert(output, bytes[..nb_bytes].to_vec())
        }
        t => panic!("into_bytes unsupported on {:?}", t),
    }
}

fn from_bytes(parser: &mut ParserCPU, val_t: &ValType, bytes_name: &String, output: &str) {
    let n = match parser.infer_type(std::slice::from_ref(bytes_name)) {
        ValType::Array(t, n) if *t == ValType::Byte => n,
        _ => panic!("TODO"),
    };
    let bytes = parser.get_t::<Vec<u8>>(bytes_name);
    assert_eq!(bytes.len(), n);

    match val_t {
        ValType::Native => {
            let mut buff = vec![0u8; F::NUM_BITS.div_ceil(8) as usize];
            buff[..bytes.len()].copy_from_slice(&bytes);
            let x = F::from_bytes_le(&buff.try_into().unwrap()).unwrap();
            parser.insert(output, x)
        }
        ValType::JubjubScalar => {
            let mut buff = [0u8; 64];
            buff[..bytes.len()].copy_from_slice(&bytes);
            let s = JubjubScalar::from_bytes_wide(&buff);
            parser.insert(output, s)
        }
        t => panic!("from_bytes unsupported on {:?}", t),
    }
}

fn poseidon(parser: &mut ParserCPU, inputs: &[String], output: &str) {
    let xs: Vec<_> = inputs.iter().map(|name| parser.get_t::<F>(name)).collect();
    parser.insert(output, <PoseidonChip<F> as HashCPU<F, F>>::hash(&xs))
}
