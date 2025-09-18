use std::collections::HashMap;

use ff::Field;
use group::Group;
use midnight_circuits::{compact_std_lib::ZkStdLib, instructions::*};
use midnight_curves::JubjubSubgroup;
use midnight_proofs::{
    circuit::{Layouter, Value},
    plonk::Error,
};

use crate::types::{
    get_bit, get_byte, get_bytes, get_jubjub_point, get_jubjub_scalar, get_native, parse_bit,
    parse_byte, parse_bytes, parse_native, type_of, CircuitType, OffCircuitType, ValType,
};

type F = midnight_curves::Fq;

pub(crate) struct Parser<'a> {
    std_lib: &'a ZkStdLib,
    memory: HashMap<String, CircuitType>,
}

impl<'a> Parser<'a> {
    pub fn new(std_lib: &'a ZkStdLib) -> Self {
        Self {
            std_lib,
            memory: HashMap::new(),
        }
    }

    pub fn insert(&mut self, name: &str, value: &CircuitType) -> Result<(), Error> {
        self.memory.insert(name.to_owned(), value.clone()).map_or(Ok(()), |_| {
            Err(Error::Synthesis(format!(
                "variable {} already exists",
                name
            )))
        })
    }

    pub fn insert_many(&mut self, names: &[String], values: &[CircuitType]) -> Result<(), Error> {
        if names.len() != values.len() {
            return Err(Error::Synthesis("".into()));
        }
        (names.iter().zip(values.iter())).try_for_each(|(name, value)| self.insert(name, value))
    }

    pub fn get(&self, name: &str) -> Option<CircuitType> {
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
                    return Err(Error::Synthesis("".into()));
                }
            }
        }
        inferred_type.ok_or(Error::Synthesis(format!(
            "type of {:?} could not be inferred",
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
                let bit_val = parse_bit(name).ok_or(Error::Synthesis("".into()))?;
                let bit = self.std_lib.assign_fixed(layouter, bit_val)?;
                self.insert(name, &CircuitType::Bit(bit))
            }
            ValType::Byte => {
                let byte_val = parse_byte(name).ok_or(Error::Synthesis("".into()))?;
                let byte = self.std_lib.assign_fixed(layouter, byte_val)?;
                self.insert(name, &CircuitType::Byte(byte))
            }
            ValType::Bytes(n) => {
                let byte_vals = parse_bytes(name).ok_or(Error::Synthesis("".into()))?;
                let bytes = self.std_lib.assign_many_fixed(layouter, &byte_vals)?;
                if bytes.len() != n {
                    return Err(Error::Synthesis(format!(
                        "expected {} bytes, {} given",
                        n,
                        bytes.len()
                    )));
                }
                self.insert(name, &CircuitType::Bytes(bytes))
            }
            ValType::Native => {
                let x_val = parse_native(name).ok_or(Error::Synthesis("".into()))?;
                let x = self.std_lib.assign_fixed(layouter, x_val)?;
                self.insert(name, &CircuitType::Native(x))
            }
            ValType::JubjubPoint => {
                let p_val = match name {
                    "Jubjub::GENERATOR" => JubjubSubgroup::generator(),
                    _ => todo!(),
                };
                let p = self.std_lib.jubjub().assign_fixed(layouter, p_val)?;
                self.insert(name, &CircuitType::JubjubPoint(p))
            }
            ValType::JubjubScalar => todo!(),
        }
    }

    /// Takes a list of names and parses as constants (of the given type) those
    /// that are do not appear in the memory. It assigns them in-circuit as
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

pub(crate) fn load(
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

pub(crate) fn publish(
    parser: &mut Parser,
    layouter: &mut impl Layouter<F>,
    vals: &[String],
) -> Result<(), Error> {
    for v in vals.iter() {
        match parser.infer_type(std::slice::from_ref(v))? {
            ValType::Bit => {
                let b = parser.get_bit(v)?;
                parser.std_lib.constrain_as_public_input(layouter, &b)
            }
            ValType::Byte => {
                let b = parser.get_byte(v)?;
                parser.std_lib.constrain_as_public_input(layouter, &b)
            }
            ValType::Bytes(n) => {
                let bytes = parser.get_bytes(v, n)?;
                (bytes.iter())
                    .try_for_each(|b| parser.std_lib.constrain_as_public_input(layouter, b))
            }
            ValType::Native => {
                let x = parser.get_native(v)?;
                parser.std_lib.constrain_as_public_input(layouter, &x)
            }
            ValType::JubjubPoint => {
                let p = parser.get_jubjub_point(v)?;
                parser.std_lib.jubjub().constrain_as_public_input(layouter, &p)
            }
            ValType::JubjubScalar => {
                let s = parser.get_jubjub_scalar(v)?;
                parser.std_lib.jubjub().constrain_as_public_input(layouter, &s)
            }
        }?;
    }
    Ok(())
}

pub(crate) fn assert_equal(
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

pub(crate) fn is_equal(
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

pub(crate) fn add(
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

        t => Err(Error::Synthesis(format!("add unsupported: {:?}", t))),
    }
}

pub(crate) fn mul(
    parser: &mut Parser,
    layouter: &mut impl Layouter<F>,
    vals: &[String],
    output: &str,
) -> Result<(), Error> {
    if vals.is_empty() {
        return Err(Error::Synthesis("mul expects at least one variable".into()));
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
        t => Err(Error::Synthesis(format!("mul unsupported: {:?}", t))),
    }
}

pub(crate) fn neg(
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
        ValType::Bit => {
            let b = parser.std_lib.not(layouter, &parser.get_bit(val)?)?;
            parser.insert(output, &CircuitType::Bit(b))
        }
        t => Err(Error::Synthesis(format!("neg unsupported: {:?}", t))),
    }
}

/// # Panics
///
/// If `|bases| != |scalars|`.
pub(crate) fn msm(
    parser: &mut Parser,
    layouter: &mut impl Layouter<F>,
    bases: &[String],
    scalars: &[String],
    output: &str,
) -> Result<(), Error> {
    if bases.len() != scalars.len() {
        return Err(Error::Synthesis(format!(
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
        _ => Err(Error::Synthesis(format!(
            "msm invalid input types( bases: {:?}, scalars: {:?} )",
            bases_t, scalars_t
        ))),
    }
}

pub(crate) fn affine_coordinates(
    parser: &mut Parser,
    _layouter: &mut impl Layouter<F>,
    input: &String,
    (x_output, y_output): &(String, String),
) -> Result<(), Error> {
    match parser.infer_type(&[input.into()])? {
        ValType::JubjubPoint => {
            let p = parser.get_jubjub_point(input)?;
            let x = parser.std_lib.jubjub().x_coordinate(&p);
            let y = parser.std_lib.jubjub().y_coordinate(&p);
            parser.insert(x_output, &CircuitType::Native(x))?;
            parser.insert(y_output, &CircuitType::Native(y))
        }
        t => Err(Error::Synthesis(format!(
            "affine_coordinates: invalid input type {:?}",
            t
        ))),
    }
}

pub(crate) fn select(
    parser: &mut Parser,
    layouter: &mut impl Layouter<F>,
    cond: &str,
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
            parser.insert(output, &z.into())
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

pub(crate) fn into_bytes(
    parser: &mut Parser,
    layouter: &mut impl Layouter<F>,
    input: &String,
    nb_bytes: usize,
    output: &str,
) -> Result<(), Error> {
    match parser.infer_type(std::slice::from_ref(input))? {
        ValType::Native => {
            let x = parser.get_native(input)?;
            let bytes = parser.std_lib.assigned_to_le_bytes(layouter, &x, Some(nb_bytes))?;
            parser.insert(output, &CircuitType::Bytes(bytes))
        }
        t => Err(Error::Synthesis(format!(
            "into_bytes is unsupported on {:?}",
            t
        ))),
    }
}

pub(crate) fn from_bytes(
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
            let x = parser.std_lib.jubjub().scalar_from_le_bytes(layouter, &bytes)?;
            parser.insert(output, &CircuitType::JubjubScalar(x))
        }
        t => Err(Error::Synthesis(format!(
            "from_bytes is unsupported on {:?}",
            t
        ))),
    }
}

pub(crate) fn poseidon(
    parser: &mut Parser,
    layouter: &mut impl Layouter<F>,
    inputs: &[String],
    output: &str,
) -> Result<(), Error> {
    let xs = inputs
        .iter()
        .map(|name| parser.get_native(name))
        .collect::<Result<Vec<_>, Error>>()?;

    let h = parser.std_lib.poseidon(layouter, &xs)?;
    parser.insert(output, &CircuitType::Native(h))
}
