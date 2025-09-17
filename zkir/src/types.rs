use std::collections::HashMap;

use midnight_curves::{Fr as JubjubScalar, JubjubExtended, JubjubSubgroup};
use midnight_proofs::plonk::Error;
use serde::Deserialize;

use crate::parser::Parser;

type F = midnight_curves::Fq;

type AssignedBit = midnight_circuits::types::AssignedBit<F>;
type AssignedByte = midnight_circuits::types::AssignedByte<F>;
type AssignedNative = midnight_circuits::types::AssignedNative<F>;
type AssignedJubjubPoint = midnight_circuits::types::AssignedNativePoint<JubjubExtended>;
type AssignedJubjubScalar = midnight_circuits::types::ScalarVar<JubjubExtended>;

#[derive(Clone, Copy, Debug, PartialEq, Deserialize)] //
pub enum ValType {
    Bit,
    Byte,
    Bytes(usize),
    #[serde(rename = "Field")]
    Native,
    JubjubPoint,
    JubjubScalar,
}

#[derive(Clone, Debug, PartialEq, Eq)]
/// TODO
pub enum OffCircuitType {
    /// TODO
    Bit(bool),
    /// TODO
    Byte(u8),
    /// TODO
    Bytes(Vec<u8>),
    /// TODO
    Native(F),
    /// TODO
    JubjubPoint(JubjubSubgroup),
    /// TODO
    JubjubScalar(JubjubScalar),
}

#[derive(Clone, Debug)]
pub enum CircuitType {
    Bit(AssignedBit),
    Byte(AssignedByte),
    Bytes(Vec<AssignedByte>),
    Native(AssignedNative),
    JubjubPoint(AssignedJubjubPoint),
    JubjubScalar(AssignedJubjubScalar),
}

pub fn type_of(v: &CircuitType) -> ValType {
    match v {
        CircuitType::Bit(_) => ValType::Bit,
        CircuitType::Byte(_) => ValType::Byte,
        CircuitType::Bytes(v) => ValType::Bytes(v.len()),
        CircuitType::Native(_) => ValType::Native,
        CircuitType::JubjubPoint(_) => ValType::JubjubPoint,
        CircuitType::JubjubScalar(_) => ValType::JubjubScalar,
    }
}

pub fn get_bit(memory: &HashMap<String, OffCircuitType>, name: &String) -> bool {
    match memory.get(name) {
        Some(OffCircuitType::Bit(bit)) => *bit,
        Some(_) => panic!("variable {} is not of type Bit", name),
        None => panic!("variable {} is not in memory", name),
    }
}

pub fn get_byte(memory: &HashMap<String, OffCircuitType>, name: &String) -> u8 {
    match memory.get(name) {
        Some(OffCircuitType::Byte(byte)) => *byte,
        Some(_) => panic!("variable {} is not of type Byte", name),
        None => panic!("variable {} is not in memory", name),
    }
}

pub fn get_bytes(memory: &HashMap<String, OffCircuitType>, name: &String, n: usize) -> Vec<u8> {
    match memory.get(name) {
        Some(OffCircuitType::Bytes(bytes)) => {
            assert_eq!(bytes.len(), n);
            bytes.clone()
        }
        Some(_) => panic!("variable {} is not of type Bytes", name),
        None => panic!("variable {} is not in memory", name),
    }
}

pub fn get_native(memory: &HashMap<String, OffCircuitType>, name: &String) -> F {
    match memory.get(name) {
        Some(OffCircuitType::Native(x)) => *x,
        Some(_) => panic!("variable {} is not of type Field", name),
        None => panic!("variable {} is not in memory", name),
    }
}

pub fn get_jubjub_point(memory: &HashMap<String, OffCircuitType>, name: &String) -> JubjubSubgroup {
    match memory.get(name) {
        Some(OffCircuitType::JubjubPoint(p)) => *p,
        Some(_) => panic!("variable {} is not of type JubjubPoint", name),
        None => panic!("variable {} is not in memory", name),
    }
}

pub fn get_jubjub_scalar(memory: &HashMap<String, OffCircuitType>, name: &String) -> JubjubScalar {
    match memory.get(name) {
        Some(OffCircuitType::JubjubScalar(s)) => *s,
        Some(_) => panic!("variable {} is not of type JubjubScalar", name),
        None => panic!("variable {} is not in memory", name),
    }
}

impl<'a> Parser<'a> {
    pub fn get_bit(&mut self, name: &String) -> Result<AssignedBit, Error> {
        match self.get(name) {
            Some(CircuitType::Bit(bit)) => Ok(bit.clone()),
            _ => Err(Error::Synthesis),
        }
    }

    pub fn get_byte(&mut self, name: &String) -> Result<AssignedByte, Error> {
        match self.get(name) {
            Some(CircuitType::Byte(byte)) => Ok(byte.clone()),
            _ => Err(Error::Synthesis),
        }
    }

    pub fn get_bytes(&mut self, name: &String, n: usize) -> Result<Vec<AssignedByte>, Error> {
        match self.get(name) {
            Some(CircuitType::Bytes(bytes)) => {
                assert_eq!(bytes.len(), n);
                Ok(bytes.clone())
            }
            _ => Err(Error::Synthesis),
        }
    }

    pub fn get_native(&mut self, name: &String) -> Result<AssignedNative, Error> {
        match self.get(name) {
            Some(CircuitType::Native(x)) => Ok(x.clone()),
            _ => Err(Error::Synthesis),
        }
    }

    pub fn get_jubjub_point(&mut self, name: &String) -> Result<AssignedJubjubPoint, Error> {
        match self.get(name) {
            Some(CircuitType::JubjubPoint(p)) => Ok(p.clone()),
            _ => Err(Error::Synthesis),
        }
    }

    pub fn get_jubjub_scalar(&mut self, name: &String) -> Result<AssignedJubjubScalar, Error> {
        match self.get(name) {
            Some(CircuitType::JubjubScalar(s)) => Ok(s.clone()),
            _ => Err(Error::Synthesis),
        }
    }
}

pub fn parse_bit(str: &str) -> Option<bool> {
    match str {
        "0" => Some(false),
        "1" => Some(true),
        _ => None,
    }
}

pub fn parse_byte(str: &str) -> Option<u8> {
    const_hex::decode(str)
        .ok()
        .and_then(|bytes| if let [b] = &bytes[..] { Some(*b) } else { None })
}

pub fn parse_bytes(str: &str) -> Option<Vec<u8>> {
    const_hex::decode(str).ok()
}

pub fn parse_native(str: &str) -> Option<F> {
    let mut repr = str.as_bytes();
    let is_negative = !repr.is_empty() && repr[0] == b'-';
    if is_negative {
        repr = &repr[1..];
    };
    const_hex::decode(repr).ok().map(|mut bytes| {
        bytes.resize(32, 0);
        let x = F::from_bytes_le(&bytes.try_into().unwrap()).unwrap();
        if is_negative {
            -x
        } else {
            x
        }
    })
}
