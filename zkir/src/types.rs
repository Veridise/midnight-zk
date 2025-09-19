use midnight_curves::{Fr as JubjubScalar, JubjubExtended, JubjubSubgroup};
use serde::Deserialize;

use crate::impl_enum_from_try_from;

type F = midnight_curves::Fq;

type AssignedBit = midnight_circuits::types::AssignedBit<F>;
type AssignedByte = midnight_circuits::types::AssignedByte<F>;
type AssignedNative = midnight_circuits::types::AssignedNative<F>;
type AssignedJubjubPoint = midnight_circuits::types::AssignedNativePoint<JubjubExtended>;
type AssignedJubjubScalar = midnight_circuits::types::AssignedScalarOfNativeCurve<JubjubExtended>;

#[derive(Clone, Copy, Debug, PartialEq, Deserialize)]
pub(crate) enum ValType {
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

// Derives implementations:
//  - From<T> for OffCircuitType
//  - From<OffCircuitType> for T
//
// for all types T.
impl_enum_from_try_from!(OffCircuitType {
    Bit => bool,
    Byte => u8,
    Bytes => Vec<u8>,
    Native => F,
    JubjubPoint => JubjubSubgroup,
    JubjubScalar => JubjubScalar,
});

// Derives implementations:
//  - From<T> for CircuitType
//  - From<CircuitType> for T
//
// for all types T.
impl_enum_from_try_from!(CircuitType {
    Bit => AssignedBit,
    Byte => AssignedByte,
    Bytes => Vec<AssignedByte>,
    Native => AssignedNative,
    JubjubPoint => AssignedJubjubPoint,
    JubjubScalar => AssignedJubjubScalar,
});

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
