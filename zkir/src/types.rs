use midnight_curves::{Fr as JubjubScalar, JubjubExtended, JubjubSubgroup};
use serde::Deserialize;

use crate::impl_enum_from_try_from;

type F = midnight_curves::Fq;

type AssignedBit = midnight_circuits::types::AssignedBit<F>;
type AssignedByte = midnight_circuits::types::AssignedByte<F>;
type AssignedNative = midnight_circuits::types::AssignedNative<F>;
type AssignedJubjubPoint = midnight_circuits::types::AssignedNativePoint<JubjubExtended>;
type AssignedJubjubScalar = midnight_circuits::types::AssignedScalarOfNativeCurve<JubjubExtended>;

#[derive(Clone, Debug, PartialEq, Deserialize)]
pub(crate) enum ValType {
    Bit,
    Byte,
    Native,
    JubjubPoint,
    JubjubScalar,
    Array(Box<ValType>, usize),
}

#[derive(Clone, Debug, PartialEq, Eq)]
/// TODO
pub enum OffCircuitType {
    /// TODO
    Bit(bool),
    /// TODO
    Byte(u8),
    /// TODO
    Native(F),
    /// TODO
    JubjubPoint(JubjubSubgroup),
    /// TODO
    JubjubScalar(JubjubScalar),
    /// TODO
    Array(Vec<OffCircuitType>),
}

#[derive(Clone, Debug)]
pub enum CircuitType {
    Bit(AssignedBit),
    Byte(AssignedByte),
    Native(AssignedNative),
    JubjubPoint(AssignedJubjubPoint),
    JubjubScalar(AssignedJubjubScalar),
    Array(Vec<CircuitType>),
}

pub fn type_of(v: &CircuitType) -> ValType {
    match v {
        CircuitType::Bit(_) => ValType::Bit,
        CircuitType::Byte(_) => ValType::Byte,
        CircuitType::Native(_) => ValType::Native,
        CircuitType::JubjubPoint(_) => ValType::JubjubPoint,
        CircuitType::JubjubScalar(_) => ValType::JubjubScalar,
        CircuitType::Array(array) => {
            let t = type_of(&array[0]);
            array.iter().skip(1).for_each(|x| assert_eq!(type_of(x), t));
            ValType::Array(Box::new(t), array.len())
        }
    }
}

// Derives implementations:
//  - From<T> for OffCircuitType
//  - TryFrom<OffCircuitType> for T
//
// for all basic types T (not Array).
impl_enum_from_try_from!(OffCircuitType {
    Bit => bool,
    Byte => u8,
    Native => F,
    JubjubPoint => JubjubSubgroup,
    JubjubScalar => JubjubScalar,
});

impl<T: Clone> From<Vec<T>> for OffCircuitType
where
    OffCircuitType: From<T>,
{
    fn from(array: Vec<T>) -> Self {
        OffCircuitType::Array(array.iter().map(|t| t.clone().into()).collect())
    }
}

impl<T> TryFrom<OffCircuitType> for Vec<T>
where
    T: TryFrom<OffCircuitType, Error = String>,
{
    type Error = String;

    fn try_from(value: OffCircuitType) -> Result<Self, Self::Error> {
        match value {
            OffCircuitType::Array(array) => {
                Ok(array.into_iter().map(|t| t.try_into()).collect::<Result<Vec<T>, _>>()?)
            }
            other => Err(format!("variable {:?} is not of type Array", other)),
        }
    }
}

// Derives implementations:
//  - From<T> for CircuitType
//  - TryFrom<CircuitType> for T
//
// for all basic types T (not Array).
impl_enum_from_try_from!(CircuitType {
    Bit => AssignedBit,
    Byte => AssignedByte,
    Native => AssignedNative,
    JubjubPoint => AssignedJubjubPoint,
    JubjubScalar => AssignedJubjubScalar,
});

impl<T: Clone> From<&[T]> for CircuitType
where
    CircuitType: From<T>,
{
    fn from(array: &[T]) -> Self {
        CircuitType::Array(array.iter().map(|t| t.clone().into()).collect())
    }
}

impl<T> TryFrom<CircuitType> for Vec<T>
where
    T: TryFrom<CircuitType, Error = String>,
{
    type Error = String;

    fn try_from(value: CircuitType) -> Result<Self, Self::Error> {
        match value {
            CircuitType::Array(array) => {
                Ok(array.into_iter().map(|t| t.try_into()).collect::<Result<Vec<T>, _>>()?)
            }
            other => Err(format!("variable {:?} is not of type Array", other)),
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
