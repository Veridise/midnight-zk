use serde::Deserialize;

use crate::types::ValType;

/// TODO
#[derive(Clone, Debug, Deserialize)]
pub struct IrSource {
    pub(crate) instructions: Vec<Instruction>,
}

impl IrSource {
    /// Read an IrSource from JSON.
    pub fn read(raw: &'static str) -> Self {
        let ir: Self = serde_json::from_str(raw).unwrap();
        ir
        // IrSource {
        //     num_inputs: ir.num_inputs,
        //     // instructions: optimize_instructions(&ir.instructions),
        //     instructions: ir.instructions,
        // }
    }
}

#[derive(Clone, Debug, PartialEq, Deserialize)]
#[serde(rename_all = "snake_case", tag = "op")]
pub enum Instruction {
    Load {
        #[serde(rename = "type")]
        val_t: ValType,
        names: Vec<String>,
    },
    /// Vals can have different types.
    Publish {
        vals: Vec<String>,
    },
    AssertEqual {
        vals: (String, String),
    },
    IsEqual {
        vals: (String, String),
        output: String,
    },
    // `Add` is polymorphic on the type of vals, as long as all vals have the same type.
    // Accepted types:
    //  - Field
    Add {
        vals: Vec<String>,
        output: String,
    },
    Mul {
        vals: Vec<String>,
        output: String,
    },
    Neg {
        val: String,
        output: String,
    },
    Not {
        val: String,
        output: String,
    },
    Msm {
        bases: Vec<String>,
        scalars: Vec<String>,
        output: String,
    },
    AffineCoordinates {
        val: String,
        output: (String, String),
    },
    /* Control-flow instructions:
         - Select : cond:Bit -> vals:(T, T) -> T

       where T:
         - Bit
         - Byte
         - Field
    */
    Select {
        cond: String,
        vals: (String, String),
        output: String,
    },
    IntoBytes {
        val: String,
        nb_bytes: u32,
        output: String,
    },
    FromBytes {
        #[serde(rename = "type")]
        val_t: ValType,
        bytes: String,
        output: String,
    },

    Poseidon {
        vals: Vec<String>,
        output: String,
    },
    /*
     * CondSelect {
     *     bit: u32,
     *     a: u32,
     *     b: u32,
     * },
     * CondSwap {
     *     bit: u32,
     *     a: u32,
     *     b: u32,
     * },
     * ConstrainBits {
     *     var: u32,
     *     bits: u32,
     * },
     * ConstrainEq {
     *     a: u32,
     *     b: u32,
     * },
     * ConstrainToBoolean {
     *     var: u32,
     * },
     * ConstrainToBooleanMany {
     *     vars: Vec<u32>,
     * },
     * ConstrainToByteMany {
     *     vars: Vec<u32>,
     * },
     * Copy {
     *     var: u32,
     * },
     * DeclarePubInput {
     *     var: u32,
     * },
     * PiSkip {
     *     guard: Option<u32>,
     *     count: u32,
     * },
     * EcAdd {
     *     a_x: u32,
     *     a_y: u32,
     *     b_x: u32,
     *     b_y: u32,
     * },
     * EcMul {
     *     a_x: u32,
     *     a_y: u32,
     *     scalar: u32,
     * },
     * EcMulGenerator {
     *     scalar: u32,
     * },
     * HashToCurve {
     *     inputs: Vec<u32>,
     * },
     * LoadImm {
     *     #[serde(deserialize_with = "field_deser")]
     *     imm: F,
     * },
     * DivModPowerOfTwo {
     *     var: u32,
     *     bits: u32,
     * },
     * ReconstituteField {
     *     divisor: u32,
     *     modulus: u32,
     *     bits: u32,
     * },
     * Output {
     *     var: u32,
     * },
     * TransientHash {
     *     inputs: Vec<u32>,
     * },
     * // PersistentHash {
     * //     alignment: Alignment,
     * //     inputs: Vec<u32>,
     * // },
     * TestEq {
     *     a: u32,
     *     b: u32,
     * },
     * LessThan {
     *     a: u32,
     *     b: u32,
     *     bits: u32,
     * },
     * PublicInput {
     *     guard: Option<u32>,
     * },
     * PrivateInput {
     *     guard: Option<u32>,
     * }, */
}

// fn optimize_instructions(instructions: &[Instruction]) -> Vec<Instruction> {
//     let n = instructions.len();
//     let mut boolean = vec![];
//     let mut bytes = vec![];
//     let mut optimized = Vec::with_capacity(n);
//     let mut i = 0;
//     while i < n {
//         if let Instruction::ConstrainToBoolean { var } = instructions[i] {
//             boolean.push(var);
//             i += 1;
//             continue;
//         }

//         if let Instruction::ConstrainBits { var, bits } = instructions[i] {
//             if bits == 8 {
//                 bytes.push(var);
//                 i += 1;
//                 continue;
//             }
//         }

//         if let Instruction::CondSelect { bit, a, b } = instructions[i] {
//             if i < n - 1 {
//                 if let Instruction::CondSelect {
//                     bit: bit2,
//                     a: a2,
//                     b: b2,
//                 } = instructions[i + 1]
//                 {
//                     if bit == bit2 && a == b2 && b == a2 {
//                         optimized.push(Instruction::CondSwap { bit, a: a2, b:
// b2 });                         i += 2;
//                         continue;
//                     }
//                 }
//             }
//         }

//         optimized.push(instructions[i].clone());
//         i += 1;
//     }

//     optimized.insert(0, Instruction::ConstrainToBooleanMany { vars: boolean
// });     optimized.insert(1, Instruction::ConstrainToByteMany { vars: bytes
// });     optimized
// }

// fn field_deser<'a, D: serde::Deserializer<'a>>(deserializer: D) -> Result<F,
// D::Error> {     let repr_str: String =
// serde::Deserialize::deserialize(deserializer)?;     let mut repr =
// repr_str.as_bytes();     let negate = if !repr.is_empty() && repr[0] == b'-'
// {         repr = &repr[1..];
//         true
//     } else {
//         false
//     };
//     let mut bytes = const_hex::decode(repr)
//         .map_err(<D::Error as serde::de::Error>::custom)?
//         .into_iter()
//         .collect::<Vec<_>>();
//     bytes.resize(32, 0);
//     let field = F::from_bytes_le(&bytes.try_into().unwrap()).unwrap();
//     Ok(if negate { -field } else { field })
// }
