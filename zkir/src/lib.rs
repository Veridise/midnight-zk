//! A toolkit for parsing ZKIR circuits.

#![deny(rustdoc::broken_intra_doc_links)]
#![deny(missing_debug_implementations)]
#![deny(missing_docs)]

// #[doc = include_str!("../README.md")]

extern crate core;

mod instructions;
mod parser;
mod parser_cpu;
mod types;
mod utils;
mod zkir;

pub use types::OffCircuitType;
pub use zkir::IrSource;
