//! Traits and structs related to groups of regions.

use ff::Field;

use crate::circuit::Layouter;

pub use haloumi_integration::core::{
    default_group_key,
    groups::{
        CellRole, DefaultKey, GroupKey, GroupKeyInstance, GroupLayouter, RegionsGroup, SourceLocKey,
    },
};

haloumi_integration::__impl_layouter_for_group_layouter!(
    Field,
    Layouter,
    crate::plonk::Error,
    super::Region,
    super::Table,
    super::Cell,
    crate::plonk::Column<crate::plonk::Instance>,
    crate::plonk::Challenge,
    super::Value
);
