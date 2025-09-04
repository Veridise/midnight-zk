use std::iter;

use ff::{PrimeField, WithSmallOrderMulGroup};

use super::Argument;
use crate::{
    plonk::{Error, VerifyingKey},
    poly::{commitment::PolynomialCommitmentScheme, VerifierQuery},
    transcript::{read_n, Hashable, Transcript},
};

#[derive(Debug)]
pub struct Committed<F: PrimeField, CS: PolynomialCommitmentScheme<F>> {
    random_poly_commitment: CS::Commitment,
}

pub struct Constructed<F: PrimeField, CS: PolynomialCommitmentScheme<F>> {
    h_commitments: Vec<CS::Commitment>,
    random_poly_commitment: CS::Commitment,
}

impl<F: PrimeField, CS: PolynomialCommitmentScheme<F>> Evaluated<F, CS> {
    pub fn h_limb_commitments(&self) -> &Vec<CS::Commitment> {
        &self.h_commitments
    }
}

pub struct Evaluated<F: PrimeField, CS: PolynomialCommitmentScheme<F>> {
    h_commitments: Vec<CS::Commitment>,
    // TODO: consider removing
    random_poly_commitment: CS::Commitment,
    random_eval: F,
}

impl<F: PrimeField, CS: PolynomialCommitmentScheme<F>> Argument<F, CS> {
    pub(in crate::plonk) fn read_commitments_before_y<T: Transcript>(
        transcript: &mut T,
    ) -> Result<Committed<F, CS>, Error>
    where
        CS::Commitment: Hashable<T::Hash>,
    {
        let random_poly_commitment = transcript.read()?;

        Ok(Committed {
            random_poly_commitment,
        })
    }
}

impl<F: WithSmallOrderMulGroup<3>, CS: PolynomialCommitmentScheme<F>> Committed<F, CS> {
    pub(in crate::plonk) fn read_commitments_after_y<T: Transcript>(
        self,
        vk: &VerifyingKey<F, CS>,
        transcript: &mut T,
    ) -> Result<Constructed<F, CS>, Error>
    where
        CS::Commitment: Hashable<T::Hash>,
    {
        // Obtain a commitment to h(X) in the form of multiple pieces of degree n - 1
        let h_commitments = read_n(transcript, vk.domain.get_quotient_poly_degree())?;

        Ok(Constructed {
            h_commitments,
            random_poly_commitment: self.random_poly_commitment,
        })
    }
}

// TODO: consider removing
impl<F: WithSmallOrderMulGroup<3>, CS: PolynomialCommitmentScheme<F>> Constructed<F, CS> {
    pub(in crate::plonk) fn evaluate_after_x<T: Transcript>(
        self,
        transcript: &mut T,
    ) -> Result<Evaluated<F, CS>, Error>
    where
        F: Hashable<T::Hash>,
    {
        let random_eval = transcript.read()?;

        Ok(Evaluated {
            h_commitments: self.h_commitments,
            random_poly_commitment: self.random_poly_commitment,
            random_eval,
        })
    }
}
