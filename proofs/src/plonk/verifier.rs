use std::{hash::Hash, iter};

use ff::{FromUniformBytes, PrimeField, WithSmallOrderMulGroup};

use super::{vanishing, Error, VerifyingKey};
use crate::{
    plonk::traces::VerifierTrace,
    poly::{commitment::PolynomialCommitmentScheme, Rotation, VerifierQuery},
    transcript::{read_n, Hashable, Sampleable, Transcript},
    utils::arithmetic::compute_inner_product,
};

/// Given a plonk proof, this function parses it to extract the verifying trace.
/// This function computes all Fiat-Shamir challenges, with the exception of
/// `x`, which is computed in [verify_algebraic_constraints]
pub fn parse_trace<F, CS, T>(
    vk: &VerifyingKey<F, CS>,
    // Unlike the prover, the verifier gets their instances in two arguments:
    // committed and normal (non-committed). Note that the total number of
    // instance columns is expected to be the sum of committed instances and
    // normal instances for every proof. (Committed instances go first, that is,
    // the first instance columns are devoted to committed instances.)
    #[cfg(feature = "committed-instances")] committed_instances: &[&[CS::Commitment]],
    instances: &[&[&[F]]],
    transcript: &mut T,
) -> Result<VerifierTrace<F, CS>, Error>
where
    CS: PolynomialCommitmentScheme<F>,
    T: Transcript,
    F: WithSmallOrderMulGroup<3>
        + Hashable<T::Hash>
        + Sampleable<T::Hash>
        + FromUniformBytes<64>
        + Ord,
    CS::Commitment: Hashable<T::Hash>,
{
    #[cfg(not(feature = "committed-instances"))]
    let committed_instances: Vec<Vec<CS::Commitment>> = vec![vec![]; instances.len()];

    let nb_committed_instances = committed_instances[0].len();
    for committed_instances in committed_instances.iter() {
        if committed_instances.len() != nb_committed_instances {
            return Err(Error::InvalidInstances);
        }
    }

    // Check that total number of instances matches the expected number of instance columns
    for (committed_instances, instances) in committed_instances.iter().zip(instances.iter()) {
        if committed_instances.len() + instances.len() != vk.cs.num_instance_columns {
            return Err(Error::InvalidInstances);
        }
    }

    let num_proofs = instances.len();

    // Hash verification key into transcript
    vk.hash_into(transcript)?;

    for committed_instances in committed_instances.iter() {
        for commitment in committed_instances.iter() {
            transcript.common(commitment)?
        }
    }

    for instance in instances.iter() {
        for instance in instance.iter() {
            transcript.common(&F::from_u128(instance.len() as u128))?;
            for value in instance.iter() {
                transcript.common(value)?;
            }
        }
    }

    // Obtain the prover's advice commitments from the proof and squeeze challenges
    let (advice_commitments, challenges) = {
        let mut advice_commitments =
            vec![vec![CS::Commitment::default(); vk.cs.num_advice_columns]; num_proofs];
        let mut challenges = vec![F::ZERO; vk.cs.num_challenges];

        for current_phase in vk.cs.phases() {
            for advice_commitments in advice_commitments.iter_mut() {
                for (phase, commitment) in vk
                    .cs
                    .advice_column_phase
                    .iter()
                    .zip(advice_commitments.iter_mut())
                {
                    if current_phase == *phase {
                        *commitment = transcript.read()?;
                    }
                }
            }
            for (phase, challenge) in vk.cs.challenge_phase.iter().zip(challenges.iter_mut()) {
                if current_phase == *phase {
                    *challenge = transcript.squeeze_challenge();
                }
            }
        }

        (advice_commitments, challenges)
    };

    // Sample theta challenge for batching lookup columns
    let theta: F = transcript.squeeze_challenge();

    // Lookup argument: Read commitments to permuted input and table columns from the transcript
    let lookup_permuted_commitments = (0..num_proofs)
        .map(|_| -> Result<Vec<_>, _> {
            // Read each lookup permuted commitment from the transcript
            vk.cs
                .lookups
                .iter()
                .map(|argument| argument.read_permuted_commitments(transcript))
                .collect::<Result<Vec<_>, _>>()
        })
        .collect::<Result<Vec<_>, _>>()?;

    // Sample beta challenge for permutation argument
    let beta: F = transcript.squeeze_challenge();

    // Sample gamma challenge for permutation argument
    let gamma: F = transcript.squeeze_challenge();

    // Permutation argument: Read commitments to limbs of product polynomial from the transcript
    let permutation_product_commitments = (0..num_proofs)
        .map(|_| vk.cs.permutation.read_product_commitments(vk, transcript))
        .collect::<Result<Vec<_>, _>>()?;

    // Lookup argument: For each lookup, read commitments to product polynomial from the transcript
    let lookup_product_commitments = lookup_permuted_commitments
        .into_iter()
        .map(|lookups| {
            lookups
                .into_iter()
                .map(|lookup| lookup.read_product_commitment(transcript))
                .collect::<Result<Vec<_>, _>>()
        })
        .collect::<Result<Vec<_>, _>>()?;

    // Sample trash challenge
    let trash_challenge: F = transcript.squeeze_challenge();

    // Read commitments to trashcans from transcript
    let trashcan_commitments = (0..num_proofs)
        .map(|_| -> Result<Vec<_>, _> {
            vk.cs
                .trashcans
                .iter()
                .map(|argument| argument.read_committed::<CS, _>(transcript))
                .collect::<Result<Vec<_>, _>>()
        })
        .collect::<Result<Vec<_>, _>>()?;

    let vanishing = vanishing::Argument::read_commitments_before_y(transcript)?;

    // Sample identity batching challenge y, for batching all independent identities
    let y: F = transcript.squeeze_challenge();

    Ok(VerifierTrace {
        advice_commitments,
        vanishing,
        lookups: lookup_product_commitments,
        trashcans: trashcan_commitments,
        permutations: permutation_product_commitments,
        challenges,
        beta,
        gamma,
        theta,
        trash_challenge,
        y,
    })
}

/// Given a [VerifierTrace], this function computes the opening challenge, x,
/// and proceeds to verify the algebraic constraints with the claimed
/// evaluations. This function does not verify the PCS proof.
///
/// The verifier will error if there are trailing bits in the transcript.
pub fn verify_algebraic_constraints<F, CS: PolynomialCommitmentScheme<F>, T: Transcript>(
    vk: &VerifyingKey<F, CS>,
    trace: VerifierTrace<F, CS>,
    // Unlike the prover, the verifier gets their instances in two arguments:
    // committed and normal (non-committed). Note that the total number of
    // instance columns is expected to be the sum of committed instances and
    // normal instances for every proof. (Committed instances go first, that is,
    // the first instance columns are devoted to committed instances.)
    #[cfg(feature = "committed-instances")] committed_instances: &[&[CS::Commitment]],
    instances: &[&[&[F]]],
    transcript: &mut T,
) -> Result<CS::VerificationGuard, Error>
where
    F: WithSmallOrderMulGroup<3>
        + Hashable<T::Hash>
        + Sampleable<T::Hash>
        + FromUniformBytes<64>
        + Hash
        + Ord,
    CS::Commitment: Hashable<T::Hash>,
{
    #[cfg(not(feature = "committed-instances"))]
    let committed_instances: Vec<Vec<CS::Commitment>> = vec![vec![]; instances.len()];
    let nb_committed_instances = committed_instances[0].len();
    let num_proofs = instances.len();

    // Destructuring assignment of given verifier trace
    let VerifierTrace {
        advice_commitments,
        vanishing,
        lookups,
        trashcans,
        permutations,
        challenges,
        beta,
        gamma,
        theta,
        trash_challenge,
        y,
    } = trace;

    // Read commitments to limbs of the quotient polynomial h(X) = nu(X)/(X^n-1) from the transcript
    let vanishing = vanishing.read_commitments_after_y(vk, transcript)?;

    // Sample evaluation challenge x
    let x: F = transcript.squeeze_challenge();
    let xn = x.pow_vartime([vk.n()]);

    let instance_evals = {
        let (min_rotation, max_rotation) =
            vk.cs
                .instance_queries
                .iter()
                .fold((0, 0), |(min, max), (_, rotation)| {
                    if rotation.0 < min {
                        (rotation.0, max)
                    } else if rotation.0 > max {
                        (min, rotation.0)
                    } else {
                        (min, max)
                    }
                });
        let max_instance_len = instances
            .iter()
            .flat_map(|instance| instance.iter().map(|instance| instance.len()))
            .max_by(Ord::cmp)
            .unwrap_or_default();
        let l_i_s = &vk.domain.l_i_range(
            x,
            xn,
            -max_rotation..max_instance_len as i32 + min_rotation.abs(),
        );
        instances
            .iter()
            .map(|instances| {
                vk.cs
                    .instance_queries
                    .iter()
                    .map(|(column, rotation)| {
                        if column.index() < nb_committed_instances {
                            transcript.read()
                        } else {
                            let instances = instances[column.index() - nb_committed_instances];
                            let offset = (max_rotation - rotation.0) as usize;
                            Ok(compute_inner_product(
                                instances,
                                &l_i_s[offset..offset + instances.len()],
                            ))
                        }
                    })
                    .collect::<Result<Vec<_>, _>>()
            })
            .collect::<Result<Vec<_>, _>>()?
    };

    // Read evals of all advice polys from transcript
    let advice_evals = (0..num_proofs)
        .map(|_| -> Result<Vec<_>, _> { read_n(transcript, vk.cs.advice_queries.len()) })
        .collect::<Result<Vec<_>, _>>()?;

    // Read evals of all fixed polys from transcript (here, `fixed_evals` also includes
    // evals of simple selectors)
    let fixed_evals = read_n(transcript, vk.cs.fixed_queries.len())?;

    // TODO: consider getting h limbs from Constructed struct above and remove this
    let vanishing = vanishing.evaluate_after_x(transcript)?;

    // TODO: for constructing commitment to linearization polynomial
    let h_limb_commitments = vanishing.h_limb_commitments();
    let permutations_common = vk.permutation.evaluate(transcript)?;

    let permutation_evals = permutations
        .into_iter()
        .map(|permutation| permutation.evaluate(transcript))
        .collect::<Result<Vec<_>, _>>()?;

    let lookup_evals = lookups
        .into_iter()
        .map(|lookups| -> Result<Vec<_>, _> {
            lookups
                .into_iter()
                .map(|lookup| lookup.evaluate(transcript))
                .collect::<Result<Vec<_>, _>>()
        })
        .collect::<Result<Vec<_>, _>>()?;

    let trashcan_evals = trashcans
        .into_iter()
        .map(|trashcans| -> Result<Vec<_>, _> {
            trashcans
                .into_iter()
                .map(|trash| trash.evaluate(transcript))
                .collect::<Result<Vec<_>, _>>()
        })
        .collect::<Result<Vec<_>, _>>()?;

    fn construct_linearization_commitment<F: PrimeField, CS: PolynomialCommitmentScheme<F>>(
        vk: &VerifyingKey<F, CS>,
        expressions: Vec<(Option<usize>, F)>,
        y: F,
        xn: F,
        h_limb_commitments: &[CS::Commitment],
    ) -> CS::Commitment {
        // Construct commitment of the linearization polynomial
        // (which will be checked that it opens to 0 at x):
        //
        //  S_1*id_1(x) + y*S_2*id_2(x) + y^2*S_3*id_3(x) + ... + y^{k-1}*S_k*id_k(x)
        //        - (h_0 + x^n*h_1 + x^{2n}*h_2 + ... + x^{l*n}*h_l) * (x^n-1),
        //
        // where:
        // * S_i are the commitments to fixed columns corresponding to simple selectors
        // * id_i are the partially evaluated individual identities,
        // * h_j are the limbs of the quotient polynomial.

        let g1 = CS::get_generator().unwrap();

        // Construct commitment to linearized identities: LHS above
        let mut acc = g1.clone() * F::ZERO;
        for (idx, e) in expressions {
            let value = match idx {
                Some(column_index) => vk.fixed_commitments[column_index].clone() * e,
                None => g1.clone() * e,
            };
            acc = acc * y + value;
        }

        // Construct commitment to linearized h polynomial: RHS above
        // h_0 + x^n*h_1 + x^{2n}*h_2 + ... + x^{ln}*h_k,
        // where h_i are commitments to the limbs of the quotient polynomial
        let mut linearized_h = g1.clone() * F::ZERO;
        for (i, piece) in h_limb_commitments.iter().enumerate() {
            linearized_h = linearized_h + piece.clone() * xn.pow([i as u64]);
        }
        linearized_h = linearized_h * (xn - F::ONE);

        acc - linearized_h
    }

    // Partially evaluate batched identities
    // (without fixed columns corresponding to simple selectors)
    let xn = x.pow([vk.n()]);
    let nr_blinding_factors = vk.cs.nr_blinding_factors();
    let l_evals = vk
        .domain
        .l_i_range(x, xn, (-((nr_blinding_factors + 1) as i32))..=0);
    assert_eq!(l_evals.len(), 2 + nr_blinding_factors);
    let l_last = l_evals[0];
    let l_blind: F = l_evals[1..(1 + nr_blinding_factors)]
        .iter()
        .fold(F::ZERO, |acc, eval| acc + eval);
    let l_0 = l_evals[1 + nr_blinding_factors];

    let mut evaluated_expressions = Vec::new();
    for ((((advice_evals, instance_evals), permutation_evals), lookup_evals), trashcan_evals) in
        advice_evals
            .iter()
            .zip(instance_evals.iter())
            .zip(permutation_evals.iter())
            .zip(lookup_evals.iter())
            .zip(trashcan_evals.iter())
    {
        let challenges = &challenges;
        let fixed_evals = &fixed_evals;
        // (Partially) evaluate polys from (custom) gates
        for (idx, e) in vk.cs.gates.iter().flat_map(move |gate| {
            gate.polynomials().iter().map(move |poly| {
                let evaluation = poly.evaluate(
                    &|scalar| scalar,
                    &|_| panic!("virtual selectors are removed during optimization"),
                    // Partially evaluate all gate polys with simple selectors
                    &|query| {
                        if vk
                            .cs
                            .indices_simple_selectors
                            // Here, we need the *column* index of the fixed column
                            // corresponding to the simple selector
                            .contains(&query.column_index())
                        {
                            F::ONE
                        } else {
                            fixed_evals[query.index.unwrap()]
                        }
                    },
                    &|query| advice_evals[query.index.unwrap()],
                    &|query| instance_evals[query.index.unwrap()],
                    &|challenge| challenges[challenge.index()],
                    &|a| -a,
                    &|a, b| a + &b,
                    &|a, b| a * &b,
                    &|a, scalar| a * &scalar,
                );
                (gate.simple_selector_index(), evaluation)
            })
        }) {
            evaluated_expressions.push((idx, e))
        }

        // Evaluate polys from permutation argument
        for e in permutation_evals.expressions(
            vk,
            &vk.cs.permutation,
            &permutations_common,
            advice_evals,
            fixed_evals,
            instance_evals,
            l_0,
            l_last,
            l_blind,
            beta,
            gamma,
            x,
        ) {
            evaluated_expressions.push((None, e))
        }

        // Evaluate polys from lookup argument
        for e in lookup_evals
            .iter()
            .zip(vk.cs.lookups.iter())
            .flat_map(move |(p, argument)| {
                p.expressions(
                    l_0,
                    l_last,
                    l_blind,
                    argument,
                    theta,
                    beta,
                    gamma,
                    advice_evals,
                    fixed_evals,
                    instance_evals,
                    challenges,
                )
            })
        {
            evaluated_expressions.push((None, e))
        }

        // Evaluate polys from trashcan
        for e in trashcan_evals
            .iter()
            .zip(vk.cs.trashcans.iter())
            .flat_map(move |(p, argument)| {
                p.expressions(
                    argument,
                    trash_challenge,
                    advice_evals,
                    fixed_evals,
                    instance_evals,
                    challenges,
                )
            })
        {
            evaluated_expressions.push((None, e))
        }
    }

    let t = std::time::Instant::now();
    let linearization_commitment =
        construct_linearization_commitment(vk, evaluated_expressions, y, xn, h_limb_commitments);
    println!(
        "Linearization commitment built in {:?} ms",
        format_args!("{:.1}", t.elapsed().as_secs_f32() * 1000.0)
    );

    // Collect queries that are checked in multi-open argument: queries corresponding
    // to simple-selectors need not be checked
    let queries = committed_instances
        .iter()
        .zip(instance_evals.iter())
        .zip(advice_commitments.iter())
        .zip(advice_evals.iter())
        .zip(permutation_evals.iter())
        .zip(lookup_evals.iter())
        .zip(trashcan_evals.iter())
        .flat_map(
            |(
                (
                    (
                        (((committed_instances, instance_evals), advice_commitments), advice_evals),
                        permutation,
                    ),
                    lookups,
                ),
                trash,
            )| {
                iter::empty()
                    .chain(vk.cs.instance_queries.iter().enumerate().filter_map(
                        move |(query_index, &(column, at))| {
                            if column.index() < nb_committed_instances {
                                Some(VerifierQuery::new(
                                    vk.domain.rotate_omega(x, at),
                                    &committed_instances[column.index()],
                                    instance_evals[query_index],
                                ))
                            } else {
                                None
                            }
                        },
                    ))
                    .chain(vk.cs.advice_queries.iter().enumerate().map(
                        move |(query_index, &(column, at))| {
                            VerifierQuery::new(
                                vk.domain.rotate_omega(x, at),
                                &advice_commitments[column.index()],
                                advice_evals[query_index],
                            )
                        },
                    ))
                    .chain(permutation.queries(vk, x))
                    .chain(lookups.iter().flat_map(move |p| p.queries(vk, x)))
                    .chain(trash.iter().flat_map(move |p| p.queries(x)))
            },
        )
        .chain(
            vk.cs
                .fixed_queries
                .iter()
                .enumerate()
                // TODO: filter out queries for fixed columns corresponding to
                // simple selectors
                .filter(|(_, (col, _))| !vk.cs.indices_simple_selectors.contains(&col.index()))
                .map(|(query_index, &(column, at))| {
                    VerifierQuery::new(
                        vk.domain.rotate_omega(x, at),
                        // fixed_commitments is sorted per column_index
                        &vk.fixed_commitments[column.index()],
                        // `fixed_evals` is indexed according to `fixed_queries`
                        fixed_evals[query_index],
                    )
                }),
        )
        .chain(permutations_common.queries(&vk.permutation, x))
        // TODO: add query for linearization poly
        .chain(iter::once(VerifierQuery::new(
            vk.domain.rotate_omega(x, Rotation::cur()),
            &linearization_commitment,
            F::ZERO,
        )))
        .collect::<Vec<_>>();
    // TODO: don't need random poly?! Saving commitment+eval in trace
    // .chain(vanishing.queries(x, vk.n()))

    // We are now convinced the circuit is satisfied so long as the
    // polynomial commitments open to the correct values.
    CS::multi_prepare(&queries, transcript).map_err(|_| Error::Opening)
}

/// Prepares a plonk proof into a PCS instance that can be finalized or
/// batched. It is responsibility of the verifier to check the validity of the
/// instance columns.
///
/// The verifier will error if there are trailing bytes in the transcript.
pub fn prepare<F, CS: PolynomialCommitmentScheme<F>, T: Transcript>(
    vk: &VerifyingKey<F, CS>,
    // Unlike the prover, the verifier gets their instances in two arguments:
    // committed and normal (non-committed). Note that the total number of
    // instance columns is expected to be the sum of committed instances and
    // normal instances for every proof. (Committed instances go first, that is,
    // the first instance columns are devoted to committed instances.)
    #[cfg(feature = "committed-instances")] committed_instances: &[&[CS::Commitment]],
    instances: &[&[&[F]]],
    transcript: &mut T,
) -> Result<CS::VerificationGuard, Error>
where
    F: WithSmallOrderMulGroup<3>
        + Hashable<T::Hash>
        + Sampleable<T::Hash>
        + FromUniformBytes<64>
        + Hash
        + Ord,
    CS::Commitment: Hashable<T::Hash>,
{
    let trace = parse_trace(
        vk,
        #[cfg(feature = "committed-instances")]
        committed_instances,
        instances,
        transcript,
    )?;

    verify_algebraic_constraints(
        vk,
        trace,
        #[cfg(feature = "committed-instances")]
        committed_instances,
        instances,
        transcript,
    )
}
