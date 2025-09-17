use std::collections::HashMap;

use blake2b_simd::State as Blake2b;
use midnight_circuits::compact_std_lib::{self, MidnightCircuit};
use midnight_proofs::poly::kzg::params::ParamsKZG;
use midnight_zkir_parser::{IrSource, OffCircuitType};
use rand_chacha::rand_core::OsRng;

type F = midnight_curves::Fq;

fn main() {
    let ir_raw = r#"{
        "version": { "major": 3, "minor": 0 },
        "instructions": [
            { "op": "load", "type": "Field", "names": ["v0", "v1"] },
            { "op": "load", "type": "Bit", "names": ["b0"] },
            { "op": "load", "type": "Byte", "names": ["B0"] },
            { "op": "add", "output": "x", "vals": ["v0", "v1"] },
            { "op": "add", "output": "y", "vals": ["x", "v1"] },
            { "op": "assert_equal", "vals": ["x", "-0x01"] },
            { "op": "assert_equal", "vals": ["b0", "1"] },
            { "op": "assert_equal", "vals": ["0xFA", "B0"] },
            { "op": "mul", "output": "z", "vals": ["x", "x"] }
        ]
    }
    "#;

    let ir = IrSource::read(ir_raw);

    dbg!(compact_std_lib::cost_model(&ir));

    let k = MidnightCircuit::from_relation(&ir).min_k();
    let srs = ParamsKZG::unsafe_setup(k, OsRng);

    let vk = compact_std_lib::setup_vk(&srs, &ir);
    let pk = compact_std_lib::setup_pk(&ir, &vk);

    let instance = vec![];
    let witness = HashMap::from_iter(
        [
            ("v0".into(), OffCircuitType::Native(F::from(1))),
            ("v1".into(), OffCircuitType::Native(-F::from(2))),
            ("b0".into(), OffCircuitType::Bit(true)),
            ("B0".into(), OffCircuitType::Byte(0xFA)),
        ]
        .into_iter(),
    );

    let proof = compact_std_lib::prove::<_, Blake2b>(&srs, &pk, &ir, &instance, witness, OsRng)
        .expect("Proof generation should not fail");

    assert!(compact_std_lib::verify::<IrSource, Blake2b>(
        &srs.verifier_params(),
        &vk,
        &instance,
        None,
        &proof
    )
    .is_ok())
}
