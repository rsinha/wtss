//! An end-to-end example of using the SP1 SDK to generate a proof of a program that can have an
//! EVM-Compatible proof generated which can be verified on-chain.
//!
//! You can run this script using the following command:
//! ```shell
//! RUST_LOG=info cargo run --release
//! ```

use alloy_sol_types::SolType;
use serde::{Deserialize, Serialize};
use serde_hex::{SerHex, StrictPfx};
use sp1_sdk::{include_elf, HashableKey, SP1ProofWithPublicValues, SP1VerifyingKey};

use ab_rotation_lib::PublicValuesStruct;
use ab_rotation_script::{construct_genesis_proof, construct_rotation_proof};

use std::path::PathBuf;

/// The ELF (executable and linkable format) file for the Succinct RISC-V zkVM.
pub const AB_ROTATION_ELF: &[u8] = include_elf!("ab-rotation-program");

/// A fixture that can be used to test the verification of SP1 zkVM proofs inside Solidity.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
struct SP1ABRotationProofFixture {
    #[serde(with = "SerHex::<StrictPfx>")]
    ab_genesis_hash: [u8; 32],
    #[serde(with = "SerHex::<StrictPfx>")]
    ab_curr_hash: [u8; 32],
    #[serde(with = "SerHex::<StrictPfx>")]
    ab_next_hash: [u8; 32],
    #[cfg(feature = "with_bls_aggregate")]
    #[serde(with = "SerHex::<StrictPfx>")]
    bls_aggregate_key: [u8; 48],
    vkey: String,
    public_values: String,
    proof: String,
}

fn main() {
    // Setup the logger.
    sp1_sdk::utils::setup_logger();

    // AB 0 (genesis AB)
    let genesis_validators = ab_rotation_lib::signers::gen_validators::<5>();
    let ab_genesis = genesis_validators.verifying_keys_with_weights_for_in([1; 5]);
    let ab_genesis_hash = ab_rotation_lib::address_book::serialize_and_digest_sha256(&ab_genesis);

    // AB 1
    let validators_1 = ab_rotation_lib::signers::gen_validators::<5>();
    let ab_1 = validators_1.verifying_keys_with_weights_for_in([1; 5]);

    // proof for AB 0 (genesis AB)
    let genesis_signatures: ab_rotation_lib::address_book::Signatures =
        ab_rotation_lib::address_book::Signatures(
            genesis_validators
                .all_sign(
                    5,
                    &ab_rotation_script::rotation_message(
                        &ab_1,
                        #[cfg(feature = "with_bls_aggregate")]
                        [0u8; 48],
                    ),
                )
                .to_vec()
                .into(),
        );
    let genesis_proof = construct_genesis_proof(
        AB_ROTATION_ELF,
        &ab_genesis,
        &ab_1,
        &genesis_signatures,
        &[0u8; 48],
    );

    let mut prev_ab = ab_1;
    let mut prev_proof = genesis_proof;
    let mut prev_validators = validators_1;

    for _day in 0..2 {
        let next_validators = ab_rotation_lib::signers::gen_validators::<5>();
        let next_ab = next_validators.verifying_keys_with_weights_for_in([1; 5]);
        #[cfg(feature = "with_bls_aggregate")]
        let bls_aggregate_key = [0; 48];

        let signatures: ab_rotation_lib::address_book::Signatures =
            ab_rotation_lib::address_book::Signatures(
                prev_validators
                    .all_sign(
                        5,
                        &ab_rotation_script::rotation_message(
                            &next_ab,
                            #[cfg(feature = "with_bls_aggregate")]
                            bls_aggregate_key,
                        ),
                    )
                    .to_vec()
                    .into(),
            );

        let next_proof = construct_rotation_proof(
            AB_ROTATION_ELF,
            &ab_genesis_hash,
            &prev_ab,
            &next_ab,
            prev_proof,
            #[cfg(feature = "with_bls_aggregate")]
            &bls_aggregate_key,
            &signatures,
        );

        prev_proof = next_proof;
        prev_ab = next_ab;
        prev_validators = next_validators;
    }
}

/// Create a fixture for the given proof.
fn _create_proof_fixture(proof: &SP1ProofWithPublicValues, vk: &SP1VerifyingKey, name: &str) {
    // Deserialize the public values.
    let bytes = proof.public_values.as_slice();
    let PublicValuesStruct {
        ab_genesis_hash,
        ab_curr_hash,
        ab_next_hash,
        #[cfg(feature = "with_bls_aggregate")]
        bls_aggregate_key,
    } = PublicValuesStruct::abi_decode(bytes, true).unwrap();

    // Create the testing fixture so we can test things end-to-end.
    let fixture = SP1ABRotationProofFixture {
        ab_genesis_hash: *ab_genesis_hash,
        ab_curr_hash: *ab_curr_hash,
        ab_next_hash: *ab_next_hash,
        #[cfg(feature = "with_bls_aggregate")]
        bls_aggregate_key: bls_aggregate_key.to_vec().try_into().unwrap(),
        vkey: vk.bytes32().to_string(),
        public_values: format!("0x{}", hex::encode(bytes)),
        proof: format!("0x{}", hex::encode(proof.bytes())),
    };

    // The verification key is used to verify that the proof corresponds to the execution of the
    // program on the given input.
    //
    // Note that the verification key stays the same regardless of the input.
    println!("Verification Key: {}", fixture.vkey);

    // The public values are the values which are publicly committed to by the zkVM.
    //
    // If you need to expose the inputs or outputs of your program, you should commit them in
    // the public values.
    println!("Public Values: {}", fixture.public_values);

    // The proof proves to the verifier that the program was executed with some inputs that led to
    // the give public values.
    println!("Proof Bytes: {}", fixture.proof);

    // Save the fixture to a file.
    let fixture_path = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../contracts/src/fixtures");
    std::fs::create_dir_all(&fixture_path).expect("failed to create fixture path");
    std::fs::write(
        fixture_path.join(
            format!(
                "{}-fixture{}.json",
                name,
                if cfg!(feature = "with_bls_aggregate") {
                    "-with_bls_aggregate"
                } else {
                    ""
                }
            )
            .to_lowercase(),
        ),
        serde_json::to_string_pretty(&fixture).unwrap(),
    )
    .expect("failed to write fixture");
}
