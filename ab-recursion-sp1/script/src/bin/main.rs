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
use smallvec::ToSmallVec;
use sp1_sdk::{include_elf, HashableKey, SP1ProofWithPublicValues, SP1VerifyingKey};

use ab_rotation_lib::{
    address_book::{AddressBook, Signatures},
    ed25519::{self, Signature, SigningKey, VerifyingKey},
    PublicValuesStruct,
};
use ab_rotation_script::raps::RAPS;

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

fn generate_signers<const N: usize>() -> ([SigningKey; N], [VerifyingKey; N]) {
    let keys: [(SigningKey, VerifyingKey); N] = std::array::from_fn(|_| RAPS::keygen());
    let signing_keys: [SigningKey; N] = keys.clone().map(|sk| sk.0);
    let verifying_keys: [VerifyingKey; N] = keys.map(|sk| sk.1);

    (signing_keys, verifying_keys)
}

fn subset_sign<const N: usize>(
    signing_keys: &[ed25519::SigningKey; N],
    signers: &[bool; N],
    message: &[u8],
) -> [Option<Signature>; N] {
    core::array::from_fn(|i| signers[i].then_some(signing_keys[i].sign(message)))
}

fn main() {
    // Setup the logger.
    sp1_sdk::utils::setup_logger();

    // Setup the program.
    let (pk, vk) = RAPS::proof_setup(AB_ROTATION_ELF);

    // AB 0 (genesis AB)
    // let genesis_validators = ab_rotation_lib::signers::gen_validators::<5>();
    // let ab_genesis = genesis_validators.verifying_keys_with_weights_for_in([1; 5]);
    let (genesis_signing_keys, genesis_verifying_keys) = generate_signers::<5>();
    let ab_genesis = AddressBook::new::<5>(
        core::array::from_fn(|i| genesis_verifying_keys[i].to_bytes()),
        [1; 5],
    );

    // AB 1
    // let validators_1 = ab_rotation_lib::signers::gen_validators::<5>();
    // let ab_1 = validators_1.verifying_keys_with_weights_for_in([1; 5]);
    let (signing_keys_1, verifying_keys_1) = generate_signers::<5>();
    let ab_1 = AddressBook::new::<5>(
        core::array::from_fn(|i| verifying_keys_1[i].to_bytes()),
        [1; 5],
    );

    let genesis_signatures = subset_sign(
        &genesis_signing_keys,
        &[true; 5],
        &RAPS::rotation_message(
            &ab_1,
            #[cfg(feature = "with_bls_aggregate")]
            [0u8; 48],
        ),
    );

    let genesis_proof = RAPS::construct_genesis_proof(
        &pk,
        &vk,
        &ab_genesis,
        &ab_1,
        &Signatures(genesis_signatures.to_smallvec()),
        &[0u8; 48],
    );

    let ab_genesis_hash = ab_rotation_lib::address_book::serialize_and_digest_sha256(&ab_genesis);

    let mut prev_ab = ab_1;
    let mut prev_proof = genesis_proof;
    let mut prev_signing_keys = signing_keys_1;

    // simulate 10 rotations
    for _day in 0..10 {
        assert!(RAPS::verify_proof(&vk, &prev_proof));

        let (next_signing_keys, next_verifying_keys) = generate_signers::<5>();
        let next_ab = AddressBook::new::<5>(
            core::array::from_fn(|i| next_verifying_keys[i].to_bytes()),
            [1; 5],
        );

        let signatures = subset_sign(
            &prev_signing_keys,
            &[true; 5],
            &RAPS::rotation_message(
                &next_ab,
                #[cfg(feature = "with_bls_aggregate")]
                [0u8; 48],
            ),
        );

        let next_proof = RAPS::construct_rotation_proof(
            &pk,
            &vk,
            &ab_genesis_hash,
            &prev_ab,
            &next_ab,
            prev_proof,
            #[cfg(feature = "with_bls_aggregate")]
            &[0u8; 48],
            &Signatures(signatures.to_smallvec()),
        );

        prev_proof = next_proof;
        prev_ab = next_ab;
        prev_signing_keys = next_signing_keys;
    }
}

fn _ser_then_deser(proof: &SP1ProofWithPublicValues) -> SP1ProofWithPublicValues {
    let mut in_memory_proof_buffer: Vec<u8> = Vec::new();
    bincode::serialize_into(&mut in_memory_proof_buffer, &proof)
        .expect("failed to serialize proof");

    println!("serialized proof of len {}", in_memory_proof_buffer.len());

    let deserialized_proof: SP1ProofWithPublicValues =
        bincode::deserialize_from(&in_memory_proof_buffer[..]).expect("Failed to deserialize");

    deserialized_proof
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
    let fixture_path =
        std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../contracts/src/fixtures");
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
