//! An end-to-end example of using the SP1 SDK to generate a proof of a program that can have an
//! EVM-Compatible proof generated which can be verified on-chain.
//!
//! You can run this script using the following command:
//! ```shell
//! RUST_LOG=info cargo run --release
//! ```

use alloy_sol_types::SolType;
use clap::Parser;
use serde::{Deserialize, Serialize};
use serde_hex::{SerHex, StrictPfx};
use sp1_sdk::{
    include_elf, HashableKey, ProverClient, SP1ProofWithPublicValues, SP1Stdin, SP1VerifyingKey,
};

use ab_rotation_lib::PublicValuesStruct;
use ab_rotation_script::generate_statement;

use std::path::PathBuf;

/// The ELF (executable and linkable format) file for the Succinct RISC-V zkVM.
pub const AB_ROTATION_ELF: &[u8] = include_elf!("ab-rotation-program");

/// The number of validators that are created for the proving
// TODO: can be done with a runtime-known length
pub const VALIDATORS_COUNT: usize = 100;
// pub const SIGNATURES_COUNT: usize = (VALIDATORS_COUNT + 2) / 3;
pub const SIGNATURES_COUNT: usize = VALIDATORS_COUNT;

/// The arguments for the EVM command.
#[derive(Parser, Debug)]
#[clap(author, version, about, long_about = None)]
struct Args {
    // #[clap(long, value_enum, default_value_t = Nothing)]
    // system: Option<ProofSystem>,
}

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

    // Parse the command line arguments.
    let Args {} = Args::parse();

    // Setup the prover client.
    let client = ProverClient::new();

    // Setup the program.
    let (pk, vk) = client.setup(AB_ROTATION_ELF);

    // AB 0
    let genesis_validators = ab_rotation_lib::signers::gen_validators::<5>();
    let ab_genesis = genesis_validators.verifying_keys_with_weights_for_in([1; 5]);
    let ab_genesis_hash = ab_rotation_lib::address_book::serialize_and_digest_sha256(&ab_genesis);

    // AB 1
    let validators_1 = ab_rotation_lib::signers::gen_validators::<5>();
    let ab_1 = validators_1.verifying_keys_with_weights_for_in([1; 5]);
    #[cfg(feature = "with_bls_aggregate")]
    let ab_1_bls_aggregate_key = [0; 48];

    // AB 0 -> AB 1
    let (proof0to1, proof0to1plonk) = {
        let (ab_curr_hash_0to1, ab_next_hash_0to1, statement0to1) = generate_statement(
            &genesis_validators,
            ab_genesis_hash,
            None,
            vk.hash_u32(),
            &ab_genesis,
            &ab_1,
            #[cfg(feature = "with_bls_aggregate")]
            ab_1_bls_aggregate_key,
        );

        // Setup the inputs.
        let mut stdin = SP1Stdin::new();

        stdin.write(&statement0to1);

        println!("Hashes to be proved:");
        println!("ab_genesis_hash: 0x{}", hex::encode(ab_genesis_hash));
        println!("ab_curr_hash:    0x{}", hex::encode(ab_curr_hash_0to1));
        println!("ab_next_hash:    0x{}", hex::encode(ab_next_hash_0to1));

        // Generate the proofs
        let proof = client
            .prove(&pk, stdin.clone())
            .compressed()
            .run()
            .expect("failed to generate proof");

        let proof_plonk = client
            .prove(&pk, stdin)
            .plonk()
            .run()
            .expect("failed to generate plonk proof");

        (proof, proof_plonk)
    };

    create_proof_fixture(&proof0to1plonk, &vk, "0to1");

    // AB 2
    let validators_2 = ab_rotation_lib::signers::gen_validators::<5>();
    let ab_2 = validators_2.verifying_keys_with_weights_for_in([1; 5]);
    #[cfg(feature = "with_bls_aggregate")]
    let ab_2_bls_aggregate_key = [0; 48];

    // AB 1 -> AB 2
    let (_proof1to2, proof1to2plonk) = {
        let (ab_curr_hash_1to2, ab_next_hash_1to2, statement1to2) = generate_statement(
            &validators_1,
            ab_genesis_hash,
            Some(&proof0to1),
            vk.hash_u32(),
            &ab_1,
            &ab_2,
            #[cfg(feature = "with_bls_aggregate")]
            ab_2_bls_aggregate_key,
        );

        // Setup the inputs.
        let mut stdin = SP1Stdin::new();

        stdin.write(&statement1to2);
        stdin.write_proof(*proof0to1.proof.try_as_compressed().unwrap(), vk.vk.clone());

        println!("Hashes to be proved:");
        println!("ab_genesis_hash: 0x{}", hex::encode(ab_genesis_hash));
        println!("ab_curr_hash:    0x{}", hex::encode(ab_curr_hash_1to2));
        println!("ab_next_hash:    0x{}", hex::encode(ab_next_hash_1to2));

        // Generate the proofs
        let proof = client
            .prove(&pk, stdin.clone())
            .compressed()
            .run()
            .expect("failed to generate proof");

        let proof_plonk = client
            .prove(&pk, stdin)
            .plonk()
            .run()
            .expect("failed to generate plonk proof");

        (proof, proof_plonk)
    };

    create_proof_fixture(&proof1to2plonk, &vk, "1to2");
}

/// Create a fixture for the given proof.
fn create_proof_fixture(proof: &SP1ProofWithPublicValues, vk: &SP1VerifyingKey, name: &str) {
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
