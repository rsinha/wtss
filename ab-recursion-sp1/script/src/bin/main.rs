//! An end-to-end example of using the SP1 SDK to generate a proof of a program that can have an
//! EVM-Compatible proof generated which can be verified on-chain.
//!
//! You can run this script using the following command:
//! ```shell
//! RUST_LOG=info cargo run --release
//! ```

use serde::{Deserialize, Serialize};
use serde_hex::{SerHex, StrictPfx};
use sp1_sdk::include_elf;

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
    #[serde(with = "SerHex::<StrictPfx>")]
    tss_vk_next_hash: [u8; 32],
    vkey: String,
    public_values: String,
    proof: String,
}

#[derive(Debug, Clone)]
pub struct Roster {
    pub verifying_keys: Vec<Vec<u8>>,
    pub signing_keys: Vec<Vec<u8>>,
    pub weights: Vec<u64>,
}

impl Roster {
    pub fn new(n: usize) -> Self {
        let mut verifying_keys = Vec::new();
        let mut signing_keys = Vec::new();
        let weights = vec![1u64; n];

        for _ in 0..n {
            let (sk, vk) = ab_rotation_script::keygen();
            signing_keys.push(sk);
            verifying_keys.push(vk);
        }

        Roster {
            verifying_keys,
            signing_keys,
            weights,
        }
    }

    pub fn subset_sign(&self, signers: &[bool], message: &[u8]) -> Vec<Option<Vec<u8>>> {
        let mut signatures = Vec::new();
        for (i, &active) in signers.iter().enumerate() {
            if active {
                signatures.push(Some(ab_rotation_script::sign(
                    &self.signing_keys[i],
                    message,
                )));
            } else {
                signatures.push(None);
            }
        }
        signatures
    }
}

fn main() {
    // Setup the logger.
    sp1_sdk::utils::setup_logger();

    let tss_vk_hash = [0u8; 32];

    // Setup the program.
    let (pk, vk) = ab_rotation_script::proof_setup(AB_ROTATION_ELF);

    // AB 0 (genesis AB)
    let genesis_committee = Roster::new(5);
    let genesis_ab_hash = ab_rotation_script::address_book_hash(
        genesis_committee.verifying_keys.clone(),
        genesis_committee.weights.clone(),
    );

    let genesis_proof = ab_rotation_script::construct_rotation_proof(
        &pk,
        &vk,
        &genesis_ab_hash,
        (
            genesis_committee.verifying_keys.clone(),
            genesis_committee.weights.clone(),
        ),
        (
            genesis_committee.verifying_keys.clone(),
            genesis_committee.weights.clone(),
        ),
        None as Option<Vec<u8>>,
        &[0u8; 32],
        genesis_committee.subset_sign(
            &[true; 5],
            &ab_rotation_script::rotation_message(&genesis_ab_hash, &tss_vk_hash),
        ),
    );

    let mut prev_proof = genesis_proof;
    let mut prev_roster = genesis_committee;

    // simulate a few rotations
    for day in 0..15 {
        assert!(ab_rotation_script::verify_proof(&vk, &prev_proof));

        let next_roster = if day % 2 == 0 {
            Roster::new(5)
        } else {
            prev_roster.clone()
        };
        let next_roster_hash = ab_rotation_script::address_book_hash(
            next_roster.verifying_keys.clone(),
            next_roster.weights.clone(),
        );

        let next_proof = ab_rotation_script::construct_rotation_proof(
            &pk,
            &vk,
            &genesis_ab_hash,
            (
                prev_roster.verifying_keys.clone(),
                prev_roster.weights.clone(),
            ),
            (
                next_roster.verifying_keys.clone(),
                next_roster.weights.clone(),
            ),
            Some(prev_proof),
            &[0u8; 32],
            prev_roster.subset_sign(
                &[true; 5],
                &ab_rotation_script::rotation_message(&next_roster_hash, &tss_vk_hash),
            ),
        );

        prev_proof = next_proof;
        prev_roster = next_roster;
    }
}

// /// Create a fixture for the given proof.
// fn _create_proof_fixture(proof: &SP1ProofWithPublicValues, vk: &SP1VerifyingKey, name: &str) {
//     // Deserialize the public values.
//     let bytes = proof.public_values.as_slice();
//     let PublicValuesStruct {
//         ab_genesis_hash,
//         ab_curr_hash,
//         ab_next_hash,
//         tss_vk_hash,
//     } = PublicValuesStruct::abi_decode(bytes, true).unwrap();

//     // Create the testing fixture so we can test things end-to-end.
//     let fixture = SP1ABRotationProofFixture {
//         ab_genesis_hash: *ab_genesis_hash,
//         ab_curr_hash: *ab_curr_hash,
//         ab_next_hash: *ab_next_hash,
//         tss_vk_next_hash: *tss_vk_hash,
//         vkey: vk.bytes32().to_string(),
//         public_values: format!("0x{}", hex::encode(bytes)),
//         proof: format!("0x{}", hex::encode(proof.bytes())),
//     };

//     // The verification key is used to verify that the proof corresponds to the execution of the
//     // program on the given input.
//     //
//     // Note that the verification key stays the same regardless of the input.
//     println!("Verification Key: {}", fixture.vkey);

//     // The public values are the values which are publicly committed to by the zkVM.
//     //
//     // If you need to expose the inputs or outputs of your program, you should commit them in
//     // the public values.
//     println!("Public Values: {}", fixture.public_values);

//     // The proof proves to the verifier that the program was executed with some inputs that led to
//     // the give public values.
//     println!("Proof Bytes: {}", fixture.proof);

//     // Save the fixture to a file.
//     let fixture_path =
//         std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../contracts/src/fixtures");
//     std::fs::create_dir_all(&fixture_path).expect("failed to create fixture path");
//     std::fs::write(
//         fixture_path.join(format!("{}-fixture.json", name).to_lowercase()),
//         serde_json::to_string_pretty(&fixture).unwrap(),
//     )
//     .expect("failed to write fixture");
// }
