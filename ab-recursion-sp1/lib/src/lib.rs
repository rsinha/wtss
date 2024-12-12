// TODO: better error types
#![allow(clippy::result_unit_err)]

use alloy_sol_types::sol;

pub mod address_book;
pub mod ed25519;
pub mod signers;
pub mod statement;

use statement::Statement;

#[cfg(not(feature = "with_bls_aggregate"))]
sol! {
    /// The public values encoded as a struct that can be easily deserialized inside Solidity.
    #[derive(Debug)]
    struct PublicValuesStruct {
        bytes32 ab_genesis_hash;
        bytes32 ab_curr_hash;
        bytes32 ab_next_hash;
    }
}

#[cfg(feature = "with_bls_aggregate")]
sol! {
    /// The public values encoded as a struct that can be easily deserialized inside Solidity.
    #[derive(Debug)]
    struct PublicValuesStruct {
        bytes32 ab_genesis_hash;
        bytes32 ab_curr_hash;
        bytes32 ab_next_hash;
        bytes bls_aggregate_key;
    }
}

/// Calculates the total weight of the validators in the current AB
pub fn calculate_total_weight(statement: &Statement) -> u64 {
    statement.ab_curr.iter().map(|abe| abe.weight).sum()
}

/// Calculates the cumulative weight of the validators in the current AB
/// that have signed the next AB's hash
pub fn calculate_signers_weight(statement: &Statement, message: &[u8]) -> u64 {
    // NOTE: assumes that signatures are presented in the same order
    //       as the validators in the current AB
    core::iter::zip(statement.ab_curr.0.iter(), statement.signatures.0.iter()).fold(
        0,
        |acc, (abe, ms)| -> u64 {
            let added_weight = ms
                .as_ref()
                .map(|signature_bytes| {
                    let verifying_key =
                        <ed25519::VerifyingKey>::from_bytes(&abe.ed25519_public_key)
                            .expect("A valid ED25519 public key");
                    let signature = <ed25519_dalek::Signature>::from_bytes(signature_bytes);
                    verifying_key
                        .verify_strict(message, &signature)
                        .map(|_| abe.weight)
                        .expect("Invalid signature")
                })
                .unwrap_or(0);

            acc + added_weight
        },
    )
}
