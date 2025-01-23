// TODO: better error types
#![allow(clippy::result_unit_err)]

use alloy_sol_types::sol;

pub mod address_book;
pub mod ed25519;
pub mod statement;

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
