use serde::{Deserialize, Serialize};
#[cfg(feature = "with_bls_aggregate")]
use serde_big_array::Array;

use crate::{address_book::AddressBook, address_book::Signatures};

#[derive(Debug, Serialize, Deserialize)]
pub struct Statement {
    pub vk_digest: [u32; 8],
    pub ab_genesis_hash: [u8; 32],
    pub ab_prev_hash: Option<[u8; 32]>,
    pub ab_curr: AddressBook,
    pub ab_next_hash: [u8; 32],
    #[cfg(feature = "with_bls_aggregate")]
    pub bls_aggregate_key: Array<u8, 48>,
    pub signatures: Signatures,
}
