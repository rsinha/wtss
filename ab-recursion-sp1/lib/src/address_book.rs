use derive_more::derive::Deref;
use serde::{Deserialize, Serialize};
use serde_big_array::Array;
use smallvec::SmallVec;

use crate::ed25519;

#[cfg(feature = "with_bls_aggregate")]
pub type BlsPublicKey = [u8; 48];
pub type Weight = u64;

pub const MAXIMUM_VALIDATORS: usize = 64;

#[derive(Debug, Clone, Copy, Serialize, Deserialize)]
pub struct AddressBookEntry {
    pub ed25519_public_key: Array<u8, { ed25519::PUBLIC_KEY_LENGTH }>,
    #[cfg(feature = "with_bls_aggregate")]
    pub bls_public_key: Array<u8, 48>,
    pub weight: Weight,
}

#[repr(transparent)]
#[derive(Debug, Deref, Clone, Serialize, Deserialize)]
pub struct AddressBook(pub SmallVec<[AddressBookEntry; MAXIMUM_VALIDATORS]>);

pub fn digest_sha256(data: impl AsRef<[u8]>) -> [u8; 32] {
    use sha2::{Digest, Sha256};

    // create a Sha256 object
    let mut hasher = Sha256::new();

    // write input message
    hasher.update(data.as_ref());

    // read hash digest and consume hasher
    let result: [u8; 32] = hasher.finalize().into();

    result
}

pub fn serialize_and_digest_sha256(data: &impl serde::Serialize) -> [u8; 32] {
    // NOTE: uses the same `bincode` as the `sp1_zkvm::io::read` and family
    let data_bytes = bincode::serialize(data).unwrap();

    digest_sha256(data_bytes)
}
