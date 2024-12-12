use derive_more::derive::Deref;
use serde::{Deserialize, Serialize};
use serde_big_array::Array;
use smallvec::SmallVec;

use crate::address_book::MAXIMUM_VALIDATORS;

#[repr(transparent)]
#[derive(Debug, Deref)]
pub struct VerifyingKey(pub ed25519_dalek::VerifyingKey);

pub const PUBLIC_KEY_LENGTH: usize = ed25519_dalek::PUBLIC_KEY_LENGTH;
pub const SIGNATURE_LENGTH: usize = ed25519_dalek::SIGNATURE_LENGTH;

impl VerifyingKey {
    pub fn from_bytes(bytes: &[u8; PUBLIC_KEY_LENGTH]) -> Result<Self, ()> {
        ed25519_dalek::VerifyingKey::from_bytes(bytes)
            .map(Self)
            .map_err(|_| ())
    }
}

///////////

#[repr(transparent)]
#[derive(Debug, Deref, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
pub struct Signature(pub Array<u8, { SIGNATURE_LENGTH }>);
#[repr(transparent)]
#[derive(Debug, Deref, Clone, Serialize, Deserialize)]
pub struct Signatures(pub SmallVec<[Option<Signature>; MAXIMUM_VALIDATORS]>);
