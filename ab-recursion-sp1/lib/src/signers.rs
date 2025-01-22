//! Mainly used for testing purposes

use serde_big_array::Array;
use smallvec::SmallVec;

use crate::{
    address_book::{AddressBook, AddressBookEntry},
    ed25519::Signature,
};

#[derive(Debug)]
#[repr(transparent)]
pub struct SigningKeys<const N: usize>([ed25519_dalek::SigningKey; N]);

impl<const N: usize> SigningKeys<N> {
    pub fn verifying_key(&self, i: usize) -> [u8; ed25519_dalek::PUBLIC_KEY_LENGTH] {
        *self.0[i].verifying_key().as_bytes()
    }

    pub fn verifying_keys(&self) -> [[u8; ed25519_dalek::PUBLIC_KEY_LENGTH]; N] {
        core::array::from_fn(|i| self.verifying_key(i))
    }

    pub fn verifying_keys_with_weights(&self, weights: [u64; N]) -> [AddressBookEntry; N] {
        let verifying_keys = self.verifying_keys();
        core::array::from_fn(|i| AddressBookEntry {
            ed25519_public_key: Array(verifying_keys[i]),
            weight: weights[i],
        })
    }

    pub fn verifying_keys_with_weights_for_in(&self, weights: [u64; N]) -> AddressBook {
        AddressBook(SmallVec::from_vec(
            self.verifying_keys_with_weights(weights).to_vec(),
        ))
    }

    pub fn all_sign(
        &self,
        signers: impl Into<Signers<N>>,
        message: &[u8],
    ) -> [Option<Signature>; N] {
        use ed25519_dalek::ed25519::signature::Signer;
        let signers: [bool; N] = signers.into().0;
        core::array::from_fn(|i| {
            signers[i]
                .then_some(Array(self.0[i].sign(message).to_bytes()))
                .map(Signature)
        })
    }
}

pub struct Signers<const N: usize>(pub [bool; N]);

impl<const N: usize> From<usize> for Signers<N> {
    fn from(n: usize) -> Self {
        assert!(n <= N, "Cannot sign with more validators than available");
        let mut signers = [false; N];
        (0..n).for_each(|i| {
            signers[i] = true;
        });
        Self(signers)
    }
}

impl<const N: usize> From<&[usize]> for Signers<N> {
    fn from(indices: &[usize]) -> Self {
        let mut signers = [false; N];
        for &idx in indices {
            assert!(idx < N, "Validator index out of bounds");
            signers[idx] = true;
        }
        Self(signers)
    }
}

pub fn gen_validators<const N: usize>() -> SigningKeys<N> {
    let mut csprng = rand::rngs::OsRng;
    let keys = std::array::from_fn(|_| ed25519_dalek::SigningKey::generate(&mut csprng));
    SigningKeys(keys)
}
