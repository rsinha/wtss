pub mod raps;

use alloy_sol_types::SolType;
use raps::RAPS;
use smallvec::SmallVec;
use sp1_sdk::{ProverClient, SP1ProofWithPublicValues, SP1ProvingKey, SP1VerifyingKey};

use ab_rotation_lib::address_book::Signatures;

pub use ab_rotation_lib::address_book::AddressBook;
pub use ab_rotation_lib::ed25519::{Signature, SigningKey, VerifyingKey};
pub use ab_rotation_lib::PublicValuesStruct;

/// outputs the byte array for the signing key,
/// followed by the byte array for the verifying key
pub fn keygen() -> (Vec<u8>, Vec<u8>) {
    let (sk, vk) = RAPS::keygen();
    (sk.to_bytes().to_vec(), vk.to_bytes().to_vec())
}

pub fn sign(sk: impl AsRef<[u8]>, message: impl AsRef<[u8]>) -> Vec<u8> {
    let sk = SigningKey::from_bytes(sk.as_ref().try_into().unwrap());
    sk.sign(message.as_ref()).0.to_vec()
}

pub fn address_book_hash(verifying_keys: Vec<impl AsRef<[u8]>>, weights: Vec<u64>) -> [u8; 32] {
    let ab = build_address_book(verifying_keys, weights);
    ab_rotation_lib::address_book::serialize_and_digest_sha256(&ab)
}

pub fn rotation_message(ab_hash: &[u8; 32], tss_vk_hash: &[u8; 32]) -> Vec<u8> {
    let message = [ab_hash.as_slice(), tss_vk_hash.as_slice()]
        .into_iter()
        .flatten()
        .copied()
        .collect::<Vec<_>>();

    message
}

pub fn proof_setup(zkvm_elf: impl AsRef<[u8]>) -> (Vec<u8>, Vec<u8>) {
    // Setup the prover client.
    let client = ProverClient::new();

    // Setup the program.
    let (pk, vk) = client.setup(zkvm_elf.as_ref());

    let mut pk_buf: Vec<u8> = Vec::new();
    bincode::serialize_into(&mut pk_buf, &pk).expect("failed to serialize pk");

    let mut vk_buf: Vec<u8> = Vec::new();
    bincode::serialize_into(&mut vk_buf, &vk).expect("failed to serialize vk");

    (pk_buf, vk_buf)
}

#[allow(clippy::too_many_arguments)]
pub fn construct_rotation_proof(
    pk: impl AsRef<[u8]>,                       // proving key output by sp1 setup
    vk: impl AsRef<[u8]>,                       // verifying key output by sp1 setup
    ab_genesis_hash: &[u8; 32],                 // genesis AddressBook hash
    ab_curr: (Vec<impl AsRef<[u8]>>, Vec<u64>), // current AddressBook
    ab_next: (Vec<impl AsRef<[u8]>>, Vec<u64>), // next AddressBook
    prev_proof: Option<impl AsRef<[u8]>>,       // the previous proof
    tss_vk_hash: &[u8; 32],                     // TSS verification key for the next AddressBook
    signatures: Vec<Option<impl AsRef<[u8]>>>,  // signatures attesting the next AddressBook
) -> Vec<u8> {
    let pk: SP1ProvingKey = bincode::deserialize(pk.as_ref()).expect("failed to deserialize pk");
    let vk: SP1VerifyingKey = bincode::deserialize(vk.as_ref()).expect("failed to deserialize vk");

    let ab_curr = build_address_book(ab_curr.0, ab_curr.1);
    let ab_next = build_address_book(ab_next.0, ab_next.1);

    let prev_proof: Option<SP1ProofWithPublicValues> = prev_proof
        .map(|p| bincode::deserialize(p.as_ref()).expect("failed to deserialize prev_proof"));

    let signatures = Signatures(SmallVec::from_vec(
        signatures
            .into_iter()
            .map(|s| s.map(|s| Signature(serde_big_array::Array(s.as_ref().try_into().unwrap()))))
            .collect(),
    ));

    let proof = RAPS::construct_rotation_proof(
        &pk,
        &vk,
        ab_genesis_hash,
        &ab_curr,
        &ab_next,
        prev_proof,
        tss_vk_hash,
        &signatures,
    );

    let mut proof_buf: Vec<u8> = Vec::new();
    bincode::serialize_into(&mut proof_buf, &proof).expect("failed to serialize proof");

    proof_buf
}

pub fn verify_proof(vk: impl AsRef<[u8]>, proof: impl AsRef<[u8]>) -> bool {
    let vk: SP1VerifyingKey = bincode::deserialize(vk.as_ref()).expect("failed to deserialize vk");
    let proof: SP1ProofWithPublicValues =
        bincode::deserialize(proof.as_ref()).expect("failed to deserialize proof");
    RAPS::verify_proof(&vk, &proof)
}

pub fn tss_vk_hash_from_proof(proof: impl AsRef<[u8]>) -> [u8; 32] {
    let proof: SP1ProofWithPublicValues =
        bincode::deserialize(proof.as_ref()).expect("failed to deserialize proof");
    let bytes = proof.public_values.as_slice();
    let pv = PublicValuesStruct::abi_decode(bytes, true).unwrap();
    pv.tss_vk_hash.0
}

fn build_address_book(verifying_keys: Vec<impl AsRef<[u8]>>, weights: Vec<u64>) -> AddressBook {
    let verifying_keys: Vec<VerifyingKey> = verifying_keys
        .into_iter()
        .map(|vk| VerifyingKey(vk.as_ref().try_into().unwrap()))
        .collect::<Vec<_>>();
    AddressBook::new(verifying_keys, weights)
}
