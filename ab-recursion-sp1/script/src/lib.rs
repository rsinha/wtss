use ab_rotation_lib::{address_book::AddressBook, address_book::Signatures, statement::Statement};
use sp1_sdk::SP1ProofWithPublicValues;

pub fn rotation_message(
    ab_next: &AddressBook,
    #[cfg(feature = "with_bls_aggregate")] bls_aggregate_key: [u8; 48],
) -> Vec<u8> {
    let ab_next_hash = ab_rotation_lib::address_book::serialize_and_digest_sha256(&ab_next);

    let message = [
        ab_next_hash.as_slice(),
        #[cfg(feature = "with_bls_aggregate")]
        bls_aggregate_key.as_slice(),
    ]
    .into_iter()
    .flatten()
    .copied()
    .collect::<Vec<_>>();

    message
}

pub fn generate_statement(
    ab_genesis_hash: [u8; 32],
    prev_proof: Option<&SP1ProofWithPublicValues>,
    vk_digest: [u32; 8],
    ab_curr: &AddressBook,
    ab_next: &AddressBook,
    signatures: &Signatures,
    #[cfg(feature = "with_bls_aggregate")] bls_aggregate_key: [u8; 48],
) -> ([u8; 32], [u8; 32], Statement) {
    let ab_next_hash = ab_rotation_lib::address_book::serialize_and_digest_sha256(&ab_next);
    let ab_curr_hash = ab_rotation_lib::address_book::serialize_and_digest_sha256(&ab_curr);

    let ab_prev_hash = prev_proof.map(|prev_proof| {
        // HACK: cannot cleanly `Deserialize` into `PublicValues`
        let prev_proof = bincode::deserialize::<([u8; 32], [u8; 32], [u8; 32])>(
            &prev_proof.public_values.to_vec(),
        )
        .unwrap();
        println!("Info from prev_proof:");
        println!("ab_genesis_hash: 0x{}", hex::encode(prev_proof.0));
        println!("ab_curr_hash:    0x{}", hex::encode(prev_proof.1));
        println!("ab_next_hash:    0x{}", hex::encode(prev_proof.2));
        prev_proof.1
    });

    // we just copy this over
    let signatures = signatures.clone();

    let statement = Statement {
        vk_digest,
        ab_genesis_hash,
        ab_prev_hash,
        ab_curr: ab_curr.clone(),
        ab_next_hash,
        #[cfg(feature = "with_bls_aggregate")]
        bls_aggregate_key: serde_big_array::Array(bls_aggregate_key),
        signatures,
    };

    (ab_curr_hash, ab_next_hash, statement)
}
