use ab_rotation_lib::{address_book::AddressBook, address_book::Signatures, statement::Statement};
use sp1_sdk::{
    HashableKey, ProverClient, SP1ProofWithPublicValues, SP1ProvingKey, SP1Stdin, SP1VerifyingKey,
};

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

pub fn setup(zkvm_elf: &[u8]) -> (SP1ProvingKey, SP1VerifyingKey) {
    // Setup the prover client.
    let client = ProverClient::new();

    // Setup the program.
    let (pk, vk) = client.setup(zkvm_elf);

    (pk, vk)
}

pub fn verify_proof(vk: &SP1VerifyingKey, proof: &SP1ProofWithPublicValues) -> bool {
    let start_time = std::time::Instant::now();
    // Setup the prover client.
    let client = ProverClient::new();
    let verification = client.verify(proof, vk);
    println!("Proof verification took {:?}", start_time.elapsed());
    verification.is_ok()
}

/// Creates the first proof for the genesis AddressBook.
pub fn construct_genesis_proof(
    pk: &SP1ProvingKey,       // proving key output by sp1 setup
    vk: &SP1VerifyingKey,     // verifying key output by sp1 setup
    ab_genesis: &AddressBook, // genesis AddressBook
    ab_next: &AddressBook,    // next AddressBook
    signatures: &Signatures,  // signatures attesting the next AddressBook
    hints_vk: &[u8; 48],      // the BLS aggregate key for the next AddressBook
) -> SP1ProofWithPublicValues {
    // Setup the prover client.
    let client = ProverClient::new();

    let ab_genesis_hash = ab_rotation_lib::address_book::serialize_and_digest_sha256(&ab_genesis);

    let start_time = std::time::Instant::now();
    let (_, _, stmt) = generate_statement(
        ab_genesis_hash,
        None,
        vk.hash_u32(),
        ab_genesis,
        ab_next,
        signatures,
        #[cfg(feature = "with_bls_aggregate")]
        *hints_vk,
    );
    println!("Statement generation took {:?}", start_time.elapsed());

    // Setup the inputs.
    let mut stdin = SP1Stdin::new();
    stdin.write(&stmt);

    println!("ab_genesis_hash: 0x{}", hex::encode(ab_genesis_hash));

    // Generate the proofs
    let start_time = std::time::Instant::now();
    let proof: SP1ProofWithPublicValues = client
        .prove(pk, stdin.clone())
        .compressed()
        .run()
        .expect("failed to generate proof");

    // let proof_plonk = client
    //     .prove(&pk, stdin)
    //     .plonk()
    //     .run()
    //     .expect("failed to generate plonk proof");

    //create_proof_fixture(&proof0to1plonk, &vk, "0to1");
    println!("Proof generation took {:?}", start_time.elapsed());
    proof
}

#[allow(clippy::too_many_arguments)]
/// Creates the first proof for the genesis AddressBook.
pub fn construct_rotation_proof(
    pk: &SP1ProvingKey,                   // proving key output by sp1 setup
    vk: &SP1VerifyingKey,                 // verifying key output by sp1 setup
    ab_genesis_hash: &[u8; 32],           // genesis AddressBook hash
    ab_curr: &AddressBook,                // current AddressBook
    ab_next: &AddressBook,                // next AddressBook
    prev_proof: SP1ProofWithPublicValues, // the previous proof
    #[cfg(feature = "with_bls_aggregate")] hints_vk: &[u8; 48], // the BLS aggregate key for the next AddressBook
    signatures: &Signatures, // signatures attesting the next AddressBook
) -> SP1ProofWithPublicValues {
    // Setup the prover client.
    let client = ProverClient::new();

    let (ab_curr_hash, ab_next_hash, stmt) = generate_statement(
        *ab_genesis_hash,
        Some(&prev_proof),
        vk.hash_u32(),
        ab_curr,
        ab_next,
        signatures,
        #[cfg(feature = "with_bls_aggregate")]
        *hints_vk,
    );

    // Setup the inputs.
    let mut stdin = SP1Stdin::new();
    stdin.write(&stmt);
    stdin.write_proof(
        *prev_proof.proof.try_as_compressed().unwrap(),
        vk.vk.clone(),
    );

    println!("Hashes to be proved:");
    println!("ab_genesis_hash: 0x{}", hex::encode(ab_genesis_hash));
    println!("ab_curr_hash:    0x{}", hex::encode(ab_curr_hash));
    println!("ab_next_hash:    0x{}", hex::encode(ab_next_hash));

    let start_time = std::time::Instant::now();
    // Generate the proofs
    let proof: SP1ProofWithPublicValues = client
        .prove(pk, stdin.clone())
        .compressed()
        .run()
        .expect("failed to generate proof");

    // let proof_plonk = client
    //     .prove(&pk, stdin)
    //     .plonk()
    //     .run()
    //     .expect("failed to generate plonk proof");

    //create_proof_fixture(&proof0to1plonk, &vk, "0to1");
    println!("Proof generation took {:?}", start_time.elapsed());

    proof
}

fn generate_statement(
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
