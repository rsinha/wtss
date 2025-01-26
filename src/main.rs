pub const AB_ROTATION_ELF: &[u8] = include_bytes!("ab-rotation-program");

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
    let tss_vk_hash = [0u8; 32];

    // Setup the program.
    let elf = include_bytes!("ab-rotation-program");
    let (pk, vk) = ab_rotation_script::proof_setup(elf);

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