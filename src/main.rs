use std::collections::HashMap;
use rand::Rng;

use hints_bls12381::hints as HinTS;
use hints_bls12381::setup as HinTS_setup;
use hints_bls12381::hints::HinTS as HinTS_scheme;
use hints_bls12381::hints::*;

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

fn sample_universe(
    n: usize,
) -> (
    HinTS::CRS,
    HinTS::AggregationKey,
    HinTS::VerificationKey,
    Vec<HinTS::SecretKey>,
    Vec<HinTS::ExtendedPublicKey>,
) {
    let num_signers = n - 1;

    // -------------- sample one-time SRS ---------------
    let init_crs = HinTS_setup::PowersOfTauProtocol::init(n);
    // WARN: supply a random seed, not a fixed one as shown here.
    let (crs, proof) = HinTS_setup::PowersOfTauProtocol::contribute(&init_crs, [86u8; 32]);
    assert!(HinTS_setup::PowersOfTauProtocol::verify_contribution(
        &init_crs, &crs, &proof
    ));

    // -------------- sample universe specific values ---------------
    //sample random keys
    // WARN: supply a random seed, not a fixed one as shown here.
    let sks: Vec<HinTS::SecretKey> = (0..num_signers).map(|_| HinTS_scheme::keygen([42u8; 32])).collect();

    let epks = (0..num_signers)
        .map(|i| HinTS_scheme::hint_gen(&crs, n, i, &sks[i]))
        .collect::<Vec<HinTS::ExtendedPublicKey>>();

    //sample random weights for each party
    let weights = sample_weights(num_signers);

    // -------------- perform universe setup ---------------
    let signers_info: HashMap<usize, (HinTS::Weight, HinTS::ExtendedPublicKey)> = (0..num_signers)
        .map(|i| (i, (weights[i], epks[i].clone())))
        .collect();

    //run universe setup
    let (vk, ak) = HinTS_scheme::preprocess(n, &crs, &signers_info);

    (crs, ak, vk, sks, epks)
}

fn sample_weights(n: usize) -> Vec<HinTS::Weight> {
    let mut csprng = rand::rngs::OsRng;
    (0..n)
        .map(|_| HinTS::weight(csprng.gen_range(5..8)))
        .collect()
}

fn sample_signing(
    num_signers: usize,
    msg: &[u8],
    sks: &Vec<HinTS::SecretKey>,
    probability: f64
) -> HashMap<usize, HinTS::PartialSignature> {
    //samples n-1 random bits
    let bitmap: Vec<bool> = {
        let mut csprng = rand::rngs::OsRng;
        (0..num_signers).map(|_| csprng.gen_bool(probability)).collect()
    };

    // for all the active parties, sample partial signatures
    // filter our bitmap indices that are 1
    let mut sigs = HashMap::new();
    bitmap.iter().enumerate().for_each(|(i, &active)| {
        if active {
            sigs.insert(i, HinTS_scheme::sign(msg, &sks[i]));
        }
    });

    sigs
}

fn main() {
    // Setup the program.
    let elf = include_bytes!("ab-rotation-program");
    let (pk, vk) = ab_rotation_script::proof_setup(elf);

    // AB 0 (genesis AB)
    let genesis_committee = Roster::new(5);
    let genesis_ab_hash = ab_rotation_script::compute_address_book_hash(
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
            &ab_rotation_script::rotation_message(&genesis_ab_hash, &[0u8; 32]),
        ),
    );

    let mut prev_proof = genesis_proof;
    let mut prev_roster = genesis_committee;

    // simulate a few rotations
    for day in 0..15 {
        let next_roster = if day % 2 == 0 {
            Roster::new(5)
        } else {
            prev_roster.clone()
        };
        let next_roster_hash = ab_rotation_script::compute_address_book_hash(
            next_roster.verifying_keys.clone(),
            next_roster.weights.clone(),
        );

        // compute HinTS verification key
        let (tss_crs, tss_ak, tss_vk, tss_sks, _) = sample_universe(32);
        let tss_vk_hash = ab_rotation_script::compute_tss_vk_hash(&HinTS::serialize(&tss_vk));

        // perform AB rotation
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
            &tss_vk_hash,
            prev_roster.subset_sign(
                &[true; 5],
                &ab_rotation_script::rotation_message(&next_roster_hash, &tss_vk_hash),
            ),
        );

        // generate a HinTS proof
        let platform_state_root = [0u8; 48];

        let hints_proof = HinTS_scheme::aggregate(
            &tss_crs,
            &tss_ak,
            &tss_vk,
            &sample_signing(31, &platform_state_root, &tss_sks, 0.75)
        );

        assert!(verify_proof(
            &platform_state_root,
            &HinTS::serialize(&hints_proof),
            &next_proof,
            &HinTS::serialize(&tss_vk),
            &vk,
        ));

        prev_proof = next_proof;
        prev_roster = next_roster;
    }
}

fn verify_proof(
    msg: &[u8],
    hints_proof_encoded: &[u8],
    raps_proof_encoded: &[u8],
    hints_vk_encoded: &[u8],
    raps_vk_encoded: &[u8]
) -> bool {
    let hints_proof = HinTS::deserialize::<HinTS::ThresholdSignature>(hints_proof_encoded);
    let hints_vk = HinTS::deserialize::<HinTS::VerificationKey>(hints_vk_encoded);

    ab_rotation_script::verify_proof(raps_vk_encoded, raps_proof_encoded) &&
    HinTS_scheme::verify(msg, &hints_vk, &hints_proof, (F::from(1), F::from(3)))
}