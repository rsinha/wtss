use anyhow::Result;
use plonky2::field::types::Field;
use plonky2::hash::hash_types::HashOutTarget;
use plonky2::hash::merkle_proofs::MerkleProofTarget;
use plonky2::hash::poseidon::PoseidonHash;
use plonky2::iop::target::Target;
use plonky2::iop::witness::{PartialWitness, WitnessWrite};
use plonky2::plonk::circuit_builder::CircuitBuilder;
use plonky2::plonk::circuit_data::{CircuitConfig, CircuitData};
use plonky2::plonk::proof::ProofWithPublicInputs;

use crate::raps::roster::{Roster, Digest, F, C};

pub struct AttestationTargets {
    merkle_root: HashOutTarget,
    message: [Target; 4],
    merkle_proof: MerkleProofTarget,
    private_key: [Target; 4],
    public_key_index: Target,
}

pub struct AttestationCircuit<const TREE_HEIGHT: usize> {
    pub targets: AttestationTargets,
    pub circuit_data: CircuitData<F, C, 2>
}

impl<const TREE_HEIGHT: usize> AttestationCircuit<TREE_HEIGHT> {
    pub fn new() -> Self {
        let config = CircuitConfig::standard_recursion_zk_config();
        let mut builder: CircuitBuilder<F, 2> = CircuitBuilder::new(config);

        // Register public inputs.
        let merkle_root = builder.add_virtual_hash();
        builder.register_public_inputs(&merkle_root.elements);
        let signature = builder.add_virtual_hash();
        builder.register_public_inputs(&signature.elements);
        let message: [Target; 4] = builder.add_virtual_targets(4).try_into().unwrap();
        builder.register_public_inputs(&message);

        // Merkle proof
        let merkle_proof = MerkleProofTarget {
            siblings: builder.add_virtual_hashes(TREE_HEIGHT),
        };

        // Verify public key Merkle proof.
        let private_key: [Target; 4] = builder.add_virtual_targets(4).try_into().unwrap();
        let public_key_index = builder.add_virtual_target();
        let public_key_index_bits = builder.split_le(public_key_index, TREE_HEIGHT);
        let zero = builder.zero();

        // note that the leaf is the hash of the private key and the zero array;
        // so the leaf data is [private_key, zero], and the verifier will do the hashing
        builder.verify_merkle_proof::<PoseidonHash>(
            [private_key, [zero; 4]].concat(),
            &public_key_index_bits,
            merkle_root,
            &merkle_proof,
        );

        // Check nullifier.
        let should_be_signature =
            builder.hash_n_to_hash_no_pad::<PoseidonHash>([private_key, message].concat());
        for i in 0..4 {
            builder.connect(signature.elements[i], should_be_signature.elements[i]);
        }

        let circuit_data = builder.build();
        let targets = AttestationTargets {
            merkle_root,
            message,
            merkle_proof,
            private_key,
            public_key_index,
        };

        AttestationCircuit {
            targets,
            circuit_data,
        }
    }

    pub fn prove(
        &self,
        roster: &Roster<TREE_HEIGHT>, 
        private_key: &Digest,
        topic: &Digest,
        public_key_index: usize
    ) -> Result<ProofWithPublicInputs<F, C, 2>> {
        let mut pw = PartialWitness::new();

        pw.set_hash_target(self.targets.merkle_root, roster.0.cap.0[0])?;
        pw.set_target_arr(&self.targets.private_key, private_key)?;
        pw.set_target_arr(&self.targets.message, topic)?;
        pw.set_target(self.targets.public_key_index, F::from_canonical_usize(public_key_index))?;

        let merkle_proof = roster.0.prove(public_key_index);
        for (ht, h) in self.targets.merkle_proof
            .siblings
            .as_slice()
            .into_iter()
            .zip(merkle_proof.siblings)
        {
            pw.set_hash_target(*ht, h)?;
        }

        self.circuit_data.prove(pw)

    }
}
