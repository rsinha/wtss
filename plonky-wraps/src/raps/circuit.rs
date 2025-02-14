use anyhow::Result;
use plonky2::field::types::Field;
use plonky2::hash::hash_types::HashOutTarget;
use plonky2::hash::merkle_proofs::MerkleProofTarget;
use plonky2::hash::poseidon::PoseidonHash;
use plonky2::iop::target::Target;
use plonky2::iop::witness::{PartialWitness, WitnessWrite};
use plonky2::plonk::circuit_builder::CircuitBuilder;

use crate::raps::roster::{Roster, Digest, F};

pub struct AttestationTargets {
    merkle_root: HashOutTarget,
    message: [Target; 4],
    merkle_proof: MerkleProofTarget,
    private_key: [Target; 4],
    public_key_index: Target,
}

impl Roster {
    fn tree_height(&self) -> usize {
        self.0.leaves.len().trailing_zeros() as usize
    }

    pub fn attestation_circuit(&self, builder: &mut CircuitBuilder<F, 2>) -> AttestationTargets {
        // Register public inputs.
        let merkle_root = builder.add_virtual_hash();
        builder.register_public_inputs(&merkle_root.elements);
        let signature = builder.add_virtual_hash();
        builder.register_public_inputs(&signature.elements);
        let message: [Target; 4] = builder.add_virtual_targets(4).try_into().unwrap();
        builder.register_public_inputs(&message);

        // Merkle proof
        let merkle_proof = MerkleProofTarget {
            siblings: builder.add_virtual_hashes(self.tree_height()),
        };

        // Verify public key Merkle proof.
        let private_key: [Target; 4] = builder.add_virtual_targets(4).try_into().unwrap();
        let public_key_index = builder.add_virtual_target();
        let public_key_index_bits = builder.split_le(public_key_index, self.tree_height());
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

        AttestationTargets {
            merkle_root,
            message,
            merkle_proof,
            private_key,
            public_key_index,
        }
    }

    // Fill the semaphore targets that we defined at the method `semaphore_circuit` with the given
    // values.
    pub fn fill_attestation_targets(
        &self,
        pw: &mut PartialWitness<F>,
        private_key: Digest,
        topic: Digest,
        public_key_index: usize,
        targets: AttestationTargets,
    ) -> Result<()> {
        let AttestationTargets {
            merkle_root,
            message: topic_target,
            merkle_proof: merkle_proof_target,
            private_key: private_key_target,
            public_key_index: public_key_index_target,
        } = targets;

        pw.set_hash_target(merkle_root, self.0.cap.0[0])?;
        pw.set_target_arr(&private_key_target, &private_key)?;
        pw.set_target_arr(&topic_target, &topic)?;
        pw.set_target(
            public_key_index_target,
            F::from_canonical_usize(public_key_index),
        )?;

        let merkle_proof = self.0.prove(public_key_index);
        for (ht, h) in merkle_proof_target
            .siblings
            .into_iter()
            .zip(merkle_proof.siblings)
        {
            pw.set_hash_target(ht, h)?;
        }
        Ok(())
    }
}
