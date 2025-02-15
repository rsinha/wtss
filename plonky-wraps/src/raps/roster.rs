use anyhow::Result;
use plonky2::hash::merkle_tree::MerkleTree;
use plonky2::hash::poseidon::PoseidonHash;
use plonky2::plonk::config::Hasher;
use plonky2::plonk::proof::ProofWithPublicInputs;
use plonky2::field::goldilocks_field::GoldilocksField;
use plonky2::plonk::config::PoseidonGoldilocksConfig;
use plonky2::plonk::proof::Proof;

use super::attestation_circuit::AttestationCircuit;

pub type F = GoldilocksField;
pub type Digest = [F; 4];
pub type C = PoseidonGoldilocksConfig;
pub type PlonkyProof = Proof<F, PoseidonGoldilocksConfig, 2>;

#[derive(Debug, Clone)]
pub struct Attestation {
    pub signature: Digest,
    pub proof: PlonkyProof,
}

pub struct Roster<const TREE_HEIGHT: usize>(pub MerkleTree<F, PoseidonHash>);

impl<const TREE_HEIGHT: usize> Roster<TREE_HEIGHT> {
    // Verify the plonky2 proof of the given nullifier (in the signal structure) and topic.
    pub fn verify_attestation(
        &self,
        message: &Digest,
        attestation: &Attestation,
    ) -> Result<()> {
        let public_inputs: Vec<F> = self
            .0
            .cap
            .0
            .iter()
            .flat_map(|h| h.elements)
            .chain(attestation.signature)
            .chain(message.clone())
            .collect();

        AttestationCircuit::<TREE_HEIGHT>::new()
            .circuit_data
            .verifier_data()
            .verify(ProofWithPublicInputs {
                proof: attestation.clone().proof,
                public_inputs,
            })
    }

    // Generate the plonky2 proof for the given key pair and topic.
    pub fn produce_attestation(
        &self,
        private_key: &Digest,
        message: &Digest,
        public_key_index: usize,
    ) -> Result<Attestation> {
        let signature = PoseidonHash::hash_no_pad(
            &[private_key.clone(), message.clone()].concat()
        ).elements;

        let circuit: AttestationCircuit<TREE_HEIGHT> = AttestationCircuit::new();
        let proof = circuit.prove(&self, private_key, message, public_key_index)?;

        Ok( Attestation { signature, proof: proof.proof, } )
    }
}

#[cfg(test)]
mod tests {
    use anyhow::Result;
    use plonky2::field::types::{Field, Sample};
    use plonky2::hash::merkle_tree::MerkleTree;
    use plonky2::hash::poseidon::PoseidonHash;
    use plonky2::plonk::config::Hasher;

    use crate::raps::roster::{Roster, Digest, F};

    #[test]
    fn test_attestation() -> Result<()> {
        let n = 1 << 10;
        let private_keys: Vec<Digest> = (0..n).map(|_| F::rand_array()).collect();
        let public_keys: Vec<Vec<F>> = private_keys
            .iter()
            .map(|&sk| {
                PoseidonHash::hash_no_pad(&[sk, [F::ZERO; 4]].concat())
                    .elements
                    .to_vec()
            })
            .collect();
        let roster = Roster::<10>(MerkleTree::new(public_keys, 0));

        let i = 12;
        let msg = F::rand_array();

        // generate the plonky2 proof for the given key
        let att = roster.produce_attestation(&private_keys[i], &msg, i)?;
        // verify the plonky2 proof (contained in `signal`)
        roster.verify_attestation(&msg, &att)
    }
}
