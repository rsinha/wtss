use anyhow::Result;
use plonky2::iop::target::Target;
use plonky2::iop::witness::{PartialWitness, WitnessWrite};
use plonky2::plonk::circuit_builder::CircuitBuilder;
use plonky2::plonk::circuit_data::{CircuitConfig, VerifierCircuitData};
use plonky2::plonk::proof::ProofWithPublicInputs;

use crate::raps::roster::{Digest, PlonkyProof, Roster, Attestation, C, F};

impl Roster {
    pub fn aggregate_attestations(
        &self,
        msg: Digest,
        attestations: impl AsRef<[Attestation]>,
        attestation_circuit_verifier_data: &VerifierCircuitData<F, C, 2>,
    ) -> Result<(PlonkyProof, VerifierCircuitData<F, C, 2>)> {
        let config = CircuitConfig::standard_recursion_zk_config();
        let mut builder = CircuitBuilder::new(config);
        let mut pw = PartialWitness::new();

        // Register public inputs.
        let merkle_root_target = builder.add_virtual_hash();
        builder.register_public_inputs(&merkle_root_target.elements);
        let message_target: [Target; 4]  = builder.add_virtual_targets(4).try_into().unwrap();
        builder.register_public_inputs(&message_target);

        for att in attestations.as_ref().iter() {
            let pis: Vec<F> = self.0.cap.0.iter().flat_map(|h| h.elements)
                .chain(att.signature)
                .chain(msg)
                .collect();

            let proof_target = builder.add_virtual_proof_with_pis(&attestation_circuit_verifier_data.common);

            for i in 0..4 {
                builder.connect(proof_target.public_inputs[i], merkle_root_target.elements[i]);
                builder.connect(proof_target.public_inputs[8 + i], message_target[i]);
            }

            pw.set_proof_with_pis_target(
                &proof_target,
                &ProofWithPublicInputs {
                    proof: att.proof.clone(),
                    public_inputs: pis,
                },
            )?;

            let vd_target = builder.add_virtual_verifier_data(attestation_circuit_verifier_data.common.config.fri_config.cap_height);
            pw.set_verifier_data_target(&vd_target, &attestation_circuit_verifier_data.verifier_only)?;
            pw.set_cap_target(
                &vd_target.constants_sigmas_cap,
                &attestation_circuit_verifier_data.verifier_only.constants_sigmas_cap,
            )?;

            builder.verify_proof::<C>(&proof_target, &vd_target, &attestation_circuit_verifier_data.common);
        }

        let data = builder.build();
        
        let now = std::time::Instant::now();
        println!("Starting recursive proof generation...");
        let recursive_proof = data.prove(pw)?;
        let elapsed_time = now.elapsed();
        println!("Elapsed time for recursive proof generation: {:?}", elapsed_time);

        data.verify(recursive_proof.clone())?;

        Ok((
            recursive_proof.proof,
            data.verifier_data(),
        ))
    }

}

#[cfg(test)]
mod tests {
    use anyhow::Result;
    use plonky2::field::types::{Field, Sample};
    use plonky2::hash::merkle_tree::MerkleTree;
    use plonky2::hash::poseidon::PoseidonHash;
    use plonky2::plonk::config::Hasher;
    use plonky2::plonk::proof::ProofWithPublicInputs;

    use crate::raps::attestation_circuit::AttestationCircuit;
    use crate::raps::roster::{Roster, Digest, F};

    #[test]
    fn test_recursion_set() -> Result<()> {
        let n = 1 << 10;
        let active = 1 << 3;
        let private_keys: Vec<Digest> = (0..n).map(|_| F::rand_array()).collect();
        let public_keys: Vec<Vec<F>> = private_keys
            .iter()
            .map(|&sk| {
                PoseidonHash::hash_no_pad(&[sk, [F::ZERO; 4]].concat())
                    .elements
                    .to_vec()
            })
            .collect();
        let roster = Roster(MerkleTree::new(public_keys, 0));

        let msg = F::rand_array();
        let mut attestations = Vec::new();
        let vd = AttestationCircuit::<10>::new().circuit_data.verifier_data();

        for i in 0..active {
            let att = roster.produce_attestation(&private_keys[i], &msg, i)?;
            println!("attestation circuit digest: {:?}", vd.verifier_only.circuit_digest);
            roster.verify_attestation(&msg, &att)?;
            attestations.push(att);
        }

        // generate recursive proof
        let (recursive_proof, recursive_vd) =
            roster.aggregate_attestations(msg, attestations, &vd)?;

        println!("recursive circuit digest: {:?}", recursive_vd.verifier_only.circuit_digest);

        let public_inputs: Vec<F> = roster.0.cap.0.iter().flat_map(|h| h.elements)
            .chain(msg)
            .collect();

        recursive_vd.verify(ProofWithPublicInputs {
            proof: recursive_proof,
            public_inputs,
        })?;
        Ok(())
    }

}
