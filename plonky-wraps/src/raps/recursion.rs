use anyhow::Result;
use plonky2::iop::witness::{PartialWitness, WitnessWrite};
use plonky2::plonk::circuit_builder::CircuitBuilder;
use plonky2::plonk::circuit_data::{CircuitConfig, VerifierCircuitData};
use plonky2::plonk::proof::ProofWithPublicInputs;

use crate::raps::roster::{Digest, PlonkyProof, Roster, Attestation, C, F};

impl Roster {
    pub fn aggregate_signals(
        &self,
        msg: Digest,
        attestation_0: Attestation,
        attestation_1: Attestation,
        verifier_data: &VerifierCircuitData<F, C, 2>,
    ) -> Result<(Digest, Digest, PlonkyProof, VerifierCircuitData<F, C, 2>)> {
        let config = CircuitConfig::standard_recursion_zk_config();
        let mut builder = CircuitBuilder::new(config);
        let mut pw = PartialWitness::new();

        let pis_0: Vec<F> = self
            .0
            .cap
            .0
            .iter()
            .flat_map(|h| h.elements)
            .chain(attestation_0.signature)
            .chain(msg)
            .collect();

        let pis_1: Vec<F> = self
            .0
            .cap
            .0
            .iter()
            .flat_map(|h| h.elements)
            .chain(attestation_1.signature)
            .chain(msg)
            .collect();

        // `add_virtual_proof_with_pis` is an extended version of the `add_virtual_target`, but
        // that takes care of adding all the values of the proof and the public inputs (pis).
        let proof_target0 = builder.add_virtual_proof_with_pis(&verifier_data.common);
        // set the public inputs
        builder.register_public_inputs(&proof_target0.public_inputs);
        // `set_proof_with_pis_target` is an extended version of the `set_target`, but that takes
        // care of adding all the values of the proof and the public inputs.
        pw.set_proof_with_pis_target(
            &proof_target0,
            &ProofWithPublicInputs {
                proof: attestation_0.proof,
                public_inputs: pis_0,
            },
        )?;
        // add & set the verifier data
        let vd_target =
            builder.add_virtual_verifier_data(verifier_data.common.config.fri_config.cap_height);
        pw.set_verifier_data_target(&vd_target, &verifier_data.verifier_only)?;

        // now, the same as we did with the proof0, with the proof1 related values:
        let proof_target1 = builder.add_virtual_proof_with_pis(&verifier_data.common);
        builder.register_public_inputs(&proof_target1.public_inputs);
        pw.set_proof_with_pis_target(
            &proof_target1,
            &ProofWithPublicInputs {
                proof: attestation_1.proof,
                public_inputs: pis_1,
            },
        )?;
        let vd_target =
            builder.add_virtual_verifier_data(verifier_data.common.config.fri_config.cap_height);
        pw.set_verifier_data_target(&vd_target, &verifier_data.verifier_only)?;

        pw.set_cap_target(
            &vd_target.constants_sigmas_cap,
            &verifier_data.verifier_only.constants_sigmas_cap,
        )?;

        builder.verify_proof::<C>(&proof_target0, &vd_target, &verifier_data.common);
        builder.verify_proof::<C>(&proof_target1, &vd_target, &verifier_data.common);

        let data = builder.build();
        let recursive_proof = data.prove(pw)?;

        data.verify(recursive_proof.clone())?;

        Ok((
            attestation_0.signature,
            attestation_1.signature,
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

    use crate::raps::roster::{Roster, Digest, F};

    #[test]
    fn test_recursion() -> Result<()> {
        let n = 1 << 20;
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

        // first proof
        let i0 = 12;
        let (att0, vd0) = roster.produce_attestation(private_keys[i0], msg, i0)?;
        roster.verify_attestation(msg, att0.clone(), &vd0)?;

        // second proof
        let i1 = 42;
        let (att1, vd1) = roster.produce_attestation(private_keys[i1], msg, i1)?;
        roster.verify_attestation(msg, att1.clone(), &vd1)?;

        // generate recursive proof
        let (nullifier0, nullifier1, recursive_proof, vd2) =
            roster.aggregate_signals(msg, att0, att1, &vd0)?;

        // verify recursive proof
        let public_inputs: Vec<F> = roster.0.cap.0.iter().flat_map(|h| h.elements)
            .chain(nullifier0)
            .chain(msg)
            .chain(roster.0.cap.0.iter().flat_map(|h| h.elements))
            .chain(nullifier1)
            .chain(msg)
            .collect();

        vd2.verify(ProofWithPublicInputs {
            proof: recursive_proof,
            public_inputs,
        })?;
        Ok(())
    }
}
