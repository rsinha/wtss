use anyhow::Result;

use plonky2::iop::target::Target;
use plonky2::iop::witness::{PartialWitness, WitnessWrite};
use plonky2::plonk::circuit_builder::CircuitBuilder;
use plonky2::plonk::circuit_data::{CircuitConfig, CircuitData, VerifierCircuitTarget};
use plonky2::plonk::proof::{ProofWithPublicInputs, ProofWithPublicInputsTarget};

use crate::raps::roster::{Roster, Attestation, Digest, F, C};
use crate::raps::attestation_circuit::AttestationCircuit;

pub struct AggregationTargets<const MAX_SIGNERS: usize> {
    vd_targets: [VerifierCircuitTarget; MAX_SIGNERS],
    proof_targets: [ProofWithPublicInputsTarget<2>; MAX_SIGNERS],
}

pub struct AggregationCircuit<const TREE_HEIGHT: usize, const MAX_SIGNERS: usize> {
    pub targets: AggregationTargets<MAX_SIGNERS>,
    pub circuit_data: CircuitData<F, C, 2>
}

impl<const TREE_HEIGHT: usize, const MAX_SIGNERS: usize> AggregationCircuit<TREE_HEIGHT, MAX_SIGNERS> {
    pub fn new() -> Self {
        let config = CircuitConfig::standard_recursion_zk_config();
        let mut builder = CircuitBuilder::new(config);

        // Register public inputs.
        let merkle_root_target = builder.add_virtual_hash();
        builder.register_public_inputs(&merkle_root_target.elements);
        let message_target: [Target; 4]  = builder.add_virtual_targets(4).try_into().unwrap();
        builder.register_public_inputs(&message_target);

        let vd = AttestationCircuit::<TREE_HEIGHT>::new().circuit_data.verifier_data();
        let mut vd_targets: Vec<VerifierCircuitTarget> = Vec::new();
        let mut proof_targets: Vec<ProofWithPublicInputsTarget<2>> = Vec::new();

        for _i in 0..MAX_SIGNERS {

            let proof_target = builder.add_virtual_proof_with_pis(&vd.common);

            for i in 0..4 {
                builder.connect(proof_target.public_inputs[i], merkle_root_target.elements[i]);
                builder.connect(proof_target.public_inputs[8 + i], message_target[i]);
            }

            let vd_target = builder.add_virtual_verifier_data(vd.common.config.fri_config.cap_height);

            builder.verify_proof::<C>(&proof_target, &vd_target, &vd.common);

            vd_targets.push(vd_target);
            proof_targets.push(proof_target);
        }

        let data = builder.build();
        
        Self {
            targets: AggregationTargets {
                vd_targets: vd_targets.try_into().unwrap(),
                proof_targets: proof_targets.try_into().unwrap(),
            },
            circuit_data: data,
        }
    }

    pub fn prove(
        &self,
        roster: &Roster<TREE_HEIGHT>,
        msg: &Digest,
        attestations: impl AsRef<[Attestation]>
    ) -> Result<ProofWithPublicInputs<F, C, 2>> {
        let mut pw = PartialWitness::new();

        let vd = AttestationCircuit::<TREE_HEIGHT>::new().circuit_data.verifier_data();

        for (i, att) in attestations.as_ref().iter().enumerate() {
            let pis: Vec<F> = roster.0.cap.0.iter().flat_map(|h| h.elements)
                .chain(att.signature)
                .chain(msg.clone())
                .collect();

            pw.set_proof_with_pis_target(
                &self.targets.proof_targets[i],
                &ProofWithPublicInputs {
                    proof: att.proof.clone(),
                    public_inputs: pis,
                },
            )?;

            pw.set_verifier_data_target(&self.targets.vd_targets[i], &vd.verifier_only)?;
            pw.set_cap_target(
                &self.targets.vd_targets[i].constants_sigmas_cap,
                &vd.verifier_only.constants_sigmas_cap,
            )?;
        }

        self.circuit_data.prove(pw)
    }
}