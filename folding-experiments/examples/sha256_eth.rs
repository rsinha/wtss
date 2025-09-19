#![allow(non_snake_case)]
#![allow(non_upper_case_globals)]
#![allow(non_camel_case_types)]
#![allow(clippy::upper_case_acronyms)]

use ark_crypto_primitives::crh::{
    sha256::constraints::{Sha256Gadget, UnitVar},
    CRHSchemeGadget,
};
use ark_ff::PrimeField;
use ark_r1cs_std::{
    convert::{ToBytesGadget, ToConstraintFieldGadget},
    fields::fp::FpVar,
};
use ark_groth16::Groth16;
use ark_relations::gr1cs::{ConstraintSystemRef, SynthesisError};
use core::marker::PhantomData;
use std::time::Instant;

use ark_bn254::{Bn254, Fr, G1Projective as G1};
use ark_grumpkin::Projective as G2;

use folding_schemes::commitment::{kzg::KZG, pedersen::Pedersen, CommitmentScheme};
use folding_schemes::folding::nova::{
    Nova,
    PreprocessorParam,
    decider_eth::Decider as DeciderEth,
    decider_eth::Proof as EthProof,
    decider_eth::VerifierParam as VerifierParam
};
use folding_schemes::frontend::FCircuit;
use folding_schemes::transcript::poseidon::poseidon_canonical_config;
use folding_schemes::{Decider, Error, FoldingScheme};
use folding_schemes::folding::traits::CommittedInstanceOps;
use ark_serialize::{CanonicalDeserialize, CanonicalSerialize};

/// This is the circuit that we want to fold, it implements the FCircuit trait.
/// The parameter z_i denotes the current state, and z_{i+1} denotes the next state which we get by
/// applying the step.
/// In this example we set z_i and z_{i+1} to be a single value, but the trait is made to support
/// arrays, so our state could be an array with different values.
#[derive(Clone, Copy, Debug)]
pub struct Sha256FCircuit<F: PrimeField> {
    _f: PhantomData<F>,
}
impl<F: PrimeField> FCircuit<F> for Sha256FCircuit<F> {
    type Params = ();
    type ExternalInputs = ();
    type ExternalInputsVar = ();

    fn new(_params: Self::Params) -> Result<Self, Error> {
        Ok(Self { _f: PhantomData })
    }
    fn state_len(&self) -> usize {
        1
    }
    /// generates the constraints for the step of F for the given z_i
    fn generate_step_constraints(
        &self,
        _cs: ConstraintSystemRef<F>,
        _i: usize,
        z_i: Vec<FpVar<F>>,
        _external_inputs: Self::ExternalInputsVar,
    ) -> Result<Vec<FpVar<F>>, SynthesisError> {
        let unit_var = UnitVar::default();
        let out_bytes = Sha256Gadget::evaluate(&unit_var, &z_i[0].to_bytes_le()?)?;
        let out = out_bytes.0.to_constraint_field()?;
        Ok(vec![out[0].clone()])
    }
}

/// cargo test --example sha256
#[cfg(test)]
pub mod tests {
    use super::*;
    use ark_crypto_primitives::crh::{sha256::Sha256, CRHScheme};
    use ark_ff::{BigInteger, ToConstraintField};
    use ark_r1cs_std::{alloc::AllocVar, GR1CSVar};
    use ark_relations::gr1cs::ConstraintSystem;

    fn sha256_step_native<F: PrimeField>(z_i: Vec<F>) -> Vec<F> {
        let out_bytes = Sha256::evaluate(&(), z_i[0].into_bigint().to_bytes_le()).unwrap();
        let out: Vec<F> = out_bytes.to_field_elements().unwrap();

        vec![out[0]]
    }

    // test to check that the Sha256FCircuit computes the same values inside and outside the circuit
    #[test]
    fn test_f_circuit() -> Result<(), Error> {
        let cs = ConstraintSystem::<Fr>::new_ref();

        let circuit = Sha256FCircuit::<Fr>::new(())?;
        let z_i = vec![Fr::from(1_u32)];

        let z_i1 = sha256_step_native(z_i.clone());

        let z_iVar = Vec::<FpVar<Fr>>::new_witness(cs.clone(), || Ok(z_i))?;
        let computed_z_i1Var =
            circuit.generate_step_constraints(cs.clone(), 0, z_iVar.clone(), ())?;
        assert_eq!(computed_z_i1Var.value()?, z_i1);
        Ok(())
    }
}

/// cargo run --release --example sha256
fn main() -> Result<(), Error> {
    let num_steps = 100;
    let initial_state = vec![Fr::from(1_u32)];

    let F_circuit = Sha256FCircuit::<Fr>::new(())?;

    /// The idea here is that eventually we could replace the next line chunk that defines the
    /// `type N = Nova<...>` by using another folding scheme that fulfills the `FoldingScheme`
    /// trait, and the rest of our code would be working without needing to be updated.
    type N = Nova<G1, G2, Sha256FCircuit<Fr>, KZG<'static, Bn254>, Pedersen<G2>, false>;
    type D = DeciderEth<G1, G2, Sha256FCircuit<Fr>, KZG<'static, Bn254>, Pedersen<G2>, Groth16<Bn254>, N>;

    let poseidon_config = poseidon_canonical_config::<Fr>();
    let mut rng = rand::rngs::OsRng;

    println!("Prepare Nova ProverParams & VerifierParams");
    let nova_preprocess_params = PreprocessorParam::new(poseidon_config, F_circuit);
    let nova_params = N::preprocess(&mut rng, &nova_preprocess_params)?;

    let (decider_pp, decider_vp) = D::preprocess(&mut rng, (nova_params.clone(), F_circuit.state_len()))?;

    println!("Initialize FoldingScheme");
    let mut folding_scheme = N::init(&nova_params, F_circuit, initial_state.clone())?;
    // compute a step of the IVC
    for i in 0..num_steps {
        let start = Instant::now();
        folding_scheme.prove_step(rng, (), None)?;
        println!("Nova::prove_step {}: {:?}", i, start.elapsed());
    }

    println!("Run the Nova's IVC verifier");
    let ivc_proof = folding_scheme.ivc_proof();
    N::verify(
        nova_params.1, // Nova's verifier params
        ivc_proof,
    )?;

    let start = Instant::now();
    let proof = D::prove(rng, decider_pp, folding_scheme.clone())?;
    println!("generated Decider proof: {:?}", start.elapsed());

    let verified = D::verify(
        decider_vp.clone(),
        folding_scheme.i,
        folding_scheme.z_0.clone(),
        folding_scheme.z_i.clone(),
        &folding_scheme.U_i.get_commitments(),
        &folding_scheme.u_i.get_commitments(),
        &proof,
    )?;
    assert!(verified);

    // serialize the proof
    let proof_data = ProofData {
        i: folding_scheme.i,
        z_0: folding_scheme.z_0,
        z_i: folding_scheme.z_i,
        U_i_commitments: folding_scheme.U_i.get_commitments(),
        u_i_commitments: folding_scheme.u_i.get_commitments(),
        proof,
    };
    let mut proof_serialized = vec![];
    proof_data.serialize_compressed(&mut proof_serialized).unwrap();
    println!("Decider proof serialized size: {} bytes", proof_serialized.len());

    let mut decider_vp_serialized = vec![];
    decider_vp.serialize_compressed(&mut decider_vp_serialized)?;

    let start = Instant::now();
    let verified = verify_tss(&decider_vp_serialized, &proof_serialized)?;
    println!("verify_tss time: {:?}", start.elapsed());
    assert!(verified);

    Ok(())
}

#[derive(CanonicalSerialize, CanonicalDeserialize)]
pub struct ProofData {
    pub i: Fr,
    pub z_0: Vec<Fr>,
    pub z_i: Vec<Fr>,
    pub U_i_commitments: Vec<G1>,
    pub u_i_commitments: Vec<G1>,
    pub proof: EthProof<G1, KZG<'static, Bn254>, Groth16<Bn254>>,
}

pub fn verify_tss(
    decider_vp_serialized: &[u8],
    proof_serialized: &[u8],
) -> Result<bool, Error> {
    type N = Nova<G1, G2, Sha256FCircuit<Fr>, KZG<'static, Bn254>, Pedersen<G2>, false>;
    type D = DeciderEth<G1, G2, Sha256FCircuit<Fr>, KZG<'static, Bn254>, Pedersen<G2>, Groth16<Bn254>, N>;

    let decider_vp =
        VerifierParam::<
            G1,
            <KZG<'static, Bn254> as CommitmentScheme<G1>>::VerifierParams,
            <Groth16<Bn254> as ark_snark::SNARK<Fr>>::VerifyingKey,
        >::deserialize_compressed(decider_vp_serialized)?;

    let proof_data = ProofData::deserialize_compressed(proof_serialized)?;

    let verified = D::verify(
        decider_vp,
        proof_data.i,
        proof_data.z_0,
        proof_data.z_i,
        &proof_data.U_i_commitments,
        &proof_data.u_i_commitments,
        &proof_data.proof,
    )?;
    Ok(verified)
}