#![allow(non_snake_case)]
#![allow(non_upper_case_globals)]
#![allow(non_camel_case_types)]
#![allow(clippy::upper_case_acronyms)]

mod signature;
mod random_oracle;

use signature::{*};

use ark_crypto_primitives::crh::{
    sha256::constraints::{Sha256Gadget, UnitVar},
    CRHSchemeGadget, sha256::Sha256, CRHScheme
};
use ark_ff::{BigInteger, PrimeField, ToConstraintField};
use ark_r1cs_std::{
    alloc::{AllocVar, AllocationMode}, convert::{ToBytesGadget, ToConstraintFieldGadget}, eq::EqGadget, fields::fp::FpVar, prelude::Boolean, uint8::UInt8, GR1CSVar
};
use ark_groth16::{Groth16};
use ark_relations::gr1cs::{Namespace, ConstraintSystemRef, SynthesisError};
use rand::thread_rng;
use core::{marker::PhantomData};

use ark_bn254::{Bn254, Fr, G1Projective as G1};
use ark_grumpkin::Projective as G2;
use ark_ed_on_bn254::constraints::EdwardsVar as JubJubVar;
use ark_ed_on_bn254::EdwardsProjective as JubJub;
type S = signature::schnorr::Schnorr<JubJub>;
type SParams = signature::schnorr::Parameters<JubJub>;
type SVerifyGadget = signature::schnorr::constraints::SchnorrSignatureVerifyGadget<JubJub, JubJubVar>;
type SPkVar = signature::schnorr::constraints::PublicKeyVar<JubJub, JubJubVar>;
type SSigVar = signature::schnorr::constraints::SignatureVar<JubJub, JubJubVar>;

use folding_schemes::commitment::{kzg::KZG, pedersen::Pedersen, CommitmentScheme};
use folding_schemes::folding::nova::{
    Nova,
    PreprocessorParam,
    ProverParams,
    VerifierParams,
    decider_eth::Decider as DeciderEth,
    decider_eth::Proof as EthProof,
    decider_eth::VerifierParam as VerifierParam
};
use folding_schemes::frontend::FCircuit;
use folding_schemes::transcript::poseidon::poseidon_canonical_config;
use folding_schemes::{Decider, Error, FoldingScheme};
use folding_schemes::folding::traits::CommittedInstanceOps;
use ark_serialize::{CanonicalDeserialize, CanonicalSerialize};
use ark_std::fmt::Debug;
use core::borrow::Borrow;

pub const MAX_AB_SIZE: usize = 16;
pub const MAX_EXT_INPUTS: usize = 68 * MAX_AB_SIZE;
type AddressBook = [schnorr::PublicKey<JubJub>; MAX_AB_SIZE];
type Keys = [schnorr::SecretKey<JubJub>; MAX_AB_SIZE];
/// The idea here is that eventually we could replace the next line chunk that defines the
/// `type N = Nova<...>` by using another folding scheme that fulfills the `FoldingScheme`
/// trait, and the rest of our code would be working without needing to be updated.
type N = Nova<G1, G2, TSSFCircuit<MAX_AB_SIZE>, KZG<'static, Bn254>, Pedersen<G2>, false>;
type NPP = ProverParams<G1, G2, KZG<'static, Bn254>, Pedersen<G2>, false>;
type NVP = VerifierParams<G1, G2, KZG<'static, Bn254>, Pedersen<G2>, false>;
type D = DeciderEth<G1, G2, TSSFCircuit<MAX_AB_SIZE>, KZG<'static, Bn254>, Pedersen<G2>, Groth16<Bn254>, N>;
type DPP = (<Groth16<Bn254> as ark_snark::SNARK<Fr>>::ProvingKey, <KZG<'static, Bn254> as CommitmentScheme<G1>>::ProverParams);
type DVP = VerifierParam<G1, <KZG<'static, Bn254> as CommitmentScheme<G1>>::VerifierParams, <Groth16<Bn254> as ark_snark::SNARK<Fr>>::VerifyingKey>;

#[derive(Clone, Debug)]
pub struct VecF<F: PrimeField, const L: usize>(pub Vec<F>);
impl<F: PrimeField, const L: usize> Default for VecF<F, L> {
    fn default() -> Self {
        VecF(vec![F::zero(); L])
    }
}
#[derive(Clone, Debug)]
pub struct VecFpVar<F: PrimeField, const L: usize>(pub Vec<FpVar<F>>);
impl<F: PrimeField, const L: usize> AllocVar<VecF<F, L>, F> for VecFpVar<F, L> {
    fn new_variable<T: Borrow<VecF<F, L>>>(
        cs: impl Into<Namespace<F>>,
        f: impl FnOnce() -> Result<T, SynthesisError>,
        mode: AllocationMode,
    ) -> Result<Self, SynthesisError> {
        f().and_then(|val| {
            let cs = cs.into();

            let v = Vec::<FpVar<F>>::new_variable(cs.clone(), || Ok(val.borrow().0.clone()), mode)?;

            Ok(VecFpVar(v))
        })
    }
}
impl<F: PrimeField, const L: usize> Default for VecFpVar<F, L> {
    fn default() -> Self {
        VecFpVar(vec![FpVar::<F>::Constant(F::zero()); L])
    }
}


/// This is the circuit that we want to fold, it implements the FCircuit trait.
/// The parameter z_i denotes the current state, and z_{i+1} denotes the next state which we get by
/// applying the step.
/// In this example we set z_i and z_{i+1} to be a single value, but the trait is made to support
/// arrays, so our state could be an array with different values.
#[derive(Clone, Copy, Debug)]
pub struct TSSFCircuit<const K: usize> {
    _f: PhantomData<Fr>,
}
impl<const K: usize> FCircuit<Fr> for TSSFCircuit<K> {
    type Params = ();
    type ExternalInputs = VecF<Fr, MAX_EXT_INPUTS>;
    type ExternalInputsVar = VecFpVar<Fr, MAX_EXT_INPUTS>;

    fn new(_params: Self::Params) -> Result<Self, Error> {
        Ok(Self { _f: PhantomData })
    }
    fn state_len(&self) -> usize {
        1
    }
    /// generates the constraints for the step of F for the given z_i
    fn generate_step_constraints(
        &self,
        cs: ConstraintSystemRef<Fr>,
        _i: usize,
        z_i: Vec<FpVar<Fr>>,
        external_inputs: Self::ExternalInputsVar,
    ) -> Result<Vec<FpVar<Fr>>, SynthesisError> {

        let prev_pks = (0..K)
            .map(|i| SPkVar::new_witness(cs.clone(), || Ok(
                ark_ed_on_bn254::EdwardsAffine::new(
                    external_inputs.0[2*i].value()?,
                    external_inputs.0[2*i + 1].value()?
                )
            )).unwrap())
            .collect::<Vec<_>>();

        let next_pks = (0..K)
            .map(|i| SPkVar::new_witness(cs.clone(), || Ok(
                ark_ed_on_bn254::EdwardsAffine::new(
                    external_inputs.0[2*K + 2*i].value()?,
                    external_inputs.0[2*K + 2*i + 1].value()?
                )
            )).unwrap())
            .collect::<Vec<_>>();

        let signatures = (0..K)
            .map(|i| SSigVar {
                verifier_challenge: (4*K + 64*i..4*K + 64*i + 32)
                    .map(|j| external_inputs.0[j].to_bytes_le().unwrap()[0].clone())
                    .collect(),
                prover_response: (4*K + 64*i + 32..4*K + 64*i + 64)
                    .map(|j| external_inputs.0[j].to_bytes_le().unwrap()[0].clone())
                    .collect(),
                _group: PhantomData,
            })
            .collect::<Vec<_>>();

        let recomputed_prev_state = {
            let sha_input: Vec<UInt8<Fr>> = (0..K)
                .flat_map(|i| external_inputs.0[2*i].to_bytes_le().unwrap())
                .collect();
            let sha_output = Sha256Gadget::evaluate(&UnitVar::default(), &sha_input[0..32])?;
            sha_output.0.to_constraint_field()?
        };

        let computed_next_state = {
            let sha_input: Vec<UInt8<Fr>> = (0..K)
                .flat_map(|i| external_inputs.0[2*K + 2*i].to_bytes_le().unwrap())
                .collect();
            let sha_output = Sha256Gadget::evaluate(&UnitVar::default(), &sha_input[0..32])?;
            sha_output.0.to_constraint_field()?
        };

        let schnorr_parameters = S::setup::<_>(&mut thread_rng()).unwrap();
        let parameters_var = <SVerifyGadget as SigVerifyGadget<S, Fr>>
            ::ParametersVar::new_constant(cs.clone(), schnorr_parameters)?;
        let msg_var = computed_next_state[0].to_bytes_le()?;
        let valid_sig_var = <SVerifyGadget as SigVerifyGadget<S, Fr>>
            ::verify(&parameters_var, &prev_pks[0], &msg_var, &signatures[0]).unwrap();
        valid_sig_var.enforce_equal(&Boolean::<Fr>::TRUE)?;

        for i in 0..K {
            prev_pks[i].pub_key.x.enforce_equal(&external_inputs.0[2*i])?;
            prev_pks[i].pub_key.y.enforce_equal(&external_inputs.0[2*i + 1])?;
        }

        for i in 0..K {
            next_pks[i].pub_key.x.enforce_equal(&external_inputs.0[2*K + 2*i])?;
            next_pks[i].pub_key.y.enforce_equal(&external_inputs.0[2*K + 2*i + 1])?;
        }

        recomputed_prev_state[0].enforce_equal(&z_i[0])?;
        Ok(vec![computed_next_state[0].clone()])
    }
}

fn hash_addressbook(ab: &AddressBook) -> Fr {
    let sha_input: Vec<u8> = ab.iter()
        .flat_map(|pk| pk.x.into_bigint().to_bytes_le())
        .collect();
    let out_bytes = Sha256::evaluate(&(), &sha_input[0..32]).unwrap();
    let out: Vec<Fr> = out_bytes.to_field_elements().unwrap();
    // because of modulus, we actually get two Fr elemeents, but we will only use the first one
    out[0]
}

fn create_new_addressbook(params: &SParams) -> (AddressBook, Keys) {
    let mut keys = Vec::new();
    let mut ab = Vec::new();
    for _i in 0..MAX_AB_SIZE {
        let (pk, sk) = S::keygen(params, &mut thread_rng()).unwrap();
        keys.push(sk);
        ab.push(pk);
    }
    (ab.try_into().unwrap(), keys.try_into().unwrap())
}

pub struct TSSPublicParams {
    pub nova_pp: Vec<u8>,
    pub nova_vp: Vec<u8>,
    pub decider_pp: Vec<u8>,
    pub decider_vp:Vec<u8>,
}

fn setup(circuit: &TSSFCircuit<MAX_AB_SIZE>) -> Result<TSSPublicParams, Error> {
    let poseidon_config = poseidon_canonical_config::<Fr>();
    let mut rng = rand::rngs::OsRng;

    println!("Prepare Nova ProverParams & VerifierParams");
    let nova_preprocess_params = PreprocessorParam::new(poseidon_config, circuit.clone());
    let (nova_pp, nova_vp) = N::preprocess(&mut rng, &nova_preprocess_params)?;
    let (decider_pp, decider_vp) = D::preprocess(&mut rng, ((nova_pp.clone(), nova_vp.clone()), circuit.state_len()))?;

    let mut nova_pp_serialized = vec![];
    nova_pp.serialize_compressed(&mut nova_pp_serialized)?;
    println!("Nova ProverParam serialized size: {} bytes", nova_pp_serialized.len());

    let mut nova_vp_serialized = vec![];
    nova_vp.serialize_compressed(&mut nova_vp_serialized)?;
    println!("Nova VerifierParam serialized size: {} bytes", nova_vp_serialized.len());

    // Serialize decider_pp and decider_vp
    let mut decider_pp_serialized = vec![];
    decider_pp.serialize_compressed(&mut decider_pp_serialized)?;
    println!("Decider PreprocessorParam serialized size: {} bytes", decider_pp_serialized.len());

    let mut decider_vp_serialized = vec![];
    decider_vp.serialize_compressed(&mut decider_vp_serialized)?;
    println!("Decider VerifierParam serialized size: {} bytes", decider_vp_serialized.len());

    Ok(TSSPublicParams {
        nova_pp: nova_pp_serialized,
        nova_vp: nova_vp_serialized,
        decider_pp: decider_pp_serialized,
        decider_vp: decider_vp_serialized,
    })
}

/// cargo run --release --example tss
fn main() -> Result<(), Error> {
    let num_steps = 5;
    let F_circuit = TSSFCircuit::<MAX_AB_SIZE>::new(())?;

    let params = setup(&F_circuit)?;
    let nova_pp: NPP = N::pp_deserialize_with_mode(params.nova_pp.as_slice(), ark_serialize::Compress::Yes, ark_serialize::Validate::Yes, ())?;
    println!("Nova ProverParam deserialized successfully");
    let nova_vp: NVP = N::vp_deserialize_with_mode(params.nova_vp.as_slice(), ark_serialize::Compress::Yes, ark_serialize::Validate::Yes, ())?;
    println!("Nova VerifierParam deserialized successfully");
    let decider_pp = DPP::deserialize_compressed(params.decider_pp.as_slice())?;
    println!("Decider PreprocessorParam deserialized successfully");
    let decider_vp = DVP::deserialize_compressed(params.decider_vp.as_slice())?;
    println!("Decider VerifierParam deserialized successfully");
    let nova_params = (nova_pp, nova_vp);

    println!("Initialize FoldingScheme");
    let schnorr_parameters = S::setup::<_>(&mut thread_rng()).unwrap();
    let (mut prev_ab, mut prev_keys) = create_new_addressbook(&schnorr_parameters);
    let initial_state = vec![hash_addressbook(&prev_ab)];
    let mut folding_scheme = N::init(&nova_params, F_circuit, initial_state.clone())?;

    // compute a step of the IVC
    for i in 0..num_steps {
        let (next_ab, next_keys) = create_new_addressbook(&schnorr_parameters);
        let mut external_inputs_at_step = Vec::new();
        for i in 0..MAX_AB_SIZE {
            external_inputs_at_step.push(prev_ab[i].x);
            external_inputs_at_step.push(prev_ab[i].y);
        }
        for i in 0..MAX_AB_SIZE {
            external_inputs_at_step.push(next_ab[i].x);
            external_inputs_at_step.push(next_ab[i].y);
        }

        let message = hash_addressbook(&next_ab).into_bigint().to_bytes_le();
        let signatures: Vec<_> = (0..MAX_AB_SIZE)
            .map(|j| S::sign(&schnorr_parameters, &prev_keys[j], &message, &mut thread_rng()).unwrap())
            .collect();
        for i in 0..MAX_AB_SIZE {
            let verifier_challenge = signatures[i].verifier_challenge;
            let prover_response = signatures[i].prover_response.into_bigint().to_bytes_le();
            for j in 0..32 {
                external_inputs_at_step.push(Fr::from_le_bytes_mod_order(&[verifier_challenge[j]]));
            }
            for j in 0..32 {
                external_inputs_at_step.push(Fr::from_le_bytes_mod_order(&[prover_response[j]]));
            }
        }

        let start = std::time::Instant::now();
        folding_scheme.prove_step(thread_rng(), VecF(external_inputs_at_step.clone()), None)?;
        println!("Nova::prove_step {}: {:?}", i, start.elapsed());

        prev_ab = next_ab;
        prev_keys = next_keys;
    }

    println!("Run the Nova's IVC verifier");
    let ivc_proof = folding_scheme.ivc_proof();
    N::verify(
        nova_params.1, // Nova's verifier params
        ivc_proof,
    )?;

    let start = std::time::Instant::now();
    let proof = D::prove(thread_rng(), decider_pp, folding_scheme.clone())?;
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

    let start = std::time::Instant::now();
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
    type N = Nova<G1, G2, TSSFCircuit<MAX_AB_SIZE>, KZG<'static, Bn254>, Pedersen<G2>, false>;
    type D = DeciderEth<G1, G2, TSSFCircuit<MAX_AB_SIZE>, KZG<'static, Bn254>, Pedersen<G2>, Groth16<Bn254>, N>;

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