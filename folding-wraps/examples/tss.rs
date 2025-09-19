#![allow(non_snake_case)]
#![allow(non_upper_case_globals)]
#![allow(non_camel_case_types)]
#![allow(clippy::upper_case_acronyms)]

mod signature;
mod random_oracle;

use signature::{*};

use std::ops::{Add, AddAssign};
use ark_crypto_primitives::crh::{
    poseidon::constraints::{CRHGadget as PoseidonCRHGadget, CRHParametersVar as PoseidonCRHParametersVar},
    poseidon::CRH as PoseidonCRH,
    CRHSchemeGadget, CRHScheme
};
use ark_ec::CurveGroup;
use ark_ff::{BigInteger, PrimeField, ToConstraintField};
use ark_r1cs_std::{
    alloc::{AllocVar, AllocationMode}, convert::{ToBytesGadget, ToConstraintFieldGadget}, eq::EqGadget, fields::fp::FpVar, prelude::Boolean, uint::UInt, GR1CSVar
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

pub const MAX_AB_SIZE: usize = 30;
pub const MAX_EXT_INPUTS: usize = 7 * MAX_AB_SIZE + 64;
type Weight = Fr;
type AddressBookEntry = (schnorr::PublicKey<JubJub>, Weight);
type AddressBook = [AddressBookEntry; MAX_AB_SIZE];
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
                    external_inputs.0[3*i + 0].value()?,
                    external_inputs.0[3*i + 1].value()?
                )
            )).unwrap())
            .collect::<Vec<_>>();

        let prev_pk_vars = (0..K)
            .map(|i| JubJubVar::new_witness(cs.clone(), || Ok(
                ark_ed_on_bn254::EdwardsAffine::new(
                    external_inputs.0[3*i + 0].value()?,
                    external_inputs.0[3*i + 1].value()?
                )
            )).unwrap())
            .collect::<Vec<_>>();

        let prev_weights = (0..K)
            .map(|i| external_inputs.0[3*i + 2].clone())
            .collect::<Vec<_>>();

        let next_pks = (0..K)
            .map(|i| SPkVar::new_witness(cs.clone(), || Ok(
                ark_ed_on_bn254::EdwardsAffine::new(
                    external_inputs.0[3*K + 3*i + 0].value()?,
                    external_inputs.0[3*K + 3*i + 1].value()?
                )
            )).unwrap())
            .collect::<Vec<_>>();

        let _next_weights = (0..K)
            .map(|i| external_inputs.0[3*K + 3*i + 2].clone())
            .collect::<Vec<_>>();

        let present_bits = (0..K)
            .map(|i| external_inputs.0[6*K + i].to_bytes_le().unwrap()[0].clone())
            .collect::<Vec<_>>();

        let aggregate_signature = SSigVar {
            verifier_challenge: (7*K..7*K + 32)
                .map(|j| external_inputs.0[j].to_bytes_le().unwrap()[0].clone())
                .collect(),
            prover_response: (7*K + 32..7*K + 64)
                .map(|j| external_inputs.0[j].to_bytes_le().unwrap()[0].clone())
                .collect(),
            _group: PhantomData,
        };

        // compute aggregate weight
        let mut aggregate_weight = FpVar::<Fr>::new_witness(cs.clone(), || Ok(Fr::from(0)))?;
        let mut total_weight = FpVar::<Fr>::new_witness(cs.clone(), || Ok(Fr::from(0)))?;
        for i in 0..K {
            let zero = FpVar::<Fr>::new_witness(cs.clone(), || Ok(Fr::from(0)))?;
            let is_present = present_bits[i].is_eq(&UInt::constant(1))?;

            aggregate_weight.add_assign(is_present.select(&prev_weights[i], &zero)?);
            total_weight.add_assign(&prev_weights[i]);
        }
        let three_times_aggregate_weight = &aggregate_weight + &aggregate_weight + &aggregate_weight;
        total_weight.enforce_cmp(&three_times_aggregate_weight, std::cmp::Ordering::Less, false)?;

        // compute aggregate public key
        let mut aggregate_pubkey = JubJubVar::new_witness(cs.clone(), || Ok(ark_ed_on_bn254::EdwardsAffine::zero()))?;
        for i in 0..K {
            let zero = JubJubVar::new_witness(cs.clone(), || Ok(ark_ed_on_bn254::EdwardsAffine::zero()))?;
            let is_present = present_bits[i].is_eq(&UInt::constant(1))?;
            let tmp = is_present.select(&prev_pk_vars[i], &zero)?;
            aggregate_pubkey.add_assign(&tmp);
        }
        let aggregate_pubkey_var = SPkVar {
            pub_key: aggregate_pubkey.clone(),
            _group: PhantomData,
        };
        aggregate_pubkey.x.enforce_equal(&aggregate_pubkey_var.pub_key.x)?;
        aggregate_pubkey.y.enforce_equal(&aggregate_pubkey_var.pub_key.y)?;

        let poseidon_config_var = PoseidonCRHParametersVar::new_constant(cs.clone(), poseidon_canonical_config::<Fr>())?;
        let recomputed_prev_state = {
            let x_coords: Vec<FpVar<Fr>> = (0..K)
                .map(|i| external_inputs.0[3*i].clone())
                .collect();
            let y_coords: Vec<FpVar<Fr>> = (0..K)
                .map(|i| external_inputs.0[3*i + 1].clone())
                .collect();
            let weights: Vec<FpVar<Fr>> = (0..K)
                .map(|i| external_inputs.0[3*i + 2].clone())
                .collect();
            let poseidon_input: Vec<FpVar<Fr>> = x_coords
                .into_iter()
                .chain(y_coords.into_iter())
                .chain(weights.into_iter())
                .collect();
            let poseidon_output = PoseidonCRHGadget::evaluate(&poseidon_config_var, &poseidon_input)?;
            poseidon_output.to_constraint_field()?
        };

        let computed_next_state = {
            let x_coords: Vec<FpVar<Fr>> = (0..K)
                .map(|i| external_inputs.0[3*K + 3*i].clone())
                .collect();
            let y_coords: Vec<FpVar<Fr>> = (0..K)
                .map(|i| external_inputs.0[3*K + 3*i + 1].clone())
                .collect();
            let weights: Vec<FpVar<Fr>> = (0..K)
                .map(|i| external_inputs.0[3*K + 3*i + 2].clone())
                .collect();
            let poseidon_input: Vec<FpVar<Fr>> = x_coords
                .into_iter()
                .chain(y_coords.into_iter())
                .chain(weights.into_iter())
                .collect();
            let poseidon_output = PoseidonCRHGadget::evaluate(&poseidon_config_var, &poseidon_input)?;
            poseidon_output.to_constraint_field()?
        };

        let schnorr_parameters = S::setup::<_>(&mut thread_rng()).unwrap();
        let parameters_var = <SVerifyGadget as SigVerifyGadget<S, Fr>>
            ::ParametersVar::new_constant(cs.clone(), schnorr_parameters)?;
        let msg_var = computed_next_state[0].to_bytes_le()?;
        let valid_sig_var = <SVerifyGadget as SigVerifyGadget<S, Fr>>::verify(&parameters_var, &aggregate_pubkey_var, &msg_var, &aggregate_signature)?;
        valid_sig_var.enforce_equal(&Boolean::<Fr>::TRUE)?;

        for i in 0..K {
            prev_pks[i].pub_key.x.enforce_equal(&external_inputs.0[3*i + 0])?;
            prev_pks[i].pub_key.y.enforce_equal(&external_inputs.0[3*i + 1])?;
            prev_pk_vars[i].x.enforce_equal(&external_inputs.0[3*i + 0])?;
            prev_pk_vars[i].y.enforce_equal(&external_inputs.0[3*i + 1])?;
        }

        for i in 0..K {
            next_pks[i].pub_key.x.enforce_equal(&external_inputs.0[3*K + 3*i + 0])?;
            next_pks[i].pub_key.y.enforce_equal(&external_inputs.0[3*K + 3*i + 1])?;
        }

        recomputed_prev_state[0].enforce_equal(&z_i[0])?;
        Ok(vec![computed_next_state[0].clone()])
    }
}

fn hash_addressbook(ab: &AddressBook) -> Fr {
    let xcoords: Vec<Fr> = ab
        .iter()
        .map(|abe| abe.0.x)
        .collect();
    let ycoords: Vec<Fr> = ab
        .iter()
        .map(|abe| abe.0.y)
        .collect();
    let weights: Vec<Fr> = ab
        .iter()
        .map(|abe| abe.1)
        .collect();
    let poseidon_input: Vec<Fr> = xcoords.into_iter()
        .chain(ycoords.into_iter())
        .chain(weights.into_iter())
        .collect();
    let out_bytes = PoseidonCRH::evaluate(&poseidon_canonical_config::<Fr>(), poseidon_input).unwrap();
    let out: Vec<Fr> = out_bytes.to_field_elements().unwrap();
    // because of modulus, we actually get two Fr elemeents, but we will only use the first one
    out[0]
}

fn create_new_addressbook(params: &SParams) -> (AddressBook, Keys) {
    let mut keys = Vec::new();
    let mut ab = Vec::new();
    for _i in 0..MAX_AB_SIZE {
        let (pk, sk) = S::keygen(params, &mut thread_rng()).unwrap();
        let weight = Fr::from(1);
        keys.push(sk);
        ab.push((pk, weight));
    }
    (ab.try_into().unwrap(), keys.try_into().unwrap())
}

fn simulate_threshold_signing(present_bits: Vec<bool>, ab: &AddressBook, keys: &Keys, message: &[u8]) 
-> signature::schnorr::Signature<JubJub> {
    let mut aggregate_pubkey = ark_ed_on_bn254::EdwardsAffine::zero();
    for i in 0..MAX_AB_SIZE {
        if i % 2 == 0 {
            aggregate_pubkey = aggregate_pubkey.add(ab[i].0).into_affine();
        }
    }

    let schnorr_parameters = S::setup::<_>(&mut thread_rng()).unwrap();
    let mut states = Vec::new();
    for i in 0..MAX_AB_SIZE {
        if present_bits[i] {
            let state = signature::schnorr::ThresholdSchnorr::<JubJub>::
                initiate_signing_session(&keys[i], &mut thread_rng());
            states.push(state);
        }
    }

    let mut round1_messages = Vec::new();
    for i in 0..states.len() {
        let (msg1, state) = signature::schnorr::ThresholdSchnorr::<JubJub>::
            sign_round1(&schnorr_parameters, states[i].clone()).unwrap();
        round1_messages.push(msg1);
        states[i] = state;
    }

    let mut round2_messages = Vec::new();
    for i in 0..states.len() {
        let (msg2, state) = signature::schnorr::ThresholdSchnorr::<JubJub>::
            sign_round2(&schnorr_parameters, &round1_messages, states[i].clone()).unwrap();
        round2_messages.push(msg2);
        states[i] = state;
    }

    let mut partial_signatures: Vec<_> = Vec::new();
    for i in 0..states.len() {
        let partial_signature = signature::schnorr::ThresholdSchnorr::<JubJub>::
            sign_round3(&schnorr_parameters, &aggregate_pubkey, message, &round2_messages, states[i].clone()).unwrap();
        partial_signatures.push(partial_signature);
    }

    signature::schnorr::ThresholdSchnorr::<JubJub>::finish_signing_session(&partial_signatures).unwrap()
}

pub struct TSSPublicParams {
    pub nova_pp: NPP,
    pub nova_vp: NVP,
    pub decider_pp: DPP,
    pub decider_vp: DVP,
}

fn setup(circuit: &TSSFCircuit<MAX_AB_SIZE>) -> Result<TSSPublicParams, Error> {
    let poseidon_config = poseidon_canonical_config::<Fr>();
    let mut rng = rand::rngs::OsRng;

    println!("Preparing Nova ProverParams & VerifierParams");
    let nova_preprocess_params = PreprocessorParam::new(poseidon_config, circuit.clone());
    let (nova_pp, nova_vp) = N::preprocess(&mut rng, &nova_preprocess_params)?;
    let (decider_pp, decider_vp) = D::preprocess(&mut rng, ((nova_pp.clone(), nova_vp.clone()), circuit.state_len()))?;

    Ok(TSSPublicParams { nova_pp, nova_vp, decider_pp, decider_vp })
}

fn load_params_from_disk() -> Result<TSSPublicParams, Error> {
    let nova_pp_path = "/tmp/tss_nova_pp.bin";
    let nova_vp_path = "/tmp/tss_nova_vp.bin";
    let decider_pp_path = "/tmp/tss_decider_pp.bin";
    let decider_vp_path = "/tmp/tss_decider_vp.bin";

    let e1 = std::path::Path::new(nova_pp_path).exists();
    let e2 = std::path::Path::new(nova_vp_path).exists();
    let e3 = std::path::Path::new(decider_pp_path).exists();
    let e4 = std::path::Path::new(decider_vp_path).exists();
    if e1 && e2 && e3 && e4 {
        println!("Loading Nova ProverParams & VerifierParams");
        let nova_pp = std::fs::read(nova_pp_path)?;
        let nova_vp = std::fs::read(nova_vp_path)?;
        let decider_pp = std::fs::read(decider_pp_path)?;
        let decider_vp = std::fs::read(decider_vp_path)?;

        let nova_pp: NPP = N::pp_deserialize_with_mode(nova_pp.as_slice(), ark_serialize::Compress::Yes, ark_serialize::Validate::Yes, ())?;
        println!("Nova ProverParam deserialized successfully");
        let nova_vp: NVP = N::vp_deserialize_with_mode(nova_vp.as_slice(), ark_serialize::Compress::Yes, ark_serialize::Validate::Yes, ())?;
        println!("Nova VerifierParam deserialized successfully");
        let decider_pp = DPP::deserialize_compressed(decider_pp.as_slice())?;
        println!("Decider PreprocessorParam deserialized successfully");
        let decider_vp = DVP::deserialize_compressed(decider_vp.as_slice())?;
        println!("Decider VerifierParam deserialized successfully");

        Ok(TSSPublicParams {
            nova_pp,
            nova_vp,
            decider_pp,
            decider_vp,
        })
    } else {
        Err(std::io::Error::new(std::io::ErrorKind::NotFound, "File does not exist")).map_err(|e| Error::from(e))
    }
}

fn write_params_to_disk(params: &TSSPublicParams) -> Result<(), ark_serialize::SerializationError> {
    let mut nova_pp_serialized = vec![];
    params.nova_pp.serialize_compressed(&mut nova_pp_serialized)?;
    println!("Nova ProverParam serialized size: {} bytes", nova_pp_serialized.len());

    let mut nova_vp_serialized = vec![];
    params.nova_vp.serialize_compressed(&mut nova_vp_serialized)?;
    println!("Nova VerifierParam serialized size: {} bytes", nova_vp_serialized.len());

    // Serialize decider_pp and decider_vp
    let mut decider_pp_serialized = vec![];
    params.decider_pp.serialize_compressed(&mut decider_pp_serialized)?;
    println!("Decider PreprocessorParam serialized size: {} bytes", decider_pp_serialized.len());

    let mut decider_vp_serialized = vec![];
    params.decider_vp.serialize_compressed(&mut decider_vp_serialized)?;
    println!("Decider VerifierParam serialized size: {} bytes", decider_vp_serialized.len());

    std::fs::write("/tmp/tss_nova_pp.bin", &nova_pp_serialized)?;
    std::fs::write("/tmp/tss_nova_vp.bin", &nova_vp_serialized)?;
    std::fs::write("/tmp/tss_decider_pp.bin", &decider_pp_serialized)?;
    std::fs::write("/tmp/tss_decider_vp.bin", &decider_vp_serialized)?;
    Ok(())
}

/// cargo run --release --example tss
fn main() -> Result<(), Error> {
    let num_steps = 10;
    let F_circuit = TSSFCircuit::<MAX_AB_SIZE>::new(())?;

    let params = setup(&F_circuit)?;

    println!("Initialize FoldingScheme");
    let schnorr_parameters = S::setup::<_>(&mut thread_rng()).unwrap();
    let (mut prev_ab, mut prev_keys) = create_new_addressbook(&schnorr_parameters);
    let initial_state = vec![hash_addressbook(&prev_ab)];
    let mut ivc_instance = N::init(&(params.nova_pp.clone(), params.nova_vp.clone()), F_circuit, initial_state.clone())?;

    println!("ledger ID: {}", prettyprint(&initial_state[0].into_bigint().to_bytes_le()));

    // compute a step of the IVC
    for i in 0..num_steps {
        println!("-------------------------- Step {} --------------------------", i);
        let (next_ab, next_keys) = create_new_addressbook(&schnorr_parameters);
        let mut external_inputs_at_step = Vec::new();
        for i in 0..MAX_AB_SIZE {
            external_inputs_at_step.push(prev_ab[i].0.x);
            external_inputs_at_step.push(prev_ab[i].0.y);
            external_inputs_at_step.push(prev_ab[i].1);
        }
        for i in 0..MAX_AB_SIZE {
            external_inputs_at_step.push(next_ab[i].0.x);
            external_inputs_at_step.push(next_ab[i].0.y);
            external_inputs_at_step.push(next_ab[i].1);
        }
        for i in 0..MAX_AB_SIZE {
            external_inputs_at_step.push(Fr::from(i % 2 == 0)); // even signatures present
        }

        let message = hash_addressbook(&next_ab).into_bigint().to_bytes_le();
        println!("Message to be signed at step {}: {}", i, prettyprint(message.as_slice()));

        // compute aggregate public key
        let mut aggregate_pubkey = ark_ed_on_bn254::EdwardsAffine::zero();
        for i in 0..MAX_AB_SIZE {
            if i % 2 == 0 {
                aggregate_pubkey = aggregate_pubkey.add(prev_ab[i].0).into_affine();
            }
        }
        let aggregate_signature = simulate_threshold_signing((0..MAX_AB_SIZE).map(|j| j % 2 == 0).collect(), &prev_ab, &prev_keys, &message);
        assert!(S::verify(&schnorr_parameters, &aggregate_pubkey, &message, &aggregate_signature).unwrap());
        let verifier_challenge = aggregate_signature.verifier_challenge;
        let prover_response = aggregate_signature.prover_response.into_bigint().to_bytes_le();
        for j in 0..32 {
            external_inputs_at_step.push(Fr::from_le_bytes_mod_order(&[verifier_challenge[j]]));
        }
        for j in 0..32 {
            external_inputs_at_step.push(Fr::from_le_bytes_mod_order(&[prover_response[j]]));
        }

        let start = std::time::Instant::now();
        ivc_instance.prove_step(thread_rng(), VecF(external_inputs_at_step.clone()), None)?;
        println!("Nova::prove_step {}: {:?}", i, start.elapsed());

        if i > 0 {
            println!("Run the Nova's IVC verifier");
            let ivc_proof = ivc_instance.ivc_proof();
            N::verify(params.nova_vp.clone(), ivc_proof.clone())?;

            let folding_scheme = N::from_ivc_proof(ivc_proof.clone(), (), (params.nova_pp.clone(), params.nova_vp.clone()))?;

            let start = std::time::Instant::now();
            let proof = D::prove(thread_rng(), params.decider_pp.clone(), folding_scheme.clone())?;
            println!("generated Decider proof: {:?}", start.elapsed());

            let verified = D::verify(
                params.decider_vp.clone(),
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
            params.decider_vp.serialize_compressed(&mut decider_vp_serialized)?;

            assert!(verify_tss(&decider_vp_serialized, &proof_serialized)?);
        }

        prev_ab = next_ab;
        prev_keys = next_keys;
    }

    let folding_scheme = N::from_ivc_proof(ivc_instance.ivc_proof(), (), (params.nova_pp.clone(), params.nova_vp.clone()))?;

    println!("Run the Nova's IVC verifier");
    let ivc_proof = ivc_instance.ivc_proof();
    N::verify(params.nova_vp, ivc_proof)?;
    let mut ivc_proof_serialized = Vec::new();
    ivc_instance.ivc_proof().serialize_compressed(&mut ivc_proof_serialized).unwrap();
    println!("IVC proof serialized size: {} bytes", ivc_proof_serialized.len());

    let start = std::time::Instant::now();
    let proof = D::prove(thread_rng(), params.decider_pp, folding_scheme.clone())?;
    println!("generated Decider proof: {:?}", start.elapsed());

    let verified = D::verify(
        params.decider_vp.clone(),
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
    params.decider_vp.serialize_compressed(&mut decider_vp_serialized)?;

    let start = std::time::Instant::now();
    let verified = verify_tss(&decider_vp_serialized, &proof_serialized)?;
    println!("verify_tss time: {:?}", start.elapsed());
    assert!(verified);

    let ledger_id = proof_data.z_0[0].clone().into_bigint().to_bytes_le();
    let latest_ab_hash = proof_data.z_i[0].clone().into_bigint().to_bytes_le();
    println!("genesis AB hash: {}", prettyprint(&ledger_id));
    println!("latest AB hash: {}", prettyprint(&latest_ab_hash));

    Ok(())
}

fn prettyprint(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{:02x}", b)).collect::<Vec<_>>().join("")
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