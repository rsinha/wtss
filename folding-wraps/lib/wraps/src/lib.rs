// SPDX-License-Identifier: Apache-2.0

#![allow(non_snake_case)]
#![allow(non_upper_case_globals)]
#![allow(non_camel_case_types)]
#![allow(clippy::upper_case_acronyms)]
#![allow(unused_imports)]
#![allow(dead_code)]

mod signature;
mod random_oracle;
mod utils;

use signature::{*};

/********************************* Imports *********************************/

use ark_ec::CurveGroup;
use ark_ff::{BigInteger, PrimeField, ToConstraintField};
use ark_r1cs_std::{
    alloc::{AllocVar, AllocationMode},
    convert::{ToBytesGadget, ToConstraintFieldGadget},
    eq::EqGadget,
    fields::fp::FpVar,
    prelude::Boolean,
    uint::UInt,
    GR1CSVar
};
use ark_crypto_primitives::crh::{
    sha256::Sha256,
    poseidon::constraints::{CRHGadget as PoseidonCRHGadget, CRHParametersVar as PoseidonCRHParametersVar},
    poseidon::CRH as PoseidonCRH,
    CRHSchemeGadget, CRHScheme
};
use ark_groth16::{Groth16};
use ark_relations::gr1cs::{Namespace, ConstraintSystemRef, SynthesisError};
use ark_serialize::{CanonicalDeserialize, CanonicalSerialize};
use ark_std::{rand::Rng, test_rng, rand::thread_rng, fmt::Debug};

use core::borrow::Borrow;
use core::{marker::PhantomData};
use std::ops::{Add, AddAssign};

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

/********************************* Parameters *********************************/

pub const MAX_AB_SIZE: usize = 128; // we need to pad up to this size
pub const MAX_EXT_INPUTS: usize = 4 * MAX_AB_SIZE + 4;
pub const ENTROPY_SIZE: usize = 32; // size of the seed for key generation

/********************************* Configurable Types *********************************/

type PairingCurve = ark_bn254::Bn254;
type G1 = ark_bn254::G1Projective;
type G2 = ark_grumpkin::Projective;
type Fr = ark_bn254::Fr;
type JubJubFr = ark_ed_on_bn254::Fr;
type JubJub = ark_ed_on_bn254::EdwardsProjective;
type JubJubVar = ark_ed_on_bn254::constraints::EdwardsVar;

/********************************* Derived Types *********************************/

type Schnorr = signature::schnorr::Schnorr<JubJub>;
type SchnorrSignature = <Schnorr as SignatureScheme>::Signature;
type SchnorrPrivKey = JubJubFr;
type SchnorrPubKey = <JubJub as CurveGroup>::Affine;
type SchnorrParams = signature::schnorr::Parameters<JubJub>;

type SchnorrPubKeyVar = signature::schnorr::constraints::PublicKeyVar<JubJub, JubJubVar>;
type SchnorrSignatureVar = signature::schnorr::constraints::SignatureVar<JubJub, JubJubVar>;
type SchnorrVerifyGadget = signature::schnorr::constraints::SchnorrSignatureVerifyGadget<JubJub, JubJubVar>;

type ThresholdSchnorr = signature::schnorr::ThresholdSchnorr<JubJub>;
type ThresholdSchnorrR1Msg = signature::schnorr::ThresholdSchnorrMessage1;
type ThresholdSchnorrR2Msg = signature::schnorr::ThresholdSchnorrMessage2<JubJub>;
type ThresholdSchnorrR3Msg = signature::schnorr::ThresholdSchnorrMessage3<JubJub>;

type GrothProverKey = <Groth16<PairingCurve> as ark_snark::SNARK<Fr>>::ProvingKey;
type GrothVerifierKey = <Groth16<PairingCurve> as ark_snark::SNARK<Fr>>::VerifyingKey;

type Weight = Fr;
type AddressBookHash = Fr;
type TSSVKHash = Fr;
type AddressBookEntry = (schnorr::PublicKey<JubJub>, Weight);
type AddressBook = Vec<AddressBookEntry>;
type Keys = Vec<schnorr::SecretKey<JubJub>>;

type N = Nova<G1, G2, TSSFCircuit<MAX_AB_SIZE>, KZG<'static, PairingCurve>, Pedersen<G2>, false>;
type NovaProof = <N as FoldingScheme<G1, G2, TSSFCircuit<MAX_AB_SIZE>>>::IVCProof;
type NPP = ProverParams<G1, G2, KZG<'static, PairingCurve>, Pedersen<G2>, false>;
type NVP = VerifierParams<G1, G2, KZG<'static, PairingCurve>, Pedersen<G2>, false>;
type D = DeciderEth<G1, G2, TSSFCircuit<MAX_AB_SIZE>, KZG<'static, PairingCurve>, Pedersen<G2>, Groth16<PairingCurve>, N>;
type DPP = (GrothProverKey, <KZG<'static, PairingCurve> as CommitmentScheme<G1>>::ProverParams);
type DVP = VerifierParam<G1, <KZG<'static, PairingCurve> as CommitmentScheme<G1>>::VerifierParams, GrothVerifierKey>;

/// Error enum to wrap underlying failures in RAPS operations, 
/// or wrap errors coming from dependencies (namely, arkworks).
#[derive(Debug)]
pub enum WRAPSError {
    /// Multi-purpose error type for describing invalid inputs
    InvalidInput(String),
    /// Multi-purpose error type for describing prover failure
    CryptographyError,
}

/// Phases of the signing protocol: 3 rounds followed by aggregation
#[derive(Clone, Debug)]
pub enum SigningProtocolPhase {
    R1 = 1,
    R2 = 2,
    R3 = 3,
    Aggregate = 4,
}

pub type SigningProtocolMessage = Vec<u8>;
pub type CompressedProofSerialized = Vec<u8>;
pub type UncompressedProofSerialized = Vec<u8>;

pub enum SigningProtocolObject {
    ProtocolMessage(SigningProtocolMessage),
    ProtocolOutput(SchnorrSignature),
}

pub type UncompressedProvingKeySerialized = Vec<u8>;
pub type CompressedProvingKeySerialized = Vec<u8>;
pub type UncompressedVerificationKeySerialized = Vec<u8>;
pub type CompressedVerificationKeySerialized = Vec<u8>;

pub type UncompressedProvingKey = NPP;
pub type CompressedProvingKey = DPP;
pub type UncompressedVerificationKey = NVP;
pub type CompressedVerificationKey = DVP;

pub struct ProvingKey {
    pub nova_pp: UncompressedProvingKey,
    pub decider_pp: CompressedProvingKey,
}

pub struct VerificationKey {
    pub nova_vp: UncompressedVerificationKey,
    pub decider_vp: CompressedVerificationKey,
}

#[derive(CanonicalSerialize, CanonicalDeserialize)]
pub struct ProofData {
    pub i: Fr,
    pub z_0: Vec<Fr>,
    pub z_i: Vec<Fr>,
    pub U_i_commitments: Vec<G1>,
    pub u_i_commitments: Vec<G1>,
    pub proof: EthProof<G1, KZG<'static, PairingCurve>, Groth16<PairingCurve>>,
}

/********************************* Useful Definitions *********************************/

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


/********************************* Circuit *********************************/

#[derive(Clone, Copy, Debug)]
pub struct TSSFCircuit<const K: usize>;

impl<const K: usize> FCircuit<Fr> for TSSFCircuit<K> {
    type Params = ();
    type ExternalInputs = VecF<Fr, MAX_EXT_INPUTS>;
    type ExternalInputsVar = VecFpVar<Fr, MAX_EXT_INPUTS>;

    fn new(_params: Self::Params) -> Result<Self, Error> {
        Ok(Self { })
    }

    fn state_len(&self) -> usize {
        2
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
            .map(|i| SchnorrPubKeyVar::new_witness(cs.clone(), || Ok(
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

        let present_bits = (0..K)
            .map(|i| external_inputs.0[3*K + i].to_bytes_le().unwrap()[0].clone())
            .collect::<Vec<_>>();

        let aggregate_signature = SchnorrSignatureVar {
            verifier_challenge: external_inputs.0[4*K + 0].to_bytes_le().unwrap(),
            prover_response: external_inputs.0[4*K + 1].to_bytes_le().unwrap(),
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
        let two_times_aggregate_weight = &aggregate_weight + &aggregate_weight;
        total_weight.enforce_cmp(&two_times_aggregate_weight, std::cmp::Ordering::Less, false)?;

        // compute aggregate public key
        let mut aggregate_pubkey = JubJubVar::new_witness(cs.clone(), || Ok(ark_ed_on_bn254::EdwardsAffine::zero()))?;
        for i in 0..K {
            let zero = JubJubVar::new_witness(cs.clone(), || Ok(ark_ed_on_bn254::EdwardsAffine::zero()))?;
            let is_present = present_bits[i].is_eq(&UInt::constant(1))?;
            let tmp = is_present.select(&prev_pk_vars[i], &zero)?;
            aggregate_pubkey.add_assign(&tmp);
        }
        let aggregate_pubkey_var = SchnorrPubKeyVar {
            pub_key: aggregate_pubkey.clone(),
            _group: PhantomData,
        };
        aggregate_pubkey.x.enforce_equal(&aggregate_pubkey_var.pub_key.x)?;
        aggregate_pubkey.y.enforce_equal(&aggregate_pubkey_var.pub_key.y)?;

        let poseidon_config_var = PoseidonCRHParametersVar::new_constant(
            cs.clone(), poseidon_canonical_config::<Fr>()
        )?;
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

        let schnorr_parameters = Schnorr::setup(test_rng().gen()).unwrap();
        let parameters_var = <SchnorrVerifyGadget as SigVerifyGadget<Schnorr, Fr>>
            ::ParametersVar::new_constant(cs.clone(), schnorr_parameters)?;
        let next_ab_hash = external_inputs.0[4*K + 2].clone();
        let tss_vk_hash = external_inputs.0[4*K + 3].clone();
        let msg_var = next_ab_hash
            .to_bytes_le()?
            .into_iter()
            .chain(tss_vk_hash.to_bytes_le()?)
            .collect::<Vec<_>>();
        let valid_sig_var = <SchnorrVerifyGadget as SigVerifyGadget<Schnorr, Fr>>::verify(
            &parameters_var,
            &aggregate_pubkey_var,
            &msg_var,
            &aggregate_signature
        )?;
        valid_sig_var.enforce_equal(&Boolean::<Fr>::TRUE)?;

        for i in 0..K {
            prev_pks[i].pub_key.x.enforce_equal(&external_inputs.0[3*i + 0])?;
            prev_pks[i].pub_key.y.enforce_equal(&external_inputs.0[3*i + 1])?;
            prev_pk_vars[i].x.enforce_equal(&external_inputs.0[3*i + 0])?;
            prev_pk_vars[i].y.enforce_equal(&external_inputs.0[3*i + 1])?;
        }

        recomputed_prev_state[0].enforce_equal(&z_i[0])?;

        Ok(vec![next_ab_hash, tss_vk_hash])
    }
}

fn hash_hints_vk(vk_bytes: &[u8]) -> Fr {
    let hash_bytes = Sha256::evaluate(&(), vk_bytes).unwrap();
    let tss_vk_hash = Fr::from_le_bytes_mod_order(&hash_bytes);

    let out_bytes = PoseidonCRH::evaluate(&poseidon_canonical_config::<Fr>(), vec![tss_vk_hash]).unwrap();
    let out: Vec<Fr> = out_bytes.to_field_elements().unwrap();
    // because of modulus, we actually get two Fr elemeents, but we will only use the first one
    out[0]
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

fn prepare_external_inputs(
    aggregate_signature: &SchnorrSignature,
    prev_ab: &AddressBook,
    next_ab: &AddressBook,
    next_tss_vk: &[u8],
    bitvector: &[bool; MAX_AB_SIZE],
) -> Vec<Fr> {
    let mut external_inputs_at_step = Vec::new();
    for i in 0..MAX_AB_SIZE {
        external_inputs_at_step.push(prev_ab[i].0.x);
        external_inputs_at_step.push(prev_ab[i].0.y);
        external_inputs_at_step.push(prev_ab[i].1);
    }

    for i in 0..MAX_AB_SIZE {
        external_inputs_at_step.push(Fr::from(bitvector[i])); // even signatures present
    }

    let verifier_challenge = Fr::from_le_bytes_mod_order(
        &aggregate_signature.verifier_challenge.into_bigint().to_bytes_le());
    let prover_response = Fr::from_le_bytes_mod_order(
        &aggregate_signature.prover_response.into_bigint().to_bytes_le());
    external_inputs_at_step.push(verifier_challenge);
    external_inputs_at_step.push(prover_response);

    external_inputs_at_step.push(hash_addressbook(next_ab));
    external_inputs_at_step.push(hash_hints_vk(next_tss_vk));

    external_inputs_at_step
}


impl ProvingKey {
    pub fn deserialize(nova_pp: impl AsRef<[u8]>, decider_pp: impl AsRef<[u8]>) -> Result<Self, Error> {
        let nova_pp: NPP = N::pp_deserialize_with_mode(nova_pp.as_ref(), ark_serialize::Compress::Yes, ark_serialize::Validate::Yes, ())?;
        let decider_pp = DPP::deserialize_compressed(decider_pp.as_ref())?;
        Ok(Self { nova_pp, decider_pp })
    }

    pub fn serialize(&self) -> Result<(UncompressedProvingKeySerialized, CompressedProvingKeySerialized), Error> {
        let mut nova_pp_serialized: UncompressedProvingKeySerialized = vec![];
        self.nova_pp.serialize_compressed(&mut nova_pp_serialized)?;

        let mut decider_pp_serialized: CompressedProvingKeySerialized = vec![];
        self.decider_pp.serialize_compressed(&mut decider_pp_serialized)?;
        Ok((nova_pp_serialized, decider_pp_serialized))
    }
}

impl VerificationKey {
    pub fn deserialize(nova_vp: impl AsRef<[u8]>, decider_vp: impl AsRef<[u8]>) -> Result<Self, Error> {
        let nova_vp: NVP = N::vp_deserialize_with_mode(nova_vp.as_ref(), ark_serialize::Compress::Yes, ark_serialize::Validate::Yes, ())?;
        let decider_vp = DVP::deserialize_compressed(decider_vp.as_ref())?;
        Ok(Self { nova_vp, decider_vp })
    }

    pub fn serialize(&self) -> Result<(UncompressedVerificationKeySerialized, CompressedVerificationKeySerialized), Error> {
        let mut nova_vp_serialized: UncompressedVerificationKeySerialized = vec![];
        self.nova_vp.serialize_compressed(&mut nova_vp_serialized)?;

        let mut decider_vp_serialized: CompressedVerificationKeySerialized = vec![];
        self.decider_vp.serialize_compressed(&mut decider_vp_serialized)?;
        Ok((nova_vp_serialized, decider_vp_serialized))
    }
}

impl std::error::Error for WRAPSError {}

impl std::fmt::Display for WRAPSError {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        match *self {
            WRAPSError::InvalidInput(ref s) => write!(f, "Invalid input: {s}"),
            WRAPSError::CryptographyError => write!(f, "CryptographyError error"),
        }
    }
}

pub struct WRAPSTrustedSetup {}

impl WRAPSTrustedSetup {
    pub fn setup() -> Result<(ProvingKey, VerificationKey), WRAPSError> {
        let mut rng = ark_std::rand::rngs::OsRng;
        let F_circuit = TSSFCircuit::<MAX_AB_SIZE>::new(())
            .map_err(|_| WRAPSError::CryptographyError)?;

        let poseidon_config = poseidon_canonical_config::<Fr>();

        let nova_preprocess_params = PreprocessorParam::new(poseidon_config, F_circuit);
        let (nova_pp, nova_vp) = N::preprocess(
            &mut rng,
            &nova_preprocess_params
        ).map_err(|_| WRAPSError::CryptographyError)?;

        let (decider_pp, decider_vp) = D::preprocess(
            &mut rng,
            ((nova_pp.clone(), nova_vp.clone()), F_circuit.state_len())
        ).map_err(|_| WRAPSError::CryptographyError)?;

        Ok((
            ProvingKey { nova_pp, decider_pp },
            VerificationKey { nova_vp, decider_vp }
        ))
    }
}

pub struct WRAPS {}

impl WRAPS {

    pub fn keygen(seed: [u8; ENTROPY_SIZE]) -> (SchnorrPrivKey, SchnorrPubKey) {
        // secret is a random scalar x, and the pubkey is y = xG
        let pp = Schnorr::setup([0u8; 32]).unwrap();
        let (pk, sk) = Schnorr::keygen(&pp, seed).unwrap();
        (sk, pk)
    }

    pub fn signing_protocol(
        phase: SigningProtocolPhase, // either R1, R2, R3, or Aggregate
        protocol_instance_entropy: [u8; ENTROPY_SIZE], // reuse in all rounds of a protocol instance
        message_to_sign: impl AsRef<[u8]>, // message to sign should be output of rotation_message(..)
        signing_key: Option<&SchnorrPrivKey>, // should be None if phase == Aggregate
        public_keys: &[SchnorrPubKey], // can be [] if phase == R1, but must be non-empty otherwise
        round1_messages: &[SigningProtocolMessage], // should be [] if phase == R1
        round2_messages: &[SigningProtocolMessage], // should be [] if phase == R2
        round3_messages: &[SigningProtocolMessage], // should be [] if phase == R3
    ) -> Result<SigningProtocolObject, WRAPSError> {
        let pp = Schnorr::setup([0u8; 32]).unwrap(); // dummy entropy for dummy parameters

        match phase {
            SigningProtocolPhase::R1 => {
                assert!(round1_messages.len() == 0);
                assert!(round2_messages.len() == 0);
                assert!(round3_messages.len() == 0);
                let r1_msg: ThresholdSchnorrR1Msg = ThresholdSchnorr::sign_round1(
                    &pp,
                    protocol_instance_entropy
                ).map_err(|_| WRAPSError::CryptographyError)?;
                let r1_msg_encoded = utils::serialize(&r1_msg);
                Ok(SigningProtocolObject::ProtocolMessage(r1_msg_encoded))
            },
            SigningProtocolPhase::R2 => {
                assert!(round1_messages.len() == public_keys.len());
                assert!(round2_messages.len() == 0);
                assert!(round3_messages.len() == 0);
                let r1_msgs: Vec<ThresholdSchnorrR1Msg> = round1_messages
                    .iter()
                    .map(|m| ThresholdSchnorrR1Msg::deserialize_uncompressed(&mut &m[..]).unwrap())
                    .collect();
                let r2_msg: ThresholdSchnorrR2Msg = ThresholdSchnorr::sign_round2(
                    &pp,
                    protocol_instance_entropy,
                    &r1_msgs
                ).map_err(|_| WRAPSError::CryptographyError)?;
                let r2_msg_encoded = utils::serialize(&r2_msg);
                Ok(SigningProtocolObject::ProtocolMessage(r2_msg_encoded))
            },
            SigningProtocolPhase::R3 => {
                assert!(round1_messages.len() == public_keys.len());
                assert!(round2_messages.len() == public_keys.len());
                assert!(round3_messages.len() == 0);
                let r1_msgs: Vec<ThresholdSchnorrR1Msg> = round1_messages
                    .iter()
                    .map(|m| ThresholdSchnorrR1Msg::deserialize_uncompressed(&mut &m[..]).unwrap())
                    .collect();
                let r2_msgs: Vec<ThresholdSchnorrR2Msg> = round2_messages
                    .iter()
                    .map(|m| ThresholdSchnorrR2Msg::deserialize_uncompressed(&mut &m[..]).unwrap())
                    .collect();
                let r3_msg = ThresholdSchnorr::sign_round3(
                    &pp,
                    protocol_instance_entropy,
                    message_to_sign.as_ref(),
                    signing_key.unwrap(),
                    public_keys,
                    &r1_msgs,
                    &r2_msgs
                ).map_err(|_| WRAPSError::CryptographyError)?;
                let r3_msg_encoded = utils::serialize(&r3_msg);
                Ok(SigningProtocolObject::ProtocolMessage(r3_msg_encoded))
            },
            SigningProtocolPhase::Aggregate => {
                assert!(round1_messages.len() == public_keys.len());
                assert!(round2_messages.len() == public_keys.len());
                assert!(round3_messages.len() == public_keys.len());
                let r1_msgs: Vec<ThresholdSchnorrR1Msg> = round1_messages
                    .iter()
                    .map(|m| ThresholdSchnorrR1Msg::deserialize_uncompressed(&mut &m[..]).unwrap())
                    .collect();
                let r2_msgs: Vec<ThresholdSchnorrR2Msg> = round2_messages
                    .iter()
                    .map(|m| ThresholdSchnorrR2Msg::deserialize_uncompressed(&mut &m[..]).unwrap())
                    .collect();
                let r3_msgs: Vec<ThresholdSchnorrR3Msg> = round3_messages
                    .iter()
                    .map(|m| ThresholdSchnorrR3Msg::deserialize_uncompressed(&mut &m[..]).unwrap())
                    .collect();
                let signature = ThresholdSchnorr::aggregate(
                    &pp,
                    message_to_sign.as_ref(),
                    public_keys,
                    &r1_msgs,
                    &r2_msgs,
                    &r3_msgs,
                ).map_err(|_| WRAPSError::CryptographyError)?;
                Ok(SigningProtocolObject::ProtocolOutput(signature))
            },
        }
    }

    pub fn verify_signature(
        public_keys: &[SchnorrPubKey],
        message: impl AsRef<[u8]>,
        signature: &SchnorrSignature
    ) -> Result<bool, WRAPSError> {
        let pp = Schnorr::setup([0u8; 32]).unwrap(); // dummy entropy for dummy parameters
        let aggregate_pk = public_keys
            .iter()
            .fold(SchnorrPubKey::zero(), |acc, pk| (acc + pk).into_affine());
        Schnorr::verify(&pp, &aggregate_pk, message.as_ref(), signature)
            .map_err(|_| WRAPSError::CryptographyError)
    }

    pub fn rotation_message(ab_next: &AddressBook, tss_vk: impl AsRef<[u8]>) -> Vec<u8> {
        [
            hash_addressbook(ab_next).into_bigint().to_bytes_le(), 
            hash_hints_vk(tss_vk.as_ref()).into_bigint().to_bytes_le()
        ].concat()
    }

    pub fn setup_prover(
        nova_pp: impl AsRef<[u8]>,
        decider_pp: impl AsRef<[u8]>,
    ) -> Result<ProvingKey, WRAPSError> {
        let pk = ProvingKey::deserialize(nova_pp, decider_pp)
            .map_err(|_| WRAPSError::CryptographyError)?;
        Ok(pk)
    }

    pub fn setup_verifier(
        nova_vp: impl AsRef<[u8]>,
        decider_vp: impl AsRef<[u8]>,
    ) -> Result<VerificationKey, WRAPSError> {
        let vk = VerificationKey::deserialize(nova_vp, decider_vp)
            .map_err(|_| WRAPSError::CryptographyError)?;
        Ok(vk)
    }

    pub fn get_compressed_verification_key_bytes(
        vk: &VerificationKey
    ) -> Result<CompressedVerificationKeySerialized, WRAPSError> {
        let mut decider_vp_serialized = vec![];
        vk.decider_vp.serialize_compressed(&mut decider_vp_serialized)
            .map_err(|_| WRAPSError::CryptographyError)?;

        Ok(decider_vp_serialized)
    }

    #[allow(clippy::too_many_arguments)]
    /// Creates the first proof for the genesis AddressBook.
    pub fn construct_wraps_proof(
        pk: &ProvingKey,                         // proving key output by sp1 setup
        vk: &VerificationKey,                    // verifying key output by sp1 setup
        ab_genesis_hash: &AddressBookHash,            // genesis AddressBook hash
        prev_ab: &AddressBook,                        // current AddressBook
        next_ab: &AddressBook,                        // next AddressBook
        prev_proof: Option<UncompressedProofSerialized>,        // the previous proof
        tss_vk: impl AsRef<[u8]>,                     // TSS verification key for the next AddressBook
        aggregate_signature: &SchnorrSignature,       // threshold Schnorr signature attesting the next AddressBook
        bitvector: &[bool; MAX_AB_SIZE],              // bitvector indicating which members signed the signature
    ) -> Result<(UncompressedProofSerialized, CompressedProofSerialized), WRAPSError> {
        let is_genesis: bool = prev_proof.is_none();
        if is_genesis {
            // ensure genesis ab hash matches
            assert_eq!(*ab_genesis_hash, hash_addressbook(prev_ab));
            // first proof uses same address book for current and next
            assert_eq!(hash_addressbook(next_ab), hash_addressbook(prev_ab));
        }

        let ab_rotation_message: Vec<u8> = [
            hash_addressbook(&next_ab).into_bigint().to_bytes_le(), 
            hash_hints_vk(tss_vk.as_ref()).into_bigint().to_bytes_le()
        ].concat();

        // compute aggregate public key
        let aggregate_pubkey = (0..MAX_AB_SIZE)
            .filter(|&i| bitvector[i])
            .fold(ark_ed_on_bn254::EdwardsAffine::zero(), |acc, i| acc.add(prev_ab[i].0).into_affine());

        let schnorr_parameters = Schnorr::setup([0u8; 32]).unwrap();
        assert!(Schnorr::verify(&schnorr_parameters, &aggregate_pubkey, &ab_rotation_message, &aggregate_signature).unwrap());

        let external_inputs_at_step = prepare_external_inputs(
            &aggregate_signature,
            &prev_ab,
            &next_ab,
            tss_vk.as_ref(),
            bitvector,
        );

        let mut ivc_instance = if is_genesis {
            let F_circuit = TSSFCircuit::<MAX_AB_SIZE>::new(())
                .map_err(|_| WRAPSError::CryptographyError)?;
            let initial_state = vec![hash_addressbook(&prev_ab), hash_hints_vk(tss_vk.as_ref())];
            let mut instance = N::init(&(pk.nova_pp.clone(), vk.nova_vp.clone()), F_circuit, initial_state.clone())
                .map_err(|_| WRAPSError::CryptographyError)?;
            instance.prove_step(thread_rng(), VecF(external_inputs_at_step.clone()), None)
                .map_err(|_| WRAPSError::CryptographyError)?;
            instance
        } else {
            let ivc_proof = NovaProof::deserialize_compressed(prev_proof.unwrap().as_slice()).unwrap();
            N::from_ivc_proof(ivc_proof, (), (pk.nova_pp.clone(), vk.nova_vp.clone()))
                .map_err(|_| WRAPSError::CryptographyError)?
        };

        ivc_instance.prove_step(thread_rng(), VecF(external_inputs_at_step.clone()), None)
            .map_err(|_| WRAPSError::CryptographyError)?;
        N::verify(vk.nova_vp.clone(), ivc_instance.ivc_proof())
            .map_err(|_| WRAPSError::CryptographyError)?;

        let mut next_ivc_proof_encoded = vec![];
        ivc_instance.ivc_proof().serialize_compressed(&mut next_ivc_proof_encoded).unwrap();

        let proof = D::prove(thread_rng(), pk.decider_pp.clone(), ivc_instance.clone())
            .map_err(|_| WRAPSError::CryptographyError)?;

        let verified = D::verify(
            vk.decider_vp.clone(),
            ivc_instance.i,
            ivc_instance.z_0.clone(),
            ivc_instance.z_i.clone(),
            &ivc_instance.U_i.get_commitments(),
            &ivc_instance.u_i.get_commitments(),
            &proof,
        ).map_err(|_| WRAPSError::CryptographyError)?;
        assert!(verified);

        // serialize the proof
        let compressed_proof = ProofData {
            i: ivc_instance.i,
            z_0: ivc_instance.z_0,
            z_i: ivc_instance.z_i,
            U_i_commitments: ivc_instance.U_i.get_commitments(),
            u_i_commitments: ivc_instance.u_i.get_commitments(),
            proof,
        };
        let mut compressed_proof_serialized = vec![];
        compressed_proof.serialize_compressed(&mut compressed_proof_serialized).unwrap();

        let decider_vp_serialized = Self::get_compressed_verification_key_bytes(vk)?;

        assert!(Self::verify_compressed_wraps_proof(
            &decider_vp_serialized,
            &compressed_proof_serialized
        ).map_err(|_| WRAPSError::CryptographyError)?);

        Ok((next_ivc_proof_encoded, compressed_proof_serialized))
    }

    pub fn verify_compressed_wraps_proof(
        compressed_vk_serialized: &CompressedVerificationKeySerialized,
        proof_serialized: &CompressedProofSerialized,
    ) -> Result<bool, Error> {
        type N = Nova<G1, G2, TSSFCircuit<MAX_AB_SIZE>, KZG<'static, PairingCurve>, Pedersen<G2>, false>;
        type D = DeciderEth<G1, G2, TSSFCircuit<MAX_AB_SIZE>, KZG<'static, PairingCurve>, Pedersen<G2>, Groth16<PairingCurve>, N>;

        let decider_vp =
            VerifierParam::<
                G1,
                <KZG<'static, PairingCurve> as CommitmentScheme<G1>>::VerifierParams,
                <Groth16<PairingCurve> as ark_snark::SNARK<Fr>>::VerifyingKey,
            >::deserialize_compressed(compressed_vk_serialized.as_slice())?;

        let compressed_proof = ProofData::deserialize_compressed(proof_serialized.as_slice())?;

        let verified = D::verify(
            decider_vp,
            compressed_proof.i,
            compressed_proof.z_0,
            compressed_proof.z_i,
            &compressed_proof.U_i_commitments,
            &compressed_proof.u_i_commitments,
            &compressed_proof.proof,
        )?;
        Ok(verified)
    }
        
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::{env, path::PathBuf};

    fn create_new_addressbook() -> (AddressBook, Keys) {
        let rng = &mut thread_rng();
        let schnorr_parameters = Schnorr::setup(rng.gen()).unwrap();
        let mut keys = Vec::new();
        let mut ab = Vec::new();
        for _i in 0..MAX_AB_SIZE {
            let (pk, sk) = Schnorr::keygen(&schnorr_parameters, rng.gen()).unwrap();
            let weight = Fr::from(1);
            keys.push(sk);
            ab.push((pk, weight));
        }
        (ab.try_into().unwrap(), keys.try_into().unwrap())
    }

    fn even_bitvector() -> [bool; MAX_AB_SIZE] {
        std::array::from_fn(|i| i % 2 == 0 || i % 3 == 0)
    }

    fn signing_subset<'a>(
        ab: &'a AddressBook,
        keys: &'a Keys,
        bitvector: &[bool; MAX_AB_SIZE],
    ) -> (Vec<SchnorrPubKey>, Vec<&'a SchnorrPrivKey>) {
        let mut pks = Vec::new();
        let mut sk_refs = Vec::new();
        for i in 0..MAX_AB_SIZE {
            if bitvector[i] {
                pks.push(ab[i].0);
                sk_refs.push(&keys[i]);
            }
        }
        (pks, sk_refs)
    }

    fn threshold_sign(message_to_sign: &[u8], pks: &[SchnorrPubKey], sk_refs: &[&SchnorrPrivKey]) -> SchnorrSignature {
        let n = pks.len();
        let rng = &mut thread_rng();
        let seeds: Vec<[u8; ENTROPY_SIZE]> = (0..pks.len())
            .map(|_| rng.gen())
            .collect();

        // Round 1 for each participant
        let r1_msgs: Vec<SigningProtocolMessage> = (0..n)
            .map(|i| match WRAPS::signing_protocol(
                SigningProtocolPhase::R1,
                seeds[i],
                message_to_sign,
                None,
                &[],
                &[],
                &[],
                &[]
            ).unwrap() {
                SigningProtocolObject::ProtocolMessage(m) => m,
                _ => unreachable!(),
            })
            .collect();

        // Round 2 for each participant
        let r2_msgs: Vec<SigningProtocolMessage> = (0..n)
            .map(|i| match WRAPS::signing_protocol(
                SigningProtocolPhase::R2,
                seeds[i],
                message_to_sign,
                None,
                pks,
                &r1_msgs,
                &[],
                &[]
            ).unwrap() {
                SigningProtocolObject::ProtocolMessage(m) => m,
                _ => unreachable!(),
            })
            .collect();

        // Round 3 for each participant (signers only)
        let r3_msgs: Vec<SigningProtocolMessage> = (0..n)
            .map(|i| match WRAPS::signing_protocol(
                SigningProtocolPhase::R3,
                seeds[i],
                message_to_sign,
                Some(sk_refs[i]),
                pks,
                &r1_msgs,
                &r2_msgs,
                &[]
            ).unwrap() {
                SigningProtocolObject::ProtocolMessage(m) => m,
                _ => unreachable!(),
            })
            .collect();

        // Aggregate signatures
        match WRAPS::signing_protocol(
            SigningProtocolPhase::Aggregate,
            [0u8; ENTROPY_SIZE], // dummy entropy for aggregation
            message_to_sign,
            None,
            pks,
            &r1_msgs,
            &r2_msgs,
            &r3_msgs,
        ).unwrap() {
            SigningProtocolObject::ProtocolOutput(sig) => sig,
            _ => unreachable!(),
        }
    }

    #[test]
    fn wraps_trusted_setup() {
        let (pk, vk) = WRAPSTrustedSetup::setup().unwrap();
        let (nova_pp_serialized, decider_pp_serialized) = pk.serialize().unwrap();
        let (nova_vp_serialized, decider_vp_serialized) = vk.serialize().unwrap();

        let cwd = env::current_dir().unwrap();
        std::fs::write(cwd.join("resources/nova_pp.bin"), &nova_pp_serialized).unwrap();
        std::fs::write(cwd.join("resources/nova_vp.bin"), &nova_vp_serialized).unwrap();
        std::fs::write(cwd.join("resources/decider_pp.bin"), &decider_pp_serialized).unwrap();
        std::fs::write(cwd.join("resources/decider_vp.bin"), &decider_vp_serialized).unwrap();
    }

    #[test]
    fn wraps_simulation() {
        let num_steps = 10;

        let start = std::time::Instant::now();
        let cwd = env::current_dir().unwrap();
        let wraps_pk = WRAPS::setup_prover(
            std::fs::read(cwd.join("resources/nova_pp.bin")).unwrap(),
            std::fs::read(cwd.join("resources/decider_pp.bin")).unwrap()
        ).unwrap();
        let wraps_vk = WRAPS::setup_verifier(
            std::fs::read(cwd.join("resources/nova_vp.bin")).unwrap(),
            std::fs::read(cwd.join("resources/decider_vp.bin")).unwrap()
        ).unwrap();
        println!("Parsed all parameters: {:?}", start.elapsed());

        let schnorr_parameters = Schnorr::setup([0u8; 32]).unwrap();
        // Build genesis address book and keys
        let (genesis_ab, genesis_keys) = create_new_addressbook();
        let ab_genesis_hash = super::hash_addressbook(&genesis_ab);

        // -------------------------------- Global State across loop iterations --------------------------------
        let mut prev_uncompressed_wraps_proof = vec![];

        // --------------------------------------- Step 0 is special ---------------------------------------

        let (mut prev_ab, mut prev_keys) = (genesis_ab, genesis_keys);
        // compute a step of the IVC
        for i in 0..num_steps {
            let (next_ab, next_keys) = if i == 0 {
                (prev_ab.clone(), prev_keys.clone())
            } else {
                create_new_addressbook()
            };
            let next_tss_vk = [0u8; 1280]; // placeholder for TSS vk bytes

            // message being signed via threshold Schnorr
            let message: Vec<u8> = [
                hash_addressbook(&next_ab).into_bigint().to_bytes_le(), 
                hash_hints_vk(&next_tss_vk).into_bigint().to_bytes_le()
            ].concat();

            let (pks_present, sks_present) = signing_subset(&prev_ab, &prev_keys, &even_bitvector());

            // compute aggregate public key
            let aggregate_pubkey = pks_present
                .iter()
                .fold(SchnorrPubKey::zero(), |acc, pk| (acc + pk).into_affine());

            // simulate the signing protocol
            let aggregate_signature = threshold_sign(&message, &pks_present, &sks_present);

            assert!(Schnorr::verify(&schnorr_parameters, &aggregate_pubkey, &message, &aggregate_signature).unwrap());

            let start = std::time::Instant::now();
            let (next_uncompressed, next_compressed) = WRAPS::construct_wraps_proof(
                &wraps_pk,
                &wraps_vk,
                &ab_genesis_hash,
                &prev_ab,
                &next_ab,
                if i == 0 { None } else { Some(prev_uncompressed_wraps_proof.clone()) },
                &next_tss_vk,
                &aggregate_signature,
                &even_bitvector(),
            ).expect("WRAPS proof should be created");
            println!("Step {} WRAPS proof creation time: {:?}", i, start.elapsed());

            let compressed_vk_bytes = WRAPS::get_compressed_verification_key_bytes(&wraps_vk).unwrap();

            let verified = WRAPS::verify_compressed_wraps_proof(&compressed_vk_bytes, &next_compressed).unwrap();
            assert!(verified);

            prev_ab = next_ab;
            prev_keys = next_keys;
            prev_uncompressed_wraps_proof = next_uncompressed;
        }
    }
}
