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

use digest::typenum::bit;
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

/********************************* Publicly Exposed Types *********************************/

/// Error enum to wrap underlying failures in RAPS operations,
/// or wrap errors coming from dependencies (namely, arkworks).
#[derive(Debug)]
pub enum WRAPSError {
    /// Multi-purpose error type for describing invalid inputs
    InvalidInput(String),
    /// Multi-purpose error type for describing prover failure
    CryptographyError,
    /// Error indicating address book size exceeded maximum allowed
    AddressBookSizeExceeded,
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

pub enum SigningProtocolObject {
    ProtocolMessage(SigningProtocolMessage),
    ProtocolOutput(SchnorrSignature),
}

pub type CompressedProofSerialized = Vec<u8>;
pub type UncompressedProofSerialized = Vec<u8>;

pub type UncompressedProvingKeySerialized = Vec<u8>;
pub type CompressedProvingKeySerialized = Vec<u8>;
pub type UncompressedVerificationKeySerialized = Vec<u8>;
pub type CompressedVerificationKeySerialized = Vec<u8>;

pub type UncompressedProvingKey = NPP;
pub type UncompressedVerificationKey = NVP;

pub struct ProvingKey {
    pub nova_pp: UncompressedProvingKey,
}

pub struct VerificationKey {
    pub nova_vp: UncompressedVerificationKey,
}

/********************************* Parameters *********************************/

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

// [prev_pk_x, prev_pk_y, sig_challenge, sig_response, next_pk_x, next_pk_y]
const MAX_EXT_INPUTS: usize = 6;

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

type Circuit = KeyChainFCircuit;
type N = Nova<G1, G2, Circuit, KZG<'static, PairingCurve>, Pedersen<G2>, false>;
type NovaProof = <N as FoldingScheme<G1, G2, Circuit>>::IVCProof;
type NPP = ProverParams<G1, G2, KZG<'static, PairingCurve>, Pedersen<G2>, false>;
type NVP = VerifierParams<G1, G2, KZG<'static, PairingCurve>, Pedersen<G2>, false>;
type D = DeciderEth<G1, G2, Circuit, KZG<'static, PairingCurve>, Pedersen<G2>, Groth16<PairingCurve>, N>;

#[derive(CanonicalSerialize, CanonicalDeserialize)]
struct ProofData {
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
pub struct KeyChainFCircuit;

impl FCircuit<Fr> for KeyChainFCircuit {
    type Params = ();
    type ExternalInputs = VecF<Fr, MAX_EXT_INPUTS>;
    type ExternalInputsVar = VecFpVar<Fr, MAX_EXT_INPUTS>;

    fn new(_params: Self::Params) -> Result<Self, Error> {
        // This circuit has no tunable parameters; return the unit struct.
        Ok(Self { })
    }

    fn state_len(&self) -> usize { 2 }

    /// generates the constraints for the step of F for the given z_i
    fn generate_step_constraints(
        &self,
        cs: ConstraintSystemRef<Fr>,
        _i: usize,
        z_i: Vec<FpVar<Fr>>,
        external_inputs: Self::ExternalInputsVar,
    ) -> Result<Vec<FpVar<Fr>>, SynthesisError> {

        let prev_pk = JubJubVar::new_witness(cs.clone(), || {
            Ok(ark_ed_on_bn254::EdwardsAffine::new(
                external_inputs.0[0].value()?,
                external_inputs.0[1].value()?,
            ))
        })?;
        let next_pk = JubJubVar::new_witness(cs.clone(), || {
            Ok(ark_ed_on_bn254::EdwardsAffine::new(
                external_inputs.0[4].value()?,
                external_inputs.0[5].value()?,
            ))
        })?;

        let signature = SchnorrSignatureVar {
            verifier_challenge: external_inputs.0[2].to_bytes_le()?,
            prover_response: external_inputs.0[3].to_bytes_le()?,
            _group: PhantomData,
        };

        let prev_schnorr_pubkey_var = SchnorrPubKeyVar {
            pub_key: prev_pk.clone(),
            _group: PhantomData,
        };

        let schnorr_parameters = Schnorr::setup(test_rng().gen()).unwrap();
        let parameters_var = <SchnorrVerifyGadget as SigVerifyGadget<Schnorr, Fr>>
            ::ParametersVar::new_constant(cs.clone(), schnorr_parameters)?;

        let msg_var = external_inputs.0[4]
            .to_bytes_le()?
            .into_iter()
            .chain(external_inputs.0[5].to_bytes_le()?)
            .collect::<Vec<_>>();

        let valid_sig_var = <SchnorrVerifyGadget as SigVerifyGadget<Schnorr, Fr>>::verify(
            &parameters_var,
            &prev_schnorr_pubkey_var,
            &msg_var,
            &signature
        )?;
        valid_sig_var.enforce_equal(&Boolean::<Fr>::TRUE)?;

        prev_pk.x.enforce_equal(&external_inputs.0[0])?;
        prev_pk.y.enforce_equal(&external_inputs.0[1])?;
        next_pk.x.enforce_equal(&external_inputs.0[4])?;
        next_pk.y.enforce_equal(&external_inputs.0[5])?;

        z_i[0].enforce_equal(&external_inputs.0[0])?;
        z_i[1].enforce_equal(&external_inputs.0[1])?;

        Ok(vec![external_inputs.0[4].clone(), external_inputs.0[5].clone()])
    }
}

/// Computes the message signed during rotation: `next_pk_x || next_pk_y` in LE bytes.
fn compute_key_rotation_message(next_public_key: &SchnorrPubKey) -> Vec<u8> {
    [
        next_public_key.x.into_bigint().to_bytes_le(),
        next_public_key.y.into_bigint().to_bytes_le(),
    ]
    .concat()
}

/// Formats user-visible data into the external-input vector consumed by the Nova circuit.
fn prepare_external_inputs(
    signature: &SchnorrSignature,
    prev_public_key: &SchnorrPubKey,
    next_public_key: &SchnorrPubKey,
) -> Vec<Fr> {
    let verifier_challenge =
        Fr::from_le_bytes_mod_order(&signature.verifier_challenge.into_bigint().to_bytes_le());
    let prover_response =
        Fr::from_le_bytes_mod_order(&signature.prover_response.into_bigint().to_bytes_le());

    vec![
        prev_public_key.x,
        prev_public_key.y,
        verifier_challenge,
        prover_response,
        next_public_key.x,
        next_public_key.y,
    ]
}


impl ProvingKey {
    /// Recreates a proving key from serialized Nova and decider artifacts.
    pub fn deserialize(nova_pp: impl AsRef<[u8]>) -> Result<Self, Error> {
        let nova_pp: NPP = N::pp_deserialize_with_mode(nova_pp.as_ref(), ark_serialize::Compress::Yes, ark_serialize::Validate::Yes, ())?;
        Ok(Self { nova_pp })
    }

    /// Serializes both Nova and decider proving parameters.
    pub fn serialize(&self) -> Result<UncompressedProvingKeySerialized, Error> {
        let mut nova_pp_serialized: UncompressedProvingKeySerialized = vec![];
        self.nova_pp.serialize_compressed(&mut nova_pp_serialized)?;
        Ok(nova_pp_serialized)
    }
}

impl VerificationKey {
    /// Recreates a verification key from serialized Nova and decider artifacts.
    pub fn deserialize(nova_vp: impl AsRef<[u8]>) -> Result<Self, Error> {
        let nova_vp: NVP = N::vp_deserialize_with_mode(nova_vp.as_ref(), ark_serialize::Compress::Yes, ark_serialize::Validate::Yes, ())?;
        Ok(Self { nova_vp })
    }

    /// Serializes both Nova and decider verifier parameters.
    pub fn serialize(&self) -> Result<UncompressedVerificationKeySerialized, Error> {
        let mut nova_vp_serialized: UncompressedVerificationKeySerialized = vec![];
        self.nova_vp.serialize_compressed(&mut nova_vp_serialized)?;
        Ok(nova_vp_serialized)
    }
}

impl std::error::Error for WRAPSError {}

impl std::fmt::Display for WRAPSError {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        match *self {
            WRAPSError::InvalidInput(ref s) => write!(f, "Invalid input: {s}"),
            WRAPSError::CryptographyError => write!(f, "CryptographyError error"),
            WRAPSError::AddressBookSizeExceeded => write!(f, "Address book size exceeded maximum allowed"),
        }
    }
}

pub struct WRAPSTrustedSetup {}

impl WRAPSTrustedSetup {
    /// Runs the trusted setup to produce matching proving and verification keys for WRAPS.
    pub fn setup() -> Result<(ProvingKey, VerificationKey), WRAPSError> {
        let mut rng = ark_std::rand::rngs::OsRng;
        let F_circuit = Circuit::new(())
            .map_err(|_| WRAPSError::CryptographyError)?;

        let poseidon_config = poseidon_canonical_config::<Fr>();

        let nova_preprocess_params = PreprocessorParam::new(poseidon_config, F_circuit);
        // Generate Nova parameters for the WRAPS folding circuit.
        let (nova_pp, nova_vp) = N::preprocess(
            &mut rng,
            &nova_preprocess_params
        ).map_err(|_| WRAPSError::CryptographyError)?;

        Ok((
            ProvingKey { nova_pp },
            VerificationKey { nova_vp }
        ))
    }
}

pub struct WRAPS {}

impl WRAPS {

    /// Derives a Schnorr keypair deterministically from the provided entropy.
    ///
    /// # Arguments
    /// * `seed` - 32-byte entropy used to sample the private key deterministically.
    ///
    /// # Returns
    /// * `Ok((sk, pk))` containing the Schnorr secret and public keys.
    /// * `Err(WRAPSError::CryptographyError)` if parameter generation or key derivation fails.
    pub fn keygen(
        seed: [u8; ENTROPY_SIZE]
    ) -> Result<(SchnorrPrivKey, SchnorrPubKey), WRAPSError> {
        // Initialize Schnorr parameters deterministically for reproducible keygen.
        // secret is a random scalar x, and the pubkey is y = xG
        let pp = Schnorr::setup([0u8; 32])
            .map_err(|_| WRAPSError::CryptographyError)?;
        // Derive the keypair from the supplied seed.
        let (pk, sk) = Schnorr::keygen(&pp, seed)
            .map_err(|_| WRAPSError::CryptographyError)?;
        Ok((sk, pk))
    }

    /// Executes a single phase of the threshold Schnorr signing protocol.
    ///
    /// # Arguments
    /// * `phase` - Which protocol phase to execute (R1, R2, R3, or Aggregate).
    /// * `protocol_instance_entropy` - Participant-specific randomness reused across rounds.
    /// * `message_to_sign` - Byte message that rounds R3/Aggregate must attest.
    /// * `signing_key` - Optional private key required only during phase R3.
    /// * `public_keys` - Participants' public keys; must be present for phases beyond R1.
    /// * `round1_messages` / `round2_messages` / `round3_messages` - Messages collected from prior rounds.
    ///
    /// # Returns
    /// * `Ok(SigningProtocolObject::ProtocolMessage(_))` for R1–R3 containing the serialized round output.
    /// * `Ok(SigningProtocolObject::ProtocolOutput(_))` for Aggregate containing the final Schnorr signature.
    /// * `Err(WRAPSError::CryptographyError)` if Schnorr operations fail.
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
        // Use fixed parameters so every participant derives identical protocol randomness.
        let pp = Schnorr::setup([0u8; 32]).unwrap(); // dummy entropy for dummy parameters

        match phase {
            SigningProtocolPhase::R1 => {
                // Round 1 only needs fresh commitments, no prior messages expected.
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
                // Round 2 produces each signer's commitments; all R1 messages must be present.
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
                // Encode the second-round commitments to broadcast to the committee.
                let r2_msg_encoded = utils::serialize(&r2_msg);
                Ok(SigningProtocolObject::ProtocolMessage(r2_msg_encoded))
            },
            SigningProtocolPhase::R3 => {
                // Round 3 produces each signer’s response; all prior messages must be present.
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
                // Return the serialized round-3 share to be gathered by the aggregator.
                let r3_msg_encoded = utils::serialize(&r3_msg);
                Ok(SigningProtocolObject::ProtocolMessage(r3_msg_encoded))
            },
            SigningProtocolPhase::Aggregate => {
                // Aggregator verifies inputs and bundles all shares into a final signature.
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

    /// Verifies a Schnorr signature for a single signer key.
    pub fn verify_signature(
        public_key: &SchnorrPubKey,
        message: impl AsRef<[u8]>,
        signature: &SchnorrSignature,
    ) -> Result<bool, WRAPSError> {
        let pp = Schnorr::setup([0u8; 32]).unwrap();
        Schnorr::verify(&pp, public_key, message.as_ref(), signature)
            .map_err(|_| WRAPSError::CryptographyError)
    }

    /// Builds the message that the current key signs to authorize the next key.
    pub fn compute_rotation_message(
        next_public_key: &SchnorrPubKey,
    ) -> Result<Vec<u8>, WRAPSError> {
        Ok(compute_key_rotation_message(next_public_key))
    }

    /// Reconstructs a proving key from serialized Nova and decider parameters.
    ///
    /// # Arguments
    /// * `nova_pp` - Byte slice containing Nova prover parameters.
    /// * `decider_pp` - Byte slice containing decider prover parameters.
    ///
    /// # Returns
    /// * `Ok(ProvingKey)` ready for WRAPS proof construction.
    /// * `Err(WRAPSError::CryptographyError)` if deserialization fails.
    pub fn setup_prover(
        nova_pp: impl AsRef<[u8]>,
    ) -> Result<ProvingKey, WRAPSError> {
        // Deserialize both Nova and decider proving artifacts from disk-ready bytes.
        let pk = ProvingKey::deserialize(nova_pp)
            .map_err(|_| WRAPSError::CryptographyError)?;
        Ok(pk)
    }

    /// Reconstructs a verification key from serialized Nova and decider parameters.
    ///
    /// # Arguments
    /// * `nova_vp` - Byte slice with Nova verifier parameters.
    /// * `decider_vp` - Byte slice with decider verifier parameters.
    ///
    /// # Returns
    /// * `Ok(VerificationKey)` suitable for WRAPS proof verification.
    /// * `Err(WRAPSError::CryptographyError)` if deserialization fails.
    pub fn setup_verifier(
        nova_vp: impl AsRef<[u8]>,
    ) -> Result<VerificationKey, WRAPSError> {
        // Deserialize the verification artifacts for Nova and the decider.
        let vk = VerificationKey::deserialize(nova_vp)
            .map_err(|_| WRAPSError::CryptographyError)?;
        Ok(vk)
    }

    #[allow(clippy::too_many_arguments)]
    /// Creates/extends a WRAPS proof where each step is:
    /// `prev_public_key` signing `next_public_key`.
    pub fn construct_wraps_proof(
        pk: &ProvingKey,
        vk: &VerificationKey,
        genesis_public_key: &SchnorrPubKey,
        prev_public_key: &SchnorrPubKey,
        next_public_key: &SchnorrPubKey,
        prev_proof: Option<UncompressedProofSerialized>,
        signature: &SchnorrSignature,
    ) -> Result<UncompressedProofSerialized, WRAPSError> {
        let is_genesis = prev_proof.is_none();
        if is_genesis && *genesis_public_key != *prev_public_key {
            return Err(WRAPSError::InvalidInput(
                "genesis_public_key must match prev_public_key at step 0".to_string(),
            ));
        }

        let rotation_message = Self::compute_rotation_message(next_public_key)?;
        let signature_valid = Self::verify_signature(prev_public_key, &rotation_message, signature)?;
        if !signature_valid {
            return Err(WRAPSError::InvalidInput(
                "invalid signature for key rotation".to_string(),
            ));
        }

        let external_inputs_at_step =
            prepare_external_inputs(signature, prev_public_key, next_public_key);

        let mut ivc_instance = if is_genesis {
            let F_circuit = Circuit::new(()).map_err(|_| WRAPSError::CryptographyError)?;
            let initial_state = vec![genesis_public_key.x, genesis_public_key.y];
            N::init(
                &(pk.nova_pp.clone(), vk.nova_vp.clone()),
                F_circuit,
                initial_state,
            )
            .map_err(|_| WRAPSError::CryptographyError)?
        } else {
            let ivc_proof = NovaProof::deserialize_compressed(prev_proof.unwrap().as_slice()).unwrap();
            N::from_ivc_proof(ivc_proof, (), (pk.nova_pp.clone(), vk.nova_vp.clone()))
                .map_err(|_| WRAPSError::CryptographyError)?
        };

        ivc_instance
            .prove_step(thread_rng(), VecF(external_inputs_at_step), None)
            .map_err(|_| WRAPSError::CryptographyError)?;
        N::verify(vk.nova_vp.clone(), ivc_instance.ivc_proof())
            .map_err(|_| WRAPSError::CryptographyError)?;

        let mut next_ivc_proof_encoded = vec![];
        ivc_instance
            .ivc_proof()
            .serialize_compressed(&mut next_ivc_proof_encoded)
            .unwrap();
        println!("ivc proof size: {} bytes", next_ivc_proof_encoded.len());

        Ok(next_ivc_proof_encoded)
    }

    /// Checks a compressed WRAPS proof against a compressed verification key.
    ///
    /// # Arguments
    /// * `compressed_vk_serialized` - Compressed decider verifier parameters produced by [`get_compressed_verification_key_bytes`].
    /// * `proof_serialized` - Compressed proof bundle returned by [`construct_wraps_proof`].
    ///
    /// # Returns
    /// * `Ok(true)` if the decider successfully verifies the proof.
    /// * `Ok(false)` if verification fails.
    /// * `Err(folding_schemes::Error)` if deserialization or verification encounters an error.
    pub fn verify_compressed_wraps_proof(
        compressed_vk_serialized: &CompressedVerificationKeySerialized,
        proof_serialized: &CompressedProofSerialized,
    ) -> Result<bool, Error> {
        type N = Nova<G1, G2, Circuit, KZG<'static, PairingCurve>, Pedersen<G2>, false>;
        type D = DeciderEth<G1, G2, Circuit, KZG<'static, PairingCurve>, Pedersen<G2>, Groth16<PairingCurve>, N>;

        // Decode the decider verification parameters from serialized form.
        let decider_vp =
            VerifierParam::<
                G1,
                <KZG<'static, PairingCurve> as CommitmentScheme<G1>>::VerifierParams,
                <Groth16<PairingCurve> as ark_snark::SNARK<Fr>>::VerifyingKey,
            >::deserialize_compressed(compressed_vk_serialized.as_slice())?;

        // Decode the proof bundle emitted during `construct_wraps_proof`.
        let compressed_proof = ProofData::deserialize_compressed(proof_serialized.as_slice())?;

        // Delegate verification to the decider gadget and return its verdict.
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
    use std::env;

    #[test]
    fn wraps_trusted_setup() {
        let (pk, vk) = WRAPSTrustedSetup::setup().unwrap();
        let nova_pp_serialized = pk.serialize().unwrap();
        let nova_vp_serialized = vk.serialize().unwrap();

        let cwd = env::current_dir().unwrap();
        std::fs::write(cwd.join("resources/nova_pp.bin"), &nova_pp_serialized).unwrap();
        std::fs::write(cwd.join("resources/nova_vp.bin"), &nova_vp_serialized).unwrap();
    }

    #[test]
    fn wraps_simulation() {
        let num_steps = 10;

        let start = std::time::Instant::now();
        let cwd = env::current_dir().unwrap();
        let nova_pp_bytes = std::fs::read(cwd.join("resources/nova_pp.bin")).unwrap();
        let nova_vp_bytes = std::fs::read(cwd.join("resources/nova_vp.bin")).unwrap();
        println!("Read all parameters from disk: {:?}", start.elapsed());

        let start = std::time::Instant::now();
        let wraps_pk = WRAPS::setup_prover(nova_pp_bytes).unwrap();
        let wraps_vk = WRAPS::setup_verifier(nova_vp_bytes).unwrap();
        println!("Parsed all parameters: {:?}", start.elapsed());

        let rng = &mut thread_rng();
        let schnorr_parameters = Schnorr::setup([0u8; 32]).unwrap();
        let (genesis_public_key, mut prev_signing_key) =
            Schnorr::keygen(&schnorr_parameters, rng.gen()).unwrap();
        let mut prev_public_key = genesis_public_key;
        let mut prev_uncompressed_wraps_proof: Option<UncompressedProofSerialized> = None;

        for i in 0..num_steps {
            let (next_public_key, next_signing_key) = if i == 0 {
                (prev_public_key, prev_signing_key)
            } else {
                Schnorr::keygen(&schnorr_parameters, rng.gen()).unwrap()
            };

            let message = WRAPS::compute_rotation_message(&next_public_key).unwrap();
            let signature =
                Schnorr::sign(&schnorr_parameters, &prev_signing_key, &message, rng.gen()).unwrap();
            assert!(WRAPS::verify_signature(&prev_public_key, &message, &signature).unwrap());

            let proof_start = std::time::Instant::now();
            let next_proof = WRAPS::construct_wraps_proof(
                &wraps_pk,
                &wraps_vk,
                &genesis_public_key,
                &prev_public_key,
                &next_public_key,
                prev_uncompressed_wraps_proof.clone(),
                &signature,
            ).expect("WRAPS proof should be created");
            println!(
                "Step {} WRAPS proof creation time: {:?}",
                i,
                proof_start.elapsed()
            );

            prev_public_key = next_public_key;
            prev_signing_key = next_signing_key;
            prev_uncompressed_wraps_proof = Some(next_proof);
        }
    }
}
