use super::SignatureScheme;

use ark_crypto_primitives::Error;
use ark_ec::{CurveGroup, AffineRepr};
use ark_ff::fields::PrimeField;
use ark_ff::UniformRand;
use ark_serialize::{CanonicalDeserialize, CanonicalSerialize};
use ark_std::rand::Rng;
use ark_std::{hash::Hash, marker::PhantomData, vec::Vec};
use ark_std::ops::*;
use ark_std::Zero;
use blake2::Blake2s;
use digest::Digest;

pub mod constraints;

pub struct Schnorr<C: CurveGroup> {
    _group: PhantomData<C>,
}

#[derive(Clone, Default, Debug, CanonicalDeserialize, CanonicalSerialize)]
pub struct Parameters<C: CurveGroup> {
    pub generator: C::Affine,
    pub salt: Option<[u8; 32]>,
}

pub type PublicKey<C> = <C as CurveGroup>::Affine;

#[derive(Clone, Default, Debug, CanonicalDeserialize, CanonicalSerialize)]
pub struct SecretKey<C: CurveGroup> {
    pub secret_key: C::ScalarField,
    pub public_key: PublicKey<C>,
}

#[derive(Clone, Default, Debug, CanonicalDeserialize, CanonicalSerialize)]
pub struct Signature<C: CurveGroup> {
    pub prover_response: C::ScalarField,
    pub verifier_challenge: [u8; 32],
}

impl<C: CurveGroup + Hash> SignatureScheme for Schnorr<C>
where
    C::ScalarField: PrimeField,
{
    type Parameters = Parameters<C>;
    type PublicKey = PublicKey<C>;
    type SecretKey = SecretKey<C>;
    type Signature = Signature<C>;

    fn setup<R: Rng>(_rng: &mut R) -> Result<Self::Parameters, Error> {
        let salt = None;
        let generator = C::generator().into();

        Ok(Parameters { generator, salt })
    }

    fn keygen<R: Rng>(
        parameters: &Self::Parameters,
        rng: &mut R,
    ) -> Result<(Self::PublicKey, Self::SecretKey), Error> {
        // Secret is a random scalar x
        // the pubkey is y = xG
        let secret_key = C::ScalarField::rand(rng);
        let public_key = parameters.generator.mul(secret_key).into();

        Ok((
            public_key,
            SecretKey {
                secret_key,
                public_key,
            },
        ))
    }

    fn sign<R: Rng>(
        parameters: &Self::Parameters,
        sk: &Self::SecretKey,
        message: &[u8],
        rng: &mut R,
    ) -> Result<Self::Signature, Error> {
        // (k, e);
        let (random_scalar, verifier_challenge) = {
            // Sample a random scalar `k` from the prime scalar field.
            let random_scalar: C::ScalarField = C::ScalarField::rand(rng);
            // Commit to the random scalar via r := k · G.
            // This is the prover's first msg in the Sigma protocol.
            let prover_commitment = parameters.generator.mul(random_scalar).into_affine();

            // Hash everything to get verifier challenge.
            // e := H(salt || pubkey || r || msg);
            let mut hash_input = Vec::new();
            if parameters.salt != None {
                hash_input.extend_from_slice(&parameters.salt.unwrap());
            }
            hash_input.extend_from_slice(&serialize(&sk.public_key));
            hash_input.extend_from_slice(&serialize(&prover_commitment));
            hash_input.extend_from_slice(message);

            let verifier_challenge: [u8; 32] = Blake2s::digest(&hash_input).into();

            (random_scalar, verifier_challenge)
        };

        let verifier_challenge_fe = C::ScalarField::from_le_bytes_mod_order(&verifier_challenge);

        // k - xe;
        let prover_response = random_scalar - (verifier_challenge_fe * sk.secret_key);
        let signature = Signature { prover_response, verifier_challenge };

        Ok(signature)
    }

    fn verify(
        parameters: &Self::Parameters,
        pk: &Self::PublicKey,
        message: &[u8],
        signature: &Self::Signature,
    ) -> Result<bool, Error> {
        let Signature {
            prover_response,
            verifier_challenge,
        } = signature;
        let verifier_challenge_fe = C::ScalarField::from_le_bytes_mod_order(verifier_challenge);
        // sG = kG - eY
        // kG = sG + eY
        // so we first solve for kG.
        let mut claimed_prover_commitment = parameters.generator.mul(*prover_response);
        let public_key_times_verifier_challenge = pk.mul(verifier_challenge_fe);
        claimed_prover_commitment += &public_key_times_verifier_challenge;
        let claimed_prover_commitment = claimed_prover_commitment.into_affine();

        // e = H(salt, kG, msg)
        let mut hash_input = Vec::new();
        if parameters.salt != None {
            hash_input.extend_from_slice(&parameters.salt.unwrap());
        }
        hash_input.extend_from_slice(&serialize(pk));
        hash_input.extend_from_slice(&serialize(&claimed_prover_commitment));
        hash_input.extend_from_slice(message);

        // cast the hash output to get e
        let obtained_verifier_challenge = &Blake2s::digest(&hash_input)[..];
        Ok(verifier_challenge == obtained_verifier_challenge)
    }
}

pub struct ThresholdSchnorr<C: CurveGroup> {
    _group: PhantomData<C>,
}

#[derive(Clone, Debug)]
pub struct ThresholdSchnorrState<C: CurveGroup> {
    signing_key: C::ScalarField,
    random_scalar: C::ScalarField,
    round1_messages: Vec<ThresholdSchnorrMessage1>,
}

pub type ThresholdSchnorrMessage1 = [u8; 32];
pub type ThresholdSchnorrMessage2<C> = <C as CurveGroup>::Affine;
pub type ThresholdSchnorrMessage3<C> = Signature<C>;

impl<C: CurveGroup + Hash> ThresholdSchnorr<C>
where
    C::ScalarField: PrimeField,
{

    pub fn initiate_signing_session<R: Rng>(
        sk: &SecretKey<C>,
        rng: &mut R,
    ) -> ThresholdSchnorrState<C> {
        ThresholdSchnorrState {
            signing_key: sk.secret_key,
            random_scalar: C::ScalarField::rand(rng),
            round1_messages: vec![],
        }
    }

    pub fn sign_round1(
        parameters: &Parameters<C>,
        state: ThresholdSchnorrState<C>,
    ) -> Result<(ThresholdSchnorrMessage1, ThresholdSchnorrState<C>), Error> {
        let prover_commitment = parameters.generator.mul(state.random_scalar).into_affine();
        let hash_commitment: [u8; 32] = Blake2s::digest(&serialize(&prover_commitment)).into();

        Ok((hash_commitment, state))
    }

    pub fn sign_round2(
        parameters: &Parameters<C>,
        round1_messages: &[ThresholdSchnorrMessage1],
        state: ThresholdSchnorrState<C>,
    ) -> Result<(ThresholdSchnorrMessage2<C>, ThresholdSchnorrState<C>), Error> {
        let prover_commitment = parameters.generator.mul(state.random_scalar).into_affine();

        let state = ThresholdSchnorrState::<C> {
            round1_messages: round1_messages.to_vec(),
            ..state
        };

        Ok((prover_commitment, state))
    }

    pub fn sign_round3(
        parameters: &Parameters<C>,
        aggregate_pk: &PublicKey<C>,
        message_to_sign: &[u8],
        round2_messages: &[ThresholdSchnorrMessage2<C>],
        state: ThresholdSchnorrState<C>,
    ) -> Result<ThresholdSchnorrMessage3<C>, ThresholdSchnorrError> {
        let mut prover_commitment = C::Affine::zero();
        for (i, msg) in round2_messages.into_iter().enumerate() {
            let hash_commitment: [u8; 32] = Blake2s::digest(&serialize(msg)).into();
            if state.round1_messages[i] != hash_commitment {
                return Err(ThresholdSchnorrError::InvalidInput);
            }

            prover_commitment = prover_commitment.add(msg).into_affine();
        }

        // Hash everything to get verifier challenge.
        // e := H(salt || pubkey || r || msg);
        let mut hash_input = Vec::new();
        if parameters.salt != None {
            hash_input.extend_from_slice(&parameters.salt.unwrap());
        }
        hash_input.extend_from_slice(&serialize(&aggregate_pk));
        hash_input.extend_from_slice(&serialize(&prover_commitment));
        hash_input.extend_from_slice(message_to_sign);
        let verifier_challenge: [u8; 32] = Blake2s::digest(&hash_input).into();

        let verifier_challenge_fe = C::ScalarField::from_le_bytes_mod_order(&verifier_challenge);

        // k - xe;
        let prover_response = state.random_scalar - (verifier_challenge_fe * state.signing_key);
        let signature = Signature { prover_response, verifier_challenge };

        Ok(signature)
    }

    pub fn finish_signing_session(
        signatures: &[Signature<C>],
    ) -> Result<Signature<C>, ThresholdSchnorrError> {
        let verifier_challenge = signatures[0].verifier_challenge;
        for sig in signatures.iter() {
            if sig.verifier_challenge != verifier_challenge {
                return Err(ThresholdSchnorrError::InvalidInput);
            }
        }

        let prover_response = signatures.iter().fold(C::ScalarField::zero(), |acc, sig| acc + sig.prover_response);

        Ok(Signature { prover_response, verifier_challenge })
    }
}

#[derive(Debug)]
pub enum ThresholdSchnorrError {
    /// Multi-purpose error type for describing invalid inputs
    InvalidInput,
}

pub fn serialize<T: CanonicalSerialize>(
    t: &T
) -> Vec<u8> {
    let mut buf = Vec::new();
    // unwrap() should be safe because we serialize into a variable-size vector.
    // However, it might fail if the `t` is invalid somehow, although this
    // should only occur if there is an error in the caller or this library.
    t.serialize_uncompressed(&mut buf).unwrap();
    buf
}
