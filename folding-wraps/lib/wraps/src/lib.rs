#![allow(non_snake_case)]
#![allow(non_upper_case_globals)]
#![allow(non_camel_case_types)]
#![allow(clippy::upper_case_acronyms)]
#![allow(unused_imports)]
#![allow(dead_code)]

mod signature;
mod random_oracle;

use signature::{*};


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
use ark_std::rand::thread_rng;
use ark_serialize::{CanonicalDeserialize, CanonicalSerialize};
use ark_std::fmt::Debug;

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

pub const MAX_AB_SIZE: usize = 30;
pub const MAX_EXT_INPUTS: usize = 7 * MAX_AB_SIZE + 64 + 1;

/********************************* Useful Types *********************************/

type PairingCurve = ark_bn254::Bn254;
type G1 = ark_bn254::G1Projective;
type G2 = ark_grumpkin::Projective;
type Fr = ark_bn254::Fr;

type JubJub = ark_ed_on_bn254::EdwardsProjective;
type JubJubVar = ark_ed_on_bn254::constraints::EdwardsVar;

type S = signature::schnorr::Schnorr<JubJub>;
type SParams = signature::schnorr::Parameters<JubJub>;
type SVerifyGadget = signature::schnorr::constraints::SchnorrSignatureVerifyGadget<JubJub, JubJubVar>;
type SPkVar = signature::schnorr::constraints::PublicKeyVar<JubJub, JubJubVar>;
type SSigVar = signature::schnorr::constraints::SignatureVar<JubJub, JubJubVar>;

type Weight = Fr;
type AddressBookEntry = (schnorr::PublicKey<JubJub>, Weight);
type AddressBook = [AddressBookEntry; MAX_AB_SIZE];
type Keys = [schnorr::SecretKey<JubJub>; MAX_AB_SIZE];
/// The idea here is that eventually we could replace the next line chunk that defines the
/// `type N = Nova<...>` by using another folding scheme that fulfills the `FoldingScheme`
/// trait, and the rest of our code would be working without needing to be updated.
type N = Nova<G1, G2, TSSFCircuit<MAX_AB_SIZE>, KZG<'static, PairingCurve>, Pedersen<G2>, false>;
type NPP = ProverParams<G1, G2, KZG<'static, PairingCurve>, Pedersen<G2>, false>;
type NVP = VerifierParams<G1, G2, KZG<'static, PairingCurve>, Pedersen<G2>, false>;
type D = DeciderEth<G1, G2, TSSFCircuit<MAX_AB_SIZE>, KZG<'static, PairingCurve>, Pedersen<G2>, Groth16<PairingCurve>, N>;
type DPP = (<Groth16<PairingCurve> as ark_snark::SNARK<Fr>>::ProvingKey, <KZG<'static, PairingCurve> as CommitmentScheme<G1>>::ProverParams);
type DVP = VerifierParam<G1, <KZG<'static, PairingCurve> as CommitmentScheme<G1>>::VerifierParams, <Groth16<PairingCurve> as ark_snark::SNARK<Fr>>::VerifyingKey>;


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
        let next_ab_hash = computed_next_state[0].to_bytes_le()?;
        let tss_vk_hash = external_inputs.0[7*K + 64].clone();
        let msg_var = next_ab_hash
            .into_iter()
            .chain(tss_vk_hash.to_bytes_le()?)
            .collect::<Vec<_>>();
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

        Ok(vec![computed_next_state[0].clone(), tss_vk_hash])
    }
}



pub struct WRAPS {}

