/// module responsible for generating the CRS
/// implements the algorithm in https://eprint.iacr.org/2022/1592.pdf

use ark_ff::{PrimeField, Field};
use ark_std::{UniformRand, ops::*};
use ark_ec::{AffineRepr, CurveGroup, pairing::Pairing, VariableBaseMSM};
use ark_serialize::CanonicalSerialize;
use sha2::*;
use rand::Rng;

use crate::kzg;
use crate::hints::{G1AffinePoint, G2AffinePoint, F, CRS, Curve};
use crate::check_or_return_false;

/// standard Schnorr proof of knowledge
pub struct ContributionProof {
    p1_mul_z: G1AffinePoint,
    z_plus_hr: F,
}

pub struct PowersOfTauProtocol { }

impl PowersOfTauProtocol {
    /// outputs the initial CRS without any entropy, to kickstart the ceremony;
    /// this should be the first CRS without any participant's contribution; 
    /// don't use this CRS!!! Wait till you have enough participants.
    pub fn init(degree: usize) -> CRS {
        let g = G1AffinePoint::generator();
        let h = G2AffinePoint::generator();

        // initial CRS is built with tau = 1
        let tau = F::from(1u64);
        // powers of tau go from tau^0 to tau^degree, inclusive
        let powers_of_tau = (0..=degree)
            .map(|i| tau.pow(&[i as u64]))
            .collect::<Vec<F>>();

        let powers_of_g = powers_of_tau
            .iter()
            .map(|tau_i| g.mul(tau_i).into_affine())
            .collect::<Vec<G1AffinePoint>>();

        let powers_of_h = powers_of_tau
            .iter()
            .map(|tau_i| h.mul(tau_i).into_affine())
            .collect::<Vec<G2AffinePoint>>();

        kzg::UniversalParams { powers_of_g, powers_of_h }
    }

    pub fn contribute(crs: &CRS, r: F) -> (CRS, ContributionProof) {
        let degree = crs.powers_of_g.len() - 1;

        let powers_of_r = (0..=degree)
            .map(|i| r.pow(&[i as u64]))
            .collect::<Vec<F>>();

        // zip powers of g with powers of r
        let powers_of_g = crs.powers_of_g
            .iter()
            .zip(powers_of_r.iter())
            .map(|(g_i, r_i)| g_i.mul(r_i).into_affine())
            .collect::<Vec<G1AffinePoint>>();

        // zip powers of h with powers of r
        let powers_of_h = crs.powers_of_h
            .iter()
            .zip(powers_of_r.iter())
            .map(|(h_i, r_i)| h_i.mul(r_i).into_affine())
            .collect::<Vec<G2AffinePoint>>();

        let next_crs = kzg::UniversalParams { powers_of_g, powers_of_h };

        let proof = schnorr_nizk(
            &crs.powers_of_g[1],
            &next_crs.powers_of_g[1],
            &r,
            &mut rand::thread_rng()
        );

       (next_crs, proof)
    }

    pub fn verify_contribution(prev_crs: &CRS, next_crs: &CRS, proof: &ContributionProof) -> bool {
        check_or_return_false!(check1(&prev_crs.powers_of_g[1], &next_crs.powers_of_g[1], proof));
        check_or_return_false!(check2(&next_crs));
        check_or_return_false!(check3(&next_crs));

        true
    }

}

fn schnorr_nizk<R: Rng>(
    prev_p1: &G1AffinePoint,
    next_p1: &G1AffinePoint,
    r: &F,
    rng: &mut R
) -> ContributionProof {
    let z = F::rand(rng);
    let prev_p1_mul_z = prev_p1.mul(&z).into_affine();
    let h = random_oracle(prev_p1, next_p1, &prev_p1_mul_z);
    let z_plus_hr = z + h * r;
    ContributionProof { p1_mul_z: prev_p1_mul_z, z_plus_hr }
}

fn check1(
    prev_p1: &G1AffinePoint,
    next_p1: &G1AffinePoint,
    proof: &ContributionProof
) -> bool {
    let lhs = prev_p1.mul(&proof.z_plus_hr).into_affine();
    let h = random_oracle(prev_p1, next_p1, &proof.p1_mul_z);
    let rhs = proof.p1_mul_z.add(prev_p1.mul(h)).into_affine();
    lhs == rhs
}

fn random_oracle(
    prev_p1: &G1AffinePoint,
    next_p1: &G1AffinePoint,
    prev_p1_mul_z: &G1AffinePoint
) -> F {
    let mut prev_p1_bytes = Vec::new();
    prev_p1.serialize_uncompressed(&mut prev_p1_bytes).unwrap();

    let mut next_p1_bytes = Vec::new();
    next_p1.serialize_uncompressed(&mut next_p1_bytes).unwrap();

    let mut prev_p1_mul_z_bytes = Vec::new();
    prev_p1_mul_z.serialize_uncompressed(&mut prev_p1_mul_z_bytes).unwrap();

    F::from_le_bytes_mod_order(&compute_sha256(&[
        next_p1_bytes.as_slice(),
        prev_p1_bytes.as_slice(),
        prev_p1_mul_z_bytes.as_slice()
    ]))
}

// eqn 4.3 in https://eprint.iacr.org/2022/1592.pdf
fn check2(crs: &CRS) -> bool {
    let n = crs.powers_of_g.len() - 1;

    let mut crs_bytes = Vec::new();
    crs.serialize_uncompressed(&mut crs_bytes).unwrap();

    // use random oracle with domain separators
    let rho1 = F::from_le_bytes_mod_order(
        &compute_sha256(&[crs_bytes.as_slice(), &[1u8]])
    );
    let rho2 = F::from_le_bytes_mod_order(
        &compute_sha256(&[crs_bytes.as_slice(), &[2u8]])
    );

    // c.f. Definition 3 in https://eprint.iacr.org/2022/1592.pdf
    // We say that crs (P1,P2,...,Pn; Q1,Q2,...,Qn) is well-formed 
    // if there exists a \tau \in Zp s.t. P_i = \tau^i * B1 and Q_i = \tau^i * B2,
    // where B1 and B2 are the generators of G1 and G2 respectively.
    // NOTE: we store B1 and B2 at index 0 in the powers_of_g and powers_of_h arrays

    let lhs_lhs = <<Curve as Pairing>::G1 as VariableBaseMSM>::msm(
        &crs.powers_of_g[1..=n],
        &(0..=n-1).map(|i| rho1.pow(&[i as u64])).collect::<Vec<F>>()
    ).unwrap().into_affine();

    let lhs_rhs = <<Curve as Pairing>::G2 as VariableBaseMSM>::msm(
        &crs.powers_of_h[1..=n-1],
        &(1..=n-1).map(|i| rho2.pow(&[i as u64])).collect::<Vec<F>>()
    ).unwrap().add(crs.powers_of_h[0]).into_affine();

    let rhs_lhs = <<Curve as Pairing>::G1 as VariableBaseMSM>::msm(
        &crs.powers_of_g[1..=n-1],
        &(1..=n-1).map(|i| rho1.pow(&[i as u64])).collect::<Vec<F>>()
    ).unwrap().add(crs.powers_of_g[0]).into_affine();

    let rhs_rhs = <<Curve as Pairing>::G2 as VariableBaseMSM>::msm(
        &crs.powers_of_h[1..=n],
        &(0..=n-1).map(|i| rho1.pow(&[i as u64])).collect::<Vec<F>>()
    ).unwrap().into_affine();

    let lhs = <Curve as Pairing>::pairing(lhs_lhs, lhs_rhs);
    let rhs = <Curve as Pairing>::pairing(rhs_lhs, rhs_rhs);

    lhs == rhs
}

// eqn 4.4 in https://eprint.iacr.org/2022/1592.pdf
fn check3(crs: &CRS) -> bool {
    // note that we use location 0 to store the generator (denoted B1)
    // so we need to perform this check for element at index 1
    return crs.powers_of_g[1] == G1AffinePoint::zero();
}

// takes a list of byte slices and computes the sha256 hash
// warning: this can lead to collisions if used unproperly.
// this is just meant for use within check2
pub fn compute_sha256(inputs: &[impl AsRef<[u8]>]) -> [u8; 32] {
    let mut hasher = sha2::Sha256::new();
    // just concatenate all the byte slices
    for input in inputs {
        hasher.update(input.as_ref());
    }
    hasher.finalize().into()
}