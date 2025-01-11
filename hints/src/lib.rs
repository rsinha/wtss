use ark_serialize::CanonicalSerialize;
use ark_poly::{
    Polynomial,
    univariate::DensePolynomial, 
    EvaluationDomain, 
    Radix2EvaluationDomain,
    Evaluations
};
use ark_std::{UniformRand, ops::*};
use ark_bls12_381::{
    Bls12_381,
    g1::Config as G1Config,
    g2::Config as G2Config
};
use ark_ec::pairing::Pairing;
use ark_ec::{AffineRepr, CurveGroup, short_weierstrass::{Affine, Projective}};
use ark_ec::VariableBaseMSM;
use ark_ec::hashing::curve_maps::wb::WBMap;
use ark_ec::hashing::map_to_curve_hasher::MapToCurveBasedHasher;
use ark_ec::hashing::HashToCurve;
use ark_ff::{Field, field_hashers::DefaultFieldHasher, BigInteger256};
use sha2::{Digest, Sha256};

use kzg::*;

mod utils;
mod kzg;

type Curve = Bls12_381;
type KZG = KZG10::<Curve, DensePolynomial<<Curve as Pairing>::ScalarField>>;
type F = ark_bls12_381::Fr;
/// Represents a point in G1 (affine coordinates)
pub type G1AffinePoint = Affine<G1Config>;
/// Represents a point in G2 (affine coordinates)
pub type G2AffinePoint = Affine<G2Config>;
/// Represents a point in G1 (projective coordinates)
pub type G1ProjectivePoint = Projective<G1Config>;
/// Represents a point in G2 (projective coordinates)
pub type G2ProjectivePoint = Projective<G2Config>;

pub type PartialSignature = G2AffinePoint;
pub type SecretKey = F;
pub type PublicKey = G1AffinePoint;
pub type Weight = F;

#[derive(Clone, Debug)]
/// hinTS signature
pub struct ThresholdSignature {
    /// aggregate public key (aPK in the paper)
    agg_pk: G1AffinePoint,
    /// aggregate weight (w in the paper)
    agg_weight: Weight,

    /// aggregate signature
    agg_sig: G2AffinePoint,

    /// commitment to the bitmap polynomial ([B(τ)]_1 in the paper)
    b_of_tau_com: G1AffinePoint,
    /// commitment to the Q_x polynomial ([Q_x(τ)]_1 in the paper)
    qx_of_tau_com: G1AffinePoint,
    /// commitment to the Q_x polynomial ([Q_x(τ) . τ ]_1 in the paper)
    qx_of_tau_mul_tau_com: G1AffinePoint,
    /// commitment to the Q_z polynomial ([Q_z(τ)]_1 in the paper)
    qz_of_tau_com: G1AffinePoint,
    /// commitment to the ParSum polynomial ([ParSum(τ)]_1 in the paper)
    parsum_of_tau_com: G1AffinePoint,

    /// commitment to the ParSum well-formedness quotient polynomial
    q1_of_tau_com: G1AffinePoint,
    /// commitment to the ParSum check at omega^{n-1} quotient polynomial
    q3_of_tau_com: G1AffinePoint,
    /// commitment to the bitmap well-formedness quotient polynomial
    q2_of_tau_com: G1AffinePoint,
    /// commitment to the bitmap check at omega^{n-1} quotient polynomial
    q4_of_tau_com: G1AffinePoint,

    /// merged opening proof for all openings at x = r
    opening_proof_r: G1AffinePoint,
    /// proof for the ParSum opening at x = r / ω
    opening_proof_r_div_ω: G1AffinePoint,

    /// polynomial evaluation of ParSum(x) at x = r
    parsum_of_r: F,
    /// polynomial evaluation of ParSum(x) at x = r / ω
    parsum_of_r_div_ω: F,
    /// polynomial evaluation of W(x) at x = r
    w_of_r: F,
    /// polynomial evaluation of bitmap B(x) at x = r
    b_of_r: F,
    /// polynomial evaluation of quotient Q1(x) at x = r
    q1_of_r: F,
    /// polynomial evaluation of quotient Q3(x) at x = r
    q3_of_r: F,
    /// polynomial evaluation of quotient Q2(x) at x = r
    q2_of_r: F,
    /// polynomial evaluation of quotient Q4(x) at x = r
    q4_of_r: F,
}

/// Hint contains all material output by a party during the setup phase
pub struct ExtendedPublicKey {
    /// index in the address book
    i: usize,
    /// public key pk = [sk]_1
    pk_i: PublicKey,
    /// [ sk_i L_i(τ) ]_1
    sk_i_l_i_of_tau_com_1: G1AffinePoint,
    /// [ sk_i L_i(τ) ]_2
    sk_i_l_i_of_tau_com_2: G2AffinePoint,
    /// qz_i_terms[i] = [ sk_i * ((L_i^2(τ) - L_i(τ)) / Z(τ)) ]_1
    /// \forall j != i, qz_i_terms[j] = [ sk_i * (L_i(τ) * L_j(τ) / Z(τ)) ]_1
    qz_i_terms: Vec<G1AffinePoint>,
    /// [ sk_i ((L_i(τ) - L_i(0)) / τ ]_1
    qx_i_term: G1AffinePoint,
    /// [ sk_i ((L_i(τ) - L_i(0))]_1
    qx_i_term_mul_tau: G1AffinePoint,
}

/// AggregationKey contains all material needed by Prover to produce a hinTS proof
pub struct AggregationKey {
    /// number of parties plus one (must be a power of 2)
    n: usize,
    /// weights has all parties' weights, where weights[i] is party i's weight
    weights: Vec<Weight>,
    /// pks contains all parties' public keys, where pks[i] is g^sk_i
    pks: Vec<PublicKey>,
    /// qz_terms contains pre-processed hints for the Q_z polynomial.
    /// qz_terms[i] has the following form:
    /// [sk_i * (L_i(\tau)^2 - L_i(\tau)) / Z(\tau) + 
    /// \Sigma_{j} sk_j * (L_i(\tau) L_j(\tau)) / Z(\tau)]_1
    qz_terms : Vec<G1AffinePoint>,
    /// qx_terms contains pre-processed hints for the Q_x polynomial.
    /// qx_terms[i] has the form [ sk_i * (L_i(\tau) - L_i(0)) / x ]_1
    qx_terms : Vec<G1AffinePoint>,
    /// qx_mul_tau_terms contains pre-processed hints for the Q_x * x polynomial.
    /// qx_mul_tau_terms[i] has the form [ sk_i * (L_i(\tau) - L_i(0)) ]_1
    qx_mul_tau_terms : Vec<G1AffinePoint>,
}

pub struct VerificationKey {
    /// the universe has n - 1 parties (where n is a power of 2)
    n: usize,
    /// total weight of all signers
    total_weight: Weight,
    /// first G1 element from the KZG CRS (for zeroth power of tau)
    g_0: G1AffinePoint,
    /// first G2 element from the KZG CRS (for zeroth power of tau)
    h_0: G2AffinePoint,
    /// second G1 element from the KZG CRS (for first power of tau)
    h_1: G2AffinePoint,
    /// commitment to the L_{n-1} polynomial
    l_n_minus_1_of_tau_com: G1AffinePoint,
    /// commitment to the W polynomial
    w_of_tau_com: G1AffinePoint,
    /// commitment to the SK polynomial
    sk_of_tau_com: G2AffinePoint,
    /// commitment to the vanishing polynomial Z(x) = x^n - 1
    z_of_tau_com: G2AffinePoint,
    /// commitment to the f(x) = x, which equals [\tau]_2
    tau_com: G2AffinePoint
}

pub struct HinTS { }

impl HinTS {

    /// generates a random secret key
    pub fn keygen<R: rand::Rng>(rng: &mut R) -> SecretKey {
        F::rand(rng)
    }

    /// generates the extended public key
    pub fn hint_gen(
        crs: &UniversalParams<Curve>,
        n: usize, 
        i: usize, 
        sk_i: &SecretKey
    ) -> ExtendedPublicKey {
        //let us compute the q1 term
        let l_i_of_x = utils::lagrange_poly(n, i);
        let z_of_x = utils::compute_vanishing_poly(n);
    
        let mut qz_terms = vec![];
        //let us compute the cross terms of q1
        for j in 0..n {
            let num: DensePolynomial<F>;// = compute_constant_poly(&F::from(0));
            if i == j {
                num = l_i_of_x.clone().mul(&l_i_of_x).sub(&l_i_of_x);
            } else { //cross-terms
                let l_j_of_x = utils::lagrange_poly(n, j);
                num = l_j_of_x.mul(&l_i_of_x);
            }
    
            let f = num.div(&z_of_x);
            let sk_times_f = utils::poly_eval_mult_c(&f, &sk_i);
    
            let com = KZG::commit_g1(&crs, &sk_times_f)
                .expect("commitment failed");
    
            qz_terms.push(com);
        }
    
        let x_monomial = utils::compute_x_monomial();
        let l_i_of_0 = l_i_of_x.evaluate(&F::from(0));
        let l_i_of_0_poly = utils::compute_constant_poly(&l_i_of_0);
    
        //numerator is l_i(x) - l_i(0)
        let num = l_i_of_x.sub(&l_i_of_0_poly);
        //denominator is x
        let den = x_monomial.clone();
        //qx_term = sk_i * (l_i(x) - l_i(0)) / x
        let qx_term = utils::poly_eval_mult_c(&num.div(&den), &sk_i);
        //qx_term_mul_tau = sk_i * (l_i(x) - l_i(0)) / x
        let qx_term_mul_tau = utils::poly_eval_mult_c(&num, &sk_i);
        //qx_term_com = [ sk_i * (l_i(τ) - l_i(0)) / τ ]_1
        let qx_term_com = KZG::commit_g1(&crs, &qx_term).expect("commitment failed");
        //qx_term_mul_tau_com = [ sk_i * (l_i(τ) - l_i(0)) ]_1
        let qx_term_mul_tau_com = KZG::commit_g1(&crs, &qx_term_mul_tau).expect("commitment failed");
    
        //release my public key
        let sk_as_poly = utils::compute_constant_poly(&sk_i);
        let pk = KZG::commit_g1(&crs, &sk_as_poly).expect("commitment failed");
    
        let sk_times_l_i_of_x = utils::poly_eval_mult_c(&l_i_of_x, &sk_i);
        let com_sk_l_i_g1 = KZG::commit_g1(&crs, &sk_times_l_i_of_x).expect("commitment failed");
        let com_sk_l_i_g2 = KZG::commit_g2(&crs, &sk_times_l_i_of_x).expect("commitment failed");
    
        ExtendedPublicKey {
            i: i,
            pk_i: pk,
            sk_i_l_i_of_tau_com_1: com_sk_l_i_g1,
            sk_i_l_i_of_tau_com_2: com_sk_l_i_g2,
            qz_i_terms: qz_terms,
            qx_i_term: qx_term_com,
            qx_i_term_mul_tau: qx_term_mul_tau_com,
        }
    }

    /// preprocesses all nodes' extended public keys and weights,
    /// and outputs the network's verification key and aggregation key
    pub fn preprocess(
        n: usize,
        crs: &UniversalParams<Curve>,
        w: &Vec<Weight>,
        epk: &Vec<ExtendedPublicKey>
    ) -> (VerificationKey, AggregationKey) {

        // let us first pad the weights to a power of 2 size to compute a commitment
        let mut weights = w.clone();
        //last element must be 0 for the math to work
        weights.push(F::from(0)); // just for computing the commitment to w(x)
    
        let w_of_x = utils::interpolate_poly_over_mult_subgroup(&weights);
    
        //allocate space to collect setup material from all n-1 parties
        let mut qz_contributions : Vec<Vec<G1AffinePoint>> = vec![Default::default(); n];
        let mut qx_contributions : Vec<G1AffinePoint> = vec![Default::default(); n];
        let mut qx_mul_tau_contributions : Vec<G1AffinePoint> = vec![Default::default(); n];
        let mut pks : Vec<G1AffinePoint> = vec![Default::default(); n];
        let mut sk_l_of_tau_coms: Vec<G2AffinePoint> = vec![Default::default(); n];
    
        for hint in epk {
            //verify hint
            verify_hint(crs, &hint);
            //extract necessary items for pre-processing
            qz_contributions[hint.i] = hint.qz_i_terms.clone();
            qx_contributions[hint.i] = hint.qx_i_term.clone();
            qx_mul_tau_contributions[hint.i] = hint.qx_i_term_mul_tau.clone();
            pks[hint.i] = hint.pk_i.clone();
            sk_l_of_tau_coms[hint.i] = hint.sk_i_l_i_of_tau_com_2.clone();
        }
    
        let z_of_x = utils::compute_vanishing_poly(n);
        let x_monomial = utils::compute_x_monomial();
        let l_n_minus_1_of_x = utils::lagrange_poly(n, n-1);

        let total_weight = weights.iter().fold(F::from(0), |acc, &x| acc + x);
    
        let vk = VerificationKey {
            n: n,
            total_weight: total_weight,
            g_0: crs.powers_of_g[0].clone(),
            h_0: crs.powers_of_h[0].clone(),
            h_1: crs.powers_of_h[1].clone(),
            l_n_minus_1_of_tau_com: KZG::commit_g1(&crs, &l_n_minus_1_of_x).unwrap(),
            w_of_tau_com: KZG::commit_g1(&crs, &w_of_x).unwrap(),
            // combine all sk_i l_i_of_x commitments to get commitment to sk(x)
            sk_of_tau_com: add_all_g2(&crs, &sk_l_of_tau_coms),
            z_of_tau_com: KZG::commit_g2(&crs, &z_of_x).unwrap(),
            tau_com: KZG::commit_g2(&crs, &x_monomial).unwrap(),
        };
    
        let ak = AggregationKey {
            n: n,
            weights: w.clone(),
            pks: pks,
            qz_terms: preprocess_qz_contributions(&qz_contributions),
            qx_terms: qx_contributions,
            qx_mul_tau_terms: qx_mul_tau_contributions,
        };
    
        (vk, ak)
    
    }

    pub fn sign(
        msg: &[u8],
        sk: &SecretKey
    ) -> PartialSignature {
        hash_to_g2(msg).mul(sk).into_affine()
    }

    pub fn partial_verify(
        crs: &UniversalParams<Curve>,
        msg: &[u8],
        pk: &PublicKey,
        sig: &PartialSignature
    ) -> bool {
        let lhs = <Curve as Pairing>::pairing(pk, hash_to_g2(msg));
        let rhs = <Curve as Pairing>::pairing(crs.powers_of_g[0], sig);
        lhs == rhs
    }

    pub fn aggregate(
        crs: &UniversalParams<Curve>,
        ak: &AggregationKey,
        vk: &VerificationKey,
        bitmap: &Vec<F>,
        partial_signatures: &Vec<Option<PartialSignature>>
    ) -> ThresholdSignature {
        // compute the nth root of unity
        let n = ak.n;
    
        //adjust the weights and bitmap polynomials

        // the weights vector is of size power of 2 - 1; lets pad
        let mut weights = ak.weights.clone();
        //compute sum of weights of active signers
        let total_active_weight = bitmap
            .iter()
            .zip(weights.iter())
            .fold(F::from(0), |acc, (&x, &y)| acc + (x * y));
        //weight's last element must the additive inverse of active weight
        weights.push(F::from(0) - total_active_weight);
    
        // bitmap needs to pad with 1 to activate the last weight
        let mut bitmap = bitmap.clone();
        //bitmap's last element must be 1 for our scheme
        bitmap.push(F::from(1));
    
        //compute all the scalars we will need in the prover
        let domain = Radix2EvaluationDomain::<F>::new(n as usize).unwrap();
        let ω: F = domain.group_gen;
        let ω_inv: F = F::from(1) / ω;
    
        //compute all the polynomials we will need in the prover
        let z_of_x = utils::compute_vanishing_poly(n); //returns Z(X) = X^n - 1
        let l_n_minus_1_of_x = utils::lagrange_poly(n, n-1);
        let w_of_x = utils::interpolate_poly_over_mult_subgroup(&weights);
        let b_of_x = utils::interpolate_poly_over_mult_subgroup(&bitmap);
        let psw_of_x = compute_psw_poly(&weights, &bitmap);
        let psw_of_x_div_ω = utils::poly_domain_mult_ω(&psw_of_x, &ω_inv);
    
        //ParSumW(X) = ParSumW(X/ω) + W(X) · b(X) + Z(X) · Q1(X)
        let t_of_x = psw_of_x.sub(&psw_of_x_div_ω).sub(&w_of_x.mul(&b_of_x));
        let psw_wff_q_of_x = t_of_x.div(&z_of_x);
    
        //L_{n−1}(X) · ParSumW(X) = Z(X) · Q2(X) 
        let t_of_x = l_n_minus_1_of_x.mul(&psw_of_x);
        let psw_check_q_of_x = t_of_x.div(&z_of_x);
    
        //b(X) · b(X) − b(X) = Z(X) · Q3(X)
        let t_of_x = b_of_x.mul(&b_of_x).sub(&b_of_x);
        let b_wff_q_of_x = t_of_x.div(&z_of_x);
    
        //L_{n−1}(X) · (b(X) - 1) = Z(X) · Q4(X)
        let t_of_x = l_n_minus_1_of_x.clone().mul(
            &b_of_x.clone().sub(&utils::compute_constant_poly(&F::from(1))));
        let b_check_q_of_x = t_of_x.div(&z_of_x);
    
        let qz_com = filter_and_add(&crs, &ak.qz_terms, &bitmap);
        let qx_com = filter_and_add(&crs, &ak.qx_terms, &bitmap);
        let qx_mul_tau_com = filter_and_add(&crs, &ak.qx_mul_tau_terms, &bitmap);

        let agg_pk = compute_aggregate_pubkey(&ak, &bitmap);
        let agg_sig = compute_aggregate_signature(&partial_signatures, &bitmap);
    
        let parsum_of_tau_com = KZG::commit_g1(&crs, &psw_of_x).unwrap();
        let b_of_tau_com = KZG::commit_g1(&crs, &b_of_x).unwrap();
        let q1_of_tau_com = KZG::commit_g1(&crs, &psw_wff_q_of_x).unwrap();
        let q2_of_tau_com = KZG::commit_g1(&crs, &b_wff_q_of_x).unwrap();
        let q3_of_tau_com = KZG::commit_g1(&crs, &psw_check_q_of_x).unwrap();
        let q4_of_tau_com = KZG::commit_g1(&crs, &b_check_q_of_x).unwrap();
    
        // RO(SK, W, B, ParSum, Qx, Qz, Qx(τ ) · τ, Q1, Q2, Q3, Q4)
        let r = random_oracle(
            vk.sk_of_tau_com, 
            vk.w_of_tau_com,
            b_of_tau_com,
            parsum_of_tau_com,
            qx_com,
            qz_com,
            qx_mul_tau_com,
            q1_of_tau_com,
            q2_of_tau_com,
            q3_of_tau_com,
            q4_of_tau_com
        );
        let r_div_ω: F = r / ω;
    
        let psw_of_r_proof = KZG::compute_opening_proof(&crs, &psw_of_x, &r).unwrap();
        let w_of_r_proof = KZG::compute_opening_proof(&crs, &w_of_x, &r).unwrap();
        let b_of_r_proof = KZG::compute_opening_proof(&crs, &b_of_x, &r).unwrap();
        let psw_wff_q_of_r_proof = KZG::compute_opening_proof(&crs, &psw_wff_q_of_x, &r).unwrap();
        let psw_check_q_of_r_proof = KZG::compute_opening_proof(&crs, &psw_check_q_of_x, &r).unwrap();
        let b_wff_q_of_r_proof = KZG::compute_opening_proof(&crs, &b_wff_q_of_x, &r).unwrap();
        let b_check_q_of_r_proof = KZG::compute_opening_proof(&crs, &b_check_q_of_x, &r).unwrap();
    
        let merged_proof: G1AffinePoint = (psw_of_r_proof
            + w_of_r_proof.mul(r.pow([1]))
            + b_of_r_proof.mul(r.pow([2]))
            + psw_wff_q_of_r_proof.mul(r.pow([3]))
            + psw_check_q_of_r_proof.mul(r.pow([4]))
            + b_wff_q_of_r_proof.mul(r.pow([5]))
            + b_check_q_of_r_proof.mul(r.pow([6]))).into();
    
        ThresholdSignature {
            agg_pk: agg_pk.clone(),
            agg_sig: agg_sig.clone(),
            agg_weight: total_active_weight,
            
            parsum_of_r_div_ω: psw_of_x.evaluate(&r_div_ω),
            opening_proof_r_div_ω: KZG::compute_opening_proof(&crs, &psw_of_x, &r_div_ω).unwrap(),
    
            parsum_of_r: psw_of_x.evaluate(&r),
            w_of_r: w_of_x.evaluate(&r),
            b_of_r: b_of_x.evaluate(&r),
            q1_of_r: psw_wff_q_of_x.evaluate(&r),
            q3_of_r: psw_check_q_of_x.evaluate(&r),
            q2_of_r: b_wff_q_of_x.evaluate(&r),
            q4_of_r: b_check_q_of_x.evaluate(&r),
            
            opening_proof_r: merged_proof.into(),
    
            parsum_of_tau_com: parsum_of_tau_com,
            b_of_tau_com: b_of_tau_com,
            q1_of_tau_com: q1_of_tau_com,
            q3_of_tau_com: q3_of_tau_com,
            q2_of_tau_com: q2_of_tau_com,
            q4_of_tau_com: q4_of_tau_com,
    
            qz_of_tau_com: qz_com,
            qx_of_tau_com: qx_com,
            qx_of_tau_mul_tau_com: qx_mul_tau_com,
        }
    }

    pub fn verify(
        crs: &UniversalParams<Curve>,
        msg: &[u8],
        vk: &VerificationKey,
        π: &ThresholdSignature,
        threshold_fraction: (F, F) // e.g. (1,3) to denote 1/3 threshold
    ) -> bool {

        // check that the threshold is satisfied
        check_or_return_false!(
            threshold_fraction.1 * π.agg_weight >= threshold_fraction.0 * vk.total_weight
        );

        // verify the signature first
        check_or_return_false!(Self::partial_verify(crs, msg, &π.agg_pk, &π.agg_sig));

        // compute root of unity
        let domain = Radix2EvaluationDomain::<F>::new(vk.n as usize).unwrap();
        let ω: F = domain.group_gen;
    
        //RO(SK, W, B, ParSum, Qx, Qz, Qx(τ ) · τ, Q1, Q2, Q3, Q4)
        let r = random_oracle(
            vk.sk_of_tau_com,
            vk.w_of_tau_com,
            π.b_of_tau_com,
            π.parsum_of_tau_com,
            π.qx_of_tau_com,
            π.qz_of_tau_com,
            π.qx_of_tau_mul_tau_com,
            π.q1_of_tau_com,
            π.q2_of_tau_com,
            π.q3_of_tau_com,
            π.q4_of_tau_com
        );
    
        // verify the polynomial openings at r and r / ω
        check_or_return_false!(verify_openings_in_proof(vk, π, r));
    
        let n: u64 = vk.n as u64;
        // this takes logarithmic computation, but concretely efficient
        let vanishing_of_r: F = r.pow([n]) - F::from(1);
    
        // compute L_i(r) using the relation L_i(x) = Z_V(x) / ( Z_V'(x) (x - ω^i) )
        // where Z_V'(x)^-1 = x / N for N = |V|.
        let ω_pow_n_minus_1 = ω.pow([n-1]);
        let l_n_minus_1_of_r = (ω_pow_n_minus_1 / F::from(n)) * (vanishing_of_r / (r - ω_pow_n_minus_1));
    
        //assert polynomial identity B(x) SK(x) = ask + Q_z(x) Z(x) + Q_x(x) x
        let lhs = <Curve as Pairing>::pairing(&π.b_of_tau_com, &vk.sk_of_tau_com);
        let x1 = <Curve as Pairing>::pairing(&π.qz_of_tau_com, &vk.z_of_tau_com);
        let x2 = <Curve as Pairing>::pairing(&π.qx_of_tau_com, &vk.tau_com);
        let x3 = <Curve as Pairing>::pairing(&π.agg_pk, &vk.h_0);
        let rhs = x1.add(x2).add(x3);
        check_or_return_false!(lhs == rhs);
    
        //assert checks on the public part
    
        //ParSumW(r) − ParSumW(r/ω) − W(r) · b(r) = Q(r) · (r^n − 1)
        let lhs = π.parsum_of_r - π.parsum_of_r_div_ω - π.w_of_r * π.b_of_r;
        let rhs = π.q1_of_r * vanishing_of_r;
        check_or_return_false!(lhs == rhs);
    
        //Ln−1(X) · ParSumW(X) = Z(X) · Q2(X)
        //TODO: compute l_n_minus_1_of_r in verifier -- dont put it in the proof.
        let lhs = l_n_minus_1_of_r * π.parsum_of_r;
        let rhs = vanishing_of_r * π.q3_of_r;
        check_or_return_false!(lhs == rhs);
    
        //b(r) * b(r) - b(r) = Q(r) · (r^n − 1)
        let lhs = π.b_of_r * π.b_of_r - π.b_of_r;
        let rhs = π.q2_of_r * vanishing_of_r;
        check_or_return_false!(lhs == rhs);
    
        //Ln−1(X) · (b(X) − 1) = Z(X) · Q4(X)
        let lhs = l_n_minus_1_of_r * (π.b_of_r - F::from(1));
        let rhs = vanishing_of_r * π.q4_of_r;
        check_or_return_false!(lhs == rhs);
    
        //run the degree check e([Qx(τ)]_1, [τ]_2) ?= e([Qx(τ)·τ]_1, [1]_2)
        let lhs = <Curve as Pairing>::pairing(&π.qx_of_tau_com, &vk.h_1);
        let rhs = <Curve as Pairing>::pairing(&π.qx_of_tau_mul_tau_com, &vk.h_0);
        check_or_return_false!(lhs == rhs);
    
        true
    }

}

#[macro_export]
macro_rules! check_or_return_false {
    ($cond:expr) => {
        if !$cond {
            return false;
        }
    };
}

fn verify_hint(
    crs: &UniversalParams<Curve>,
    hint: &ExtendedPublicKey
) -> bool {
    let i = hint.i;
    let n = hint.qz_i_terms.len();

    //e([sk_i L_i(τ)]1, [1]2) = e([sk_i]1, [L_i(τ)]2)
    let l_i_of_x = utils::lagrange_poly(n, i);
    let z_of_x = utils::compute_vanishing_poly(n);

    let l_i_of_tau_com = KZG::commit_g2(&crs, &l_i_of_x).expect("commitment failed");
    let lhs = <Curve as Pairing>::pairing(hint.sk_i_l_i_of_tau_com_1, crs.powers_of_h[0]);
    let rhs = <Curve as Pairing>::pairing(hint.pk_i, l_i_of_tau_com);
    check_or_return_false!(lhs == rhs);

    for j in 0..n {
        let num: DensePolynomial<F>;
        if i == j {
            num = l_i_of_x.clone().mul(&l_i_of_x).sub(&l_i_of_x);
        } else { //cross-terms
            let l_j_of_x = utils::lagrange_poly(n, j);
            num = l_j_of_x.mul(&l_i_of_x);
        }
        let f = num.div(&z_of_x);

        //f = li^2 - l_i / z or li lj / z
        let f_com = KZG::commit_g2(&crs, &f).expect("commitment failed");
        
        let lhs = <Curve as Pairing>::pairing(hint.qz_i_terms[j], crs.powers_of_h[0]);
        let rhs = <Curve as Pairing>::pairing(hint.pk_i, f_com);
        check_or_return_false!(lhs == rhs);
    }

    let x_monomial = utils::compute_x_monomial();
    let l_i_of_0 = l_i_of_x.evaluate(&F::from(0));
    let l_i_of_0_poly = utils::compute_constant_poly(&l_i_of_0);

    //numerator is l_i(x) - l_i(0)
    let num = l_i_of_x.sub(&l_i_of_0_poly);
    //denominator is x
    let den = x_monomial.clone();

    //qx_term = (l_i(x) - l_i(0)) / x
    let qx_term = &num.div(&den);
    //qx_term_com = [ sk_i * (l_i(τ) - l_i(0)) / τ ]_1
    let qx_term_com = KZG::commit_g2(&crs, &qx_term).expect("commitment failed");
    let lhs = <Curve as Pairing>::pairing(hint.qx_i_term, crs.powers_of_h[0]);
    let rhs = <Curve as Pairing>::pairing(hint.pk_i, qx_term_com);
    check_or_return_false!(lhs == rhs);

    //qx_term_mul_tau = (l_i(x) - l_i(0))
    let qx_term_mul_tau = &num;
    //qx_term_mul_tau_com = [ (l_i(τ) - l_i(0)) ]_1
    let qx_term_mul_tau_com = KZG::commit_g2(&crs, &qx_term_mul_tau).expect("commitment failed");
    let lhs = <Curve as Pairing>::pairing(hint.qx_i_term_mul_tau, crs.powers_of_h[0]);
    let rhs = <Curve as Pairing>::pairing(hint.pk_i, qx_term_mul_tau_com);
    check_or_return_false!(lhs == rhs);

    true
}

//RO(SK, W, B, ParSum, Qx, Qz, Qx(τ ) · τ, Q1, Q2, Q3, Q4)
fn random_oracle(
    sk_com: G2AffinePoint,
    w_com: G1AffinePoint,
    b_com: G1AffinePoint,
    parsum_com: G1AffinePoint,
    qx_com: G1AffinePoint,
    qz_com: G1AffinePoint,
    qx_mul_x_com: G1AffinePoint,
    q1_com: G1AffinePoint,
    q2_com: G1AffinePoint,
    q3_com: G1AffinePoint,
    q4_com: G1AffinePoint,
) -> F {

    let mut serialized_data = Vec::new();
    sk_com.serialize_compressed(&mut serialized_data).unwrap();
    w_com.serialize_compressed(&mut serialized_data).unwrap();
    b_com.serialize_compressed(&mut serialized_data).unwrap();
    parsum_com.serialize_compressed(&mut serialized_data).unwrap();
    qx_com.serialize_compressed(&mut serialized_data).unwrap();
    qz_com.serialize_compressed(&mut serialized_data).unwrap();
    qx_mul_x_com.serialize_compressed(&mut serialized_data).unwrap();
    q1_com.serialize_compressed(&mut serialized_data).unwrap();
    q2_com.serialize_compressed(&mut serialized_data).unwrap();
    q3_com.serialize_compressed(&mut serialized_data).unwrap();
    q4_com.serialize_compressed(&mut serialized_data).unwrap();

    let mut hash_result = Sha256::digest(serialized_data.as_slice());
    hash_result[31] = 0u8; //this makes sure we get a number below modulus
    let hash_bytes = hash_result.as_slice();

    let mut hash_values: [u64; 4] = [0; 4];
    hash_values[0] = u64::from_le_bytes(hash_bytes[0..8].try_into().unwrap());
    hash_values[1] = u64::from_le_bytes(hash_bytes[8..16].try_into().unwrap());
    hash_values[2] = u64::from_le_bytes(hash_bytes[16..24].try_into().unwrap());
    hash_values[3] = u64::from_le_bytes(hash_bytes[24..32].try_into().unwrap());
    //hash_values[3] = u64::from(0u64);

    let bi = BigInteger256::new(hash_values);

    //let input: [u8; 32] = [0u8; 32];
    F::try_from(bi).unwrap()
}

fn verify_opening(
    vp: &VerificationKey, 
    commitment: &G1AffinePoint,
    point: &F, 
    evaluation: &F,
    opening_proof: &G1AffinePoint
) -> bool {
    let eval_com: G1AffinePoint = vp.g_0.clone().mul(evaluation).into();
    let point_com: G2AffinePoint = vp.h_0.clone().mul(point).into();

    let lhs = <Curve as Pairing>::pairing(commitment.clone() - eval_com, vp.h_0);
    let rhs = <Curve as Pairing>::pairing(opening_proof.clone(), vp.h_1 - point_com);
    
    lhs == rhs
}

fn verify_openings_in_proof(
    vk: &VerificationKey,
    π: &ThresholdSignature,
    r: F
) -> bool {
    //adjust the w_of_x_com
    let adjustment = F::from(0) - π.agg_weight;
    let adjustment_com = vk.l_n_minus_1_of_tau_com.mul(adjustment);
    let w_of_x_com: G1AffinePoint = (vk.w_of_tau_com + adjustment_com).into();

    let psw_of_r_argument = π.parsum_of_tau_com - vk.g_0.clone().mul(π.parsum_of_r).into_affine();
    let w_of_r_argument = w_of_x_com - vk.g_0.clone().mul(π.w_of_r).into_affine();
    let b_of_r_argument = π.b_of_tau_com - vk.g_0.clone().mul(π.b_of_r).into_affine();
    let psw_wff_q_of_r_argument = π.q1_of_tau_com - vk.g_0.clone().mul(π.q1_of_r).into_affine();
    let psw_check_q_of_r_argument = π.q3_of_tau_com - vk.g_0.clone().mul(π.q3_of_r).into_affine();
    let b_wff_q_of_r_argument = π.q2_of_tau_com - vk.g_0.clone().mul(π.q2_of_r).into_affine();
    let b_check_q_of_r_argument = π.q4_of_tau_com - vk.g_0.clone().mul(π.q4_of_r).into_affine();

    let merged_argument: G1AffinePoint = (psw_of_r_argument
        + w_of_r_argument.mul(r.pow([1]))
        + b_of_r_argument.mul(r.pow([2]))
        + psw_wff_q_of_r_argument.mul(r.pow([3]))
        + psw_check_q_of_r_argument.mul(r.pow([4]))
        + b_wff_q_of_r_argument.mul(r.pow([5]))
        + b_check_q_of_r_argument.mul(r.pow([6]))).into_affine();

    let lhs = <Curve as Pairing>::pairing(
        merged_argument, 
        vk.h_0);
    let rhs = <Curve as Pairing>::pairing(
        π.opening_proof_r, 
        vk.h_1 - vk.h_0.clone().mul(r).into_affine());
    check_or_return_false!(lhs == rhs);

    let domain = Radix2EvaluationDomain::<F>::new(vk.n as usize).unwrap();
    let ω: F = domain.group_gen;
    let r_div_ω: F = r / ω;

    verify_opening(
        vk, 
        &π.parsum_of_tau_com, 
        &r_div_ω, 
        &π.parsum_of_r_div_ω, 
        &π.opening_proof_r_div_ω
    )
}

fn compute_aggregate_pubkey(
    pp: &AggregationKey, 
    bitmap: &Vec<F>
) -> G1AffinePoint {
    let n = bitmap.len();
    let mut exponents: Vec<F> = vec![];
    let n_inv = F::from(1) / F::from(n as u64);
    for i in 0..n {
        let l_i_of_0 = n_inv;
        let active = bitmap[i] == F::from(1);
        exponents.push(if active { l_i_of_0 } else { F::from(0) });
    }

    <<Curve as Pairing>::G1 as VariableBaseMSM>
        ::msm(&pp.pks[..], &exponents).unwrap().into_affine()
}

fn compute_aggregate_signature(
    partial_signatures: &Vec<Option<PartialSignature>>,
    bitmap: &Vec<F>
) -> G2AffinePoint {
    let n = bitmap.len();
    let n_inv = F::from(1) / F::from(n as u64);

    // add up all the partial signatures that are not none
    let aggregated_signature = partial_signatures
        .iter()
        .zip(bitmap.iter())
        .fold(G2AffinePoint::zero(), |acc, (sig, &bit)| {
            if sig.is_some() && bit == F::from(1) {
                acc.add(sig.unwrap().mul(n_inv)).into_affine()
            } else {
                acc
            }
        });

    aggregated_signature
}

fn preprocess_qz_contributions(
    q1_contributions: &Vec<Vec<G1AffinePoint>>
) -> Vec<G1AffinePoint> {
    let n = q1_contributions.len();
    let mut q1_coms = vec![];

    for i in 0..n {
        // extract party i's hints, from which we extract the term for i.
        let mut party_i_q1_com = q1_contributions[i][i].clone();
        for j in 0..n {
            if i != j {
                // extract party j's hints, from which we extract cross-term for party i
                let party_j_contribution = q1_contributions[j][i].clone();
                party_i_q1_com = party_i_q1_com.add(party_j_contribution).into();
            }
        }
        // the aggregation key contains a single term that 
        // is a product of all cross-terms and the ith term
        q1_coms.push(party_i_q1_com);
    }
    q1_coms
}

fn compute_psw_poly(
    weights: &Vec<Weight>,
    bitmap: &Vec<F>
) -> DensePolynomial<F> {
    let n = weights.len(); //power of 2 size
    let mut parsum = F::from(0);
    let mut evals = vec![];
    for i in 0..n {
        parsum += bitmap[i] * weights[i];
        evals.push(parsum);
    }

    let domain = Radix2EvaluationDomain::<F>::new(n).unwrap();
    let eval_form = Evaluations::from_vec_and_domain(evals, domain);
    eval_form.interpolate()    
}

fn filter_and_add(
    crs: &UniversalParams<Curve>, 
    elements: &Vec<G1AffinePoint>, 
    bitmap: &Vec<F>
) -> G1AffinePoint {
    let mut com = KZG::commit_g1(crs, &utils::compute_constant_poly(&F::from(0))).unwrap();
    for i in 0..bitmap.len() {
        if bitmap[i] == F::from(1) {
            com = com.add(elements[i]).into_affine();
        }
    }
    com
}

fn add_all_g2(
    crs: &UniversalParams<Curve>, 
    elements: &Vec<G2AffinePoint>
) -> G2AffinePoint {
    let mut com = KZG::commit_g2(crs, &utils::compute_constant_poly(&F::from(0))).unwrap();
    for i in 0..elements.len() {
        com = com.add(elements[i]).into_affine();
    }
    com
}

pub fn hash_to_g2(msg: impl AsRef<[u8]>) -> G2AffinePoint {
    const DST_G2: &str = "BLS_SIG_BLS12381G2_XMD:SHA-256_SSWU_RO_POP_";
    let g2_mapper = MapToCurveBasedHasher::<
        G2ProjectivePoint,
        DefaultFieldHasher<Sha256, 128>,
        WBMap<G2Config>,
    >::new(DST_G2.as_bytes())
    .unwrap();
    let q: G2AffinePoint = g2_mapper.hash(msg.as_ref()).unwrap();
    q
}

#[cfg(test)]
mod tests {
    use super::*;

    use std::time::Instant;
    use ark_std::rand::Rng;
    use ark_std::test_rng;

    #[test]
    fn it_works() {
        let n = 32;
        println!("n = {}", n);

        let msg = b"hello";
    
        // -------------- sample one-time SRS ---------------
        //run KZG setup
        let rng = &mut test_rng();
        let params = KZG::setup(n, rng).expect("Setup failed");
    
        // -------------- sample universe specific values ---------------
        //sample random keys
        let mut sk: Vec<F> = (0..n-1)
            .map(|_| HinTS::keygen(rng))
            .collect();
        sk.push(F::from(0)); //last element must be 0 for the math to work

        let epk = (0..n)
            .map(|i| HinTS::hint_gen(&params, n, i, &sk[i]))
            .collect::<Vec<ExtendedPublicKey>>();

        //sample random weights for each party
        let weights = sample_weights(n - 1);
    
        // -------------- perform universe setup ---------------
        //run universe setup
        let (vk, ak) = HinTS::preprocess(n, &params, &weights, &epk);
    
        // -------------- sample proof specific values ---------------
        //samples n-1 random bits
        let bitmap = sample_bitmap(n - 1, 0.95);

        // for all the active parties, sample partial signatures
        let partial_signatures = (0..n-1)
            .map(|i| {
                if bitmap[i] == F::from(1) {
                    let sig = HinTS::sign(msg, &sk[i]);
                    let valid = HinTS::partial_verify(&params, msg, &epk[i].pk_i, &sig);
                    if valid { Some(sig) } else { None }
                } else {
                    None
                }
            })
            .collect::<Vec<Option<G2AffinePoint>>>();
    
        let start = Instant::now();
        let π = HinTS::aggregate(&params, &ak, &vk, &bitmap, &partial_signatures);
        let duration = start.elapsed();
        println!("Time elapsed in prover is: {:?}", duration);
        
    
        let start = Instant::now();
        let threshold = (F::from(1), F::from(3)); // 1/3
        assert!(HinTS::verify(&params, msg, &vk, &π, threshold));
        let duration = start.elapsed();
        println!("Time elapsed in verifier is: {:?}", duration);

        // attack the proof
        let mut π_attack = π.clone();
        π_attack.agg_weight = F::from(1000000000); // some arbitrary weight
        assert!(!HinTS::verify(&params, msg, &vk, &π_attack, threshold));
    }

    fn sample_weights(n: usize) -> Vec<F> {
        let rng = &mut test_rng();
        (0..n).map(|_| F::from(rng.gen_range(1..10)) + F::from(10)).collect()
    }
    
    /// n is the size of the bitmap, and probability is for true or 1.
    fn sample_bitmap(n: usize, probability: f64) -> Vec<F> {
        let rng = &mut test_rng();
        let mut bitmap = vec![];
        for _i in 0..n {
            //let r = u64::rand(&mut rng);
            let bit = rng.gen_bool(probability);
            bitmap.push(F::from(bit));
        }
        bitmap
    }
}
