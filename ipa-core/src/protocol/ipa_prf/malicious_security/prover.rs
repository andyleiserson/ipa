use std::{
    borrow::Borrow,
    iter::zip,
    ops::{Index, IndexMut},
};

use typenum::{Sum, U1, U3, U4, U5};

use crate::{
    ff::{Fp31, PrimeField},
    helpers::hashing::{compute_hash, hash_to_field},
    protocol::ipa_prf::malicious_security::lagrange::{
        LagrangeInterpolator, LagrangeTable
    },
    secret_sharing::SharedValue,
};

trait ProofParams {
    const λ: usize;
    type Field: PrimeField;

    /// A `u` or `v` polynomial, defined by its evaluation at x \in 0..λ.
    type Polynomial: Default + AsRef<[Self::Field]> + IndexMut<usize, Output = Self::Field>;

    /// A proof, defined by its evaluation at x \in 0..2λ-1.
    type Proof: Default + AsRef<[Self::Field]> + IndexMut<usize, Output = Self::Field>;

    /// Lagrange table for ...
    type LagrangeTableUV: LagrangeInterpolator<Field = Self::Field>;

    /// Lagrange table for ...
    type LagrangeTableR: LagrangeInterpolator<Field = Self::Field>;

    /// Variants for final proof
    type FinalLagrangeTable: LagrangeInterpolator<Field = Self::Field>;
    type FinalPolynomial: Default + AsRef<[Self::Field]> + IndexMut<usize, Output = Self::Field>;
    type FinalProof: Default + AsRef<[Self::Field]> + IndexMut<usize, Output = Self::Field>;
}

// TODO: add to prime fields
impl Default for Fp31 {
    fn default() -> Self {
        Fp31::ZERO
    }
}

impl ProofParams for (Fp31, U4) {
    const λ: usize = 4;
    type Field = Fp31;
    type Polynomial = [Fp31; 4];
    type Proof = ZeroKnowledgeProof<Fp31, 7>;
    type LagrangeTableUV = LagrangeTable<Fp31, U4, U3>;
    type LagrangeTableR = LagrangeTable<Fp31, U4, U1>;

    type FinalLagrangeTable = LagrangeTable<Fp31, U5, U4>;
    type FinalPolynomial = [Fp31; 5];
    type FinalProof = ZeroKnowledgeProof<Fp31, 9>;
}

pub struct ZeroKnowledgeProof<F: PrimeField, const N: usize> {
    pub g: [F; N],
}

impl<F, const N: usize> Default for ZeroKnowledgeProof<F, N>
where
    F: PrimeField,
    [F; N]: Default,
{
    fn default() -> Self {
        Self {
            g: Default::default(),
        }
    }
}

impl<F: PrimeField, const N: usize> Index<usize> for ZeroKnowledgeProof<F, N> {
    type Output = F;

    fn index(&self, idx: usize) -> &F {
        &self.g[idx]
    }
}

impl<F: PrimeField, const N: usize> IndexMut<usize> for ZeroKnowledgeProof<F, N> {
    fn index_mut(&mut self, idx: usize) -> &mut F {
        &mut self.g[idx]
    }
}

impl<F: PrimeField, const N: usize> AsRef<[F]> for ZeroKnowledgeProof<F, N> {
    fn as_ref(&self) -> &[F] {
        &self.g
    }
}

#[derive(Debug)]
pub struct ProofGenerator<Params: ProofParams> {
    u: Vec<Params::Field>,
    v: Vec<Params::Field>,
}

///
/// Distributed Zero Knowledge Proofs algorithm drawn from
/// `https://eprint.iacr.org/2023/909.pdf`
///
#[allow(non_camel_case_types, clippy::many_single_char_names)]
impl<Params: ProofParams> ProofGenerator<Params> {
    pub fn new(u: Vec<Params::Field>, v: Vec<Params::Field>) -> Self {
        debug_assert_eq!(u.len(), v.len(), "u and v must be of equal length");
        Self { u, v }
    }

    pub fn compute_proof<J, B>(
        uv_iterator: J,
        lagrange_table: &Params::LagrangeTableUV,
    ) -> Params::Proof
    where
        J: Iterator<Item = B>,
        B: Borrow<(Params::Polynomial, Params::Polynomial)>,
    {
        let mut proof = Params::Proof::default();
        for uv_polynomial in uv_iterator {
            for i in 0..Params::λ {
                proof[i] += uv_polynomial.borrow().0[i] * uv_polynomial.borrow().1[i];
            }
            let p_extrapolated = lagrange_table.eval(uv_polynomial.borrow().0.as_ref());
            let q_extrapolated = lagrange_table.eval(uv_polynomial.borrow().1.as_ref());

            for (i, (x, y)) in
                zip(p_extrapolated.into_iter(), q_extrapolated.into_iter()).enumerate()
            {
                proof[Params::λ + i] += x * y;
            }
        }
        proof
    }

    pub fn compute_final_proof<I, J>(
        u: I,
        v: J,
        p_0: Params::Field,
        q_0: Params::Field,
        lagrange_table: &Params::FinalLagrangeTable,
    ) -> Params::FinalProof
    where
        I: IntoIterator<Item = Params::Field>,
        J: IntoIterator<Item = Params::Field>,
        I::IntoIter: ExactSizeIterator,
        J::IntoIter: ExactSizeIterator,
    {
        let mut u = u.into_iter();
        let mut v = v.into_iter();

        assert_eq!(u.len(), Params::λ); // We should pad with zeroes eventually
        assert_eq!(v.len(), Params::λ); // We should pad with zeroes eventually

        let mut p = Params::FinalPolynomial::default();
        let mut q = Params::FinalPolynomial::default();
        let mut proof = Params::FinalProof::default();
        p[0] = p_0;
        q[0] = q_0;
        proof[0] = p_0 * q_0;

        for i in 0..Params::λ {
            let x = u.next().unwrap_or(Params::Field::ZERO);
            let y = v.next().unwrap_or(Params::Field::ZERO);
            p[i + 1] = x;
            q[i + 1] = y;
            proof[i + 1] += x * y;
        }
        // We need a table of size `λ + 1` since we add a random point at x=0
        let p_extrapolated = lagrange_table.eval(p.as_ref());
        let q_extrapolated = lagrange_table.eval(q.as_ref());

        for (i, (x, y)) in zip(p_extrapolated.into_iter(), q_extrapolated.into_iter()).enumerate() {
            proof[Params::λ + 1 + i] += x * y;
        }

        proof
    }

    pub fn gen_challenge_and_recurse<I, J>(
        proof_left: &Params::Proof,
        proof_right: &Params::Proof,
        u: I,
        v: J,
    ) -> Self
    where
        I: IntoIterator<Item = Params::Field>,
        J: IntoIterator<Item = Params::Field>,
        I::IntoIter: ExactSizeIterator,
        J::IntoIter: ExactSizeIterator,
    {
        let mut u = u.into_iter();
        let mut v = v.into_iter();

        debug_assert_eq!(u.len() % Params::λ, 0); // We should pad with zeroes eventually

        let s = u.len() / Params::λ;

        assert!(
            s > 1,
            "When the output is this small, you should validate the proof with a more straightforward reveal"
        );

        let r: Params::Field = hash_to_field(
            &compute_hash(proof_left.as_ref()),
            &compute_hash(proof_right.as_ref()),
            u128::try_from(Params::λ).unwrap(),
        );
        let mut p = Params::Polynomial::default();
        let mut q = Params::Polynomial::default();
        let lagrange_table_r = Params::LagrangeTableR::new(&r);

        let pairs = (0..s).map(|_| {
            for i in 0..Params::λ {
                let x = u.next().unwrap_or(Params::Field::ZERO);
                let y = v.next().unwrap_or(Params::Field::ZERO);
                p[i] = x;
                q[i] = y;
            }
            let p_r = lagrange_table_r.eval(p.as_ref())[0];
            let q_r = lagrange_table_r.eval(q.as_ref())[0];
            (p_r, q_r)
        });
        let (u, v) = pairs.unzip();
        ProofGenerator::new(u, v)
    }
}

impl<Params> PartialEq<(&[u128], &[u128])> for ProofGenerator<Params>
where
    Params: ProofParams,
    Params::Field: std::cmp::PartialEq<u128>,
{
    fn eq(&self, other: &(&[u128], &[u128])) -> bool {
        let (cmp_a, cmp_b) = other;
        for (i, elem) in cmp_a.iter().enumerate() {
            if !self.u[i].eq(elem) {
                return false;
            }
        }
        for (i, elem) in cmp_b.iter().enumerate() {
            if !self.v[i].eq(elem) {
                return false;
            }
        }
        true
    }
}

#[cfg(all(test, unit_test))]
mod test {
    use generic_array::{sequence::GenericSequence, GenericArray};
    use typenum::{U2, U3, U4, U7};

    use super::ProofGenerator;
    use crate::{
        ff::{Fp31, U128Conversions},
        protocol::ipa_prf::malicious_security::lagrange::{
            CanonicalLagrangeDenominator, LagrangeTable,
        },
    };

    #[test]
    fn sample_proof() {
        const U_1: [u128; 32] = [
            0, 30, 0, 16, 0, 1, 0, 15, 0, 0, 0, 16, 0, 30, 0, 16, 29, 1, 1, 15, 0, 0, 1, 15, 2, 30,
            30, 16, 0, 0, 30, 16,
        ];
        const V_1: [u128; 32] = [
            0, 0, 0, 30, 0, 0, 0, 1, 30, 30, 30, 30, 0, 0, 30, 30, 0, 30, 0, 30, 0, 0, 0, 1, 0, 0,
            1, 1, 0, 0, 1, 1,
        ];
        const PROOF_1: [u128; 7] = [0, 30, 29, 30, 5, 28, 13];
        const PROOF_LEFT_1: [u128; 7] = [0, 11, 24, 8, 0, 4, 3];
        const U_2: [u128; 8] = [0, 0, 26, 0, 7, 18, 24, 13];
        const V_2: [u128; 8] = [10, 21, 30, 28, 15, 21, 3, 3];

        const PROOF_2: [u128; 7] = [12, 6, 15, 8, 29, 30, 6];
        const PROOF_LEFT_2: [u128; 7] = [5, 26, 14, 9, 0, 25, 2];
        const U_3: [u128; 2] = [3, 3];
        const V_3: [u128; 2] = [5, 24];

        const PROOF_3: [u128; 5] = [12, 15, 10, 14, 17];
        const P_RANDOM_WEIGHT: u128 = 12;
        const Q_RANDOM_WEIGHT: u128 = 1;

        let denominator = CanonicalLagrangeDenominator::<Fp31, U4>::new();
        let lagrange_table = LagrangeTable::<Fp31, U4, U3>::from(denominator);

        // convert to field
        let vec_u_1 = U_1
            .into_iter()
            .map(|x| Fp31::try_from(x).unwrap())
            .collect::<Vec<_>>();
        let vec_v_1 = V_1
            .into_iter()
            .map(|x| Fp31::try_from(x).unwrap())
            .collect::<Vec<_>>();
        let vec_u_2 = U_2
            .into_iter()
            .map(|x| Fp31::try_from(x).unwrap())
            .collect::<Vec<_>>();
        let vec_v_2 = V_2
            .into_iter()
            .map(|x| Fp31::try_from(x).unwrap())
            .collect::<Vec<_>>();

        // uv values in input format
        let uv_1 = (0usize..8)
            .map(|i| {
                (
                    <[_; 4]>::try_from(&vec_u_1[4 * i..4 * i + 4]).unwrap(),
                    <[_; 4]>::try_from(&vec_v_1[4 * i..4 * i + 4]).unwrap(),
                )
            })
            .collect::<Vec<_>>();
        let uv_2 = (0usize..2)
            .map(|i| {
                (
                    <[_; 4]>::try_from(&vec_u_2[4 * i..4 * i + 4]).unwrap(),
                    <[_; 4]>::try_from(&vec_v_2[4 * i..4 * i + 4]).unwrap(),
                )
            })
            .collect::<Vec<_>>();

        // first iteration
        let proof_1 =
            ProofGenerator::<(Fp31, U4)>::compute_proof::<_, _>(uv_1.iter(), &lagrange_table);
        assert_eq!(
            proof_1.g.iter().map(Fp31::as_u128).collect::<Vec<_>>(),
            PROOF_1,
        );

        // ZKP is secret-shared into two pieces
        // proof_left comes from PRSS
        let proof_left_1 =
            GenericArray::<Fp31, U7>::generate(|i| Fp31::try_from(PROOF_LEFT_1[i]).unwrap());
        let proof_right_1 = GenericArray::<Fp31, U7>::generate(|i| proof_1.g[i] - proof_left_1[i]);

        // fiat-shamir
        let pg_2 = ProofGenerator::gen_challenge_and_recurse::<_, _>(
            &proof_left_1,
            &proof_right_1,
            U_1.into_iter().map(|x| Fp31::try_from(x).unwrap()),
            V_1.into_iter().map(|x| Fp31::try_from(x).unwrap()),
        );
        assert_eq!(pg_2, (&U_2[..], &V_2[..]));

        // next iteration
        let proof_2 =
            ProofGenerator::<(Fp31, U4)>::compute_proof::<_, _>(uv_2.iter(), &lagrange_table);
        assert_eq!(
            proof_2.g.iter().map(Fp31::as_u128).collect::<Vec<_>>(),
            PROOF_2,
        );

        // ZKP is secret-shared into two pieces
        // proof_left comes from PRSS
        let proof_left_2 =
            GenericArray::<Fp31, U7>::generate(|i| Fp31::try_from(PROOF_LEFT_2[i]).unwrap());
        let proof_right_2 = GenericArray::<Fp31, U7>::generate(|i| proof_2.g[i] - proof_left_2[i]);

        // fiat-shamir
        let pg_3 = ProofGenerator::gen_challenge_and_recurse::<_, _>(
            &proof_left_2,
            &proof_right_2,
            pg_2.u,
            pg_2.v,
        );
        assert_eq!(pg_3, (&U_3[..], &V_3[..]));

        // final iteration
        let denominator = CanonicalLagrangeDenominator::<Fp31, U3>::new();
        let lagrange_table = LagrangeTable::<Fp31, U3, U2>::from(denominator);
        let proof_3 = ProofGenerator::<(Fp31, U4)>::compute_final_proof::<_, _>(
            pg_3.u,
            pg_3.v,
            Fp31::try_from(P_RANDOM_WEIGHT).unwrap(),
            Fp31::try_from(Q_RANDOM_WEIGHT).unwrap(),
            &lagrange_table,
        );
        assert_eq!(
            proof_3.g.iter().map(Fp31::as_u128).collect::<Vec<_>>(),
            PROOF_3,
        );
    }
}
