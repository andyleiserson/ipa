use crate::{
    bits::Serializable,
    ff::Field,
    helpers::{Map, Mapping},
    protocol::{
        basics::Reveal,
        context::{Context, MaliciousContext, NoRecord},
        sort::{
            generate_permutation::ShuffledPermutationWrapper, ShuffleRevealStep::RevealPermutation,
        },
    },
    secret_sharing::{
        replicated::semi_honest::AdditiveShare as SemiHonestAdditiveShare,
        Arithmetic as ArithmeticSecretSharing, SecretSharing, SharedValue,
    },
};
use async_trait::async_trait;
use generic_array::{ArrayLength, GenericArray};
use std::{
    fmt::{Debug, Formatter},
    ops::{Add, AddAssign, Mul, Neg, Sub, SubAssign},
};
use typenum::Unsigned;

#[derive(Clone, PartialEq, Eq)]
pub struct AdditiveShare<V: SharedValue> {
    x: SemiHonestAdditiveShare<V>,
    rx: SemiHonestAdditiveShare<V>,
}

impl<V: SharedValue> SecretSharing<V> for AdditiveShare<V> {
    const ZERO: Self = AdditiveShare::ZERO;
}

impl<V: SharedValue> ArithmeticSecretSharing<V> for AdditiveShare<V> {}

/// Trait for dangerously downgrading a malicious sharing to a semi-honest sharing, without an
/// `UnauthorizedDowngradeWrapper` to prevent unsafe use of the result.
///
/// This should not be used directly. Downgrades should use the `Downgrade` trait which applies the
/// protective `UnauthorizedDowngradeWrapper` to the result. `UncheckedDowngrade` has to be pub because
/// it is visible in the associated type `Downgrade::Target`.
///
/// The value of `UncheckedDowngrade` is that downgrades can be supported for arbitrary structs via a
/// safe implementation of the `Map` trait.
pub struct UncheckedDowngrade;

impl Mapping for UncheckedDowngrade {}

/// A trait that is implemented for various collections of `replicated::malicious::AdditiveShare`.
/// This allows a protocol to downgrade to ordinary `replicated::semi_honest::AdditiveShare`
/// when the protocol is done.  This should not be used directly.
#[async_trait]
pub trait Downgrade: Send {
    type Target: Send;
    async fn downgrade(self) -> UnauthorizedDowngradeWrapper<Self::Target>;
}

#[async_trait]
impl<T> Downgrade for T
where
    T: Map<UncheckedDowngrade> + Send + 'static,
    <T as Map<UncheckedDowngrade>>::Output: Send + 'static,
{
    type Target = <T as Map<UncheckedDowngrade>>::Output;

    async fn downgrade(self) -> UnauthorizedDowngradeWrapper<Self::Target> {
        UnauthorizedDowngradeWrapper(self.map())
    }
}

#[must_use = "You should not be downgrading `replicated::malicious::AdditiveShare` values without calling `MaliciousValidator::validate()`"]
pub struct UnauthorizedDowngradeWrapper<T>(T);
impl<T> UnauthorizedDowngradeWrapper<T> {
    pub(crate) fn new(v: T) -> Self {
        Self(v)
    }
}

pub trait ThisCodeIsAuthorizedToDowngradeFromMalicious<T> {
    fn access_without_downgrade(self) -> T;
}

impl<V: SharedValue + Debug> Debug for AdditiveShare<V> {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        write!(f, "x: {:?}, rx: {:?}", self.x, self.rx)
    }
}

impl<V: SharedValue> Default for AdditiveShare<V> {
    fn default() -> Self {
        AdditiveShare::new(
            SemiHonestAdditiveShare::default(),
            SemiHonestAdditiveShare::default(),
        )
    }
}

impl<V: SharedValue> AdditiveShare<V> {
    #[must_use]
    pub fn new(x: SemiHonestAdditiveShare<V>, rx: SemiHonestAdditiveShare<V>) -> Self {
        Self { x, rx }
    }

    pub fn x(&self) -> UnauthorizedDowngradeWrapper<&SemiHonestAdditiveShare<V>> {
        UnauthorizedDowngradeWrapper(&self.x)
    }

    pub fn rx(&self) -> &SemiHonestAdditiveShare<V> {
        &self.rx
    }

    pub const ZERO: Self = Self {
        x: SemiHonestAdditiveShare::ZERO,
        rx: SemiHonestAdditiveShare::ZERO,
    };
}

impl<V: SharedValue> Add<Self> for &AdditiveShare<V> {
    type Output = AdditiveShare<V>;

    fn add(self, rhs: Self) -> Self::Output {
        AdditiveShare {
            x: &self.x + &rhs.x,
            rx: &self.rx + &rhs.rx,
        }
    }
}

impl<V: SharedValue> Add<&Self> for AdditiveShare<V> {
    type Output = Self;

    fn add(mut self, rhs: &Self) -> Self::Output {
        self += rhs;
        self
    }
}

impl<V: SharedValue> AddAssign<&Self> for AdditiveShare<V> {
    fn add_assign(&mut self, rhs: &Self) {
        self.x += &rhs.x;
        self.rx += &rhs.rx;
    }
}

impl<V: SharedValue> Neg for AdditiveShare<V> {
    type Output = Self;

    fn neg(self) -> Self {
        Self {
            x: -self.x,
            rx: -self.rx,
        }
    }
}

impl<V: SharedValue> Sub<Self> for &AdditiveShare<V> {
    type Output = AdditiveShare<V>;

    fn sub(self, rhs: Self) -> Self::Output {
        AdditiveShare {
            x: &self.x - &rhs.x,
            rx: &self.rx - &rhs.rx,
        }
    }
}
impl<V: SharedValue> Sub<&Self> for AdditiveShare<V> {
    type Output = Self;

    fn sub(mut self, rhs: &Self) -> Self::Output {
        self -= rhs;
        self
    }
}

impl<V: SharedValue> SubAssign<&Self> for AdditiveShare<V> {
    fn sub_assign(&mut self, rhs: &Self) {
        self.x -= &rhs.x;
        self.rx -= &rhs.rx;
    }
}

impl<V: SharedValue> Mul<V> for AdditiveShare<V> {
    type Output = Self;

    fn mul(self, rhs: V) -> Self::Output {
        Self {
            x: self.x * rhs,
            rx: self.rx * rhs,
        }
    }
}

/// todo serde macro for these collections so we can hide the crazy size calculations
impl<V: SharedValue> Serializable for AdditiveShare<V>
where
    SemiHonestAdditiveShare<V>: Serializable,
    <SemiHonestAdditiveShare<V> as Serializable>::Size:
        Add<<SemiHonestAdditiveShare<V> as Serializable>::Size>,
    <<SemiHonestAdditiveShare<V> as Serializable>::Size as Add<
        <SemiHonestAdditiveShare<V> as Serializable>::Size,
    >>::Output: ArrayLength<u8>,
{
    type Size = <<SemiHonestAdditiveShare<V> as Serializable>::Size as Add<
        <SemiHonestAdditiveShare<V> as Serializable>::Size,
    >>::Output;

    fn serialize(self, buf: &mut GenericArray<u8, Self::Size>) {
        let (left, right) =
            buf.split_at_mut(<SemiHonestAdditiveShare<V> as Serializable>::Size::USIZE);
        self.x.serialize(GenericArray::from_mut_slice(left));
        self.rx.serialize(GenericArray::from_mut_slice(right));
    }

    fn deserialize(buf: &GenericArray<u8, Self::Size>) -> Self {
        let x =
            <SemiHonestAdditiveShare<V> as Serializable>::deserialize(GenericArray::from_slice(
                &buf[..<SemiHonestAdditiveShare<V> as Serializable>::Size::USIZE],
            ));
        let rx =
            <SemiHonestAdditiveShare<V> as Serializable>::deserialize(GenericArray::from_slice(
                &buf[<SemiHonestAdditiveShare<V> as Serializable>::Size::USIZE..],
            ));
        Self { x, rx }
    }
}

impl<F: Field> Map<UncheckedDowngrade> for AdditiveShare<F> {
    type Output = SemiHonestAdditiveShare<F>;
    fn map(self) -> Self::Output {
        self.x
    }
}

#[async_trait]
impl<'a, F: Field> Downgrade
    for ShuffledPermutationWrapper<AdditiveShare<F>, MaliciousContext<'a, F>>
{
    type Target = Vec<u32>;
    /// For ShuffledPermutationWrapper on downgrading, we return revealed permutation. This runs reveal on the malicious context
    async fn downgrade(self) -> UnauthorizedDowngradeWrapper<Self::Target> {
        let output = Self::reveal(self.ctx.narrow(&RevealPermutation), NoRecord, &self)
            .await
            .unwrap();
        UnauthorizedDowngradeWrapper(output)
    }
}

impl<T> ThisCodeIsAuthorizedToDowngradeFromMalicious<T> for UnauthorizedDowngradeWrapper<T> {
    fn access_without_downgrade(self) -> T {
        self.0
    }
}

#[cfg(all(test, not(feature = "shuttle")))]
mod tests {
    use super::{AdditiveShare, Downgrade, ThisCodeIsAuthorizedToDowngradeFromMalicious};
    use crate::{
        ff::{Field, Fp31},
        helpers::Role,
        rand::thread_rng,
        secret_sharing::{
            replicated::semi_honest::AdditiveShare as SemiHonestAdditiveShare, IntoShares,
        },
        test_fixture::Reconstruct,
    };
    use proptest::prelude::Rng;

    #[test]
    #[allow(clippy::many_single_char_names)]
    fn test_local_operations() {
        let mut rng = rand::thread_rng();

        let a = rng.gen::<Fp31>();
        let b = rng.gen::<Fp31>();
        let c = rng.gen::<Fp31>();
        let d = rng.gen::<Fp31>();
        let e = rng.gen::<Fp31>();
        let f = rng.gen::<Fp31>();
        // Randomization constant
        let r = rng.gen::<Fp31>();

        let one_shared = Fp31::ONE.share_with(&mut rng);
        let a_shared = a.share_with(&mut rng);
        let b_shared = b.share_with(&mut rng);
        let c_shared = c.share_with(&mut rng);
        let d_shared = d.share_with(&mut rng);
        let e_shared = e.share_with(&mut rng);
        let f_shared = f.share_with(&mut rng);
        // Randomization constant
        let r_shared = r.share_with(&mut rng);

        let ra = a * r;
        let rb = b * r;
        let rc = c * r;
        let rd = d * r;
        let re = e * r;
        let rf = f * r;

        let ra_shared = ra.share_with(&mut rng);
        let rb_shared = rb.share_with(&mut rng);
        let rc_shared = rc.share_with(&mut rng);
        let rd_shared = rd.share_with(&mut rng);
        let re_shared = re.share_with(&mut rng);
        let rf_shared = rf.share_with(&mut rng);

        let mut results = Vec::with_capacity(3);

        for &i in Role::all() {
            // Avoiding copies here is a real pain: clone!
            let malicious_one = AdditiveShare::new(one_shared[i].clone(), r_shared[i].clone());
            let malicious_a = AdditiveShare::new(a_shared[i].clone(), ra_shared[i].clone());
            let malicious_b = AdditiveShare::new(b_shared[i].clone(), rb_shared[i].clone());
            let malicious_c = AdditiveShare::new(c_shared[i].clone(), rc_shared[i].clone());
            let malicious_d = AdditiveShare::new(d_shared[i].clone(), rd_shared[i].clone());
            let malicious_e = AdditiveShare::new(e_shared[i].clone(), re_shared[i].clone());
            let malicious_f = AdditiveShare::new(f_shared[i].clone(), rf_shared[i].clone());

            let malicious_a_plus_b = malicious_a + &malicious_b;
            let malicious_c_minus_d = malicious_c - &malicious_d;
            let malicious_1_minus_e = malicious_one - &malicious_e;
            let malicious_2f = malicious_f * Fp31::from(2_u128);

            let mut temp = -malicious_a_plus_b - &malicious_c_minus_d - &malicious_1_minus_e;
            temp = temp * Fp31::from(6_u128);
            results.push(temp + &malicious_2f);
        }

        let correct =
            (-(a + b) - (c - d) - (Fp31::ONE - e)) * Fp31::from(6_u128) + Fp31::from(2_u128) * f;

        assert_eq!(
            [
                results[0].x().access_without_downgrade(),
                results[1].x().access_without_downgrade(),
                results[2].x().access_without_downgrade(),
            ]
            .reconstruct(),
            correct,
        );
        assert_eq!(
            [results[0].rx(), results[1].rx(), results[2].rx()].reconstruct(),
            correct * r,
        );
    }

    #[tokio::test]
    async fn downgrade() {
        let mut rng = thread_rng();
        let x = SemiHonestAdditiveShare::new(rng.gen::<Fp31>(), rng.gen());
        let y = SemiHonestAdditiveShare::new(rng.gen::<Fp31>(), rng.gen());
        let m = AdditiveShare::new(x.clone(), y);
        assert_eq!(x, m.downgrade().await.access_without_downgrade());
    }
}
