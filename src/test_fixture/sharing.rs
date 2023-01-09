use crate::ff::Field;
use crate::protocol::boolean::RandomBitsShare;
use crate::protocol::context::MaliciousContext;
use crate::protocol::{RecordId, Substep};
use crate::rand::Rng;
use crate::secret_sharing::{
    IntoShares, MaliciousReplicated, Replicated, SecretSharing, XorReplicated,
};
use async_trait::async_trait;
use futures::future::{join, try_join_all};
use std::borrow::Borrow;
use std::iter::{repeat, zip};

#[derive(Clone, Copy)]
pub struct MaskedMatchKey(u64);

impl MaskedMatchKey {
    pub const BITS: u32 = 23;
    const MASK: u64 = u64::MAX >> (64 - Self::BITS);

    #[must_use]
    pub fn mask(v: u64) -> Self {
        Self(v & Self::MASK)
    }

    #[must_use]
    pub fn bit(self, bit_num: u32) -> u64 {
        (self.0 >> bit_num) & 1
    }
}

impl From<MaskedMatchKey> for u64 {
    fn from(v: MaskedMatchKey) -> Self {
        v.0
    }
}

impl IntoShares<XorReplicated> for MaskedMatchKey {
    fn share_with<R: Rng>(self, rng: &mut R) -> [XorReplicated; 3] {
        debug_assert_eq!(self.0, self.0 & Self::MASK);
        let s0 = rng.gen::<u64>() & Self::MASK;
        let s1 = rng.gen::<u64>() & Self::MASK;
        let s2 = self.0 ^ s0 ^ s1;
        [
            XorReplicated::new(s0, s1),
            XorReplicated::new(s1, s2),
            XorReplicated::new(s2, s0),
        ]
    }
}

/// Deconstructs a value into N values, one for each bit.
pub fn into_bits<F: Field>(x: F) -> Vec<F> {
    (0..(128 - F::PRIME.into().leading_zeros()))
        .map(|i| F::from((x.as_u128() >> i) & 1))
        .collect::<Vec<_>>()
}

/// Deconstructs a value into N values, one for each bi3t.
/// # Panics
/// It won't
#[must_use]
pub fn get_bits<F: Field>(x: u32, num_bits: u32) -> Vec<F> {
    (0..num_bits.try_into().unwrap())
        .map(|i| F::from(((x >> i) & 1).into()))
        .collect::<Vec<_>>()
}

/// Default step type for upgrades.
struct IntoMaliciousStep;

impl Substep for IntoMaliciousStep {}

impl AsRef<str> for IntoMaliciousStep {
    fn as_ref(&self) -> &str {
        "malicious_upgrade"
    }
}

/// For upgrading various shapes of replicated share to malicious.
#[async_trait]
pub trait IntoMalicious<F: Field, M>: Sized {
    async fn upgrade(self, ctx: MaliciousContext<'_, F>, record_id: &mut RecordId) -> M;
    fn upgrade_count(&self) -> usize;
}

#[async_trait]
impl<F: Field> IntoMalicious<F, MaliciousReplicated<F>> for Replicated<F> {
    async fn upgrade(
        self,
        ctx: MaliciousContext<'_, F>,
        record_id: &mut RecordId,
    ) -> MaliciousReplicated<F> {
        ctx.upgrade(*record_id, self)
            .await
            .unwrap()
    }

    fn upgrade_count(&self) -> usize { 1 }
}

#[async_trait]
impl<F, T, TM, U, UM> IntoMalicious<F, (TM, UM)> for (T, U)
where
    F: Field,
    T: IntoMalicious<F, TM> + Send,
    U: IntoMalicious<F, UM> + Send,
    TM: Sized + Send,
    UM: Sized + Send,
{
    // Note that this implementation doesn't work with arbitrary nesting.
    // For that, we'd need a `.narrow_for_upgrade()` function on the context.
    async fn upgrade(self, ctx: MaliciousContext<'_, F>, record_id: &mut RecordId) -> (TM, UM) {
        (
            self.0.upgrade(ctx.clone(), record_id).await,
            self.1.upgrade(ctx, record_id).await,
        )
    }
    fn upgrade_count(&self) -> usize {
        self.0.upgrade_count() + self.1.upgrade_count()
    }
}

#[async_trait]
impl<F, I> IntoMalicious<F, Vec<MaliciousReplicated<F>>> for I
where
    F: Field,
    I: IntoIterator<Item = Replicated<F>> + Send,
    <I as IntoIterator>::IntoIter: ExactSizeIterator + Send,
{
    // Note that this implementation doesn't work with arbitrary nesting.
    // For that, we'd need a `.narrow_for_upgrade()` function on the context.
    async fn upgrade(
        self,
        ctx: MaliciousContext<'_, F>,
        record_id: &mut RecordId,
    ) -> Vec<MaliciousReplicated<F>> {
        try_join_all(
            zip(repeat(ctx), self.into_iter().enumerate()).map(|(ctx, (i, share))| async move {
                ctx.upgrade(RecordId::from(i), share).await
            }),
        )
        .await
        .unwrap()
    }
    fn upgrade_count(&self) -> usize { 1 /* TODO */ }
}

/// A trait that is helpful for reconstruction of values in tests.
pub trait Reconstruct<T> {
    /// Validates correctness of the secret sharing scheme.
    ///
    /// # Panics
    /// Panics if the given input is not a valid replicated secret share.
    fn reconstruct(&self) -> T;
}

impl<F: Field> Reconstruct<F> for [&Replicated<F>; 3] {
    fn reconstruct(&self) -> F {
        let s0 = &self[0];
        let s1 = &self[1];
        let s2 = &self[2];

        assert_eq!(
            s0.left() + s1.left() + s2.left(),
            s0.right() + s1.right() + s2.right(),
        );

        assert_eq!(s0.right(), s1.left());
        assert_eq!(s1.right(), s2.left());
        assert_eq!(s2.right(), s0.left());

        s0.left() + s1.left() + s2.left()
    }
}

impl<F: Field> Reconstruct<F> for [Replicated<F>; 3] {
    fn reconstruct(&self) -> F {
        [&self[0], &self[1], &self[2]].reconstruct()
    }
}

impl<F, T, U, V> Reconstruct<F> for (T, U, V)
where
    F: Field,
    T: Borrow<Replicated<F>>,
    U: Borrow<Replicated<F>>,
    V: Borrow<Replicated<F>>,
{
    fn reconstruct(&self) -> F {
        [self.0.borrow(), self.1.borrow(), self.2.borrow()].reconstruct()
    }
}

impl<T, U, V, W> Reconstruct<(V, W)> for [(T, U); 3]
where
    for<'t> [&'t T; 3]: Reconstruct<V>,
    for<'u> [&'u U; 3]: Reconstruct<W>,
    V: Sized,
    W: Sized,
{
    fn reconstruct(&self) -> (V, W) {
        (
            [&self[0].0, &self[1].0, &self[2].0].reconstruct(),
            [&self[0].1, &self[1].1, &self[2].1].reconstruct(),
        )
    }
}

impl<I, T> Reconstruct<T> for [Vec<I>; 3]
where
    for<'v> [&'v Vec<I>; 3]: Reconstruct<T>,
{
    fn reconstruct(&self) -> T {
        [&self[0], &self[1], &self[2]].reconstruct()
    }
}

impl<I, T> Reconstruct<Vec<T>> for [&Vec<I>; 3]
where
    for<'i> [&'i I; 3]: Reconstruct<T>,
{
    fn reconstruct(&self) -> Vec<T> {
        assert_eq!(self[0].len(), self[1].len());
        assert_eq!(self[0].len(), self[2].len());
        zip(self[0].iter(), zip(self[1].iter(), self[2].iter()))
            .map(|(x0, (x1, x2))| [x0, x1, x2].reconstruct())
            .collect()
    }
}

impl<F, S> Reconstruct<F> for [RandomBitsShare<F, S>; 3]
where
    F: Field,
    S: SecretSharing<F>,
    for<'a> [&'a S; 3]: Reconstruct<F>,
{
    fn reconstruct(&self) -> F {
        let bits = zip(
            self[0].b_b.iter(),
            zip(self[1].b_b.iter(), self[2].b_b.iter()),
        )
        .enumerate()
        .map(|(i, (b0, (b1, b2)))| [b0, b1, b2].reconstruct() * F::from(1 << i))
        .fold(F::ZERO, |a, b| a + b);
        let value = [&self[0].b_p, &self[1].b_p, &self[2].b_p].reconstruct();
        assert_eq!(bits, value);
        value
    }
}

pub trait ValidateMalicious<F> {
    fn validate(&self, r: F);
}

impl<F, T> ValidateMalicious<F> for [T; 3]
where
    F: Field,
    T: Borrow<MaliciousReplicated<F>>,
{
    fn validate(&self, r: F) {
        use crate::secret_sharing::ThisCodeIsAuthorizedToDowngradeFromMalicious;

        let x = (
            self[0].borrow().x().access_without_downgrade(),
            self[1].borrow().x().access_without_downgrade(),
            self[2].borrow().x().access_without_downgrade(),
        );
        let rx = (
            self[0].borrow().rx(),
            self[1].borrow().rx(),
            self[2].borrow().rx(),
        );
        assert_eq!(x.reconstruct() * r, rx.reconstruct());
    }
}

impl<F: Field> ValidateMalicious<F> for [Vec<MaliciousReplicated<F>>; 3] {
    fn validate(&self, r: F) {
        assert_eq!(self[0].len(), self[1].len());
        assert_eq!(self[0].len(), self[2].len());

        for (m0, (m1, m2)) in zip(self[0].iter(), zip(self[1].iter(), self[2].iter())) {
            [m0, m1, m2].validate(r);
        }
    }
}

impl<F: Field> ValidateMalicious<F> for [(MaliciousReplicated<F>, Vec<MaliciousReplicated<F>>); 3] {
    fn validate(&self, r: F) {
        let [t0, t1, t2] = self;
        let ((s0, v0), (s1, v1), (s2, v2)) = (t0, t1, t2);

        [s0, s1, s2].validate(r);
        [v0.clone(), v1.clone(), v2.clone()].validate(r);
    }
}
