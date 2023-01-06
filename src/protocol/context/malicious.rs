use std::num::NonZeroUsize;

use futures::future::try_join_all;

use crate::error::Error;
use crate::ff::Field;
use crate::helpers::messaging::{Gateway, Mesh};
use crate::helpers::Role;
use crate::protocol::basics::mul::malicious::Step::RandomnessForValidation;
use crate::protocol::basics::{SecureMul, ZeroPositions};
use crate::protocol::context::prss::InstrumentedIndexedSharedRandomness;
use crate::protocol::context::{
    Context, InstrumentedSequentialSharedRandomness, SemiHonestContext,
};
use crate::protocol::malicious::MaliciousValidatorAccumulator;
use crate::protocol::modulus_conversion::BitConversionTriple;
use crate::protocol::prss::Endpoint as PrssEndpoint;
use crate::protocol::{RecordId, Step, Substep};
use crate::secret_sharing::{MaliciousReplicated, Replicated};
use crate::sync::Arc;

/// Represents protocol context in malicious setting, i.e. secure against one active adversary
/// in 3 party MPC ring.
#[derive(Clone, Debug)]
pub struct MaliciousContext<'a, F: Field> {
    /// TODO (alex): Arc is required here because of the `TestWorld` structure. Real world
    /// may operate with raw references and be more efficient
    inner: Arc<ContextInner<'a, F>>,
    step: Step,
    total_records: Option<NonZeroUsize>,
}

pub trait SpecialAccessToMaliciousContext<'a, F: Field> {
    fn accumulate_macs(self, record_id: RecordId, x: &MaliciousReplicated<F>);
    fn semi_honest_context(self) -> SemiHonestContext<'a, F>;
}

impl<'a, F: Field> MaliciousContext<'a, F> {
    pub(super) fn new<S: Substep + ?Sized>(
        source: &SemiHonestContext<'a, F>,
        malicious_step: &S,
        upgrade_ctx: SemiHonestContext<'a, F>,
        acc: MaliciousValidatorAccumulator<F>,
        r_share: Replicated<F>,
    ) -> Self {
        Self {
            inner: ContextInner::new(upgrade_ctx, acc, r_share),
            step: source.step().narrow(malicious_step),
            total_records: None,
        }
    }

    /// Sets the context's "total number of upgrades" field, which is like the
    /// "total number of records" field, but for inputs that need to be upgraded
    /// to a malicious sharing.
    #[must_use]
    pub fn set_total_upgrades(&self, total_upgrades: usize) -> Self {
        Self {
            inner: self.inner.set_total_upgrades(total_upgrades),
            step: self.step.clone(),
            total_records: self.total_records,
        }
    }

    /// Upgrade an input using this context.
    /// # Errors
    /// When the multiplication fails. This does not include additive attacks
    /// by other helpers.  These are caught later.
    pub async fn upgrade(
        &self,
        record_id: RecordId,
        input: Replicated<F>,
    ) -> Result<MaliciousReplicated<F>, Error> {
        self.upgrade_sparse(record_id, input, ZeroPositions::Pvvv)
            .await
    }

    /// Upgrade an input vector using this context.
    ///
    /// Note: This can only be used once. To use it multiple times, it would
    /// need to take a step (like the _with variants).
    ///
    /// # Errors
    /// When the multiplication fails. This does not include additive attacks
    /// by other helpers.  These are caught later.
    pub async fn upgrade_vector(
        &self,
        input: Vec<Replicated<F>>,
    ) -> Result<Vec<MaliciousReplicated<F>>, Error> {
        let ctx = self.set_total_upgrades(input.len());
        let ctx_ref = &ctx;
        try_join_all(input.into_iter().enumerate().map(|(i, share)| async move {
            ctx_ref
                .upgrade_sparse(RecordId::from(i), share, ZeroPositions::Pvvv)
                .await
        }))
        .await
    }

    /// Upgrade a sparse input using this context.
    /// # Errors
    /// When the multiplication fails. This does not include additive attacks
    /// by other helpers.  These are caught later.
    pub async fn upgrade_sparse(
        &self,
        record_id: RecordId,
        input: Replicated<F>,
        zeros_at: ZeroPositions,
    ) -> Result<MaliciousReplicated<F>, Error> {
        self.inner.upgrade(record_id, input, zeros_at).await
    }

    /// Upgrade an input for a specific bit index using this context.  Use this for
    /// inputs that have multiple bit positions in place of `upgrade()`.
    /// # Errors
    /// When the multiplication fails. This does not include additive attacks
    /// by other helpers.  These are caught later.
    pub async fn upgrade_with<SS: Substep>(
        &self,
        step: &SS,
        record_id: RecordId,
        input: Replicated<F>,
    ) -> Result<MaliciousReplicated<F>, Error> {
        self.upgrade_with_sparse(step, record_id, input, ZeroPositions::Pvvv)
            .await
    }

    /// Upgrade an input for a specific bit index using this context.  Use this for
    /// inputs that have multiple bit positions in place of `upgrade()`.
    /// # Errors
    /// When the multiplication fails. This does not include additive attacks
    /// by other helpers.  These are caught later.
    pub async fn upgrade_with_sparse<SS: Substep>(
        &self,
        step: &SS,
        record_id: RecordId,
        input: Replicated<F>,
        zeros_at: ZeroPositions,
    ) -> Result<MaliciousReplicated<F>, Error> {
        self.inner
            .upgrade_with(step, record_id, input, zeros_at)
            .await
    }

    /// Upgrade an bit conversion triple for a specific bit.
    /// # Errors
    /// When the multiplication fails. This does not include additive attacks
    /// by other helpers.  These are caught later.
    pub async fn upgrade_bit_triple<SS: Substep>(
        &self,
        step: &SS,
        record_id: RecordId,
        triple: BitConversionTriple<Replicated<F>>,
    ) -> Result<BitConversionTriple<MaliciousReplicated<F>>, Error> {
        self.inner.upgrade_bit_triple(step, record_id, triple).await
    }
}

impl<'a, F: Field> Context<F> for MaliciousContext<'a, F> {
    type Share = MaliciousReplicated<F>;

    fn role(&self) -> Role {
        self.inner.role
    }

    fn step(&self) -> &Step {
        &self.step
    }

    fn narrow<S: Substep + ?Sized>(&self, step: &S) -> Self {
        Self {
            inner: Arc::clone(&self.inner),
            step: self.step.narrow(step),
            total_records: self.total_records,
        }
    }

    #[cfg(debug_assertions)]
    fn is_total_records_known(&self) -> bool {
        self.total_records.is_some()
    }

    fn set_total_records(&self, total_records: usize) -> Self {
        Self {
            inner: Arc::clone(&self.inner),
            step: self.step.clone(),
            total_records: Some(total_records.try_into().unwrap()),
        }
    }

    fn prss(&self) -> InstrumentedIndexedSharedRandomness<'_> {
        let prss = self.inner.prss.indexed(self.step());

        InstrumentedIndexedSharedRandomness::new(prss, &self.step, self.role())
    }

    fn prss_rng(
        &self,
    ) -> (
        InstrumentedSequentialSharedRandomness<'_>,
        InstrumentedSequentialSharedRandomness<'_>,
    ) {
        let (left, right) = self.inner.prss.sequential(self.step());
        (
            InstrumentedSequentialSharedRandomness::new(left, self.step(), self.role()),
            InstrumentedSequentialSharedRandomness::new(right, self.step(), self.role()),
        )
    }

    fn mesh(&self) -> Mesh<'_, '_> {
        self.inner.gateway.mesh(self.step(), self.total_records)
    }

    fn share_of_one(&self) -> <Self as Context<F>>::Share {
        MaliciousReplicated::one(self.role(), self.inner.r_share.clone())
    }
}

/// Sometimes it is required to reinterpret malicious context as semi-honest. Ideally
/// protocols should be generic over `SecretShare` trait and not requiring this cast and taking
/// `ProtocolContext<'a, S: SecretShare<F>, F: Field>` as the context. If that is not possible,
/// this implementation makes it easier to reinterpret the context as semi-honest.
impl<'a, F: Field> SpecialAccessToMaliciousContext<'a, F> for MaliciousContext<'a, F> {
    fn accumulate_macs(self, record_id: RecordId, x: &MaliciousReplicated<F>) {
        self.inner
            .accumulator
            .accumulate_macs(&self.prss(), record_id, x);
    }

    /// Get a semi-honest context that is an  exact copy of this malicious
    /// context, so it will be tied up to the same step and prss.
    #[must_use]
    fn semi_honest_context(self) -> SemiHonestContext<'a, F> {
        // TODO: it can be made more efficient by impersonating malicious context as semi-honest
        // it does not work as of today because of https://github.com/rust-lang/rust/issues/20400
        // while it is possible to define a struct that wraps a reference to malicious context
        // and implement `Context` trait for it, implementing SecureMul and Reveal for Context
        // is not
        // For the same reason, it is not possible to implement Context<F, Share = Replicated<F>>
        // for `MaliciousContext`. Deep clone is the only option
        let mut ctx = SemiHonestContext::new_with_total_records(
            self.inner.role,
            self.inner.prss,
            self.inner.gateway,
            self.total_records,
        );
        ctx.step = self.step;

        ctx
    }
}

enum UpgradeTripleStep {
    V0,
    V1,
    V2,
}

impl crate::protocol::Substep for UpgradeTripleStep {}

impl AsRef<str> for UpgradeTripleStep {
    fn as_ref(&self) -> &str {
        match self {
            Self::V0 => "upgrade_bit_triple0",
            Self::V1 => "upgrade_bit_triple1",
            Self::V2 => "upgrade_bit_triple2",
        }
    }
}

#[derive(Debug)]
struct ContextInner<'a, F: Field> {
    role: Role,
    prss: &'a PrssEndpoint,
    gateway: &'a Gateway,
    upgrade_ctx: SemiHonestContext<'a, F>,
    accumulator: MaliciousValidatorAccumulator<F>,
    r_share: Replicated<F>,
}

impl<'a, F: Field> ContextInner<'a, F> {
    fn new(
        upgrade_ctx: SemiHonestContext<'a, F>,
        accumulator: MaliciousValidatorAccumulator<F>,
        r_share: Replicated<F>,
    ) -> Arc<Self> {
        Arc::new(ContextInner {
            role: upgrade_ctx.inner.role,
            prss: upgrade_ctx.inner.prss,
            gateway: upgrade_ctx.inner.gateway,
            upgrade_ctx,
            accumulator,
            r_share,
        })
    }

    #[must_use]
    fn set_total_upgrades(&self, total_upgrades: usize) -> Arc<Self> {
        Arc::new(ContextInner {
            role: self.role,
            prss: self.prss,
            gateway: self.gateway,
            upgrade_ctx: self.upgrade_ctx.set_total_records(total_upgrades),
            accumulator: self.accumulator.clone(),
            r_share: self.r_share.clone(),
        })
    }

    async fn upgrade_one(
        &self,
        ctx: SemiHonestContext<'a, F>,
        record_id: RecordId,
        x: Replicated<F>,
        zeros_at: ZeroPositions,
    ) -> Result<MaliciousReplicated<F>, Error> {
        let rx = ctx
            .clone()
            .multiply_sparse(
                record_id,
                &x,
                &self.r_share,
                (zeros_at, ZeroPositions::Pvvv),
            )
            .await?;
        let m = MaliciousReplicated::new(x, rx);
        let ctx = ctx.narrow(&RandomnessForValidation);
        let prss = ctx.prss();
        self.accumulator.accumulate_macs(&prss, record_id, &m);
        Ok(m)
    }

    async fn upgrade(
        &self,
        record_id: RecordId,
        x: Replicated<F>,
        zeros_at: ZeroPositions,
    ) -> Result<MaliciousReplicated<F>, Error> {
        self.upgrade_one(self.upgrade_ctx.clone(), record_id, x, zeros_at)
            .await
    }

    async fn upgrade_with<SS: Substep>(
        &self,
        step: &SS,
        record_id: RecordId,
        x: Replicated<F>,
        zeros_at: ZeroPositions,
    ) -> Result<MaliciousReplicated<F>, Error> {
        self.upgrade_one(self.upgrade_ctx.narrow(step), record_id, x, zeros_at)
            .await
    }

    async fn upgrade_bit_triple<SS: Substep>(
        &self,
        step: &SS,
        record_id: RecordId,
        triple: BitConversionTriple<Replicated<F>>,
    ) -> Result<BitConversionTriple<MaliciousReplicated<F>>, Error> {
        let [v0, v1, v2] = triple.0;
        let c = self.upgrade_ctx.narrow(step);
        Ok(BitConversionTriple(
            try_join_all([
                self.upgrade_one(
                    c.narrow(&UpgradeTripleStep::V0),
                    record_id,
                    v0,
                    ZeroPositions::Pvzz,
                ),
                self.upgrade_one(
                    c.narrow(&UpgradeTripleStep::V1),
                    record_id,
                    v1,
                    ZeroPositions::Pzvz,
                ),
                self.upgrade_one(
                    c.narrow(&UpgradeTripleStep::V2),
                    record_id,
                    v2,
                    ZeroPositions::Pzzv,
                ),
            ])
            .await?
            .try_into()
            .unwrap(),
        ))
    }
}
