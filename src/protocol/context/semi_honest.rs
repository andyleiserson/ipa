use crate::ff::Field;
use crate::helpers::messaging::{Gateway, Mesh};
use crate::helpers::Role;
use crate::protocol::context::{
    Context, InstrumentedIndexedSharedRandomness, InstrumentedSequentialSharedRandomness,
    MaliciousContext,
};
use crate::protocol::malicious::MaliciousValidatorAccumulator;
use crate::protocol::prss::Endpoint as PrssEndpoint;
use crate::protocol::{Step, Substep};
use crate::secret_sharing::Replicated;
use crate::sync::Arc;

use std::marker::PhantomData;
use std::num::NonZeroUsize;

/// Context for protocol executions suitable for semi-honest security model, i.e. secure against
/// honest-but-curious adversary parties.
#[derive(Clone, Debug)]
pub struct SemiHonestContext<'a, F: Field> {
    /// TODO (alex): Arc is required here because of the `TestWorld` structure. Real world
    /// may operate with raw references and be more efficient
    pub(super) inner: Arc<ContextInner<'a>>,
    pub(super) step: Step,
    pub(super) total_records: Option<NonZeroUsize>,
    _marker: PhantomData<F>,
}

impl<'a, F: Field> SemiHonestContext<'a, F> {
    pub fn new(role: Role, participant: &'a PrssEndpoint, gateway: &'a Gateway) -> Self {
        Self::new_with_total_records(role, participant, gateway, None)
    }

    pub fn new_with_total_records(
        role: Role,
        participant: &'a PrssEndpoint,
        gateway: &'a Gateway,
        total_records: Option<NonZeroUsize>,
    ) -> Self {
        Self {
            inner: ContextInner::new(role, participant, gateway),
            step: Step::default(),
            total_records,
            _marker: PhantomData::default(),
        }
    }

    /// Upgrade this context to malicious.
    /// `malicious_step` is the step that will be used for malicious protocol execution.
    /// `upgrade_step` is the step that will be used for upgrading inputs
    /// from `Replicated` to `MaliciousReplicated`.
    /// `accumulator` and `r_share` come from a `MaliciousValidator`.
    #[must_use]
    pub fn upgrade<S: Substep + ?Sized>(
        self,
        malicious_step: &S,
        upgrade_step: &S,
        accumulator: MaliciousValidatorAccumulator<F>,
        r_share: Replicated<F>,
    ) -> MaliciousContext<'a, F> {
        let upgrade_ctx = self.narrow(upgrade_step);
        MaliciousContext::new(&self, malicious_step, upgrade_ctx, accumulator, r_share)
    }
}

impl<'a, F: Field> Context<F> for SemiHonestContext<'a, F> {
    type Share = Replicated<F>;

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
            _marker: PhantomData::default(),
        }
    }

    fn is_total_records_known(&self) -> bool {
        self.total_records.is_some()
    }

    fn set_total_records(&self, total_records: usize) -> Self {
        Self {
            inner: Arc::clone(&self.inner),
            step: self.step.clone(),
            total_records: NonZeroUsize::new(total_records),
            _marker: PhantomData::default(),
        }
    }

    fn prss(&self) -> InstrumentedIndexedSharedRandomness {
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
        Replicated::one(self.role())
    }
}

#[derive(Debug)]
pub(super) struct ContextInner<'a> {
    pub role: Role,
    pub prss: &'a PrssEndpoint,
    pub gateway: &'a Gateway,
}

impl<'a> ContextInner<'a> {
    fn new(role: Role, prss: &'a PrssEndpoint, gateway: &'a Gateway) -> Arc<Self> {
        Arc::new(Self {
            role,
            prss,
            gateway,
        })
    }
}
