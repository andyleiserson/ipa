use std::sync::Arc;

use super::{
    maliciously_secure_mul::MaliciouslySecureMul,
    prss::{IndexedSharedRandomness, SequentialSharedRandomness},
    securemul::SecureMul,
    RecordId, Step, UniqueStepId,
};
use crate::{
    ff::Field,
    helpers::{
        messaging::{Gateway, Mesh},
        Identity,
    },
    protocol::{malicious::SecurityValidatorAccumulator, prss::Endpoint as PrssEndpoint},
};

/// Context used by each helper to perform computation. Currently they need access to shared
/// randomness generator (see `Participant`) and communication trait to send messages to each other.
#[allow(clippy::module_name_repetitions)]
#[derive(Clone, Debug)]
pub struct ProtocolContext<'a, F> {
    role: Identity,
    step: UniqueStepId,
    prss: &'a PrssEndpoint,
    gateway: &'a Gateway,
    accumulator: Option<SecurityValidatorAccumulator<F>>,
}

impl<'a, F: Field> ProtocolContext<'a, F> {
    pub fn new(role: Identity, participant: &'a PrssEndpoint, gateway: &'a Gateway) -> Self {
        Self {
            role,
            step: UniqueStepId::default(),
            prss: participant,
            gateway,
            accumulator: None,
        }
    }

    #[must_use]
    pub fn upgrade_to_malicious(self, accumulator: SecurityValidatorAccumulator<F>) -> Self {
        ProtocolContext {
            role: self.role,
            step: self.step,
            prss: self.prss,
            gateway: self.gateway,
            accumulator: Some(accumulator),
        }
    }

    /// The role of this context.
    #[must_use]
    pub fn role(&self) -> Identity {
        self.role
    }

    /// A unique identifier for this stage of the protocol execution.
    #[must_use]
    pub fn step(&self) -> &UniqueStepId {
        &self.step
    }

    /// Make a sub-context.
    /// Note that each invocation of this should use a unique value of `step`.
    #[must_use]
    pub fn narrow<S: Step + ?Sized>(&self, step: &S) -> Self {
        self.narrow_internal(self.step.narrow(step))
    }

    /// Make a sub-context.
    /// Note that each invocation of this should use a unique value of `step`.
    /// This variant (vs. `narrow`) must be used when it may be called multiple times.
    /// TODO: there are probably better names than `narrow2` and `step_holder`.
    #[must_use]
    pub fn narrow2<S: Step + ?Sized>(&self, step_holder: &once_cell::sync::OnceCell<UniqueStepId>, step: &S) -> Self {
        // TODO: confirm that `step` is consistent with `step_holder` when the once cell is already populated.
        match step_holder.get() {
            Some(saved_step) => {
                saved_step.check(step);
                self.narrow_internal(saved_step.to_owned())
            }
            None => {
                let step = step_holder.get_or_init(|| self.step.narrow(step)).to_owned();
                self.narrow_internal(step)
            }
        }
    }

    // It doesn't seem wise to expose this externally since a `step` not
    // having the right relation to `self.step` makes no sense.  The
    // public API is `narrow` and `narrow2`.
    fn narrow_internal(&self, step: UniqueStepId) -> Self {
        ProtocolContext {
            role: self.role,
            step,
            prss: self.prss,
            gateway: self.gateway,
            accumulator: self.accumulator.clone(),
        }
    }

    /// Get the indexed PRSS instance for this step.  It is safe to call this function
    /// multiple times.
    ///
    /// # Panics
    /// If `prss_rng()` is invoked for the same context, this will panic.  Use of
    /// these two functions are mutually exclusive.
    #[must_use]
    pub fn prss(&self) -> Arc<IndexedSharedRandomness> {
        self.prss.indexed(&self.step)
    }

    /// Get a pair of PRSS-based RNGs.  The first is shared with the helper to the "left",
    /// the second is shared with the helper to the "right".
    ///
    /// # Panics
    /// This method can only be called once.  This is also mutually exclusive with `prss()`.
    /// This will panic if you have previously invoked `prss()`.
    #[must_use]
    pub fn prss_rng(&self) -> (SequentialSharedRandomness, SequentialSharedRandomness) {
        self.prss.sequential(&self.step)
    }

    /// Get a set of communications channels to different peers.
    #[must_use]
    pub fn mesh(&self) -> Mesh<'_, '_> {
        self.gateway.mesh(&self.step)
    }

    /// Request a multiplication for a given record.
    #[must_use]
    pub fn multiply(self, record_id: RecordId) -> SecureMul<'a, F> {
        SecureMul::new(self, record_id)
    }

    /// ## Panics
    /// If you failed to upgrade to malicious protocol context
    #[must_use]
    pub fn malicious_multiply(self, record_id: RecordId) -> MaliciouslySecureMul<'a, F> {
        let accumulator = self.accumulator.as_ref().unwrap().clone();
        MaliciouslySecureMul::new(self, record_id, accumulator)
    }
}

macro_rules! narrow {
    ($ctx:expr, $step:expr) => ({
        static STEP_ID: once_cell::sync::OnceCell::<$crate::protocol::UniqueStepId> = once_cell::sync::OnceCell::new();
        $ctx.narrow2(&STEP_ID, $step)
    })
}

#[cfg(test)]
mod tests {
    use crate::{
        error::BoxError,
        ff::Fp31,
        protocol::QueryId,
        test_fixture::{make_contexts, make_world},
    };

    #[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
    struct TestStep;

    impl crate::protocol::Step for TestStep {}

    impl AsRef<str> for TestStep {
        fn as_ref(&self) -> &str {
            "test"
        }
    }

    #[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
    struct ChameleonStep(usize);

    impl crate::protocol::Step for ChameleonStep {}

    impl AsRef<str> for ChameleonStep {
        fn as_ref(&self) -> &str {
            if self.0 == 0 {
                "first"
            } else {
                "not first"
            }
        }
    }

    #[tokio::test]
    pub async fn narrow() -> Result<(), BoxError> {
        let world = make_world(QueryId);
        let context = make_contexts::<Fp31>(&world);

        let _ = context[0].narrow(&TestStep);

        Ok(())
    }

    // In debug builds, we should panic if we try to reuse a step in the same context.
    #[cfg(debug_assertions)]
    #[tokio::test]
    #[should_panic]
    pub async fn narrow_twice() {
        let world = make_world(QueryId);
        let context = make_contexts::<Fp31>(&world);

        let _ = context[0].narrow(&TestStep);
        let _ = context[0].narrow(&TestStep);
    }

    // When a context is narrowed inside a loop, that should not be reported as a
    // duplicate usage. Note, however, that care must be taken when writing protocols
    // or this exception may let things through that are not okay. For example:
    //
    // ```
    // for i in 0..2 {
    //  // narrow
    //  if i == 0 {
    //      // do something
    //  } else {
    //      // do something completely different
    //  }
    // }
    // ```
    #[tokio::test]
    pub async fn narrow_in_loop() {
        let world = make_world(QueryId);
        let context = make_contexts::<Fp31>(&world);

        for _ in 0..2 {
            let _ = narrow!(context[0], &TestStep);
        }
    }

    // ChameleonStep seems pretty contrived, but the check in `narrow2` that the
    // same refinement is passed each time it is called (vs. silently ignoring
    // the refinement after the first call) seemed important, and this is a test
    // for that check.
    #[cfg(debug_assertions)]
    #[tokio::test]
    #[should_panic]
    pub async fn narrow_different_ways() {
        let world = make_world(QueryId);
        let context = make_contexts::<Fp31>(&world);

        for i in 0..2 {
            let _ = narrow!(context[0], &ChameleonStep(i));
        }
    }
}
