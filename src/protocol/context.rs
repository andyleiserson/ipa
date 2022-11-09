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
        ProtocolContext {
            role: self.role,
            step: self.step.narrow(step),
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

/*
macro_rules! narrow {
    ($result:ident, $ctx:expr, $step:expr) => {
        static $result: once_cell::sync::OnceCell::<$crate::protocol::context::ProtocolContext<Fp31>> = once_cell::sync::OnceCell::new();
        $result.get_or_init(|| $ctx.narrow($step));
        static NARROWED: once_cell::sync::OnceCell::<$crate::protocol::UniqueStepId> = once_cell::sync::OnceCell::new();
        let ctx = ctx.narrow($step);
        NARROWED.get_or_init(|| ctx.step().to_owned());
        // TODO: if NARROWED was already set, verify it still matches
        ctx
    }
}
*/

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
            let _ = context[0].narrow(&TestStep);
        }
    }
}
