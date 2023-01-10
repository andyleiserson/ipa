use crate::ff::Field;
use crate::protocol::context::{Context, MaliciousContext};
use crate::protocol::prss::SharedRandomness;
use crate::protocol::sort::ReshareStep::RandomnessForValidation;
use crate::secret_sharing::{ArithmeticShare, MaliciousReplicated, SecretSharing};
use crate::{
    error::Error,
    helpers::{Direction, Role},
    protocol::{context::SemiHonestContext, sort::ReshareStep::ReshareRx, RecordId},
    secret_sharing::Replicated,
};
use async_trait::async_trait;
use embed_doc_image::embed_doc_image;
use futures::future::try_join;
#[embed_doc_image("reshare", "images/sort/reshare.png")]
/// Trait for reshare protocol to renew shares of a secret value for all 3 helpers.
///
/// Steps
/// ![Reshare steps][reshare]
/// 1. While calculating for a helper, we call pseudo random secret sharing (prss) to get random values which match
///    with those generated by other helpers (say `rand_left`, `rand_right`)
///    `to_helper.left` knows `rand_left` (named r1) and `to_helper.right` knows `rand_right` (named r0)
/// 2. `to_helper.left` calculates part1 = (a1 + a2) - r2 = Same as (input.left() + input.right()) - r1 from helper POV
///    `to_helper.right` calculates part2 = (a3 - r3) = Same as (input.left() - r0) from helper POV
/// 3. `to_helper.left` and `to_helper.right` exchange their calculated shares
/// 4. Everyone sets their shares
///    `to_helper.left`  = (part1 + part2, `rand_left`)  = (part1 + part2, r1)
///    `to_helper`       = (`rand_left`, `rand_right`)     = (r0, r1)
///    `to_helper.right` = (`rand_right`, part1 + part2) = (r0, part1 + part2)
#[async_trait]
pub trait Reshare<V>
where
    V: ArithmeticShare,
{
    type Share: SecretSharing<V>;

    async fn reshare(
        self,
        input: &Self::Share,
        record: RecordId,
        to_helper: Role,
    ) -> Result<Self::Share, Error>;
}

#[async_trait]
/// Reshare(i, \[x\])
/// This implements semi-honest reshare algorithm of "Efficient Secure Three-Party Sorting Protocol with an Honest Majority" at communication cost of 2R.
/// Input: Pi-1 and Pi+1 know their secret shares
/// Output: At the end of the protocol, all 3 helpers receive their shares of a new, random secret sharing of the secret value
impl<F: Field> Reshare<F> for SemiHonestContext<'_, F> {
    type Share = Replicated<F>;
    async fn reshare(
        self,
        input: &Self::Share,
        record_id: RecordId,
        to_helper: Role,
    ) -> Result<Self::Share, Error> {
        let channel = self.mesh();
        let (r0, r1) = self.prss().generate_fields(record_id);

        // `to_helper.left` calculates part1 = (input.0 + input.1) - r1 and sends part1 to `to_helper.right`
        // This is same as (a1 + a2) - r2 in the diagram
        if self.role() == to_helper.peer(Direction::Left) {
            let part1 = input.left() + input.right() - r1;
            channel
                .send(to_helper.peer(Direction::Right), record_id, part1)
                .await?;

            // Sleep until `to_helper.right` sends us their part2 value
            let part2 = channel
                .receive(to_helper.peer(Direction::Right), record_id)
                .await?;

            Ok(Replicated::new(part1 + part2, r1))
        } else if self.role() == to_helper.peer(Direction::Right) {
            // `to_helper.right` calculates part2 = (input.left() - r0) and sends it to `to_helper.left`
            // This is same as (a3 - r3) in the diagram
            let part2 = input.left() - r0;
            channel
                .send(to_helper.peer(Direction::Left), record_id, part2)
                .await?;

            // Sleep until `to_helper.left` sends us their part1 value
            let part1: F = channel
                .receive(to_helper.peer(Direction::Left), record_id)
                .await?;

            Ok(Replicated::new(r0, part1 + part2))
        } else {
            Ok(Replicated::new(r0, r1))
        }
    }
}

#[async_trait]
/// For malicious reshare, we run semi honest reshare protocol twice, once for x and another for rx and return the results
/// # Errors
/// If either of reshares fails
impl<F: Field> Reshare<F> for MaliciousContext<'_, F> {
    type Share = MaliciousReplicated<F>;
    async fn reshare(
        self,
        input: &Self::Share,
        record_id: RecordId,
        to_helper: Role,
    ) -> Result<Self::Share, Error> {
        use crate::protocol::context::SpecialAccessToMaliciousContext;
        use crate::secret_sharing::ThisCodeIsAuthorizedToDowngradeFromMalicious;
        let random_constant_ctx = self.narrow(&RandomnessForValidation);

        let (rx, x) = try_join(
            self.narrow(&ReshareRx)
                .semi_honest_context()
                .reshare(input.rx(), record_id, to_helper),
            self.semi_honest_context().reshare(
                input.x().access_without_downgrade(),
                record_id,
                to_helper,
            ),
        )
        .await?;
        let malicious_input = MaliciousReplicated::new(x, rx);
        random_constant_ctx.accumulate_macs(record_id, &malicious_input);
        Ok(malicious_input)
    }
}

#[cfg(all(test, not(feature = "shuttle")))]
mod tests {
    mod semi_honest {
        use proptest::prelude::Rng;

        use crate::rand::thread_rng;

        use crate::ff::Fp32BitPrime;
        use crate::protocol::context::Context;
        use crate::protocol::prss::SharedRandomness;
        use crate::{
            helpers::Role,
            protocol::{basics::Reshare, RecordId},
            test_fixture::{Reconstruct, Runner, TestWorld},
        };

        /// Validates that reshare protocol actually generates new shares using PRSS.
        #[tokio::test]
        async fn generates_unique_shares() {
            let world = TestWorld::new().await;

            for &target in Role::all() {
                let secret = thread_rng().gen::<Fp32BitPrime>();
                let shares = world
                    .semi_honest(secret, |ctx, share| async move {
                        let record_id = RecordId::from(0);

                        // run reshare protocol for all helpers except the one that does not know the input
                        if ctx.role() == target {
                            // test follows the reshare protocol
                            ctx.prss().generate_fields(record_id).into()
                        } else {
                            ctx.reshare(&share, record_id, target).await.unwrap()
                        }
                    })
                    .await;

                let reshared_secret = shares.reconstruct();

                // if reshare cheated and just returned its input without adding randomness,
                // this test will catch it with the probability of error (1/|F|)^2.
                // Using 32 bit field is sufficient to consider error probability negligible
                assert_eq!(secret, reshared_secret);
            }
        }

        /// This test validates the correctness of the protocol, relying on `generates_unique_shares`
        /// to ensure security. It does not verify that helpers actually attempt to generate new shares
        /// so a naive implementation of reshare that just output shares `[O]` = `[I]` where `[I]` is
        /// the input will pass this test. However `generates_unique_shares` will fail this implementation.
        #[tokio::test]
        async fn correct() {
            let world = TestWorld::new().await;

            for &role in Role::all() {
                let secret = thread_rng().gen::<Fp32BitPrime>();
                let new_shares = world
                    .semi_honest(secret, |ctx, share| async move {
                        ctx.reshare(&share, RecordId::from(0), role).await.unwrap()
                    })
                    .await;

                assert_eq!(secret, new_shares.reconstruct());
            }
        }
    }

    mod malicious {
        use futures::future::try_join;

        use crate::error::Error;
        use crate::ff::{Field, Fp32BitPrime};
        use crate::helpers::{Direction, Role};
        use crate::protocol::basics::Reshare;
        use crate::protocol::context::{Context, MaliciousContext, SemiHonestContext};
        use crate::protocol::malicious::MaliciousValidator;
        use crate::protocol::prss::SharedRandomness;
        use crate::protocol::sort::ReshareStep::{RandomnessForValidation, ReshareRx};
        use crate::protocol::RecordId;
        use crate::rand::{thread_rng, Rng};
        use crate::secret_sharing::{MaliciousReplicated, Replicated};
        use crate::test_fixture::{Reconstruct, Runner, TestWorld};

        /// Relies on semi-honest protocol tests that enforce reshare to communicate and produce
        /// new shares.
        /// TODO: It would be great to have a test to validate that helpers cannot cheat. In this
        /// setting we have 1 helper that does not know the input and if another one is malicious
        /// adversary, we are only left with one honest helper that knows the input and can validate
        /// it.
        #[tokio::test]
        async fn correct() {
            let world = TestWorld::new().await;

            for &role in Role::all() {
                let secret = thread_rng().gen::<Fp32BitPrime>();
                let new_shares = world
                    .malicious(secret, |ctx, share| async move {
                        ctx.reshare(&share, RecordId::from(0), role).await.unwrap()
                    })
                    .await;

                assert_eq!(secret, new_shares.reconstruct());
            }
        }

        async fn reshare_with_additive_attack<F: Field>(
            ctx: SemiHonestContext<'_, F>,
            input: &Replicated<F>,
            record_id: RecordId,
            to_helper: Role,
            additive_error: F,
        ) -> Result<Replicated<F>, Error> {
            let channel = ctx.mesh();
            let (r0, r1) = ctx.prss().generate_fields(record_id);

            // `to_helper.left` calculates part1 = (input.0 + input.1) - r1 and sends part1 to `to_helper.right`
            // This is same as (a1 + a2) - r2 in the diagram
            if ctx.role() == to_helper.peer(Direction::Left) {
                let part1 = input.left() + input.right() - r1 + additive_error;
                channel
                    .send(to_helper.peer(Direction::Right), record_id, part1)
                    .await?;

                // Sleep until `to_helper.right` sends us their part2 value
                let part2 = channel
                    .receive(to_helper.peer(Direction::Right), record_id)
                    .await?;

                Ok(Replicated::new(part1 + part2, r1))
            } else if ctx.role() == to_helper.peer(Direction::Right) {
                // `to_helper.right` calculates part2 = (input.left() - r0) and sends it to `to_helper.left`
                // This is same as (a3 - r3) in the diagram
                let part2 = input.left() - r0 + additive_error;
                channel
                    .send(to_helper.peer(Direction::Left), record_id, part2)
                    .await?;

                // Sleep until `to_helper.left` sends us their part1 value
                let part1: F = channel
                    .receive(to_helper.peer(Direction::Left), record_id)
                    .await?;

                Ok(Replicated::new(r0, part1 + part2))
            } else {
                Ok(Replicated::new(r0, r1))
            }
        }

        async fn reshare_malicious_with_additive_attack<F: Field>(
            ctx: MaliciousContext<'_, F>,
            input: &MaliciousReplicated<F>,
            record_id: RecordId,
            to_helper: Role,
            additive_error: F,
        ) -> Result<MaliciousReplicated<F>, Error> {
            use crate::protocol::context::SpecialAccessToMaliciousContext;
            use crate::secret_sharing::ThisCodeIsAuthorizedToDowngradeFromMalicious;
            let random_constant_ctx = ctx.narrow(&RandomnessForValidation);

            let (rx, x) = try_join(
                reshare_with_additive_attack(
                    ctx.narrow(&ReshareRx).semi_honest_context(),
                    input.rx(),
                    record_id,
                    to_helper,
                    additive_error,
                ),
                reshare_with_additive_attack(
                    ctx.semi_honest_context(),
                    input.x().access_without_downgrade(),
                    record_id,
                    to_helper,
                    additive_error,
                ),
            )
            .await?;
            let malicious_input = MaliciousReplicated::new(x, rx);

            random_constant_ctx.accumulate_macs(record_id, &malicious_input);
            Ok(malicious_input)
        }

        #[tokio::test]
        async fn malicious_validation_fail() {
            let world = TestWorld::new().await;
            let mut rng = thread_rng();

            let a = rng.gen::<Fp32BitPrime>();

            let to_helper = Role::H1;
            for malicious_actor in &[Role::H2, Role::H3] {
                world
                    .semi_honest(a, |ctx, a| async move {
                        let v = MaliciousValidator::new(ctx);
                        let m_ctx = v.context().set_total_upgrades(1);
                        let record_id = RecordId::from(0);
                        let m_a = m_ctx.upgrade(RecordId::from(0), a).await.unwrap();

                        let m_reshared_a = if m_ctx.role() == *malicious_actor {
                            // This role is spoiling the value.
                            reshare_malicious_with_additive_attack(
                                m_ctx,
                                &m_a,
                                record_id,
                                to_helper,
                                Fp32BitPrime::ONE,
                            )
                            .await
                            .unwrap()
                        } else {
                            m_ctx.reshare(&m_a, record_id, to_helper).await.unwrap()
                        };
                        match v.validate(m_reshared_a).await {
                            Ok(result) => panic!("Got a result {result:?}"),
                            Err(err) => assert!(matches!(err, Error::MaliciousSecurityCheckFailed)),
                        }
                    })
                    .await;
            }
        }
    }
}
