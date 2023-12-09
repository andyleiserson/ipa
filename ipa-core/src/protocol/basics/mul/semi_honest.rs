use crate::{
    error::Error,
    ff::Field,
    helpers::Direction,
    protocol::{
        basics::{mul::sparse::MultiplyWork, MultiplyZeroPositions},
        context::Context,
        prss::{SharedRandomness, FromPrss},
        RecordId,
    },
    secret_sharing::{
        replicated::semi_honest::AdditiveShare as Replicated, FieldArray, SharedValueArray,
        SharedValueSimd, FieldSimd, SharedValue,
    },
};

/// IKHC multiplication protocol
/// for use with replicated secret sharing over some field F.
/// K. Chida, K. Hamada, D. Ikarashi, R. Kikuchi, and B. Pinkas. High-throughput secure AES computation. In WAHC@CCS 2018, pp. 13–24, 2018
/// Executes the secure multiplication on the MPC helper side. Each helper will proceed with
/// their part, eventually producing 2/3 shares of the product and that is what this function
/// returns.
///
///
/// The `zeros_at` argument indicates where there are known zeros in the inputs.
///
/// ## Errors
/// Lots of things may go wrong here, from timeouts to bad output. They will be signalled
/// back via the error response
pub async fn multiply<C, F, const N: usize>(
    ctx: C,
    record_id: RecordId,
    a: &Replicated<F, N>,
    b: &Replicated<F, N>,
    zeros: MultiplyZeroPositions,
) -> Result<Replicated<F, N>, Error>
where
    C: Context,
    F: Field + FieldSimd<N>,
{
    let role = ctx.role();
    let [need_to_recv, need_to_send, need_random_right] = zeros.work_for(role);
    zeros.0.check(role, "a", a);
    zeros.1.check(role, "b", b);

    // Shared randomness used to mask the values that are sent.
    let (s0, s1) = ctx.prss().generate::<(F::Array<N>, _), _>(record_id);

    let mut rhs = a.right_arr().clone() * b.right_arr();

    if need_to_send {
        // Compute the value (d_i) we want to send to the right helper (i+1).
        let right_d = a.left_arr().clone() * b.right_arr()
            + a.right_arr().clone() * b.left_arr()
            - s0.clone(); // TODO clone

        ctx.send_channel(role.peer(Direction::Right))
            .send(
                record_id,
                right_d.clone(),
            ) // TODO clone
            .await?;
        rhs += right_d;
    } else {
        debug_assert_eq!(
            a.left_arr().clone() * b.right_arr() + a.right_arr().clone() * b.left_arr(),
            <F::Array<N> as SharedValueArray<F>>::ZERO
        );
    }
    // Add randomness to this value whether we sent or not, depending on whether the
    // peer to the right needed to send.  If they send, they subtract randomness,
    // and we need to add to our share to compensate.
    if need_random_right {
        rhs += s1;
    }

    // Sleep until helper on the left sends us their (d_i-1) value.
    let mut lhs = a.left_arr().clone() * b.left_arr();
    if need_to_recv {
        let left_d: F::Array<N> = ctx.recv_channel(role.peer(Direction::Left))
            .receive(record_id)
            .await?;
        lhs += left_d;
    }
    // If we send, we subtract randomness, so we need to add to our share.
    if need_to_send {
        lhs += s0;
    }

    Ok(Replicated::new_arr(lhs, rhs))
}

#[cfg(all(test, unit_test))]
mod test {
    use std::{
        array,
        iter::{repeat, zip},
        time::Instant,
    };

    use rand::distributions::{Distribution, Standard};

    use super::multiply;
    use crate::{
        ff::{Field, Fp31, Fp32BitPrime},
        helpers::TotalRecords,
        protocol::{
            basics::{SecureMul, ZeroPositions},
            context::Context,
            RecordId,
        },
        rand::{thread_rng, Rng},
        secret_sharing::replicated::semi_honest::AdditiveShare,
        seq_join::SeqJoin,
        test_fixture::{Reconstruct, ReconstructArr, Runner, TestWorld},
    };

    #[tokio::test]
    async fn basic() {
        let world = TestWorld::default();

        assert_eq!(30, multiply_sync::<Fp31>(&world, 6, 5).await);
        assert_eq!(25, multiply_sync::<Fp31>(&world, 5, 5).await);
        assert_eq!(7, multiply_sync::<Fp31>(&world, 7, 1).await);
        assert_eq!(0, multiply_sync::<Fp31>(&world, 0, 14).await);
        assert_eq!(8, multiply_sync::<Fp31>(&world, 7, 10).await);
        assert_eq!(4, multiply_sync::<Fp31>(&world, 5, 7).await);
        assert_eq!(1, multiply_sync::<Fp31>(&world, 16, 2).await);
    }

    #[tokio::test]
    pub async fn simple() {
        let world = TestWorld::default();

        let mut rng = thread_rng();
        let a = rng.gen::<Fp31>();
        let b = rng.gen::<Fp31>();

        let res = world
            .semi_honest((a, b), |ctx, (a, b)| async move {
                a.multiply(&b, ctx.set_total_records(1), RecordId::from(0))
                    .await
                    .unwrap()
            })
            .await;

        assert_eq!(a * b, res.reconstruct());
    }

    /// This test ensures that many secure multiplications can run concurrently as long as
    /// they all have unique id associated with it. Basically it validates
    /// `TestHelper`'s ability to distinguish messages of the same type sent towards helpers
    /// executing multiple same type protocols
    #[tokio::test]
    pub async fn concurrent_mul() {
        const COUNT: usize = 10;
        let world = TestWorld::default();

        let mut rng = thread_rng();
        let a = (0..COUNT).map(|_| rng.gen::<Fp31>()).collect::<Vec<_>>();
        let b = (0..COUNT).map(|_| rng.gen::<Fp31>()).collect::<Vec<_>>();
        let expected: Vec<_> = zip(a.iter(), b.iter()).map(|(&a, &b)| a * b).collect();
        let results = world
            .semi_honest(
                (a.into_iter(), b.into_iter()),
                |ctx, (a_shares, b_shares)| async move {
                    ctx.try_join(
                        zip(
                            repeat(ctx.set_total_records(COUNT)),
                            zip(a_shares, b_shares),
                        )
                        .enumerate()
                        .map(|(i, (ctx, (a_share, b_share)))| async move {
                            a_share.multiply(&b_share, ctx, RecordId::from(i)).await
                        }),
                    )
                    .await
                    .unwrap()
                },
            )
            .await;
        assert_eq!(expected, results.reconstruct());
    }

    async fn multiply_sync<F>(world: &TestWorld, a: u128, b: u128) -> u128
    where
        F: Field,
        (F, F): Sized,
        Standard: Distribution<F>,
    {
        let a = F::try_from(a).unwrap();
        let b = F::try_from(b).unwrap();

        let result = world
            .semi_honest((a, b), |ctx, (a_share, b_share)| async move {
                a_share
                    .multiply(&b_share, ctx.set_total_records(1), RecordId::from(0))
                    .await
                    .unwrap()
            })
            .await;

        result.reconstruct().as_u128()
    }

    const MANYMULT_ITERS: usize = 16384;
    const MANYMULT_WIDTH: usize = 32;

    #[tokio::test]
    pub async fn wide_mul() {
        const COUNT: usize = 32;
        let world = TestWorld::default();

        let mut rng = thread_rng();
        let a: [Fp32BitPrime; COUNT] = (0..COUNT)
            .map(|_| rng.gen::<Fp32BitPrime>())
            .collect::<Vec<_>>()
            .try_into()
            .unwrap();
        let b: [Fp32BitPrime; COUNT] = (0..COUNT)
            .map(|_| rng.gen::<Fp32BitPrime>())
            .collect::<Vec<_>>()
            .try_into()
            .unwrap();
        let expected: [Fp32BitPrime; COUNT] = zip(a.iter(), b.iter())
            .map(|(&a, &b)| a * b)
            .collect::<Vec<_>>()
            .try_into()
            .unwrap();
        let results = world
            .semi_honest((a, b), |ctx, (a_shares, b_shares)| async move {
                multiply(
                    ctx.set_total_records(1),
                    RecordId::from(0),
                    &a_shares,
                    &b_shares,
                    ZeroPositions::NONE,
                )
                .await
                .unwrap()
            })
            .await;
        assert_eq!(expected, results.reconstruct_arr());
    }

    #[tokio::test]
    pub async fn manymult_novec() {
        let world = TestWorld::default();
        let mut rng = thread_rng();
        let mut inputs = Vec::<Vec<Fp32BitPrime>>::new();
        for _ in 0..MANYMULT_ITERS {
            inputs.push(
                (0..MANYMULT_WIDTH)
                    .map(|_| Fp32BitPrime::try_from(rng.gen_range(0u32..100) as u128).unwrap())
                    .collect::<Vec<_>>(),
            );
        }
        let expected = inputs
            .iter()
            .fold(None, |acc: Option<Vec<Fp32BitPrime>>, b| match acc {
                Some(a) => Some(a.iter().zip(b.iter()).map(|(&a, &b)| a * b).collect()),
                None => Some(b.to_vec()),
            })
            .unwrap();

        let begin = Instant::now();
        let result = world
            .semi_honest(
                inputs.into_iter().map(IntoIterator::into_iter),
                |ctx, share: Vec<Vec<AdditiveShare<Fp32BitPrime>>>| async move {
                    let ctx = ctx.set_total_records(MANYMULT_ITERS * MANYMULT_WIDTH);
                    let mut iter = share.iter();
                    let mut val = iter.next().unwrap().clone();
                    for i in 1..MANYMULT_ITERS.try_into().unwrap() {
                        let cur = iter.next().unwrap();
                        let mut res = Vec::with_capacity(MANYMULT_WIDTH);
                        for j in 0..MANYMULT_WIDTH {
                            //res.push(ctx.clone().multiply(RecordId::from(MANYMULT_WIDTH * (i - 1) + j), &val[j], &cur[j]));
                            res.push(val[j].multiply(
                                &cur[j],
                                ctx.clone(),
                                RecordId::from(MANYMULT_WIDTH * (i - 1) + j),
                            ));
                        }
                        val = ctx.parallel_join(res).await.unwrap();
                    }
                    val
                },
            )
            .await;
        tracing::info!("Protocol execution time: {:?}", begin.elapsed());
        assert_eq!(expected, result.reconstruct());
    }

    #[tokio::test]
    pub async fn manymult_vec() {
        let world = TestWorld::default();
        let mut rng = thread_rng();
        let mut inputs = Vec::<[Fp32BitPrime; MANYMULT_WIDTH]>::new();
        for _ in 0..MANYMULT_ITERS {
            inputs.push(array::from_fn(|_| rng.gen()));
        }
        let expected = inputs
            .iter()
            .fold(None, |acc: Option<Vec<Fp32BitPrime>>, b| match acc {
                Some(a) => Some(a.iter().zip(b.iter()).map(|(&a, &b)| a * b).collect()),
                None => Some(b.to_vec()),
            })
            .unwrap();

        let begin = Instant::now();
        let result = world
            .semi_honest(
                inputs.into_iter(),
                |ctx, share: Vec<AdditiveShare<Fp32BitPrime, MANYMULT_WIDTH>>| async move {
                    let ctx = ctx.set_total_records(TotalRecords::Indeterminate);
                    let mut iter = share.iter();
                    let mut val = iter.next().unwrap().clone();
                    for i in 1..MANYMULT_ITERS.try_into().unwrap() {
                        val = multiply(
                            ctx.clone(),
                            RecordId::from(i - 1),
                            &val,
                            iter.next().unwrap(),
                            ZeroPositions::NONE,
                        )
                        .await
                        .unwrap();
                    }
                    val
                },
            )
            .await;
        tracing::info!("Protocol execution time: {:?}", begin.elapsed());
        assert_eq!(expected, result.reconstruct_arr());
    }
}
