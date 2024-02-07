use std::num::NonZeroUsize;

use futures::{stream, StreamExt};
use futures_util::future::join3;
use rand::distributions::{Standard, Distribution};

use crate::{
    ff::Field,
    helpers::GatewayConfig,
    protocol::{
        basics::SecureMul,
        context::{Context, SemiHonestContext},
        RecordId,
    },
    rand::thread_rng,
    secret_sharing::{replicated::semi_honest::AdditiveShare as Replicated, IntoShares, FieldSimd},
    test_fixture::{TestWorld, ReconstructArr, TestWorldConfig}, seq_join::seq_join,
};

struct Inputs<F: Field + FieldSimd<N>, const N: usize> {
    a: Replicated<F, N>,
    b: Vec<Replicated<F, N>>,
}

impl<F: Field + FieldSimd<N>, const N: usize> Inputs<F, N> {
    fn new(a: Replicated<F, N>, b: Vec<Replicated<F, N>>) -> Self {
        Self { a, b }
    }
}

/// Creates an arithmetic circuit with the given width and depth.
///
/// # Panics
/// panics when circuits did not produce the expected value.
pub async fn arithmetic<F, const N: usize>(width: u32, depth: u16, active_work: usize)
where
    F: Field + FieldSimd<N>,
    for<'a> Replicated<F, N>: SecureMul<SemiHonestContext<'a>>,
    [F; N]: IntoShares<Replicated<F, N>>,
    Standard: Distribution<F>,
{
    // The default GatewayConfig is optimized for performance. The default TestWorldConfig uses a
    // modified GatewayConfig that is optimized for unit tests.
    let mut config = TestWorldConfig::default();
    config.gateway_config = GatewayConfig::new(active_work);
    let world = TestWorld::new_with(config);

    // Re-use contexts for the entire execution because record identifiers are contiguous.
    let contexts = world.contexts();

    let mut inp0 = Vec::with_capacity(width as usize / N);
    let mut inp1 = Vec::with_capacity(width as usize / N);
    let mut inp2 = Vec::with_capacity(width as usize / N);
    for _ in 0..(width / (N as u32)) {
        let [a0, a1, a2] = [F::ONE; N].share_with(&mut thread_rng());
        let mut b0 = Vec::with_capacity(depth as usize);
        let mut b1 = Vec::with_capacity(depth as usize);
        let mut b2 = Vec::with_capacity(depth as usize);
        for _ in 0..(depth as usize) {
            let [s0, s1, s2] = [F::ONE; N].share_with(&mut thread_rng());
            b0.push(s0);
            b1.push(s1);
            b2.push(s2);
        }
        inp0.push(Inputs::new(a0, b0));
        inp1.push(Inputs::new(a1, b1));
        inp2.push(Inputs::new(a2, b2));
    }

    let [fut0, fut1, fut2] = match contexts.into_iter().zip([inp0, inp1, inp2])
        .map(|(ctx, col_data)| {
            let ctx = ctx.set_total_records(width as usize / N);
            seq_join(
                NonZeroUsize::new(active_work * 16).unwrap(),
                stream::iter((0..(width / (N as u32))).zip(col_data))
                    .map(move |(record, Inputs { a, b })| {
                        circuit(ctx.clone(), RecordId::from(record), depth, a, b)
                    })
            )
            .collect::<Vec<_>>()
        })
        .collect::<Vec<_>>()
        .try_into()
    {
        Ok(futs) => futs,
        Err(_) => panic!("infallible try_into array")
    };

    let (res0, res1, res2) = join3(fut0, fut1, fut2).await;

    let mut sum = 0;
    for line in res0.into_iter().zip(res1).zip(res2) {
        let ((s0, s1), s2) = line;
        for col_sum in [s0, s1, s2].reconstruct_arr() {
            sum += col_sum.as_u128();
        }
    }

    assert_eq!(sum, u128::from(width));
}

async fn circuit<'a, F, const N: usize>(
    ctx: SemiHonestContext<'a>,
    record_id: RecordId,
    depth: u16,
    mut a: Replicated<F, N>,
    b: Vec<Replicated<F, N>>,
) -> Replicated<F, N>
where
    F: Field + FieldSimd<N>,
    Replicated<F, N>: SecureMul<SemiHonestContext<'a>>,
{

    for stripe in 0..(depth as usize) {
        let stripe_ctx = ctx.narrow(&format!("s{stripe}"));
        a = a.multiply(
            &b[stripe],
            stripe_ctx,
            record_id,
        ).await.unwrap();
    }

    a
}
