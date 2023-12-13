use std::{ops::Not, iter::repeat};

#[cfg(all(test, unit_test))]
use ipa_macros::Step;

#[cfg(all(test, unit_test))]
use crate::ff::Expand;
use crate::{
    error::Error,
    ff::{ArrayAccess, CustomArray, Field},
    protocol::{
        basics::{SecureMul, ShareKnownValue},
        context::Context,
        step::BitOpStep,
        RecordId,
    },
    secret_sharing::{replicated::semi_honest::AdditiveShare, SharedValue, FieldSimd, Additive},
};

#[cfg(all(test, unit_test))]
#[derive(Step)]
pub(crate) enum Step {
    SaturatedSubtraction,
    MultiplyWithCarry,
}

/*
/// Comparison operation
/// outputs x>=y
/// # Errors
/// propagates errors from multiply
#[cfg(all(test, unit_test))]
pub async fn compare_geq<C, XS, YS>(
    ctx: C,
    record_id: RecordId,
    x: &AdditiveShare<XS>,
    y: &AdditiveShare<YS>,
) -> Result<AdditiveShare<XS::Element>, Error>
where
    C: Context,
    for<'a> &'a AdditiveShare<XS>: IntoIterator<Item = AdditiveShare<XS::Element>>,
    YS: SharedValue + CustomArray<Element = XS::Element>,
    XS: SharedValue + CustomArray + Field,
    XS::Element: Field + std::ops::Not<Output = XS::Element>,
    AdditiveShare<XS::Element>: ShareKnownValue<C, XS::Element>,
{
    // we need to initialize carry to 1 for x>=y,
    // since there are three shares 1+1+1 = 1 mod 2, so setting left = 1 and right = 1 works

    let mut carry = AdditiveShare::share_known_value(&ctx, XS::Element::ONE);
    // we don't care about the subtraction, we just want the carry
    let _ = subtraction_circuit(ctx, record_id, x, y, &mut carry).await;
    Ok(carry)
}
*/

/// Comparison operation
/// outputs x>y
/// # Errors
/// propagates errors from multiply
pub async fn compare_gt<C, F, const N: usize>(
    ctx: C,
    record_id: RecordId,
    x: Vec<AdditiveShare<F, N>>,
    y: &[AdditiveShare<F, N>],
) -> Result<AdditiveShare<F, N>, Error>
where
    C: Context,
    F: Field + FieldSimd<N>,
    AdditiveShare<F, N>: SecureMul<C> + Not<Output = AdditiveShare<F, N>>,
{
    // we need to initialize carry to 0 for x>y
    let mut carry = AdditiveShare::<F, N>::ZERO;
    // we don't care about the subtraction, we just want the carry
    let _ = subtraction_circuit(ctx, record_id, x, y, &mut carry).await;
    Ok(carry)
}

/*
/// non-saturated unsigned integer subtraction
/// subtracts y from x, Output has same length as x (carries and indices of y too large for x are ignored)
/// when y>x, it computes `(x+"XS::MaxValue")-y`
/// # Errors
/// propagates errors from multiply
pub async fn integer_sub<C, XS, YS>(
    ctx: C,
    record_id: RecordId,
    x: &AdditiveShare<XS>,
    y: &AdditiveShare<YS>,
) -> Result<AdditiveShare<XS>, Error>
where
    C: Context,
    for<'a> &'a AdditiveShare<XS>: IntoIterator<Item = AdditiveShare<XS::Element>>,
    YS: SharedValue + CustomArray<Element = XS::Element>,
    XS: SharedValue + CustomArray + Field,
    XS::Element: Field + std::ops::Not<Output = XS::Element>,
    AdditiveShare<XS::Element>: ShareKnownValue<C, XS::Element>,
{
    // we need to initialize carry to 1 for a subtraction
    let mut carry = AdditiveShare::share_known_value(&ctx, XS::Element::ONE);
    subtraction_circuit(ctx, record_id, x, y, &mut carry).await
}

/// saturated unsigned integer subtraction
/// subtracts y from x, Output has same length as x (we dont seem to need support for different length)
/// when y>x, it outputs 0
/// # Errors
/// propagates errors from multiply
#[cfg(all(test, unit_test))]
pub async fn integer_sat_sub<C, S>(
    ctx: C,
    record_id: RecordId,
    x: &AdditiveShare<S>,
    y: &AdditiveShare<S>,
) -> Result<AdditiveShare<S>, Error>
where
    C: Context,
    for<'a> &'a AdditiveShare<S>: IntoIterator<Item = AdditiveShare<S::Element>>,
    S: CustomArray + Field,
    S::Element: Field + std::ops::Not<Output = S::Element>,
    AdditiveShare<S::Element>: ShareKnownValue<C, S::Element>,
{
    let mut carry = AdditiveShare::share_known_value(&ctx, S::Element::ONE);
    let result = subtraction_circuit(
        ctx.narrow(&Step::SaturatedSubtraction),
        record_id,
        x,
        y,
        &mut carry,
    )
    .await?;

    // carry computes carry=(x>=y)
    // if carry==0 {all 0 array, i.e. Array[carry]} else {result}:
    // compute (1-carry)*Array[carry]+carry*result =carry*result
    AdditiveShare::<S>::expand(&carry)
        .multiply(&result, ctx.narrow(&Step::MultiplyWithCarry), record_id)
        .await
}
*/

/// subtraction using bit subtractor
/// subtracts y from x, Output has same length as x (carries and indices of y too large for x are ignored)
/// implementing `https://encrypto.de/papers/KSS09.pdf` from Section 3.1/3.2
///
/// # Errors
/// propagates errors from multiply
async fn subtraction_circuit<C, F, const N: usize>(
    ctx: C,
    record_id: RecordId,
    x: Vec<AdditiveShare<F, N>>,
    y: &[AdditiveShare<F, N>],
    carry: &mut AdditiveShare<F, N>,
) -> Result<Vec<AdditiveShare<F, N>>, Error>
where
    C: Context,
    F: Field + FieldSimd<N>,
    AdditiveShare<F, N>: SecureMul<C> + Not<Output = AdditiveShare<F, N>>,
{
    let mut result = Vec::with_capacity(x.len());
    assert!(y.len() <= x.len());

    for (i, (xb, yb)) in x.iter().zip(
        y.iter().chain(repeat(&AdditiveShare::<F, N>::ZERO))
    ).enumerate()
    {
        result.push(bit_subtractor(
            ctx.narrow(&BitOpStep::from(i)),
            record_id,
            xb,
            yb,
            carry,
        ).await?);
    }

    Ok(result)
}

/// This improved one-bit subtractor that only requires a single multiplication was taken from:
/// "Improved Garbled Circuit Building Blocks and Applications to Auctions and Computing Minima"
/// `https://encrypto.de/papers/KSS09.pdf`
/// Section 3.1 Integer Addition, Subtraction and Multiplication
///
/// For each bit, the `difference_bit` denoted with `result` can be efficiently computed as:
/// `d_i = x_i ⊕ !y_i ⊕ c_i` i.e. `result = x + !(c + y)`
///
/// The `carry_out` bit can be efficiently computed with just a single multiplication as:
/// `c_(i+1) = c_i ⊕ ((x_i ⊕ c_i) ∧ !(y_i ⊕ c_i))`
/// i.e. update `carry` to `carry = ( x + carry)(!(y + carry)) + carry`
///
/// # Errors
/// propagates errors from multiply
async fn bit_subtractor<C, F, const N: usize>(
    ctx: C,
    record_id: RecordId,
    x: &AdditiveShare<F, N>,
    y: &AdditiveShare<F, N>,
    carry: &mut AdditiveShare<F, N>,
) -> Result<AdditiveShare<F, N>, Error>
where
    C: Context,
    F: Field + FieldSimd<N>,
    AdditiveShare<F, N>: SecureMul<C> + Not<Output = AdditiveShare<F, N>>,
{
    let output = x + !(y + &*carry);

    *carry = &*carry
        + (x + &*carry)
            .multiply(
                &(!(y + &*carry)),
                ctx,
                record_id,
            )
            .await?;

    Ok(output)
}

#[cfg(all(test, unit_test))]
mod test {
    use futures_util::{StreamExt, TryFutureExt, TryStreamExt};
    use rand::Rng;

    use crate::{
        ff::{
            boolean::Boolean,
            boolean_array::{BA3, BA32, BA5, BA64},
            Expand, Field, Gf2,
        },
        protocol,
        protocol::{
            context::Context,
            ipa_prf::boolean_ops::comparison_and_subtraction_sequential::{
                /*compare_geq,*/ compare_gt, /*integer_sat_sub, integer_sub,*/
            }, RecordId,
        },
        rand::thread_rng,
        secret_sharing::{
            replicated::{semi_honest::AdditiveShare, ReplicatedSecretSharing},
            SharedValue, Gf2Array, IntoShares,
        },
        test_executor::run,
        test_fixture::{Reconstruct, Runner, TestWorld}, seq_join::{seq_join, SeqJoin},
    };
    use futures::stream::iter as stream_iter;

    /// testing correctness of Not
    /// just because we need it for subtractions
    #[test]
    fn test_not() {
        assert_eq!(<Boolean>::ONE, !(<Boolean>::ZERO));
        assert_eq!(<Boolean>::ZERO, !(<Boolean>::ONE));
        assert_eq!(
            AdditiveShare::new(<Boolean>::ZERO, <Boolean>::ZERO),
            !AdditiveShare::new(<Boolean>::ONE, <Boolean>::ONE)
        );
        assert_eq!(
            AdditiveShare::new(
                <BA64>::expand(&<Boolean>::ZERO),
                <BA64>::expand(&<Boolean>::ZERO)
            ),
            !AdditiveShare::new(
                <BA64>::expand(&<Boolean>::ONE),
                <BA64>::expand(&<Boolean>::ONE)
            )
        );
        assert_eq!(
            !AdditiveShare::new(
                <BA64>::expand(&<Boolean>::ZERO),
                <BA64>::expand(&<Boolean>::ZERO)
            ),
            AdditiveShare::new(
                <BA64>::expand(&<Boolean>::ONE),
                <BA64>::expand(&<Boolean>::ONE)
            )
        );
    }

    /*
    /// testing comparisons geq
    #[test]
    fn semi_honest_compare_geq() {
        run(|| async move {
            let world = TestWorld::default();

            let mut rng = thread_rng();

            let records: Vec<BA64> = vec![rng.gen::<BA64>(), rng.gen::<BA64>()];
            let x = records[0].as_u128();
            let y = records[1].as_u128();

            let expected = x >= y;

            let result = world
                .semi_honest(records.clone().into_iter(), |ctx, x_y| async move {
                    compare_geq::<_, BA64, BA64>(
                        ctx.set_total_records(1),
                        protocol::RecordId(0),
                        &x_y[0],
                        &x_y[1],
                    )
                    .await
                    .unwrap()
                })
                .await
                .reconstruct();

            assert_eq!(result, <Boolean>::from(expected));

            let result2 = world
                .semi_honest(records.into_iter(), |ctx, x_y| async move {
                    compare_geq::<_, BA64, BA64>(
                        ctx.set_total_records(1),
                        protocol::RecordId(0),
                        &x_y[0],
                        &x_y[0],
                    )
                    .await
                    .unwrap()
                })
                .await
                .reconstruct();
            assert_eq!(result2, <Boolean>::from(true));
        });
    }
    */

    /// testing comparisons gt
    #[test]
    fn semi_honest_compare_gt() {
        run(|| async move {
            let world = TestWorld::default();
            const COUNT: usize = 16_384;

            let mut rng = thread_rng();

            let mut x = Vec::with_capacity(COUNT);
            for i in 0..COUNT {
                x.push(rng.gen::<BA64>());

            }
            let x_int = x.iter().map(|x| x.as_u128()).collect::<Vec<_>>();
            let y: BA64 = rng.gen::<BA64>();
            let y_int = y.as_u128();
            let xa = x_int.clone().into_iter().map(|x| {
                (0..64).map(move |j| if (x >> j) & 1 == 1 { Gf2::ONE } else { Gf2::ZERO })
            })
            .collect::<Vec<_>>();
            let ya = (0..64).map(|i| if (y_int >> i) & 1 == 1 { Gf2::ONE } else { Gf2::ZERO }).collect::<Vec<_>>();

            let expected = x_int.iter().map(|x| *x > y_int).collect::<Vec<_>>();

            let result = world
                .semi_honest((xa.clone().into_iter(), ya.clone().into_iter()), |ctx, (x, y)| async move {
                    let ctx = ctx.set_total_records(x.len());
                    seq_join(
                        ctx.active_work(),
                        stream_iter(x.into_iter().enumerate().map(|(i, x)| {
                            compare_gt(
                                ctx.clone(),
                                RecordId::from(i),
                                x,
                                &y[..],
                            )
                        }))
                    )
                    .try_collect::<Vec<AdditiveShare<Gf2>>>()
                    .await
                    .unwrap()
                })
                .await
                .reconstruct();

            for i in 0..COUNT {
                assert_eq!(result[i], <Gf2>::from(expected[i]));
            }

            /*
            // check that x is not greater than itself
            let result2 = world
                .semi_honest(records.into_iter(), |ctx, x_y| async move {
                    compare_gt::<_, BA64, BA64>(
                        ctx.set_total_records(1),
                        protocol::RecordId(0),
                        &x_y[0],
                        &x_y[0],
                    )
                    .await
                    .unwrap()
                })
                .await
                .reconstruct();
            assert_eq!(result2, <Boolean>::from(false));
            */
        });
    }

    /*
    /// testing correctness of subtraction
    #[test]
    fn semi_honest_sub() {
        run(|| async move {
            let world = TestWorld::default();

            let mut rng = thread_rng();

            let records: Vec<BA64> = vec![rng.gen::<BA64>(), rng.gen::<BA64>()];
            let x = records[0].as_u128();
            let y = records[1].as_u128();
            let z = 1_u128 << 64;

            let expected = ((x + z) - y) % z;

            let result = world
                .semi_honest(records.into_iter(), |ctx, x_y| async move {
                    integer_sub::<_, BA64, BA64>(
                        ctx.set_total_records(1),
                        protocol::RecordId(0),
                        &x_y[0],
                        &x_y[1],
                    )
                    .await
                    .unwrap()
                })
                .await
                .reconstruct()
                .as_u128();
            assert_eq!((x, y, result), (x, y, expected));
        });
    }

    #[test]
    fn semi_honest_sat_sub() {
        run(|| async move {
            let world = TestWorld::default();

            let mut rng = thread_rng();

            let records: Vec<BA64> = vec![rng.gen::<BA64>(), rng.gen::<BA64>()];
            let x = records[0].as_u128();
            let y = records[1].as_u128();

            let expected = if y > x { 0u128 } else { x - y };

            let result = world
                .semi_honest(records.into_iter(), |ctx, x_y| async move {
                    integer_sat_sub::<_, BA64>(
                        ctx.set_total_records(1),
                        protocol::RecordId(0),
                        &x_y[0],
                        &x_y[1],
                    )
                    .await
                    .unwrap()
                })
                .await
                .reconstruct()
                .as_u128();
            assert_eq!((x, y, result), (x, y, expected));
        });
    }

    #[test]
    fn test_overflow_behavior() {
        run(|| async move {
            let world = TestWorld::default();

            let x = BA3::truncate_from(0_u128);
            let y = BA5::truncate_from(28_u128);
            let expected = 4_u128;

            let result = world
                .semi_honest((x, y), |ctx, x_y| async move {
                    integer_sub(
                        ctx.set_total_records(1),
                        protocol::RecordId(0),
                        &x_y.0,
                        &x_y.1,
                    )
                    .await
                    .unwrap()
                })
                .await
                .reconstruct()
                .as_u128();
            assert_eq!((x, y, result), (x, y, expected));
        });
    }

    #[test]
    fn semi_honest_sub_differing_lengths() {
        run(|| async move {
            let world = TestWorld::default();

            let mut rng = thread_rng();

            let records = (rng.gen::<BA64>(), rng.gen::<BA32>());
            let x = records.0.as_u128();
            let y = records.1.as_u128();
            let z = 1_u128 << 64;

            let expected = ((x + z) - y) % z;

            let result = world
                .semi_honest(records, |ctx, x_y| async move {
                    integer_sub::<_, BA64, BA32>(
                        ctx.set_total_records(1),
                        protocol::RecordId(0),
                        &x_y.0,
                        &x_y.1,
                    )
                    .await
                    .unwrap()
                })
                .await
                .reconstruct()
                .as_u128();
            assert_eq!((x, y, result), (x, y, expected));
        });
    }
    */
}
