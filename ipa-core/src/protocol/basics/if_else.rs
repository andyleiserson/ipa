use std::borrow::Cow;
use futures::{Future, FutureExt};

use crate::{
    error::Error,
    ff::{boolean::Boolean, Field},
    protocol::{
        basics::{
            mul::BooleanArrayMul,
            SecureMul,
        },
        context::Context,
        RecordId,
    },
    secret_sharing::{replicated::semi_honest::AdditiveShare, LinearRefOps},
};

/// Multiplexer.
///
/// Returns `true_value` if `condition` is a share of 1, else `false_value`.
/// If the arguments are vectors, all must have the same dimension and the
/// operation is performed element-wise.
///
/// Each `condition` must be a share of either 0 or 1.
/// Each `true_value` and `false_value` may be any type supporting multiplication.
///
/// # Errors
/// If the protocol fails to execute.
pub async fn if_else<F, C, S>(
    ctx: C,
    record_id: RecordId,
    condition: &S,
    true_value: &S,
    false_value: &S,
) -> Result<S, Error>
where
    F: Field,
    C: Context,
    S: SecureMul<C>,
    for<'a> &'a S: LinearRefOps<'a, S, F>,
{
    // If `condition` is a share of 1 (true), then
    //   = false_value + 1 * (true_value - false_value)
    //   = false_value + true_value - false_value
    //   = true_value
    //
    // If `condition` is a share of 0 (false), then
    //   = false_value + 0 * (true_value - false_value)
    //   = false_value
    Ok(false_value
        + &condition
            .multiply(&(true_value - false_value), ctx, record_id)
            .await?)
}

/// Wide multiplexer.
///
/// Returns `true_value` if `condition` is a share of 1, else `false_value`.
/// `condition` must be a single shared value. `true_value` and `false_value`
/// may be vectors, in which case one or the other is selected in its entirety,
/// depending on `condition`.
///
/// `condition` must be a share of either 0 or 1.
/// `true_value` and `false_value` may be any type supporting multiplication,
/// vectors of a type supporting multiplication, or a type convertible to
/// one of those.
///
/// # Errors
/// If the protocol fails to execute.
pub fn select<'fut, C, B>(
    ctx: C,
    record_id: RecordId,
    condition: &AdditiveShare<Boolean>,
    true_value: &B,
    false_value: &B,
) -> impl Future<Output = Result<B, Error>> + Send + 'fut
where
    C: Context + 'fut,
    B: Clone + BooleanArrayMul + 'fut,
{
    let false_value = B::Vectorized::from(false_value.clone());
    let true_value = B::Vectorized::from(true_value.clone());
    let condition = B::Vectorized::from(B::expand(condition));
    // If `condition` is a share of 1 (true), then
    //     false_value + condition * (true_value - false_value)
    //   = false_value + true_value - false_value
    //   = true_value
    //
    // If `condition` is a share of 0 (false), then
    //     false_value + condition * (true_value - false_value)
    //   = false_value + 0
    //   = false_value
    B::multiply(ctx, record_id, Cow::Owned(condition), Cow::Owned(true_value - &false_value))
        .map(|res| res.map(|product| (false_value + &product).into()))
}
