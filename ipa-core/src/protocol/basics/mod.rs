pub mod apply_permutation;
#[cfg(feature = "descriptive-gate")]
pub mod check_zero;
mod if_else;
pub(crate) mod mul;
mod reshare;
mod reveal;
mod share_known_value;
pub mod sum_of_product;

use std::ops::Not;

#[cfg(feature = "descriptive-gate")]
pub use check_zero::check_zero;
pub use if_else::{if_else, select};
pub use mul::{BooleanArrayMul, MultiplyZeroPositions, SecureMul, ZeroPositions};
pub use reshare::Reshare;
pub use reveal::{partial_reveal, reveal, Reveal};
pub use share_known_value::ShareKnownValue;
pub use sum_of_product::SumOfProducts;

use crate::{
    ff::{boolean::Boolean, PrimeField},
    protocol::{
        context::{Context, SemiHonestContext, UpgradedSemiHonestContext},
        ipa_prf::PRF_CHUNK,
    },
    secret_sharing::{
        replicated::semi_honest::AdditiveShare, SecretSharing, SharedValue, Vectorizable,
    },
    sharding::ShardBinding,
};
#[cfg(feature = "descriptive-gate")]
use crate::{
    protocol::context::UpgradedMaliciousContext,
    secret_sharing::replicated::malicious::{
        AdditiveShare as MaliciousReplicated, ExtendableField,
    },
};

pub trait BasicProtocols<C: Context, V: SharedValue + Vectorizable<N>, const N: usize = 1>:
    SecretSharing<V>
    + Reshare<C>
    + Reveal<C, N, Output = <V as Vectorizable<N>>::Array>
    + SecureMul<C>
    + ShareKnownValue<C, V>
    + SumOfProducts<C>
{
}

pub trait BooleanProtocols<C: Context, V: SharedValue + Vectorizable<N>, const N: usize = 1>:
    SecretSharing<V>
    + Reveal<C, N, Output = <V as Vectorizable<N>>::Array>
    + SecureMul<C>
    + Not<Output = Self>
{
}

// TODO: It might be better to remove this (protocols should use upgraded contexts)
impl<B: ShardBinding, F: PrimeField> BasicProtocols<SemiHonestContext<'_, B>, F>
    for AdditiveShare<F>
{
}

impl<B: ShardBinding, F: PrimeField> BasicProtocols<UpgradedSemiHonestContext<'_, B, F>, F>
    for AdditiveShare<F>
{
}

// TODO: It might be better to remove this (protocols should use upgraded contexts)
impl<B: ShardBinding> BooleanProtocols<SemiHonestContext<'_, B>, Boolean, 1>
    for AdditiveShare<Boolean>
{
}

impl<B: ShardBinding> BooleanProtocols<UpgradedSemiHonestContext<'_, B, Boolean>, Boolean, 1>
    for AdditiveShare<Boolean>
{
}

impl<B: ShardBinding> BooleanProtocols<SemiHonestContext<'_, B>, Boolean, PRF_CHUNK>
    for AdditiveShare<Boolean, PRF_CHUNK>
{
}

// Used by semi_honest_compare_gt_vec test.
impl<B: ShardBinding> BooleanProtocols<SemiHonestContext<'_, B>, Boolean, 256>
    for AdditiveShare<Boolean, 256>
{
}

#[cfg(feature = "descriptive-gate")]
impl<F: ExtendableField> BasicProtocols<UpgradedMaliciousContext<'_, F>, F>
    for MaliciousReplicated<F>
{
}
