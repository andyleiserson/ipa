use crate::bits::{BitArray, BitArray40};
use crate::error::Error;
use crate::ff::{Field, Int};
use crate::protocol::modulus_conversion::{convert_bit, convert_bit_local, BitConversionTriple};
use crate::protocol::prss::SharedRandomness;
use crate::protocol::{context::Context, BitOpStep, RecordId};
use crate::secret_sharing::Arithmetic as ArithmeticSecretSharing;
use crate::secret_sharing::{
    replicated::semi_honest::AdditiveShare as Replicated,
    replicated::semi_honest::XorShare as XorReplicated, ArithmeticShare, SecretSharing,
};
use async_trait::async_trait;
use futures::future::try_join_all;
use std::iter::repeat;

mod malicious;
mod semi_honest;

#[async_trait]
pub trait RandomBits<V: ArithmeticShare> {
    type Share: SecretSharing<V>;

    async fn generate_random_bits(self, record_id: RecordId) -> Result<Vec<Self::Share>, Error>;
}

fn random_bits_triples<F, C, S>(
    ctx: &C,
    record_id: RecordId,
) -> Vec<BitConversionTriple<Replicated<F>>>
where
    F: Field,
    C: Context<F, Share = S>,
    S: SecretSharing<F>,
{
    // Calculate the number of bits we need to form a random number that
    // has the same number of bits as the prime.
    let l = u128::BITS - F::PRIME.into().leading_zeros();

    // Generate a pair of random numbers. We'll use these numbers as
    // the source of `l`-bit long uniformly random sequence of bits.
    let (b_bits_left, b_bits_right) = ctx.prss().generate_values(record_id);

    // Same here. For now, 256-bit is enough for our F_p
    let xor_share = XorReplicated::new(
        BitArray40::truncate_from(b_bits_left),
        BitArray40::truncate_from(b_bits_right),
    );

    // Convert each bit to secret sharings of that bit in the target field
    (0..l)
        .map(|i| convert_bit_local::<F, BitArray40>(ctx.role(), i, &xor_share))
        .collect::<Vec<_>>()
}

async fn convert_triples_to_shares<F, C, S>(
    ctx: C,
    record_id: RecordId,
    triples: &[BitConversionTriple<S>],
) -> Result<Vec<S>, Error>
where
    F: Field,
    C: Context<F, Share = S>,
    S: ArithmeticSecretSharing<F>,
{
    // Calculate the number of bits we need to form a random number that
    // has the same number of bits as the prime.
    let l = u128::BITS - F::PRIME.into().leading_zeros();
    let leading_zero_bits = F::Integer::BITS - l;

    let futures = triples.iter().enumerate().map(|(i, t)| {
        let c = ctx.narrow(&BitOpStep::from(i));
        async move { convert_bit(c, record_id, t).await }
    });

    // Pad 0's at the end to return `F::Integer::BITS` long bits
    let mut b_b = try_join_all(futures).await?;
    b_b.append(
        &mut repeat(S::ZERO)
            .take(usize::try_from(leading_zero_bits).unwrap())
            .collect::<Vec<_>>(),
    );

    Ok(b_b)
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
enum Step {
    ConvertShares,
    UpgradeBitTriples,
}

impl crate::protocol::Substep for Step {}

impl AsRef<str> for Step {
    fn as_ref(&self) -> &str {
        match self {
            Self::ConvertShares => "convert_shares",
            Self::UpgradeBitTriples => "upgrade_bit_triples",
        }
    }
}
