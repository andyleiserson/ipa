use std::{cmp::max, convert::Infallible, iter::zip, num::NonZeroU32, ops::Add};

use futures::{stream, StreamExt, TryStreamExt};
use generic_array::{ArrayLength, GenericArray};
use tracing::{info_span, Instrument};
use typenum::{Const, Unsigned, U18};

use self::quicksort::quicksort_ranges_by_key_insecure;
use crate::{
    error::{Error, LengthError, UnwrapInfallible},
    ff::{
        boolean::Boolean,
        boolean_array::{
            BooleanArray, BooleanArrayReader, BooleanArrayWriter, BA112, BA5, BA64, BA8,
        },
        curve_points::RP25519,
        ec_prime_field::Fp25519,
        Serializable, U128Conversions,
    },
    helpers::{
        stream::{div_round_up, process_slice_by_chunks, Chunk, ChunkData, TryFlattenItersExt},
        TotalRecords,
    },
    protocol::{
        basics::{BooleanArrayMul, BooleanProtocols, Reveal},
        context::{
            dzkp_validator::{DZKPValidator, TARGET_PROOF_SIZE},
            DZKPUpgraded, MacUpgraded, MaliciousProtocolSteps, UpgradableContext,
        },
        ipa_prf::{
            boolean_ops::convert_to_fp25519,
            oprf_padding::apply_dp_padding,
            prf_eval::{eval_dy_prf, gen_prf_key},
            prf_sharding::{
                attribute_cap_aggregate, histograms_ranges_sortkeys, PrfShardedIpaInputRow,
            },
            step::IpaPrfStep,
        },
        prss::FromPrss,
        RecordId,
    },
    secret_sharing::{
        replicated::{semi_honest::AdditiveShare as Replicated, ReplicatedSecretSharing},
        BitDecomposed, FieldSimd, SharedValue, TransposeFrom, Vectorizable,
    },
    seq_join::seq_join,
    utils::non_zero_prev_power_of_two,
};

pub(crate) mod aggregation;
pub mod boolean_ops;
pub mod oprf_padding;
pub mod prf_eval;
pub mod prf_sharding;

mod malicious_security;
mod quicksort;
pub(crate) mod shuffle;
pub(crate) mod step;
pub mod validation_protocol;

pub use malicious_security::{
    CompressedProofGenerator, FirstProofGenerator, LagrangeTable, ProverTableIndices,
    VerifierTableIndices,
};
pub use shuffle::Shuffle;

/// Match key type
pub type MatchKey = BA64;
/// Match key size
pub const MK_BITS: usize = BA64::BITS as usize;

// In theory, we could support (runtime-configured breakdown count) ≤ (compile-time breakdown count)
// ≤ 2^|bk|, with all three values distinct, but at present, there is no runtime configuration and
// the latter two must be equal. The implementation of `move_single_value_to_bucket` does support a
// runtime-specified count via the `breakdown_count` parameter, and implements a runtime check of
// its value.
//
// It would usually be more appropriate to make `MAX_BREAKDOWNS` an associated constant rather than
// a const parameter. However, we want to use it to enforce a correct pairing of the `BK` type
// parameter and the `B` const parameter, and specifying a constraint like
// `BreakdownKey<MAX_BREAKDOWNS = B>` on an associated constant is not currently supported. (Nor is
// supplying an associated constant `<BK as BreakdownKey>::MAX_BREAKDOWNS` as the value of a const
// parameter.) Structured the way we have it, it probably doesn't make sense to use the
// `BreakdownKey` trait in places where the `B` const parameter is not already available.
pub trait BreakdownKey<const MAX_BREAKDOWNS: usize>: BooleanArray + U128Conversions {}
impl BreakdownKey<32> for BA5 {}
impl BreakdownKey<256> for BA8 {}

/// Vectorization dimension for share conversion
pub const CONV_CHUNK: usize = 256;

/// Vectorization dimension for PRF
pub const PRF_CHUNK: usize = 16;

/// Vectorization dimension for aggregation.
pub const AGG_CHUNK: usize = 256;

/// Vectorization dimension for sort.
pub const SORT_CHUNK: usize = 256;

use step::IpaPrfStep as Step;

use crate::{
    helpers::query::DpMechanism,
    protocol::{
        context::Validator,
        dp::dp_for_histogram,
        ipa_prf::{oprf_padding::PaddingParameters, prf_eval::PrfSharing},
    },
    secret_sharing::replicated::semi_honest::AdditiveShare,
};

#[derive(Clone, Debug, Default)]
#[cfg_attr(test, derive(PartialEq, Eq))]
pub struct OPRFIPAInputRow<BK: SharedValue, TV: SharedValue, TS: SharedValue> {
    pub match_key: Replicated<MatchKey>,
    pub is_trigger: Replicated<Boolean>,
    pub breakdown_key: Replicated<BK>,
    pub trigger_value: Replicated<TV>,
    pub timestamp: Replicated<TS>,
}

impl<BK: SharedValue, TV: SharedValue, TS: SharedValue> Serializable for OPRFIPAInputRow<BK, TV, TS>
where
    Replicated<BK>: Serializable,
    Replicated<TV>: Serializable,
    Replicated<TS>: Serializable,
    <Replicated<BK> as Serializable>::Size: Add<U18>,
    <Replicated<TS> as Serializable>::Size:
        Add<<<Replicated<BK> as Serializable>::Size as Add<U18>>::Output>,
    <Replicated<TV> as Serializable>::Size: Add<
        <<Replicated<TS> as Serializable>::Size as Add<
            <<Replicated<BK> as Serializable>::Size as Add<U18>>::Output,
        >>::Output,
    >,
    <<Replicated<TV> as Serializable>::Size as Add<
        <<Replicated<TS> as Serializable>::Size as Add<
            <<Replicated<BK> as Serializable>::Size as Add<U18>>::Output,
        >>::Output,
    >>::Output: ArrayLength,
{
    type Size = <<Replicated<TV> as Serializable>::Size as Add<
        <<Replicated<TS> as Serializable>::Size as Add<
            <<Replicated<BK> as Serializable>::Size as Add<U18>>::Output,
        >>::Output,
    >>::Output;
    type DeserializationError = Error;

    fn serialize(&self, buf: &mut GenericArray<u8, Self::Size>) {
        let mk_sz = <Replicated<MatchKey> as Serializable>::Size::USIZE;
        let ts_sz = <Replicated<TS> as Serializable>::Size::USIZE;
        let bk_sz = <Replicated<BK> as Serializable>::Size::USIZE;
        let tv_sz = <Replicated<TV> as Serializable>::Size::USIZE;
        let it_sz = <Replicated<Boolean> as Serializable>::Size::USIZE;

        self.match_key
            .serialize(GenericArray::from_mut_slice(&mut buf[..mk_sz]));

        self.timestamp
            .serialize(GenericArray::from_mut_slice(&mut buf[mk_sz..mk_sz + ts_sz]));

        self.breakdown_key.serialize(GenericArray::from_mut_slice(
            &mut buf[mk_sz + ts_sz..mk_sz + ts_sz + bk_sz],
        ));

        self.trigger_value.serialize(GenericArray::from_mut_slice(
            &mut buf[mk_sz + ts_sz + bk_sz..mk_sz + ts_sz + bk_sz + tv_sz],
        ));

        self.is_trigger.serialize(GenericArray::from_mut_slice(
            &mut buf[mk_sz + ts_sz + bk_sz + tv_sz..mk_sz + ts_sz + bk_sz + tv_sz + it_sz],
        ));
    }

    fn deserialize(buf: &GenericArray<u8, Self::Size>) -> Result<Self, Self::DeserializationError> {
        let mk_sz = <Replicated<MatchKey> as Serializable>::Size::USIZE;
        let ts_sz = <Replicated<TS> as Serializable>::Size::USIZE;
        let bk_sz = <Replicated<BK> as Serializable>::Size::USIZE;
        let tv_sz = <Replicated<TV> as Serializable>::Size::USIZE;
        let it_sz = <Replicated<Boolean> as Serializable>::Size::USIZE;

        let match_key =
            Replicated::<MatchKey>::deserialize(GenericArray::from_slice(&buf[..mk_sz]))
                .unwrap_infallible();
        let timestamp =
            Replicated::<TS>::deserialize(GenericArray::from_slice(&buf[mk_sz..mk_sz + ts_sz]))
                .map_err(|e| Error::ParseError(e.into()))?;
        let breakdown_key = Replicated::<BK>::deserialize(GenericArray::from_slice(
            &buf[mk_sz + ts_sz..mk_sz + ts_sz + bk_sz],
        ))
        .map_err(|e| Error::ParseError(e.into()))?;
        let trigger_value = Replicated::<TV>::deserialize(GenericArray::from_slice(
            &buf[mk_sz + ts_sz + bk_sz..mk_sz + ts_sz + bk_sz + tv_sz],
        ))
        .map_err(|e| Error::ParseError(e.into()))?;
        let is_trigger = Replicated::<Boolean>::deserialize(GenericArray::from_slice(
            &buf[mk_sz + ts_sz + bk_sz + tv_sz..mk_sz + ts_sz + bk_sz + tv_sz + it_sz],
        ))
        .map_err(|e| Error::ParseError(e.into()))?;

        Ok(Self {
            match_key,
            is_trigger,
            breakdown_key,
            trigger_value,
            timestamp,
        })
    }
}

impl<BK, TV, TS> OPRFIPAInputRow<BK, TV, TS>
where
    BK: BooleanArray,
    TV: BooleanArray,
    TS: BooleanArray,
{
    fn join_fields(
        match_key: MatchKey,
        is_trigger: Boolean,
        breakdown_key: BK,
        trigger_value: TV,
        timestamp: TS,
    ) -> <Self as shuffle::Shuffleable>::Share {
        let mut share = <Self as shuffle::Shuffleable>::Share::ZERO;

        BooleanArrayWriter::new(&mut share)
            .write(&match_key)
            .write_boolean(is_trigger)
            .write(&breakdown_key)
            .write(&trigger_value)
            .write(&timestamp);

        share
    }

    fn split_fields(
        share: &<Self as shuffle::Shuffleable>::Share,
    ) -> (MatchKey, Boolean, BK, TV, TS) {
        let bits = BooleanArrayReader::new(share);
        let (match_key, bits) = bits.read();
        let (is_trigger, bits) = bits.read_boolean();
        let (breakdown_key, bits) = bits.read();
        let (trigger_value, bits) = bits.read();
        let (timestamp, _) = bits.read();
        (
            match_key,
            is_trigger,
            breakdown_key,
            trigger_value,
            timestamp,
        )
    }
}

impl<BK, TV, TS> shuffle::Shuffleable for OPRFIPAInputRow<BK, TV, TS>
where
    BK: BooleanArray,
    TV: BooleanArray,
    TS: BooleanArray,
{
    type Share = BA112;

    fn left(&self) -> Self::Share {
        Self::join_fields(
            ReplicatedSecretSharing::left(&self.match_key),
            self.is_trigger.left(),
            self.breakdown_key.left(),
            self.trigger_value.left(),
            self.timestamp.left(),
        )
    }

    fn right(&self) -> Self::Share {
        Self::join_fields(
            ReplicatedSecretSharing::right(&self.match_key),
            self.is_trigger.right(),
            self.breakdown_key.right(),
            self.trigger_value.right(),
            self.timestamp.right(),
        )
    }

    fn new(l: Self::Share, r: Self::Share) -> Self {
        debug_assert!(
            MatchKey::BITS + 1 + BK::BITS + TV::BITS + TS::BITS <= Self::Share::BITS,
            "share type {} is too small",
            std::any::type_name::<Self::Share>(),
        );

        let left = Self::split_fields(&l);
        let right = Self::split_fields(&r);

        Self {
            match_key: ReplicatedSecretSharing::new(left.0, right.0),
            is_trigger: ReplicatedSecretSharing::new(left.1, right.1),
            breakdown_key: ReplicatedSecretSharing::new(left.2, right.2),
            trigger_value: ReplicatedSecretSharing::new(left.3, right.3),
            timestamp: ReplicatedSecretSharing::new(left.4, right.4),
        }
    }
}

/// IPA OPRF Protocol
///
/// The output of this function is a vector of secret-shared totals, one per breakdown key
/// This protocol performs the following steps
/// 1. Converts secret-sharings of boolean arrays to secret-sharings of elliptic curve points
/// 2. Generates a random number of "dummy records" (needed to mask the information that will
///    be revealed in a later step, and thereby provide a differential privacy guarantee on that
///    information leakage) (TBD)
/// 3. Shuffles the input
/// 4. Computes an OPRF of these elliptic curve points and reveals this "pseudonym"
/// 5. Groups together rows with the same OPRF, and then obliviously sorts each group by the
///    secret-shared timestamp
/// 6. Attributes trigger events to source events
/// 7. Caps each user's total contribution to the final result
/// 8. Aggregates the contributions of all users
/// 9. Adds random noise to the total for each breakdown key (to provide a differential
///    privacy guarantee)
/// # Errors
/// Propagates errors from config issues or while running the protocol
/// # Panics
/// Propagates errors from config issues or while running the protocol
pub async fn oprf_ipa<'ctx, C, BK, TV, HV, TS, const SS_BITS: usize, const B: usize>(
    ctx: C,
    input_rows: Vec<OPRFIPAInputRow<BK, TV, TS>>,
    attribution_window_seconds: Option<NonZeroU32>,
    dp_params: DpMechanism,
    dp_padding_params: PaddingParameters,
) -> Result<Vec<Replicated<HV>>, Error>
where
    C: UpgradableContext + 'ctx + Shuffle,
    BK: BreakdownKey<B>,
    TV: BooleanArray + U128Conversions,
    HV: BooleanArray + U128Conversions,
    TS: BooleanArray + U128Conversions,
    Boolean: FieldSimd<B>,
    Replicated<Boolean>: BooleanProtocols<DZKPUpgraded<C>>,
    Replicated<Boolean, B>: BooleanProtocols<DZKPUpgraded<C>, B>,
    Replicated<Boolean, AGG_CHUNK>: BooleanProtocols<DZKPUpgraded<C>, AGG_CHUNK>,
    Replicated<Boolean, CONV_CHUNK>: BooleanProtocols<DZKPUpgraded<C>, CONV_CHUNK>,
    Replicated<Boolean, SORT_CHUNK>: BooleanProtocols<DZKPUpgraded<C>, SORT_CHUNK>,
    Replicated<Fp25519, PRF_CHUNK>:
        PrfSharing<MacUpgraded<C, Fp25519>, PRF_CHUNK, Field = Fp25519> + FromPrss,
    Replicated<RP25519, PRF_CHUNK>:
        Reveal<MacUpgraded<C, Fp25519>, Output = <RP25519 as Vectorizable<PRF_CHUNK>>::Array>,
    Replicated<BK>: BooleanArrayMul<DZKPUpgraded<C>>
        + Reveal<DZKPUpgraded<C>, Output = <BK as Vectorizable<1>>::Array>,
    Replicated<TS>: BooleanArrayMul<DZKPUpgraded<C>>,
    Replicated<TV>: BooleanArrayMul<DZKPUpgraded<C>>,
    BitDecomposed<Replicated<Boolean, AGG_CHUNK>>:
        for<'a> TransposeFrom<&'a Vec<Replicated<BK>>, Error = LengthError>,
    BitDecomposed<Replicated<Boolean, AGG_CHUNK>>:
        for<'a> TransposeFrom<&'a Vec<Replicated<TV>>, Error = LengthError>,
    Vec<BitDecomposed<Replicated<Boolean, B>>>: for<'a> TransposeFrom<
        &'a [BitDecomposed<Replicated<Boolean, AGG_CHUNK>>],
        Error = Infallible,
    >,
    BitDecomposed<Replicated<Boolean, B>>:
        for<'a> TransposeFrom<&'a [Replicated<TV>; B], Error = Infallible>,
    Vec<Replicated<HV>>:
        for<'a> TransposeFrom<&'a BitDecomposed<Replicated<Boolean, B>>, Error = LengthError>,
    BitDecomposed<AdditiveShare<Boolean, B>>:
        for<'a> TransposeFrom<&'a [AdditiveShare<HV>; B], Error = Infallible>,
{
    if input_rows.is_empty() {
        return Ok(vec![Replicated::ZERO; B]);
    }

    // Apply DP padding for OPRF
    let padded_input_rows = apply_dp_padding::<_, OPRFIPAInputRow<BK, TV, TS>, B>(
        ctx.narrow(&Step::PaddingDp),
        input_rows,
        &dp_padding_params,
    )
    .await?;

    let shuffled = ctx
        .narrow(&Step::Shuffle)
        .shuffle(padded_input_rows)
        .instrument(info_span!("shuffle_inputs"))
        .await?;
    let mut prfd_inputs = compute_prf_for_inputs(ctx.clone(), &shuffled).await?;

    prfd_inputs.sort_by(|a, b| a.prf_of_match_key.cmp(&b.prf_of_match_key));

    let (row_count_histogram, ranges) = histograms_ranges_sortkeys(&mut prfd_inputs);
    if row_count_histogram.len() == 1 {
        // No user has more than one record.
        return Ok(vec![Replicated::ZERO; B]);
    }
    quicksort_ranges_by_key_insecure(
        ctx.narrow(&Step::SortByTimestamp),
        &mut prfd_inputs,
        false,
        |x| &x.sort_key,
        ranges,
    )
    .await?;

    let output_histogram = attribute_cap_aggregate::<_, _, _, _, _, SS_BITS, B>(
        ctx.narrow(&Step::Attribution),
        prfd_inputs,
        attribution_window_seconds,
        &row_count_histogram,
        &dp_padding_params,
    )
    .await?;

    let noisy_output_histogram =
        dp_for_histogram::<_, B, HV, SS_BITS>(ctx, output_histogram, dp_params).await?;
    Ok(noisy_output_histogram)
}

/// Returns a suitable proof chunk size (in records) for use with `convert_to_fp25519`.
///
/// We expect 2*256 = 512 gates in total for two additions per conversion. The
/// vectorization factor is `CONV_CHUNK`. Let `len` equal the number of converted
/// shares. The total amount of multiplications is `CONV_CHUNK`*512*len. We want
/// `CONV_CHUNK`*512*len ≈ 50M for a reasonably-sized proof. There is also a constraint
/// on proof chunks to be powers of two, and we don't want to compute a proof chunk
/// of zero when `TARGET_PROOF_SIZE` is smaller for tests.
fn conv_proof_chunk() -> usize {
    non_zero_prev_power_of_two(max(2, TARGET_PROOF_SIZE / CONV_CHUNK / 512))
}

#[tracing::instrument(name = "compute_prf_for_inputs", skip_all)]
async fn compute_prf_for_inputs<C, BK, TV, TS>(
    ctx: C,
    input_rows: &[OPRFIPAInputRow<BK, TV, TS>],
) -> Result<Vec<PrfShardedIpaInputRow<BK, TV, TS>>, Error>
where
    C: UpgradableContext,
    BK: BooleanArray,
    TV: BooleanArray,
    TS: BooleanArray,
    Replicated<Boolean, CONV_CHUNK>: BooleanProtocols<DZKPUpgraded<C>, CONV_CHUNK>,
    Replicated<Fp25519, PRF_CHUNK>:
        PrfSharing<MacUpgraded<C, Fp25519>, PRF_CHUNK, Field = Fp25519> + FromPrss,
    Replicated<RP25519, PRF_CHUNK>:
        Reveal<MacUpgraded<C, Fp25519>, Output = <RP25519 as Vectorizable<PRF_CHUNK>>::Array>,
{
    let conv_records =
        TotalRecords::specified(div_round_up(input_rows.len(), Const::<CONV_CHUNK>))?;
    let eval_records = TotalRecords::specified(div_round_up(input_rows.len(), Const::<PRF_CHUNK>))?;
    let convert_ctx = ctx.set_total_records(conv_records);

    let validator = convert_ctx.dzkp_validator(
        MaliciousProtocolSteps {
            protocol: &Step::ConvertFp25519,
            validate: &Step::ConvertFp25519Validate,
        },
        conv_proof_chunk(),
    );
    let m_ctx = validator.context();

    let curve_pts = seq_join(
        ctx.active_work(),
        process_slice_by_chunks(input_rows, move |idx, records: ChunkData<_, CONV_CHUNK>| {
            let record_id = RecordId::from(idx);
            let input_match_keys: &dyn Fn(usize) -> Replicated<MatchKey> =
                &|i| records[i].match_key.clone();
            let match_keys =
                BitDecomposed::<Replicated<Boolean, 256>>::transposed_from(input_match_keys)
                    .unwrap_infallible();
            convert_to_fp25519::<_, CONV_CHUNK, PRF_CHUNK>(m_ctx.clone(), record_id, match_keys)
        }),
    )
    .map_ok(Chunk::unpack::<PRF_CHUNK>)
    .try_flatten_iters()
    .try_collect::<Vec<_>>()
    .await?;

    let prf_key = gen_prf_key(&ctx.narrow(&IpaPrfStep::PrfKeyGen));
    let validator = ctx
        .narrow(&Step::EvalPrf)
        .set_total_records(eval_records)
        .validator::<Fp25519>();
    let eval_ctx = validator.context();

    let prf_of_match_keys = seq_join(
        ctx.active_work(),
        stream::iter(curve_pts).enumerate().map(|(i, curve_pts)| {
            let record_id = RecordId::from(i);
            let eval_ctx = eval_ctx.clone();
            let prf_key = &prf_key;
            curve_pts
                .then(move |pts| eval_dy_prf::<_, PRF_CHUNK>(eval_ctx, record_id, prf_key, pts))
        }),
    )
    .try_collect::<Vec<_>>()
    .await?;

    Ok(zip(input_rows, prf_of_match_keys.into_iter().flatten())
        .map(|(input, prf_of_match_key)| {
            let OPRFIPAInputRow {
                match_key: _,
                is_trigger,
                breakdown_key,
                trigger_value,
                timestamp,
            } = &input;

            PrfShardedIpaInputRow {
                prf_of_match_key,
                is_trigger_bit: is_trigger.clone(),
                breakdown_key: breakdown_key.clone(),
                trigger_value: trigger_value.clone(),
                timestamp: timestamp.clone(),
                sort_key: Replicated::ZERO,
            }
        })
        .collect())
}

#[cfg(all(test, any(unit_test, feature = "shuttle")))]
pub mod tests {

    use crate::{
        ff::{
            boolean_array::{BA16, BA20, BA3, BA5, BA8},
            U128Conversions,
        },
        helpers::query::DpMechanism,
        protocol::{
            dp::NoiseParams,
            ipa_prf::{oprf_ipa, oprf_padding::PaddingParameters},
        },
        sharding::NotSharded,
        test_executor::run,
        test_fixture::{ipa::TestRawDataRecord, Reconstruct, Runner, TestWorld, TestWorldConfig},
    };

    fn test_input(
        timestamp: u64,
        user_id: u64,
        is_trigger_report: bool,
        breakdown_key: u32,
        trigger_value: u32,
    ) -> TestRawDataRecord {
        TestRawDataRecord {
            timestamp,
            user_id,
            is_trigger_report,
            breakdown_key,
            trigger_value,
        }
    }

    #[test]
    fn semi_honest() {
        const EXPECTED: &[u128] = &[0, 2, 5, 0, 0, 0, 0, 0];

        run(|| async {
            let world = TestWorld::default();

            let records: Vec<TestRawDataRecord> = vec![
                test_input(0, 12345, false, 1, 0),
                test_input(5, 12345, false, 2, 0),
                test_input(10, 12345, true, 0, 5),
                test_input(0, 68362, false, 1, 0),
                test_input(20, 68362, true, 0, 2),
            ]; // trigger value of 2 attributes to earlier source row with breakdown 1 and trigger
               // value of 5 attributes to source row with breakdown 2.
            let dp_params = DpMechanism::NoDp;
            let padding_params = if cfg!(feature = "shuttle") {
                // To reduce runtime. There is also a hard upper limit in the shuttle
                // config (`max_steps`), that may need to be increased to support larger
                // runs.
                PaddingParameters::no_padding()
            } else {
                PaddingParameters::relaxed()
            };

            let mut result: Vec<_> = world
                .semi_honest(records.into_iter(), |ctx, input_rows| async move {
                    oprf_ipa::<_, BA5, BA3, BA16, BA20, 5, 32>(
                        ctx,
                        input_rows,
                        None,
                        dp_params,
                        padding_params,
                    )
                    .await
                    .unwrap()
                })
                .await
                .reconstruct();
            result.truncate(EXPECTED.len());
            assert_eq!(
                result.iter().map(|&v| v.as_u128()).collect::<Vec<_>>(),
                EXPECTED,
            );
        });
    }

    #[test]
    fn malicious() {
        const EXPECTED: &[u128] = &[0, 2, 5, 0, 0, 0, 0, 0];

        run(|| async {
            let world = TestWorld::default();

            let records: Vec<TestRawDataRecord> = vec![
                test_input(0, 12345, false, 1, 0),
                test_input(5, 12345, false, 2, 0),
                test_input(10, 12345, true, 0, 5),
                test_input(0, 68362, false, 1, 0),
                test_input(20, 68362, true, 0, 2),
            ]; // trigger value of 2 attributes to earlier source row with breakdown 1 and trigger
               // value of 5 attributes to source row with breakdown 2.
            let dp_params = DpMechanism::NoDp;
            let padding_params = PaddingParameters::no_padding();

            let mut result: Vec<_> = world
                .malicious(records.into_iter(), |ctx, input_rows| async move {
                    oprf_ipa::<_, BA5, BA3, BA16, BA20, 5, 32>(
                        ctx,
                        input_rows,
                        None,
                        dp_params,
                        padding_params,
                    )
                    .await
                    .unwrap()
                })
                .await
                .reconstruct();
            result.truncate(EXPECTED.len());
            assert_eq!(
                result.iter().map(|&v| v.as_u128()).collect::<Vec<_>>(),
                EXPECTED,
            );
        });
    }

    #[test]
    fn semi_honest_with_dp() {
        const SS_BITS: usize = 1;
        // setting SS_BITS this small will cause clipping in capping
        // since per_user_credit_cap == 2^SS_BITS
        semi_honest_with_dp_internal::<SS_BITS>(DpMechanism::DiscreteLaplace { epsilon: 5.0 });
    }
    #[test]
    fn semi_honest_with_dp_slow() {
        const SS_BITS: usize = 6;
        if std::env::var("EXEC_SLOW_TESTS").is_err() {
            return;
        }
        semi_honest_with_dp_internal::<SS_BITS>(DpMechanism::Binomial { epsilon: 10.0 });
    }

    fn semi_honest_with_dp_internal<const SS_BITS: usize>(_dp_mechanism: DpMechanism) {
        // TODO match on DpMechanism but get error if try to move into run
        println!("Running semi_honest_with_dp");
        run(move || async {
            const B: usize = 32; // number of histogram bins
            let expected: Vec<u32> = vec![0, 2, 5, 0, 0, 0, 0, 0];
            let epsilon = 10.0;
            let dp_params = DpMechanism::Binomial { epsilon };
            let per_user_credit_cap = 2_f64.powi(i32::try_from(SS_BITS).unwrap());
            let padding_params = PaddingParameters::relaxed();
            let config = TestWorldConfig::default().with_timeout_secs(60);
            let world = TestWorld::<NotSharded>::with_config(&config);

            let records: Vec<TestRawDataRecord> = vec![
                test_input(0, 12345, false, 1, 0),
                test_input(5, 12345, false, 2, 0),
                test_input(10, 12345, true, 0, 5),
                test_input(0, 68362, false, 1, 0),
                test_input(20, 68362, true, 0, 2),
            ];
            let mut result: Vec<_> = world
                .semi_honest(records.into_iter(), |ctx, input_rows| async move {
                    oprf_ipa::<_, BA5, BA3, BA16, BA20, SS_BITS, B>(
                        ctx,
                        input_rows,
                        None,
                        dp_params,
                        padding_params,
                    )
                    .await
                    .unwrap()
                })
                .await
                .reconstruct();
            result.truncate(expected.len());

            let noise_params = NoiseParams {
                epsilon,
                ell_1_sensitivity: per_user_credit_cap,
                ell_2_sensitivity: per_user_credit_cap,
                ell_infty_sensitivity: per_user_credit_cap,
                dimensions: f64::from(u32::try_from(B).unwrap()),
                ..Default::default()
            };
            let (mean, std) = crate::protocol::dp::binomial_noise_mean_std(&noise_params);
            println!("In semi_honest_with_dp:  mean = {mean}, standard_deviation = {std}");
            let result_u32: Vec<u32> = result
                .iter()
                .map(|&v| u32::try_from(v.as_u128()).unwrap())
                .collect::<Vec<_>>();

            println!(
                "in test: semi_honest_with_dp. len result = {} and expected len =  {}",
                result_u32.len(),
                expected.len()
            );
            assert!(result_u32.len() == expected.len());
            for (index, actual_u128) in result_u32.iter().enumerate() {
                println!("actual = {actual_u128}, expected = {}", expected[index]);
                assert!(
                    f64::from(*actual_u128) - mean
                        > f64::from(expected[index]) - 5.0 * std
                        && f64::from(*actual_u128) - mean
                            < f64::from(expected[index]) + 5.0 * std
                , "DP result was more than 5 standard deviations of the noise from the expected result"
                );
            }
        });
    }

    #[test]
    fn semi_honest_empty() {
        const EXPECTED: &[u128] = &[0, 0, 0, 0, 0, 0, 0, 0];

        run(|| async {
            let world = TestWorld::default();

            let records: Vec<TestRawDataRecord> = vec![];
            let dp_params = DpMechanism::NoDp;
            let padding_params = PaddingParameters::no_padding();

            let mut result: Vec<_> = world
                .semi_honest(records.into_iter(), |ctx, input_rows| async move {
                    oprf_ipa::<_, BA5, BA3, BA8, BA20, 5, 32>(
                        ctx,
                        input_rows,
                        None,
                        dp_params,
                        padding_params,
                    )
                    .await
                    .unwrap()
                })
                .await
                .reconstruct();
            result.truncate(EXPECTED.len());
            assert_eq!(
                result.iter().map(|&v| v.as_u128()).collect::<Vec<_>>(),
                EXPECTED,
            );
        });
    }

    #[test]
    fn semi_honest_degenerate() {
        const EXPECTED: &[u128] = &[0, 0, 0, 0, 0, 0, 0, 0];

        run(|| async {
            let world = TestWorld::default();

            let records: Vec<TestRawDataRecord> = vec![
                test_input(0, 12345, false, 1, 0),
                test_input(0, 68362, false, 1, 0),
            ];
            let dp_params = DpMechanism::NoDp;
            let padding_params = PaddingParameters::no_padding();

            let mut result: Vec<_> = world
                .semi_honest(records.into_iter(), |ctx, input_rows| async move {
                    oprf_ipa::<_, BA5, BA3, BA8, BA20, 5, 32>(
                        ctx,
                        input_rows,
                        None,
                        dp_params,
                        padding_params,
                    )
                    .await
                    .unwrap()
                })
                .await
                .reconstruct();
            result.truncate(EXPECTED.len());
            assert_eq!(
                result.iter().map(|&v| v.as_u128()).collect::<Vec<_>>(),
                EXPECTED,
            );
        });
    }

    // Test that IPA tolerates duplicate timestamps among a user's records. The end-to-end test
    // harness does not generate data like this because the attribution result is non-deterministic.
    // To make the output deterministic for this case, all of the duplicate timestamp records are
    // identical.
    //
    // Don't run this with shuttle because it is slow and is unlikely to provide different coverage
    // than the previous test.
    #[cfg(not(feature = "shuttle"))]
    #[test]
    fn duplicate_timestamps() {
        use rand::{seq::SliceRandom, thread_rng};

        use crate::ff::boolean_array::{BA16, BA8};

        const EXPECTED: &[u128] = &[0, 2, 10, 0, 0, 0, 0, 0];

        run(|| async {
            let world = TestWorld::default();

            let mut records: Vec<TestRawDataRecord> = vec![
                test_input(0, 12345, false, 1, 0),
                test_input(5, 12345, false, 2, 0),
                test_input(5, 12345, false, 2, 0),
                test_input(10, 12345, true, 0, 5),
                test_input(10, 12345, true, 0, 5),
                test_input(0, 68362, false, 1, 0),
                test_input(20, 68362, true, 0, 2),
            ];

            records.shuffle(&mut thread_rng());
            let dp_params = DpMechanism::NoDp;
            let padding_params = PaddingParameters::no_padding();
            let mut result: Vec<_> = world
                .semi_honest(records.into_iter(), |ctx, input_rows| async move {
                    oprf_ipa::<_, BA8, BA3, BA16, BA20, 5, 256>(
                        ctx,
                        input_rows,
                        None,
                        dp_params,
                        padding_params,
                    )
                    .await
                    .unwrap()
                })
                .await
                .reconstruct();
            result.truncate(EXPECTED.len());
            assert_eq!(
                result.iter().map(|&v| v.as_u128()).collect::<Vec<_>>(),
                EXPECTED,
            );
        });
    }
}

#[cfg(all(test, all(compact_gate, feature = "in-memory-infra")))]
mod compact_gate_tests {
    use ipa_step::{CompactStep, StepNarrow};

    use crate::{
        ff::{
            boolean_array::{BA20, BA5, BA8},
            U128Conversions,
        },
        helpers::query::DpMechanism,
        protocol::{
            ipa_prf::{oprf_ipa, oprf_padding::PaddingParameters},
            step::{ProtocolGate, ProtocolStep},
        },
        test_executor::run,
        test_fixture::{ipa::TestRawDataRecord, Reconstruct, Runner, TestWorld, TestWorldConfig},
    };

    #[test]
    fn step_count_limit() {
        // This is an arbitrary limit intended to catch changes that unintentionally
        // blow up the step count. It can be increased, within reason.
        const STEP_COUNT_LIMIT: u32 = 32_500;
        assert!(
            ProtocolStep::STEP_COUNT < STEP_COUNT_LIMIT,
            "Step count of {actual} exceeds limit of {STEP_COUNT_LIMIT}.",
            actual = ProtocolStep::STEP_COUNT,
        );
    }

    #[test]
    fn saturated_agg() {
        const EXPECTED: &[u128] = &[0, 255, 255, 0, 0, 0, 0, 0];

        run(|| async {
            let world = TestWorld::new_with(TestWorldConfig {
                initial_gate: Some(ProtocolGate::default().narrow(&ProtocolStep::IpaPrf)),
                ..Default::default()
            });

            let records: Vec<TestRawDataRecord> = vec![
                TestRawDataRecord {
                    timestamp: 0,
                    user_id: 12345,
                    is_trigger_report: false,
                    breakdown_key: 1,
                    trigger_value: 0,
                },
                TestRawDataRecord {
                    timestamp: 5,
                    user_id: 12345,
                    is_trigger_report: false,
                    breakdown_key: 2,
                    trigger_value: 0,
                },
                TestRawDataRecord {
                    timestamp: 10,
                    user_id: 12345,
                    is_trigger_report: true,
                    breakdown_key: 0,
                    trigger_value: 255,
                },
                TestRawDataRecord {
                    timestamp: 20,
                    user_id: 12345,
                    is_trigger_report: true,
                    breakdown_key: 0,
                    trigger_value: 255,
                },
                TestRawDataRecord {
                    timestamp: 30,
                    user_id: 12345,
                    is_trigger_report: true,
                    breakdown_key: 0,
                    trigger_value: 255,
                },
                TestRawDataRecord {
                    timestamp: 0,
                    user_id: 68362,
                    is_trigger_report: false,
                    breakdown_key: 1,
                    trigger_value: 0,
                },
                TestRawDataRecord {
                    timestamp: 20,
                    user_id: 68362,
                    is_trigger_report: true,
                    breakdown_key: 1,
                    trigger_value: 255,
                },
            ];
            let dp_params = DpMechanism::NoDp;
            let padding_params = PaddingParameters::relaxed();

            let mut result: Vec<_> = world
                .semi_honest(records.into_iter(), |ctx, input_rows| async move {
                    oprf_ipa::<_, BA5, BA8, BA8, BA20, 5, 32>(
                        ctx,
                        input_rows,
                        None,
                        dp_params,
                        padding_params,
                    )
                    .await
                    .unwrap()
                })
                .await
                .reconstruct();
            result.truncate(EXPECTED.len());
            assert_eq!(
                result.iter().map(|&v| v.as_u128()).collect::<Vec<_>>(),
                EXPECTED,
            );
        });
    }
}
