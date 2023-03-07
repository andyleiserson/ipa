#![cfg(all(feature = "shuttle", test))]

use crate::{
    ff::Fp32BitPrime,
    ipa_test_input,
    protocol::{
        ipa::{ipa, ipa_malicious},
        BreakdownKey, MatchKey,
    },
    rand::{thread_rng, Rng},
    test_fixture::{input::GenericReportTestInput, Reconstruct, Runner, TestWorld},
};
use crate::test_fixture::TestWorldConfig;

#[test]
fn semi_honest_ipa() {
    shuttle::check_random(
        || {
            shuttle::future::block_on(async {
                const BATCHSIZE: usize = 5;
                const PER_USER_CAP: u32 = 10;
                const MAX_BREAKDOWN_KEY: u128 = 8;
                const MAX_TRIGGER_VALUE: u128 = 5;
                const NUM_MULTI_BITS: u32 = 3;
                const MAX_MATCH_KEY: u128 = 3;

                let mut config = TestWorldConfig::default();
                config.gateway_config.send_outstanding = 256;
                tracing::info!("another iteration");
                let world = TestWorld::new_with(config).await;
                let mut rng = thread_rng();

                let records = (0..BATCHSIZE)
                    .map(|_| {
                        ipa_test_input!(
                            {
                                    match_key: rng.gen_range(0..MAX_MATCH_KEY),
                                    is_trigger_report: rng.gen::<u32>(),
                                    breakdown_key: rng.gen_range(0..MAX_BREAKDOWN_KEY),
                                    trigger_value: rng.gen_range(0..MAX_TRIGGER_VALUE),
                            };
                            (Fp32BitPrime, MatchKey, BreakdownKey)
                        )
                    })
                    .collect::<Vec<_>>();

                let result: Vec<GenericReportTestInput<Fp32BitPrime, MatchKey, BreakdownKey>> =
                    world
                        .semi_honest(records, |ctx, input_rows| async move {
                            ipa::<Fp32BitPrime, MatchKey, BreakdownKey>(
                                ctx,
                                &input_rows,
                                PER_USER_CAP,
                                MAX_BREAKDOWN_KEY,
                                NUM_MULTI_BITS,
                            )
                            .await
                            .unwrap()
                        })
                        .await
                        .reconstruct();

                assert_eq!(MAX_BREAKDOWN_KEY, result.len() as u128);
            });
        },
        10,
    );
}

#[test]
fn malicious_ipa() {
    shuttle::check_random(
        || {
            shuttle::future::block_on(async {
                const BATCHSIZE: usize = 5;
                const PER_USER_CAP: u32 = 10;
                const MAX_BREAKDOWN_KEY: u128 = 8;
                const MAX_TRIGGER_VALUE: u128 = 5;
                const NUM_MULTI_BITS: u32 = 3;
                const MAX_MATCH_KEY: u128 = 3;

                let world = TestWorld::new().await;
                let mut rng = thread_rng();

                let records = (0..BATCHSIZE)
                    .map(|_| {
                        ipa_test_input!(
                            {
                                    match_key: rng.gen_range(0..MAX_MATCH_KEY),
                                    is_trigger_report: rng.gen::<u32>(),
                                    breakdown_key: rng.gen_range(0..MAX_BREAKDOWN_KEY),
                                    trigger_value: rng.gen_range(0..MAX_TRIGGER_VALUE),
                            };
                            (Fp32BitPrime, MatchKey, BreakdownKey)
                        )
                    })
                    .collect::<Vec<_>>();

                let result: Vec<GenericReportTestInput<Fp32BitPrime, MatchKey, BreakdownKey>> =
                    world
                        .semi_honest(records, |ctx, input_rows| async move {
                            ipa_malicious::<Fp32BitPrime, MatchKey, BreakdownKey>(
                                ctx,
                                &input_rows,
                                PER_USER_CAP,
                                MAX_BREAKDOWN_KEY,
                                NUM_MULTI_BITS,
                            )
                            .await
                            .unwrap()
                        })
                        .await
                        .reconstruct();

                assert_eq!(MAX_BREAKDOWN_KEY, result.len() as u128);
            });
        },
        4,
    );
}
