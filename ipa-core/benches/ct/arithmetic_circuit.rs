use criterion::{
    measurement::Measurement,
    black_box, criterion_group, criterion_main, BenchmarkGroup, BenchmarkId, Criterion, SamplingMode, Throughput,
};
use ipa_core::{
    ff::{Fp31, Fp32BitPrime, Field},
    protocol::{basics::SecureMul, context::SemiHonestContext},
    secret_sharing::{replicated::semi_honest::AdditiveShare as Replicated, FieldSimd, IntoShares},
    test_fixture::circuit,
};
use rand::distributions::{Standard, Distribution};
use tokio::runtime::{Builder, Runtime};

fn do_benchmark<M, F, const N: usize>(rt: &Runtime, group: &mut BenchmarkGroup<M>, width: u32, depth: u16, active_work: usize)
where
    M: Measurement,
    F: Field + FieldSimd<N> + IntoShares<Replicated<F>>,
    for<'a> Replicated<F>: SecureMul<SemiHonestContext<'a>>,
    Standard: Distribution<F>,
{
    group.throughput(Throughput::Elements((width * depth as u32) as u64));
    group.bench_with_input(
        BenchmarkId::new("circuit", format!("{width}:{depth}:{active_work}:{}x{}", F::NAME, N)),
        &(width, depth),
        |b, &(width, depth)| {
            b.to_async(rt)
                .iter(|| circuit::arithmetic::<F, N>(black_box(width), black_box(depth), active_work));
        },
    );
}

pub fn criterion_benchmark(c: &mut Criterion) {
    let rt = Builder::new_multi_thread()
        .worker_threads(3)
        .thread_name("helper-worker")
        .enable_time()
        .build()
        .expect("Creating runtime failed");

    let mut group = c.benchmark_group("arithmetic");
    group.sample_size(10);
    group.sampling_mode(SamplingMode::Flat);

    // The width parameter (2nd-to-last argument to do_benchmark) must
    // be a multiple of the vectorization width.

    // These total 262,144 elements.
    do_benchmark::<_, Fp32BitPrime, 32>(&rt, &mut group, 16_384,    16,    8);
    do_benchmark::<_, Fp32BitPrime, 32>(&rt, &mut group, 16_384,    16,   32);
    do_benchmark::<_, Fp32BitPrime, 32>(&rt, &mut group, 16_384,    16,  128);
    do_benchmark::<_, Fp32BitPrime, 32>(&rt, &mut group, 16_384,    16,  512);
    do_benchmark::<_, Fp32BitPrime, 32>(&rt, &mut group,  2_048,   128,    8);
    do_benchmark::<_, Fp32BitPrime, 32>(&rt, &mut group,  2_048,   128,   32);
    do_benchmark::<_, Fp32BitPrime, 32>(&rt, &mut group,  2_048,   128,  128);
    do_benchmark::<_, Fp32BitPrime, 32>(&rt, &mut group,  2_048,   128,  512);

    // These total 1,048,576 elements.
    do_benchmark::<_, Fp32BitPrime,  32>(&rt, &mut group,  1_024, 1_024,   8);
    do_benchmark::<_, Fp32BitPrime,  32>(&rt, &mut group,  1_024, 1_024,  32);
    do_benchmark::<_, Fp32BitPrime,  32>(&rt, &mut group,  1_024, 1_024, 128);
    do_benchmark::<_, Fp32BitPrime, 256>(&rt, &mut group,  4_096,   256,   8);
    do_benchmark::<_, Fp32BitPrime, 256>(&rt, &mut group,  4_096,   256,  32);
    do_benchmark::<_, Fp32BitPrime, 256>(&rt, &mut group,  4_096,   256, 128);
}

criterion_group!(benches, criterion_benchmark);
criterion_main!(benches);
