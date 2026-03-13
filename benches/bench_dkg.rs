#[path = "support/common.rs"]
mod common;

use std::time::Duration;

use criterion::{black_box, criterion_group, criterion_main, Criterion};

fn bench_dkg(c: &mut Criterion) {
    let mut group = c.benchmark_group("dkg");
    group.sample_size(10);
    group.warm_up_time(Duration::from_secs(5));
    // DKG is expensive; allocate enough time so Criterion can collect all samples.
    group.measurement_time(Duration::from_secs(45));

    let bench_id = common::bench_id();

    group.bench_function(&bench_id, |b| {
        b.iter(|| {
            let parties = common::run_dkg_once();
            black_box(parties);
        })
    });

    group.finish();
}

criterion_group!(benches, bench_dkg);
criterion_main!(benches);
