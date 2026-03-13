#[path = "support/common.rs"]
mod common;

use std::time::Duration;

use criterion::{black_box, criterion_group, criterion_main, Criterion};

fn bench_refresh(c: &mut Criterion) {
    let mut group = c.benchmark_group("refresh_complete");
    group.sample_size(10);
    group.warm_up_time(Duration::from_secs(5));
    group.measurement_time(Duration::from_secs(20));

    let parties = common::baseline_parties_rekey();
    let bench_id = common::bench_id();

    group.bench_function(&bench_id, |b| {
        b.iter(|| {
            let refreshed = common::run_refresh_complete_once(&parties);
            black_box(refreshed);
        })
    });

    group.finish();
}

criterion_group!(benches, bench_refresh);
criterion_main!(benches);
