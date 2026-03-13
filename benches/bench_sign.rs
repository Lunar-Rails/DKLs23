#[path = "support/common.rs"]
mod common;

use std::time::Duration;

use criterion::{black_box, criterion_group, criterion_main, Criterion};

fn bench_sign(c: &mut Criterion) {
    let mut group = c.benchmark_group("sign");
    group.sample_size(100);
    group.warm_up_time(Duration::from_secs(3));
    group.measurement_time(Duration::from_secs(4));

    let parties = common::baseline_parties_rekey();
    let message_hash = common::fixed_message_hash();
    let bench_id = common::bench_id();

    group.bench_function(&bench_id, |b| {
        b.iter(|| {
            common::run_sign_once(&parties, black_box(common::SIGN_SID), black_box(message_hash));
        })
    });

    group.finish();
}

criterion_group!(benches, bench_sign);
criterion_main!(benches);
