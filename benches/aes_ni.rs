use criterion::{criterion_group, criterion_main, Criterion};
use core::arch::x86_64::{_mm_loadu_si128, __m128i};
use cmp_pot_aes::aes_ni::*;

pub fn criterion_benchmark(c: &mut Criterion) {
    let (keys_enc, _) = expand(&ID);
    let iterations = 1_000_000;
    let block_reg = unsafe { _mm_loadu_si128(SEED.as_ptr() as *const __m128i) };
    let block_asm = unsafe { _mm_loadu_si128(SEED.as_ptr() as *const __m128i) };

    let mut group = c.benchmark_group("AES-NI");
    group.sample_size(10);
    group.bench_function( "pot_prove_low_level",
        |b| b.iter(|| pot_prove_low_level(keys_enc, block_reg, iterations))
    );

    group.bench_function( "pot_prove_low_level_asm",
        |b| b.iter(|| pot_prove_low_level_asm(keys_enc, block_asm, iterations))
    );
}

criterion_group!(benches, criterion_benchmark);
criterion_main!(benches);
