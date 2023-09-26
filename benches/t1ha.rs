#[macro_use]
extern crate lazy_static;
#[macro_use]
extern crate criterion;

use std::mem;
use std::slice;

use criterion::{black_box, Criterion, ParameterizedBenchmark, Throughput};

use t1ha::{t1ha0_32, t1ha1, t1ha2_atonce, t1ha2_atonce128, T1ha2Hasher};

#[cfg(target_feature = "avx2")]
use t1ha::t1ha0_ia32aes_avx2;
#[cfg(not(target_feature = "avx2"))]
fn t1ha0_ia32aes_avx2(_data: &[u8], _seed: u64) -> u64 {
    0
}

#[cfg(target_feature = "avx")]
use t1ha::t1ha0_ia32aes_avx;
#[cfg(not(target_feature = "avx"))]
fn t1ha0_ia32aes_avx(_data: &[u8], _seed: u64) -> u64 {
    0
}

const KB: usize = 1024;
const SEED: u64 = 0x0123456789ABCDEF;
const PARAMS: [usize; 7] = [4, 16, 64, 256, KB, 4 * KB, 4 * 4 * KB];

fn get_aligned_data() -> &'static [u8] {

    use std::alloc::{alloc, dealloc, Layout};
    use rand::Rng;

    let mut rng = rand::thread_rng();

    // Allocate 32-bytes-aligned
    let layout = Layout::from_size_align(100000, 32).unwrap();
    let ptr = unsafe { alloc(layout) };
    let slice: &mut [u8] = unsafe { slice::from_raw_parts_mut(ptr, 100000) };

    // Fill with random bytes
    rng.fill(slice);

    slice
}

fn bench_t1ha(c: &mut Criterion) {
    // c.bench(
    //     "memory",
    //     ParameterizedBenchmark::new(
    //         "sum",
    //         move |b, &&size| {
    //             let s = unsafe {
    //                 slice::from_raw_parts(DATA.as_ptr() as *mut u32, size / mem::size_of::<u32>())
    //             };

    //             b.iter(|| {
    //                 black_box(s.iter().fold(0u64, |acc, &x| acc + x as u64));
    //             })
    //         },
    //         &PARAMS,
    //     )
    //     .throughput(|&&size| Throughput::Bytes(size as u32)),
    // )
    
    let data = get_aligned_data();

    let mut bench = ParameterizedBenchmark::new(
        "t1ha0_32",
        move |b, &&size| {
            b.iter(|| t1ha0_32(&data[..size], SEED));
        },
        &PARAMS,
    );

    if cfg!(target_feature = "avx") {
        bench = bench.with_function("t1ha0_ia32aes_avx", move |b, &&size| {
            b.iter(|| t1ha0_ia32aes_avx(&data[..size], SEED));
        });
    }
    if cfg!(target_feature = "avx2") {
        bench = bench.with_function("t1ha0_ia32aes_avx2", move |b, &&size| {
            b.iter(|| t1ha0_ia32aes_avx2(&data[..size], SEED));
        });
    }

    c.bench(
        "t1ha0",
        bench.throughput(|&&size| Throughput::Bytes(size as u32)),
    );

    // c.bench(
    //     "t1ha1",
    //     ParameterizedBenchmark::new(
    //         "t1ha1",
    //         move |b, &&size| {
    //             b.iter(|| t1ha1(&DATA[..size], SEED));
    //         },
    //         &PARAMS,
    //     )
    //     .throughput(|&&size| Throughput::Bytes(size as u32)),
    // );

    // c.bench(
    //     "t1ha2",
    //     ParameterizedBenchmark::new(
    //         "t1ha2_atonce",
    //         move |b, &&size| {
    //             b.iter(|| t1ha2_atonce(&DATA[..size], SEED));
    //         },
    //         &PARAMS,
    //     )
    //     .with_function("t1ha2_atonce128", move |b, &&size| {
    //         b.iter(|| t1ha2_atonce128(&DATA[..size], SEED));
    //     })
    //     .with_function("t1ha2_stream", move |b, &&size| {
    //         b.iter(|| {
    //             let mut h = T1ha2Hasher::with_seeds(SEED, SEED);
    //             h.update(&DATA[..size]);
    //             h.finish()
    //         });
    //     })
    //     .with_function("t1ha2_stream128", move |b, &&size| {
    //         b.iter(|| {
    //             let mut h = T1ha2Hasher::with_seeds(SEED, SEED);
    //             h.update(&DATA[..size]);
    //             h.finish128() as u64
    //         });
    //     })
    //     .throughput(|&&size| Throughput::Bytes(size as u32)),
    // );
}

criterion_group!(benches, bench_t1ha);
criterion_main!(benches);
