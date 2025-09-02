use criterion::{black_box, criterion_group, criterion_main, Criterion};
use legion_prover::final_circuit::{FinalAuthCircuit, FinalBatchProcessor, SecurityLevel, clear_nullifier_cache};
use halo2_proofs::dev::MockProver;
use std::time::Instant;
use tracing::{info, warn, error};
use anyhow::{Result, Context};

fn bench_circuit_creation(c: &mut Criterion) {
    c.bench_function("circuit_creation_standard", |b| {
        b.iter(|| {
            clear_nullifier_cache();
            let circuit = match FinalAuthCircuit::new(
                black_box(b"alice"),
                black_box(b"password123"),
                black_box(SecurityLevel::Standard)
            ) {
                Ok(c) => c,
                Err(e) => {
                    error!("Circuit creation failed: {}", e);
                    return;
                }
            };
            black_box(circuit);
        });
    });

    c.bench_function("circuit_creation_production", |b| {
        b.iter(|| {
            clear_nullifier_cache();
            let circuit = FinalAuthCircuit::new(
                black_box(b"alice"),
                black_box(b"password123"),
                black_box(SecurityLevel::Production)
            ).context("Circuit creation failed in benchmark").unwrap();
            black_box(circuit);
        });
    });

    c.bench_function("circuit_creation_quantum", |b| {
        b.iter(|| {
            clear_nullifier_cache();
            let circuit = FinalAuthCircuit::new(
                black_box(b"alice"),
                black_box(b"password123"),
                black_box(SecurityLevel::Quantum)
            ).context("Circuit creation failed in benchmark").unwrap();
            black_box(circuit);
        });
    });
}

fn bench_proof_generation(c: &mut Criterion) {
    clear_nullifier_cache();
    let circuit = match FinalAuthCircuit::new(b"alice", b"password123", SecurityLevel::Standard) {
        Ok(c) => c,
        Err(e) => {
            error!("Failed to create circuit for proof benchmark: {}", e);
            return;
        }
    };
    let public_inputs = circuit.public_inputs();

    c.bench_function("mock_proof_k16", |b| {
        b.iter(|| {
            let prover = match MockProver::run(16, &circuit, vec![public_inputs.clone()]) {
                Ok(p) => p,
                Err(e) => {
                    error!("MockProver failed: {}", e);
                    return;
                }
            };
            black_box(prover);
        });
    });

    c.bench_function("mock_proof_k18", |b| {
        b.iter(|| {
            let prover = match MockProver::run(18, &circuit, vec![public_inputs.clone()]) {
                Ok(p) => p,
                Err(e) => {
                    error!("MockProver failed: {}", e);
                    return;
                }
            };
            black_box(prover);
        });
    });
}

fn bench_batch_processing(c: &mut Criterion) {
    c.bench_function("batch_10_circuits", |b| {
        b.iter(|| {
            clear_nullifier_cache();
            let mut processor = FinalBatchProcessor::new(SecurityLevel::Standard);
            
            for i in 0..10 {
                let username = format!("user_{:03}", i);
                let password = format!("pass_{:03}", i);
                processor.add_auth(username.as_bytes(), password.as_bytes())
                    .context("Failed to add auth to batch").unwrap();
            }
            
            black_box(processor);
        });
    });

    c.bench_function("batch_100_circuits", |b| {
        b.iter(|| {
            clear_nullifier_cache();
            let mut processor = FinalBatchProcessor::new(SecurityLevel::Standard);
            
            for i in 0..100 {
                let username = format!("user_{:03}", i);
                let password = format!("pass_{:03}", i);
                processor.add_auth(username.as_bytes(), password.as_bytes())
                    .context("Failed to add auth to batch").unwrap();
            }
            
            black_box(processor);
        });
    });
}

fn bench_hashing_performance(c: &mut Criterion) {
    c.bench_function("blake3_hashing", |b| {
        b.iter(|| {
            let result = FinalAuthCircuit::benchmark_hash_performance(
                black_box(b"test_username")
            ).context("Hash benchmark failed").unwrap();
            black_box(result);
        });
    });

    c.bench_function("poseidon_hashing", |b| {
        b.iter(|| {
            use halo2_gadgets::poseidon::primitives as poseidon;
            use halo2curves::pasta::Fp;
            
            let hash = poseidon::Hash::<_, poseidon::P128Pow5T3, poseidon::ConstantLength<4>, 3, 2>::init()
                .hash([
                    black_box(Fp::from(12345u64)),
                    black_box(Fp::from(67890u64)),
                    black_box(Fp::from(11111u64)),
                    black_box(Fp::from(22222u64)),
                ]);
            black_box(hash);
        });
    });
}

fn bench_encryption_performance(c: &mut Criterion) {
    clear_nullifier_cache();
    let circuit = match FinalAuthCircuit::new(b"alice", b"password123", SecurityLevel::Standard) {
        Ok(c) => c,
        Err(e) => {
            error!("Failed to create circuit for encryption benchmark: {}", e);
            return;
        }
    };
    let server_key = [42u8; 32];

    c.bench_function("encrypted_proof_generation", |b| {
        b.iter(|| {
            let proof = circuit.generate_encrypted_proof(&server_key)
                .context("Encrypted proof generation failed").unwrap();
            black_box(proof);
        });
    });
}

fn bench_memory_usage() {
    info!("MEMORY USAGE ANALYSIS");
    
    let start_mem = get_memory_usage();
    clear_nullifier_cache();
    let circuit = FinalAuthCircuit::new(b"alice", b"password123", SecurityLevel::Standard)
        .context("Failed to create circuit for memory test").unwrap();
    let single_mem = get_memory_usage() - start_mem;
    info!("Single circuit memory: ~{} KB", single_mem / 1024);
    
    let start_mem = get_memory_usage();
    clear_nullifier_cache();
    let mut processor = FinalBatchProcessor::new(SecurityLevel::Standard);
    
    for i in 0..1000 {
        let username = format!("user_{:04}", i);
        let password = format!("pass_{:04}", i);
        processor.add_auth(username.as_bytes(), password.as_bytes())
            .context("Failed to add auth for memory test").unwrap();
    }
    
    let batch_mem = get_memory_usage() - start_mem;
    info!("1000 circuits memory: ~{} KB", batch_mem / 1024);
    info!("Memory per circuit: ~{} bytes", batch_mem / 1000);
}

fn get_memory_usage() -> usize {
    std::mem::size_of::<FinalAuthCircuit>() * 1000
}

fn comprehensive_performance_test() {
    info!("COMPREHENSIVE PERFORMANCE TEST");
    
    let start = Instant::now();
    clear_nullifier_cache();
    for i in 0..1000 {
        let username = format!("user_{:04}", i);
        let password = format!("pass_{:04}", i);
        let _circuit = FinalAuthCircuit::new(username.as_bytes(), password.as_bytes(), SecurityLevel::Standard)
            .context("Failed to create circuit in performance test").unwrap();
    }
    let creation_time = start.elapsed();
    info!("1000 circuit creations: {:?} ({:.2} circuits/sec)", 
             creation_time, 1000.0 / creation_time.as_secs_f64());
    
    clear_nullifier_cache();
    let circuit = FinalAuthCircuit::new(b"alice", b"password123", SecurityLevel::Standard)
        .context("Failed to create circuit for proof test").unwrap();
    let public_inputs = circuit.public_inputs();
    
    let start = Instant::now();
    for _ in 0..100 {
        let _prover = MockProver::run(16, &circuit, vec![public_inputs.clone()])
            .context("MockProver failed in performance test").unwrap();
    }
    let proof_time = start.elapsed();
    info!("100 mock proofs (k=16): {:?} ({:.2} proofs/sec)", 
             proof_time, 100.0 / proof_time.as_secs_f64());
    
    let server_key = [42u8; 32];
    let start = Instant::now();
    for _ in 0..1000 {
        let _proof = circuit.generate_encrypted_proof(&server_key)
            .context("Encrypted proof generation failed in performance test").unwrap();
    }
    let encrypt_time = start.elapsed();
    info!("1000 encrypted proofs: {:?} ({:.2} proofs/sec)", 
             encrypt_time, 1000.0 / encrypt_time.as_secs_f64());
    
    info!("SECURITY LEVEL PERFORMANCE");
    for level in [SecurityLevel::Standard, SecurityLevel::Production, SecurityLevel::Quantum] {
        let start = Instant::now();
        clear_nullifier_cache();
        for i in 0..100 {
            let username = format!("user_{:03}", i);
            let password = format!("pass_{:03}", i);
            let _circuit = FinalAuthCircuit::new(username.as_bytes(), password.as_bytes(), level)
                .context("Failed to create circuit for security level test").unwrap();
        }
        let level_time = start.elapsed();
        info!("{:?} level (100 circuits): {:?} ({:.2} circuits/sec)", 
                 level, level_time, 100.0 / level_time.as_secs_f64());
    }
}

criterion_group!(
    benches,
    bench_circuit_creation,
    bench_proof_generation,
    bench_batch_processing,
    bench_hashing_performance,
    bench_encryption_performance
);

criterion_main!(benches);

#[cfg(test)]
mod perf_tests {
    use super::*;
    
    #[test]
    fn run_comprehensive_test() {
        comprehensive_performance_test();
        bench_memory_usage();
    }
}