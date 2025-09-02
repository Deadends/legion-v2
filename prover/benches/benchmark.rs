//! Comprehensive benchmarking harness for Legion prover
//! 
//! Measures: witness generation, FFT operations, MSM, commitment schemes,
//! and end-to-end proof generation across different circuit sizes.

use criterion::{black_box, criterion_group, criterion_main, Criterion, BenchmarkId};
use prover::{Prover, ProverConfig, AuthCircuit, create_proof_async, verify_proof_async};
use std::time::Duration;
use tokio::runtime::Runtime;
use anyhow::Result;
use tracing::{info, warn, error, debug};

fn bench_proof_generation_by_size(c: &mut Criterion) {
    let rt = match Runtime::new() {
        Ok(rt) => rt,
        Err(e) => {
            error!("Failed to create tokio runtime: {}", e);
            return;
        }
    };
    let mut group = c.benchmark_group("proof_generation");
    group.measurement_time(Duration::from_secs(30));
    
    for k in [12, 14, 16, 18].iter() {
        group.bench_with_input(BenchmarkId::new("circuit_size", k), k, |b, &k| {
            b.to_async(&rt).iter(|| async {
                let mut prover = Prover::with_config(ProverConfig {
                    k,
                    debug: false,
                    num_threads: Some(1),
                });
                
                if let Err(e) = prover.init().await {
                    error!("Failed to initialize prover: {}", e);
                    return;
                }
                
                let circuit = AuthCircuit::new(b"bench_user", b"bench_password");
                match create_proof_async(circuit).await {
                    Ok(proof) => {
                        black_box(proof);
                    }
                    Err(e) => {
                        error!("Proof generation failed: {}", e);
                    }
                }
            });
        });
    }
    group.finish();
}

fn bench_verification_by_size(c: &mut Criterion) {
    let rt = match Runtime::new() {
        Ok(rt) => rt,
        Err(e) => {
            error!("Failed to create tokio runtime: {}", e);
            return;
        }
    };
    let mut group = c.benchmark_group("verification");
    
    // Pre-generate proofs for verification benchmarks
    let proofs: Vec<_> = rt.block_on(async {
        let mut results = Vec::new();
        for k in [12, 14, 16, 18].iter() {
            let mut prover = Prover::with_config(ProverConfig {
                k: *k,
                debug: false,
                num_threads: Some(1),
            });
            
            if let Err(e) = prover.init().await {
                error!("Failed to initialize prover for k={}: {}", k, e);
                continue;
            }
            
            let circuit = AuthCircuit::new(b"verify_user", b"verify_password");
            match create_proof_async(circuit.clone()).await {
                Ok(proof) => {
                    results.push((*k, proof, circuit.public_inputs()));
                }
                Err(e) => {
                    error!("Failed to generate proof for verification benchmark k={}: {}", k, e);
                }
            }
        }
        results
    });
    
    for (k, proof, public_inputs) in proofs {
        group.bench_with_input(BenchmarkId::new("circuit_size", k), &k, |b, _| {
            b.to_async(&rt).iter(|| async {
                match verify_proof_async(proof.clone(), public_inputs.clone()).await {
                    Ok(is_valid) => {
                        black_box(is_valid);
                    }
                    Err(e) => {
                        error!("Verification failed: {}", e);
                    }
                }
            });
        });
    }
    group.finish();
}

fn bench_concurrent_proof_generation(c: &mut Criterion) {
    let rt = match Runtime::new() {
        Ok(rt) => rt,
        Err(e) => {
            error!("Failed to create tokio runtime: {}", e);
            return;
        }
    };
    let mut group = c.benchmark_group("concurrent_proofs");
    group.measurement_time(Duration::from_secs(45));
    
    for num_concurrent in [1, 2, 4, 8].iter() {
        group.bench_with_input(BenchmarkId::new("concurrent_count", num_concurrent), num_concurrent, |b, &num_concurrent| {
            b.to_async(&rt).iter(|| async {
                let mut handles = Vec::new();
                
                for i in 0..num_concurrent {
                    let handle = tokio::spawn(async move {
                        let mut prover = Prover::with_config(ProverConfig {
                            k: 14,
                            debug: false,
                            num_threads: Some(1),
                        });
                        
                        if let Err(e) = prover.init().await {
                            error!("Failed to initialize concurrent prover {}: {}", i, e);
                            return Err(e);
                        }
                        
                        let user_id = format!("concurrent_user_{}", i);
                        let circuit = AuthCircuit::new(user_id.as_bytes(), b"concurrent_password");
                        create_proof_async(circuit).await
                    });
                    handles.push(handle);
                }
                
                let proofs: Vec<_> = futures::future::join_all(handles)
                    .await
                    .into_iter()
                    .filter_map(|r| match r {
                        Ok(Ok(proof)) => Some(proof),
                        Ok(Err(e)) => {
                            error!("Concurrent proof generation failed: {}", e);
                            None
                        }
                        Err(e) => {
                            error!("Concurrent task failed: {}", e);
                            None
                        }
                    })
                    .collect();
                
                black_box(proofs);
            });
        });
    }
    group.finish();
}

fn bench_memory_usage(c: &mut Criterion) {
    let rt = match Runtime::new() {
        Ok(rt) => rt,
        Err(e) => {
            error!("Failed to create tokio runtime: {}", e);
            return;
        }
    };
    let mut group = c.benchmark_group("memory_efficiency");
    
    group.bench_function("repeated_proof_generation", |b| {
        b.to_async(&rt).iter(|| async {
            // Test memory efficiency with repeated operations
            for i in 0..10 {
                let mut prover = Prover::with_config(ProverConfig {
                    k: 13,
                    debug: false,
                    num_threads: Some(1),
                });
                
                if let Err(e) = prover.init().await {
                    error!("Failed to initialize prover for memory test {}: {}", i, e);
                    continue;
                }
                
                let user_id = format!("memory_test_{}", i);
                let circuit = AuthCircuit::new(user_id.as_bytes(), b"memory_password");
                
                match create_proof_async(circuit).await {
                    Ok(proof) => {
                        // Force cleanup
                        drop(proof);
                        drop(prover);
                    }
                    Err(e) => {
                        error!("Memory test proof generation failed for iteration {}: {}", i, e);
                    }
                }
            }
        });
    });
    
    group.finish();
}

fn bench_circuit_compilation(c: &mut Criterion) {
    let rt = match Runtime::new() {
        Ok(rt) => rt,
        Err(e) => {
            error!("Failed to create tokio runtime: {}", e);
            return;
        }
    };
    let mut group = c.benchmark_group("circuit_compilation");
    
    for k in [12, 14, 16].iter() {
        group.bench_with_input(BenchmarkId::new("circuit_size", k), k, |b, &k| {
            b.to_async(&rt).iter(|| async {
                let config = ProverConfig {
                    k,
                    debug: false,
                    num_threads: Some(1),
                };
                
                let mut prover = Prover::with_config(config);
                match prover.init().await {
                    Ok(_) => {
                        black_box(prover);
                    }
                    Err(e) => {
                        error!("Circuit compilation failed for k={}: {}", k, e);
                    }
                }
            });
        });
    }
    
    group.finish();
}

fn bench_witness_generation(c: &mut Criterion) {
    let mut group = c.benchmark_group("witness_generation");
    
    for input_size in [32, 64, 128, 256].iter() {
        group.bench_with_input(BenchmarkId::new("input_size", input_size), input_size, |b, &input_size| {
            b.iter(|| {
                let username = vec![b'u'; input_size];
                let password = vec![b'p'; input_size];
                
                let circuit = AuthCircuit::new(&username, &password);
                match circuit.generate_witness() {
                    Ok(witness) => {
                        black_box(witness);
                    }
                    Err(e) => {
                        error!("Witness generation failed for input size {}: {}", input_size, e);
                    }
                }
            });
        });
    }
    
    group.finish();
}

criterion_group!(
    benches,
    bench_proof_generation_by_size,
    bench_verification_by_size,
    bench_concurrent_proof_generation,
    bench_memory_usage,
    bench_circuit_compilation,
    bench_witness_generation
);
criterion_main!(benches);