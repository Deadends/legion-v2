use legion_sidecar::*;
use std::time::Instant;
use anyhow::Result;
use tracing::{info, warn, error};
use dotenvy::dotenv;

fn main() -> Result<()> {
    // Initialize environment and logging
    dotenv().ok();
    tracing_subscriber::fmt::init();
    
    info!("🔬 LEGION REAL PERFORMANCE TEST");
    info!("===============================");
    
    // Test actual ZK proof generation speed
    info!("📊 P0: ZK PROOF GENERATION BENCHMARK");
    let start = Instant::now();
    let mut protocol = LegionProtocol::new()?;
    
    let mut successful_auths = 0;
    let test_duration = std::time::Duration::from_secs(5);
    let benchmark_start = Instant::now();
    
    while benchmark_start.elapsed() < test_duration {
        match protocol.authenticate("alice", "password123") {
            Ok(_) => successful_auths += 1,
            Err(e) => warn!("Auth failed: {}", e),
        }
    }
    
    let elapsed = benchmark_start.elapsed();
    let proofs_per_sec = successful_auths as f64 / elapsed.as_secs_f64();
    
    info!("   Duration: {:.2}s", elapsed.as_secs_f64());
    info!("   Successful authentications: {}", successful_auths);
    info!("   ACTUAL PERFORMANCE: {:.0} proofs/second", proofs_per_sec);
    
    // Test encryption/decryption speed
    info!("📊 P1: ENCRYPTION BENCHMARK");
    let session_id = protocol.authenticate("alice", "password123")?;
    let message = b"Hello Legion Protocol - Performance Test Message";
    
    let encrypt_start = Instant::now();
    let mut encryptions = 0;
    
    while encrypt_start.elapsed() < std::time::Duration::from_secs(1) {
        let _encrypted = protocol.encrypt_message(&session_id, message)?;
        encryptions += 1;
    }
    
    let encrypt_elapsed = encrypt_start.elapsed();
    let encryptions_per_sec = encryptions as f64 / encrypt_elapsed.as_secs_f64();
    
    info!("   Encryptions in 1s: {}", encryptions);
    info!("   Encryption speed: {:.0} messages/second", encryptions_per_sec);
    
    // Test memory operations
    info!("📊 P3: MEMORY OPERATIONS BENCHMARK");
    let mem_start = Instant::now();
    let mut memory_ops = 0;
    
    while mem_start.elapsed() < std::time::Duration::from_secs(1) {
        let mut secure_mem = SecureKey::new(b"test_key_material_for_benchmarking")?;
        secure_mem.zeroize();
        memory_ops += 1;
    }
    
    let mem_elapsed = mem_start.elapsed();
    let mem_ops_per_sec = memory_ops as f64 / mem_elapsed.as_secs_f64();
    
    info!("   Memory operations in 1s: {}", memory_ops);
    info!("   Memory ops speed: {:.0} operations/second", mem_ops_per_sec);
    
    info!("🎯 REAL PERFORMANCE SUMMARY");
    info!("   ZK Authentication: {:.0} proofs/sec", proofs_per_sec);
    info!("   Record Encryption: {:.0} msgs/sec", encryptions_per_sec);
    info!("   Memory Operations: {:.0} ops/sec", mem_ops_per_sec);
    
    Ok(())
}