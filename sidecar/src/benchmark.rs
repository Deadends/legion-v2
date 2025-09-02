use std::time::{Duration, Instant};
use crate::*;
use tracing::{info, warn, error, debug};
use anyhow::{Result, Context};

pub fn benchmark_crypto_operations() -> Result<()> {
    info!("LEGION Circuit Performance Benchmark");
    
    benchmark_ed25519_signatures()?;
    benchmark_aead_operations()?;
    benchmark_key_derivation()?;
    benchmark_master_key_derivation()?;

    Ok(())
}

fn benchmark_ed25519_signatures() -> Result<()> {
    info!("Ed25519 Signature Performance");
    
    let keys = SecureEd25519Keys::generate()
        .context("Failed to generate Ed25519 keys")?;
    let message = b"LEGION benchmark message for signature testing";
    
    for _ in 0..100 {
        let _ = keys.sign(message)?;
    }
    
    let iterations = 10000;
    let start = Instant::now();
    
    for _ in 0..iterations {
        let _ = keys.sign(message)?;
    }
    
    let sign_duration = start.elapsed();
    let signs_per_sec = (iterations as f64) / sign_duration.as_secs_f64();
    
    let signature = keys.sign(message)?;
    let start = Instant::now();
    
    for _ in 0..iterations {
        let _ = keys.verify(message, &signature)?;
    }
    
    let verify_duration = start.elapsed();
    let verifies_per_sec = (iterations as f64) / verify_duration.as_secs_f64();
    
    info!("Signatures/sec: {:.0}", signs_per_sec);
    info!("Verifications/sec: {:.0}", verifies_per_sec);
    info!("Signature size: {} bytes", signature.len());
    
    Ok(())
}

fn benchmark_aead_operations() -> Result<()> {
    info!("AEAD Encryption Performance");
    
    let key = [1u8; 32];
    let nonce = [2u8; 24];
    let plaintext = vec![0u8; 1024];
    let aad = b"benchmark_aad";
    
    for _ in 0..100 {
        let _ = aead_encrypt(&key, &nonce, aad, &plaintext)?;
    }
    
    let iterations = 10000;
    let start = Instant::now();
    
    for _ in 0..iterations {
        let _ = aead_encrypt(&key, &nonce, aad, &plaintext)?;
    }
    
    let encrypt_duration = start.elapsed();
    let encrypts_per_sec = (iterations as f64) / encrypt_duration.as_secs_f64();
    let mb_per_sec = (encrypts_per_sec * plaintext.len() as f64) / (1024.0 * 1024.0);
    
    let ciphertext = aead_encrypt(&key, &nonce, aad, &plaintext)?;
    let start = Instant::now();
    
    for _ in 0..iterations {
        let _ = aead_decrypt(&key, &nonce, aad, &ciphertext)?;
    }
    
    let decrypt_duration = start.elapsed();
    let decrypts_per_sec = (iterations as f64) / decrypt_duration.as_secs_f64();
    let decrypt_mb_per_sec = (decrypts_per_sec * plaintext.len() as f64) / (1024.0 * 1024.0);
    
    info!("Encryptions/sec: {:.0}", encrypts_per_sec);
    info!("Encryption MB/s: {:.1}", mb_per_sec);
    info!("Decryptions/sec: {:.0}", decrypts_per_sec);
    info!("Decryption MB/s: {:.1}", decrypt_mb_per_sec);
    info!("Ciphertext overhead: {} bytes", ciphertext.len() - plaintext.len());
    
    Ok(())
}

fn benchmark_key_derivation() -> Result<()> {
    info!("Key Derivation Performance");
    
    let shared_secret = [3u8; 32];
    let salt = [4u8; 32];
    let session_id = "benchmark_session";
    
    for _ in 0..100 {
        let _ = derive_keys(&shared_secret, &salt, session_id)?;
    }
    
    let iterations = 10000;
    let start = Instant::now();
    
    for _ in 0..iterations {
        let _ = derive_keys(&shared_secret, &salt, session_id)?;
    }
    
    let duration = start.elapsed();
    let derivations_per_sec = (iterations as f64) / duration.as_secs_f64();
    
    info!("Key derivations/sec: {:.0}", derivations_per_sec);
    info!("Avg derivation time: {:.2}μs", duration.as_micros() as f64 / iterations as f64);
    
    Ok(())
}

fn benchmark_master_key_derivation() -> Result<()> {
    info!("Master Key Derivation Performance");
    
    for _ in 0..10 {
        let _ = StableMasterKey::derive()?;
    }
    
    let iterations = 1000;
    let start = Instant::now();
    
    for _ in 0..iterations {
        let _ = StableMasterKey::derive()?;
    }
    
    let duration = start.elapsed();
    let derivations_per_sec = (iterations as f64) / duration.as_secs_f64();
    
    info!("Master key derivations/sec: {:.0}", derivations_per_sec);
    info!("Avg derivation time: {:.2}ms", duration.as_millis() as f64 / iterations as f64);
    
    let key1 = StableMasterKey::derive()?;
    let key2 = StableMasterKey::derive()?;
    info!("Key stability: {}", if key1.as_bytes() == key2.as_bytes() { "STABLE" } else { "UNSTABLE" });
    
    Ok(())
}

pub fn benchmark_memory_usage() -> Result<()> {
    info!("Memory Usage Analysis");
    
    let ed25519_keys = SecureEd25519Keys::generate()
        .context("Failed to generate keys for memory analysis")?;
    let signature = ed25519_keys.sign(b"test")?;
    let master_key = StableMasterKey::derive()?;
    
    info!("Ed25519 private key: 32 bytes");
    info!("Ed25519 public key: 32 bytes");
    info!("Ed25519 signature: {} bytes", signature.len());
    info!("Master key: {} bytes", master_key.as_bytes().len());
    info!("AEAD nonce: 24 bytes");
    info!("AEAD tag overhead: 16 bytes");
    
    Ok(())
}

pub fn stress_test_operations() -> Result<()> {
    info!("Stress Test - 1 Million Operations");
    
    let keys = SecureEd25519Keys::generate()
        .context("Failed to generate keys for stress test")?;
    let message = b"stress test message";
    let iterations = 1_000_000;
    
    let start = Instant::now();
    
    for i in 0..iterations {
        let signature = keys.sign(message)?;
        let valid = keys.verify(message, &signature)?;
        
        if !valid {
            return Err(anyhow::anyhow!("Signature verification failed at iteration {}", i));
        }
        
        if i % 100_000 == 0 {
            info!("Completed {} operations", i);
        }
    }
    
    let duration = start.elapsed();
    let ops_per_sec = (iterations as f64) / duration.as_secs_f64();
    
    info!("Total operations: {}", iterations);
    info!("Total time: {:.2}s", duration.as_secs_f64());
    info!("Operations/sec: {:.0}", ops_per_sec);
    info!("Result: ALL OPERATIONS SUCCESSFUL");
    
    Ok(())
}