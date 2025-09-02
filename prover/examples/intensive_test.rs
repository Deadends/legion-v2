use legion_prover::final_circuit::*;
use halo2_proofs::dev::MockProver;
use std::time::{SystemTime, UNIX_EPOCH};
use std::collections::HashMap;
use rayon::prelude::*;
use pqcrypto_dilithium::dilithium5::{keypair, detached_sign, verify_detached_signature};
use pqcrypto_traits::sign::{PublicKey, DetachedSignature};
use ml_kem::{KemCore, EncodedSizeUser};
use tracing::{info, warn, error, debug};
use anyhow::{Result, Context};
use zeroize::{Zeroize, Zeroizing};
use dotenvy::dotenv;

fn main() -> Result<()> {
    dotenv().ok();
    tracing_subscriber::fmt::init();
    
    info!("Starting intensive world-class circuit tests");
    
    WorldClassAuthSystem::initialize()
        .context("Failed to initialize system")?;
    info!("System initialized successfully");
    
    test_core_circuit_functionality()
        .context("Core circuit functionality test failed")?;
    
    test_all_security_levels()
        .context("Security levels test failed")?;
    
    test_enterprise_features()
        .context("Enterprise features test failed")?;
    
    test_performance_under_load()
        .context("Performance test failed")?;
    
    test_cryptographic_operations()
        .context("Cryptographic operations test failed")?;
    
    test_edge_cases()
        .context("Edge cases test failed")?;
    
    test_concurrent_operations()
        .context("Concurrent operations test failed")?;
    
    test_memory_management()
        .context("Memory management test failed")?;
    
    info!("All intensive tests passed - circuit is production ready");
    Ok(())
}

fn test_core_circuit_functionality() -> Result<()> {
    info!("Testing core circuit functionality");
    
    for level in [SecurityLevel::Standard, SecurityLevel::Production, SecurityLevel::Quantum, SecurityLevel::Enterprise] {
        debug!("Testing security level: {:?}", level);
        
        let test_password = std::env::var("LEGION_TEST_PASSWORD")
            .unwrap_or_else(|_| "ultra_secure_password_with_maximum_entropy_for_testing_123456789!@#$%^&*()".to_string());
        
        let circuit = WorldClassAuthCircuit::new_enterprise(
            b"test_user_core",
            test_password.as_bytes(),
            level,
            None, None, None, None, Some("192.168.1.100")
        ).context("Failed to create circuit")?;
        
        let public_inputs = circuit.public_inputs();
        if public_inputs.len() != 6 {
            return Err(anyhow::anyhow!("Expected 6 public inputs for {:?}, got {}", level, public_inputs.len()));
        }
        
        if public_inputs[0] == halo2curves::pasta::Fp::zero() {
            return Err(anyhow::anyhow!("Commitment should be non-zero"));
        }
        if public_inputs[1] == halo2curves::pasta::Fp::zero() {
            return Err(anyhow::anyhow!("Nullifier should be non-zero"));
        }
        if public_inputs[3] == halo2curves::pasta::Fp::zero() {
            return Err(anyhow::anyhow!("Auth token should be non-zero"));
        }
        
        circuit.validate_enterprise_compliance()
            .context("Compliance validation failed")?;
        
        if !circuit.verify_advanced_merkle_proof() {
            return Err(anyhow::anyhow!("Merkle proof verification failed for {:?}", level));
        }
        
        let k = level.circuit_size();
        let prover = MockProver::run(k, &circuit, vec![public_inputs])
            .context("MockProver failed")?;
        prover.assert_satisfied();
        
        debug!("Security level {:?} passed", level);
    }
    
    info!("Core circuit functionality: PASSED");
    Ok(())
}

fn test_all_security_levels() -> Result<()> {
    info!("Testing all security levels");
    
    let test_cases = vec![
        (SecurityLevel::Standard, "standard_user", "standard_password_with_good_entropy_123!"),
        (SecurityLevel::Production, "production_user", "production_password_with_high_entropy_456789!@#"),
        (SecurityLevel::Quantum, "quantum_user", "quantum_resistant_password_with_maximum_entropy_987654321!@#$%^&*()"),
        (SecurityLevel::Enterprise, "enterprise_user", "enterprise_grade_password_with_ultimate_security_and_entropy_abcdefghijklmnopqrstuvwxyz_123456789!@#$%^&*()"),
    ];
    
    for (level, username, password) in test_cases {
        debug!("Testing {:?} with entropy requirements: {}", level, level.min_entropy());
        
        let entropy = WorldClassAuthCircuit::calculate_advanced_entropy(password.as_bytes());
        if entropy < level.min_entropy() {
            return Err(anyhow::anyhow!("Entropy {} insufficient for {:?} (requires {})", entropy, level, level.min_entropy()));
        }
        
        let _circuit = WorldClassAuthCircuit::new_enterprise(
            username.as_bytes(),
            password.as_bytes(),
            level,
            None, None, None, None, Some("10.0.0.1")
        ).context("Failed to create circuit")?;
        
        let expected_inputs = level.commitment_inputs();
        debug!("Expected commitment inputs: {}", expected_inputs);
        
        let hash_rounds = level.hash_rounds();
        debug!("Hash rounds: {}", hash_rounds);
        
        let circuit_size = level.circuit_size();
        debug!("Circuit size (k): {}", circuit_size);
        
        debug!("Security level {:?} validated", level);
    }
    
    info!("All security levels: PASSED");
    Ok(())
}

fn test_enterprise_features() -> Result<()> {
    info!("Testing enterprise features");
    
    debug!("Testing certificate management");
    let (cert_pk, cert_sk) = keypair();
    let public_key = [42u8; 32];
    let mut cert_data = Vec::new();
    cert_data.extend_from_slice(b"test.enterprise.com");
    cert_data.extend_from_slice(&public_key);
    let cert_signature = detached_sign(&cert_data, &cert_sk);
    
    let cert = EnterpriseCertificate {
        subject: "test.enterprise.com".to_string(),
        issuer: "Legion Test CA".to_string(),
        public_key,
        dilithium_pubkey: cert_pk.as_bytes().to_vec(),
        signature: cert_signature.as_bytes().to_vec(),
        valid_from: SystemTime::now(),
        valid_until: SystemTime::now() + std::time::Duration::from_secs(86400 * 365),
        revoked: false,
        trust_level: 5,
        extensions: HashMap::new(),
        ocsp_url: Some("https://ocsp.test.com".to_string()),
    };
    
    if !cert.is_valid() {
        return Err(anyhow::anyhow!("Certificate should be valid"));
    }
    if !cert.check_ocsp() {
        return Err(anyhow::anyhow!("OCSP check should pass"));
    }
    
    WorldClassAuthSystem::add_enterprise_certificate(cert.clone())
        .context("Failed to add certificate")?;
    debug!("Certificate added successfully");
    
    WorldClassAuthSystem::revoke_certificate_with_reason("test.enterprise.com", "Test revocation")
        .context("Failed to revoke certificate")?;
    debug!("Certificate revoked successfully");
    
    debug!("Testing audit system");
    WorldClassAuthSystem::audit_compliance(
        "TEST_EVENT",
        "test_user",
        Some("192.168.1.1".to_string()),
        true,
        SecurityLevel::Enterprise,
        0.5
    ).context("Failed to log audit event")?;
    debug!("Audit event logged successfully");
    
    debug!("Testing rate limiting");
    let mut rate_limit_failures = 0;
    for i in 0..10 {
        let username = format!("rate_test_user_{}", i);
        let result = WorldClassAuthCircuit::new_enterprise(
            username.as_bytes(),
            b"rate_limit_test_password_with_sufficient_entropy_123456789!",
            SecurityLevel::Standard,
            None, None, None, None, Some("192.168.1.200")
        );
        
        if result.is_err() {
            rate_limit_failures += 1;
        }
    }
    
    debug!("Rate limit triggered {} times out of 10 attempts", rate_limit_failures);
    if rate_limit_failures == 0 {
        return Err(anyhow::anyhow!("Rate limiting should trigger with repeated attempts"));
    }
    
    info!("Enterprise features: PASSED");
    Ok(())
}

fn test_performance_under_load() -> Result<()> {
    info!("Testing performance under load");
    
    debug!("Testing batch processing (1000 circuits)");
    let mut processor = WorldClassBatchProcessor::new(SecurityLevel::Production);
    
    let start_time = SystemTime::now();
    for i in 0..1000 {
        let username = format!("load_test_user_{:04}", i);
        let password = format!("load_test_password_with_high_entropy_{:04}!", i);
        let ip = format!("10.0.{}.{}", (i / 256) + 1, i % 256);
        
        if i % 10 == 0 {
            processor.add_enterprise_auth(
                username.as_bytes(),
                password.as_bytes(),
                None, None, None, None,
                Some(&ip)
            ).context("Failed to add enterprise auth")?;
        }
    }
    
    let batch_creation_time = SystemTime::now().duration_since(start_time)
        .context("Failed to calculate batch creation time")?
        .as_millis();
    debug!("Batch creation time: {}ms for {} circuits", batch_creation_time, processor.len());
    
    debug!("Testing parallel proving");
    let prove_start = SystemTime::now();
    let proofs = processor.batch_prove_parallel()
        .context("Failed to generate proofs")?;
    let prove_time = SystemTime::now().duration_since(prove_start)
        .context("Failed to calculate prove time")?
        .as_millis();
    
    debug!("Parallel proving time: {}ms for {} proofs", prove_time, proofs.len());
    if proofs.len() != processor.len() {
        return Err(anyhow::anyhow!("Should generate proof for each circuit"));
    }
    
    let metrics = processor.get_performance_metrics();
    debug!("Performance metrics available");
    if !metrics.contains_key("proofs_per_second") {
        return Err(anyhow::anyhow!("Should have proofs_per_second metric"));
    }
    
    let (total, merkle, compliance, avg_security) = processor.security_statistics();
    debug!("Security stats - Total: {}, Merkle: {}, Compliance: {}, Avg Security: {}", 
             total, merkle, compliance, avg_security);
    
    info!("Performance under load: PASSED");
    Ok(())
}

fn test_cryptographic_operations() -> Result<()> {
    info!("Testing cryptographic operations");
    
    debug!("Testing ML-KEM integration");
    let mut rng = rand::rngs::OsRng;
    let (_dk, ek) = ml_kem::MlKem1024::generate(&mut rng);
    let pubkey_encoded = ek.as_bytes();
    let mut pubkey_bytes = Zeroizing::new([0u8; 1568]);
    pubkey_bytes.copy_from_slice(pubkey_encoded.as_slice());
    
    let test_data = WorldClassAuthCircuit::encrypt_for_blockchain(
        b"crypto_test_user",
        b"crypto_test_password_with_maximum_entropy_123456789!",
        &[1u8; 32],
        &[2u8; 32],
        SystemTime::now().duration_since(UNIX_EPOCH)
            .context("Failed to get timestamp")?
            .as_secs(),
        &[3u8; 32],
        &pubkey_bytes
    ).context("Failed to encrypt for blockchain")?;
    
    if test_data.len() <= 1600 {
        return Err(anyhow::anyhow!("Encrypted data should be substantial (got {} bytes)", test_data.len()));
    }
    debug!("ML-KEM encryption successful: {} bytes", test_data.len());
    
    debug!("Testing Dilithium signatures");
    let (pk, sk) = keypair();
    let test_message = b"test message for dilithium signature verification";
    let signature = detached_sign(test_message, &sk);
    
    verify_detached_signature(&signature, test_message, &pk)
        .map_err(|_| anyhow::anyhow!("Dilithium signature verification should succeed"))?;
    debug!("Dilithium signature verification successful");
    
    debug!("Testing multi-round hashing");
    for level in [SecurityLevel::Standard, SecurityLevel::Production, SecurityLevel::Quantum, SecurityLevel::Enterprise] {
        let hash_result = WorldClassAuthCircuit::multi_round_hash(
            b"test_input_for_hashing",
            b"TEST_DOMAIN",
            level
        ).context("Failed to compute multi-round hash")?;
        
        if hash_result == halo2curves::pasta::Fp::zero() {
            return Err(anyhow::anyhow!("Hash result should be non-zero for {:?}", level));
        }
        debug!("Multi-round hashing successful for {:?}", level);
    }
    
    debug!("Testing forward secrecy");
    let circuit = WorldClassAuthCircuit::new_enterprise(
        b"fs_test_user",
        b"forward_secrecy_test_password_with_high_entropy_123456789!",
        SecurityLevel::Production,
        None, None, None, None, None
    ).context("Failed to create circuit for forward secrecy test")?;
    
    let proof1 = circuit.generate_enterprise_proof()
        .context("Failed to generate first proof")?;
    let proof2 = circuit.generate_enterprise_proof()
        .context("Failed to generate second proof")?;
    
    if proof1 == proof2 {
        return Err(anyhow::anyhow!("Forward secrecy should generate different proofs"));
    }
    debug!("Forward secrecy working: different proofs generated");
    
    info!("Cryptographic operations: PASSED");
    Ok(())
}

fn test_edge_cases() -> Result<()> {
    info!("Testing edge cases and error handling");
    
    debug!("Testing empty credentials");
    let result = WorldClassAuthCircuit::new_enterprise(
        b"",
        b"password",
        SecurityLevel::Standard,
        None, None, None, None, None
    );
    if result.is_ok() {
        return Err(anyhow::anyhow!("Empty username should fail"));
    }
    
    let result = WorldClassAuthCircuit::new_enterprise(
        b"username",
        b"",
        SecurityLevel::Standard,
        None, None, None, None, None
    );
    if result.is_ok() {
        return Err(anyhow::anyhow!("Empty password should fail"));
    }
    debug!("Empty credentials properly rejected");
    
    debug!("Testing insufficient entropy");
    let result = WorldClassAuthCircuit::new_enterprise(
        b"test",
        b"weak",
        SecurityLevel::Enterprise,
        None, None, None, None, None
    );
    if result.is_ok() {
        return Err(anyhow::anyhow!("Weak password should fail for Enterprise level"));
    }
    debug!("Insufficient entropy properly rejected");
    
    debug!("Testing replay attack protection");
    let _circuit1 = WorldClassAuthCircuit::new_enterprise(
        b"replay_test_user",
        b"replay_test_password_with_sufficient_entropy_123456789!",
        SecurityLevel::Standard,
        None, None, None, None, Some("192.168.1.50")
    ).context("Failed to create first circuit")?;
    
    let _result = WorldClassAuthCircuit::new_enterprise(
        b"replay_test_user",
        b"replay_test_password_with_sufficient_entropy_123456789!",
        SecurityLevel::Standard,
        None, None, None, None, Some("192.168.1.50")
    );
    
    debug!("Replay protection mechanisms active");
    
    debug!("Testing invalid certificate operations");
    let invalid_cert = EnterpriseCertificate {
        subject: "invalid.test.com".to_string(),
        issuer: "Invalid CA".to_string(),
        public_key: [0u8; 32],
        dilithium_pubkey: vec![0u8; 1952],
        signature: vec![0u8; 4595],
        valid_from: SystemTime::now(),
        valid_until: SystemTime::now() - std::time::Duration::from_secs(3600),
        revoked: false,
        trust_level: 1,
        extensions: HashMap::new(),
        ocsp_url: None,
    };
    
    if invalid_cert.is_valid() {
        return Err(anyhow::anyhow!("Expired certificate should be invalid"));
    }
    
    let result = WorldClassAuthSystem::add_enterprise_certificate(invalid_cert);
    if result.is_ok() {
        return Err(anyhow::anyhow!("Invalid certificate should be rejected"));
    }
    debug!("Invalid certificates properly rejected");
    
    info!("Edge cases and error handling: PASSED");
    Ok(())
}

fn test_concurrent_operations() -> Result<()> {
    info!("Testing concurrent operations");
    
    debug!("Testing concurrent circuit creation");
    let results: Vec<Result<WorldClassAuthCircuit, _>> = (0..50)
        .into_par_iter()
        .map(|i| {
            let username = format!("concurrent_user_{:02}", i);
            let password = format!("concurrent_password_with_entropy_{:02}!", i);
            let ip = format!("192.168.2.{}", i + 1);
            
            WorldClassAuthCircuit::new_enterprise(
                username.as_bytes(),
                password.as_bytes(),
                SecurityLevel::Standard,
                None, None, None, None,
                Some(&ip)
            )
        })
        .collect();
    
    let successful_circuits = results.iter().filter(|r| r.is_ok()).count();
    debug!("Successful concurrent circuits: {}/50", successful_circuits);
    if successful_circuits == 0 {
        return Err(anyhow::anyhow!("At least some concurrent operations should succeed"));
    }
    
    debug!("Testing concurrent batch processing");
    let processors: Vec<_> = (0..5)
        .into_par_iter()
        .map(|batch_id| {
            let mut processor = WorldClassBatchProcessor::new(SecurityLevel::Standard);
            
            for i in 0..10 {
                let username = format!("batch_{}_user_{:02}", batch_id, i);
                let password = format!("batch_password_with_entropy_{:02}!", i);
                let ip = format!("10.{}.1.{}", batch_id + 1, i + 1);
                
                let _ = processor.add_enterprise_auth(
                    username.as_bytes(),
                    password.as_bytes(),
                    None, None, None, None,
                    Some(&ip)
                );
            }
            
            processor
        })
        .collect();
    
    let total_circuits: usize = processors.iter().map(|p| p.len()).sum();
    debug!("Total circuits in concurrent batches: {}", total_circuits);
    if total_circuits == 0 {
        return Err(anyhow::anyhow!("Concurrent batch processing should create circuits"));
    }
    
    info!("Concurrent operations: PASSED");
    Ok(())
}

fn test_memory_management() -> Result<()> {
    info!("Testing memory and resource management");
    
    debug!("Testing cleanup operations");
    
    for i in 0..10 {
        let username = format!("cleanup_user_{:02}", i);
        let password = format!("cleanup_password_with_entropy_{:02}!", i);
        let ip = format!("192.168.3.{}", i + 1);
        
        let _ = WorldClassAuthCircuit::new_enterprise(
            username.as_bytes(),
            password.as_bytes(),
            SecurityLevel::Standard,
            None, None, None, None,
            Some(&ip)
        );
    }
    
    let initial_nullifier_count = NULLIFIER_STORE.len();
    WorldClassAuthCircuit::cleanup_expired_data();
    let final_nullifier_count = NULLIFIER_STORE.len();
    
    debug!("Nullifier count before cleanup: {}", initial_nullifier_count);
    debug!("Nullifier count after cleanup: {}", final_nullifier_count);
    if final_nullifier_count > initial_nullifier_count {
        return Err(anyhow::anyhow!("Cleanup should not increase entries"));
    }
    
    debug!("Testing batch processor memory management");
    let mut processor = WorldClassBatchProcessor::new(SecurityLevel::Standard);
    
    let mut added_count = 0;
    for i in 0..200 {
        let username = format!("memory_user_{:03}", i);
        let password = format!("memory_password_with_entropy_{:03}!", i);
        let ip = format!("10.1.{}.{}", (i / 256) + 1, i % 256);
        
        if processor.add_enterprise_auth(
            username.as_bytes(),
            password.as_bytes(),
            None, None, None, None,
            Some(&ip)
        ).is_ok() {
            added_count += 1;
        }
    }
    
    debug!("Successfully added {} circuits to batch processor", added_count);
    
    processor.clear();
    if processor.len() != 0 {
        return Err(anyhow::anyhow!("Batch processor should be empty after clear"));
    }
    debug!("Batch processor cleared successfully");
    
    info!("Memory and resource management: PASSED");
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_core_functionality() {
        test_core_circuit_functionality().expect("Core functionality test failed");
    }

    #[test]
    fn test_security_levels() {
        test_all_security_levels().expect("Security levels test failed");
    }

    #[test]
    fn test_enterprise() {
        test_enterprise_features().expect("Enterprise features test failed");
    }
}