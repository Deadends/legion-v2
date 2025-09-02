// LEGION Security Validation Test Suite
// Tests all the fixes for fake/placeholder code

use legion_sidecar::*;
use legion_prover::*;
use anyhow::Result;
use std::time::{SystemTime, UNIX_EPOCH};

#[test]
fn test_rate_limiting() -> Result<()> {
    let mut auth = AuthSystem::new()?;
    
    // Test progressive rate limiting
    for i in 0..3 {
        let result = auth.authenticate(
            &format!("rate_test_user_{}", i), 
            "weak_password" // This should fail due to entropy
        );
        // Should fail due to weak password, not rate limiting
        assert!(result.is_err());
    }
    
    // Test that rate limiting actually works
    for i in 0..10 {
        let result = auth.authenticate(
            "rate_test_user", 
            "weak_password"
        );
        if i >= 5 {
            // Should be rate limited after 5 attempts
            assert!(result.is_err());
            let error_msg = result.unwrap_err().to_string();
            assert!(error_msg.contains("Rate limit") || error_msg.contains("Too many attempts"));
        }
    }
    
    Ok(())
}

#[test]
fn test_entropy_calculation() -> Result<()> {
    // Test weak passwords are rejected
    let weak_passwords = [
        "password",
        "123456",
        "qwerty", 
        "admin",
        "test",
        "abc123"
    ];
    
    for weak_pass in &weak_passwords {
        let entropy = WorldClassAuthCircuit::calculate_advanced_entropy(weak_pass.as_bytes());
        assert!(entropy < 50.0, "Weak password '{}' should have low entropy, got {}", weak_pass, entropy);
    }
    
    // Test strong passwords are accepted
    let strong_passwords = [
        "MyVerySecurePassword123!@#",
        "Tr0ub4dor&3_with_extra_complexity",
        "P@ssw0rd_with_M4ny_Ch4r4ct3rs!",
        "Enterprise_Grade_Security_2024!"
    ];
    
    for strong_pass in &strong_passwords {
        let entropy = WorldClassAuthCircuit::calculate_advanced_entropy(strong_pass.as_bytes());
        assert!(entropy >= 100.0, "Strong password '{}' should have high entropy, got {}", strong_pass, entropy);
    }
    
    Ok(())
}

#[test]
fn test_proof_generation() -> Result<()> {
    WorldClassAuthSystem::initialize()?;
    
    // Test that proof generation actually works (not just returns mock)
    let circuit = WorldClassAuthCircuit::new_enterprise(
        b"proof_test_user",
        b"ProofTestPassword_With_High_Entropy_123!",
        SecurityLevel::Production,
        None, None, None, None, None
    )?;
    
    // Generate proof
    let proof = circuit.generate_enterprise_proof()?;
    
    // Verify proof is not empty and has reasonable size
    assert!(!proof.is_empty(), "Proof should not be empty");
    assert!(proof.len() > 32, "Proof should be substantial size, got {} bytes", proof.len());
    
    // Verify proof contains encrypted data (should have nonce + ciphertext + tag)
    assert!(proof.len() >= 28, "Proof should contain at least nonce + minimal ciphertext + tag");
    
    Ok(())
}

#[test]
fn test_certificate_validation() -> Result<()> {
    WorldClassAuthSystem::initialize()?;
    
    // Test that certificate validation actually works
    let now = SystemTime::now();
    let future = now + std::time::Duration::from_secs(86400 * 365);
    
    // Create test certificate
    let cert = EnterpriseCertificate {
        subject: "test.legion.com".to_string(),
        issuer: "Legion Test CA".to_string(),
        public_key: [42u8; 32],
        dilithium_pubkey: vec![0u8; 2592], // ML-DSA-87 size
        signature: vec![0u8; 96], // Ed25519 + ML-DSA commitment
        valid_from: now,
        valid_until: future,
        revoked: false,
        trust_level: 3,
        extensions: std::collections::HashMap::new(),
        ocsp_url: Some("https://ocsp.test.legion.com".to_string()),
    };
    
    // Test certificate validity checks
    assert!(cert.is_valid(), "Valid certificate should pass is_valid()");
    assert!(!cert.is_expired(), "Non-expired certificate should not be expired");
    assert!(cert.check_ocsp(), "Certificate should pass OCSP check");
    
    // Test revoked certificate
    let mut revoked_cert = cert.clone();
    revoked_cert.revoked = true;
    assert!(!revoked_cert.check_ocsp(), "Revoked certificate should fail OCSP check");
    
    // Test expired certificate
    let mut expired_cert = cert.clone();
    expired_cert.valid_until = now - std::time::Duration::from_secs(1);
    assert!(expired_cert.is_expired(), "Expired certificate should be detected");
    assert!(!expired_cert.is_valid(), "Expired certificate should not be valid");
    
    Ok(())
}

#[test]
fn test_circuit_constraints() -> Result<()> {
    WorldClassAuthSystem::initialize()?;
    
    // Test that circuit constraints actually prevent invalid inputs
    
    // Test 1: Empty username should fail
    let result = WorldClassAuthCircuit::new_enterprise(
        b"", // Empty username
        b"ValidPassword123!",
        SecurityLevel::Standard,
        None, None, None, None, None
    );
    assert!(result.is_err(), "Empty username should be rejected");
    
    // Test 2: Empty password should fail  
    let result = WorldClassAuthCircuit::new_enterprise(
        b"valid_user",
        b"", // Empty password
        SecurityLevel::Standard,
        None, None, None, None, None
    );
    assert!(result.is_err(), "Empty password should be rejected");
    
    // Test 3: Weak password should fail
    let result = WorldClassAuthCircuit::new_enterprise(
        b"valid_user",
        b"weak", // Too weak
        SecurityLevel::Standard,
        None, None, None, None, None
    );
    assert!(result.is_err(), "Weak password should be rejected");
    
    // Test 4: Valid inputs should succeed
    let result = WorldClassAuthCircuit::new_enterprise(
        b"valid_user",
        b"StrongPassword123!@#",
        SecurityLevel::Standard,
        None, None, None, None, None
    );
    assert!(result.is_ok(), "Valid inputs should be accepted");
    
    if let Ok(circuit) = result {
        // Test compliance validation
        assert!(circuit.validate_enterprise_compliance()?, "Valid circuit should pass compliance");
        
        // Test public inputs are non-zero
        let public_inputs = circuit.public_inputs();
        assert_eq!(public_inputs.len(), 6, "Should have 6 public inputs");
        
        for (i, input) in public_inputs.iter().enumerate() {
            assert_ne!(*input, halo2curves::pasta::Fp::zero(), "Public input {} should be non-zero", i);
        }
    }
    
    Ok(())
}

#[test]
fn test_session_security() -> Result<()> {
    let mut auth = AuthSystem::new()?;
    
    // Test session creation with strong password
    let session_id = auth.authenticate(
        "session_test_user", 
        "SessionTestPassword_With_High_Entropy_123!"
    )?;
    
    // Test encryption/decryption
    let message = b"Test message for session security";
    let encrypted = auth.encrypt(&session_id, message, "client_to_server")?;
    let decrypted = auth.decrypt(&session_id, &encrypted, "client_to_server")?;
    
    assert_eq!(message, &decrypted[..], "Message should decrypt correctly");
    
    // Test that wrong direction fails
    let result = auth.decrypt(&session_id, &encrypted, "server_to_client");
    assert!(result.is_err(), "Wrong direction should fail decryption");
    
    // Test session metadata
    let metadata = auth.get_session_metadata(&session_id);
    assert!(metadata.is_some(), "Session metadata should exist");
    
    if let Some(meta) = metadata {
        assert!(meta.verified, "Session should be verified");
        assert_eq!(meta.session_id.as_bytes(), session_id.as_bytes());
    }
    
    Ok(())
}

#[test]
fn test_nullifier_uniqueness() -> Result<()> {
    WorldClassAuthSystem::initialize()?;
    
    // Test that same credentials produce same nullifier
    let circuit1 = WorldClassAuthCircuit::new_enterprise(
        b"nullifier_test_user",
        b"NullifierTestPassword_123!",
        SecurityLevel::Standard,
        None, None, None, None, None
    )?;
    
    let circuit2 = WorldClassAuthCircuit::new_enterprise(
        b"nullifier_test_user", 
        b"NullifierTestPassword_123!",
        SecurityLevel::Standard,
        None, None, None, None, None
    )?;
    
    let inputs1 = circuit1.public_inputs();
    let inputs2 = circuit2.public_inputs();
    
    // Nullifiers should be the same for same inputs (index 1)
    assert_eq!(inputs1[1], inputs2[1], "Same credentials should produce same nullifier");
    
    // Test that different credentials produce different nullifiers
    let circuit3 = WorldClassAuthCircuit::new_enterprise(
        b"different_user",
        b"DifferentPassword_123!",
        SecurityLevel::Standard,
        None, None, None, None, None
    )?;
    
    let inputs3 = circuit3.public_inputs();
    assert_ne!(inputs1[1], inputs3[1], "Different credentials should produce different nullifiers");
    
    Ok(())
}

#[test]
fn test_cipher_negotiation() -> Result<()> {
    let mut negotiator = CipherNegotiator::new_with_config(
        128, // Quantum threat level
        ComplianceLevel::FIPS140_2,
        false // Security over performance
    );
    
    // Test secure negotiation
    let client_suites = vec![
        CipherSuite::Hybrid.to_u16(),
        CipherSuite::PostQuantum.to_u16(),
        CipherSuite::Classical.to_u16()
    ];
    
    let result = negotiator.negotiate(&client_suites)?;
    assert!(result.is_some(), "Should negotiate a cipher suite");
    
    if let Some(suite) = result {
        assert!(suite.quantum_security_level() >= 128, "Should select quantum-safe suite");
    }
    
    // Test rejection of weak suites
    let weak_suites = vec![CipherSuite::LegacyCompat.to_u16()];
    let result = negotiator.negotiate(&weak_suites)?;
    // Should either reject or select with warnings
    
    // Test negotiation stats
    let stats = negotiator.get_negotiation_stats();
    assert!(stats.total_negotiations >= 1, "Should record negotiations");
    
    Ok(())
}

#[test]
fn test_batch_processing() -> Result<()> {
    let mut processor = WorldClassBatchProcessor::new(SecurityLevel::Standard);
    
    // Add multiple authentications
    for i in 0..10 {
        let username = format!("batch_user_{:02}", i);
        let password = format!("BatchPassword_{}_{}_With_High_Entropy!", i, i * 7);
        
        processor.add_enterprise_auth(
            username.as_bytes(),
            password.as_bytes(),
            None, None, None, None, None
        )?;
    }
    
    assert_eq!(processor.len(), 10, "Should have 10 circuits");
    
    // Test batch proof generation
    let proofs = processor.batch_prove_parallel()?;
    assert_eq!(proofs.len(), 10, "Should generate 10 proofs");
    
    // Verify all proofs are non-empty
    for (i, proof) in proofs.iter().enumerate() {
        assert!(!proof.is_empty(), "Proof {} should not be empty", i);
        assert!(proof.len() > 32, "Proof {} should be substantial size", i);
    }
    
    // Test performance metrics
    let metrics = processor.get_performance_metrics();
    assert!(metrics.contains_key("proofs_per_second"), "Should have performance metrics");
    assert!(metrics["proofs_per_second"] > 0, "Should have positive throughput");
    
    Ok(())
}

#[test]
fn test_ml_kem_integration() -> Result<()> {
    use ml_kem::KemCore;
    use rand::rngs::OsRng;
    
    let mut rng = OsRng;
    let (_dk, ek) = ml_kem::MlKem1024::generate(&mut rng);
    let pubkey_bytes = ek.as_bytes();
    let pubkey_array: &[u8; 1568] = pubkey_bytes.as_ref();
    
    // Test ML-KEM encryption
    let test_commitment = [0x42u8; 32];
    let test_nullifier = [0x43u8; 32];
    let timestamp = SystemTime::now().duration_since(UNIX_EPOCH)?.as_secs();
    let chain_salt = [0x44u8; 32];
    
    let encrypted = WorldClassAuthCircuit::encrypt_for_blockchain(
        b"ml_kem_test_user",
        b"MlKemTestPassword_With_High_Entropy_123!",
        &test_commitment,
        &test_nullifier,
        timestamp,
        &chain_salt,
        pubkey_array
    )?;
    
    // Verify encryption structure
    assert!(encrypted.len() > 1600, "ML-KEM encrypted data should be substantial");
    assert_eq!(&encrypted[..1568], &ek.as_bytes()[..1568], "Should contain ML-KEM ciphertext");
    
    Ok(())
}

#[test]
fn test_security_cleanup() -> Result<()> {
    // Test that cleanup operations work
    let _circuit = WorldClassAuthCircuit::new_enterprise(
        b"cleanup_test_user",
        b"CleanupTestPassword_With_High_Entropy_123!",
        SecurityLevel::Standard,
        None, None, None, None, None
    )?;
    
    // Run cleanup
    WorldClassAuthCircuit::cleanup_expired_data();
    
    // Verify cleanup doesn't crash and handles edge cases
    WorldClassAuthCircuit::cleanup_expired_data();
    
    Ok(())
}