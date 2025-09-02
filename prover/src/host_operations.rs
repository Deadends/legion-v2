// FIXED: Host-side operations - all IO, crypto validation, and state changes
use crate::deterministic_circuit::{AuthWitness, DeterministicAuthCircuit, SecurityLevel};
use halo2curves::pasta::Fp;
use blake3;
use std::time::{SystemTime, UNIX_EPOCH};
use std::collections::HashMap;
use anyhow::{Result, Context};
use rand::{rngs::OsRng, RngCore};
use ed25519_dalek::{SigningKey, VerifyingKey, Signature, Verifier, Signer};

// FIXED: Host manages all state and IO
pub struct AuthHost {
    nullifier_store: HashMap<[u8; 32], SystemTime>,
    certificate_store: HashMap<String, CertificateInfo>,
    rate_limiters: HashMap<String, RateLimiter>,
    audit_log: Vec<AuditEvent>,
}

#[derive(Debug, Clone)]
pub struct CertificateInfo {
    pub public_key: [u8; 32],
    pub valid_until: SystemTime,
    pub revoked: bool,
}

#[derive(Debug)]
struct RateLimiter {
    attempts: u32,
    last_attempt: SystemTime,
    locked_until: Option<SystemTime>,
}

#[derive(Debug, Clone)]
struct AuditEvent {
    timestamp: SystemTime,
    event_type: String,
    user_id: String,
    success: bool,
}

#[derive(Debug)]
pub struct AuthRequest {
    pub username: String,
    pub password: String,
    pub timestamp: u64,
    pub server_pubkey: [u8; 32],
    pub ip_address: Option<String>,
}

#[derive(Debug)]
pub struct AuthResult {
    pub witness: AuthWitness,
    pub proof: Vec<u8>,
    pub public_inputs: Vec<Fp>,
}

impl AuthHost {
    pub fn new() -> Self {
        Self {
            nullifier_store: HashMap::new(),
            certificate_store: HashMap::new(),
            rate_limiters: HashMap::new(),
            audit_log: Vec::new(),
        }
    }

    // FIXED: Host validates inputs and prepares deterministic witness
    pub fn authenticate(&mut self, request: AuthRequest, security_level: SecurityLevel) -> Result<AuthResult> {
        // 1. FIXED: Host-side validation (no circuit side effects)
        self.validate_request(&request)?;
        self.check_rate_limit(&request.username, request.ip_address.as_deref())?;
        self.validate_certificate(&request.server_pubkey)?;
        
        // 2. FIXED: Generate deterministic witness data
        let witness = self.create_witness(&request, security_level)?;
        
        // 3. FIXED: Check nullifier uniqueness (host-side)
        let nullifier_bytes = self.compute_nullifier_bytes(&witness);
        if self.is_nullifier_used(&nullifier_bytes) {
            return Err(anyhow::anyhow!("Nullifier already used - replay attack"));
        }
        
        // 4. FIXED: Generate proof with pure circuit
        let circuit = DeterministicAuthCircuit::new(Some(witness.clone()), security_level);
        let public_inputs = circuit.public_inputs();
        let proof = self.generate_proof(circuit, &public_inputs, security_level)?;
        
        // 5. FIXED: Store nullifier and audit (after successful proof)
        self.store_nullifier(nullifier_bytes);
        self.audit_authentication(&request.username, true);
        
        Ok(AuthResult {
            witness,
            proof,
            public_inputs,
        })
    }

    // FIXED: Pure validation without side effects
    fn validate_request(&self, request: &AuthRequest) -> Result<()> {
        if request.username.is_empty() || request.password.is_empty() {
            return Err(anyhow::anyhow!("Empty credentials"));
        }
        
        if request.username.len() > 256 || request.password.len() > 1024 {
            return Err(anyhow::anyhow!("Credentials too long"));
        }
        
        // FIXED: Validate timestamp bounds
        let now = SystemTime::now().duration_since(UNIX_EPOCH)?.as_secs();
        let time_diff = if now > request.timestamp {
            now - request.timestamp
        } else {
            request.timestamp - now
        };
        
        if time_diff > 300 { // 5 minute skew
            return Err(anyhow::anyhow!("Timestamp skew too large"));
        }
        
        // FIXED: Validate entropy
        let entropy = self.calculate_entropy(request.password.as_bytes());
        if entropy < 50.0 {
            return Err(anyhow::anyhow!("Password entropy too low: {:.1}", entropy));
        }
        
        Ok(())
    }

    // FIXED: Deterministic witness creation
    fn create_witness(&self, request: &AuthRequest, security_level: SecurityLevel) -> Result<AuthWitness> {
        // FIXED: Deterministic hashing with known salt
        let salt = b"LEGION_DETERMINISTIC_SALT_V1";
        let rounds = security_level as usize + 5;
        
        let username_hash = DeterministicAuthCircuit::deterministic_hash(
            request.username.as_bytes(), 
            salt, 
            rounds
        );
        
        let password_hash = DeterministicAuthCircuit::deterministic_hash(
            request.password.as_bytes(), 
            salt, 
            rounds
        );
        
        let server_pubkey_hash = DeterministicAuthCircuit::deterministic_hash(
            &request.server_pubkey, 
            salt, 
            rounds
        );
        
        // FIXED: Deterministic nonce from inputs (not random)
        let mut nonce_input = Vec::new();
        nonce_input.extend_from_slice(request.username.as_bytes());
        nonce_input.extend_from_slice(&request.timestamp.to_le_bytes());
        nonce_input.extend_from_slice(&request.server_pubkey);
        
        let nonce_hash = blake3::hash(&nonce_input);
        let nonce = u64::from_le_bytes(nonce_hash.as_bytes()[..8].try_into().unwrap());
        
        // FIXED: Simple Merkle path (single leaf for now)
        let merkle_path = [Fp::zero(); 20]; // Will be computed properly later
        
        Ok(AuthWitness {
            username_hash,
            password_hash,
            timestamp: request.timestamp,
            nonce,
            merkle_path,
            merkle_index: 0,
            server_pubkey_hash,
        })
    }

    // FIXED: Host-side rate limiting
    fn check_rate_limit(&mut self, username: &str, ip: Option<&str>) -> Result<()> {
        let now = SystemTime::now();
        let limiter = self.rate_limiters.entry(username.to_string()).or_insert(RateLimiter {
            attempts: 0,
            last_attempt: now,
            locked_until: None,
        });
        
        // Check if locked
        if let Some(locked_until) = limiter.locked_until {
            if now < locked_until {
                return Err(anyhow::anyhow!("Account locked"));
            } else {
                limiter.locked_until = None;
                limiter.attempts = 0;
            }
        }
        
        // Check attempts
        limiter.attempts += 1;
        limiter.last_attempt = now;
        
        if limiter.attempts > 5 {
            limiter.locked_until = Some(now + std::time::Duration::from_secs(300));
            return Err(anyhow::anyhow!("Too many attempts"));
        }
        
        Ok(())
    }

    // FIXED: Host-side certificate validation
    fn validate_certificate(&self, server_pubkey: &[u8; 32]) -> Result<()> {
        let key_hex = hex::encode(server_pubkey);
        
        // Check if certificate exists and is valid
        if let Some(cert) = self.certificate_store.get(&key_hex) {
            let now = SystemTime::now();
            if cert.revoked || now > cert.valid_until {
                return Err(anyhow::anyhow!("Certificate invalid or expired"));
            }
        } else {
            // For testing, allow default key
            let default_key = self.get_default_server_key();
            if server_pubkey != &default_key {
                return Err(anyhow::anyhow!("Unknown server certificate"));
            }
        }
        
        Ok(())
    }

    // FIXED: Host computes nullifier for uniqueness check
    fn compute_nullifier_bytes(&self, witness: &AuthWitness) -> [u8; 32] {
        let mut hasher = blake3::Hasher::new();
        hasher.update(b"NULLIFIER_V1");
        hasher.update(&witness.username_hash.to_repr());
        hasher.update(&witness.password_hash.to_repr());
        hasher.update(&witness.nonce.to_le_bytes());
        hasher.update(&witness.timestamp.to_le_bytes());
        hasher.update(&witness.server_pubkey_hash.to_repr());
        
        let mut result = [0u8; 32];
        result.copy_from_slice(&hasher.finalize().as_bytes()[..32]);
        result
    }

    fn is_nullifier_used(&self, nullifier: &[u8; 32]) -> bool {
        self.nullifier_store.contains_key(nullifier)
    }

    fn store_nullifier(&mut self, nullifier: [u8; 32]) {
        self.nullifier_store.insert(nullifier, SystemTime::now());
    }

    // FIXED: Real proof generation
    fn generate_proof(
        &self, 
        circuit: DeterministicAuthCircuit, 
        public_inputs: &[Fp],
        security_level: SecurityLevel
    ) -> Result<Vec<u8>> {
        use halo2_proofs::{
            plonk::{create_proof, keygen_pk, keygen_vk},
            poly::commitment::Params,
            transcript::Blake2bWrite,
        };
        use halo2curves::pasta::EqAffine;
        use rand::rngs::OsRng;
        
        let k = security_level.circuit_size();
        let params = Params::<EqAffine>::new(k);
        
        // Generate keys
        let empty_circuit = DeterministicAuthCircuit::new(None, security_level);
        let vk = keygen_vk(&params, &empty_circuit)?;
        let pk = keygen_pk(&params, vk, &empty_circuit)?;
        
        // Generate proof
        let instances = vec![public_inputs.to_vec()];
        let mut transcript = Blake2bWrite::<_, _, halo2_proofs::transcript::Challenge255<_>>::init(vec![]);
        
        create_proof(
            &params,
            &pk,
            &[circuit],
            &[instances.iter().map(|i| i.as_slice()).collect::<Vec<_>>().as_slice()],
            OsRng,
            &mut transcript,
        )?;
        
        Ok(transcript.finalize())
    }

    fn calculate_entropy(&self, password: &[u8]) -> f64 {
        if password.is_empty() {
            return 0.0;
        }
        
        let mut char_counts = [0u32; 256];
        for &byte in password {
            char_counts[byte as usize] += 1;
        }
        
        let len = password.len() as f64;
        let mut entropy = 0.0;
        
        for &count in &char_counts {
            if count > 0 {
                let p = count as f64 / len;
                entropy -= p * p.log2();
            }
        }
        
        entropy * len
    }

    fn get_default_server_key(&self) -> [u8; 32] {
        let mut hasher = blake3::Hasher::new();
        hasher.update(b"LEGION_DEFAULT_SERVER_KEY_V1");
        let mut key = [0u8; 32];
        key.copy_from_slice(&hasher.finalize().as_bytes()[..32]);
        key
    }

    fn audit_authentication(&mut self, username: &str, success: bool) {
        self.audit_log.push(AuditEvent {
            timestamp: SystemTime::now(),
            event_type: "AUTH".to_string(),
            user_id: username.to_string(),
            success,
        });
    }

    // FIXED: Add certificate to store
    pub fn add_certificate(&mut self, public_key: [u8; 32], valid_until: SystemTime) {
        let key_hex = hex::encode(&public_key);
        self.certificate_store.insert(key_hex, CertificateInfo {
            public_key,
            valid_until,
            revoked: false,
        });
    }

    // FIXED: Revoke certificate
    pub fn revoke_certificate(&mut self, public_key: &[u8; 32]) {
        let key_hex = hex::encode(public_key);
        if let Some(cert) = self.certificate_store.get_mut(&key_hex) {
            cert.revoked = true;
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_deterministic_authentication() {
        let mut host = AuthHost::new();
        
        let request = AuthRequest {
            username: "test_user".to_string(),
            password: "test_password_with_sufficient_entropy_123!".to_string(),
            timestamp: 1640995200,
            server_pubkey: host.get_default_server_key(),
            ip_address: Some("127.0.0.1".to_string()),
        };
        
        // First authentication
        let result1 = host.authenticate(request.clone(), SecurityLevel::Standard).unwrap();
        
        // Reset host state for second attempt
        let mut host2 = AuthHost::new();
        let result2 = host2.authenticate(request, SecurityLevel::Standard).unwrap();
        
        // Witnesses should be identical (deterministic)
        assert_eq!(result1.witness.username_hash, result2.witness.username_hash);
        assert_eq!(result1.witness.password_hash, result2.witness.password_hash);
        assert_eq!(result1.witness.nonce, result2.witness.nonce);
        assert_eq!(result1.public_inputs, result2.public_inputs);
    }

    #[test]
    fn test_nullifier_replay_protection() {
        let mut host = AuthHost::new();
        
        let request = AuthRequest {
            username: "replay_user".to_string(),
            password: "replay_password_with_entropy_456!".to_string(),
            timestamp: 1640995200,
            server_pubkey: host.get_default_server_key(),
            ip_address: Some("127.0.0.1".to_string()),
        };
        
        // First authentication should succeed
        let _result1 = host.authenticate(request.clone(), SecurityLevel::Standard).unwrap();
        
        // Second authentication with same inputs should fail (replay)
        let result2 = host.authenticate(request, SecurityLevel::Standard);
        assert!(result2.is_err());
        assert!(result2.unwrap_err().to_string().contains("replay"));
    }

    #[test]
    fn test_rate_limiting() {
        let mut host = AuthHost::new();
        
        let mut request = AuthRequest {
            username: "rate_test".to_string(),
            password: "rate_password_with_entropy_789!".to_string(),
            timestamp: 1640995200,
            server_pubkey: host.get_default_server_key(),
            ip_address: Some("127.0.0.1".to_string()),
        };
        
        // First 5 attempts should work (different timestamps to avoid replay)
        for i in 0..5 {
            request.timestamp += i;
            let _result = host.authenticate(request.clone(), SecurityLevel::Standard).unwrap();
        }
        
        // 6th attempt should be rate limited
        request.timestamp += 10;
        let result = host.authenticate(request, SecurityLevel::Standard);
        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("Too many attempts"));
    }
}