// Host-side wrapper that handles all IO, validation, and state management
// This replaces the side effects that were incorrectly in the circuit constructor

use super::final_circuit::{WorldClassAuthCircuit, SecurityLevel};
use halo2curves::ff::{PrimeField, FromUniformBytes};
use halo2curves::pasta::Fp;
use std::time::{SystemTime, UNIX_EPOCH};
use std::collections::HashMap;
use anyhow::{Result, Context};
use blake3;

pub struct AuthHost {
    nullifier_store: HashMap<[u8; 32], SystemTime>,
    rate_limiters: HashMap<String, RateLimiter>,
    certificate_store: HashMap<String, bool>, // Simplified for now
}

struct RateLimiter {
    attempts: u32,
    last_attempt: SystemTime,
}

pub struct AuthRequest {
    pub username: String,
    pub password: String,
    pub timestamp: u64,
    pub server_pubkey: [u8; 32],
    pub ip_address: Option<String>,
}

impl AuthHost {
    pub fn new() -> Self {
        Self {
            nullifier_store: HashMap::new(),
            rate_limiters: HashMap::new(),
            certificate_store: HashMap::new(),
        }
    }

    // FIXED: Host handles all validation and side effects
    pub fn authenticate(&mut self, request: AuthRequest, security_level: SecurityLevel) -> Result<(WorldClassAuthCircuit, Vec<Fp>)> {
        // 1. Host-side validation
        self.validate_inputs(&request)?;
        self.check_rate_limit(&request.username)?;
        self.validate_certificate(&request.server_pubkey)?;
        
        // 2. Generate deterministic witness data
        let salt = b"LEGION_DETERMINISTIC_SALT_V1";
        
        let username_hash = WorldClassAuthCircuit::deterministic_hash(
            request.username.as_bytes(),
            b"USER_DOMAIN",
            salt,
            security_level,
        )?;
        
        let password_hash = WorldClassAuthCircuit::deterministic_hash(
            request.password.as_bytes(),
            b"PASS_DOMAIN", 
            salt,
            security_level,
        )?;
        
        let server_pubkey_hash = WorldClassAuthCircuit::deterministic_hash(
            &request.server_pubkey,
            b"SERVER_DOMAIN",
            salt,
            security_level,
        )?;
        
        // 3. Generate deterministic nonce from inputs
        let nonce = self.compute_deterministic_nonce(&request);
        
        // 4. Create deterministic random values
        let (random1, random2) = self.compute_deterministic_randoms(&request, security_level);
        
        // 5. Check nullifier uniqueness BEFORE creating circuit
        let nullifier_bytes = self.compute_nullifier_bytes(
            username_hash, password_hash, nonce, request.timestamp, server_pubkey_hash
        );
        
        if self.is_nullifier_used(&nullifier_bytes) {
            return Err(anyhow::anyhow!("Nullifier already used - replay attack"));
        }
        
        // 6. Create pure circuit with deterministic inputs
        let circuit = WorldClassAuthCircuit::new_deterministic(
            username_hash,
            password_hash,
            request.timestamp,
            nonce,
            security_level,
            None, // merkle_path
            None, // merkle_root
            None, // leaf_index
            server_pubkey_hash,
            random1,
            random2,
        )?;
        
        let public_inputs = circuit.public_inputs();
        
        // 7. Store nullifier AFTER successful circuit creation
        self.store_nullifier(nullifier_bytes);
        
        Ok((circuit, public_inputs))
    }

    fn validate_inputs(&self, request: &AuthRequest) -> Result<()> {
        if request.username.is_empty() || request.password.is_empty() {
            return Err(anyhow::anyhow!("Empty credentials"));
        }
        
        // Validate entropy
        let entropy = self.calculate_entropy(request.password.as_bytes());
        if entropy < 50.0 {
            return Err(anyhow::anyhow!("Password entropy too low: {:.1}", entropy));
        }
        
        // Validate timestamp
        let now = SystemTime::now().duration_since(UNIX_EPOCH)?.as_secs();
        let time_diff = if now > request.timestamp {
            now - request.timestamp
        } else {
            request.timestamp - now
        };
        
        if time_diff > 300 {
            return Err(anyhow::anyhow!("Timestamp skew too large"));
        }
        
        Ok(())
    }

    fn check_rate_limit(&mut self, username: &str) -> Result<()> {
        let now = SystemTime::now();
        let limiter = self.rate_limiters.entry(username.to_string()).or_insert(RateLimiter {
            attempts: 0,
            last_attempt: now,
        });
        
        limiter.attempts += 1;
        limiter.last_attempt = now;
        
        if limiter.attempts > 5 {
            return Err(anyhow::anyhow!("Too many attempts"));
        }
        
        Ok(())
    }

    fn validate_certificate(&self, _server_pubkey: &[u8; 32]) -> Result<()> {
        // Simplified certificate validation
        // In production, this would check certificate store, OCSP, etc.
        Ok(())
    }

    fn compute_deterministic_nonce(&self, request: &AuthRequest) -> u64 {
        let mut hasher = blake3::Hasher::new();
        hasher.update(b"DETERMINISTIC_NONCE_V1");
        hasher.update(request.username.as_bytes());
        hasher.update(&request.timestamp.to_le_bytes());
        hasher.update(&request.server_pubkey);
        
        let hash = hasher.finalize();
        u64::from_le_bytes(hash.as_bytes()[..8].try_into().unwrap())
    }

    fn compute_deterministic_randoms(&self, request: &AuthRequest, security_level: SecurityLevel) -> (Fp, Fp) {
        let mut hasher1 = blake3::Hasher::new();
        hasher1.update(b"DETERMINISTIC_RANDOM1_V1");
        hasher1.update(request.username.as_bytes());
        hasher1.update(request.password.as_bytes());
        hasher1.update(&(security_level as u8).to_le_bytes());
        
        let mut hasher2 = blake3::Hasher::new();
        hasher2.update(b"DETERMINISTIC_RANDOM2_V1");
        hasher2.update(request.password.as_bytes());
        hasher2.update(&request.timestamp.to_le_bytes());
        hasher2.update(&(security_level as u8).to_le_bytes());
        
        let hash1 = hasher1.finalize();
        let hash2 = hasher2.finalize();
        
        let mut buf1 = [0u8; 64];
        let mut buf2 = [0u8; 64];
        buf1[..32].copy_from_slice(&hash1.as_bytes()[..32]);
        buf2[..32].copy_from_slice(&hash2.as_bytes()[..32]);
        
        (Fp::from_uniform_bytes(&buf1), Fp::from_uniform_bytes(&buf2))
    }

    fn compute_nullifier_bytes(
        &self,
        username_hash: Fp,
        password_hash: Fp,
        nonce: u64,
        timestamp: u64,
        server_pubkey_hash: Fp,
    ) -> [u8; 32] {
        let mut hasher = blake3::Hasher::new();
        hasher.update(b"NULLIFIER_COMPUTATION_V1");
        hasher.update(&username_hash.to_repr());
        hasher.update(&password_hash.to_repr());
        hasher.update(&nonce.to_le_bytes());
        hasher.update(&timestamp.to_le_bytes());
        hasher.update(&server_pubkey_hash.to_repr());
        
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
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_deterministic_authentication() {
        let mut host1 = AuthHost::new();
        let mut host2 = AuthHost::new();
        
        let request = AuthRequest {
            username: "test_user".to_string(),
            password: "test_password_with_sufficient_entropy_123!".to_string(),
            timestamp: 1640995200,
            server_pubkey: [42u8; 32],
            ip_address: Some("127.0.0.1".to_string()),
        };
        
        let (circuit1, public1) = host1.authenticate(request.clone(), SecurityLevel::Standard).unwrap();
        let (circuit2, public2) = host2.authenticate(request, SecurityLevel::Standard).unwrap();
        
        // Should be identical (deterministic)
        assert_eq!(public1, public2);
    }

    #[test]
    fn test_replay_protection() {
        let mut host = AuthHost::new();
        
        let request = AuthRequest {
            username: "replay_user".to_string(),
            password: "replay_password_with_entropy_456!".to_string(),
            timestamp: 1640995200,
            server_pubkey: [42u8; 32],
            ip_address: Some("127.0.0.1".to_string()),
        };
        
        // First should succeed
        let _result1 = host.authenticate(request.clone(), SecurityLevel::Standard).unwrap();
        
        // Second should fail (replay)
        let result2 = host.authenticate(request, SecurityLevel::Standard);
        assert!(result2.is_err());
        assert!(result2.unwrap_err().to_string().contains("replay"));
    }
}