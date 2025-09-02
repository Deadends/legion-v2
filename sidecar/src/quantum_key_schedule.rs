use hkdf::Hkdf;
use sha3::Sha3_256;
use blake3::Hasher;
use std::time::{SystemTime, UNIX_EPOCH};
use zeroize::{Zeroize, ZeroizeOnDrop, Zeroizing};
use serde::{Serialize, Deserialize};
use rand::{RngCore, rngs::OsRng};
use anyhow::{Result, Context};
use tracing::{info, warn, error, debug};

// Quantum-resistant key derivation constants
const QUANTUM_SECURITY_LEVEL: usize = 256;
const KEY_DERIVATION_ROUNDS: u32 = 100000;
const SALT_SIZE: usize = 64;
const MASTER_KEY_SIZE: usize = 64;
const SESSION_KEY_SIZE: usize = 32;
const FORWARD_SECRECY_INTERVAL: u64 = 3600;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum KeyDerivationAlgorithm {
    HKDF_SHA3_256,
    HKDF_BLAKE3,
    Argon2id,
    PBKDF2_SHA3,
    QuantumResistant,
}

#[derive(Debug, Clone, ZeroizeOnDrop)]
pub struct QuantumResistantKeySchedule {
    master_secret: Zeroizing<[u8; MASTER_KEY_SIZE]>,
    transcript_hash: [u8; 32],
    derivation_algorithm: KeyDerivationAlgorithm,
    security_level: u8,
    forward_secrecy_counter: u64,
    key_rotation_history: Vec<KeyRotationEvent>,
    quantum_entropy_pool: Zeroizing<[u8; 128]>,
}

#[derive(Debug, Clone, Serialize, Deserialize, Zeroize, ZeroizeOnDrop)]
pub struct KeyRotationEvent {
    pub timestamp: SystemTime,
    pub old_key_hash: [u8; 32],
    pub new_key_hash: [u8; 32],
    pub rotation_reason: KeyRotationReason,
    pub security_level: u8,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum KeyRotationReason {
    Scheduled,
    SecurityBreach,
    ComplianceRequirement,
    QuantumThreat,
    UserRequest,
    SystemMaintenance,
}

#[derive(Debug, Clone, Serialize, Deserialize, ZeroizeOnDrop)]
pub struct EnhancedSessionKeys {
    pub client_to_server: Zeroizing<[u8; SESSION_KEY_SIZE]>,
    pub server_to_client: Zeroizing<[u8; SESSION_KEY_SIZE]>,
    pub epoch: u32,
    pub derived_at: SystemTime,
    pub expires_at: SystemTime,
    pub key_id: [u8; 16],
    pub algorithm: KeyDerivationAlgorithm,
    pub forward_secrecy_key: Zeroizing<[u8; SESSION_KEY_SIZE]>,
}

impl QuantumResistantKeySchedule {
    pub fn new(
        shared_secret: &[u8], 
        salt: &[u8], 
        transcript_hash: [u8; 32]
    ) -> Result<Self> {
        Self::new_with_algorithm(
            shared_secret, 
            salt, 
            transcript_hash, 
            KeyDerivationAlgorithm::HKDF_BLAKE3,
            128
        )
    }
    
    pub fn new_with_algorithm(
        shared_secret: &[u8],
        salt: &[u8],
        transcript_hash: [u8; 32],
        algorithm: KeyDerivationAlgorithm,
        security_level: u8
    ) -> Result<Self> {
        if shared_secret.len() < 32 {
            return Err(anyhow::anyhow!("Shared secret too short for quantum resistance"));
        }
        
        let mut master_secret = Zeroizing::new([0u8; MASTER_KEY_SIZE]);
        let mut quantum_entropy_pool = Zeroizing::new([0u8; 128]);
        
        OsRng.fill_bytes(&mut *quantum_entropy_pool);
        
        match algorithm {
            KeyDerivationAlgorithm::HKDF_BLAKE3 => {
                Self::derive_with_blake3_hkdf(
                    shared_secret, 
                    salt, 
                    &transcript_hash, 
                    &quantum_entropy_pool,
                    &mut master_secret
                )?;
            }
            KeyDerivationAlgorithm::QuantumResistant => {
                Self::derive_quantum_resistant(
                    shared_secret, 
                    salt, 
                    &transcript_hash, 
                    &quantum_entropy_pool,
                    &mut master_secret
                )?;
            }
            _ => {
                return Err(anyhow::anyhow!("Unsupported key derivation algorithm"));
            }
        }
        
        Ok(Self {
            master_secret,
            transcript_hash,
            derivation_algorithm: algorithm,
            security_level,
            forward_secrecy_counter: 0,
            key_rotation_history: Vec::new(),
            quantum_entropy_pool,
        })
    }
    
    fn derive_with_blake3_hkdf(
        shared_secret: &[u8],
        salt: &[u8],
        transcript_hash: &[u8; 32],
        quantum_entropy: &[u8; 128],
        output: &mut [u8; MASTER_KEY_SIZE]
    ) -> Result<()> {
        let mut stage1_hasher = blake3::Hasher::new();
        stage1_hasher.update(b"LEGION_QUANTUM_RESISTANT_V1");
        stage1_hasher.update(shared_secret);
        stage1_hasher.update(salt);
        stage1_hasher.update(transcript_hash);
        let stage1_key = stage1_hasher.finalize();
        
        let mut stage2_hasher = blake3::Hasher::new();
        stage2_hasher.update(b"LEGION_QUANTUM_STAGE2_V1");
        stage2_hasher.update(stage1_key.as_bytes());
        stage2_hasher.update(quantum_entropy);
        stage2_hasher.update(&SystemTime::now().duration_since(UNIX_EPOCH)
            .context("System time error")?
            .as_nanos().to_le_bytes());
        let stage2_key = stage2_hasher.finalize();
        
        let mut final_hasher = blake3::Hasher::new();
        final_hasher.update(b"LEGION_MASTER_KEY_FINAL_V1");
        final_hasher.update(stage2_key.as_bytes());
        final_hasher.update(transcript_hash);
        
        let mut reader = final_hasher.finalize_xof();
        reader.fill(output);
        
        Ok(())
    }
    
    fn derive_quantum_resistant(
        shared_secret: &[u8],
        salt: &[u8],
        transcript_hash: &[u8; 32],
        quantum_entropy: &[u8; 128],
        output: &mut [u8; MASTER_KEY_SIZE]
    ) -> Result<()> {
        let mut blake3_output = Zeroizing::new([0u8; MASTER_KEY_SIZE]);
        Self::derive_with_blake3_hkdf(
            shared_secret, salt, transcript_hash, quantum_entropy, &mut blake3_output
        )?;
        
        let mut sha3_output = Zeroizing::new([0u8; MASTER_KEY_SIZE]);
        Self::derive_with_sha3_hkdf(
            shared_secret, salt, transcript_hash, quantum_entropy, &mut sha3_output
        )?;
        
        for i in 0..MASTER_KEY_SIZE {
            output[i] = blake3_output[i] ^ sha3_output[i];
        }
        
        let mut final_hasher = blake3::Hasher::new();
        final_hasher.update(b"LEGION_QUANTUM_FINAL_MIX_V1");
        final_hasher.update(output);
        final_hasher.update(quantum_entropy);
        final_hasher.update(transcript_hash);
        
        let final_hash = final_hasher.finalize();
        
        for i in 0..32.min(MASTER_KEY_SIZE) {
            output[i] ^= final_hash.as_bytes()[i];
        }
        
        Ok(())
    }
    
    fn derive_with_sha3_hkdf(
        shared_secret: &[u8],
        salt: &[u8],
        transcript_hash: &[u8; 32],
        quantum_entropy: &[u8; 128],
        output: &mut [u8; MASTER_KEY_SIZE]
    ) -> Result<()> {
        let mut combined_input = Vec::with_capacity(
            shared_secret.len() + quantum_entropy.len() + transcript_hash.len()
        );
        combined_input.extend_from_slice(shared_secret);
        combined_input.extend_from_slice(quantum_entropy);
        combined_input.extend_from_slice(transcript_hash);
        
        let hk = Hkdf::<Sha3_256>::new(Some(salt), &combined_input);
        
        let mut info = Vec::new();
        info.extend_from_slice(b"LEGION_QUANTUM_MASTER_SECRET_V1");
        info.extend_from_slice(transcript_hash);
        info.extend_from_slice(&SystemTime::now().duration_since(UNIX_EPOCH)
            .context("System time error")?
            .as_secs().to_le_bytes());
        
        hk.expand(&info, output)
            .context("SHA3-HKDF master secret derivation failed")?;
        
        Ok(())
    }
    
    pub fn derive_session_keys(&self, session_id: &[u8; 32], epoch: u32) -> Result<EnhancedSessionKeys> {
        let hk = Hkdf::<Sha3_256>::new(None, &*self.master_secret);
        
        let mut epoch_info = Vec::new();
        epoch_info.extend_from_slice(b"LEGION_QUANTUM_EPOCH_SALT");
        epoch_info.extend_from_slice(&epoch.to_le_bytes());
        epoch_info.extend_from_slice(&self.transcript_hash);
        epoch_info.extend_from_slice(session_id);
        epoch_info.extend_from_slice(&self.forward_secrecy_counter.to_le_bytes());
        
        let mut epoch_salt = [0u8; 32];
        hk.expand(&epoch_info, &mut epoch_salt)
            .context("Epoch salt derivation failed")?;
        
        let hk_epoch = Hkdf::<Sha3_256>::new(Some(&epoch_salt), &*self.master_secret);
        
        let mut client_key = Zeroizing::new([0u8; SESSION_KEY_SIZE]);
        let mut c2s_info = Vec::new();
        c2s_info.extend_from_slice(b"QUANTUM_CLIENT_TO_SERVER");
        c2s_info.extend_from_slice(&self.transcript_hash);
        c2s_info.extend_from_slice(&self.quantum_entropy_pool[..32]);
        hk_epoch.expand(&c2s_info, &mut *client_key)
            .context("Client key derivation failed")?;
        
        let mut server_key = Zeroizing::new([0u8; SESSION_KEY_SIZE]);
        let mut s2c_info = Vec::new();
        s2c_info.extend_from_slice(b"QUANTUM_SERVER_TO_CLIENT");
        s2c_info.extend_from_slice(&self.transcript_hash);
        s2c_info.extend_from_slice(&self.quantum_entropy_pool[32..64]);
        hk_epoch.expand(&s2c_info, &mut *server_key)
            .context("Server key derivation failed")?;
        
        let mut forward_secrecy_key = Zeroizing::new([0u8; SESSION_KEY_SIZE]);
        let mut fs_info = Vec::new();
        fs_info.extend_from_slice(b"QUANTUM_FORWARD_SECRECY");
        fs_info.extend_from_slice(&self.transcript_hash);
        fs_info.extend_from_slice(&self.quantum_entropy_pool[64..96]);
        hk_epoch.expand(&fs_info, &mut *forward_secrecy_key)
            .context("Forward secrecy key derivation failed")?;
        
        let mut key_id = [0u8; 16];
        let mut id_info = Vec::new();
        id_info.extend_from_slice(b"QUANTUM_KEY_ID");
        id_info.extend_from_slice(session_id);
        id_info.extend_from_slice(&epoch.to_le_bytes());
        hk_epoch.expand(&id_info, &mut key_id)
            .context("Key ID derivation failed")?;
        
        let now = SystemTime::now();
        
        debug!("Derived quantum-resistant session keys for epoch {}", epoch);
        
        Ok(EnhancedSessionKeys {
            client_to_server: client_key,
            server_to_client: server_key,
            epoch,
            derived_at: now,
            expires_at: now + std::time::Duration::from_secs(FORWARD_SECRECY_INTERVAL),
            key_id,
            algorithm: self.derivation_algorithm.clone(),
            forward_secrecy_key,
        })
    }
    
    pub fn rotate_master_key(&mut self, reason: KeyRotationReason) -> Result<()> {
        let old_key_hash = blake3::hash(&*self.master_secret);
        
        OsRng.fill_bytes(&mut *self.quantum_entropy_pool);
        
        let mut new_master = Zeroizing::new([0u8; MASTER_KEY_SIZE]);
        Self::derive_quantum_resistant(
            &*self.master_secret,
            &self.quantum_entropy_pool[..64],
            &self.transcript_hash,
            &self.quantum_entropy_pool,
            &mut new_master
        )?;
        
        let new_key_hash = blake3::hash(&*new_master);
        
        let rotation_event = KeyRotationEvent {
            timestamp: SystemTime::now(),
            old_key_hash: *old_key_hash.as_bytes(),
            new_key_hash: *new_key_hash.as_bytes(),
            rotation_reason: reason.clone(),
            security_level: self.security_level,
        };
        
        self.key_rotation_history.push(rotation_event);
        self.master_secret = new_master;
        self.forward_secrecy_counter += 1;
        
        if self.key_rotation_history.len() > 100 {
            self.key_rotation_history.remove(0);
        }
        
        info!("Rotated quantum-resistant master key, reason: {:?}", reason);
        Ok(())
    }
    
    pub fn compute_transcript_hash(
        client_hello: &[u8],
        server_hello: &[u8], 
        proof_message: &[u8],
        timestamp: u64
    ) -> [u8; 32] {
        let mut hasher = blake3::Hasher::new();
        hasher.update(b"LEGION_QUANTUM_HANDSHAKE_V1");
        hasher.update(client_hello);
        hasher.update(server_hello);
        hasher.update(proof_message);
        hasher.update(&timestamp.to_le_bytes());
        
        *hasher.finalize().as_bytes()
    }
    
    pub fn get_rotation_history(&self) -> &[KeyRotationEvent] {
        &self.key_rotation_history
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    
    #[test]
    fn test_quantum_key_schedule() -> Result<()> {
        let shared_secret = b"test_shared_secret_32_bytes_long_quantum";
        let salt = b"test_salt_64_bytes_long_for_quantum_resistance_testing_purposes";
        let transcript = [0x42u8; 32];
        let session_id = [0x01u8; 32];
        
        let ks = QuantumResistantKeySchedule::new(shared_secret, salt, transcript)?;
        let keys = ks.derive_session_keys(&session_id, 0)?;
        
        assert_eq!(keys.epoch, 0);
        assert_ne!(*keys.client_to_server, *keys.server_to_client);
        
        Ok(())
    }
    
    #[test]
    fn test_quantum_key_rotation() -> Result<()> {
        let shared_secret = b"test_shared_secret_32_bytes_long_quantum";
        let salt = b"test_salt_64_bytes_long_for_quantum_resistance_testing_purposes";
        let transcript = [0x42u8; 32];
        
        let mut ks = QuantumResistantKeySchedule::new(shared_secret, salt, transcript)?;
        
        let session_id = [0x01u8; 32];
        let keys_before = ks.derive_session_keys(&session_id, 0)?;
        
        ks.rotate_master_key(KeyRotationReason::Scheduled)?;
        
        let keys_after = ks.derive_session_keys(&session_id, 0)?;
        
        assert_ne!(*keys_before.client_to_server, *keys_after.client_to_server);
        assert_eq!(ks.get_rotation_history().len(), 1);
        
        Ok(())
    }
}