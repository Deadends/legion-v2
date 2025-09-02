use chacha20poly1305::{ChaCha20Poly1305, Key, Nonce, KeyInit, aead::Aead};
use ed25519_dalek::{SigningKey, VerifyingKey, Signature, Signer, Verifier};
use rand::{rngs::OsRng, RngCore};
use std::time::{SystemTime, UNIX_EPOCH};
use serde::{Serialize, Deserialize};
use zeroize::{Zeroize, ZeroizeOnDrop, Zeroizing};
use std::collections::HashMap;
use std::sync::{Arc, Mutex};
use anyhow::{Result, Context};
use tracing::{info, warn, error, debug};

const ENVELOPE_VERSION: u8 = 2;
const MAX_PROOF_SIZE: usize = 5 * 1024 * 1024;
const COMPRESSION_THRESHOLD: usize = 1024;
const TAMPER_DETECTION_SIZE: usize = 64;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum CompressionType {
    None,
    Zstd,
    Lz4,
}

#[derive(Debug, Clone, Serialize, Deserialize, ZeroizeOnDrop)]
pub struct EnhancedProofMetadata {
    pub version: u8,
    pub proof_id: [u8; 32],
    pub original_size: usize,
    pub compressed_size: usize,
    pub compression_type: CompressionType,
    pub encryption_layers: u8,
    pub integrity_hashes: Vec<[u8; 32]>,
    pub tamper_detection: [u8; TAMPER_DETECTION_SIZE],
    pub security_level: u8,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct SecureProofEnvelope {
    pub metadata: Option<EnhancedProofMetadata>,
    pub encrypted_proof: Vec<u8>,
    pub server_signature: [u8; 64],
    pub session_binding: [u8; 32],
    pub timestamp: u64,
    pub nonce: [u8; 12],
    pub witness_commitment: Option<[u8; 32]>,
    pub public_inputs_hash: Option<[u8; 32]>,
}

impl SecureProofEnvelope {
    pub fn seal(
        proof: &[u8],
        session_key: &[u8; 32],
        server_sk: &SigningKey,
        session_id: &[u8; 32]
    ) -> Result<Self> {
        Self::seal_enhanced(proof, session_key, server_sk, session_id, 128, CompressionType::Zstd)
    }
    
    pub fn seal_enhanced(
        proof: &[u8],
        session_key: &[u8; 32],
        server_sk: &SigningKey,
        session_id: &[u8; 32],
        security_level: u8,
        compression: CompressionType
    ) -> Result<Self> {
        if proof.len() > MAX_PROOF_SIZE {
            return Err(anyhow::anyhow!("Proof size exceeds maximum"));
        }
        
        let timestamp = SystemTime::now().duration_since(UNIX_EPOCH)
            .context("Invalid timestamp")?
            .as_secs();
        
        // Generate nonce
        let mut nonce_bytes = [0u8; 12];
        OsRng.fill_bytes(&mut nonce_bytes);
        let nonce = Nonce::from_slice(&nonce_bytes);
        
        // Create session binding
        let mut hasher = blake3::Hasher::new();
        hasher.update(b"LEGION_PROOF_BINDING_V1");
        hasher.update(session_id);
        hasher.update(&timestamp.to_le_bytes());
        let session_binding = *hasher.finalize().as_bytes();
        
        // Build AAD for proof encryption
        let mut aad = Vec::new();
        aad.extend_from_slice(session_id);
        aad.extend_from_slice(&session_binding);
        aad.extend_from_slice(&timestamp.to_le_bytes());
        
        // Encrypt proof
        let cipher = ChaCha20Poly1305::new(Key::from_slice(session_key));
        let encrypted_proof = cipher.encrypt(nonce, &*proof)
            .map_err(|_| anyhow::anyhow!("Proof encryption failed"))?;
        
        // Sign the envelope
        let mut sig_data = Vec::new();
        sig_data.extend_from_slice(&encrypted_proof);
        sig_data.extend_from_slice(&session_binding);
        sig_data.extend_from_slice(&timestamp.to_le_bytes());
        
        let signature = server_sk.sign(&sig_data);
        
        debug!("Sealed proof envelope for session {}", hex::encode(&session_id[..8]));
        
        Ok(Self {
            metadata: None,
            encrypted_proof,
            server_signature: signature.to_bytes(),
            session_binding,
            timestamp,
            nonce: nonce_bytes,
            witness_commitment: None,
            public_inputs_hash: None,
        })
    }
    
    pub fn verify_and_open(
        &self,
        session_key: &[u8; 32],
        server_pk: &VerifyingKey,
        session_id: &[u8; 32]
    ) -> Result<Vec<u8>> {
        // Verify timestamp (5 minute window)
        let now = SystemTime::now().duration_since(UNIX_EPOCH)
            .context("Invalid current time")?
            .as_secs();
        
        if now.saturating_sub(self.timestamp) > 300 {
            return Err(anyhow::anyhow!("Proof envelope expired"));
        }
        
        // Verify session binding
        let mut hasher = blake3::Hasher::new();
        hasher.update(b"LEGION_PROOF_BINDING_V1");
        hasher.update(session_id);
        hasher.update(&self.timestamp.to_le_bytes());
        let expected_binding = hasher.finalize();
        
        if expected_binding.as_bytes() != &self.session_binding {
            return Err(anyhow::anyhow!("Invalid session binding"));
        }
        
        // Verify server signature
        let mut sig_data = Vec::new();
        sig_data.extend_from_slice(&self.encrypted_proof);
        sig_data.extend_from_slice(&self.session_binding);
        sig_data.extend_from_slice(&self.timestamp.to_le_bytes());
        
        let signature = Signature::from_bytes(&self.server_signature)
            .context("Invalid signature format")?;
        
        server_pk.verify(&sig_data, &signature)
            .context("Signature verification failed")?;
        
        // Decrypt proof
        let cipher = ChaCha20Poly1305::new(Key::from_slice(session_key));
        let nonce = Nonce::from_slice(&self.nonce);
        
        let decrypted = cipher.decrypt(nonce, &*self.encrypted_proof)
            .map_err(|_| anyhow::anyhow!("Proof decryption failed"))?;
        
        debug!("Verified and opened proof envelope for session {}", hex::encode(&session_id[..8]));
        Ok(decrypted)
    }
    
    pub fn create_enhanced(
        proof: &[u8],
        session_key: &[u8; 32],
        server_sk: &SigningKey,
        session_id: &[u8; 32],
        witness_commitment: [u8; 32],
        public_inputs_hash: [u8; 32],
        security_level: u8
    ) -> Result<Self> {
        let mut envelope = Self::seal_enhanced(
            proof, session_key, server_sk, session_id, security_level, CompressionType::Zstd
        )?;
        
        envelope.witness_commitment = Some(witness_commitment);
        envelope.public_inputs_hash = Some(public_inputs_hash);
        
        // Generate proof ID
        let mut proof_id_hasher = blake3::Hasher::new();
        proof_id_hasher.update(b"LEGION_PROOF_ID_V2");
        proof_id_hasher.update(proof);
        proof_id_hasher.update(&witness_commitment);
        proof_id_hasher.update(&public_inputs_hash);
        let proof_id = *proof_id_hasher.finalize().as_bytes();
        
        // Generate tamper detection
        let mut tamper_hasher = blake3::Hasher::new();
        tamper_hasher.update(b"LEGION_TAMPER_DETECTION_V2");
        tamper_hasher.update(&envelope.encrypted_proof);
        tamper_hasher.update(&witness_commitment);
        tamper_hasher.update(&public_inputs_hash);
        tamper_hasher.update(session_key);
        
        let mut tamper_detection = [0u8; TAMPER_DETECTION_SIZE];
        let mut reader = tamper_hasher.finalize_xof();
        reader.fill(&mut tamper_detection);
        
        envelope.metadata = Some(EnhancedProofMetadata {
            version: ENVELOPE_VERSION,
            proof_id,
            original_size: proof.len(),
            compressed_size: proof.len(), // No compression in this example
            compression_type: CompressionType::None,
            encryption_layers: 1,
            integrity_hashes: vec![*blake3::hash(&envelope.encrypted_proof).as_bytes()],
            tamper_detection,
            security_level,
        });
        
        info!("Created enhanced proof envelope with ID {}", hex::encode(&proof_id[..8]));
        Ok(envelope)
    }
    
    pub fn validate_enhanced(&self, session_key: &[u8; 32]) -> Result<bool> {
        let metadata = self.metadata.as_ref()
            .ok_or_else(|| anyhow::anyhow!("No metadata in envelope"))?;
        
        // Validate version
        if metadata.version != ENVELOPE_VERSION {
            return Err(anyhow::anyhow!("Unsupported envelope version"));
        }
        
        // Validate integrity hashes
        if !metadata.integrity_hashes.is_empty() {
            let computed_hash = *blake3::hash(&self.encrypted_proof).as_bytes();
            if computed_hash != metadata.integrity_hashes[0] {
                return Err(anyhow::anyhow!("Integrity hash validation failed"));
            }
        }
        
        // Validate tamper detection if witness commitment is available
        if let Some(witness_commitment) = &self.witness_commitment {
            if let Some(public_inputs_hash) = &self.public_inputs_hash {
                let mut tamper_hasher = blake3::Hasher::new();
                tamper_hasher.update(b"LEGION_TAMPER_DETECTION_V2");
                tamper_hasher.update(&self.encrypted_proof);
                tamper_hasher.update(witness_commitment);
                tamper_hasher.update(public_inputs_hash);
                tamper_hasher.update(session_key);
                
                let mut expected_tamper = [0u8; TAMPER_DETECTION_SIZE];
                let mut reader = tamper_hasher.finalize_xof();
                reader.fill(&mut expected_tamper);
                
                if expected_tamper != metadata.tamper_detection {
                    return Err(anyhow::anyhow!("Tamper detection failed"));
                }
            }
        }
        
        Ok(true)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use ed25519_dalek::SigningKey;
    use rand::rngs::OsRng;
    
    #[test]
    fn test_proof_envelope_roundtrip() -> Result<()> {
        let mut rng = OsRng;
        let signing_key = SigningKey::generate(&mut rng);
        let verifying_key = signing_key.verifying_key();
        
        let session_key = [0x42u8; 32];
        let session_id = [0x01u8; 32];
        let proof_data = b"test_proof_data_12345";
        
        let envelope = SecureProofEnvelope::seal(
            proof_data,
            &session_key,
            &signing_key,
            &session_id
        )?;
        
        let decrypted = envelope.verify_and_open(
            &session_key,
            &verifying_key,
            &session_id
        )?;
        
        assert_eq!(proof_data, &decrypted[..]);
        Ok(())
    }
    
    #[test]
    fn test_tampered_envelope_fails() -> Result<()> {
        let mut rng = OsRng;
        let signing_key = SigningKey::generate(&mut rng);
        let verifying_key = signing_key.verifying_key();
        
        let session_key = [0x42u8; 32];
        let session_id = [0x01u8; 32];
        let proof_data = b"test_proof_data";
        
        let mut envelope = SecureProofEnvelope::seal(
            proof_data,
            &session_key,
            &signing_key,
            &session_id
        )?;
        
        // Tamper with encrypted proof
        envelope.encrypted_proof[0] ^= 0x01;
        
        let result = envelope.verify_and_open(
            &session_key,
            &verifying_key,
            &session_id
        );
        
        assert!(result.is_err());
        Ok(())
    }
    
    #[test]
    fn test_enhanced_envelope() -> Result<()> {
        let mut rng = OsRng;
        let signing_key = SigningKey::generate(&mut rng);
        
        let session_key = [0x42u8; 32];
        let session_id = [0x01u8; 32];
        let proof_data = b"test_proof_data_enhanced";
        let witness_commitment = [0x11u8; 32];
        let public_inputs_hash = [0x22u8; 32];
        
        let envelope = SecureProofEnvelope::create_enhanced(
            proof_data,
            &session_key,
            &signing_key,
            &session_id,
            witness_commitment,
            public_inputs_hash,
            128
        )?;
        
        assert!(envelope.validate_enhanced(&session_key)?);
        assert!(envelope.metadata.is_some());
        assert!(envelope.witness_commitment.is_some());
        assert!(envelope.public_inputs_hash.is_some());
        
        Ok(())
    }
}