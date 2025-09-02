use chacha20poly1305::{ChaCha20Poly1305, Key, Nonce, KeyInit, aead::{Aead, OsRng}};
use blake3;
use std::time::{SystemTime, UNIX_EPOCH};
use serde::{Serialize, Deserialize};
use zeroize::{Zeroize, ZeroizeOnDrop, Zeroizing};
use rand::RngCore;
use std::collections::HashMap;
use std::sync::{Arc, Mutex, RwLock};
use anyhow::{Result, Context};
use tracing::{info, warn, error, debug};
use std::io::{Read, Write};

// Multi-layer proof protection constants
const ENVELOPE_VERSION: u8 = 3;
const MAX_PROOF_SIZE: usize = 10 * 1024 * 1024; // 10MB
const ENCRYPTION_LAYERS: usize = 3;
const INTEGRITY_HASH_SIZE: usize = 32;
const TAMPER_DETECTION_SIZE: usize = 64;
const COMPRESSION_THRESHOLD: usize = 1024;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum ProofEncryptionAlgorithm {
    ChaCha20Poly1305,
    AES256GCM,
    XChaCha20Poly1305,
    QuantumResistant,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum CompressionAlgorithm {
    None,
    Zstd,
    Lz4,
    Brotli,
}

#[derive(Debug, Clone, Serialize, Deserialize, ZeroizeOnDrop)]
pub struct ProofEnvelopeMetadata {
    pub version: u8,
    pub proof_id: [u8; 32],
    pub original_size: usize,
    pub compressed_size: usize,
    pub encryption_layers: Vec<EncryptionLayer>,
    pub compression_algorithm: CompressionAlgorithm,
    pub creation_timestamp: u64,
    pub expiry_timestamp: u64,
    pub security_level: u8,
    pub integrity_hashes: Vec<[u8; 32]>,
    pub tamper_detection: [u8; TAMPER_DETECTION_SIZE],
}

#[derive(Debug, Clone, Serialize, Deserialize, ZeroizeOnDrop)]
pub struct EncryptionLayer {
    pub algorithm: ProofEncryptionAlgorithm,
    pub key_derivation_info: KeyDerivationInfo,
    pub nonce: [u8; 12],
    pub layer_hash: [u8; 32],
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct KeyDerivationInfo {
    pub salt: [u8; 32],
    pub iterations: u32,
    pub context: String,
    pub key_id: [u8; 16],
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SecureProofEnvelope {
    pub metadata: ProofEnvelopeMetadata,
    pub encrypted_proof: Vec<u8>,
    pub signature: Vec<u8>,
    pub witness_commitment: [u8; 32],
    pub public_inputs_hash: [u8; 32],
}

#[derive(Debug)]
pub struct EnterpriseProofProtector {
    master_key: Zeroizing<[u8; 32]>,
    signing_key: Zeroizing<ed25519_dalek::SigningKey>,
    verifying_key: ed25519_dalek::VerifyingKey,
    envelope_cache: Arc<RwLock<HashMap<[u8; 32], SecureProofEnvelope>>>,
    compression_stats: Arc<Mutex<CompressionStatistics>>,
    security_monitor: Arc<Mutex<SecurityMonitor>>,
}

#[derive(Debug, Clone)]
struct CompressionStatistics {
    total_proofs_processed: u64,
    total_bytes_saved: u64,
    avg_compression_ratio: f64,
    compression_times_ms: Vec<u64>,
}

#[derive(Debug, Clone)]
struct SecurityMonitor {
    tamper_attempts: u64,
    decryption_failures: u64,
    integrity_violations: u64,
    suspicious_access_patterns: Vec<SuspiciousAccess>,
}

#[derive(Debug, Clone)]
struct SuspiciousAccess {
    timestamp: SystemTime,
    proof_id: [u8; 32],
    access_type: String,
    threat_level: u8,
}

impl EnterpriseProofProtector {
    pub fn new() -> Result<Self> {
        let mut master_key = Zeroizing::new([0u8; 32]);
        OsRng.fill_bytes(&mut *master_key);
        
        let mut signing_key_bytes = Zeroizing::new([0u8; 32]);
        OsRng.fill_bytes(&mut *signing_key_bytes);
        let signing_key = Zeroizing::new(ed25519_dalek::SigningKey::from_bytes(&signing_key_bytes));
        let verifying_key = signing_key.verifying_key();
        
        Ok(Self {
            master_key,
            signing_key,
            verifying_key,
            envelope_cache: Arc::new(RwLock::new(HashMap::with_capacity(1000))),
            compression_stats: Arc::new(Mutex::new(CompressionStatistics {
                total_proofs_processed: 0,
                total_bytes_saved: 0,
                avg_compression_ratio: 1.0,
                compression_times_ms: Vec::with_capacity(1000),
            })),
            security_monitor: Arc::new(Mutex::new(SecurityMonitor {
                tamper_attempts: 0,
                decryption_failures: 0,
                integrity_violations: 0,
                suspicious_access_patterns: Vec::new(),
            })),
        })
    }
    
    pub fn protect_proof(
        &self,
        proof_data: &[u8],
        public_inputs: &[halo2curves::pasta::Fp],
        security_level: u8,
        compression: CompressionAlgorithm,
    ) -> Result<SecureProofEnvelope> {
        if proof_data.len() > MAX_PROOF_SIZE {
            return Err(anyhow::anyhow!("Proof size exceeds maximum allowed"));
        }
        
        let start_time = std::time::Instant::now();
        
        // Generate unique proof ID
        let proof_id = self.generate_proof_id(proof_data, public_inputs)?;
        
        // Compress proof if beneficial
        let (compressed_data, compression_ratio) = self.compress_proof(proof_data, &compression)?;
        
        // Generate witness commitment
        let witness_commitment = self.generate_witness_commitment(proof_data, public_inputs)?;
        
        // Hash public inputs
        let public_inputs_hash = self.hash_public_inputs(public_inputs)?;
        
        // Multi-layer encryption
        let (encrypted_proof, encryption_layers) = self.apply_multi_layer_encryption(
            &compressed_data,
            security_level,
            &proof_id
        )?;
        
        // Generate integrity hashes for each layer
        let integrity_hashes = self.generate_integrity_hashes(&encrypted_proof, &encryption_layers)?;
        
        // Generate tamper detection data
        let tamper_detection = self.generate_tamper_detection(
            &encrypted_proof,
            &witness_commitment,
            &public_inputs_hash
        )?;
        
        let now = SystemTime::now().duration_since(UNIX_EPOCH)
            .context("System time error")?
            .as_secs();
        
        let metadata = ProofEnvelopeMetadata {
            version: ENVELOPE_VERSION,
            proof_id,
            original_size: proof_data.len(),
            compressed_size: compressed_data.len(),
            encryption_layers,
            compression_algorithm: compression,
            creation_timestamp: now,
            expiry_timestamp: now + 86400, // 24 hours
            security_level,
            integrity_hashes,
            tamper_detection,
        };
        
        // Sign the envelope
        let signature = self.sign_envelope(&metadata, &encrypted_proof)?;
        
        let envelope = SecureProofEnvelope {
            metadata,
            encrypted_proof,
            signature,
            witness_commitment,
            public_inputs_hash,
        };
        
        // Update statistics
        self.update_compression_stats(compression_ratio, start_time.elapsed().as_millis() as u64)?;
        
        // Cache envelope
        self.cache_envelope(&proof_id, &envelope)?;
        
        info!("Protected proof {} with {} layers", hex::encode(&proof_id[..8]), envelope.metadata.encryption_layers.len());
        Ok(envelope)
    }
    
    pub fn unprotect_proof(
        &self,
        envelope: &SecureProofEnvelope,
        expected_public_inputs: &[halo2curves::pasta::Fp],
    ) -> Result<Vec<u8>> {
        // Validate envelope integrity
        self.validate_envelope_integrity(envelope)?;
        
        // Verify signature
        self.verify_envelope_signature(envelope)?;
        
        // Check expiry
        let now = SystemTime::now().duration_since(UNIX_EPOCH)
            .context("System time error")?
            .as_secs();
        if now > envelope.metadata.expiry_timestamp {
            return Err(anyhow::anyhow!("Proof envelope has expired"));
        }
        
        // Verify public inputs hash
        let expected_hash = self.hash_public_inputs(expected_public_inputs)?;
        if expected_hash != envelope.public_inputs_hash {
            self.record_security_violation("public_inputs_mismatch", &envelope.metadata.proof_id)?;
            return Err(anyhow::anyhow!("Public inputs hash mismatch"));
        }
        
        // Multi-layer decryption
        let decrypted_data = self.decrypt_multi_layer(
            &envelope.encrypted_proof,
            &envelope.metadata.encryption_layers,
            &envelope.metadata.proof_id
        )?;
        
        // Decompress if needed
        let original_proof = self.decompress_proof(
            &decrypted_data,
            &envelope.metadata.compression_algorithm
        )?;
        
        // Verify witness commitment
        let computed_commitment = self.generate_witness_commitment(&original_proof, expected_public_inputs)?;
        if computed_commitment != envelope.witness_commitment {
            self.record_security_violation("witness_commitment_mismatch", &envelope.metadata.proof_id)?;
            return Err(anyhow::anyhow!("Witness commitment verification failed"));
        }
        
        // Validate original size
        if original_proof.len() != envelope.metadata.original_size {
            return Err(anyhow::anyhow!("Decompressed proof size mismatch"));
        }
        
        info!("Successfully unprotected proof {}", hex::encode(&envelope.metadata.proof_id[..8]));
        Ok(original_proof)
    }
    
    fn compress_proof(
        &self,
        data: &[u8],
        algorithm: &CompressionAlgorithm,
    ) -> Result<(Vec<u8>, f64)> {
        if data.len() < COMPRESSION_THRESHOLD {
            return Ok((data.to_vec(), 1.0));
        }
        
        let compressed = match algorithm {
            CompressionAlgorithm::None => data.to_vec(),
            CompressionAlgorithm::Zstd => {
                zstd::bulk::compress(data, 3)
                    .context("Zstd compression failed")?
            }
            CompressionAlgorithm::Lz4 => {
                lz4_flex::compress_prepend_size(data)
            }
            CompressionAlgorithm::Brotli => {
                let mut compressed = Vec::new();
                let mut writer = brotli::CompressorWriter::new(&mut compressed, 4096, 6, 22);
                writer.write_all(data)
                    .context("Brotli compression failed")?;
                drop(writer);
                compressed
            }
        };
        
        let ratio = data.len() as f64 / compressed.len() as f64;
        Ok((compressed, ratio))
    }
    
    fn decompress_proof(
        &self,
        data: &[u8],
        algorithm: &CompressionAlgorithm,
    ) -> Result<Vec<u8>> {
        match algorithm {
            CompressionAlgorithm::None => Ok(data.to_vec()),
            CompressionAlgorithm::Zstd => {
                zstd::bulk::decompress(data, MAX_PROOF_SIZE)
                    .context("Zstd decompression failed")
            }
            CompressionAlgorithm::Lz4 => {
                lz4_flex::decompress_size_prepended(data)
                    .context("Lz4 decompression failed")
            }
            CompressionAlgorithm::Brotli => {
                let mut decompressed = Vec::new();
                let mut reader = brotli::Decompressor::new(data, 4096);
                reader.read_to_end(&mut decompressed)
                    .context("Brotli decompression failed")?;
                Ok(decompressed)
            }
        }
    }
    
    fn apply_multi_layer_encryption(
        &self,
        data: &[u8],
        security_level: u8,
        proof_id: &[u8; 32],
    ) -> Result<(Vec<u8>, Vec<EncryptionLayer>)> {
        let layers = match security_level {
            0..=64 => 1,
            65..=128 => 2,
            _ => 3,
        };
        
        let mut current_data = data.to_vec();
        let mut encryption_layers = Vec::with_capacity(layers);
        
        for layer in 0..layers {
            let (encrypted, layer_info) = self.encrypt_layer(
                &current_data,
                layer,
                proof_id,
                security_level
            )?;
            
            current_data = encrypted;
            encryption_layers.push(layer_info);
        }
        
        Ok((current_data, encryption_layers))
    }
    
    fn encrypt_layer(
        &self,
        data: &[u8],
        layer_index: usize,
        proof_id: &[u8; 32],
        security_level: u8,
    ) -> Result<(Vec<u8>, EncryptionLayer)> {
        let mut salt = [0u8; 32];
        OsRng.fill_bytes(&mut salt);
        
        let mut key_id = [0u8; 16];
        OsRng.fill_bytes(&mut key_id);
        
        // Derive layer-specific key
        let layer_key = self.derive_layer_key(&salt, proof_id, layer_index, security_level)?;
        
        let mut nonce_bytes = [0u8; 12];
        OsRng.fill_bytes(&mut nonce_bytes);
        let nonce = Nonce::from_slice(&nonce_bytes);
        
        // Encrypt with ChaCha20Poly1305
        let cipher = ChaCha20Poly1305::new(Key::from_slice(&layer_key));
        let encrypted = cipher.encrypt(nonce, data)
            .map_err(|_| anyhow::anyhow!("Layer encryption failed"))?;
        
        // Generate layer hash
        let layer_hash = blake3::hash(&encrypted);
        
        let layer_info = EncryptionLayer {
            algorithm: ProofEncryptionAlgorithm::ChaCha20Poly1305,
            key_derivation_info: KeyDerivationInfo {
                salt,
                iterations: 100000 + (security_level as u32 * 1000),
                context: format!("LEGION_LAYER_{}", layer_index),
                key_id,
            },
            nonce: nonce_bytes,
            layer_hash: *layer_hash.as_bytes(),
        };
        
        Ok((encrypted, layer_info))
    }
    
    fn decrypt_multi_layer(
        &self,
        encrypted_data: &[u8],
        layers: &[EncryptionLayer],
        proof_id: &[u8; 32],
    ) -> Result<Vec<u8>> {
        let mut current_data = encrypted_data.to_vec();
        
        // Decrypt in reverse order
        for (layer_index, layer) in layers.iter().enumerate().rev() {
            // Verify layer hash
            let computed_hash = blake3::hash(&current_data);
            if computed_hash.as_bytes() != &layer.layer_hash {
                self.record_security_violation("layer_hash_mismatch", proof_id)?;
                return Err(anyhow::anyhow!("Layer integrity check failed"));
            }
            
            // Derive decryption key
            let layer_key = self.derive_layer_key(
                &layer.key_derivation_info.salt,
                proof_id,
                layer_index,
                128 // Use max security for decryption
            )?;
            
            // Decrypt layer
            let cipher = ChaCha20Poly1305::new(Key::from_slice(&layer_key));
            let nonce = Nonce::from_slice(&layer.nonce);
            
            current_data = cipher.decrypt(nonce, current_data.as_slice())
                .map_err(|_| {
                    let _ = self.record_security_violation("decryption_failure", proof_id);
                    anyhow::anyhow!("Layer decryption failed")
                })?;
        }
        
        Ok(current_data)
    }
    
    fn derive_layer_key(
        &self,
        salt: &[u8; 32],
        proof_id: &[u8; 32],
        layer_index: usize,
        security_level: u8,
    ) -> Result<[u8; 32]> {
        let mut hasher = blake3::Hasher::new();
        hasher.update(b"LEGION_LAYER_KEY_V3");
        hasher.update(&*self.master_key);
        hasher.update(salt);
        hasher.update(proof_id);
        hasher.update(&layer_index.to_le_bytes());
        hasher.update(&security_level.to_le_bytes());
        
        Ok(*hasher.finalize().as_bytes())
    }
    
    fn generate_proof_id(
        &self,
        proof_data: &[u8],
        public_inputs: &[halo2curves::pasta::Fp],
    ) -> Result<[u8; 32]> {
        let mut hasher = blake3::Hasher::new();
        hasher.update(b"LEGION_PROOF_ID_V3");
        hasher.update(proof_data);
        
        for input in public_inputs {
            hasher.update(&input.to_repr());
        }
        
        hasher.update(&SystemTime::now().duration_since(UNIX_EPOCH)
            .context("System time error")?
            .as_nanos().to_le_bytes());
        
        Ok(*hasher.finalize().as_bytes())
    }
    
    fn generate_witness_commitment(
        &self,
        proof_data: &[u8],
        public_inputs: &[halo2curves::pasta::Fp],
    ) -> Result<[u8; 32]> {
        let mut hasher = blake3::Hasher::new();
        hasher.update(b"LEGION_WITNESS_COMMITMENT_V3");
        hasher.update(proof_data);
        
        for input in public_inputs {
            hasher.update(&input.to_repr());
        }
        
        Ok(*hasher.finalize().as_bytes())
    }
    
    fn hash_public_inputs(
        &self,
        public_inputs: &[halo2curves::pasta::Fp],
    ) -> Result<[u8; 32]> {
        let mut hasher = blake3::Hasher::new();
        hasher.update(b"LEGION_PUBLIC_INPUTS_V3");
        
        for input in public_inputs {
            hasher.update(&input.to_repr());
        }
        
        Ok(*hasher.finalize().as_bytes())
    }
    
    fn generate_integrity_hashes(
        &self,
        encrypted_data: &[u8],
        layers: &[EncryptionLayer],
    ) -> Result<Vec<[u8; 32]>> {
        let mut hashes = Vec::with_capacity(layers.len() + 1);
        
        // Hash of final encrypted data
        hashes.push(*blake3::hash(encrypted_data).as_bytes());
        
        // Hash of each layer metadata
        for layer in layers {
            let layer_bytes = bincode::serialize(layer)
                .context("Layer serialization failed")?;
            hashes.push(*blake3::hash(&layer_bytes).as_bytes());
        }
        
        Ok(hashes)
    }
    
    fn generate_tamper_detection(
        &self,
        encrypted_proof: &[u8],
        witness_commitment: &[u8; 32],
        public_inputs_hash: &[u8; 32],
    ) -> Result<[u8; TAMPER_DETECTION_SIZE]> {
        let mut hasher = blake3::Hasher::new();
        hasher.update(b"LEGION_TAMPER_DETECTION_V3");
        hasher.update(encrypted_proof);
        hasher.update(witness_commitment);
        hasher.update(public_inputs_hash);
        hasher.update(&*self.master_key);
        
        let mut detection_data = [0u8; TAMPER_DETECTION_SIZE];
        let mut reader = hasher.finalize_xof();
        reader.fill(&mut detection_data);
        
        Ok(detection_data)
    }
    
    fn sign_envelope(
        &self,
        metadata: &ProofEnvelopeMetadata,
        encrypted_proof: &[u8],
    ) -> Result<Vec<u8>> {
        let metadata_bytes = bincode::serialize(metadata)
            .context("Metadata serialization failed")?;
        
        let mut data_to_sign = Vec::with_capacity(metadata_bytes.len() + encrypted_proof.len());
        data_to_sign.extend_from_slice(&metadata_bytes);
        data_to_sign.extend_from_slice(encrypted_proof);
        
        use ed25519_dalek::Signer;
        let signature = self.signing_key.sign(&data_to_sign);
        
        Ok(signature.to_bytes().to_vec())
    }
    
    fn verify_envelope_signature(
        &self,
        envelope: &SecureProofEnvelope,
    ) -> Result<()> {
        let metadata_bytes = bincode::serialize(&envelope.metadata)
            .context("Metadata serialization failed")?;
        
        let mut data_to_verify = Vec::with_capacity(metadata_bytes.len() + envelope.encrypted_proof.len());
        data_to_verify.extend_from_slice(&metadata_bytes);
        data_to_verify.extend_from_slice(&envelope.encrypted_proof);
        
        if envelope.signature.len() != 64 {
            return Err(anyhow::anyhow!("Invalid signature length"));
        }
        
        let signature_bytes: [u8; 64] = envelope.signature.as_slice().try_into()
            .context("Invalid signature format")?;
        
        let signature = ed25519_dalek::Signature::from_bytes(&signature_bytes);
        
        use ed25519_dalek::Verifier;
        self.verifying_key.verify(&data_to_verify, &signature)
            .context("Signature verification failed")?;
        
        Ok(())
    }
    
    fn validate_envelope_integrity(
        &self,
        envelope: &SecureProofEnvelope,
    ) -> Result<()> {
        // Check version
        if envelope.metadata.version != ENVELOPE_VERSION {
            return Err(anyhow::anyhow!("Unsupported envelope version"));
        }
        
        // Validate tamper detection
        let expected_tamper_detection = self.generate_tamper_detection(
            &envelope.encrypted_proof,
            &envelope.witness_commitment,
            &envelope.public_inputs_hash,
        )?;
        
        if expected_tamper_detection != envelope.metadata.tamper_detection {
            self.record_security_violation("tamper_detection_failure", &envelope.metadata.proof_id)?;
            return Err(anyhow::anyhow!("Tamper detection failed"));
        }
        
        // Validate integrity hashes
        let expected_hashes = self.generate_integrity_hashes(
            &envelope.encrypted_proof,
            &envelope.metadata.encryption_layers,
        )?;
        
        if expected_hashes != envelope.metadata.integrity_hashes {
            self.record_security_violation("integrity_hash_mismatch", &envelope.metadata.proof_id)?;
            return Err(anyhow::anyhow!("Integrity hash validation failed"));
        }
        
        Ok(())
    }
    
    fn cache_envelope(
        &self,
        proof_id: &[u8; 32],
        envelope: &SecureProofEnvelope,
    ) -> Result<()> {
        let mut cache = self.envelope_cache.write()
            .map_err(|_| anyhow::anyhow!("Cache lock poisoned"))?;
        
        cache.insert(*proof_id, envelope.clone());
        
        // Limit cache size
        if cache.len() > 1000 {
            let oldest_key = cache.keys().next().copied();
            if let Some(key) = oldest_key {
                cache.remove(&key);
            }
        }
        
        Ok(())
    }
    
    fn update_compression_stats(
        &self,
        compression_ratio: f64,
        processing_time_ms: u64,
    ) -> Result<()> {
        let mut stats = self.compression_stats.lock()
            .map_err(|_| anyhow::anyhow!("Stats lock poisoned"))?;
        
        stats.total_proofs_processed += 1;
        stats.compression_times_ms.push(processing_time_ms);
        
        // Update rolling average
        let total = stats.total_proofs_processed as f64;
        stats.avg_compression_ratio = 
            (stats.avg_compression_ratio * (total - 1.0) + compression_ratio) / total;
        
        // Keep only recent timing data
        if stats.compression_times_ms.len() > 1000 {
            stats.compression_times_ms.remove(0);
        }
        
        Ok(())
    }
    
    fn record_security_violation(
        &self,
        violation_type: &str,
        proof_id: &[u8; 32],
    ) -> Result<()> {
        let mut monitor = self.security_monitor.lock()
            .map_err(|_| anyhow::anyhow!("Security monitor lock poisoned"))?;
        
        match violation_type {
            "tamper_detection_failure" => monitor.tamper_attempts += 1,
            "decryption_failure" => monitor.decryption_failures += 1,
            _ => monitor.integrity_violations += 1,
        }
        
        let suspicious_access = SuspiciousAccess {
            timestamp: SystemTime::now(),
            proof_id: *proof_id,
            access_type: violation_type.to_string(),
            threat_level: match violation_type {
                "tamper_detection_failure" => 9,
                "decryption_failure" => 7,
                _ => 5,
            },
        };
        
        monitor.suspicious_access_patterns.push(suspicious_access);
        
        // Keep only recent violations
        if monitor.suspicious_access_patterns.len() > 1000 {
            monitor.suspicious_access_patterns.remove(0);
        }
        
        warn!("Security violation recorded: {} for proof {}", violation_type, hex::encode(&proof_id[..8]));
        Ok(())
    }
    
    pub fn get_security_statistics(&self) -> Result<SecurityStatistics> {
        let monitor = self.security_monitor.lock()
            .map_err(|_| anyhow::anyhow!("Security monitor lock poisoned"))?;
        let stats = self.compression_stats.lock()
            .map_err(|_| anyhow::anyhow!("Compression stats lock poisoned"))?;
        
        Ok(SecurityStatistics {
            total_proofs_protected: stats.total_proofs_processed,
            tamper_attempts: monitor.tamper_attempts,
            decryption_failures: monitor.decryption_failures,
            integrity_violations: monitor.integrity_violations,
            avg_compression_ratio: stats.avg_compression_ratio,
            suspicious_activities: monitor.suspicious_access_patterns.len() as u64,
        })
    }
}

#[derive(Debug, Clone)]
pub struct SecurityStatistics {
    pub total_proofs_protected: u64,
    pub tamper_attempts: u64,
    pub decryption_failures: u64,
    pub integrity_violations: u64,
    pub avg_compression_ratio: f64,
    pub suspicious_activities: u64,
}

#[cfg(test)]
mod tests {
    use super::*;
    use halo2curves::pasta::Fp;
    
    #[test]
    fn test_proof_protection_and_recovery() -> Result<()> {
        let protector = EnterpriseProofProtector::new()?;
        let proof_data = vec![1, 2, 3, 4, 5];
        let public_inputs = vec![Fp::from(42u64), Fp::from(84u64)];
        
        let envelope = protector.protect_proof(
            &proof_data,
            &public_inputs,
            128,
            CompressionAlgorithm::Zstd,
        )?;
        
        let recovered = protector.unprotect_proof(&envelope, &public_inputs)?;
        assert_eq!(proof_data, recovered);
        
        Ok(())
    }
    
    #[test]
    fn test_multi_layer_encryption() -> Result<()> {
        let protector = EnterpriseProofProtector::new()?;
        let data = vec![0u8; 1000];
        let proof_id = [42u8; 32];
        
        let (encrypted, layers) = protector.apply_multi_layer_encryption(&data, 200, &proof_id)?;
        assert_eq!(layers.len(), 3); // High security = 3 layers
        
        let decrypted = protector.decrypt_multi_layer(&encrypted, &layers, &proof_id)?;
        assert_eq!(data, decrypted);
        
        Ok(())
    }
}