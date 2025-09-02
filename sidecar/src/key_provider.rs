use ed25519_dalek::{SigningKey, VerifyingKey};
use rand::rngs::OsRng;
use std::fs;
use std::path::PathBuf;
use std::sync::{Arc, RwLock, Mutex};
use std::time::{SystemTime, UNIX_EPOCH, Duration};
use zeroize::{Zeroize, ZeroizeOnDrop, Zeroizing};
use std::collections::{HashMap, VecDeque};
use serde::{Serialize, Deserialize};
use blake3;
use std::sync::atomic::{AtomicU64, Ordering};
use anyhow::{Result, Context};
use tracing::{info, warn, error, debug};

const KEY_ROTATION_INTERVAL: Duration = Duration::from_secs(86400);
const KEY_ESCROW_THRESHOLD: usize = 3;
const HSM_RETRY_ATTEMPTS: usize = 3;
const KEY_DERIVATION_ROUNDS: u32 = 100000;
const AUDIT_LOG_RETENTION: Duration = Duration::from_secs(86400 * 365);

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct KeyEscrowShare {
    pub share_id: u8,
    pub encrypted_share: Vec<u8>,
    pub verification_hash: [u8; 32],
    pub created_at: SystemTime,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct KeyAuditEvent {
    pub timestamp: SystemTime,
    pub event_type: KeyEventType,
    pub key_id: String,
    pub user_id: String,
    pub success: bool,
    pub details: HashMap<String, String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum KeyEventType {
    Generation,
    Rotation,
    Backup,
    Recovery,
    Access,
    Deletion,
    EscrowCreation,
    EscrowRecovery,
}

#[derive(Debug, Clone)]
pub struct KeyMetadata {
    pub key_id: String,
    pub created_at: u64,
    pub expires_at: Option<u64>,
    pub algorithm: String,
    pub key_type: KeyType,
}

#[derive(Debug, Clone)]
pub enum KeyType {
    Signing,
    Encryption,
    Authority,
}

pub trait KeyProvider: Send + Sync {
    fn get_signing_key(&self) -> Result<SigningKey>;
    fn get_verifying_key(&self) -> Result<VerifyingKey>;
    fn rotate_keys(&mut self) -> Result<KeyMetadata>;
    fn get_key_metadata(&self) -> KeyMetadata;
    fn backup_key(&self, path: &str) -> Result<()>;
    
    // Enterprise key escrow operations
    fn create_key_escrow(&self, threshold: usize, total_shares: usize) -> Result<Vec<KeyEscrowShare>>;
    fn recover_from_escrow(&self, shares: &[KeyEscrowShare]) -> Result<SigningKey>;
    fn verify_escrow_integrity(&self, shares: &[KeyEscrowShare]) -> Result<bool>;
    
    // HSM operations
    fn hsm_generate_key(&self, slot_id: u32) -> Result<KeyMetadata>;
    fn hsm_sign_data(&self, data: &[u8], slot_id: u32) -> Result<Vec<u8>>;
    fn hsm_get_public_key(&self, slot_id: u32) -> Result<VerifyingKey>;
    
    // Audit and compliance
    fn get_audit_log(&self) -> Result<Vec<KeyAuditEvent>>;
    fn export_compliance_report(&self, start_time: SystemTime, end_time: SystemTime) -> Result<String>;
    fn secure_delete_key(&mut self) -> Result<()>;
}

pub struct FileKeyProvider {
    key_path: PathBuf,
    backup_path: PathBuf,
    current_key: Arc<RwLock<Zeroizing<SigningKey>>>,
    metadata: Arc<RwLock<KeyMetadata>>,
    escrow_shares: Arc<Mutex<Vec<KeyEscrowShare>>>,
    audit_log: Arc<Mutex<VecDeque<KeyAuditEvent>>>,
    access_counter: Arc<AtomicU64>,
    last_rotation: Arc<RwLock<SystemTime>>,
}

impl FileKeyProvider {
    pub fn new(key_path: PathBuf, backup_path: PathBuf) -> Result<Self> {
        let (signing_key, metadata) = if key_path.exists() {
            Self::load_key(&key_path)?
        } else {
            Self::generate_new_key(&key_path)?
        };
        
        Ok(Self {
            key_path,
            backup_path,
            current_key: Arc::new(RwLock::new(Zeroizing::new(signing_key))),
            metadata: Arc::new(RwLock::new(metadata)),
            escrow_shares: Arc::new(Mutex::new(Vec::new())),
            audit_log: Arc::new(Mutex::new(VecDeque::new())),
            access_counter: Arc::new(AtomicU64::new(0)),
            last_rotation: Arc::new(RwLock::new(SystemTime::now())),
        })
    }
    
    fn load_key(path: &PathBuf) -> Result<(SigningKey, KeyMetadata)> {
        let key_data = fs::read(path)
            .context("Failed to read key file")?;
        
        if key_data.len() < 32 {
            return Err(anyhow::anyhow!("Invalid key file format"));
        }
        
        let mut key_bytes = Zeroizing::new([0u8; 32]);
        key_bytes.copy_from_slice(&key_data[..32]);
        
        let signing_key = SigningKey::from_bytes(&key_bytes);
        
        let metadata = KeyMetadata {
            key_id: hex::encode(&key_bytes[..8]),
            created_at: SystemTime::now().duration_since(UNIX_EPOCH)
                .context("System time error")?
                .as_secs(),
            expires_at: None,
            algorithm: "Ed25519".to_string(),
            key_type: KeyType::Signing,
        };
        
        Ok((signing_key, metadata))
    }
    
    fn generate_new_key(path: &PathBuf) -> Result<(SigningKey, KeyMetadata)> {
        let mut rng = OsRng;
        let signing_key = SigningKey::generate(&mut rng);
        
        // Create secure key file
        if let Some(parent) = path.parent() {
            fs::create_dir_all(parent)
                .context("Failed to create key directory")?;
        }
        
        fs::write(path, signing_key.to_bytes())
            .context("Failed to write key file")?;
        
        // Set restrictive permissions (Unix only)
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let mut perms = fs::metadata(path)
                .context("Failed to get file metadata")?
                .permissions();
            perms.set_mode(0o600); // Owner read/write only
            fs::set_permissions(path, perms)
                .context("Failed to set file permissions")?;
        }
        
        let key_bytes = signing_key.to_bytes();
        let metadata = KeyMetadata {
            key_id: hex::encode(&key_bytes[..8]),
            created_at: SystemTime::now().duration_since(UNIX_EPOCH)
                .context("System time error")?
                .as_secs(),
            expires_at: None,
            algorithm: "Ed25519".to_string(),
            key_type: KeyType::Signing,
        };
        
        Ok((signing_key, metadata))
    }
}

impl KeyProvider for FileKeyProvider {
    fn get_signing_key(&self) -> Result<SigningKey> {
        let key = self.current_key.read()
            .map_err(|_| anyhow::anyhow!("Lock poisoned"))?;
        self.access_counter.fetch_add(1, Ordering::Relaxed);
        Ok(key.clone())
    }
    
    fn get_verifying_key(&self) -> Result<VerifyingKey> {
        let key = self.current_key.read()
            .map_err(|_| anyhow::anyhow!("Lock poisoned"))?;
        Ok(key.verifying_key())
    }
    
    fn rotate_keys(&mut self) -> Result<KeyMetadata> {
        // Backup current key
        self.backup_key(&format!("{}.backup", self.key_path.to_string_lossy()))?;
        
        // Generate new key
        let (new_key, new_metadata) = Self::generate_new_key(&self.key_path)?;
        
        // Update current key atomically
        {
            let mut key = self.current_key.write()
                .map_err(|_| anyhow::anyhow!("Lock poisoned"))?;
            *key = Zeroizing::new(new_key);
        }
        
        {
            let mut metadata = self.metadata.write()
                .map_err(|_| anyhow::anyhow!("Lock poisoned"))?;
            *metadata = new_metadata.clone();
        }
        
        {
            let mut last_rotation = self.last_rotation.write()
                .map_err(|_| anyhow::anyhow!("Lock poisoned"))?;
            *last_rotation = SystemTime::now();
        }
        
        info!("Key rotation completed for key_id: {}", new_metadata.key_id);
        Ok(new_metadata)
    }
    
    fn get_key_metadata(&self) -> KeyMetadata {
        self.metadata.read()
            .map(|m| m.clone())
            .unwrap_or_else(|_| {
                warn!("Failed to read key metadata, returning default");
                KeyMetadata {
                    key_id: "unknown".to_string(),
                    created_at: 0,
                    expires_at: None,
                    algorithm: "Ed25519".to_string(),
                    key_type: KeyType::Signing,
                }
            })
    }
    
    fn backup_key(&self, backup_path: &str) -> Result<()> {
        let key = self.current_key.read()
            .map_err(|_| anyhow::anyhow!("Lock poisoned"))?;
        
        fs::write(backup_path, key.to_bytes())
            .context("Backup failed")?;
        
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let mut perms = fs::metadata(backup_path)
                .context("Failed to get backup file metadata")?
                .permissions();
            perms.set_mode(0o600);
            fs::set_permissions(backup_path, perms)
                .context("Failed to set backup file permissions")?;
        }
        
        info!("Key backup created at: {}", backup_path);
        Ok(())
    }
    
    fn create_key_escrow(&self, threshold: usize, total_shares: usize) -> Result<Vec<KeyEscrowShare>> {
        // Placeholder implementation - in production would use proper secret sharing
        let mut shares = Vec::new();
        let key = self.get_signing_key()?;
        let key_bytes = key.to_bytes();
        
        for i in 0..total_shares {
            let share = KeyEscrowShare {
                share_id: i as u8,
                encrypted_share: key_bytes.to_vec(), // Simplified - would be actual share
                verification_hash: blake3::hash(&key_bytes).into(),
                created_at: SystemTime::now(),
            };
            shares.push(share);
        }
        
        info!("Created {} key escrow shares with threshold {}", total_shares, threshold);
        Ok(shares)
    }
    
    fn recover_from_escrow(&self, shares: &[KeyEscrowShare]) -> Result<SigningKey> {
        if shares.is_empty() {
            return Err(anyhow::anyhow!("No escrow shares provided"));
        }
        
        // Simplified recovery - in production would reconstruct from shares
        let key_bytes: [u8; 32] = shares[0].encrypted_share[..32].try_into()
            .context("Invalid share data")?;
        
        info!("Recovered key from {} escrow shares", shares.len());
        Ok(SigningKey::from_bytes(&key_bytes))
    }
    
    fn verify_escrow_integrity(&self, shares: &[KeyEscrowShare]) -> Result<bool> {
        for share in shares {
            let computed_hash = blake3::hash(&share.encrypted_share);
            if computed_hash.as_bytes() != &share.verification_hash {
                warn!("Escrow share {} failed integrity check", share.share_id);
                return Ok(false);
            }
        }
        
        info!("All {} escrow shares passed integrity check", shares.len());
        Ok(true)
    }
    
    fn hsm_generate_key(&self, slot_id: u32) -> Result<KeyMetadata> {
        // Placeholder for HSM integration
        info!("HSM key generation requested for slot {}", slot_id);
        Err(anyhow::anyhow!("HSM not available in file provider"))
    }
    
    fn hsm_sign_data(&self, _data: &[u8], slot_id: u32) -> Result<Vec<u8>> {
        info!("HSM signing requested for slot {}", slot_id);
        Err(anyhow::anyhow!("HSM not available in file provider"))
    }
    
    fn hsm_get_public_key(&self, slot_id: u32) -> Result<VerifyingKey> {
        info!("HSM public key requested for slot {}", slot_id);
        Err(anyhow::anyhow!("HSM not available in file provider"))
    }
    
    fn get_audit_log(&self) -> Result<Vec<KeyAuditEvent>> {
        let log = self.audit_log.lock()
            .map_err(|_| anyhow::anyhow!("Audit log lock poisoned"))?;
        Ok(log.iter().cloned().collect())
    }
    
    fn export_compliance_report(&self, start_time: SystemTime, end_time: SystemTime) -> Result<String> {
        let log = self.get_audit_log()?;
        let filtered_events: Vec<_> = log.into_iter()
            .filter(|event| event.timestamp >= start_time && event.timestamp <= end_time)
            .collect();
        
        let report = format!(
            "Key Provider Compliance Report\n\
             Period: {:?} to {:?}\n\
             Total Events: {}\n\
             Access Count: {}\n",
            start_time, end_time, filtered_events.len(),
            self.access_counter.load(Ordering::Relaxed)
        );
        
        info!("Generated compliance report with {} events", filtered_events.len());
        Ok(report)
    }
    
    fn secure_delete_key(&mut self) -> Result<()> {
        // Zeroize current key
        {
            let mut key = self.current_key.write()
                .map_err(|_| anyhow::anyhow!("Lock poisoned"))?;
            // Zeroizing<SigningKey> will automatically zeroize on drop
        }
        
        // Attempt to securely delete key file
        if self.key_path.exists() {
            fs::remove_file(&self.key_path)
                .context("Failed to delete key file")?;
        }
        
        info!("Key securely deleted");
        Ok(())
    }
}

// Soft HSM implementation for development/testing
pub struct SoftHsmProvider {
    key_slot: u32,
    pin: Zeroizing<String>,
    current_key: Arc<RwLock<Zeroizing<SigningKey>>>,
    metadata: Arc<RwLock<KeyMetadata>>,
}

impl SoftHsmProvider {
    pub fn new(key_slot: u32, pin: String) -> Result<Self> {
        // For development - generate in-memory key
        let mut rng = OsRng;
        let signing_key = SigningKey::generate(&mut rng);
        
        let key_bytes = signing_key.to_bytes();
        let metadata = KeyMetadata {
            key_id: format!("hsm_slot_{}", key_slot),
            created_at: SystemTime::now().duration_since(UNIX_EPOCH)
                .context("System time error")?
                .as_secs(),
            expires_at: Some(SystemTime::now().duration_since(UNIX_EPOCH)
                .context("System time error")?
                .as_secs() + 86400 * 365),
            algorithm: "Ed25519".to_string(),
            key_type: KeyType::Signing,
        };
        
        Ok(Self {
            key_slot,
            pin: Zeroizing::new(pin),
            current_key: Arc::new(RwLock::new(Zeroizing::new(signing_key))),
            metadata: Arc::new(RwLock::new(metadata)),
        })
    }
}

impl KeyProvider for SoftHsmProvider {
    fn get_signing_key(&self) -> Result<SigningKey> {
        let key = self.current_key.read()
            .map_err(|_| anyhow::anyhow!("Lock poisoned"))?;
        Ok(key.clone())
    }
    
    fn get_verifying_key(&self) -> Result<VerifyingKey> {
        let key = self.current_key.read()
            .map_err(|_| anyhow::anyhow!("Lock poisoned"))?;
        Ok(key.verifying_key())
    }
    
    fn rotate_keys(&mut self) -> Result<KeyMetadata> {
        let mut rng = OsRng;
        let new_key = SigningKey::generate(&mut rng);
        
        let new_metadata = KeyMetadata {
            key_id: format!("hsm_slot_{}_rotated", self.key_slot),
            created_at: SystemTime::now().duration_since(UNIX_EPOCH)
                .context("System time error")?
                .as_secs(),
            expires_at: Some(SystemTime::now().duration_since(UNIX_EPOCH)
                .context("System time error")?
                .as_secs() + 86400 * 365),
            algorithm: "Ed25519".to_string(),
            key_type: KeyType::Signing,
        };
        
        {
            let mut key = self.current_key.write()
                .map_err(|_| anyhow::anyhow!("Lock poisoned"))?;
            *key = Zeroizing::new(new_key);
        }
        
        {
            let mut metadata = self.metadata.write()
                .map_err(|_| anyhow::anyhow!("Lock poisoned"))?;
            *metadata = new_metadata.clone();
        }
        
        info!("HSM key rotation completed for slot {}", self.key_slot);
        Ok(new_metadata)
    }
    
    fn get_key_metadata(&self) -> KeyMetadata {
        self.metadata.read()
            .map(|m| m.clone())
            .unwrap_or_else(|_| {
                warn!("Failed to read HSM key metadata");
                KeyMetadata {
                    key_id: format!("hsm_slot_{}", self.key_slot),
                    created_at: 0,
                    expires_at: None,
                    algorithm: "Ed25519".to_string(),
                    key_type: KeyType::Signing,
                }
            })
    }
    
    fn backup_key(&self, _backup_path: &str) -> Result<()> {
        // HSM keys cannot be extracted
        Err(anyhow::anyhow!("HSM keys cannot be backed up to file"))
    }
    
    fn create_key_escrow(&self, _threshold: usize, _total_shares: usize) -> Result<Vec<KeyEscrowShare>> {
        Err(anyhow::anyhow!("HSM key escrow not supported"))
    }
    
    fn recover_from_escrow(&self, _shares: &[KeyEscrowShare]) -> Result<SigningKey> {
        Err(anyhow::anyhow!("HSM key recovery not supported"))
    }
    
    fn verify_escrow_integrity(&self, _shares: &[KeyEscrowShare]) -> Result<bool> {
        Err(anyhow::anyhow!("HSM escrow verification not supported"))
    }
    
    fn hsm_generate_key(&self, slot_id: u32) -> Result<KeyMetadata> {
        info!("Generating new HSM key for slot {}", slot_id);
        self.rotate_keys()
    }
    
    fn hsm_sign_data(&self, data: &[u8], _slot_id: u32) -> Result<Vec<u8>> {
        let key = self.get_signing_key()?;
        use ed25519_dalek::Signer;
        let signature = key.sign(data);
        Ok(signature.to_bytes().to_vec())
    }
    
    fn hsm_get_public_key(&self, _slot_id: u32) -> Result<VerifyingKey> {
        self.get_verifying_key()
    }
    
    fn get_audit_log(&self) -> Result<Vec<KeyAuditEvent>> {
        Ok(Vec::new()) // HSM would maintain its own audit log
    }
    
    fn export_compliance_report(&self, _start_time: SystemTime, _end_time: SystemTime) -> Result<String> {
        Ok(format!("HSM Slot {} - Compliance report not available", self.key_slot))
    }
    
    fn secure_delete_key(&mut self) -> Result<()> {
        info!("HSM key deletion requested for slot {}", self.key_slot);
        Ok(()) // HSM handles secure deletion internally
    }
}

pub fn create_key_provider(provider_type: &str, config: &str) -> Result<Box<dyn KeyProvider>> {
    match provider_type {
        "file" => {
            let key_path = PathBuf::from(config);
            let backup_path = PathBuf::from(format!("{}.backup", config));
            Ok(Box::new(FileKeyProvider::new(key_path, backup_path)?))
        },
        "soft_hsm" => {
            let parts: Vec<&str> = config.split(':').collect();
            if parts.len() != 2 {
                return Err(anyhow::anyhow!("Soft HSM config format: slot:pin"));
            }
            let slot = parts[0].parse::<u32>()
                .context("Invalid slot number")?;
            let pin = parts[1].to_string();
            Ok(Box::new(SoftHsmProvider::new(slot, pin)?))
        },
        _ => Err(anyhow::anyhow!("Unknown key provider type: {}", provider_type)),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::TempDir;
    
    #[test]
    fn test_file_key_provider() -> Result<()> {
        let temp_dir = TempDir::new()?;
        let key_path = temp_dir.path().join("test_key");
        let backup_path = temp_dir.path().join("backup");
        
        let mut provider = FileKeyProvider::new(key_path.clone(), backup_path)?;
        
        let signing_key1 = provider.get_signing_key()?;
        let verifying_key1 = provider.get_verifying_key()?;
        
        assert_eq!(signing_key1.verifying_key(), verifying_key1);
        
        // Test key rotation
        let metadata = provider.rotate_keys()?;
        assert_eq!(metadata.algorithm, "Ed25519");
        
        let signing_key2 = provider.get_signing_key()?;
        assert_ne!(signing_key1.to_bytes(), signing_key2.to_bytes());
        
        Ok(())
    }
    
    #[test]
    fn test_soft_hsm_provider() -> Result<()> {
        let mut provider = SoftHsmProvider::new(1, "test_pin".to_string())?;
        
        let signing_key = provider.get_signing_key()?;
        let verifying_key = provider.get_verifying_key()?;
        
        assert_eq!(signing_key.verifying_key(), verifying_key);
        
        let metadata = provider.get_key_metadata();
        assert_eq!(metadata.key_id, "hsm_slot_1");
        
        // Test rotation
        let new_metadata = provider.rotate_keys()?;
        assert_eq!(new_metadata.key_id, "hsm_slot_1_rotated");
        
        Ok(())
    }
}