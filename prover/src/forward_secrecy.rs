use std::time::{Duration, Instant};
use std::sync::{Arc, Mutex, RwLock};
use std::collections::HashMap;
use rand::{rngs::OsRng, RngCore};
use zeroize::{Zeroize, Zeroizing};
use ml_kem::{MlKem1024, kem::{Encapsulate, Decapsulate}, KemCore};
use ring::rand::SystemRandom;
use blake3;
use tracing::{info, warn, error, debug};
use anyhow::{Result, Context};

const KEY_ROTATION_INTERVAL: Duration = Duration::from_secs(3600);
const SESSION_KEY_TTL: Duration = Duration::from_secs(300);
const MAX_ROTATED_KEYS: usize = 12;
const CLEANUP_INTERVAL: Duration = Duration::from_secs(300);

#[derive(Clone)]
pub struct EphemeralKeyMaterial {
    pub ml_kem_public: ml_kem::kem::EncapsulationKey<ml_kem::MlKem1024Params>,
    ml_kem_secret: ml_kem::kem::DecapsulationKey<ml_kem::MlKem1024Params>,
    
    _secure_rng: SystemRandom,
    
    pub session_id: [u8; 32],
    client_to_server_key: [u8; 32],
    server_to_client_key: [u8; 32],
    
    creation_time: Instant,
    last_used: Instant,
    #[allow(dead_code)]
    rotation_counter: u64,
}

impl EphemeralKeyMaterial {
    pub fn new_session() -> Result<Self> {
        let secure_rng = SystemRandom::new();
        let mut rng = OsRng;
        let (ml_kem_secret, ml_kem_public) = MlKem1024::generate(&mut rng);
        
        let mut session_id = Zeroizing::new([0u8; 32]);
        OsRng.fill_bytes(&mut *session_id);
        
        let mut os_entropy = Zeroizing::new([0u8; 32]);
        OsRng.fill_bytes(&mut *os_entropy);
        
        let (c2s_key, s2c_key) = Self::derive_session_keys(&session_id, &os_entropy)?;
        
        let now = Instant::now();
        Ok(Self {
            ml_kem_public,
            ml_kem_secret,
            _secure_rng: secure_rng,
            session_id: *session_id,
            client_to_server_key: c2s_key,
            server_to_client_key: s2c_key,
            creation_time: now,
            last_used: now,
            rotation_counter: 0,
        })
    }
    
    fn derive_session_keys(
        session_id: &[u8; 32], 
        os_entropy: &[u8; 32]
    ) -> Result<([u8; 32], [u8; 32])> {
        let mut hasher = blake3::Hasher::new();
        hasher.update(b"LEGION_FS_HKDF_V1");
        hasher.update(session_id);
        hasher.update(os_entropy);
        
        let key_material = hasher.finalize();
        let expanded = key_material.as_bytes();
        
        let mut c2s_key = [0u8; 32];
        let mut s2c_key = [0u8; 32];
        
        c2s_key.copy_from_slice(&expanded[..32]);
        
        let mut hasher2 = blake3::Hasher::new();
        hasher2.update(b"LEGION_FS_S2C_V1");
        hasher2.update(&expanded[..32]);
        hasher2.update(os_entropy);
        let s2c_material = hasher2.finalize();
        s2c_key.copy_from_slice(&s2c_material.as_bytes()[..32]);
        
        Ok((c2s_key, s2c_key))
    }
    
    pub fn is_expired(&self) -> bool {
        self.creation_time.elapsed() > SESSION_KEY_TTL
    }
    
    pub fn should_rotate(&self) -> bool {
        self.creation_time.elapsed() > KEY_ROTATION_INTERVAL
    }
    
    pub fn update_last_used(&mut self) {
        self.last_used = Instant::now();
    }
    
    pub fn encapsulate_ephemeral(&self) -> Result<(Vec<u8>, [u8; 32])> {
        let mut rng = OsRng;
        let (shared_secret, ciphertext) = self.ml_kem_public.encapsulate(&mut rng)
            .context("ML-KEM encapsulation failed")?;
        
        let mut session_key = Zeroizing::new([0u8; 32]);
        let mut hasher = blake3::Hasher::new();
        hasher.update(b"LEGION_EPHEMERAL_MLKEM_V1");
        hasher.update(shared_secret.as_slice());
        hasher.update(&self.session_id);
        hasher.update(&self.rotation_counter.to_le_bytes());
        let derived = hasher.finalize();
        session_key.copy_from_slice(&derived.as_bytes()[..32]);
        
        Ok((ciphertext.as_slice().to_vec(), *session_key))
    }
    
    pub fn decapsulate_ephemeral(&self, ciphertext: &[u8]) -> Result<[u8; 32]> {
        if ciphertext.len() != 1568 {
            return Err(anyhow::anyhow!("Invalid ML-KEM ciphertext length: {}", ciphertext.len()));
        }
        let mut ct_array = [0u8; 1568];
        ct_array.copy_from_slice(ciphertext);
        
        let shared_secret = self.ml_kem_secret.decapsulate((&ct_array).into())
            .context("ML-KEM decapsulation failed")?;
        
        let mut session_key = Zeroizing::new([0u8; 32]);
        let mut hasher = blake3::Hasher::new();
        hasher.update(b"LEGION_EPHEMERAL_MLKEM_V1");
        hasher.update(shared_secret.as_slice());
        hasher.update(&self.session_id);
        hasher.update(&self.rotation_counter.to_le_bytes());
        let derived = hasher.finalize();
        session_key.copy_from_slice(&derived.as_bytes()[..32]);
        
        Ok(*session_key)
    }
    
    pub fn get_c2s_key(&self) -> &[u8; 32] {
        &self.client_to_server_key
    }
    
    pub fn get_s2c_key(&self) -> &[u8; 32] {
        &self.server_to_client_key
    }
}

impl Zeroize for EphemeralKeyMaterial {
    fn zeroize(&mut self) {
        self.client_to_server_key.zeroize();
        self.server_to_client_key.zeroize();
        self.session_id.zeroize();
    }
}

impl std::fmt::Debug for EphemeralKeyMaterial {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("EphemeralKeyMaterial")
            .field("session_id", &"[REDACTED]")
            .field("creation_time", &self.creation_time)
            .finish()
    }
}

impl Drop for EphemeralKeyMaterial {
    fn drop(&mut self) {
        self.zeroize();
    }
}

pub struct ForwardSecrecyManager {
    current_key: Arc<RwLock<Option<EphemeralKeyMaterial>>>,
    rotated_keys: Arc<Mutex<HashMap<u64, EphemeralKeyMaterial>>>,
    rotation_counter: Arc<Mutex<u64>>,
    last_cleanup: Arc<Mutex<Instant>>,
}

impl ForwardSecrecyManager {
    pub fn new() -> Self {
        Self {
            current_key: Arc::new(RwLock::new(None)),
            rotated_keys: Arc::new(Mutex::new(HashMap::new())),
            rotation_counter: Arc::new(Mutex::new(0)),
            last_cleanup: Arc::new(Mutex::new(Instant::now())),
        }
    }
    
    pub fn get_or_rotate_key(&self) -> Result<Arc<EphemeralKeyMaterial>> {
        self.cleanup_if_needed()?;
        
        let current = self.current_key.read()
            .map_err(|_| anyhow::anyhow!("Failed to acquire read lock on current key"))?;
        
        if let Some(ref key) = *current {
            if !key.should_rotate() && !key.is_expired() {
                return Ok(Arc::new(key.clone()));
            }
        }
        
        drop(current);
        
        let mut current = self.current_key.write()
            .map_err(|_| anyhow::anyhow!("Failed to acquire write lock on current key"))?;
        
        if let Some(ref key) = *current {
            if !key.should_rotate() && !key.is_expired() {
                return Ok(Arc::new(key.clone()));
            }
        }
        
        if let Some(old_key) = current.take() {
            let mut rotated = self.rotated_keys.lock()
                .map_err(|_| anyhow::anyhow!("Failed to lock rotated keys"))?;
            let mut counter = self.rotation_counter.lock()
                .map_err(|_| anyhow::anyhow!("Failed to lock rotation counter"))?;
            rotated.insert(*counter, old_key);
            *counter += 1;
            
            if rotated.len() > MAX_ROTATED_KEYS {
                let oldest_key = rotated.keys().min().copied();
                if let Some(oldest) = oldest_key {
                    rotated.remove(&oldest);
                }
            }
        }
        
        let new_key = EphemeralKeyMaterial::new_session()?;
        let key_arc = Arc::new(new_key.clone());
        *current = Some(new_key);
        
        Ok(key_arc)
    }
    
    fn cleanup_if_needed(&self) -> Result<()> {
        let mut last_cleanup = self.last_cleanup.lock()
            .map_err(|_| anyhow::anyhow!("Failed to lock cleanup timer"))?;
        
        if last_cleanup.elapsed() < CLEANUP_INTERVAL {
            return Ok(());
        }
        
        *last_cleanup = Instant::now();
        drop(last_cleanup);
        
        let mut rotated = self.rotated_keys.lock()
            .map_err(|_| anyhow::anyhow!("Failed to lock rotated keys for cleanup"))?;
        let expired_keys: Vec<u64> = rotated
            .iter()
            .filter(|(_, key)| key.creation_time.elapsed() > KEY_ROTATION_INTERVAL * 2)
            .map(|(id, _)| *id)
            .collect();
        
        for key_id in expired_keys {
            if let Some(mut expired_key) = rotated.remove(&key_id) {
                expired_key.client_to_server_key.zeroize();
                expired_key.server_to_client_key.zeroize();
                expired_key.session_id.zeroize();
                expired_key.rotation_counter = 0;
            }
        }
        
        Ok(())
    }
    
    pub fn force_cleanup(&self) -> Result<()> {
        let mut current = self.current_key.write()
            .map_err(|_| anyhow::anyhow!("Failed to acquire write lock for cleanup"))?;
        if let Some(mut key) = current.take() {
            key.client_to_server_key.zeroize();
            key.server_to_client_key.zeroize();
            key.session_id.zeroize();
        }
        
        let mut rotated = self.rotated_keys.lock()
            .map_err(|_| anyhow::anyhow!("Failed to lock rotated keys for cleanup"))?;
        for (_, mut key) in rotated.drain() {
            key.client_to_server_key.zeroize();
            key.server_to_client_key.zeroize();
            key.session_id.zeroize();
        }
        
        Ok(())
    }
    
    pub fn try_decrypt_with_any_key(&self, encrypted_data: &[u8]) -> Result<Vec<u8>> {
        if let Ok(current_key) = self.get_or_rotate_key() {
            if let Ok(session_key) = current_key.decapsulate_ephemeral(&encrypted_data[..1568]) {
                if let Ok(decrypted) = self.decrypt_with_key(&encrypted_data[1568..], &session_key) {
                    return Ok(decrypted);
                }
            }
        }
        
        let rotated = self.rotated_keys.lock()
            .map_err(|_| anyhow::anyhow!("Failed to lock rotated keys for decryption"))?;
        for (_, key) in rotated.iter() {
            if key.creation_time.elapsed() <= KEY_ROTATION_INTERVAL {
                if let Ok(session_key) = key.decapsulate_ephemeral(&encrypted_data[..1568]) {
                    if let Ok(decrypted) = self.decrypt_with_key(&encrypted_data[1568..], &session_key) {
                        return Ok(decrypted);
                    }
                }
            }
        }
        
        Err(anyhow::anyhow!("Could not decrypt with any available key"))
    }
    
    fn decrypt_with_key(&self, encrypted_data: &[u8], key: &[u8; 32]) -> Result<Vec<u8>> {
        use ring::aead::{Aad, LessSafeKey, Nonce, UnboundKey, AES_256_GCM};
        
        if encrypted_data.len() < 28 {
            return Err(anyhow::anyhow!("Invalid encrypted data length: {}", encrypted_data.len()));
        }
        
        let nonce_bytes = &encrypted_data[..12];
        let ciphertext = &encrypted_data[12..];
        
        let unbound_key = UnboundKey::new(&AES_256_GCM, key)
            .context("Key creation failed")?;
        let opening_key = LessSafeKey::new(unbound_key);
        let nonce = Nonce::try_assume_unique_for_key(nonce_bytes)
            .context("Invalid nonce")?;
        
        let mut plaintext = ciphertext.to_vec();
        let decrypted_slice = opening_key.open_in_place(nonce, Aad::empty(), &mut plaintext)
            .context("Decryption failed")?;
        
        let decrypted_len = decrypted_slice.len();
        plaintext.truncate(decrypted_len);
        Ok(plaintext)
    }
}

impl Default for ForwardSecrecyManager {
    fn default() -> Self {
        Self::new()
    }
}

use std::sync::LazyLock;
pub static FS_MANAGER: LazyLock<ForwardSecrecyManager> = LazyLock::new(|| ForwardSecrecyManager::new());

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_ephemeral_key_lifecycle() {
        let key1 = EphemeralKeyMaterial::new_session()
            .expect("Failed to create first ephemeral key");
        let key2 = EphemeralKeyMaterial::new_session()
            .expect("Failed to create second ephemeral key");
        
        assert_ne!(key1.session_id, key2.session_id);
        
        assert!(!key1.is_expired());
        assert!(!key1.should_rotate());
        
        assert_ne!(key1.session_id, [0u8; 32]);
        assert_ne!(key1.client_to_server_key, [0u8; 32]);
        assert_ne!(key1.server_to_client_key, [0u8; 32]);
    }
    
    #[test]
    fn test_time_based_rotation() {
        let manager = ForwardSecrecyManager::new();
        
        let key1 = manager.get_or_rotate_key()
            .expect("Failed to get initial key");
        let session_id1 = key1.session_id;
        
        let key2 = manager.get_or_rotate_key()
            .expect("Failed to get or rotate key");
        assert_eq!(key2.session_id, session_id1);
        
        {
            let mut current = manager.current_key.write()
                .expect("Failed to acquire write lock");
            if let Some(ref mut key) = *current {
                key.creation_time = Instant::now() - KEY_ROTATION_INTERVAL - Duration::from_secs(1);
            }
        }
        
        let key3 = manager.get_or_rotate_key()
            .expect("Failed to get or rotate key after forced expiry");
        assert_ne!(key3.session_id, session_id1);
    }
    
    #[test]
    fn test_secure_cleanup() {
        let manager = ForwardSecrecyManager::new();
        
        let _key1 = manager.get_or_rotate_key()
            .expect("Failed to get key before cleanup");
        
        manager.force_cleanup()
            .expect("Failed to force cleanup");
        
        let key2 = manager.get_or_rotate_key()
            .expect("Failed to get key after cleanup");
        assert_ne!(key2.session_id, [0u8; 32]);
    }
}