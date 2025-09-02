use ml_kem::{KemCore, MlKem1024};
use ml_dsa::{MlDsa87, Signature as MlDsaSignature};
use crate::secure_crypto::{CryptoError, KEY_LEN, NONCE_LEN};
use zeroize::{Zeroize, ZeroizeOnDrop, Zeroizing};
use rand_core::{OsRng, RngCore};
use std::time::{SystemTime, UNIX_EPOCH, Duration};
use std::sync::{Arc, Mutex};
use blake3::Hasher;
use tracing::{info, warn, error, debug};
use anyhow::{Result, Context};

pub const ML_KEM_PUBLIC_KEY_LEN: usize = 1568;
pub const ML_KEM_SECRET_KEY_LEN: usize = 3168;
pub const ML_KEM_CIPHERTEXT_LEN: usize = 1568;
pub const ML_KEM_SHARED_SECRET_LEN: usize = 32;
pub const ML_DSA_PUBLIC_KEY_LEN: usize = 2592;
pub const ML_DSA_SECRET_KEY_LEN: usize = 4896;
pub const ML_DSA_SIGNATURE_LEN: usize = 4627;

const KEY_ROTATION_INTERVAL: Duration = Duration::from_secs(1800);

#[derive(ZeroizeOnDrop)]
pub struct QuantumResistantCrypto {
    kem_public_key: ml_kem::kem::PublicKey<MlKem1024>,
    kem_secret_key: ml_kem::kem::SecretKey<MlKem1024>,
    
    dsa_public_key: ml_dsa::PublicKey<MlDsa87>,
    dsa_secret_key: ml_dsa::SecretKey<MlDsa87>,
    
    created_at: SystemTime,
    rotation_counter: u64,
}

impl QuantumResistantCrypto {
    pub fn new() -> Result<Self, CryptoError> {
        let mut rng = OsRng;
        
        let (kem_secret_key, kem_public_key) = MlKem1024::generate(&mut rng);
        let (dsa_secret_key, dsa_public_key) = MlDsa87::generate(&mut rng);
        
        Ok(Self {
            kem_public_key,
            kem_secret_key,
            dsa_public_key,
            dsa_secret_key,
            created_at: SystemTime::now(),
            rotation_counter: 0,
        })
    }
    
    pub fn needs_rotation(&self) -> bool {
        self.created_at.elapsed().unwrap_or(Duration::ZERO) > KEY_ROTATION_INTERVAL
    }
    
    pub fn rotate_keys(&mut self) -> Result<(), CryptoError> {
        let mut rng = OsRng;
        
        let (new_kem_secret, new_kem_public) = MlKem1024::generate(&mut rng);
        let (new_dsa_secret, new_dsa_public) = MlDsa87::generate(&mut rng);
        
        self.kem_secret_key = new_kem_secret;
        self.kem_public_key = new_kem_public;
        self.dsa_secret_key = new_dsa_secret;
        self.dsa_public_key = new_dsa_public;
        
        self.created_at = SystemTime::now();
        self.rotation_counter = self.rotation_counter.wrapping_add(1);
        
        Ok(())
    }

    pub fn kem_public_key_bytes(&self) -> Result<[u8; ML_KEM_PUBLIC_KEY_LEN], CryptoError> {
        self.kem_public_key.as_bytes().try_into()
            .map_err(|_| CryptoError::KeyConvFailed)
    }
    
    pub fn dsa_public_key_bytes(&self) -> Result<[u8; ML_DSA_PUBLIC_KEY_LEN], CryptoError> {
        self.dsa_public_key.as_bytes().try_into()
            .map_err(|_| CryptoError::KeyConvFailed)
    }

    pub fn encapsulate(public_key_bytes: &[u8; ML_KEM_PUBLIC_KEY_LEN]) -> Result<([u8; ML_KEM_SHARED_SECRET_LEN], [u8; ML_KEM_CIPHERTEXT_LEN]), CryptoError> {
        let public_key = ml_kem::kem::PublicKey::<MlKem1024>::from_bytes(public_key_bytes)
            .map_err(|_| CryptoError::KeyConvFailed)?;
        
        let mut rng = OsRng;
        let (shared_secret, ciphertext) = public_key.encapsulate(&mut rng)
            .map_err(|_| CryptoError::EncryptFailed)?;
        
        let shared_secret_bytes = shared_secret.as_bytes().try_into()
            .map_err(|_| CryptoError::KeyConvFailed)?;
        let ciphertext_bytes = ciphertext.as_bytes().try_into()
            .map_err(|_| CryptoError::KeyConvFailed)?;
        
        Ok((shared_secret_bytes, ciphertext_bytes))
    }

    pub fn decapsulate(&self, ciphertext_bytes: &[u8; ML_KEM_CIPHERTEXT_LEN]) -> Result<[u8; ML_KEM_SHARED_SECRET_LEN], CryptoError> {
        let ciphertext = ml_kem::kem::Ciphertext::<MlKem1024>::from_bytes(ciphertext_bytes)
            .map_err(|_| CryptoError::DecryptFailed)?;
        
        let shared_secret = self.kem_secret_key.decapsulate(&ciphertext)
            .map_err(|_| CryptoError::DecryptFailed)?;
        
        let shared_secret_bytes = shared_secret.as_bytes().try_into()
            .map_err(|_| CryptoError::KeyConvFailed)?;
        Ok(shared_secret_bytes)
    }
    
    pub fn sign_quantum_resistant(&self, message: &[u8]) -> Result<[u8; ML_DSA_SIGNATURE_LEN], CryptoError> {
        let mut rng = OsRng;
        let signature = self.dsa_secret_key.sign(&mut rng, message)
            .map_err(|_| CryptoError::SigInvalid)?;
        
        let signature_bytes = signature.as_bytes().try_into()
            .map_err(|_| CryptoError::SigInvalid)?;
        Ok(signature_bytes)
    }
    
    pub fn verify_quantum_resistant(
        public_key_bytes: &[u8; ML_DSA_PUBLIC_KEY_LEN],
        message: &[u8],
        signature_bytes: &[u8; ML_DSA_SIGNATURE_LEN]
    ) -> Result<bool, CryptoError> {
        let public_key = ml_dsa::PublicKey::<MlDsa87>::from_bytes(public_key_bytes)
            .map_err(|_| CryptoError::KeyConvFailed)?;
        
        let signature = MlDsaSignature::<MlDsa87>::from_bytes(signature_bytes)
            .map_err(|_| CryptoError::SigInvalid)?;
        
        Ok(public_key.verify(message, &signature).is_ok())
    }
}

pub fn quantum_resistant_key_derivation(
    ml_kem_shared_secret: &[u8; ML_KEM_SHARED_SECRET_LEN],
    salt: &[u8; 32],
    session_id: &str,
    rotation_counter: u64,
) -> Result<([u8; KEY_LEN], [u8; KEY_LEN]), CryptoError> {
    let mut hasher = Hasher::new();
    hasher.update(b"LEGION_PQ_KDF_V1");
    hasher.update(ml_kem_shared_secret);
    hasher.update(salt);
    hasher.update(session_id.as_bytes());
    hasher.update(&rotation_counter.to_le_bytes());
    
    let master_key = hasher.finalize();
    
    let mut c2s_hasher = Hasher::new();
    c2s_hasher.update(b"C2S_KEY");
    c2s_hasher.update(master_key.as_bytes());
    let key_c2s: [u8; KEY_LEN] = c2s_hasher.finalize().as_bytes()[..KEY_LEN].try_into()
        .map_err(|_| CryptoError::KeyConvFailed)?;
    
    let mut s2c_hasher = Hasher::new();
    s2c_hasher.update(b"S2C_KEY");
    s2c_hasher.update(master_key.as_bytes());
    let key_s2c: [u8; KEY_LEN] = s2c_hasher.finalize().as_bytes()[..KEY_LEN].try_into()
        .map_err(|_| CryptoError::KeyConvFailed)?;
    
    Ok((key_c2s, key_s2c))
}

pub struct QuantumCryptoManager {
    crypto: Arc<Mutex<QuantumResistantCrypto>>,
}

impl QuantumCryptoManager {
    pub fn new() -> Result<Self, CryptoError> {
        let crypto = QuantumResistantCrypto::new()?;
        Ok(Self {
            crypto: Arc::new(Mutex::new(crypto)),
        })
    }
    
    pub fn get_or_rotate(&self) -> Result<(), CryptoError> {
        let mut crypto = self.crypto.lock()
            .map_err(|_| CryptoError::KeyConvFailed)?;
        if crypto.needs_rotation() {
            crypto.rotate_keys()?;
        }
        Ok(())
    }
    
    pub fn force_rotation(&self) -> Result<(), CryptoError> {
        let mut crypto = self.crypto.lock()
            .map_err(|_| CryptoError::KeyConvFailed)?;
        crypto.rotate_keys()
    }
}

use std::sync::LazyLock;
pub static QUANTUM_MANAGER: LazyLock<Result<QuantumCryptoManager, CryptoError>> = LazyLock::new(|| {
    QuantumCryptoManager::new()
});

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_ml_kem_key_exchange() -> Result<(), CryptoError> {
        let server_crypto = QuantumResistantCrypto::new()?;
        let server_public_key = server_crypto.kem_public_key_bytes()?;

        let (client_shared_secret, ciphertext) = QuantumResistantCrypto::encapsulate(&server_public_key)?;
        let server_shared_secret = server_crypto.decapsulate(&ciphertext)?;

        assert_eq!(client_shared_secret, server_shared_secret);
        Ok(())
    }

    #[test]
    fn test_ml_dsa_signatures() -> Result<(), CryptoError> {
        let crypto = QuantumResistantCrypto::new()?;
        let message = b"test message for quantum signature";
        
        let signature = crypto.sign_quantum_resistant(message)?;
        let public_key = crypto.dsa_public_key_bytes()?;
        
        let valid = QuantumResistantCrypto::verify_quantum_resistant(&public_key, message, &signature)?;
        assert!(valid);
        Ok(())
    }

    #[test]
    fn test_automatic_key_rotation() -> Result<(), CryptoError> {
        let mut crypto = QuantumResistantCrypto::new()?;
        let original_counter = crypto.rotation_counter;
        
        crypto.rotate_keys()?;
        assert_eq!(crypto.rotation_counter, original_counter + 1);
        Ok(())
    }

    #[test]
    fn test_quantum_key_derivation() -> Result<(), CryptoError> {
        let ml_kem_secret = [1u8; 32];
        let salt = [2u8; 32];
        let session_id = "test_pq_session";
        
        let (key_c2s, key_s2c) = quantum_resistant_key_derivation(&ml_kem_secret, &salt, session_id, 0)?;
        assert_ne!(key_c2s, key_s2c);
        
        let (key_c2s_2, key_s2c_2) = quantum_resistant_key_derivation(&ml_kem_secret, &salt, session_id, 1)?;
        assert_ne!(key_c2s, key_c2s_2);
        assert_ne!(key_s2c, key_s2c_2);
        Ok(())
    }
}