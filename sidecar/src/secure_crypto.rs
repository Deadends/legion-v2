use std::fs;
use std::path::Path;
use blake3::Hasher;
use chacha20poly1305::{ChaCha20Poly1305, Key, Nonce, KeyInit, AeadInPlace};
use ed25519_dalek::{SigningKey, VerifyingKey, Signature, Signer, Verifier};
use pqcrypto_dilithium::dilithium5::*;
use pqcrypto_kyber::kyber1024::*;
use rand_core::{OsRng, RngCore};
use zeroize::{Zeroize, ZeroizeOnDrop, Zeroizing};
use subtle::ConstantTimeEq;
use anyhow::{Result, Context};
use tracing::{info, warn, error};

use crate::CryptoError;

#[derive(ZeroizeOnDrop)]
pub struct StableMasterKey {
    key: [u8; 32],
}

impl StableMasterKey {
    pub fn derive() -> Result<Self, CryptoError> {
        let mut hasher = Hasher::new();
        hasher.update(b"LEGION_STABLE_MASTER_V1");
        
        let machine_id = Self::get_stable_machine_id()?;
        hasher.update(&machine_id);
        
        if let Ok(cpu_info) = Self::get_cpu_identifier() {
            hasher.update(&cpu_info);
        }
        
        if let Ok(mb_serial) = Self::get_motherboard_serial() {
            hasher.update(&mb_serial);
        }
        
        let key_material = hasher.finalize();
        let mut key = Zeroizing::new([0u8; 32]);
        key.copy_from_slice(&key_material.as_bytes()[..32]);
        
        Ok(Self { key: *key })
    }
    
    fn get_stable_machine_id() -> Result<Vec<u8>, CryptoError> {
        if let Ok(machine_id) = fs::read("/etc/machine-id") {
            return Ok(machine_id);
        }
        
        if let Ok(guid) = fs::read("C:\\Windows\\System32\\MachineGUID") {
            return Ok(guid);
        }
        
        let mut hasher = Hasher::new();
        hasher.update(b"LEGION_FALLBACK_ID");
        
        if let Ok(hostname) = std::env::var("COMPUTERNAME")
            .or_else(|_| std::env::var("HOSTNAME")) {
            hasher.update(hostname.as_bytes());
        }
        
        if let Ok(username) = std::env::var("USERNAME")
            .or_else(|_| std::env::var("USER")) {
            hasher.update(username.as_bytes());
        }
        
        Ok(hasher.finalize().as_bytes().to_vec())
    }
    
    fn get_cpu_identifier() -> Result<Vec<u8>, CryptoError> {
        let cpu_info = std::env::var("PROCESSOR_IDENTIFIER")
            .or_else(|_| std::env::var("CPU_INFO"))
            .unwrap_or_else(|_| "UNKNOWN_CPU".to_string());
        Ok(cpu_info.as_bytes().to_vec())
    }
    
    fn get_motherboard_serial() -> Result<Vec<u8>, CryptoError> {
        let mb_info = std::env::var("MOTHERBOARD_SERIAL")
            .unwrap_or_else(|_| "UNKNOWN_MB".to_string());
        Ok(mb_info.as_bytes().to_vec())
    }
    
    pub fn as_bytes(&self) -> &[u8; 32] {
        &self.key
    }
}

pub struct SecureDilithiumKeys {
    pub signing_key: SecretKey,
    pub verifying_key: PublicKey,
}

impl SecureDilithiumKeys {
    pub fn generate() -> Result<Self, CryptoError> {
        let (verifying_key, signing_key) = keypair();
        
        Ok(Self {
            signing_key,
            verifying_key,
        })
    }
    
    pub fn sign(&self, data: &[u8]) -> Result<Vec<u8>, CryptoError> {
        let signature = sign(data, &self.signing_key);
        Ok(signature.as_bytes().to_vec())
    }
    
    pub fn verify(&self, data: &[u8], signature: &[u8]) -> Result<bool, CryptoError> {
        if signature.len() != SIGNATUREBYTES {
            return Ok(false);
        }
        
        let mut sig_array = [0u8; SIGNATUREBYTES];
        sig_array.copy_from_slice(signature);
        let sig = SignedMessage::from_bytes(&sig_array)
            .map_err(|_| CryptoError::SigInvalid)?;
        
        match verify(&sig, data, &self.verifying_key) {
            Ok(_) => Ok(true),
            Err(_) => Ok(false),
        }
    }
    
    pub fn signing_key_bytes(&self) -> Vec<u8> {
        self.signing_key.as_bytes().to_vec()
    }
    
    pub fn verifying_key_bytes(&self) -> Vec<u8> {
        self.verifying_key.as_bytes().to_vec()
    }
    
    pub fn from_signing_key_bytes(bytes: &[u8]) -> Result<SecretKey, CryptoError> {
        if bytes.len() != SECRETKEYBYTES {
            return Err(CryptoError::KeyConvFailed);
        }
        
        let mut key_array = [0u8; SECRETKEYBYTES];
        key_array.copy_from_slice(bytes);
        
        Ok(SecretKey::from_bytes(&key_array)
            .map_err(|_| CryptoError::KeyConvFailed)?)
    }
    
    pub fn from_verifying_key_bytes(bytes: &[u8]) -> Result<PublicKey, CryptoError> {
        if bytes.len() != PUBLICKEYBYTES {
            return Err(CryptoError::KeyConvFailed);
        }
        
        let mut key_array = [0u8; PUBLICKEYBYTES];
        key_array.copy_from_slice(bytes);
        
        Ok(PublicKey::from_bytes(&key_array)
            .map_err(|_| CryptoError::KeyConvFailed)?)
    }
}

pub struct SecureKemKeys {
    pub public_key: pqcrypto_kyber::kyber1024::PublicKey,
    pub secret_key: pqcrypto_kyber::kyber1024::SecretKey,
}

impl SecureKemKeys {
    pub fn generate() -> Result<Self, CryptoError> {
        let (public_key, secret_key) = pqcrypto_kyber::kyber1024::keypair();
        
        Ok(Self {
            public_key,
            secret_key,
        })
    }
    
    pub fn encapsulate(&self) -> Result<(Vec<u8>, Vec<u8>), CryptoError> {
        let (shared_secret, ciphertext) = pqcrypto_kyber::kyber1024::encapsulate(&self.public_key);
        
        Ok((ciphertext.as_bytes().to_vec(), shared_secret.as_bytes().to_vec()))
    }
    
    pub fn decapsulate(&self, ciphertext: &[u8]) -> Result<Vec<u8>, CryptoError> {
        if ciphertext.len() != pqcrypto_kyber::kyber1024::CIPHERTEXTBYTES {
            return Err(CryptoError::KeyConvFailed);
        }
        
        let mut ct_array = [0u8; pqcrypto_kyber::kyber1024::CIPHERTEXTBYTES];
        ct_array.copy_from_slice(ciphertext);
        
        let ct = pqcrypto_kyber::kyber1024::Ciphertext::from_bytes(&ct_array)
            .map_err(|_| CryptoError::KeyConvFailed)?;
        
        let shared_secret = pqcrypto_kyber::kyber1024::decapsulate(&ct, &self.secret_key);
        
        Ok(shared_secret.as_bytes().to_vec())
    }
}

pub struct SecureKeyStorage {
    master_key: StableMasterKey,
    storage_path: String,
}

impl SecureKeyStorage {
    pub fn new(storage_path: &str) -> Result<Self, CryptoError> {
        fs::create_dir_all(storage_path)
            .context("Failed to create storage directory")
            .map_err(|_| CryptoError::KeyConvFailed)?;
        
        let master_key = StableMasterKey::derive()?;
        
        Ok(Self {
            master_key,
            storage_path: storage_path.to_string(),
        })
    }
    
    pub fn store_key(&self, key_id: &str, key_data: &[u8]) -> Result<(), CryptoError> {
        let key_path = format!("{}/{}.key", self.storage_path, key_id);
        let encrypted_data = self.encrypt_key_data(key_data)?;
        
        fs::write(key_path, encrypted_data)
            .context("Failed to write encrypted key")
            .map_err(|_| CryptoError::KeyConvFailed)
    }
    
    pub fn load_key(&self, key_id: &str) -> Result<Vec<u8>, CryptoError> {
        let key_path = format!("{}/{}.key", self.storage_path, key_id);
        
        if !Path::new(&key_path).exists() {
            return Err(CryptoError::KeyConvFailed);
        }
        
        let encrypted_data = fs::read(key_path)
            .context("Failed to read encrypted key")
            .map_err(|_| CryptoError::KeyConvFailed)?;
        
        self.decrypt_key_data(&encrypted_data)
    }
    
    fn encrypt_key_data(&self, key_data: &[u8]) -> Result<Vec<u8>, CryptoError> {
        let cipher = ChaCha20Poly1305::new(Key::from_slice(self.master_key.as_bytes()));
        let mut nonce_bytes = Zeroizing::new([0u8; 12]);
        OsRng.fill_bytes(&mut *nonce_bytes);
        let nonce = Nonce::from_slice(&nonce_bytes);
        
        let mut buffer = key_data.to_vec();
        let tag = cipher.encrypt_in_place_detached(nonce, b"LEGION_KEY_STORAGE", &mut buffer)
            .map_err(|_| CryptoError::EncryptFailed)?;
        
        let mut encrypted = Vec::new();
        encrypted.extend_from_slice(&nonce_bytes);
        encrypted.extend_from_slice(&buffer);
        encrypted.extend_from_slice(&tag);
        
        Ok(encrypted)
    }
    
    fn decrypt_key_data(&self, encrypted_data: &[u8]) -> Result<Vec<u8>, CryptoError> {
        if encrypted_data.len() < 28 {
            return Err(CryptoError::DecryptFailed);
        }
        
        let cipher = ChaCha20Poly1305::new(Key::from_slice(self.master_key.as_bytes()));
        let nonce = Nonce::from_slice(&encrypted_data[..12]);
        let mut buffer = encrypted_data[12..encrypted_data.len()-16].to_vec();
        let tag = &encrypted_data[encrypted_data.len()-16..];
        
        cipher.decrypt_in_place_detached(nonce, b"LEGION_KEY_STORAGE", &mut buffer, tag.into())
            .map_err(|_| CryptoError::DecryptFailed)?;
        
        Ok(buffer)
    }
}

pub fn constant_time_eq(a: &[u8], b: &[u8]) -> bool {
    if a.len() != b.len() {
        return false;
    }
    
    a.ct_eq(b).into()
}

pub fn secure_random_bytes(len: usize) -> Vec<u8> {
    let mut bytes = vec![0u8; len];
    OsRng.fill_bytes(&mut bytes);
    bytes
}

#[cfg(test)]
mod tests {
    use super::*;
    
    #[test]
    fn test_stable_master_key() -> Result<(), CryptoError> {
        let key1 = StableMasterKey::derive()?;
        let key2 = StableMasterKey::derive()?;
        
        assert_eq!(key1.as_bytes(), key2.as_bytes());
        Ok(())
    }
    
    #[test]
    fn test_dilithium_keygen() -> Result<(), CryptoError> {
        let keys = SecureDilithiumKeys::generate()?;
        let message = b"test message";
        
        let signature = keys.sign(message)?;
        assert!(keys.verify(message, &signature)?);
        
        assert!(!keys.verify(b"wrong message", &signature)?);
        Ok(())
    }
    
    #[test]
    fn test_kem_keygen() -> Result<(), CryptoError> {
        let keys = SecureKemKeys::generate()?;
        let (ciphertext, shared_secret1) = keys.encapsulate()?;
        let shared_secret2 = keys.decapsulate(&ciphertext)?;
        
        assert_eq!(shared_secret1, shared_secret2);
        Ok(())
    }
    
    #[test]
    fn test_secure_storage() -> Result<(), CryptoError> {
        let storage = SecureKeyStorage::new("./test_storage")?;
        let test_key = b"test_key_data";
        
        storage.store_key("test", test_key)?;
        let loaded_key = storage.load_key("test")?;
        
        assert_eq!(test_key, loaded_key.as_slice());
        
        std::fs::remove_dir_all("./test_storage").ok();
        Ok(())
    }
}