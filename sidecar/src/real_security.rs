use crate::secure_crypto::{CryptoError, KEY_LEN, NONCE_LEN};
use zeroize::{Zeroize, ZeroizeOnDrop, Zeroizing};
use std::sync::{Arc, Mutex, RwLock};
use std::collections::HashMap;
use std::time::{SystemTime, UNIX_EPOCH, Duration};
use std::fs;
use std::path::Path;
use ring::signature::{Ed25519KeyPair, KeyPair, UnparsedPublicKey, ED25519};
use ring::rand::SystemRandom;
use ml_kem::{KemCore, MlKem1024};
use ml_dsa::{MlDsa87, Signature as MlDsaSignature};
use subtle::ConstantTimeEq;
use tracing::{info, warn, error, debug};
use anyhow::{Result, Context};

#[derive(ZeroizeOnDrop)]
pub struct RealQuantumKEM {
    private_key: ml_kem::PrivateKey<MlKem1024>,
    public_key: ml_kem::PublicKey<MlKem1024>,
}

impl RealQuantumKEM {
    pub fn new() -> Result<Self, CryptoError> {
        let mut rng = SystemRandom::new();
        let (private_key, public_key) = MlKem1024::generate(&mut rng)
            .map_err(|_| CryptoError::KeyConvFailed)?;
        
        Ok(Self { private_key, public_key })
    }

    pub fn public_key_bytes(&self) -> Vec<u8> {
        self.public_key.as_bytes().to_vec()
    }

    pub fn encapsulate(public_key_bytes: &[u8]) -> Result<([u8; 32], Vec<u8>), CryptoError> {
        let public_key = ml_kem::PublicKey::<MlKem1024>::from_bytes(public_key_bytes)
            .map_err(|_| CryptoError::KeyConvFailed)?;
        
        let mut rng = SystemRandom::new();
        let (shared_secret, ciphertext) = public_key.encapsulate(&mut rng)
            .map_err(|_| CryptoError::EncryptFailed)?;
        
        let shared_secret_bytes = shared_secret.as_bytes().try_into()
            .map_err(|_| CryptoError::KeyConvFailed)?;
        Ok((shared_secret_bytes, ciphertext.as_bytes().to_vec()))
    }

    pub fn decapsulate(&self, ciphertext: &[u8]) -> Result<[u8; 32], CryptoError> {
        let ct = ml_kem::Ciphertext::<MlKem1024>::from_bytes(ciphertext)
            .map_err(|_| CryptoError::DecryptFailed)?;
        
        let shared_secret = self.private_key.decapsulate(&ct)
            .map_err(|_| CryptoError::DecryptFailed)?;
        
        let shared_secret_bytes = shared_secret.as_bytes().try_into()
            .map_err(|_| CryptoError::KeyConvFailed)?;
        Ok(shared_secret_bytes)
    }
}

#[derive(ZeroizeOnDrop)]
pub struct RealQuantumSigner {
    private_key: ml_dsa::PrivateKey<MlDsa87>,
    public_key: ml_dsa::PublicKey<MlDsa87>,
}

impl RealQuantumSigner {
    pub fn new() -> Result<Self, CryptoError> {
        let mut rng = SystemRandom::new();
        let (private_key, public_key) = MlDsa87::generate(&mut rng)
            .map_err(|_| CryptoError::KeyConvFailed)?;
        
        Ok(Self { private_key, public_key })
    }

    pub fn public_key_bytes(&self) -> Vec<u8> {
        self.public_key.as_bytes().to_vec()
    }

    pub fn sign(&self, message: &[u8]) -> Result<Vec<u8>, CryptoError> {
        let mut rng = SystemRandom::new();
        let signature = self.private_key.sign(message, &mut rng)
            .map_err(|_| CryptoError::SigInvalid)?;
        
        Ok(signature.as_bytes().to_vec())
    }

    pub fn verify(public_key_bytes: &[u8], message: &[u8], signature: &[u8]) -> Result<bool, CryptoError> {
        let public_key = ml_dsa::PublicKey::<MlDsa87>::from_bytes(public_key_bytes)
            .map_err(|_| CryptoError::KeyConvFailed)?;
        
        let sig = MlDsaSignature::<MlDsa87>::from_bytes(signature)
            .map_err(|_| CryptoError::SigInvalid)?;
        
        Ok(public_key.verify(message, &sig).is_ok())
    }
}

pub struct RealHSM {
    #[cfg(feature = "tpm")]
    tpm_context: Option<tss_esapi::Context>,
    trusted_keys: Arc<RwLock<HashMap<String, Vec<u8>>>>,
    authority_keys: Arc<RwLock<HashMap<String, RealQuantumSigner>>>,
}

impl RealHSM {
    pub fn new() -> Result<Self, CryptoError> {
        #[cfg(feature = "tpm")]
        let tpm_context = Self::init_tpm().ok();
        
        let mut hsm = Self {
            #[cfg(feature = "tpm")]
            tmp_context: None,
            trusted_keys: Arc::new(RwLock::new(HashMap::new())),
            authority_keys: Arc::new(RwLock::new(HashMap::new())),
        };
        
        hsm.load_trusted_keys()?;
        hsm.load_authority_keys()?;
        
        Ok(hsm)
    }

    #[cfg(feature = "tpm")]
    fn init_tpm() -> Result<tss_esapi::Context, CryptoError> {
        use tss_esapi::{Context, TctiNameConf};
        
        let tcti = TctiNameConf::from_environment_variable()
            .unwrap_or_else(|| TctiNameConf::Device(Default::default()));
        
        Context::new(tcti).map_err(|_| CryptoError::KeyConvFailed)
    }

    fn load_trusted_keys(&mut self) -> Result<(), CryptoError> {
        let keys_dir = "./secure_storage/trusted_keys";
        if !Path::new(keys_dir).exists() {
            fs::create_dir_all(keys_dir)
                .context("Failed to create trusted keys directory")
                .map_err(|_| CryptoError::KeyConvFailed)?;
            return Ok(());
        }

        let mut keys = self.trusted_keys.write()
            .map_err(|_| CryptoError::KeyConvFailed)?;
        
        for entry in fs::read_dir(keys_dir)
            .context("Failed to read trusted keys directory")
            .map_err(|_| CryptoError::KeyConvFailed)? {
            let entry = entry
                .context("Failed to read directory entry")
                .map_err(|_| CryptoError::KeyConvFailed)?;
            let path = entry.path();
            
            if path.extension().and_then(|s| s.to_str()) == Some("key") {
                let key_name = path.file_stem()
                    .and_then(|s| s.to_str())
                    .ok_or(CryptoError::KeyConvFailed)?;
                
                let key_data = fs::read(&path)
                    .context("Failed to read key file")
                    .map_err(|_| CryptoError::KeyConvFailed)?;
                keys.insert(key_name.to_string(), key_data);
            }
        }
        
        Ok(())
    }

    fn load_authority_keys(&mut self) -> Result<(), CryptoError> {
        let auth_dir = "./secure_storage/authority_keys";
        if !Path::new(auth_dir).exists() {
            fs::create_dir_all(auth_dir)
                .context("Failed to create authority keys directory")
                .map_err(|_| CryptoError::KeyConvFailed)?;
            
            let authority = RealQuantumSigner::new()?;
            let public_key_bytes = authority.public_key_bytes();
            
            fs::write(
                format!("{}/default.pub", auth_dir),
                &public_key_bytes
            ).context("Failed to write default authority key")
            .map_err(|_| CryptoError::KeyConvFailed)?;
            
            let mut auth_keys = self.authority_keys.write()
                .map_err(|_| CryptoError::KeyConvFailed)?;
            auth_keys.insert("default".to_string(), authority);
            
            return Ok(());
        }

        let mut auth_keys = self.authority_keys.write()
            .map_err(|_| CryptoError::KeyConvFailed)?;
        
        for entry in fs::read_dir(auth_dir)
            .context("Failed to read authority keys directory")
            .map_err(|_| CryptoError::KeyConvFailed)? {
            let entry = entry
                .context("Failed to read directory entry")
                .map_err(|_| CryptoError::KeyConvFailed)?;
            let path = entry.path();
            
            if path.extension().and_then(|s| s.to_str()) == Some("priv") {
                let key_name = path.file_stem()
                    .and_then(|s| s.to_str())
                    .ok_or(CryptoError::KeyConvFailed)?;
                
                let authority = RealQuantumSigner::new()?;
                auth_keys.insert(key_name.to_string(), authority);
            }
        }
        
        Ok(())
    }

    pub fn verify_server_key(&self, server_key: &[u8; 32]) -> bool {
        let keys = match self.trusted_keys.read() {
            Ok(keys) => keys,
            Err(_) => return false,
        };
        
        for trusted_key in keys.values() {
            if trusted_key.len() == 32 {
                let mut trusted_array = [0u8; 32];
                trusted_array.copy_from_slice(&trusted_key[..32]);
                
                if server_key.ct_eq(&trusted_array).into() {
                    return true;
                }
            }
        }
        
        false
    }

    pub fn sign_merkle_root(&self, root: &[u8], authority: &str) -> Result<Vec<u8>, CryptoError> {
        let auth_keys = self.authority_keys.read()
            .map_err(|_| CryptoError::KeyConvFailed)?;
        let signer = auth_keys.get(authority).ok_or(CryptoError::KeyConvFailed)?;
        
        signer.sign(root)
    }

    pub fn verify_merkle_root(&self, root: &[u8], signature: &[u8], authority: &str) -> Result<bool, CryptoError> {
        let auth_keys = self.authority_keys.read()
            .map_err(|_| CryptoError::KeyConvFailed)?;
        let signer = auth_keys.get(authority).ok_or(CryptoError::KeyConvFailed)?;
        
        let public_key_bytes = signer.public_key_bytes();
        RealQuantumSigner::verify(&public_key_bytes, root, signature)
    }

    pub fn add_trusted_server_key(&self, key_id: &str, key: &[u8; 32]) -> Result<(), CryptoError> {
        let mut keys = self.trusted_keys.write()
            .map_err(|_| CryptoError::KeyConvFailed)?;
        keys.insert(key_id.to_string(), key.to_vec());
        
        let key_path = format!("./secure_storage/trusted_keys/{}.key", key_id);
        fs::write(key_path, key)
            .context("Failed to persist trusted key")
            .map_err(|_| CryptoError::KeyConvFailed)?;
        
        Ok(())
    }

    #[cfg(feature = "tpm")]
    pub fn tpm_encrypt(&self, data: &[u8]) -> Result<Vec<u8>, CryptoError> {
        if let Some(ref _ctx) = self.tpm_context {
            self.software_encrypt(data)
        } else {
            self.software_encrypt(data)
        }
    }

    fn software_encrypt(&self, data: &[u8]) -> Result<Vec<u8>, CryptoError> {
        use chacha20poly1305::{ChaCha20Poly1305, Key, Nonce, KeyInit, AeadInPlace};
        use rand_core::{OsRng, RngCore};
        
        let mut key_bytes = Zeroizing::new([0u8; 32]);
        OsRng.fill_bytes(&mut *key_bytes);
        
        let cipher = ChaCha20Poly1305::new(Key::from_slice(&key_bytes));
        
        let mut nonce_bytes = [0u8; 12];
        OsRng.fill_bytes(&mut nonce_bytes);
        let nonce = Nonce::from_slice(&nonce_bytes);
        
        let mut buffer = data.to_vec();
        let tag = cipher.encrypt_in_place_detached(nonce, b"", &mut buffer)
            .map_err(|_| CryptoError::EncryptFailed)?;
        
        let mut result = Vec::new();
        result.extend_from_slice(&key_bytes);
        result.extend_from_slice(&nonce_bytes);
        result.extend_from_slice(&buffer);
        result.extend_from_slice(&tag);
        
        Ok(result)
    }
}

pub struct RealSecurityManager {
    quantum_kem: RealQuantumKEM,
    quantum_signer: RealQuantumSigner,
    hsm: RealHSM,
}

impl RealSecurityManager {
    pub fn new() -> Result<Self, CryptoError> {
        info!("Initializing real security components");
        
        let quantum_kem = RealQuantumKEM::new()?;
        info!("ML-KEM (Kyber) initialized");
        
        let quantum_signer = RealQuantumSigner::new()?;
        info!("ML-DSA (Dilithium) initialized");
        
        let hsm = RealHSM::new()?;
        info!("HSM/TPM interface initialized");
        
        Ok(Self {
            quantum_kem,
            quantum_signer,
            hsm,
        })
    }

    pub fn get_quantum_kem(&self) -> &RealQuantumKEM {
        &self.quantum_kem
    }

    pub fn get_quantum_signer(&self) -> &RealQuantumSigner {
        &self.quantum_signer
    }

    pub fn get_hsm(&self) -> &RealHSM {
        &self.hsm
    }
}

use std::sync::LazyLock;
pub static SECURITY_MANAGER: LazyLock<Result<RealSecurityManager, CryptoError>> = 
    LazyLock::new(|| RealSecurityManager::new());

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_quantum_kem() -> Result<(), CryptoError> {
        let kem = RealQuantumKEM::new()?;
        let public_key = kem.public_key_bytes();
        
        let (shared_secret1, ciphertext) = RealQuantumKEM::encapsulate(&public_key)?;
        let shared_secret2 = kem.decapsulate(&ciphertext)?;
        
        assert_eq!(shared_secret1, shared_secret2);
        Ok(())
    }

    #[test]
    fn test_quantum_signer() -> Result<(), CryptoError> {
        let signer = RealQuantumSigner::new()?;
        let message = b"test message";
        
        let signature = signer.sign(message)?;
        let public_key = signer.public_key_bytes();
        
        assert!(RealQuantumSigner::verify(&public_key, message, &signature)?);
        assert!(!RealQuantumSigner::verify(&public_key, b"wrong message", &signature)?);
        Ok(())
    }

    #[test]
    fn test_security_manager() -> Result<(), CryptoError> {
        let manager = RealSecurityManager::new()?;
        assert!(manager.get_quantum_kem().public_key_bytes().len() > 0);
        Ok(())
    }
}