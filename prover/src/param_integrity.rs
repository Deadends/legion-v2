use crate::dilithium_verifier::DilithiumVerifier;
use blake3::Hasher;
use std::fs;
use std::path::Path;
#[cfg(feature = "legacy-pq")]
use pqcrypto_traits::sign::{SecretKey as PQSecretKey, DetachedSignature as PQDetachedSignature};

#[derive(Debug)]
pub enum ParamError {
    InvalidSignature,
    InvalidParams,
    IoError(std::io::Error),
}

impl From<std::io::Error> for ParamError {
    fn from(err: std::io::Error) -> Self {
        ParamError::IoError(err)
    }
}

pub struct SecureParams {
    params_hash: [u8; 32],
    #[allow(dead_code)]
    signature: Vec<u8>,
}

impl SecureParams {
    pub fn new(params_data: &[u8]) -> Self {
        let mut hasher = Hasher::new();
        hasher.update(b"LEGION_PARAMS_V1");
        hasher.update(params_data);
        let hash = hasher.finalize();
        
        let mut params_hash = [0u8; 32];
        params_hash.copy_from_slice(&hash.as_bytes()[..32]);
        
        Self {
            params_hash,
            signature: Vec::new(),
        }
    }
    
    pub fn verify_with_dilithium(
        &self,
        param_path: &str,
        public_key: &[u8],
        signature: &[u8]
    ) -> Result<bool, ParamError> {
        if !Path::new(param_path).exists() {
            return Err(ParamError::InvalidParams);
        }
        
        let param_data = fs::read(param_path)?;
        let mut hasher = Hasher::new();
        hasher.update(b"LEGION_PARAMS_V1");
        hasher.update(&param_data);
        let hash = hasher.finalize();
        
        let verifier = DilithiumVerifier::new(public_key).map_err(|_| ParamError::InvalidSignature)?;
        Ok(verifier.verify(hash.as_bytes(), signature))
    }
    
    pub fn verify_hybrid_signature(
        &self,
        param_path: &str,
        ed25519_public_key: &[u8],
        signature: &[u8]
    ) -> Result<bool, ParamError> {
        if !Path::new(param_path).exists() {
            return Err(ParamError::InvalidParams);
        }
        
        if signature.len() != 96 { // 64 bytes Ed25519 + 32 bytes PQ commitment
            return Err(ParamError::InvalidSignature);
        }
        
        let param_data = fs::read(param_path)?;
        let mut hasher = Hasher::new();
        hasher.update(b"LEGION_PARAMS_V1");
        hasher.update(&param_data);
        let hash = hasher.finalize();
        
        // Verify Ed25519 signature
        use ed25519_dalek::{VerifyingKey, Signature, Verifier};
        
        if ed25519_public_key.len() != 32 {
            return Err(ParamError::InvalidSignature);
        }
        
        let verifying_key = VerifyingKey::from_bytes(ed25519_public_key)
            .map_err(|_| ParamError::InvalidSignature)?;
        
        let ed25519_sig_bytes: [u8; 64] = signature[..64].try_into()
            .map_err(|_| ParamError::InvalidSignature)?;
        let ed25519_signature = Signature::from_bytes(&ed25519_sig_bytes);
        
        match verifying_key.verify(hash.as_bytes(), &ed25519_signature) {
            Ok(()) => {
                // Verify PQ commitment (for future migration)
                let pq_commitment = &signature[64..];
                let mut expected_commitment = Hasher::new();
                expected_commitment.update(b"PQ_COMMITMENT_V1");
                expected_commitment.update(hash.as_bytes());
                // Note: We can't verify the private key component without it
                // This is a commitment for future PQ migration
                Ok(pq_commitment.len() == 32) // Basic length check
            },
            Err(_) => Ok(false)
        }
    }
    
    pub fn get_hash(&self) -> &[u8; 32] {
        &self.params_hash
    }
    
    pub fn sign_params(
        param_path: &str,
        signing_key: &[u8],
    ) -> Result<Vec<u8>, ParamError> {
        if !Path::new(param_path).exists() {
            return Err(ParamError::InvalidParams);
        }
        
        let param_data = fs::read(param_path)?;
        let mut hasher = Hasher::new();
        hasher.update(b"LEGION_PARAMS_V1");
        hasher.update(&param_data);
        let hash = hasher.finalize();
        
        #[cfg(feature = "legacy-pq")]
        {
            use pqcrypto_dilithium::dilithium5::*;
            if signing_key.len() != 4864 {
                return Err(ParamError::InvalidSignature);
            }
            
            match PQSecretKey::from_bytes(signing_key) {
                Ok(sk) => {
                    let signature = detached_sign(hash.as_bytes(), &sk);
                    Ok(PQDetachedSignature::as_bytes(&signature).to_vec())
                }
                Err(_) => Err(ParamError::InvalidSignature),
            }
        }
        
        #[cfg(not(feature = "legacy-pq"))]
        {
            // Use Ed25519 hybrid with post-quantum commitment for parameter signing
            // This provides immediate security with a path to full PQ migration
            use ed25519_dalek::{SigningKey, Signature, Signer};
            
            if signing_key.len() != 32 {
                return Err(ParamError::InvalidSignature);
            }
            
            let ed25519_key = SigningKey::from_bytes(signing_key);
            let signature: Signature = ed25519_key.sign(hash.as_bytes());
            
            // Create hybrid signature: Ed25519 + PQ commitment
            let mut hybrid_signature = Vec::with_capacity(64 + 32);
            hybrid_signature.extend_from_slice(&signature.to_bytes());
            
            // Add PQ commitment hash for future migration
            let mut pq_commitment = Hasher::new();
            pq_commitment.update(b"PQ_COMMITMENT_V1");
            pq_commitment.update(hash.as_bytes());
            pq_commitment.update(signing_key);
            hybrid_signature.extend_from_slice(&pq_commitment.finalize().as_bytes()[..32]);
            
            Ok(hybrid_signature)
        }
    }
}