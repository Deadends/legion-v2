use pqcrypto_dilithium::dilithium5::*;
use pqcrypto_traits::sign::{PublicKey as PQPublicKey, DetachedSignature as PQDetachedSignature};
use std::error::Error;

pub struct DilithiumVerifier {
    public_key: PublicKey,
}

impl DilithiumVerifier {
    pub fn new(public_key_bytes: &[u8]) -> Result<Self, Box<dyn Error + Send + Sync>> {
        let public_key = PQPublicKey::from_bytes(public_key_bytes)
            .map_err(|_| "Invalid Dilithium public key")?;
        
        Ok(Self { public_key })
    }
    
    pub fn verify(&self, message: &[u8], signature: &[u8]) -> bool {
        // Try to create a DetachedSignature from the signature bytes
        if let Ok(detached_sig) = PQDetachedSignature::from_bytes(signature) {
            // Use verify_detached_signature function
            verify_detached_signature(&detached_sig, message, &self.public_key).is_ok()
        } else {
            false
        }
    }
}