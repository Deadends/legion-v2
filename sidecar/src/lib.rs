pub mod crypto;
pub mod auth;
pub mod proof_verifier;
pub mod session_manager;
pub mod key_schedule;
pub mod nonce;
pub mod aad;
pub mod secure_proof;
pub mod session_store;
pub mod key_provider;
pub mod metrics;
pub mod threadpool;
pub mod cipher_negotiation;

pub use crypto::*;
pub use auth::{AuthSystem, SessionData, SessionMetadata};
pub use proof_verifier::*;
pub use session_manager::{SessionManager, SessionTicket};
pub use key_schedule::{KeySchedule, SessionKeys};
pub use nonce::{NonceGenerator, Direction, NonceState};
pub use aad::AadBuilder;
pub use secure_proof::SecureProofEnvelope;
pub use session_store::SessionStore;
pub use key_provider::{KeyProvider, KeyMetadata, create_key_provider};
pub use metrics::LegionMetrics;
pub use threadpool::{AsyncProofService, ThreadPoolStats};
pub use cipher_negotiation::{CipherSuite, CipherNegotiator};

use anyhow::Result;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_verify_first_session_creation() -> Result<()> {
        let mut auth = AuthSystem::new()?;
        
        let session_id = auth.authenticate("alice", "secure_password_123!")?;
        assert_eq!(auth.session_count(), 1);
        
        let message = b"test message";
        let encrypted = auth.encrypt(&session_id, message, "client_to_server")?;
        let decrypted = auth.decrypt(&session_id, &encrypted, "client_to_server")?;
        assert_eq!(message, &decrypted[..]);
        
        Ok(())
    }

    #[test]
    fn test_deterministic_nonces() -> Result<()> {
        let gen = NonceGenerator::new(1, Direction::ClientToServer);
        
        let nonce1 = gen.next_nonce()?;
        let nonce2 = gen.next_nonce()?;
        
        assert_ne!(nonce1, nonce2);
        assert_eq!(&nonce1[0..4], &1u32.to_le_bytes());
        assert_eq!(&nonce1[4..11], &0u64.to_le_bytes()[..7]);
        assert_eq!(nonce1[11], 0x01);
        assert_eq!(&nonce2[4..11], &1u64.to_le_bytes()[..7]);
        
        Ok(())
    }

    #[test]
    fn test_hkdf_transcript_binding() -> Result<()> {
        let shared_secret = b"test_shared_secret_32_bytes_long";
        let salt = b"test_salt_32_bytes_long_exactly!";
        let transcript1 = [0x42u8; 32];
        let transcript2 = [0x43u8; 32];
        let session_id = [0x01u8; 32];
        
        let ks1 = KeySchedule::new(shared_secret, salt, transcript1)?;
        let ks2 = KeySchedule::new(shared_secret, salt, transcript2)?;
        
        let keys1 = ks1.derive_session_keys(&session_id, 0)?;
        let keys2 = ks2.derive_session_keys(&session_id, 0)?;
        
        assert_ne!(*keys1.client_to_server, *keys2.client_to_server);
        assert_ne!(*keys1.server_to_client, *keys2.server_to_client);
        
        Ok(())
    }

    #[test]
    fn test_aad_standardization() -> Result<()> {
        let session_id = [0x01u8; 32];
        let epoch = 42u32;
        let direction = Direction::ClientToServer;
        let transcript = [0x02u8; 32];
        let sequence = 1337u64;

        let aad = AadBuilder::build(&session_id, epoch, direction, &transcript, sequence);
        
        assert_eq!(aad.len(), 79);
        
        assert!(AadBuilder::validate_aad(
            &aad, &session_id, epoch, direction, &transcript, sequence
        ).is_ok());
        
        assert!(AadBuilder::validate_aad(
            &aad, &session_id, epoch + 1, direction, &transcript, sequence
        ).is_err());
        
        Ok(())
    }

    #[test]
    fn test_session_metadata_access() -> Result<()> {
        let mut auth = AuthSystem::new()?;
        let session_id = auth.authenticate("alice", "secure_password_123!")?;
        
        let metadata = auth.get_session_metadata(&session_id)
            .ok_or_else(|| anyhow::anyhow!("Session metadata not found"))?;
        assert_eq!(metadata.session_id, session_id);
        assert!(metadata.verified);
        
        let cleaned = auth.cleanup_expired_sessions(0);
        assert_eq!(cleaned, 1);
        assert!(auth.get_session_metadata(&session_id).is_none());
        
        Ok(())
    }
}