use legion_sidecar::*;
use legion_prover::{WorldClassAuthCircuit, SecurityLevel};
use std::time::Duration;
use tempfile::TempDir;
use anyhow::{Result, Context};

#[tokio::test]
async fn test_complete_authentication_flow() -> Result<()> {
    let mut auth = AuthSystem::new()
        .context("Failed to create auth system")?;
    
    let session_id = auth.authenticate("alice", "secure_password_with_entropy_123!")
        .context("Authentication failed")?;
    assert_eq!(auth.session_count(), 1);
    
    let message = b"confidential data";
    let encrypted = auth.encrypt(&session_id, message, "client_to_server")
        .context("Encryption failed")?;
    let decrypted = auth.decrypt(&session_id, &encrypted, "client_to_server")
        .context("Decryption failed")?;
    assert_eq!(message, &decrypted[..]);
    
    auth.rotate_session_keys(&session_id)
        .context("Key rotation failed")?;
    
    let encrypted2 = auth.encrypt(&session_id, message, "client_to_server")
        .context("Encryption after rotation failed")?;
    let decrypted2 = auth.decrypt(&session_id, &encrypted2, "client_to_server")
        .context("Decryption after rotation failed")?;
    assert_eq!(message, &decrypted2[..]);
    
    Ok(())
}

#[tokio::test]
async fn test_session_store_persistence() -> Result<()> {
    let temp_dir = TempDir::new()
        .context("Failed to create temp dir")?;
    let store = SessionStore::new(temp_dir.path().to_str()
        .context("Invalid path")?)
        .context("Failed to create session store")?;
    
    let session_id = SessionId([0x42u8; 32]);
    let session_data = create_test_session_data();
    
    store.store_session(&session_id, &session_data, 3600)
        .context("Failed to store session")?;
    let retrieved = store.get_session(&session_id)
        .context("Failed to get session")?
        .context("Session not found")?;
    
    assert_eq!(session_data.verified, retrieved.verified);
    assert_eq!(session_data.keys.epoch, retrieved.keys.epoch);
    
    let cleaned = store.cleanup_expired()
        .context("Failed to cleanup expired sessions")?;
    assert_eq!(cleaned, 0);
    
    Ok(())
}

#[tokio::test]
async fn test_proof_envelope_security() -> Result<()> {
    use ed25519_dalek::SigningKey;
    use rand::rngs::OsRng;
    
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
    ).context("Failed to seal envelope")?;
    
    let decrypted = envelope.verify_and_open(
        &session_key,
        &verifying_key,
        &session_id
    ).context("Failed to verify and open envelope")?;
    
    assert_eq!(proof_data, &decrypted[..]);
    
    let wrong_key = [0xFFu8; 32];
    let result = envelope.verify_and_open(
        &wrong_key,
        &verifying_key,
        &session_id
    );
    assert!(result.is_err());
    
    Ok(())
}

#[tokio::test]
async fn test_async_proof_service() -> Result<()> {
    let service = AsyncProofService::new(Some(2))
        .context("Failed to create proof service")?;
    
    let circuit = WorldClassAuthCircuit::new_enterprise(
        b"test_user",
        b"test_password_with_sufficient_entropy_123!",
        SecurityLevel::Standard,
        None, None, None, None, None
    ).context("Failed to create circuit")?;
    
    let result = service.generate_proof(circuit).await;
    assert!(result.is_ok());
    
    let stats = service.get_performance_stats()
        .context("Failed to get performance stats")?;
    assert_eq!(stats.worker_count, 2);
    assert!(stats.total_completed >= 1);
    
    Ok(())
}

#[tokio::test]
async fn test_metrics_collection() -> Result<()> {
    let metrics = LegionMetrics::new()
        .context("Failed to create metrics")?;
    
    metrics.record_auth_attempt();
    metrics.record_auth_success(Duration::from_millis(10));
    metrics.record_proof_generation(Duration::from_millis(100), 4096);
    metrics.update_active_sessions(42);
    
    let registry = metrics.registry();
    let metric_families = registry.gather();
    assert!(!metric_families.is_empty());
    
    Ok(())
}

#[test]
fn test_cipher_negotiation() -> Result<()> {
    let negotiator = CipherNegotiator::new();
    
    let client_suites = vec![0x0001, 0x0002];
    let result = negotiator.negotiate(&client_suites);
    assert!(result.is_some());
    
    let client_suites = vec![0x9999];
    let result = negotiator.negotiate(&client_suites);
    assert!(result.is_none());
    
    Ok(())
}

#[test]
fn test_key_provider_file() -> Result<()> {
    let temp_dir = TempDir::new()
        .context("Failed to create temp dir")?;
    let key_path = temp_dir.path().join("test_key");
    let backup_path = temp_dir.path().join("backup");
    
    let mut provider = legion_sidecar::key_provider::FileKeyProvider::new(key_path, backup_path)
        .context("Failed to create key provider")?;
    
    let signing_key1 = provider.get_signing_key()
        .context("Failed to get signing key")?;
    let verifying_key1 = provider.get_verifying_key()
        .context("Failed to get verifying key")?;
    
    assert_eq!(signing_key1.verifying_key(), verifying_key1);
    
    let metadata = provider.rotate_keys()
        .context("Failed to rotate keys")?;
    assert_eq!(metadata.algorithm, "Ed25519");
    
    let signing_key2 = provider.get_signing_key()
        .context("Failed to get signing key after rotation")?;
    assert_ne!(signing_key1.to_bytes(), signing_key2.to_bytes());
    
    Ok(())
}

#[tokio::test]
async fn test_performance_benchmarks() -> Result<()> {
    let service = AsyncProofService::new(Some(4))
        .context("Failed to create proof service")?;
    
    let start = std::time::Instant::now();
    let mut tasks = Vec::new();
    
    for i in 0..100 {
        let username = format!("user_{}", i);
        let password = format!("password_with_entropy_{}!", i);
        
        let circuit = WorldClassAuthCircuit::new_enterprise(
            username.as_bytes(),
            password.as_bytes(),
            SecurityLevel::Standard,
            None, None, None, None, None
        ).context("Failed to create circuit")?;
        
        let service_clone = service.clone();
        let task = tokio::spawn(async move {
            service_clone.generate_proof(circuit).await
        });
        tasks.push(task);
    }
    
    let mut success_count = 0;
    for task in tasks {
        if task.await
            .context("Task panicked")?
            .is_ok() {
            success_count += 1;
        }
    }
    
    let duration = start.elapsed();
    let proofs_per_second = (success_count as f64) / duration.as_secs_f64();
    
    assert!(proofs_per_second > 50.0);
    assert_eq!(success_count, 100);
    
    Ok(())
}

fn create_test_session_data() -> SessionData {
    use std::time::SystemTime;
    
    SessionData {
        keys: SessionKeys {
            client_to_server: [0x01u8; 32],
            server_to_client: [0x02u8; 32],
            epoch: 0,
        },
        transcript_hash: [0x03u8; 32],
        c2s_nonce_gen: NonceGenerator::new(0, Direction::ClientToServer),
        s2c_nonce_gen: NonceGenerator::new(0, Direction::ServerToClient),
        created_at: SystemTime::now(),
        last_used: SystemTime::now(),
        verified: true,
    }
}

use legion_sidecar::auth::SessionId;

impl SessionId {
    pub fn new(bytes: [u8; 32]) -> Self {
        Self(bytes)
    }
}