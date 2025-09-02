use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{SystemTime, UNIX_EPOCH, Duration};
use serde::{Serialize, Deserialize};
use blake3;
use rand::{RngCore, rngs::OsRng};
use zeroize::{Zeroize, ZeroizeOnDrop, Zeroizing};
use anyhow::{Result, Context};
use tracing::{info, warn, error, debug};

// Enterprise nonce constants
const NONCE_SIZE: usize = 12;
const EPOCH_DURATION: Duration = Duration::from_secs(3600); // 1 hour
const MAX_SEQUENCE_NUMBER: u64 = 0x7FFFFFFFFFFFFF; // 2^55 - 1
const NONCE_VALIDATION_WINDOW: u64 = 1000; // Allow 1000 nonces out of order
const CRYPTOGRAPHIC_NONCE_SIZE: usize = 32;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum Direction {
    ClientToServer = 0x01,
    ServerToClient = 0x02,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NonceState {
    pub epoch: u32,
    pub sequence: u64,
    pub timestamp: u64,
    pub direction: Direction,
}

#[derive(Debug, Clone, Serialize, Deserialize, ZeroizeOnDrop)]
pub struct CryptographicNonce {
    pub deterministic_part: [u8; NONCE_SIZE],
    pub cryptographic_part: Zeroizing<[u8; CRYPTOGRAPHIC_NONCE_SIZE]>,
    pub validation_hash: [u8; 32],
    pub generation_timestamp: SystemTime,
    pub security_level: u8,
}

#[derive(Debug)]
pub struct EnterpriseNonceGenerator {
    epoch: AtomicU64,
    sequence: AtomicU64,
    direction: Direction,
    session_key: Zeroizing<[u8; 32]>,
    nonce_history: std::sync::Mutex<std::collections::VecDeque<u64>>,
    validation_window: std::sync::RwLock<std::collections::HashMap<u64, SystemTime>>,
    entropy_pool: std::sync::Mutex<Zeroizing<[u8; 256]>>,
    security_level: u8,
}

impl EnterpriseNonceGenerator {
    pub fn new(epoch: u32, direction: Direction, session_key: [u8; 32]) -> Self {
        let mut entropy_pool = Zeroizing::new([0u8; 256]);
        OsRng.fill_bytes(&mut *entropy_pool);
        
        Self {
            epoch: AtomicU64::new(epoch as u64),
            sequence: AtomicU64::new(0),
            direction,
            session_key: Zeroizing::new(session_key),
            nonce_history: std::sync::Mutex::new(std::collections::VecDeque::with_capacity(1000)),
            validation_window: std::sync::RwLock::new(std::collections::HashMap::new()),
            entropy_pool: std::sync::Mutex::new(entropy_pool),
            security_level: 128, // Default security level
        }
    }
    
    pub fn new_enterprise(
        epoch: u32, 
        direction: Direction, 
        session_key: [u8; 32],
        security_level: u8
    ) -> Self {
        let mut generator = Self::new(epoch, direction, session_key);
        generator.security_level = security_level;
        generator
    }
    
    pub fn next_nonce(&self) -> Result<[u8; NONCE_SIZE]> {
        let current_epoch = self.epoch.load(Ordering::SeqCst);
        let sequence = self.sequence.fetch_add(1, Ordering::SeqCst);
        
        if sequence > MAX_SEQUENCE_NUMBER {
            return Err(anyhow::anyhow!("Sequence number overflow - epoch rotation required"));
        }
        
        let timestamp = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .context("System time error")?
            .as_secs();
        
        let mut nonce = [0u8; NONCE_SIZE];
        
        // Epoch (4 bytes)
        nonce[0..4].copy_from_slice(&(current_epoch as u32).to_le_bytes());
        
        // Sequence (7 bytes) - allows for 2^56 nonces per epoch
        let sequence_bytes = sequence.to_le_bytes();
        nonce[4..11].copy_from_slice(&sequence_bytes[..7]);
        
        // Direction (1 byte)
        nonce[11] = self.direction as u8;
        
        // Validate nonce uniqueness
        self.validate_nonce_uniqueness(sequence)?;
        
        // Record nonce in history
        self.record_nonce_generation(sequence)?;
        
        debug!("Generated nonce for epoch {} sequence {}", current_epoch, sequence);
        Ok(nonce)
    }
    
    pub fn generate_cryptographic_nonce(&self) -> Result<CryptographicNonce> {
        let deterministic_nonce = self.next_nonce()?;
        
        // Generate cryptographic component
        let mut cryptographic_part = Zeroizing::new([0u8; CRYPTOGRAPHIC_NONCE_SIZE]);
        
        // Mix session key with entropy pool
        let entropy_pool = self.entropy_pool.lock()
            .map_err(|_| anyhow::anyhow!("Entropy pool lock poisoned"))?;
        
        let mut hasher = blake3::Hasher::new();
        hasher.update(b"LEGION_CRYPTOGRAPHIC_NONCE_V1");
        hasher.update(&*self.session_key);
        hasher.update(&deterministic_nonce);
        hasher.update(&entropy_pool[..64]); // Use first 64 bytes of entropy
        hasher.update(&SystemTime::now().duration_since(UNIX_EPOCH)
            .context("System time error")?
            .as_nanos().to_le_bytes());
        
        let mut reader = hasher.finalize_xof();
        reader.fill(&mut **cryptographic_part);
        
        // Generate validation hash
        let mut validation_hasher = blake3::Hasher::new();
        validation_hasher.update(b"LEGION_NONCE_VALIDATION_V1");
        validation_hasher.update(&deterministic_nonce);
        validation_hasher.update(&**cryptographic_part);
        validation_hasher.update(&*self.session_key);
        let validation_hash = *validation_hasher.finalize().as_bytes();
        
        Ok(CryptographicNonce {
            deterministic_part: deterministic_nonce,
            cryptographic_part,
            validation_hash,
            generation_timestamp: SystemTime::now(),
            security_level: self.security_level,
        })
    }
    
    pub fn validate_nonce(&self, nonce: &[u8; NONCE_SIZE]) -> Result<NonceState> {
        if nonce.len() != NONCE_SIZE {
            return Err(anyhow::anyhow!("Invalid nonce size"));
        }
        
        // Extract components
        let epoch = u32::from_le_bytes([nonce[0], nonce[1], nonce[2], nonce[3]]);
        
        let mut sequence_bytes = [0u8; 8];
        sequence_bytes[..7].copy_from_slice(&nonce[4..11]);
        let sequence = u64::from_le_bytes(sequence_bytes);
        
        let direction_byte = nonce[11];
        let direction = match direction_byte {
            0x01 => Direction::ClientToServer,
            0x02 => Direction::ServerToClient,
            _ => return Err(anyhow::anyhow!("Invalid direction in nonce")),
        };
        
        // Validate epoch is current or recent
        let current_epoch = self.epoch.load(Ordering::SeqCst) as u32;
        if epoch > current_epoch || (current_epoch - epoch) > 2 {
            return Err(anyhow::anyhow!("Nonce epoch out of valid range"));
        }
        
        // Validate sequence number
        if sequence > MAX_SEQUENCE_NUMBER {
            return Err(anyhow::anyhow!("Sequence number too large"));
        }
        
        // Check for replay attacks
        self.check_replay_protection(sequence)?;
        
        let timestamp = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .context("System time error")?
            .as_secs();
        
        Ok(NonceState {
            epoch,
            sequence,
            timestamp,
            direction,
        })
    }
    
    pub fn validate_cryptographic_nonce(&self, crypto_nonce: &CryptographicNonce) -> Result<bool> {
        // Validate deterministic part
        let _nonce_state = self.validate_nonce(&crypto_nonce.deterministic_part)?;
        
        // Recompute validation hash
        let mut validation_hasher = blake3::Hasher::new();
        validation_hasher.update(b"LEGION_NONCE_VALIDATION_V1");
        validation_hasher.update(&crypto_nonce.deterministic_part);
        validation_hasher.update(&*crypto_nonce.cryptographic_part);
        validation_hasher.update(&*self.session_key);
        let expected_hash = *validation_hasher.finalize().as_bytes();
        
        if expected_hash != crypto_nonce.validation_hash {
            return Err(anyhow::anyhow!("Cryptographic nonce validation failed"));
        }
        
        // Check timestamp freshness
        let now = SystemTime::now();
        let age = now.duration_since(crypto_nonce.generation_timestamp)
            .context("Invalid nonce timestamp")?;
        
        if age > Duration::from_secs(300) { // 5 minute window
            return Err(anyhow::anyhow!("Cryptographic nonce too old"));
        }
        
        // Validate security level
        if crypto_nonce.security_level < self.security_level {
            return Err(anyhow::anyhow!("Insufficient nonce security level"));
        }
        
        Ok(true)
    }
    
    pub fn rotate_epoch(&self) -> u32 {
        let new_epoch = self.epoch.fetch_add(1, Ordering::SeqCst) + 1;
        self.sequence.store(0, Ordering::SeqCst);
        
        // Clear validation window for new epoch
        if let Ok(mut window) = self.validation_window.write() {
            window.clear();
        }
        
        // Refresh entropy pool
        if let Ok(mut entropy) = self.entropy_pool.lock() {
            OsRng.fill_bytes(&mut **entropy);
        }
        
        info!("Rotated to epoch {}", new_epoch);
        new_epoch as u32
    }
    
    pub fn current_state(&self) -> NonceState {
        let epoch = self.epoch.load(Ordering::SeqCst) as u32;
        let sequence = self.sequence.load(Ordering::SeqCst);
        let timestamp = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();
        
        NonceState {
            epoch,
            sequence,
            timestamp,
            direction: self.direction,
        }
    }
    
    fn validate_nonce_uniqueness(&self, sequence: u64) -> Result<()> {
        let history = self.nonce_history.lock()
            .map_err(|_| anyhow::anyhow!("Nonce history lock poisoned"))?;
        
        // Check if sequence number was recently used
        if history.contains(&sequence) {
            return Err(anyhow::anyhow!("Nonce sequence number recently used"));
        }
        
        Ok(())
    }
    
    fn record_nonce_generation(&self, sequence: u64) -> Result<()> {
        let mut history = self.nonce_history.lock()
            .map_err(|_| anyhow::anyhow!("Nonce history lock poisoned"))?;
        
        history.push_back(sequence);
        
        // Keep only recent history
        while history.len() > 1000 {
            history.pop_front();
        }
        
        // Update validation window
        if let Ok(mut window) = self.validation_window.write() {
            window.insert(sequence, SystemTime::now());
            
            // Cleanup old entries
            let cutoff = SystemTime::now() - Duration::from_secs(300);
            window.retain(|_, &mut timestamp| timestamp > cutoff);
        }
        
        Ok(())
    }
    
    fn check_replay_protection(&self, sequence: u64) -> Result<()> {
        let window = self.validation_window.read()
            .map_err(|_| anyhow::anyhow!("Validation window lock poisoned"))?;
        
        if window.contains_key(&sequence) {
            return Err(anyhow::anyhow!("Replay attack detected - sequence number already used"));
        }
        
        // Check if sequence is within acceptable window
        let current_sequence = self.sequence.load(Ordering::SeqCst);
        
        if sequence > current_sequence + NONCE_VALIDATION_WINDOW {
            return Err(anyhow::anyhow!("Sequence number too far in future"));
        }
        
        if current_sequence > sequence + NONCE_VALIDATION_WINDOW {
            return Err(anyhow::anyhow!("Sequence number too far in past"));
        }
        
        Ok(())
    }
    
    pub fn get_nonce_statistics(&self) -> Result<NonceStatistics> {
        let history = self.nonce_history.lock()
            .map_err(|_| anyhow::anyhow!("Nonce history lock poisoned"))?;
        let window = self.validation_window.read()
            .map_err(|_| anyhow::anyhow!("Validation window lock poisoned"))?;
        
        Ok(NonceStatistics {
            current_epoch: self.epoch.load(Ordering::SeqCst) as u32,
            current_sequence: self.sequence.load(Ordering::SeqCst),
            nonces_generated: history.len() as u64,
            validation_window_size: window.len(),
            direction: self.direction,
            security_level: self.security_level,
        })
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NonceStatistics {
    pub current_epoch: u32,
    pub current_sequence: u64,
    pub nonces_generated: u64,
    pub validation_window_size: usize,
    pub direction: Direction,
    pub security_level: u8,
}

// Legacy compatibility
pub type NonceGenerator = EnterpriseNonceGenerator;

#[cfg(test)]
mod tests {
    use super::*;
    
    #[test]
    fn test_enterprise_nonce_generation() -> Result<()> {
        let session_key = [42u8; 32];
        let generator = EnterpriseNonceGenerator::new(1, Direction::ClientToServer, session_key);
        
        let nonce1 = generator.next_nonce()?;
        let nonce2 = generator.next_nonce()?;
        
        assert_ne!(nonce1, nonce2);
        assert_eq!(nonce1[11], Direction::ClientToServer as u8);
        assert_eq!(nonce2[11], Direction::ClientToServer as u8);
        
        Ok(())
    }
    
    #[test]
    fn test_cryptographic_nonce() -> Result<()> {
        let session_key = [42u8; 32];
        let generator = EnterpriseNonceGenerator::new_enterprise(
            1, Direction::ClientToServer, session_key, 128
        );
        
        let crypto_nonce = generator.generate_cryptographic_nonce()?;
        assert!(generator.validate_cryptographic_nonce(&crypto_nonce)?);
        
        Ok(())
    }
    
    #[test]
    fn test_nonce_validation() -> Result<()> {
        let session_key = [42u8; 32];
        let generator = EnterpriseNonceGenerator::new(1, Direction::ClientToServer, session_key);
        
        let nonce = generator.next_nonce()?;
        let state = generator.validate_nonce(&nonce)?;
        
        assert_eq!(state.epoch, 1);
        assert_eq!(state.direction, Direction::ClientToServer);
        
        Ok(())
    }
    
    #[test]
    fn test_epoch_rotation() -> Result<()> {
        let session_key = [42u8; 32];
        let generator = EnterpriseNonceGenerator::new(1, Direction::ClientToServer, session_key);
        
        let old_epoch = generator.current_state().epoch;
        let new_epoch = generator.rotate_epoch();
        
        assert_eq!(new_epoch, old_epoch + 1);
        assert_eq!(generator.current_state().sequence, 0);
        
        Ok(())
    }
}