use serde::{Serialize, Deserialize};
use blake3;
use std::time::{SystemTime, UNIX_EPOCH};
use crate::enterprise_nonce::Direction;
use anyhow::{Result, Context};
use tracing::{info, warn, error, debug};

// Advanced AAD constants
const AAD_VERSION: u8 = 2;
const MAX_AAD_SIZE: usize = 1024;
const CONTEXT_HASH_SIZE: usize = 32;
const SECURITY_LABEL_SIZE: usize = 16;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AdvancedAadBuilder {
    version: u8,
    security_level: u8,
    compliance_flags: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AadContext {
    pub session_id: [u8; 32],
    pub epoch: u32,
    pub direction: Direction,
    pub transcript_hash: [u8; 32],
    pub sequence: u64,
    pub timestamp: u64,
    pub security_context: SecurityContext,
    pub compliance_metadata: ComplianceMetadata,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SecurityContext {
    pub threat_level: u8,
    pub encryption_algorithm: String,
    pub key_derivation_method: String,
    pub forward_secrecy_enabled: bool,
    pub quantum_resistant: bool,
    pub security_labels: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ComplianceMetadata {
    pub data_classification: String,
    pub retention_policy: String,
    pub audit_required: bool,
    pub pci_dss_scope: bool,
    pub hipaa_scope: bool,
    pub gdpr_scope: bool,
    pub compliance_hash: [u8; 32],
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EnhancedAad {
    pub version: u8,
    pub core_aad: Vec<u8>,
    pub security_context_hash: [u8; 32],
    pub compliance_hash: [u8; 32],
    pub integrity_check: [u8; 32],
    pub generation_timestamp: u64,
}

impl AdvancedAadBuilder {
    pub fn new(security_level: u8) -> Self {
        Self {
            version: AAD_VERSION,
            security_level,
            compliance_flags: 0,
        }
    }
    
    pub fn build_enhanced(
        &self,
        session_id: &[u8; 32],
        epoch: u32,
        direction: Direction,
        transcript_hash: &[u8; 32],
        sequence: u64,
        security_context: SecurityContext,
        compliance_metadata: ComplianceMetadata,
    ) -> Result<EnhancedAad> {
        let timestamp = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .context("System time error")?
            .as_secs();
        
        let context = AadContext {
            session_id: *session_id,
            epoch,
            direction,
            transcript_hash: *transcript_hash,
            sequence,
            timestamp,
            security_context: security_context.clone(),
            compliance_metadata: compliance_metadata.clone(),
        };
        
        // Build core AAD
        let core_aad = self.build_core_aad(&context)?;
        
        // Generate security context hash
        let security_context_hash = self.hash_security_context(&security_context)?;
        
        // Generate compliance hash
        let compliance_hash = self.hash_compliance_metadata(&compliance_metadata)?;
        
        // Generate integrity check
        let integrity_check = self.generate_integrity_check(
            &core_aad,
            &security_context_hash,
            &compliance_hash,
            timestamp
        )?;
        
        debug!("Built enhanced AAD for session {} epoch {}", hex::encode(&session_id[..8]), epoch);
        
        Ok(EnhancedAad {
            version: self.version,
            core_aad,
            security_context_hash,
            compliance_hash,
            integrity_check,
            generation_timestamp: timestamp,
        })
    }
    
    fn build_core_aad(&self, context: &AadContext) -> Result<Vec<u8>> {
        let mut aad = Vec::with_capacity(256);
        
        // Version and security level
        aad.push(self.version);
        aad.push(self.security_level);
        
        // Session context
        aad.extend_from_slice(&context.session_id);
        aad.extend_from_slice(&context.epoch.to_le_bytes());
        aad.push(context.direction as u8);
        aad.extend_from_slice(&context.transcript_hash);
        aad.extend_from_slice(&context.sequence.to_le_bytes());
        aad.extend_from_slice(&context.timestamp.to_le_bytes());
        
        // Security flags
        let mut security_flags = 0u32;
        if context.security_context.forward_secrecy_enabled {
            security_flags |= 0x01;
        }
        if context.security_context.quantum_resistant {
            security_flags |= 0x02;
        }
        if context.compliance_metadata.audit_required {
            security_flags |= 0x04;
        }
        aad.extend_from_slice(&security_flags.to_le_bytes());
        
        // Compliance flags
        aad.extend_from_slice(&self.compliance_flags.to_le_bytes());
        
        // Threat level
        aad.push(context.security_context.threat_level);
        
        if aad.len() > MAX_AAD_SIZE {
            return Err(anyhow::anyhow!("AAD size exceeds maximum"));
        }
        
        Ok(aad)
    }
    
    fn hash_security_context(&self, context: &SecurityContext) -> Result<[u8; 32]> {
        let mut hasher = blake3::Hasher::new();
        hasher.update(b"LEGION_SECURITY_CONTEXT_V2");
        hasher.update(&[context.threat_level]);
        hasher.update(context.encryption_algorithm.as_bytes());
        hasher.update(context.key_derivation_method.as_bytes());
        hasher.update(&[context.forward_secrecy_enabled as u8]);
        hasher.update(&[context.quantum_resistant as u8]);
        
        // Hash security labels
        for label in &context.security_labels {
            hasher.update(label.as_bytes());
        }
        
        Ok(*hasher.finalize().as_bytes())
    }
    
    fn hash_compliance_metadata(&self, metadata: &ComplianceMetadata) -> Result<[u8; 32]> {
        let mut hasher = blake3::Hasher::new();
        hasher.update(b"LEGION_COMPLIANCE_METADATA_V2");
        hasher.update(metadata.data_classification.as_bytes());
        hasher.update(metadata.retention_policy.as_bytes());
        hasher.update(&[metadata.audit_required as u8]);
        hasher.update(&[metadata.pci_dss_scope as u8]);
        hasher.update(&[metadata.hipaa_scope as u8]);
        hasher.update(&[metadata.gdpr_scope as u8]);
        hasher.update(&metadata.compliance_hash);
        
        Ok(*hasher.finalize().as_bytes())
    }
    
    fn generate_integrity_check(
        &self,
        core_aad: &[u8],
        security_hash: &[u8; 32],
        compliance_hash: &[u8; 32],
        timestamp: u64
    ) -> Result<[u8; 32]> {
        let mut hasher = blake3::Hasher::new();
        hasher.update(b"LEGION_AAD_INTEGRITY_V2");
        hasher.update(&[self.version]);
        hasher.update(&[self.security_level]);
        hasher.update(core_aad);
        hasher.update(security_hash);
        hasher.update(compliance_hash);
        hasher.update(&timestamp.to_le_bytes());
        hasher.update(&self.compliance_flags.to_le_bytes());
        
        Ok(*hasher.finalize().as_bytes())
    }
    
    pub fn validate_enhanced_aad(&self, aad: &EnhancedAad) -> Result<bool> {
        // Version check
        if aad.version != self.version {
            return Err(anyhow::anyhow!("AAD version mismatch"));
        }
        
        // Size validation
        if aad.core_aad.len() > MAX_AAD_SIZE {
            return Err(anyhow::anyhow!("AAD size exceeds maximum"));
        }
        
        // Timestamp freshness check (within 5 minutes)
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .context("System time error")?
            .as_secs();
        
        if now > aad.generation_timestamp + 300 {
            return Err(anyhow::anyhow!("AAD timestamp too old"));
        }
        
        // Recompute integrity check
        let expected_integrity = self.generate_integrity_check(
            &aad.core_aad,
            &aad.security_context_hash,
            &aad.compliance_hash,
            aad.generation_timestamp
        )?;
        
        if expected_integrity != aad.integrity_check {
            return Err(anyhow::anyhow!("AAD integrity check failed"));
        }
        
        Ok(true)
    }
    
    pub fn serialize_aad(&self, aad: &EnhancedAad) -> Result<Vec<u8>> {
        let mut serialized = Vec::with_capacity(
            1 + aad.core_aad.len() + 32 + 32 + 32 + 8
        );
        
        serialized.push(aad.version);
        serialized.extend_from_slice(&(aad.core_aad.len() as u32).to_le_bytes());
        serialized.extend_from_slice(&aad.core_aad);
        serialized.extend_from_slice(&aad.security_context_hash);
        serialized.extend_from_slice(&aad.compliance_hash);
        serialized.extend_from_slice(&aad.integrity_check);
        serialized.extend_from_slice(&aad.generation_timestamp.to_le_bytes());
        
        Ok(serialized)
    }
    
    pub fn deserialize_aad(&self, data: &[u8]) -> Result<EnhancedAad> {
        if data.len() < 1 + 4 + 32 + 32 + 32 + 8 {
            return Err(anyhow::anyhow!("AAD data too short"));
        }
        
        let version = data[0];
        if version != self.version {
            return Err(anyhow::anyhow!("AAD version mismatch"));
        }
        
        let core_aad_len = u32::from_le_bytes([data[1], data[2], data[3], data[4]]) as usize;
        if core_aad_len > MAX_AAD_SIZE {
            return Err(anyhow::anyhow!("AAD core size too large"));
        }
        
        let expected_len = 1 + 4 + core_aad_len + 32 + 32 + 32 + 8;
        if data.len() != expected_len {
            return Err(anyhow::anyhow!("AAD data length mismatch"));
        }
        
        let core_aad = data[5..5 + core_aad_len].to_vec();
        
        let mut security_context_hash = [0u8; 32];
        security_context_hash.copy_from_slice(&data[5 + core_aad_len..5 + core_aad_len + 32]);
        
        let mut compliance_hash = [0u8; 32];
        compliance_hash.copy_from_slice(&data[5 + core_aad_len + 32..5 + core_aad_len + 64]);
        
        let mut integrity_check = [0u8; 32];
        integrity_check.copy_from_slice(&data[5 + core_aad_len + 64..5 + core_aad_len + 96]);
        
        let generation_timestamp = u64::from_le_bytes([
            data[5 + core_aad_len + 96],
            data[5 + core_aad_len + 97],
            data[5 + core_aad_len + 98],
            data[5 + core_aad_len + 99],
            data[5 + core_aad_len + 100],
            data[5 + core_aad_len + 101],
            data[5 + core_aad_len + 102],
            data[5 + core_aad_len + 103],
        ]);
        
        let aad = EnhancedAad {
            version,
            core_aad,
            security_context_hash,
            compliance_hash,
            integrity_check,
            generation_timestamp,
        };
        
        // Validate the deserialized AAD
        self.validate_enhanced_aad(&aad)?;
        
        Ok(aad)
    }
    
    pub fn set_compliance_flags(&mut self, flags: u64) {
        self.compliance_flags = flags;
    }
    
    pub fn add_compliance_flag(&mut self, flag: u64) {
        self.compliance_flags |= flag;
    }
}

// Legacy compatibility wrapper
pub struct AadBuilder;

impl AadBuilder {
    pub fn build(
        session_id: &[u8; 32],
        epoch: u32,
        direction: Direction,
        transcript_hash: &[u8; 32],
        sequence: u64,
    ) -> Vec<u8> {
        let mut aad = Vec::with_capacity(79);
        aad.extend_from_slice(session_id);
        aad.extend_from_slice(&epoch.to_le_bytes());
        aad.push(direction as u8);
        aad.extend_from_slice(transcript_hash);
        aad.extend_from_slice(&sequence.to_le_bytes());
        aad
    }
    
    pub fn validate_aad(
        aad: &[u8],
        session_id: &[u8; 32],
        epoch: u32,
        direction: Direction,
        transcript_hash: &[u8; 32],
        sequence: u64,
    ) -> Result<()> {
        let expected = Self::build(session_id, epoch, direction, transcript_hash, sequence);
        if aad == expected {
            Ok(())
        } else {
            Err(anyhow::anyhow!("AAD validation failed"))
        }
    }
}

impl Default for SecurityContext {
    fn default() -> Self {
        Self {
            threat_level: 1,
            encryption_algorithm: "ChaCha20Poly1305".to_string(),
            key_derivation_method: "HKDF-BLAKE3".to_string(),
            forward_secrecy_enabled: true,
            quantum_resistant: false,
            security_labels: vec!["STANDARD".to_string()],
        }
    }
}

impl Default for ComplianceMetadata {
    fn default() -> Self {
        Self {
            data_classification: "PUBLIC".to_string(),
            retention_policy: "STANDARD".to_string(),
            audit_required: false,
            pci_dss_scope: false,
            hipaa_scope: false,
            gdpr_scope: false,
            compliance_hash: [0u8; 32],
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    
    #[test]
    fn test_enhanced_aad_build_and_validate() -> Result<()> {
        let builder = AdvancedAadBuilder::new(128);
        let session_id = [1u8; 32];
        let transcript_hash = [2u8; 32];
        
        let aad = builder.build_enhanced(
            &session_id,
            1,
            Direction::ClientToServer,
            &transcript_hash,
            100,
            SecurityContext::default(),
            ComplianceMetadata::default(),
        )?;
        
        assert!(builder.validate_enhanced_aad(&aad)?);
        Ok(())
    }
    
    #[test]
    fn test_aad_serialization() -> Result<()> {
        let builder = AdvancedAadBuilder::new(128);
        let session_id = [1u8; 32];
        let transcript_hash = [2u8; 32];
        
        let aad = builder.build_enhanced(
            &session_id,
            1,
            Direction::ClientToServer,
            &transcript_hash,
            100,
            SecurityContext::default(),
            ComplianceMetadata::default(),
        )?;
        
        let serialized = builder.serialize_aad(&aad)?;
        let deserialized = builder.deserialize_aad(&serialized)?;
        
        assert_eq!(aad.version, deserialized.version);
        assert_eq!(aad.core_aad, deserialized.core_aad);
        assert_eq!(aad.integrity_check, deserialized.integrity_check);
        
        Ok(())
    }
}