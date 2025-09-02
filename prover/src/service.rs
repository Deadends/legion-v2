use crate::final_circuit::{WorldClassAuthCircuit, SecurityLevel};
use crate::host_wrapper::{AuthHost, AuthRequest};
use halo2curves::pasta::Fp;
use std::sync::Arc;
use tokio::sync::RwLock;
use tracing::{info, error};

pub struct LegionService {
    auth_host: Arc<RwLock<AuthHost>>,
    config: LegionConfig,
}

#[derive(Clone)]
pub struct LegionConfig {
    pub security_level: SecurityLevel,
    pub max_concurrent_proofs: usize,
    pub enable_metrics: bool,
}

impl Default for LegionConfig {
    fn default() -> Self {
        Self {
            security_level: SecurityLevel::Production,
            max_concurrent_proofs: 100,
            enable_metrics: true,
        }
    }
}

impl LegionService {
    pub fn new(config: LegionConfig) -> Self {
        Self {
            auth_host: Arc::new(RwLock::new(AuthHost::new())),
            config,
        }
    }

    pub async fn authenticate(&self, request: AuthRequest) -> Result<Vec<u8>, Box<dyn std::error::Error + Send + Sync>> {
        let mut host = self.auth_host.write().await;
        
        let (circuit, _public_inputs) = host.authenticate(request, self.config.security_level)?;
        
        let proof = circuit.generate_enterprise_proof()?;
        
        info!("Authentication successful, proof generated");
        Ok(proof)
    }

    pub async fn batch_authenticate(&self, requests: Vec<AuthRequest>) -> Result<Vec<Vec<u8>>, Box<dyn std::error::Error + Send + Sync>> {
        if requests.len() > self.config.max_concurrent_proofs {
            return Err("Too many concurrent requests".into());
        }

        let mut proofs = Vec::with_capacity(requests.len());
        
        for request in requests {
            match self.authenticate(request).await {
                Ok(proof) => proofs.push(proof),
                Err(e) => {
                    error!("Batch authentication failed: {}", e);
                    return Err(e);
                }
            }
        }

        Ok(proofs)
    }
}