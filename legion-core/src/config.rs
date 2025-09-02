use serde::{Deserialize, Serialize};
use std::path::PathBuf;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LegionConfig {
    pub server: ServerConfig,
    pub crypto: CryptoConfig,
    pub storage: StorageConfig,
    pub security: SecurityConfig,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ServerConfig {
    pub host: String,
    pub port: u16,
    pub max_connections: usize,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CryptoConfig {
    pub circuit_size: u32,
    pub security_level: String,
    pub params_path: PathBuf,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StorageConfig {
    pub database_url: String,
    pub max_pool_size: u32,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SecurityConfig {
    pub rate_limit_per_minute: u32,
    pub max_login_attempts: u32,
    pub lockout_duration_secs: u64,
}

impl Default for LegionConfig {
    fn default() -> Self {
        Self {
            server: ServerConfig {
                host: "127.0.0.1".to_string(),
                port: 8080,
                max_connections: 1000,
            },
            crypto: CryptoConfig {
                circuit_size: 18,
                security_level: "Production".to_string(),
                params_path: PathBuf::from("./params"),
            },
            storage: StorageConfig {
                database_url: "sqlite://legion.db".to_string(),
                max_pool_size: 10,
            },
            security: SecurityConfig {
                rate_limit_per_minute: 60,
                max_login_attempts: 5,
                lockout_duration_secs: 3600,
            },
        }
    }
}