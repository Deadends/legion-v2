#[derive(Debug, thiserror::Error)]
pub enum LegionError {
    #[error("Cryptographic error: {0}")]
    Crypto(#[from] CryptoError),
    #[error("Storage error: {0}")]
    Storage(#[from] StorageError),
    #[error("Authentication failed: {reason}")]
    Auth { reason: String },
    #[error("Rate limit exceeded")]
    RateLimit,
    #[error("Invalid input: {field}")]
    InvalidInput { field: String },
}

#[derive(Debug, thiserror::Error)]
pub enum CryptoError {
    #[error("Circuit constraint failed")]
    ConstraintFailed,
    #[error("Proof generation failed")]
    ProofFailed,
    #[error("Invalid nullifier")]
    InvalidNullifier,
}

#[derive(Debug, thiserror::Error)]
pub enum StorageError {
    #[error("Database connection failed")]
    ConnectionFailed,
    #[error("Serialization failed")]
    SerializationFailed,
}

pub type Result<T> = std::result::Result<T, LegionError>;