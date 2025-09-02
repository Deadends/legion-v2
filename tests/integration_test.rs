use legion::prover::{
    service::{LegionService, LegionConfig},
    host_wrapper::AuthRequest,
    final_circuit::SecurityLevel,
};
use std::time::{SystemTime, UNIX_EPOCH};

#[tokio::test]
async fn test_production_authentication_flow() {
    let config = LegionConfig {
        security_level: SecurityLevel::Production,
        max_concurrent_proofs: 100,
        enable_metrics: true,
    };
    
    let service = LegionService::new(config);
    
    let request = AuthRequest {
        username: "test_user".to_string(),
        password: "secure_password_with_entropy_123!".to_string(),
        timestamp: SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_secs(),
        server_pubkey: [42u8; 32],
        ip_address: Some("127.0.0.1".to_string()),
    };
    
    let result = service.authenticate(request).await;
    assert!(result.is_ok());
    
    let proof = result.unwrap();
    assert!(!proof.is_empty());
    assert!(proof.len() > 100); // Reasonable proof size
}

#[tokio::test]
async fn test_batch_authentication() {
    let config = LegionConfig::default();
    let service = LegionService::new(config);
    
    let requests = (0..10).map(|i| AuthRequest {
        username: format!("user_{}", i),
        password: format!("password_with_entropy_{}!", i),
        timestamp: SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_secs(),
        server_pubkey: [42u8; 32],
        ip_address: Some("127.0.0.1".to_string()),
    }).collect();
    
    let result = service.batch_authenticate(requests).await;
    assert!(result.is_ok());
    
    let proofs = result.unwrap();
    assert_eq!(proofs.len(), 10);
}

#[tokio::test]
async fn test_rate_limiting() {
    let config = LegionConfig::default();
    let service = LegionService::new(config);
    
    let request = AuthRequest {
        username: "rate_limit_user".to_string(),
        password: "password_123!".to_string(),
        timestamp: SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_secs(),
        server_pubkey: [42u8; 32],
        ip_address: Some("127.0.0.1".to_string()),
    };
    
    // First few should succeed
    for _ in 0..3 {
        let result = service.authenticate(request.clone()).await;
        assert!(result.is_ok());
    }
    
    // Eventually should hit rate limit
    let mut hit_limit = false;
    for _ in 0..10 {
        if service.authenticate(request.clone()).await.is_err() {
            hit_limit = true;
            break;
        }
    }
    assert!(hit_limit, "Rate limiting should eventually trigger");
}