// Integration tests for LEGION prover
use legion_prover::{WorldClassAuthCircuit, SecurityLevel, WorldClassAuthSystem};
use anyhow::Result;
use tracing::{info, warn, error, debug};

#[tokio::test]
async fn test_basic_authentication() -> Result<()> {
    WorldClassAuthSystem::initialize()
        .map_err(|e| anyhow::anyhow!("System initialization failed: {}", e))?;
    
    let circuit = WorldClassAuthCircuit::new_enterprise(
        b"test_user", 
        b"test_password_with_entropy_123!", 
        SecurityLevel::Standard,
        None, None, None, None, None
    )?;
    
    let proof = circuit.generate_enterprise_proof()
        .map_err(|e| anyhow::anyhow!("Proof generation failed: {}", e))?;
    
    if proof.is_empty() {
        return Err(anyhow::anyhow!("Proof should not be empty"));
    }
    
    let public_inputs = circuit.public_inputs();
    if public_inputs.len() != 6 {
        return Err(anyhow::anyhow!("Should have 6 public inputs, got {}", public_inputs.len()));
    }
    
    info!("Basic authentication test passed");
    Ok(())
}

#[tokio::test] 
async fn test_concurrent_authentication() -> Result<()> {
    WorldClassAuthSystem::initialize()
        .map_err(|e| anyhow::anyhow!("System initialization failed: {}", e))?;
    
    let handles: Vec<_> = (0..10).map(|i| {
        tokio::spawn(async move {
            let user_id = format!("user_{}", i);
            let password = format!("password_with_entropy_{}!", i);
            
            let circuit = WorldClassAuthCircuit::new_enterprise(
                user_id.as_bytes(), 
                password.as_bytes(), 
                SecurityLevel::Standard,
                None, None, None, None, None
            )?;
            
            let proof = circuit.generate_enterprise_proof()
                .map_err(|e| anyhow::anyhow!("Proof generation failed: {}", e))?;
            
            if proof.is_empty() {
                return Err(anyhow::anyhow!("Proof should not be empty"));
            }
            
            let public_inputs = circuit.public_inputs();
            if public_inputs.len() != 6 {
                return Err(anyhow::anyhow!("Should have 6 public inputs"));
            }
            
            Ok(())
        })
    }).collect();
    
    for handle in handles {
        handle.await
            .map_err(|e| anyhow::anyhow!("Task should complete successfully: {}", e))??;
    }
    
    info!("Concurrent authentication test passed");
    Ok(())
}

#[tokio::test]
async fn test_different_users_different_proofs() -> Result<()> {
    WorldClassAuthSystem::initialize()
        .map_err(|e| anyhow::anyhow!("System initialization failed: {}", e))?;
    
    let circuit1 = WorldClassAuthCircuit::new_enterprise(
        b"alice", 
        b"password123_with_entropy!", 
        SecurityLevel::Standard,
        None, None, None, None, None
    )?;
    
    let circuit2 = WorldClassAuthCircuit::new_enterprise(
        b"bob", 
        b"secret456_with_entropy!", 
        SecurityLevel::Standard,
        None, None, None, None, None
    )?;
    
    let inputs1 = circuit1.public_inputs();
    let inputs2 = circuit2.public_inputs();
    
    // Different users should have different commitments
    if inputs1[0] == inputs2[0] {
        return Err(anyhow::anyhow!("Different users should have different commitments"));
    }
    
    if inputs1[1] == inputs2[1] {
        return Err(anyhow::anyhow!("Different users should have different nullifiers"));
    }
    
    info!("Different users test passed");
    Ok(())
}