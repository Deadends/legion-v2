use legion_sidecar::*;
use std::time::Instant;
use tracing::{info, warn, error};
use anyhow::Result;
use dotenvy::dotenv;

fn main() -> Result<()> {
    dotenv().ok();
    tracing_subscriber::fmt::init();
    
    info!("LEGION REAL TEST");
    info!("==================");
    
    let mut auth = AuthSystem::new()?;
    let start = Instant::now();
    let mut count = 0;
    
    while start.elapsed().as_secs() < 5 {
        match auth.authenticate("alice", "password123") {
            Ok(_) => count += 1,
            Err(e) => warn!("Auth failed: {}", e),
        }
    }
    
    let elapsed = start.elapsed();
    let rate = count as f64 / elapsed.as_secs_f64();
    
    info!("ZK Authentications: {} in {:.2}s", count, elapsed.as_secs_f64());
    info!("Rate: {:.4} proofs/second", rate);
    
    let session_id = auth.authenticate("alice", "password123")?;
    let message = b"Hello Legion";
    let encrypted = auth.encrypt(&session_id, message, "client_to_server")?;
    let decrypted = auth.decrypt(&session_id, &encrypted, "client_to_server")?;
    
    info!("Encryption test: {}", if message == &decrypted[..] { "PASS" } else { "FAIL" });
    info!("Sessions: {}", auth.session_count());
    
    Ok(())
}