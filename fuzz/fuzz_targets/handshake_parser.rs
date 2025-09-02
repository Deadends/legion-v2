#![no_main]
use libfuzzer_sys::fuzz_target;
use arbitrary::{Arbitrary, Unstructured};

#[derive(Arbitrary, Debug)]
struct HandshakeData {
    client_hello: Vec<u8>,
    server_hello: Vec<u8>,
    proof_data: Vec<u8>,
    timestamp: u64,
}

fuzz_target!(|data: &[u8]| {
    let mut u = Unstructured::new(data);
    if let Ok(handshake) = HandshakeData::arbitrary(&mut u) {
        // Test transcript hash computation
        let _ = legion_sidecar::key_schedule::KeySchedule::compute_transcript_hash(
            &handshake.client_hello,
            &handshake.server_hello,
            &handshake.proof_data,
            handshake.timestamp,
        );
        
        // Test key schedule creation with fuzzy inputs
        if handshake.client_hello.len() >= 32 && handshake.server_hello.len() >= 32 {
            let shared_secret = &handshake.client_hello[..32];
            let salt = &handshake.server_hello[..32];
            let transcript = [0u8; 32]; // Fixed transcript for fuzzing
            
            if let Ok(ks) = legion_sidecar::key_schedule::KeySchedule::new(
                shared_secret, salt, transcript
            ) {
                let session_id = [0x42u8; 32];
                let _ = ks.derive_session_keys(&session_id, 0);
            }
        }
    }
});