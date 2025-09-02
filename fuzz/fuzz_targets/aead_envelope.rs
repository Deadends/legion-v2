#![no_main]
use libfuzzer_sys::fuzz_target;
use arbitrary::{Arbitrary, Unstructured};
use legion_sidecar::secure_proof::SecureProofEnvelope;
use ed25519_dalek::SigningKey;
use rand::rngs::OsRng;

#[derive(Arbitrary, Debug)]
struct EnvelopeData {
    proof_data: Vec<u8>,
    session_key: [u8; 32],
    session_id: [u8; 32],
}

fuzz_target!(|data: &[u8]| {
    let mut u = Unstructured::new(data);
    if let Ok(envelope_data) = EnvelopeData::arbitrary(&mut u) {
        // Limit proof size to prevent excessive memory usage
        if envelope_data.proof_data.len() > 10000 {
            return;
        }
        
        // Generate signing key for testing
        let mut rng = OsRng;
        let signing_key = SigningKey::generate(&mut rng);
        let verifying_key = signing_key.verifying_key();
        
        // Test envelope creation
        if let Ok(envelope) = SecureProofEnvelope::seal(
            &envelope_data.proof_data,
            &envelope_data.session_key,
            &signing_key,
            &envelope_data.session_id,
        ) {
            // Test envelope verification and opening
            let result = envelope.verify_and_open(
                &envelope_data.session_key,
                &verifying_key,
                &envelope_data.session_id,
            );
            
            // If successful, verify data integrity
            if let Ok(decrypted) = result {
                assert_eq!(decrypted, envelope_data.proof_data);
            }
        }
        
        // Test with tampered data
        if envelope_data.proof_data.len() > 0 {
            let mut tampered_data = envelope_data.proof_data.clone();
            tampered_data[0] ^= 0x01;
            
            if let Ok(envelope) = SecureProofEnvelope::seal(
                &tampered_data,
                &envelope_data.session_key,
                &signing_key,
                &envelope_data.session_id,
            ) {
                // Should fail with wrong session key
                let wrong_key = [0xFFu8; 32];
                let result = envelope.verify_and_open(
                    &wrong_key,
                    &verifying_key,
                    &envelope_data.session_id,
                );
                assert!(result.is_err());
            }
        }
    }
});