#![no_main]
use libfuzzer_sys::fuzz_target;
use arbitrary::{Arbitrary, Unstructured};
use legion_prover::{WorldClassAuthCircuit, SecurityLevel};

#[derive(Arbitrary, Debug)]
struct ProofInput {
    username: Vec<u8>,
    password: Vec<u8>,
    security_level: u8,
}

fuzz_target!(|data: &[u8]| {
    let mut u = Unstructured::new(data);
    if let Ok(input) = ProofInput::arbitrary(&mut u) {
        // Limit input sizes to prevent excessive memory usage
        if input.username.len() > 1000 || input.password.len() > 1000 {
            return;
        }
        
        // Map security level to valid enum
        let security_level = match input.security_level % 4 {
            0 => SecurityLevel::Standard,
            1 => SecurityLevel::Production,
            2 => SecurityLevel::Quantum,
            _ => SecurityLevel::Enterprise,
        };
        
        // Test circuit creation with fuzzy inputs
        let result = WorldClassAuthCircuit::new_enterprise(
            &input.username,
            &input.password,
            security_level,
            None, None, None, None, None
        );
        
        // If circuit creation succeeds, test public inputs
        if let Ok(circuit) = result {
            let public_inputs = circuit.public_inputs();
            
            // Verify we get expected number of outputs
            assert_eq!(public_inputs.len(), 6);
            
            // Test compliance validation
            let _ = circuit.validate_enterprise_compliance();
        }
    }
});