use std::collections::{HashMap, HashSet};
use std::sync::{Arc, Mutex};
use rand::{Rng, rngs::StdRng};
use blake3::Hasher;
use crate::property_fuzzer::{FuzzInput, MutationStrategy};
use anyhow::{Result, Context};
use tracing::{info, warn, error, debug};

// Advanced mutation engine with structure-aware mutations
pub struct MutationEngine {
    strategies: Vec<Box<dyn MutationStrategyTrait + Send + Sync>>,
    interesting_values: Vec<Vec<u8>>,
    dictionary: HashSet<Vec<u8>>,
    rng: Arc<Mutex<StdRng>>,
}

pub trait MutationStrategyTrait: Send + Sync {
    fn mutate(&self, input: &FuzzInput, rng: &mut StdRng) -> Result<FuzzInput>;
    fn name(&self) -> &str;
    fn weight(&self) -> f64; // Higher weight = more likely to be selected
}

// Bit flip mutation
pub struct BitFlipMutation;

impl MutationStrategyTrait for BitFlipMutation {
    fn mutate(&self, input: &FuzzInput, rng: &mut StdRng) -> Result<FuzzInput> {
        if input.data.is_empty() {
            return Err(anyhow::anyhow!("Empty input"));
        }
        
        let mut new_data = input.data.clone();
        let position = rng.gen_range(0..new_data.len());
        let bit_position = rng.gen_range(0..8);
        
        new_data[position] ^= 1 << bit_position;
        
        let mut new_input = input.clone();
        new_input.data = new_data;
        new_input.generation += 1;
        new_input.mutations_applied.push(MutationStrategy::BitFlip {
            position,
            bits: 1 << bit_position,
        });
        new_input.parent_hash = Some(self.hash_input(input));
        
        debug!("Applied bit flip mutation at position {} bit {}", position, bit_position);
        Ok(new_input)
    }
    
    fn name(&self) -> &str {
        "bit_flip"
    }
    
    fn weight(&self) -> f64 {
        1.0
    }
}

impl BitFlipMutation {
    fn hash_input(&self, input: &FuzzInput) -> [u8; 32] {
        let mut hasher = Hasher::new();
        hasher.update(&input.data);
        *hasher.finalize().as_bytes()
    }
}

// Arithmetic mutation
pub struct ArithmeticMutation;

impl MutationStrategyTrait for ArithmeticMutation {
    fn mutate(&self, input: &FuzzInput, rng: &mut StdRng) -> Result<FuzzInput> {
        if input.data.len() < 4 {
            return Err(anyhow::anyhow!("Input too small for arithmetic mutation"));
        }
        
        let mut new_data = input.data.clone();
        let position = rng.gen_range(0..new_data.len() - 3);
        let value = rng.gen_range(-1000..1000);
        
        // Interpret bytes as little-endian u32
        let mut bytes = [0u8; 4];
        bytes.copy_from_slice(&new_data[position..position + 4]);
        let mut num = u32::from_le_bytes(bytes);
        
        if value >= 0 {
            num = num.wrapping_add(value as u32);
        } else {
            num = num.wrapping_sub((-value) as u32);
        }
        
        let new_bytes = num.to_le_bytes();
        new_data[position..position + 4].copy_from_slice(&new_bytes);
        
        let mut new_input = input.clone();
        new_input.data = new_data;
        new_input.generation += 1;
        new_input.mutations_applied.push(if value >= 0 {
            MutationStrategy::ArithmeticAdd { position, value }
        } else {
            MutationStrategy::ArithmeticSub { position, value: -value }
        });
        new_input.parent_hash = Some(self.hash_input(input));
        
        debug!("Applied arithmetic mutation at position {} value {}", position, value);
        Ok(new_input)
    }
    
    fn name(&self) -> &str {
        "arithmetic"
    }
    
    fn weight(&self) -> f64 {
        0.8
    }
}

impl ArithmeticMutation {
    fn hash_input(&self, input: &FuzzInput) -> [u8; 32] {
        let mut hasher = Hasher::new();
        hasher.update(&input.data);
        *hasher.finalize().as_bytes()
    }
}

// Dictionary-based mutation
pub struct DictionaryMutation {
    dictionary: Vec<Vec<u8>>,
}

impl DictionaryMutation {
    pub fn new() -> Self {
        let dictionary = vec![
            b"LEGION".to_vec(),
            b"AUTH".to_vec(),
            b"PROOF".to_vec(),
            b"SESSION".to_vec(),
            b"NONCE".to_vec(),
            b"SIGNATURE".to_vec(),
            b"CERTIFICATE".to_vec(),
            b"HANDSHAKE".to_vec(),
            b"\x00\x00\x00\x00".to_vec(), // NULL bytes
            b"\xFF\xFF\xFF\xFF".to_vec(), // Max bytes
            b"\x01\x00\x00\x00".to_vec(), // Little-endian 1
            b"\x00\x00\x00\x01".to_vec(), // Big-endian 1
        ];
        
        Self { dictionary }
    }
}

impl MutationStrategyTrait for DictionaryMutation {
    fn mutate(&self, input: &FuzzInput, rng: &mut StdRng) -> Result<FuzzInput> {
        if self.dictionary.is_empty() {
            return Err(anyhow::anyhow!("Empty dictionary"));
        }
        
        let word = &self.dictionary[rng.gen_range(0..self.dictionary.len())];
        let mut new_data = input.data.clone();
        
        if new_data.len() < word.len() {
            // Extend the input if necessary
            new_data.resize(word.len(), 0);
        }
        
        let position = if new_data.len() == word.len() {
            0
        } else {
            rng.gen_range(0..new_data.len() - word.len() + 1)
        };
        
        // Replace bytes at position with dictionary word
        new_data[position..position + word.len()].copy_from_slice(word);
        
        let mut new_input = input.clone();
        new_input.data = new_data;
        new_input.generation += 1;
        new_input.mutations_applied.push(MutationStrategy::Dictionary {
            word: word.clone(),
            position,
        });
        new_input.parent_hash = Some(self.hash_input(input));
        
        debug!("Applied dictionary mutation with word {:?} at position {}", 
               String::from_utf8_lossy(word), position);
        Ok(new_input)
    }
    
    fn name(&self) -> &str {
        "dictionary"
    }
    
    fn weight(&self) -> f64 {
        1.2
    }
}

impl DictionaryMutation {
    fn hash_input(&self, input: &FuzzInput) -> [u8; 32] {
        let mut hasher = Hasher::new();
        hasher.update(&input.data);
        *hasher.finalize().as_bytes()
    }
}

// Block deletion mutation
pub struct BlockDeletionMutation;

impl MutationStrategyTrait for BlockDeletionMutation {
    fn mutate(&self, input: &FuzzInput, rng: &mut StdRng) -> Result<FuzzInput> {
        if input.data.len() < 2 {
            return Err(anyhow::anyhow!("Input too small for block deletion"));
        }
        
        let max_delete_size = (input.data.len() / 4).max(1);
        let delete_size = rng.gen_range(1..=max_delete_size);
        let start_pos = rng.gen_range(0..=input.data.len() - delete_size);
        
        let mut new_data = input.data.clone();
        new_data.drain(start_pos..start_pos + delete_size);
        
        let mut new_input = input.clone();
        new_input.data = new_data;
        new_input.generation += 1;
        new_input.mutations_applied.push(MutationStrategy::BlockDeletion {
            start: start_pos,
            length: delete_size,
        });
        new_input.parent_hash = Some(self.hash_input(input));
        
        debug!("Applied block deletion at position {} length {}", start_pos, delete_size);
        Ok(new_input)
    }
    
    fn name(&self) -> &str {
        "block_deletion"
    }
    
    fn weight(&self) -> f64 {
        0.6
    }
}

impl BlockDeletionMutation {
    fn hash_input(&self, input: &FuzzInput) -> [u8; 32] {
        let mut hasher = Hasher::new();
        hasher.update(&input.data);
        *hasher.finalize().as_bytes()
    }
}

impl MutationEngine {
    pub fn new() -> Self {
        use rand::SeedableRng;
        
        let strategies: Vec<Box<dyn MutationStrategyTrait + Send + Sync>> = vec![
            Box::new(BitFlipMutation),
            Box::new(ArithmeticMutation),
            Box::new(DictionaryMutation::new()),
            Box::new(BlockDeletionMutation),
        ];
        
        let interesting_values = vec![
            vec![0x00],
            vec![0xFF],
            vec![0x7F],
            vec![0x80],
            vec![0x00, 0x00],
            vec![0xFF, 0xFF],
            vec![0x00, 0x00, 0x00, 0x00],
            vec![0xFF, 0xFF, 0xFF, 0xFF],
        ];
        
        Self {
            strategies,
            interesting_values,
            dictionary: HashSet::new(),
            rng: Arc::new(Mutex::new(StdRng::from_entropy())),
        }
    }
    
    pub fn mutate(&self, input: &FuzzInput) -> Result<FuzzInput> {
        let mut rng = self.rng.lock()
            .map_err(|_| anyhow::anyhow!("RNG lock poisoned"))?;
        
        // Select mutation strategy based on weights
        let total_weight: f64 = self.strategies.iter().map(|s| s.weight()).sum();
        let selection = rng.gen::<f64>() * total_weight;
        
        let mut cumulative_weight = 0.0;
        for strategy in &self.strategies {
            cumulative_weight += strategy.weight();
            if cumulative_weight >= selection {
                return strategy.mutate(input, &mut rng);
            }
        }
        
        // Fallback to first strategy
        self.strategies[0].mutate(input, &mut rng)
    }
    
    pub fn add_dictionary_word(&mut self, word: Vec<u8>) {
        self.dictionary.insert(word);
        info!("Added word to mutation dictionary");
    }
    
    pub fn get_strategy_count(&self) -> usize {
        self.strategies.len()
    }
    
    pub fn get_dictionary_size(&self) -> usize {
        self.dictionary.len()
    }
    
    pub fn clear_dictionary(&mut self) {
        self.dictionary.clear();
        info!("Cleared mutation dictionary");
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::property_fuzzer::InputMetadata;
    
    #[test]
    fn test_bit_flip_mutation() -> Result<()> {
        let input = FuzzInput {
            data: vec![0x00, 0x01, 0x02, 0x03],
            metadata: InputMetadata {
                size: 4,
                entropy: 1.0,
                structure_hints: Vec::new(),
                energy: 1.0,
                execution_count: 0,
                last_execution: 0,
                coverage_contribution: 0.0,
            },
            mutations_applied: Vec::new(),
            generation: 0,
            parent_hash: None,
        };
        
        let mutation = BitFlipMutation;
        let mut rng = StdRng::from_entropy();
        let result = mutation.mutate(&input, &mut rng)?;
        
        assert_ne!(result.data, input.data);
        assert_eq!(result.generation, 1);
        assert_eq!(result.mutations_applied.len(), 1);
        
        Ok(())
    }
    
    #[test]
    fn test_mutation_engine() -> Result<()> {
        let engine = MutationEngine::new();
        
        let input = FuzzInput {
            data: vec![0x41, 0x42, 0x43, 0x44], // "ABCD"
            metadata: InputMetadata {
                size: 4,
                entropy: 1.0,
                structure_hints: Vec::new(),
                energy: 1.0,
                execution_count: 0,
                last_execution: 0,
                coverage_contribution: 0.0,
            },
            mutations_applied: Vec::new(),
            generation: 0,
            parent_hash: None,
        };
        
        let result = engine.mutate(&input)?;
        
        assert_eq!(result.generation, 1);
        assert!(result.mutations_applied.len() > 0);
        assert!(result.parent_hash.is_some());
        
        Ok(())
    }
}