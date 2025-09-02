use std::collections::{HashMap, HashSet};
use std::sync::{Arc, Mutex};
use rand::rngs::StdRng;
use blake3::Hasher;
use crate::property_fuzzer::{FuzzInput, CoverageTracker, InputMetadata, StructureHint};
use anyhow::{Result, Context};
use tracing::{info, warn, error, debug};

// Advanced corpus management with energy-based scheduling
pub struct FuzzCorpus {
    inputs: Arc<Mutex<HashMap<[u8; 32], FuzzInput>>>,
    energy_queue: Arc<Mutex<Vec<([u8; 32], f64)>>>,
    max_size: usize,
    total_energy: Arc<Mutex<f64>>,
    selection_stats: Arc<Mutex<HashMap<[u8; 32], u64>>>,
}

impl FuzzCorpus {
    pub fn new(max_size: usize) -> Self {
        Self {
            inputs: Arc::new(Mutex::new(HashMap::new())),
            energy_queue: Arc::new(Mutex::new(Vec::new())),
            max_size,
            total_energy: Arc::new(Mutex::new(0.0)),
            selection_stats: Arc::new(Mutex::new(HashMap::new())),
        }
    }
    
    pub fn add_input(&self, mut input: FuzzInput, coverage_tracker: &CoverageTracker) -> Result<bool> {
        let input_hash = self.hash_input(&input);
        
        // Calculate energy based on coverage contribution
        let coverage_score = coverage_tracker.get_coverage_score(&input);
        input.metadata.energy = self.calculate_energy(&input, coverage_score);
        
        let mut inputs = self.inputs.lock()
            .map_err(|_| anyhow::anyhow!("Inputs lock poisoned"))?;
        
        // Check if we already have this input
        if inputs.contains_key(&input_hash) {
            return Ok(false);
        }
        
        // Enforce corpus size limit
        if inputs.len() >= self.max_size {
            self.evict_low_energy_input(&mut inputs)?;
        }
        
        // Add to corpus
        inputs.insert(input_hash, input.clone());
        
        // Update energy queue
        {
            let mut energy_queue = self.energy_queue.lock()
                .map_err(|_| anyhow::anyhow!("Energy queue lock poisoned"))?;
            energy_queue.push((input_hash, input.metadata.energy));
            
            // Sort by energy (highest first)
            energy_queue.sort_by(|a, b| b.1.partial_cmp(&a.1).unwrap_or(std::cmp::Ordering::Equal));
        }
        
        // Update total energy
        {
            let mut total_energy = self.total_energy.lock()
                .map_err(|_| anyhow::anyhow!("Total energy lock poisoned"))?;
            *total_energy += input.metadata.energy;
        }
        
        debug!("Added input {} with energy {:.2}", hex::encode(&input_hash[..8]), input.metadata.energy);
        Ok(true)
    }
    
    pub fn select_input(&self, rng: &mut StdRng) -> Result<Option<FuzzInput>> {
        use rand::Rng;
        
        let energy_queue = self.energy_queue.lock()
            .map_err(|_| anyhow::anyhow!("Energy queue lock poisoned"))?;
        
        if energy_queue.is_empty() {
            return Ok(None);
        }
        
        // Energy-based selection with some randomness
        let total_energy = self.total_energy.lock()
            .map_err(|_| anyhow::anyhow!("Total energy lock poisoned"))?;
        let selection_threshold = rng.gen::<f64>() * *total_energy;
        
        let mut cumulative_energy = 0.0;
        for &(input_hash, energy) in energy_queue.iter() {
            cumulative_energy += energy;
            if cumulative_energy >= selection_threshold {
                // Update selection statistics
                {
                    let mut stats = self.selection_stats.lock()
                        .map_err(|_| anyhow::anyhow!("Selection stats lock poisoned"))?;
                    *stats.entry(input_hash).or_insert(0) += 1;
                }
                
                // Return the selected input
                let inputs = self.inputs.lock()
                    .map_err(|_| anyhow::anyhow!("Inputs lock poisoned"))?;
                return Ok(inputs.get(&input_hash).cloned());
            }
        }
        
        // Fallback: return first input
        let first_hash = energy_queue[0].0;
        let inputs = self.inputs.lock()
            .map_err(|_| anyhow::anyhow!("Inputs lock poisoned"))?;
        Ok(inputs.get(&first_hash).cloned())
    }
    
    fn calculate_energy(&self, input: &FuzzInput, coverage_score: f64) -> f64 {
        let base_energy = 1.0;
        let coverage_bonus = coverage_score * 10.0;
        let size_penalty = (input.data.len() as f64).log2() * 0.1;
        let entropy_bonus = input.metadata.entropy * 2.0;
        
        (base_energy + coverage_bonus + entropy_bonus - size_penalty).max(0.1)
    }
    
    fn evict_low_energy_input(&self, inputs: &mut HashMap<[u8; 32], FuzzInput>) -> Result<()> {
        let energy_queue = self.energy_queue.lock()
            .map_err(|_| anyhow::anyhow!("Energy queue lock poisoned"))?;
        
        if let Some(&(lowest_hash, _)) = energy_queue.last() {
            inputs.remove(&lowest_hash);
            debug!("Evicted low-energy input {}", hex::encode(&lowest_hash[..8]));
        }
        
        Ok(())
    }
    
    fn hash_input(&self, input: &FuzzInput) -> [u8; 32] {
        let mut hasher = Hasher::new();
        hasher.update(&input.data);
        hasher.update(&input.generation.to_le_bytes());
        *hasher.finalize().as_bytes()
    }
    
    pub fn size(&self) -> usize {
        match self.inputs.lock() {
            Ok(inputs) => inputs.len(),
            Err(_) => {
                warn!("Inputs lock poisoned when getting size");
                0
            }
        }
    }
    
    pub fn get_stats(&self) -> Result<CorpusStats> {
        let inputs = self.inputs.lock()
            .map_err(|_| anyhow::anyhow!("Inputs lock poisoned"))?;
        let total_energy = *self.total_energy.lock()
            .map_err(|_| anyhow::anyhow!("Total energy lock poisoned"))?;
        let selection_stats = self.selection_stats.lock()
            .map_err(|_| anyhow::anyhow!("Selection stats lock poisoned"))?;
        
        let avg_energy = if inputs.is_empty() { 0.0 } else { total_energy / inputs.len() as f64 };
        let most_selected = selection_stats.iter()
            .max_by_key(|(_, &count)| count)
            .map(|(_, &count)| count)
            .unwrap_or(0);
        
        Ok(CorpusStats {
            total_inputs: inputs.len(),
            total_energy,
            avg_energy,
            most_selected_count: most_selected,
        })
    }
    
    pub fn clear(&self) -> Result<()> {
        let mut inputs = self.inputs.lock()
            .map_err(|_| anyhow::anyhow!("Inputs lock poisoned"))?;
        let mut energy_queue = self.energy_queue.lock()
            .map_err(|_| anyhow::anyhow!("Energy queue lock poisoned"))?;
        let mut total_energy = self.total_energy.lock()
            .map_err(|_| anyhow::anyhow!("Total energy lock poisoned"))?;
        let mut selection_stats = self.selection_stats.lock()
            .map_err(|_| anyhow::anyhow!("Selection stats lock poisoned"))?;
        
        inputs.clear();
        energy_queue.clear();
        *total_energy = 0.0;
        selection_stats.clear();
        
        info!("Corpus cleared");
        Ok(())
    }
    
    pub fn get_input_by_hash(&self, hash: &[u8; 32]) -> Result<Option<FuzzInput>> {
        let inputs = self.inputs.lock()
            .map_err(|_| anyhow::anyhow!("Inputs lock poisoned"))?;
        Ok(inputs.get(hash).cloned())
    }
    
    pub fn remove_input(&self, hash: &[u8; 32]) -> Result<bool> {
        let mut inputs = self.inputs.lock()
            .map_err(|_| anyhow::anyhow!("Inputs lock poisoned"))?;
        
        if let Some(input) = inputs.remove(hash) {
            // Update energy queue
            {
                let mut energy_queue = self.energy_queue.lock()
                    .map_err(|_| anyhow::anyhow!("Energy queue lock poisoned"))?;
                energy_queue.retain(|(h, _)| h != hash);
            }
            
            // Update total energy
            {
                let mut total_energy = self.total_energy.lock()
                    .map_err(|_| anyhow::anyhow!("Total energy lock poisoned"))?;
                *total_energy -= input.metadata.energy;
            }
            
            // Update selection stats
            {
                let mut selection_stats = self.selection_stats.lock()
                    .map_err(|_| anyhow::anyhow!("Selection stats lock poisoned"))?;
                selection_stats.remove(hash);
            }
            
            debug!("Removed input {}", hex::encode(&hash[..8]));
            Ok(true)
        } else {
            Ok(false)
        }
    }
}

#[derive(Debug, Clone)]
pub struct CorpusStats {
    pub total_inputs: usize,
    pub total_energy: f64,
    pub avg_energy: f64,
    pub most_selected_count: u64,
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::property_fuzzer::{FuzzInput, InputMetadata};
    
    #[test]
    fn test_corpus_basic_operations() -> Result<()> {
        let corpus = FuzzCorpus::new(100);
        let coverage_tracker = CoverageTracker::new();
        
        let input = FuzzInput {
            data: vec![1, 2, 3, 4],
            generation: 0,
            metadata: InputMetadata {
                energy: 0.0,
                entropy: 1.0,
                structure_hints: Vec::new(),
                parent_hash: None,
            },
        };
        
        // Add input
        assert!(corpus.add_input(input.clone(), &coverage_tracker)?);
        assert_eq!(corpus.size(), 1);
        
        // Try to add same input again
        assert!(!corpus.add_input(input, &coverage_tracker)?);
        assert_eq!(corpus.size(), 1);
        
        Ok(())
    }
    
    #[test]
    fn test_corpus_stats() -> Result<()> {
        let corpus = FuzzCorpus::new(100);
        let coverage_tracker = CoverageTracker::new();
        
        let input = FuzzInput {
            data: vec![1, 2, 3, 4],
            generation: 0,
            metadata: InputMetadata {
                energy: 0.0,
                entropy: 2.0,
                structure_hints: Vec::new(),
                parent_hash: None,
            },
        };
        
        corpus.add_input(input, &coverage_tracker)?;
        
        let stats = corpus.get_stats()?;
        assert_eq!(stats.total_inputs, 1);
        assert!(stats.total_energy > 0.0);
        assert!(stats.avg_energy > 0.0);
        
        Ok(())
    }
}