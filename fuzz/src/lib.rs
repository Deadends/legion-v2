pub mod property_fuzzer;
pub mod corpus_manager;
pub mod mutation_engine;

pub use property_fuzzer::*;
pub use corpus_manager::*;
pub use mutation_engine::*;

use std::collections::HashSet;
use std::sync::{Arc, Mutex, atomic::{AtomicU64, AtomicBool, Ordering}};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};
use std::thread::{self, JoinHandle};
use rand::{SeedableRng, rngs::StdRng};
use anyhow::{Result, Context};
use tracing::{info, warn, error, debug};

// Real property-based fuzzer with invariant checking
pub struct PropertyBasedFuzzer {
    corpus: Arc<FuzzCorpus>,
    coverage_tracker: Arc<CoverageTracker>,
    mutation_engine: Arc<MutationEngine>,
    
    // Execution tracking
    total_executions: AtomicU64,
    crashes_found: AtomicU64,
    hangs_found: AtomicU64,
    unique_crashes: Arc<Mutex<HashSet<[u8; 32]>>>,
    
    // Configuration
    config: FuzzerConfig,
    
    // Worker threads
    workers: Vec<JoinHandle<()>>,
    shutdown_flag: Arc<AtomicBool>,
    
    // Results
    crash_inputs: Arc<Mutex<Vec<FuzzInput>>>,
    hang_inputs: Arc<Mutex<Vec<FuzzInput>>>,
}

#[derive(Clone)]
pub struct FuzzerConfig {
    pub max_iterations: u64,
    pub worker_count: usize,
    pub timeout: Duration,
    pub corpus_size: usize,
    pub enable_coverage_tracking: bool,
    pub enable_crash_deduplication: bool,
    pub mutation_rate: f64,
}

impl Default for FuzzerConfig {
    fn default() -> Self {
        Self {
            max_iterations: 1000000,
            worker_count: num_cpus::get(),
            timeout: Duration::from_secs(5),
            corpus_size: 100000,
            enable_coverage_tracking: true,
            enable_crash_deduplication: true,
            mutation_rate: 0.1,
        }
    }
}

impl PropertyBasedFuzzer {
    pub fn new(config: Option<FuzzerConfig>) -> Self {
        let config = config.unwrap_or_default();
        
        Self {
            corpus: Arc::new(FuzzCorpus::new(config.corpus_size)),
            coverage_tracker: Arc::new(CoverageTracker::new()),
            mutation_engine: Arc::new(MutationEngine::new()),
            total_executions: AtomicU64::new(0),
            crashes_found: AtomicU64::new(0),
            hangs_found: AtomicU64::new(0),
            unique_crashes: Arc::new(Mutex::new(HashSet::new())),
            config,
            workers: Vec::new(),
            shutdown_flag: Arc::new(AtomicBool::new(false)),
            crash_inputs: Arc::new(Mutex::new(Vec::new())),
            hang_inputs: Arc::new(Mutex::new(Vec::new())),
        }
    }
    
    pub fn add_seed_input(&self, data: Vec<u8>) -> Result<()> {
        let input = FuzzInput {
            data: data.clone(),
            metadata: InputMetadata {
                size: data.len(),
                entropy: self.calculate_entropy(&data),
                structure_hints: self.analyze_structure(&data),
                energy: 1.0,
                execution_count: 0,
                last_execution: SystemTime::now().duration_since(UNIX_EPOCH)
                    .context("System time error")?
                    .as_secs(),
                coverage_contribution: 0.0,
            },
            mutations_applied: Vec::new(),
            generation: 0,
            parent_hash: None,
        };
        
        self.corpus.add_input(input, &self.coverage_tracker)?;
        Ok(())
    }
    
    pub fn run_fuzzing<F>(&mut self, target_function: F) -> Result<FuzzingResults>
    where
        F: Fn(&[u8]) -> FuzzResult + Send + Sync + Clone + 'static,
    {
        let start_time = Instant::now();
        
        // Spawn worker threads
        for worker_id in 0..self.config.worker_count {
            let worker_handle = self.spawn_worker(worker_id, target_function.clone())?;
            self.workers.push(worker_handle);
        }
        
        // Monitor progress
        let mut last_stats_print = Instant::now();
        while !self.should_stop() {
            if last_stats_print.elapsed() > Duration::from_secs(10) {
                self.print_stats()?;
                last_stats_print = Instant::now();
            }
            
            thread::sleep(Duration::from_millis(100));
        }
        
        // Shutdown workers
        self.shutdown_flag.store(true, Ordering::Relaxed);
        for worker in self.workers.drain(..) {
            let _ = worker.join();
        }
        
        let total_time = start_time.elapsed();
        
        Ok(FuzzingResults {
            total_executions: self.total_executions.load(Ordering::Relaxed),
            crashes_found: self.crashes_found.load(Ordering::Relaxed),
            hangs_found: self.hangs_found.load(Ordering::Relaxed),
            unique_crashes: self.unique_crashes.lock()
                .map_err(|_| anyhow::anyhow!("Unique crashes lock poisoned"))?
                .len(),
            coverage_stats: self.coverage_tracker.get_stats(),
            corpus_stats: self.corpus.get_stats()?,
            total_time,
            executions_per_second: {
                let execs = self.total_executions.load(Ordering::Relaxed) as f64;
                let secs = total_time.as_secs_f64();
                if secs > 0.0 { execs / secs } else { 0.0 }
            },
        })
    }
    
    fn spawn_worker<F>(&self, worker_id: usize, target_function: F) -> Result<JoinHandle<()>>
    where
        F: Fn(&[u8]) -> FuzzResult + Send + 'static,
    {
        let corpus = self.corpus.clone();
        let coverage_tracker = self.coverage_tracker.clone();
        let mutation_engine = self.mutation_engine.clone();
        let shutdown_flag = self.shutdown_flag.clone();
        let total_executions = self.total_executions.clone();
        let crashes_found = self.crashes_found.clone();
        let hangs_found = self.hangs_found.clone();
        let unique_crashes = self.unique_crashes.clone();
        let crash_inputs = self.crash_inputs.clone();
        let hang_inputs = self.hang_inputs.clone();
        let config = self.config.clone();
        
        let handle = thread::Builder::new()
            .name(format!("fuzzer-worker-{}", worker_id))
            .spawn(move || {
                let mut rng = StdRng::from_entropy();
                let mut local_executions = 0u64;
                
                while !shutdown_flag.load(Ordering::Relaxed) && 
                      local_executions < config.max_iterations / config.worker_count as u64 {
                    
                    // Select input from corpus
                    let input = match corpus.select_input(&mut rng) {
                        Ok(Some(input)) => input,
                        Ok(None) => {
                            thread::sleep(Duration::from_millis(10));
                            continue;
                        }
                        Err(e) => {
                            error!("Failed to select input from corpus: {}", e);
                            continue;
                        }
                    };
                    
                    // Mutate the input
                    let mutated_input = match mutation_engine.mutate(&input) {
                        Ok(input) => input,
                        Err(e) => {
                            debug!("Mutation failed: {}", e);
                            continue;
                        }
                    };
                    
                    // Execute target function
                    let _execution_start = Instant::now();
                    let result = target_function(&mutated_input.data);
                    
                    // Process result
                    match result {
                        FuzzResult::Success => {
                            // Add to corpus if it increases coverage
                            if coverage_tracker.reset_new_coverage_flag() {
                                if let Err(e) = corpus.add_input(mutated_input, &coverage_tracker) {
                                    debug!("Failed to add input to corpus: {}", e);
                                }
                            }
                        },
                        FuzzResult::Crash(crash_info) => {
                            crashes_found.fetch_add(1, Ordering::Relaxed);
                            
                            if config.enable_crash_deduplication {
                                let crash_hash = Self::hash_crash(&crash_info);
                                if let Ok(mut unique_crashes_guard) = unique_crashes.lock() {
                                    if unique_crashes_guard.insert(crash_hash) {
                                        // New unique crash
                                        if let Ok(mut crash_inputs_guard) = crash_inputs.lock() {
                                            crash_inputs_guard.push(mutated_input);
                                        }
                                    }
                                }
                            } else {
                                if let Ok(mut crash_inputs_guard) = crash_inputs.lock() {
                                    crash_inputs_guard.push(mutated_input);
                                }
                            }
                        },
                        FuzzResult::Hang => {
                            hangs_found.fetch_add(1, Ordering::Relaxed);
                            if let Ok(mut hang_inputs_guard) = hang_inputs.lock() {
                                hang_inputs_guard.push(mutated_input);
                            }
                        },
                        FuzzResult::Error(e) => {
                            debug!("Target function error: {}", e);
                            // Continue fuzzing on errors
                        },
                    }
                    
                    local_executions += 1;
                    total_executions.fetch_add(1, Ordering::Relaxed);
                }
                
                info!("Fuzzer worker {} completed {} executions", worker_id, local_executions);
            })
            .context("Failed to spawn fuzzer worker thread")?;
        
        Ok(handle)
    }
    
    fn should_stop(&self) -> bool {
        let executions = self.total_executions.load(Ordering::Relaxed);
        executions >= self.config.max_iterations
    }
    
    fn print_stats(&self) -> Result<()> {
        let executions = self.total_executions.load(Ordering::Relaxed);
        let crashes = self.crashes_found.load(Ordering::Relaxed);
        let hangs = self.hangs_found.load(Ordering::Relaxed);
        let coverage_stats = self.coverage_tracker.get_stats();
        let corpus_stats = self.corpus.get_stats()?;
        
        info!("Fuzzing Stats:");
        info!("  Executions: {}", executions);
        info!("  Crashes: {}", crashes);
        info!("  Hangs: {}", hangs);
        info!("  Coverage: {:.2}% ({} unique edges)", 
                 coverage_stats.coverage_percentage, coverage_stats.unique_edges);
        info!("  Corpus: {} inputs, avg energy: {:.2}", 
                 corpus_stats.total_inputs, corpus_stats.avg_energy);
        
        Ok(())
    }
    
    fn calculate_entropy(&self, data: &[u8]) -> f64 {
        if data.is_empty() {
            return 0.0;
        }
        
        let mut counts = [0u32; 256];
        for &byte in data {
            counts[byte as usize] += 1;
        }
        
        let len = data.len() as f64;
        let mut entropy = 0.0;
        
        for &count in &counts {
            if count > 0 {
                let p = count as f64 / len;
                entropy -= p * p.log2();
            }
        }
        
        entropy
    }
    
    fn analyze_structure(&self, data: &[u8]) -> Vec<StructureHint> {
        let mut hints = Vec::new();
        
        // Check for magic bytes
        if data.starts_with(b"LEGION") {
            hints.push(StructureHint::HasMagicBytes(b"LEGION".to_vec()));
        }
        
        // Check for length fields
        if data.len() >= 4 {
            let length = u32::from_le_bytes([data[0], data[1], data[2], data[3]]);
            if length as usize == data.len() - 4 {
                hints.push(StructureHint::HasLength(length as usize));
            }
        }
        
        // Check for timestamps
        if data.len() >= 8 {
            let timestamp = u64::from_le_bytes([
                data[0], data[1], data[2], data[3],
                data[4], data[5], data[6], data[7]
            ]);
            
            // Check if it's a reasonable timestamp (between 2020 and 2030)
            if timestamp > 1577836800 && timestamp < 1893456000 {
                hints.push(StructureHint::HasTimestamp(timestamp));
            }
        }
        
        hints
    }
    
    fn hash_crash(crash_info: &str) -> [u8; 32] {
        use blake3::Hasher;
        let mut hasher = Hasher::new();
        hasher.update(crash_info.as_bytes());
        *hasher.finalize().as_bytes()
    }
    
    pub fn get_crash_inputs(&self) -> Result<Vec<FuzzInput>> {
        Ok(self.crash_inputs.lock()
            .map_err(|_| anyhow::anyhow!("Crash inputs lock poisoned"))?
            .clone())
    }
    
    pub fn get_hang_inputs(&self) -> Result<Vec<FuzzInput>> {
        Ok(self.hang_inputs.lock()
            .map_err(|_| anyhow::anyhow!("Hang inputs lock poisoned"))?
            .clone())
    }
}

#[derive(Debug, Clone)]
pub enum FuzzResult {
    Success,
    Crash(String),
    Hang,
    Error(String),
}

#[derive(Debug, Clone)]
pub struct FuzzingResults {
    pub total_executions: u64,
    pub crashes_found: u64,
    pub hangs_found: u64,
    pub unique_crashes: usize,
    pub coverage_stats: CoverageStats,
    pub corpus_stats: CorpusStats,
    pub total_time: Duration,
    pub executions_per_second: f64,
}

#[cfg(test)]
mod tests {
    use super::*;
    
    #[test]
    fn test_fuzzer_creation() {
        let fuzzer = PropertyBasedFuzzer::new(None);
        assert_eq!(fuzzer.total_executions.load(Ordering::Relaxed), 0);
        assert_eq!(fuzzer.crashes_found.load(Ordering::Relaxed), 0);
    }
    
    #[test]
    fn test_seed_input() -> Result<()> {
        let fuzzer = PropertyBasedFuzzer::new(None);
        fuzzer.add_seed_input(vec![1, 2, 3, 4])?;
        assert_eq!(fuzzer.corpus.size(), 1);
        Ok(())
    }
}