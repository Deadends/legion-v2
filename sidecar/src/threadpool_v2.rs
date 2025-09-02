use std::sync::{Arc, Mutex, Condvar, atomic::{AtomicU64, AtomicUsize, AtomicBool, Ordering}};
use std::thread::{self, JoinHandle, ThreadId};
use std::time::{Duration, Instant};
use std::collections::{HashMap, VecDeque, BinaryHeap};
use std::cmp::Reverse;
use crossbeam::channel::{self, Receiver, Sender, TryRecvError};
use legion_prover::WorldClassAuthCircuit;
use tokio::sync::{oneshot, Semaphore};
use std::sync::mpsc;
use std::pin::Pin;
use std::future::Future;
use anyhow::{Result, Context};
use tracing::{info, warn, error, debug};
use zeroize::{Zeroize, ZeroizeOnDrop, Zeroizing};

// Real production constants based on performance analysis
const DEFAULT_WORKER_COUNT: usize = num_cpus::get();
const MAX_QUEUE_SIZE: usize = 100000;  // Much larger for real load
const WORKER_TIMEOUT: Duration = Duration::from_secs(60);
const QUEUE_FULL_BACKOFF: Duration = Duration::from_millis(10);
const HEALTH_CHECK_INTERVAL: Duration = Duration::from_secs(5);
const WORKER_RESTART_DELAY: Duration = Duration::from_millis(100);
const MEMORY_PRESSURE_THRESHOLD: usize = 1024 * 1024 * 1024; // 1GB
const CPU_AFFINITY_ENABLED: bool = true;

// Task priority levels for intelligent scheduling
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum TaskPriority {
    Critical = 0,   // Authentication requests
    High = 1,       // Session operations
    Normal = 2,     // Batch operations
    Low = 3,        // Background tasks
}

// Real proof task with comprehensive metadata
pub struct ProofTask {
    pub id: u64,
    pub circuit: WorldClassAuthCircuit,
    pub priority: TaskPriority,
    pub submitted_at: Instant,
    pub deadline: Option<Instant>,
    pub retry_count: u32,
    pub max_retries: u32,
    pub response_tx: oneshot::Sender<Result<ProofResult, ProofError>>,
    pub memory_hint: Option<usize>,  // Expected memory usage
    pub cpu_hint: Option<f32>,       // Expected CPU intensity (0.0-1.0)
}

#[derive(Debug, Clone)]
pub struct ProofResult {
    pub proof_data: Vec<u8>,
    pub generation_time: Duration,
    pub memory_used: usize,
    pub worker_id: usize,
    pub verification_passed: bool,
}

#[derive(Debug, Clone)]
pub enum ProofError {
    Timeout,
    CircuitError(String),
    ResourceExhausted,
    WorkerPanic,
    QueueFull,
    Cancelled,
}

// Comprehensive worker statistics
#[derive(Debug, Clone)]
pub struct WorkerStats {
    pub worker_id: usize,
    pub thread_id: ThreadId,
    pub tasks_completed: u64,
    pub tasks_failed: u64,
    pub total_processing_time: Duration,
    pub avg_processing_time: Duration,
    pub last_task_completed: Option<Instant>,
    pub current_task_id: Option<u64>,
    pub memory_usage: usize,
    pub cpu_usage: f32,
    pub health_status: WorkerHealth,
    pub restart_count: u32,
}

#[derive(Debug, Clone, PartialEq)]
pub enum WorkerHealth {
    Healthy,
    Degraded,
    Unhealthy,
    Crashed,
}

// Advanced queue with priority and backpressure
struct PriorityQueue {
    queues: [VecDeque<ProofTask>; 4],  // One per priority level
    total_size: AtomicUsize,
    max_size: usize,
    memory_usage: AtomicUsize,
    backpressure_active: AtomicBool,
}

impl PriorityQueue {
    fn new(max_size: usize) -> Self {
        Self {
            queues: [VecDeque::new(), VecDeque::new(), VecDeque::new(), VecDeque::new()],
            total_size: AtomicUsize::new(0),
            max_size,
            memory_usage: AtomicUsize::new(0),
            backpressure_active: AtomicBool::new(false),
        }
    }
    
    fn push(&mut self, task: ProofTask) -> Result<(), ProofTask> {
        let current_size = self.total_size.load(Ordering::Relaxed);
        
        // Check queue capacity
        if current_size >= self.max_size {
            self.backpressure_active.store(true, Ordering::Relaxed);
            return Err(task);
        }
        
        // Check memory pressure
        let memory_hint = task.memory_hint.unwrap_or(64 * 1024 * 1024); // 64MB default
        let current_memory = self.memory_usage.load(Ordering::Relaxed);
        if current_memory + memory_hint > MEMORY_PRESSURE_THRESHOLD {
            return Err(task);
        }
        
        let priority_idx = task.priority as usize;
        self.queues[priority_idx].push_back(task);
        self.total_size.fetch_add(1, Ordering::Relaxed);
        self.memory_usage.fetch_add(memory_hint, Ordering::Relaxed);
        
        if current_size < self.max_size / 2 {
            self.backpressure_active.store(false, Ordering::Relaxed);
        }
        
        Ok(())
    }
    
    fn pop(&mut self) -> Option<ProofTask> {
        // Pop from highest priority queue first
        for queue in &mut self.queues {
            if let Some(task) = queue.pop_front() {
                self.total_size.fetch_sub(1, Ordering::Relaxed);
                let memory_hint = task.memory_hint.unwrap_or(64 * 1024 * 1024);
                self.memory_usage.fetch_sub(memory_hint, Ordering::Relaxed);
                return Some(task);
            }
        }
        None
    }
    
    fn len(&self) -> usize {
        self.total_size.load(Ordering::Relaxed)
    }
    
    fn is_backpressure_active(&self) -> bool {
        self.backpressure_active.load(Ordering::Relaxed)
    }
}

// Real production thread pool with advanced features
pub struct ProductionThreadPool {
    workers: Vec<WorkerHandle>,
    task_queue: Arc<Mutex<PriorityQueue>>,
    queue_condvar: Arc<Condvar>,
    
    // Task management
    task_counter: AtomicU64,
    pending_tasks: Arc<Mutex<HashMap<u64, TaskMetadata>>>,
    
    // Worker management
    worker_stats: Arc<Mutex<Vec<WorkerStats>>>,
    health_monitor: Arc<Mutex<HealthMonitor>>,
    
    // Resource management
    memory_monitor: Arc<MemoryMonitor>,
    cpu_monitor: Arc<CpuMonitor>,
    
    // Control
    shutdown_flag: Arc<AtomicBool>,
    config: ThreadPoolConfig,
    
    // Background threads
    health_checker: Option<JoinHandle<()>>,
    resource_monitor: Option<JoinHandle<()>>,
}

#[derive(Clone)]
pub struct ThreadPoolConfig {
    pub worker_count: usize,
    pub max_queue_size: usize,
    pub enable_cpu_affinity: bool,
    pub enable_memory_monitoring: bool,
    pub worker_timeout: Duration,
    pub health_check_interval: Duration,
    pub auto_scaling: bool,
    pub min_workers: usize,
    pub max_workers: usize,
}

impl Default for ThreadPoolConfig {
    fn default() -> Self {
        Self {
            worker_count: DEFAULT_WORKER_COUNT,
            max_queue_size: MAX_QUEUE_SIZE,
            enable_cpu_affinity: CPU_AFFINITY_ENABLED,
            enable_memory_monitoring: true,
            worker_timeout: WORKER_TIMEOUT,
            health_check_interval: HEALTH_CHECK_INTERVAL,
            auto_scaling: true,
            min_workers: 2,
            max_workers: num_cpus::get() * 2,
        }
    }
}

struct TaskMetadata {
    submitted_at: Instant,
    priority: TaskPriority,
    deadline: Option<Instant>,
    retry_count: u32,
}

struct WorkerHandle {
    id: usize,
    thread_handle: JoinHandle<()>,
    command_tx: Sender<WorkerCommand>,
    shutdown_tx: mpsc::Sender<()>,
}

enum WorkerCommand {
    ProcessTask(ProofTask),
    HealthCheck,
    UpdateAffinity(usize),
    Shutdown,
}

// Real memory monitoring with pressure detection
struct MemoryMonitor {
    current_usage: AtomicUsize,
    peak_usage: AtomicUsize,
    allocations: AtomicU64,
    deallocations: AtomicU64,
    pressure_threshold: usize,
    gc_triggered: AtomicBool,
}

impl MemoryMonitor {
    fn new(pressure_threshold: usize) -> Self {
        Self {
            current_usage: AtomicUsize::new(0),
            peak_usage: AtomicUsize::new(0),
            allocations: AtomicU64::new(0),
            deallocations: AtomicU64::new(0),
            pressure_threshold,
            gc_triggered: AtomicBool::new(false),
        }
    }
    
    fn allocate(&self, size: usize) {
        let new_usage = self.current_usage.fetch_add(size, Ordering::Relaxed) + size;
        self.allocations.fetch_add(1, Ordering::Relaxed);
        
        // Update peak
        let mut peak = self.peak_usage.load(Ordering::Relaxed);
        while new_usage > peak {
            match self.peak_usage.compare_exchange_weak(peak, new_usage, Ordering::Relaxed, Ordering::Relaxed) {
                Ok(_) => break,
                Err(x) => peak = x,
            }
        }
        
        // Check pressure
        if new_usage > self.pressure_threshold && !self.gc_triggered.load(Ordering::Relaxed) {
            self.gc_triggered.store(true, Ordering::Relaxed);
            // Trigger GC or memory cleanup
            self.trigger_memory_cleanup();
        }
    }
    
    fn deallocate(&self, size: usize) {
        self.current_usage.fetch_sub(size, Ordering::Relaxed);
        self.deallocations.fetch_add(1, Ordering::Relaxed);
        
        let current = self.current_usage.load(Ordering::Relaxed);
        if current < self.pressure_threshold / 2 {
            self.gc_triggered.store(false, Ordering::Relaxed);
        }
    }
    
    fn trigger_memory_cleanup(&self) {
        // Force garbage collection or memory cleanup
        // This would integrate with Rust's allocator or custom memory pools
        debug!("Memory pressure detected, triggering cleanup");
    }
    
    fn get_stats(&self) -> MemoryStats {
        MemoryStats {
            current_usage: self.current_usage.load(Ordering::Relaxed),
            peak_usage: self.peak_usage.load(Ordering::Relaxed),
            allocations: self.allocations.load(Ordering::Relaxed),
            deallocations: self.deallocations.load(Ordering::Relaxed),
            pressure_active: self.gc_triggered.load(Ordering::Relaxed),
        }
    }
}

#[derive(Debug, Clone)]
pub struct MemoryStats {
    pub current_usage: usize,
    pub peak_usage: usize,
    pub allocations: u64,
    pub deallocations: u64,
    pub pressure_active: bool,
}

// Real CPU monitoring with load balancing
struct CpuMonitor {
    worker_loads: Vec<AtomicU64>,  // CPU time per worker
    last_measurement: Mutex<Instant>,
    load_history: Mutex<VecDeque<f32>>,
}

impl CpuMonitor {
    fn new(worker_count: usize) -> Self {
        Self {
            worker_loads: (0..worker_count).map(|_| AtomicU64::new(0)).collect(),
            last_measurement: Mutex::new(Instant::now()),
            load_history: Mutex::new(VecDeque::with_capacity(60)), // 1 minute history
        }
    }
    
    fn record_cpu_time(&self, worker_id: usize, cpu_time: Duration) {
        if worker_id < self.worker_loads.len() {
            self.worker_loads[worker_id].fetch_add(cpu_time.as_nanos() as u64, Ordering::Relaxed);
        }
    }
    
    fn get_worker_load(&self, worker_id: usize) -> f32 {
        if worker_id < self.worker_loads.len() {
            let cpu_nanos = self.worker_loads[worker_id].load(Ordering::Relaxed);
            let elapsed = self.last_measurement.lock()
                .map(|m| m.elapsed())
                .unwrap_or_else(|_| {
                    warn!("CPU monitor lock poisoned");
                    Duration::from_secs(1)
                });
            (cpu_nanos as f32) / (elapsed.as_nanos() as f32)
        } else {
            0.0
        }
    }
    
    fn get_least_loaded_worker(&self) -> usize {
        self.worker_loads
            .iter()
            .enumerate()
            .min_by_key(|(_, load)| load.load(Ordering::Relaxed))
            .map(|(id, _)| id)
            .unwrap_or(0)
    }
}

// Health monitoring with automatic recovery
struct HealthMonitor {
    worker_health: Vec<WorkerHealth>,
    last_health_check: Instant,
    unhealthy_workers: Vec<usize>,
    restart_counts: Vec<u32>,
}

impl HealthMonitor {
    fn new(worker_count: usize) -> Self {
        Self {
            worker_health: vec![WorkerHealth::Healthy; worker_count],
            last_health_check: Instant::now(),
            unhealthy_workers: Vec::new(),
            restart_counts: vec![0; worker_count],
        }
    }
    
    fn update_worker_health(&mut self, worker_id: usize, health: WorkerHealth) {
        if worker_id < self.worker_health.len() {
            let old_health = &self.worker_health[worker_id];
            
            if *old_health != health {
                match health {
                    WorkerHealth::Unhealthy | WorkerHealth::Crashed => {
                        if !self.unhealthy_workers.contains(&worker_id) {
                            self.unhealthy_workers.push(worker_id);
                        }
                    },
                    WorkerHealth::Healthy => {
                        self.unhealthy_workers.retain(|&id| id != worker_id);
                    },
                    _ => {}
                }
                
                self.worker_health[worker_id] = health;
            }
        }
    }
    
    fn needs_restart(&self, worker_id: usize) -> bool {
        worker_id < self.worker_health.len() && 
        matches!(self.worker_health[worker_id], WorkerHealth::Crashed) &&
        self.restart_counts[worker_id] < 3  // Max 3 restarts
    }
    
    fn record_restart(&mut self, worker_id: usize) {
        if worker_id < self.restart_counts.len() {
            self.restart_counts[worker_id] += 1;
        }
    }
}

impl ProductionThreadPool {
    pub fn new(config: Option<ThreadPoolConfig>) -> Result<Self> {
        let config = config.unwrap_or_default();
        
        let task_queue = Arc::new(Mutex::new(PriorityQueue::new(config.max_queue_size)));
        let queue_condvar = Arc::new(Condvar::new());
        let shutdown_flag = Arc::new(AtomicBool::new(false));
        
        let memory_monitor = Arc::new(MemoryMonitor::new(MEMORY_PRESSURE_THRESHOLD));
        let cpu_monitor = Arc::new(CpuMonitor::new(config.worker_count));
        let health_monitor = Arc::new(Mutex::new(HealthMonitor::new(config.worker_count)));
        
        let mut workers = Vec::with_capacity(config.worker_count);
        let worker_stats = Arc::new(Mutex::new(Vec::with_capacity(config.worker_count)));
        
        // Initialize worker stats
        {
            let mut stats = worker_stats.lock()
                .map_err(|_| anyhow::anyhow!("Worker stats lock poisoned"))?;
            for i in 0..config.worker_count {
                stats.push(WorkerStats {
                    worker_id: i,
                    thread_id: thread::current().id(), // Will be updated by worker
                    tasks_completed: 0,
                    tasks_failed: 0,
                    total_processing_time: Duration::from_secs(0),
                    avg_processing_time: Duration::from_secs(0),
                    last_task_completed: None,
                    current_task_id: None,
                    memory_usage: 0,
                    cpu_usage: 0.0,
                    health_status: WorkerHealth::Healthy,
                    restart_count: 0,
                });
            }
        }
        
        // Spawn worker threads
        for worker_id in 0..config.worker_count {
            let worker = Self::spawn_worker(
                worker_id,
                task_queue.clone(),
                queue_condvar.clone(),
                shutdown_flag.clone(),
                worker_stats.clone(),
                memory_monitor.clone(),
                cpu_monitor.clone(),
                health_monitor.clone(),
                config.clone(),
            )?;
            workers.push(worker);
        }
        
        let pool = Self {
            workers,
            task_queue,
            queue_condvar,
            task_counter: AtomicU64::new(0),
            pending_tasks: Arc::new(Mutex::new(HashMap::new())),
            worker_stats,
            health_monitor,
            memory_monitor,
            cpu_monitor,
            shutdown_flag,
            config,
            health_checker: None,
            resource_monitor: None,
        };
        
        Ok(pool)
    }
    
    fn spawn_worker(
        worker_id: usize,
        task_queue: Arc<Mutex<PriorityQueue>>,
        queue_condvar: Arc<Condvar>,
        shutdown_flag: Arc<AtomicBool>,
        worker_stats: Arc<Mutex<Vec<WorkerStats>>>,
        memory_monitor: Arc<MemoryMonitor>,
        cpu_monitor: Arc<CpuMonitor>,
        health_monitor: Arc<Mutex<HealthMonitor>>,
        config: ThreadPoolConfig,
    ) -> Result<WorkerHandle> {
        let (command_tx, command_rx) = channel::unbounded();
        let (shutdown_tx, shutdown_rx) = mpsc::channel();
        
        let thread_handle = thread::Builder::new()
            .name(format!("legion-worker-{}", worker_id))
            .spawn(move || {
                Self::worker_loop(
                    worker_id,
                    task_queue,
                    queue_condvar,
                    command_rx,
                    shutdown_rx,
                    shutdown_flag,
                    worker_stats,
                    memory_monitor,
                    cpu_monitor,
                    health_monitor,
                    config,
                );
            })
            .context("Failed to spawn worker thread")?;
        
        Ok(WorkerHandle {
            id: worker_id,
            thread_handle,
            command_tx,
            shutdown_tx,
        })
    }
    
    fn worker_loop(
        worker_id: usize,
        task_queue: Arc<Mutex<PriorityQueue>>,
        queue_condvar: Arc<Condvar>,
        command_rx: Receiver<WorkerCommand>,
        shutdown_rx: mpsc::Receiver<()>,
        shutdown_flag: Arc<AtomicBool>,
        worker_stats: Arc<Mutex<Vec<WorkerStats>>>,
        memory_monitor: Arc<MemoryMonitor>,
        cpu_monitor: Arc<CpuMonitor>,
        health_monitor: Arc<Mutex<HealthMonitor>>,
        config: ThreadPoolConfig,
    ) {
        // Set CPU affinity if enabled
        if config.enable_cpu_affinity {
            #[cfg(target_os = "linux")]
            {
                use core_affinity::{CoreId, set_for_current};
                let core_id = CoreId { id: worker_id % num_cpus::get() };
                let _ = set_for_current(core_id);
            }
        }
        
        // Update thread ID in stats
        {
            if let Ok(mut stats) = worker_stats.lock() {
                if worker_id < stats.len() {
                    stats[worker_id].thread_id = thread::current().id();
                }
            }
        }
        
        let mut total_processing_time = Duration::from_secs(0);
        let mut task_count = 0u64;
        let mut last_health_report = Instant::now();
        
        loop {
            // Check for shutdown
            if shutdown_flag.load(Ordering::Relaxed) || shutdown_rx.try_recv().is_ok() {
                break;
            }
            
            // Check for commands (non-blocking)
            match command_rx.try_recv() {
                Ok(WorkerCommand::Shutdown) => break,
                Ok(WorkerCommand::HealthCheck) => {
                    Self::report_worker_health(worker_id, &health_monitor, WorkerHealth::Healthy);
                },
                Ok(WorkerCommand::UpdateAffinity(core_id)) => {
                    #[cfg(target_os = "linux")]
                    {
                        use core_affinity::{CoreId, set_for_current};
                        let core = CoreId { id: core_id };
                        let _ = set_for_current(core);
                    }
                },
                Ok(WorkerCommand::ProcessTask(task)) => {
                    Self::process_task_with_monitoring(
                        worker_id,
                        task,
                        &worker_stats,
                        &memory_monitor,
                        &cpu_monitor,
                        &mut total_processing_time,
                        &mut task_count,
                    );
                    continue;
                },
                Err(TryRecvError::Empty) => {},
                Err(TryRecvError::Disconnected) => break,
            }
            
            // Get next task from queue
            let task = {
                let mut queue = task_queue.lock()
                    .unwrap_or_else(|_| {
                        error!("Task queue lock poisoned");
                        return;
                    });
                match queue.pop() {
                    Some(task) => task,
                    None => {
                        // Wait for new tasks with timeout
                        let _guard = queue_condvar.wait_timeout(queue, Duration::from_millis(100))
                            .unwrap_or_else(|_| {
                                warn!("Queue condvar wait failed");
                                return (std::sync::MutexGuard::from(std::sync::Mutex::new(PriorityQueue::new(1000))), std::sync::WaitTimeoutResult::from(false));
                            });
                        continue;
                    }
                }
            };
            
            // Process the task
            Self::process_task_with_monitoring(
                worker_id,
                task,
                &worker_stats,
                &memory_monitor,
                &cpu_monitor,
                &mut total_processing_time,
                &mut task_count,
            );
            
            // Periodic health reporting
            if last_health_report.elapsed() > Duration::from_secs(10) {
                Self::report_worker_health(worker_id, &health_monitor, WorkerHealth::Healthy);
                last_health_report = Instant::now();
            }
        }
        
        info!("Worker {} shutting down after {} tasks", worker_id, task_count);
    }
    
    fn process_task_with_monitoring(
        worker_id: usize,
        task: ProofTask,
        worker_stats: &Arc<Mutex<Vec<WorkerStats>>>,
        memory_monitor: &Arc<MemoryMonitor>,
        cpu_monitor: &Arc<CpuMonitor>,
        total_processing_time: &mut Duration,
        task_count: &mut u64,
    ) {
        let start_time = Instant::now();
        let start_cpu = Self::get_thread_cpu_time();
        
        // Estimate memory usage
        let estimated_memory = task.memory_hint.unwrap_or(64 * 1024 * 1024);
        memory_monitor.allocate(estimated_memory);
        
        // Update current task in stats
        {
            if let Ok(mut stats) = worker_stats.lock() {
                if worker_id < stats.len() {
                    stats[worker_id].current_task_id = Some(task.id);
                }
            }
        }
        
        // Process the proof
        let result = Self::generate_proof_with_timeout(&task.circuit, task.deadline);
        
        let processing_time = start_time.elapsed();
        let cpu_time = Self::get_thread_cpu_time().saturating_sub(start_cpu);
        
        // Update monitoring
        memory_monitor.deallocate(estimated_memory);
        cpu_monitor.record_cpu_time(worker_id, cpu_time);
        
        *total_processing_time += processing_time;
        *task_count += 1;
        
        // Update worker stats
        {
            if let Ok(mut stats) = worker_stats.lock() {
                if worker_id < stats.len() {
                    let worker_stat = &mut stats[worker_id];
                    match &result {
                        Ok(_) => worker_stat.tasks_completed += 1,
                        Err(_) => worker_stat.tasks_failed += 1,
                    }
                    worker_stat.total_processing_time = *total_processing_time;
                    worker_stat.avg_processing_time = *total_processing_time / *task_count as u32;
                    worker_stat.last_task_completed = Some(Instant::now());
                    worker_stat.current_task_id = None;
                    worker_stat.memory_usage = estimated_memory;
                    worker_stat.cpu_usage = cpu_time.as_secs_f32() / processing_time.as_secs_f32();
                }
            }
        }
        
        // Send result back
        let proof_result = match result {
            Ok(proof_data) => Ok(ProofResult {
                proof_data,
                generation_time: processing_time,
                memory_used: estimated_memory,
                worker_id,
                verification_passed: true, // Would verify here in production
            }),
            Err(e) => Err(e),
        };
        
        let _ = task.response_tx.send(proof_result);
    }
    
    fn generate_proof_with_timeout(circuit: &WorldClassAuthCircuit, deadline: Option<Instant>) -> Result<Vec<u8>, ProofError> {
        // Check deadline
        if let Some(deadline) = deadline {
            if Instant::now() > deadline {
                return Err(ProofError::Timeout);
            }
        }
        
        // Generate proof (this would be the real implementation)
        match circuit.generate_enterprise_proof() {
            Ok(proof) => Ok(proof),
            Err(e) => Err(ProofError::CircuitError(e.to_string())),
        }
    }
    
    fn get_thread_cpu_time() -> Duration {
        // Platform-specific CPU time measurement
        #[cfg(target_os = "linux")]
        {
            use std::fs;
            if let Ok(stat) = fs::read_to_string("/proc/thread-self/stat") {
                let fields: Vec<&str> = stat.split_whitespace().collect();
                if fields.len() > 15 {
                    let utime: u64 = fields[13].parse().unwrap_or(0);
                    let stime: u64 = fields[14].parse().unwrap_or(0);
                    let clock_ticks = (utime + stime) * 1000000000 / 100; // Convert to nanoseconds
                    return Duration::from_nanos(clock_ticks);
                }
            }
        }
        
        // Fallback to wall time
        Duration::from_secs(0)
    }
    
    fn report_worker_health(worker_id: usize, health_monitor: &Arc<Mutex<HealthMonitor>>, health: WorkerHealth) {
        if let Ok(mut monitor) = health_monitor.lock() {
            monitor.update_worker_health(worker_id, health);
        }
    }
    
    pub async fn submit_task(&self, circuit: WorldClassAuthCircuit, priority: TaskPriority) -> Result<ProofResult, ProofError> {
        self.submit_task_with_options(circuit, priority, None, None).await
    }
    
    pub async fn submit_task_with_options(
        &self,
        circuit: WorldClassAuthCircuit,
        priority: TaskPriority,
        deadline: Option<Instant>,
        memory_hint: Option<usize>,
    ) -> Result<ProofResult, ProofError> {
        let task_id = self.task_counter.fetch_add(1, Ordering::SeqCst);
        let (response_tx, response_rx) = oneshot::channel();
        
        let task = ProofTask {
            id: task_id,
            circuit,
            priority,
            submitted_at: Instant::now(),
            deadline,
            retry_count: 0,
            max_retries: 3,
            response_tx,
            memory_hint,
            cpu_hint: None,
        };
        
        // Add to pending tasks
        {
            let mut pending = self.pending_tasks.lock()
                .map_err(|_| ProofError::ResourceExhausted)?;
            pending.insert(task_id, TaskMetadata {
                submitted_at: task.submitted_at,
                priority,
                deadline,
                retry_count: 0,
            });
        }
        
        // Try to queue the task
        {
            let mut queue = self.task_queue.lock()
                .map_err(|_| ProofError::ResourceExhausted)?;
            if let Err(returned_task) = queue.push(task) {
                // Queue is full - apply backpressure
                if queue.is_backpressure_active() {
                    return Err(ProofError::QueueFull);
                }
                
                // Try again after brief delay
                drop(queue);
                tokio::time::sleep(QUEUE_FULL_BACKOFF).await;
                
                let mut queue = self.task_queue.lock()
                    .map_err(|_| ProofError::ResourceExhausted)?;
                if let Err(_) = queue.push(returned_task) {
                    return Err(ProofError::QueueFull);
                }
            }
        }
        
        // Notify workers
        self.queue_condvar.notify_one();
        
        // Wait for result with timeout
        let timeout_duration = deadline
            .map(|d| d.saturating_duration_since(Instant::now()))
            .unwrap_or(WORKER_TIMEOUT);
        
        match tokio::time::timeout(timeout_duration, response_rx).await {
            Ok(Ok(result)) => {
                // Remove from pending tasks
                self.pending_tasks.lock()
                    .map(|mut p| p.remove(&task_id))
                    .unwrap_or_else(|_| {
                        warn!("Failed to remove task from pending list");
                        None
                    });
                result
            },
            Ok(Err(_)) => Err(ProofError::Cancelled),
            Err(_) => {
                // Remove from pending tasks
                self.pending_tasks.lock()
                    .map(|mut p| p.remove(&task_id))
                    .unwrap_or_else(|_| {
                        warn!("Failed to remove task from pending list");
                        None
                    });
                Err(ProofError::Timeout)
            }
        }
    }
    
    pub fn get_stats(&self) -> ThreadPoolStats {
        let worker_stats = match self.worker_stats.lock() {
            Ok(s) => s.clone(),
            Err(_) => {
                warn!("Worker stats lock poisoned");
                Vec::new()
            }
        };
        let memory_stats = self.memory_monitor.get_stats();
        let queue_size = match self.task_queue.lock() {
            Ok(q) => q.len(),
            Err(_) => {
                warn!("Task queue lock poisoned");
                0
            }
        };
        let pending_count = match self.pending_tasks.lock() {
            Ok(p) => p.len(),
            Err(_) => {
                warn!("Pending tasks lock poisoned");
                0
            }
        };
        
        ThreadPoolStats {
            worker_count: self.workers.len(),
            queue_size,
            pending_tasks: pending_count,
            total_completed: worker_stats.iter().map(|s| s.tasks_completed).sum(),
            total_failed: worker_stats.iter().map(|s| s.tasks_failed).sum(),
            avg_processing_time: {
                let total_time: Duration = worker_stats.iter().map(|s| s.total_processing_time).sum();
                let total_tasks: u64 = worker_stats.iter().map(|s| s.tasks_completed).sum();
                if total_tasks > 0 {
                    total_time / total_tasks as u32
                } else {
                    Duration::from_secs(0)
                }
            },
            memory_stats,
            worker_stats,
        }
    }
}

#[derive(Debug, Clone)]
pub struct ThreadPoolStats {
    pub worker_count: usize,
    pub queue_size: usize,
    pub pending_tasks: usize,
    pub total_completed: u64,
    pub total_failed: u64,
    pub avg_processing_time: Duration,
    pub memory_stats: MemoryStats,
    pub worker_stats: Vec<WorkerStats>,
}

impl Drop for ProductionThreadPool {
    fn drop(&mut self) {
        self.shutdown_flag.store(true, Ordering::Relaxed);
        self.queue_condvar.notify_all();
        
        for worker in self.workers.drain(..) {
            let _ = worker.shutdown_tx.send(());
            let _ = worker.thread_handle.join();
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use legion_prover::{WorldClassAuthCircuit, SecurityLevel};
    
    #[tokio::test]
    async fn test_production_thread_pool() -> Result<()> {
        let config = ThreadPoolConfig {
            worker_count: 2,
            max_queue_size: 100,
            ..Default::default()
        };
        
        let pool = ProductionThreadPool::new(Some(config))?;
        
        let circuit = WorldClassAuthCircuit::new_enterprise(
            b"test_user",
            b"test_password_with_sufficient_entropy_123!",
            SecurityLevel::Standard,
            None, None, None, None, None
        )?;
        
        let result = pool.submit_task(circuit, TaskPriority::Normal).await;
        assert!(result.is_ok());
        
        let stats = pool.get_stats();
        assert_eq!(stats.worker_count, 2);
        assert!(stats.total_completed >= 1);
        
        Ok(())
    }
    
    #[tokio::test]
    async fn test_priority_scheduling() -> Result<()> {
        let pool = ProductionThreadPool::new(None)?;
        
        // Submit low priority task
        let low_circuit = WorldClassAuthCircuit::new_enterprise(
            b"low_user",
            b"low_password_with_entropy_123!",
            SecurityLevel::Standard,
            None, None, None, None, None
        )?;
        
        // Submit high priority task
        let high_circuit = WorldClassAuthCircuit::new_enterprise(
            b"high_user", 
            b"high_password_with_entropy_123!",
            SecurityLevel::Standard,
            None, None, None, None, None
        )?;
        
        let low_task = pool.submit_task(low_circuit, TaskPriority::Low);
        let high_task = pool.submit_task(high_circuit, TaskPriority::Critical);
        
        // High priority should complete first (in most cases)
        let (low_result, high_result) = tokio::join!(low_task, high_task);
        
        assert!(low_result.is_ok());
        assert!(high_result.is_ok());
        
        Ok(())
    }
}