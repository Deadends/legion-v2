use rocksdb::{DB, Options, WriteBatch, IteratorMode, ColumnFamily, ColumnFamilyDescriptor, SliceTransform};
use serde::{Serialize, Deserialize};
use std::sync::{Arc, RwLock, Mutex, atomic::{AtomicU64, AtomicBool, Ordering}};
use std::time::{SystemTime, Duration, Instant};
use lru::LruCache;
use std::num::NonZeroUsize;
use std::collections::{HashMap, VecDeque};
use std::thread::{self, JoinHandle};
use crossbeam::channel::{self, Receiver, Sender};
use zeroize::Zeroize;
use blake3::Hasher;
use anyhow::{Result, Context};
use tracing::{info, warn, error, debug};

use crate::auth::{SessionId, SessionData};

const CACHE_SIZE: usize = 50000;
const BATCH_SIZE: usize = 5000;
const WAL_SYNC_INTERVAL_MS: u64 = 100;
const COMPACTION_TRIGGER_SIZE: usize = 100000;
const MAX_CONCURRENT_OPERATIONS: usize = 1000;
const RECOVERY_CHECKPOINT_INTERVAL: Duration = Duration::from_secs(30);
const CACHE_EVICTION_BATCH: usize = 1000;
const SESSION_LOCK_TIMEOUT: Duration = Duration::from_millis(100);

#[derive(Serialize, Deserialize, Clone)]
struct StoredSession {
    version: u32,
    data: SessionData,
    expires_at: u64,
    created_at: u64,
    last_accessed: u64,
    access_count: u64,
    checksum: [u8; 32],
    migration_state: MigrationState,
}

#[derive(Serialize, Deserialize, Clone, Debug)]
enum MigrationState {
    Stable,
    Migrating { target_epoch: u32, progress: f32 },
    PendingCleanup,
}

#[derive(Serialize, Deserialize, Clone)]
struct WalEntry {
    sequence: u64,
    timestamp: u64,
    operation: WalOperation,
    session_id: SessionId,
    checksum: [u8; 32],
}

#[derive(Serialize, Deserialize, Clone)]
enum WalOperation {
    Create { data: SessionData, ttl: u64 },
    Update { data: SessionData },
    Delete,
    Migrate { old_epoch: u32, new_epoch: u32 },
}

#[derive(Clone)]
struct CacheEntry {
    data: SessionData,
    last_accessed: Instant,
    access_count: u64,
    dirty: bool,
    lock_count: u32,
}

#[derive(Default)]
struct SessionStoreMetrics {
    cache_hits: AtomicU64,
    cache_misses: AtomicU64,
    disk_reads: AtomicU64,
    disk_writes: AtomicU64,
    concurrent_operations: AtomicU64,
    recovery_operations: AtomicU64,
    corruption_detected: AtomicU64,
    last_compaction: Mutex<Option<Instant>>,
}

enum BackgroundCommand {
    Compact,
    Checkpoint,
    EvictCache,
    SyncWal,
    Shutdown,
}

pub struct ProductionSessionStore {
    db: Arc<DB>,
    wal_db: Arc<DB>,
    
    l1_cache: Arc<RwLock<LruCache<SessionId, CacheEntry>>>,
    l2_cache: Arc<RwLock<HashMap<SessionId, CacheEntry>>>,
    
    session_locks: Arc<RwLock<HashMap<SessionId, Arc<RwLock<()>>>>>,
    operation_semaphore: Arc<tokio::sync::Semaphore>,
    
    wal_sequence: AtomicU64,
    wal_buffer: Arc<Mutex<VecDeque<WalEntry>>>,
    
    background_tx: Sender<BackgroundCommand>,
    background_handle: Option<JoinHandle<()>>,
    shutdown_flag: Arc<AtomicBool>,
    
    metrics: Arc<SessionStoreMetrics>,
    
    config: SessionStoreConfig,
}

#[derive(Clone)]
pub struct SessionStoreConfig {
    pub cache_size: usize,
    pub wal_sync_interval: Duration,
    pub compaction_threshold: usize,
    pub checkpoint_interval: Duration,
    pub enable_compression: bool,
    pub enable_encryption: bool,
    pub max_concurrent_ops: usize,
}

impl Default for SessionStoreConfig {
    fn default() -> Self {
        Self {
            cache_size: CACHE_SIZE,
            wal_sync_interval: Duration::from_millis(WAL_SYNC_INTERVAL_MS),
            compaction_threshold: COMPACTION_TRIGGER_SIZE,
            checkpoint_interval: RECOVERY_CHECKPOINT_INTERVAL,
            enable_compression: true,
            enable_encryption: false,
            max_concurrent_ops: MAX_CONCURRENT_OPERATIONS,
        }
    }
}

impl ProductionSessionStore {
    pub fn new(path: &str, config: Option<SessionStoreConfig>) -> Result<Self> {
        let config = config.unwrap_or_default();
        
        let mut db_opts = Options::default();
        db_opts.create_if_missing(true);
        db_opts.create_missing_column_families(true);
        
        db_opts.set_max_write_buffer_number(6);
        db_opts.set_write_buffer_size(128 * 1024 * 1024);
        db_opts.set_target_file_size_base(256 * 1024 * 1024);
        db_opts.set_level_zero_file_num_compaction_trigger(4);
        db_opts.set_level_zero_slowdown_writes_trigger(20);
        db_opts.set_level_zero_stop_writes_trigger(36);
        db_opts.set_max_background_jobs(8);
        
        if config.enable_compression {
            db_opts.set_compression_type(rocksdb::DBCompressionType::Lz4);
        }
        
        let session_cf = ColumnFamilyDescriptor::new("sessions", Options::default());
        let metadata_cf = ColumnFamilyDescriptor::new("metadata", Options::default());
        let index_cf = ColumnFamilyDescriptor::new("index", Options::default());
        
        let db = DB::open_cf_descriptors(&db_opts, path, vec![session_cf, metadata_cf, index_cf])
            .context("Failed to open main DB")?;
        
        let wal_path = format!("{}_wal", path);
        let wal_db = DB::open(&db_opts, wal_path)
            .context("Failed to open WAL DB")?;
        
        let cache_size = NonZeroUsize::new(config.cache_size)
            .context("Invalid cache size")?;
        let l1_cache = Arc::new(RwLock::new(LruCache::new(cache_size)));
        let l2_cache = Arc::new(RwLock::new(HashMap::with_capacity(config.cache_size * 2)));
        
        let (background_tx, background_rx) = channel::unbounded();
        let shutdown_flag = Arc::new(AtomicBool::new(false));
        
        let store = Self {
            db: Arc::new(db),
            wal_db: Arc::new(wal_db),
            l1_cache,
            l2_cache,
            session_locks: Arc::new(RwLock::new(HashMap::new())),
            operation_semaphore: Arc::new(tokio::sync::Semaphore::new(config.max_concurrent_ops)),
            wal_sequence: AtomicU64::new(0),
            wal_buffer: Arc::new(Mutex::new(VecDeque::new())),
            background_tx,
            background_handle: None,
            shutdown_flag: shutdown_flag.clone(),
            metrics: Arc::new(SessionStoreMetrics::default()),
            config,
        };
        
        let background_handle = store.start_background_processor(background_rx, shutdown_flag);
        
        Ok(Self {
            background_handle: Some(background_handle),
            ..store
        })
    }
    
    pub async fn store_session(&self, id: &SessionId, data: &SessionData, ttl_seconds: u64) -> Result<()> {
        let _permit = self.operation_semaphore.acquire().await
            .context("Operation semaphore closed")?;
        
        let session_lock = self.get_session_lock(id).await;
        let _lock = session_lock.write()
            .map_err(|_| anyhow::anyhow!("Session lock poisoned"))?;
        
        let now = SystemTime::now().duration_since(std::time::UNIX_EPOCH)
            .context("System time error")?.as_secs();
        let expires_at = now + ttl_seconds;
        
        let stored = StoredSession {
            version: 1,
            data: data.clone(),
            expires_at,
            created_at: now,
            last_accessed: now,
            access_count: 1,
            checksum: self.compute_checksum(data),
            migration_state: MigrationState::Stable,
        };
        
        let wal_entry = WalEntry {
            sequence: self.wal_sequence.fetch_add(1, Ordering::SeqCst),
            timestamp: now,
            operation: WalOperation::Create { data: data.clone(), ttl: ttl_seconds },
            session_id: id.clone(),
            checksum: self.compute_wal_checksum(&stored),
        };
        
        self.write_wal_entry(&wal_entry)?;
        
        let key = self.session_key(id);
        let value = bincode::serialize(&stored)
            .context("Serialization failed")?;
        
        let session_cf = self.db.cf_handle("sessions")
            .context("Sessions column family not found")?;
        
        let mut batch = WriteBatch::default();
        batch.put_cf(session_cf, &key, &value);
        
        let index_cf = self.db.cf_handle("index")
            .context("Index column family not found")?;
        let index_key = format!("expires:{}", expires_at);
        batch.put_cf(index_cf, index_key.as_bytes(), id.as_bytes());
        
        self.db.write(batch)
            .context("Atomic write failed")?;
        
        self.update_cache(id, data.clone(), false).await;
        
        self.metrics.disk_writes.fetch_add(1, Ordering::Relaxed);
        
        Ok(())
    }
    
    pub async fn get_session(&self, id: &SessionId) -> Result<Option<SessionData>> {
        let _permit = self.operation_semaphore.acquire().await
            .context("Operation semaphore closed")?;
        
        if let Ok(mut l1_cache) = self.l1_cache.write() {
            if let Some(entry) = l1_cache.get_mut(id) {
                entry.last_accessed = Instant::now();
                entry.access_count += 1;
                self.metrics.cache_hits.fetch_add(1, Ordering::Relaxed);
                return Ok(Some(entry.data.clone()));
            }
        }
        
        if let Ok(mut l2_cache) = self.l2_cache.write() {
            if let Some(entry) = l2_cache.get_mut(id) {
                entry.last_accessed = Instant::now();
                entry.access_count += 1;
                
                if let Ok(mut l1_cache) = self.l1_cache.write() {
                    l1_cache.put(id.clone(), entry.clone());
                }
                
                self.metrics.cache_hits.fetch_add(1, Ordering::Relaxed);
                return Ok(Some(entry.data.clone()));
            }
        }
        
        self.metrics.cache_misses.fetch_add(1, Ordering::Relaxed);
        self.metrics.disk_reads.fetch_add(1, Ordering::Relaxed);
        
        let session_lock = self.get_session_lock(id).await;
        let _lock = session_lock.read()
            .map_err(|_| anyhow::anyhow!("Session lock poisoned"))?;
        
        let key = self.session_key(id);
        let session_cf = self.db.cf_handle("sessions")
            .context("Sessions column family not found")?;
        
        let value = match self.db.get_cf(session_cf, &key) {
            Ok(Some(v)) => v,
            Ok(None) => return Ok(None),
            Err(e) => return Err(anyhow::anyhow!("DB read failed: {}", e)),
        };
        
        let mut stored: StoredSession = bincode::deserialize(&value)
            .context("Deserialization failed")?;
        
        let expected_checksum = self.compute_checksum(&stored.data);
        if stored.checksum != expected_checksum {
            self.metrics.corruption_detected.fetch_add(1, Ordering::Relaxed);
            return Err(anyhow::anyhow!("Session data corruption detected"));
        }
        
        let now = SystemTime::now().duration_since(std::time::UNIX_EPOCH)
            .context("System time error")?.as_secs();
        if now > stored.expires_at {
            self.delete_session(id).await?;
            return Ok(None);
        }
        
        stored.last_accessed = now;
        stored.access_count += 1;
        
        let updated_value = bincode::serialize(&stored)
            .context("Serialization failed")?;
        self.db.put_cf(session_cf, &key, &updated_value)
            .context("Metadata update failed")?;
        
        self.update_cache(id, stored.data.clone(), false).await;
        
        Ok(Some(stored.data))
    }
    
    pub async fn delete_session(&self, id: &SessionId) -> Result<()> {
        let _permit = self.operation_semaphore.acquire().await
            .context("Operation semaphore closed")?;
        
        let session_lock = self.get_session_lock(id).await;
        let _lock = session_lock.write()
            .map_err(|_| anyhow::anyhow!("Session lock poisoned"))?;
        
        let wal_entry = WalEntry {
            sequence: self.wal_sequence.fetch_add(1, Ordering::SeqCst),
            timestamp: SystemTime::now().duration_since(std::time::UNIX_EPOCH)
                .context("System time error")?.as_secs(),
            operation: WalOperation::Delete,
            session_id: id.clone(),
            checksum: [0u8; 32],
        };
        
        self.write_wal_entry(&wal_entry)?;
        
        let key = self.session_key(id);
        let session_cf = self.db.cf_handle("sessions")
            .context("Sessions column family not found")?;
        
        self.db.delete_cf(session_cf, &key)
            .context("DB delete failed")?;
        
        if let Ok(mut l1_cache) = self.l1_cache.write() {
            l1_cache.pop(id);
        }
        if let Ok(mut l2_cache) = self.l2_cache.write() {
            l2_cache.remove(id);
        }
        
        if let Ok(mut locks) = self.session_locks.write() {
            locks.remove(id);
        }
        
        Ok(())
    }
    
    pub async fn recover_from_crash(&self) -> Result<usize> {
        let mut recovered_count = 0;
        let wal_iter = self.wal_db.iterator(IteratorMode::Start);
        
        for item in wal_iter {
            let (key, value) = item
                .context("WAL iterator error")?;
            
            let wal_entry: WalEntry = bincode::deserialize(&value)
                .context("WAL deserialization failed")?;
            
            if !self.verify_wal_entry(&wal_entry) {
                continue;
            }
            
            match wal_entry.operation {
                WalOperation::Create { data, ttl } => {
                    let current_time = SystemTime::now().duration_since(std::time::UNIX_EPOCH)
                        .context("System time error")?.as_secs();
                    let remaining_ttl = ttl.saturating_sub(current_time - wal_entry.timestamp);
                    if remaining_ttl > 0 {
                        self.store_session(&wal_entry.session_id, &data, remaining_ttl).await?;
                        recovered_count += 1;
                    }
                },
                WalOperation::Update { data } => {
                    if self.get_session(&wal_entry.session_id).await?.is_some() {
                        recovered_count += 1;
                    }
                },
                WalOperation::Delete => {
                    self.delete_session(&wal_entry.session_id).await?;
                    recovered_count += 1;
                },
                WalOperation::Migrate { .. } => {
                    recovered_count += 1;
                },
            }
            
            self.wal_db.delete(&key)
                .context("WAL cleanup failed")?;
        }
        
        self.metrics.recovery_operations.fetch_add(recovered_count as u64, Ordering::Relaxed);
        Ok(recovered_count)
    }
    
    async fn get_session_lock(&self, id: &SessionId) -> Arc<RwLock<()>> {
        if let Ok(locks) = self.session_locks.read() {
            if let Some(lock) = locks.get(id) {
                return lock.clone();
            }
        }
        
        if let Ok(mut locks) = self.session_locks.write() {
            locks.entry(id.clone()).or_insert_with(|| Arc::new(RwLock::new(()))).clone()
        } else {
            Arc::new(RwLock::new(()))
        }
    }
    
    async fn update_cache(&self, id: &SessionId, data: SessionData, dirty: bool) {
        let entry = CacheEntry {
            data,
            last_accessed: Instant::now(),
            access_count: 1,
            dirty,
            lock_count: 0,
        };
        
        if let Ok(mut l1_cache) = self.l1_cache.write() {
            l1_cache.put(id.clone(), entry);
        }
    }
    
    fn compute_checksum(&self, data: &SessionData) -> [u8; 32] {
        let mut hasher = Hasher::new();
        hasher.update(b"LEGION_SESSION_V1");
        hasher.update(&data.keys.client_to_server);
        hasher.update(&data.keys.server_to_client);
        hasher.update(&data.transcript_hash);
        *hasher.finalize().as_bytes()
    }
    
    fn compute_wal_checksum(&self, stored: &StoredSession) -> [u8; 32] {
        let mut hasher = Hasher::new();
        hasher.update(b"LEGION_WAL_V1");
        hasher.update(&stored.checksum);
        hasher.update(&stored.expires_at.to_le_bytes());
        *hasher.finalize().as_bytes()
    }
    
    fn write_wal_entry(&self, entry: &WalEntry) -> Result<()> {
        let key = format!("wal:{:016x}", entry.sequence);
        let value = bincode::serialize(entry)
            .context("WAL serialization failed")?;
        
        self.wal_db.put(key.as_bytes(), &value)
            .context("WAL write failed")?;
        
        if let Ok(mut buffer) = self.wal_buffer.lock() {
            buffer.push_back(entry.clone());
        }
        
        Ok(())
    }
    
    fn verify_wal_entry(&self, entry: &WalEntry) -> bool {
        entry.sequence > 0 && entry.timestamp > 0
    }
    
    fn session_key(&self, id: &SessionId) -> Vec<u8> {
        let mut key = Vec::with_capacity(40);
        key.extend_from_slice(b"session:");
        key.extend_from_slice(id.as_bytes());
        key
    }
    
    fn start_background_processor(&self, rx: Receiver<BackgroundCommand>, shutdown: Arc<AtomicBool>) -> JoinHandle<()> {
        let db = self.db.clone();
        let wal_db = self.wal_db.clone();
        let metrics = self.metrics.clone();
        let config = self.config.clone();
        
        thread::spawn(move || {
            let mut last_checkpoint = Instant::now();
            let mut last_compaction = Instant::now();
            
            while !shutdown.load(Ordering::Relaxed) {
                match rx.recv_timeout(Duration::from_millis(100)) {
                    Ok(BackgroundCommand::Compact) => {
                        if let Err(e) = db.compact_range::<&[u8], &[u8]>(None, None) {
                            error!("Compaction failed: {}", e);
                        }
                        last_compaction = Instant::now();
                    },
                    Ok(BackgroundCommand::Checkpoint) => {
                        last_checkpoint = Instant::now();
                    },
                    Ok(BackgroundCommand::SyncWal) => {
                        if let Err(e) = wal_db.flush() {
                            error!("WAL sync failed: {}", e);
                        }
                    },
                    Ok(BackgroundCommand::Shutdown) => break,
                    _ => {
                        let now = Instant::now();
                        
                        if now.duration_since(last_checkpoint) > config.checkpoint_interval {
                            last_checkpoint = now;
                        }
                        
                        if now.duration_since(last_compaction) > Duration::from_secs(3600) {
                            if let Err(e) = db.compact_range::<&[u8], &[u8]>(None, None) {
                                error!("Auto-compaction failed: {}", e);
                            }
                            last_compaction = now;
                        }
                    }
                }
            }
        })
    }
    
    pub fn get_metrics(&self) -> SessionStoreStats {
        SessionStoreStats {
            cache_hits: self.metrics.cache_hits.load(Ordering::Relaxed),
            cache_misses: self.metrics.cache_misses.load(Ordering::Relaxed),
            disk_reads: self.metrics.disk_reads.load(Ordering::Relaxed),
            disk_writes: self.metrics.disk_writes.load(Ordering::Relaxed),
            concurrent_operations: self.metrics.concurrent_operations.load(Ordering::Relaxed),
            recovery_operations: self.metrics.recovery_operations.load(Ordering::Relaxed),
            corruption_detected: self.metrics.corruption_detected.load(Ordering::Relaxed),
        }
    }
}

#[derive(Debug)]
pub struct SessionStoreStats {
    pub cache_hits: u64,
    pub cache_misses: u64,
    pub disk_reads: u64,
    pub disk_writes: u64,
    pub concurrent_operations: u64,
    pub recovery_operations: u64,
    pub corruption_detected: u64,
}

impl Drop for ProductionSessionStore {
    fn drop(&mut self) {
        self.shutdown_flag.store(true, Ordering::Relaxed);
        let _ = self.background_tx.send(BackgroundCommand::Shutdown);
        
        if let Some(handle) = self.background_handle.take() {
            let _ = handle.join();
        }
    }
}

impl SessionId {
    pub fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::TempDir;
    use tokio;
    
    #[tokio::test]
    async fn test_production_session_store() -> Result<()> {
        let temp_dir = TempDir::new()
            .context("Failed to create temp directory")?;
        let store = ProductionSessionStore::new(
            temp_dir.path().to_str()
                .context("Invalid temp path")?, 
            None
        ).context("Failed to create session store")?;
        
        let session_id = SessionId([0x42u8; 32]);
        let session_data = create_test_session_data();
        
        store.store_session(&session_id, &session_data, 3600).await
            .context("Failed to store session")?;
        let retrieved = store.get_session(&session_id).await
            .context("Failed to get session")?
            .context("Session not found")?;
        
        assert_eq!(session_data.verified, retrieved.verified);
        
        let retrieved2 = store.get_session(&session_id).await
            .context("Failed to get session again")?
            .context("Session not found on second retrieval")?;
        assert_eq!(session_data.verified, retrieved2.verified);
        
        let stats = store.get_metrics();
        assert!(stats.cache_hits > 0);
        assert!(stats.disk_reads > 0);
        Ok(())
    }
    
    #[tokio::test]
    async fn test_crash_recovery() -> Result<()> {
        let temp_dir = TempDir::new()
            .context("Failed to create temp directory")?;
        let path = temp_dir.path().to_str()
            .context("Invalid temp path")?;
        
        {
            let store = ProductionSessionStore::new(path, None)
                .context("Failed to create initial store")?;
            let session_id = SessionId([0x42u8; 32]);
            let session_data = create_test_session_data();
            store.store_session(&session_id, &session_data, 3600).await
                .context("Failed to store session for recovery test")?;
        }
        
        let store = ProductionSessionStore::new(path, None)
            .context("Failed to create recovery store")?;
        let recovered = store.recover_from_crash().await
            .context("Failed to recover from crash")?;
        
        let session_id = SessionId([0x42u8; 32]);
        let retrieved = store.get_session(&session_id).await
            .context("Failed to get recovered session")?;
        assert!(retrieved.is_some());
        Ok(())
    }
    
    fn create_test_session_data() -> SessionData {
        use crate::auth::SessionKeys;
        use crate::nonce::{NonceGenerator, Direction};
        use std::time::SystemTime;
        
        SessionData {
            keys: SessionKeys {
                client_to_server: [0x01u8; 32],
                server_to_client: [0x02u8; 32],
                epoch: 0,
            },
            transcript_hash: [0x03u8; 32],
            c2s_nonce_gen: NonceGenerator::new(0, Direction::ClientToServer),
            s2c_nonce_gen: NonceGenerator::new(0, Direction::ServerToClient),
            created_at: SystemTime::now(),
            last_used: SystemTime::now(),
            verified: true,
        }
    }
}