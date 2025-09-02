use std::collections::{HashMap, BTreeMap, VecDeque};
use std::time::{SystemTime, Duration, Instant};
use serde::{Serialize, Deserialize};
use std::sync::{Arc, RwLock, Mutex};
use std::sync::atomic::{AtomicU64, AtomicUsize, AtomicBool, Ordering};
use dashmap::DashMap;
use std::net::SocketAddr;
use std::hash::{Hash, Hasher as StdHasher};
use std::collections::hash_map::DefaultHasher;
use anyhow::{Result, Context};
use tracing::{info, warn, error, debug};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ClusterConfig {
    pub node_capacity: usize,
    pub replication_factor: usize,
    pub consistency_level: ConsistencyLevel,
    pub load_balance_strategy: LoadBalanceStrategy,
    pub heartbeat_interval: Duration,
    pub session_timeout: Duration,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum ConsistencyLevel {
    One,
    Quorum,
    All,
    LocalQuorum,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum LoadBalanceStrategy {
    RoundRobin,
    LeastConnections,
    ConsistentHashing,
    WeightedRoundRobin,
    ResourceBased,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum MigrationType {
    Planned,
    Emergency,
    LoadBalancing,
    Maintenance,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum NodeStatus {
    Healthy,
    Degraded,
    Unhealthy,
    Offline,
    Maintenance,
}

#[derive(Debug, Clone)]
pub struct ClientContext {
    pub geo_location: Option<String>,
    pub device_fingerprint: [u8; 32],
    pub is_new_device: bool,
    pub connection_type: String,
    pub data_classification: String,
    pub requires_sticky_routing: bool,
    pub requires_audit_trail: bool,
    pub pci_dss_required: bool,
}

#[derive(Debug)]
pub struct ConsistentHashRing {
    nodes: BTreeMap<u64, u64>,
    virtual_nodes: usize,
    total_capacity: usize,
}

impl ConsistentHashRing {
    pub fn new(virtual_nodes: usize) -> Self {
        Self {
            nodes: BTreeMap::new(),
            virtual_nodes,
            total_capacity: 0,
        }
    }
    
    pub fn add_node(&mut self, node_id: u64, capacity: usize) -> Result<()> {
        for i in 0..self.virtual_nodes {
            let mut hasher = DefaultHasher::new();
            node_id.hash(&mut hasher);
            i.hash(&mut hasher);
            let hash = hasher.finish();
            self.nodes.insert(hash, node_id);
        }
        self.total_capacity += capacity;
        
        info!("Added node {} with capacity {} to consistent hash ring", node_id, capacity);
        Ok(())
    }
    
    pub fn remove_node(&mut self, node_id: u64) -> Result<()> {
        let mut to_remove = Vec::new();
        for (hash, id) in &self.nodes {
            if *id == node_id {
                to_remove.push(*hash);
            }
        }
        for hash in to_remove {
            self.nodes.remove(&hash);
        }
        
        info!("Removed node {} from consistent hash ring", node_id);
        Ok(())
    }
    
    pub fn get_node(&self, key: u64) -> Option<u64> {
        if self.nodes.is_empty() {
            return None;
        }
        
        // Find the first node with hash >= key
        for (_, node_id) in self.nodes.range(key..) {
            return Some(*node_id);
        }
        
        // Wrap around to the first node
        self.nodes.values().next().copied()
    }
    
    pub fn get_nodes_for_replication(&self, key: u64, count: usize) -> Vec<u64> {
        if self.nodes.is_empty() {
            return Vec::new();
        }
        
        let mut result = Vec::new();
        let mut seen_nodes = std::collections::HashSet::new();
        
        // Start from the primary node
        let mut current_key = key;
        
        while result.len() < count && seen_nodes.len() < self.nodes.len() {
            if let Some(node_id) = self.get_node(current_key) {
                if seen_nodes.insert(node_id) {
                    result.push(node_id);
                }
                // Move to next position in ring
                current_key = current_key.wrapping_add(1);
            } else {
                break;
            }
        }
        
        result
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SessionAffinityRule {
    pub user_pattern: String,
    pub preferred_nodes: Vec<u64>,
    pub sticky_duration: Duration,
    pub priority: u8,
}

#[derive(Debug, Clone)]
pub struct LoadBalancingDecision {
    pub selected_node: u64,
    pub decision_time: Instant,
    pub load_factors: HashMap<u64, f32>,
    pub strategy_used: LoadBalanceStrategy,
    pub fallback_used: bool,
}

#[derive(Debug, Clone)]
pub struct SessionMigrationPlan {
    pub session_id: [u8; 32],
    pub from_node: u64,
    pub to_node: u64,
    pub migration_type: MigrationType,
    pub estimated_duration: Duration,
    pub data_size_bytes: u64,
    pub priority: u8,
}

#[derive(Debug)]
pub struct ClusterHealthMonitor {
    pub node_health: HashMap<u64, NodeHealth>,
    pub cluster_metrics: ClusterMetrics,
    pub alert_thresholds: AlertThresholds,
    pub last_health_check: SystemTime,
}

#[derive(Debug, Clone)]
pub struct NodeHealth {
    pub cpu_usage: f32,
    pub memory_usage: f32,
    pub disk_usage: f32,
    pub network_latency_ms: u32,
    pub session_count: u64,
    pub error_rate: f32,
    pub last_heartbeat: SystemTime,
    pub status: NodeStatus,
}

#[derive(Debug, Clone)]
pub struct ClusterMetrics {
    pub total_nodes: usize,
    pub active_nodes: usize,
    pub total_sessions: u64,
    pub avg_load_per_node: f32,
    pub cluster_throughput: f64,
    pub replication_lag_ms: u32,
}

#[derive(Debug, Clone)]
pub struct AlertThresholds {
    pub max_cpu_usage: f32,
    pub max_memory_usage: f32,
    pub max_error_rate: f32,
    pub max_response_time_ms: u32,
    pub min_available_nodes: usize,
}

pub struct SessionClusterManager {
    config: ClusterConfig,
    hash_ring: Arc<RwLock<ConsistentHashRing>>,
    health_monitor: Arc<Mutex<ClusterHealthMonitor>>,
    affinity_rules: Arc<RwLock<Vec<SessionAffinityRule>>>,
    migration_queue: Arc<Mutex<VecDeque<SessionMigrationPlan>>>,
    load_balancer: Arc<Mutex<LoadBalancer>>,
}

struct LoadBalancer {
    strategy: LoadBalanceStrategy,
    node_weights: HashMap<u64, f32>,
    round_robin_counter: AtomicUsize,
    connection_counts: HashMap<u64, AtomicU64>,
}

impl SessionClusterManager {
    pub fn new(config: ClusterConfig) -> Result<Self> {
        let hash_ring = Arc::new(RwLock::new(ConsistentHashRing::new(150))); // 150 virtual nodes
        
        let health_monitor = Arc::new(Mutex::new(ClusterHealthMonitor {
            node_health: HashMap::new(),
            cluster_metrics: ClusterMetrics {
                total_nodes: 0,
                active_nodes: 0,
                total_sessions: 0,
                avg_load_per_node: 0.0,
                cluster_throughput: 0.0,
                replication_lag_ms: 0,
            },
            alert_thresholds: AlertThresholds {
                max_cpu_usage: 80.0,
                max_memory_usage: 85.0,
                max_error_rate: 5.0,
                max_response_time_ms: 1000,
                min_available_nodes: 2,
            },
            last_health_check: SystemTime::now(),
        }));
        
        let load_balancer = Arc::new(Mutex::new(LoadBalancer {
            strategy: config.load_balance_strategy.clone(),
            node_weights: HashMap::new(),
            round_robin_counter: AtomicUsize::new(0),
            connection_counts: HashMap::new(),
        }));
        
        Ok(Self {
            config,
            hash_ring,
            health_monitor,
            affinity_rules: Arc::new(RwLock::new(Vec::new())),
            migration_queue: Arc::new(Mutex::new(VecDeque::new())),
            load_balancer,
        })
    }
    
    pub fn add_node(&self, node_id: u64, capacity: usize) -> Result<()> {
        {
            let mut ring = self.hash_ring.write()
                .map_err(|_| anyhow::anyhow!("Hash ring lock poisoned"))?;
            ring.add_node(node_id, capacity)?;
        }
        
        {
            let mut health_monitor = self.health_monitor.lock()
                .map_err(|_| anyhow::anyhow!("Health monitor lock poisoned"))?;
            health_monitor.node_health.insert(node_id, NodeHealth {
                cpu_usage: 0.0,
                memory_usage: 0.0,
                disk_usage: 0.0,
                network_latency_ms: 0,
                session_count: 0,
                error_rate: 0.0,
                last_heartbeat: SystemTime::now(),
                status: NodeStatus::Healthy,
            });
            health_monitor.cluster_metrics.total_nodes += 1;
            health_monitor.cluster_metrics.active_nodes += 1;
        }
        
        {
            let mut load_balancer = self.load_balancer.lock()
                .map_err(|_| anyhow::anyhow!("Load balancer lock poisoned"))?;
            load_balancer.node_weights.insert(node_id, 1.0);
            load_balancer.connection_counts.insert(node_id, AtomicU64::new(0));
        }
        
        info!("Added node {} to cluster with capacity {}", node_id, capacity);
        Ok(())
    }
    
    pub fn remove_node(&self, node_id: u64) -> Result<()> {
        {
            let mut ring = self.hash_ring.write()
                .map_err(|_| anyhow::anyhow!("Hash ring lock poisoned"))?;
            ring.remove_node(node_id)?;
        }
        
        {
            let mut health_monitor = self.health_monitor.lock()
                .map_err(|_| anyhow::anyhow!("Health monitor lock poisoned"))?;
            health_monitor.node_health.remove(&node_id);
            health_monitor.cluster_metrics.total_nodes = health_monitor.cluster_metrics.total_nodes.saturating_sub(1);
            health_monitor.cluster_metrics.active_nodes = health_monitor.cluster_metrics.active_nodes.saturating_sub(1);
        }
        
        {
            let mut load_balancer = self.load_balancer.lock()
                .map_err(|_| anyhow::anyhow!("Load balancer lock poisoned"))?;
            load_balancer.node_weights.remove(&node_id);
            load_balancer.connection_counts.remove(&node_id);
        }
        
        info!("Removed node {} from cluster", node_id);
        Ok(())
    }
    
    pub fn select_node_for_session(&self, session_id: &[u8; 32], client_context: &ClientContext) -> Result<u64> {
        let load_balancer = self.load_balancer.lock()
            .map_err(|_| anyhow::anyhow!("Load balancer lock poisoned"))?;
        
        match load_balancer.strategy {
            LoadBalanceStrategy::ConsistentHashing => {
                let ring = self.hash_ring.read()
                    .map_err(|_| anyhow::anyhow!("Hash ring lock poisoned"))?;
                
                let mut hasher = DefaultHasher::new();
                session_id.hash(&mut hasher);
                let key = hasher.finish();
                
                ring.get_node(key)
                    .ok_or_else(|| anyhow::anyhow!("No nodes available in hash ring"))
            }
            LoadBalanceStrategy::LeastConnections => {
                let min_connections = load_balancer.connection_counts
                    .iter()
                    .min_by_key(|(_, count)| count.load(Ordering::Relaxed))
                    .map(|(node_id, _)| *node_id);
                
                min_connections
                    .ok_or_else(|| anyhow::anyhow!("No nodes available for least connections"))
            }
            LoadBalanceStrategy::RoundRobin => {
                let nodes: Vec<u64> = load_balancer.node_weights.keys().copied().collect();
                if nodes.is_empty() {
                    return Err(anyhow::anyhow!("No nodes available for round robin"));
                }
                
                let index = load_balancer.round_robin_counter.fetch_add(1, Ordering::Relaxed) % nodes.len();
                Ok(nodes[index])
            }
            _ => {
                // Fallback to consistent hashing
                let ring = self.hash_ring.read()
                    .map_err(|_| anyhow::anyhow!("Hash ring lock poisoned"))?;
                
                let mut hasher = DefaultHasher::new();
                session_id.hash(&mut hasher);
                let key = hasher.finish();
                
                ring.get_node(key)
                    .ok_or_else(|| anyhow::anyhow!("No nodes available"))
            }
        }
    }
    
    pub fn update_node_health(&self, node_id: u64, health: NodeHealth) -> Result<()> {
        let mut health_monitor = self.health_monitor.lock()
            .map_err(|_| anyhow::anyhow!("Health monitor lock poisoned"))?;
        
        health_monitor.node_health.insert(node_id, health.clone());
        health_monitor.last_health_check = SystemTime::now();
        
        // Check for alerts
        if health.cpu_usage > health_monitor.alert_thresholds.max_cpu_usage {
            warn!("Node {} CPU usage high: {:.1}%", node_id, health.cpu_usage);
        }
        
        if health.memory_usage > health_monitor.alert_thresholds.max_memory_usage {
            warn!("Node {} memory usage high: {:.1}%", node_id, health.memory_usage);
        }
        
        if health.error_rate > health_monitor.alert_thresholds.max_error_rate {
            warn!("Node {} error rate high: {:.1}%", node_id, health.error_rate);
        }
        
        debug!("Updated health for node {}: CPU {:.1}%, Memory {:.1}%, Sessions {}", 
               node_id, health.cpu_usage, health.memory_usage, health.session_count);
        
        Ok(())
    }
    
    pub fn get_cluster_stats(&self) -> Result<ClusterStats> {
        let health_monitor = self.health_monitor.lock()
            .map_err(|_| anyhow::anyhow!("Health monitor lock poisoned"))?;
        
        let healthy_nodes = health_monitor.node_health.values()
            .filter(|health| matches!(health.status, NodeStatus::Healthy))
            .count();
        
        let total_sessions: u64 = health_monitor.node_health.values()
            .map(|health| health.session_count)
            .sum();
        
        let avg_cpu_usage = if !health_monitor.node_health.is_empty() {
            health_monitor.node_health.values()
                .map(|health| health.cpu_usage)
                .sum::<f32>() / health_monitor.node_health.len() as f32
        } else {
            0.0
        };
        
        Ok(ClusterStats {
            total_nodes: health_monitor.cluster_metrics.total_nodes,
            healthy_nodes,
            total_sessions,
            avg_cpu_usage,
            avg_memory_usage: health_monitor.node_health.values()
                .map(|health| health.memory_usage)
                .sum::<f32>() / health_monitor.node_health.len().max(1) as f32,
        })
    }
}

#[derive(Debug, Clone)]
pub struct ClusterStats {
    pub total_nodes: usize,
    pub healthy_nodes: usize,
    pub total_sessions: u64,
    pub avg_cpu_usage: f32,
    pub avg_memory_usage: f32,
}

impl Default for ClientContext {
    fn default() -> Self {
        Self {
            geo_location: None,
            device_fingerprint: [0u8; 32],
            is_new_device: false,
            connection_type: "HTTPS".to_string(),
            data_classification: "PUBLIC".to_string(),
            requires_sticky_routing: false,
            requires_audit_trail: false,
            pci_dss_required: false,
        }
    }
}

impl Default for ClusterConfig {
    fn default() -> Self {
        Self {
            node_capacity: 10000,
            replication_factor: 3,
            consistency_level: ConsistencyLevel::Quorum,
            load_balance_strategy: LoadBalanceStrategy::ConsistentHashing,
            heartbeat_interval: Duration::from_secs(10),
            session_timeout: Duration::from_secs(3600),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    
    #[test]
    fn test_consistent_hash_ring() -> Result<()> {
        let mut ring = ConsistentHashRing::new(100);
        
        ring.add_node(1, 1000)?;
        ring.add_node(2, 1000)?;
        ring.add_node(3, 1000)?;
        
        // Test that same key always maps to same node
        let key = 12345u64;
        let node1 = ring.get_node(key);
        let node2 = ring.get_node(key);
        assert_eq!(node1, node2);
        
        // Test replication
        let replicas = ring.get_nodes_for_replication(key, 2);
        assert!(replicas.len() <= 2);
        
        Ok(())
    }
    
    #[test]
    fn test_cluster_manager() -> Result<()> {
        let config = ClusterConfig::default();
        let manager = SessionClusterManager::new(config)?;
        
        manager.add_node(1, 1000)?;
        manager.add_node(2, 1000)?;
        
        let session_id = [42u8; 32];
        let client_context = ClientContext::default();
        
        let selected_node = manager.select_node_for_session(&session_id, &client_context)?;
        assert!(selected_node == 1 || selected_node == 2);
        
        let stats = manager.get_cluster_stats()?;
        assert_eq!(stats.total_nodes, 2);
        
        Ok(())
    }
}