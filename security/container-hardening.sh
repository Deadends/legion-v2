#!/bin/bash
set -euo pipefail

# LEGION Container Security Hardening Script
# This script implements advanced container security measures

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
LEGION_ROOT="$(dirname "$SCRIPT_DIR")"

echo "🔒 Starting LEGION container security hardening..."

# Function to check if running as root
check_root() {
    if [[ $EUID -ne 0 ]]; then
        echo "❌ This script must be run as root for security hardening"
        exit 1
    fi
}

# Function to install security tools
install_security_tools() {
    echo "📦 Installing security tools..."
    
    # Update package lists
    apt-get update -qq
    
    # Install security scanning tools
    apt-get install -y --no-install-recommends \
        apparmor-utils \
        auditd \
        fail2ban \
        rkhunter \
        chkrootkit \
        lynis \
        clamav \
        clamav-daemon \
        aide \
        logwatch \
        psad \
        tiger \
        unhide
    
    # Install network security tools
    apt-get install -y --no-install-recommends \
        nftables \
        iptables-persistent \
        netfilter-persistent
    
    # Clean up
    apt-get clean
    rm -rf /var/lib/apt/lists/*
}

# Function to configure AppArmor
configure_apparmor() {
    echo "🛡️  Configuring AppArmor..."
    
    # Copy LEGION AppArmor profile
    cp "$SCRIPT_DIR/apparmor-profile" /etc/apparmor.d/legion-container
    
    # Load the profile
    apparmor_parser -r /etc/apparmor.d/legion-container
    
    # Enable AppArmor
    systemctl enable apparmor
    systemctl start apparmor
    
    echo "✅ AppArmor configured for LEGION containers"
}

# Function to configure audit logging
configure_audit() {
    echo "📋 Configuring audit logging..."
    
    # Create audit rules for LEGION
    cat > /etc/audit/rules.d/legion.rules << 'EOF'
# LEGION Security Audit Rules

# Monitor file access in LEGION directories
-w /var/lib/legion/ -p rwxa -k legion_data_access
-w /var/log/legion/ -p rwxa -k legion_log_access
-w /etc/legion/ -p rwxa -k legion_config_access

# Monitor LEGION binaries
-w /usr/local/bin/legion-sidecar -p x -k legion_execution
-w /usr/local/bin/legion-prover -p x -k legion_execution

# Monitor network connections
-a always,exit -F arch=b64 -S socket -F a0=2 -k legion_network
-a always,exit -F arch=b64 -S connect -k legion_network
-a always,exit -F arch=b64 -S bind -k legion_network

# Monitor privilege escalation
-a always,exit -F arch=b64 -S setuid -S setgid -S setreuid -S setregid -k legion_privilege
-a always,exit -F arch=b64 -S execve -k legion_exec

# Monitor file permissions changes
-a always,exit -F arch=b64 -S chmod -S fchmod -S fchmodat -k legion_perm_mod
-a always,exit -F arch=b64 -S chown -S fchown -S fchownat -S lchown -k legion_ownership

# Monitor cryptographic operations (approximate)
-w /dev/random -p r -k legion_crypto
-w /dev/urandom -p r -k legion_crypto

# Monitor process creation and termination
-a always,exit -F arch=b64 -S clone -S fork -S vfork -k legion_process
EOF

    # Restart auditd
    systemctl enable auditd
    systemctl restart auditd
    
    echo "✅ Audit logging configured"
}

# Function to configure fail2ban
configure_fail2ban() {
    echo "🚫 Configuring fail2ban..."
    
    # Create LEGION-specific fail2ban jail
    cat > /etc/fail2ban/jail.d/legion.conf << 'EOF'
[legion-auth]
enabled = true
port = 8443
protocol = tcp
filter = legion-auth
logpath = /var/log/legion/audit.log
maxretry = 3
bantime = 3600
findtime = 600
action = iptables-multiport[name=legion-auth, port="8443", protocol=tcp]

[legion-dos]
enabled = true
port = 8443
protocol = tcp
filter = legion-dos
logpath = /var/log/legion/access.log
maxretry = 100
bantime = 1800
findtime = 60
action = iptables-multiport[name=legion-dos, port="8443", protocol=tcp]
EOF

    # Create LEGION authentication filter
    cat > /etc/fail2ban/filter.d/legion-auth.conf << 'EOF'
[Definition]
failregex = ^.*authentication_failure.*client_ip="<HOST>".*$
            ^.*invalid_proof.*client_ip="<HOST>".*$
            ^.*rate_limit_exceeded.*client_ip="<HOST>".*$
ignoreregex =
EOF

    # Create LEGION DoS filter
    cat > /etc/fail2ban/filter.d/legion-dos.conf << 'EOF'
[Definition]
failregex = ^<HOST>.*"(GET|POST|PUT|DELETE).*" (4\d\d|5\d\d) .*$
ignoreregex = ^<HOST>.*"(GET|POST|PUT|DELETE).*" (200|201|204|301|302|304) .*$
EOF

    # Enable and start fail2ban
    systemctl enable fail2ban
    systemctl restart fail2ban
    
    echo "✅ Fail2ban configured"
}

# Function to configure network security
configure_network_security() {
    echo "🌐 Configuring network security..."
    
    # Configure nftables rules
    cat > /etc/nftables.conf << 'EOF'
#!/usr/sbin/nft -f

flush ruleset

table inet filter {
    chain input {
        type filter hook input priority 0; policy drop;
        
        # Allow loopback
        iif lo accept
        
        # Allow established and related connections
        ct state established,related accept
        
        # Allow LEGION service port
        tcp dport 8443 ct state new accept
        
        # Allow SSH (if needed)
        tcp dport 22 ct state new accept
        
        # Allow ping
        icmp type echo-request accept
        icmpv6 type echo-request accept
        
        # Rate limiting for LEGION port
        tcp dport 8443 limit rate 100/minute accept
        
        # Log dropped packets
        log prefix "LEGION-DROP: " drop
    }
    
    chain forward {
        type filter hook forward priority 0; policy drop;
    }
    
    chain output {
        type filter hook output priority 0; policy accept;
    }
}

# Anti-DDoS table
table inet ddos {
    set ratelimit {
        type ipv4_addr
        size 65536
        flags dynamic,timeout
        timeout 1m
    }
    
    chain input {
        type filter hook input priority -100;
        
        # Rate limit per IP
        add @ratelimit { ip saddr limit rate 50/minute } accept
        drop
    }
}
EOF

    # Enable nftables
    systemctl enable nftables
    systemctl start nftables
    
    echo "✅ Network security configured"
}

# Function to configure file integrity monitoring
configure_file_integrity() {
    echo "🔍 Configuring file integrity monitoring..."
    
    # Configure AIDE
    cat > /etc/aide/aide.conf << 'EOF'
# LEGION AIDE Configuration

database=file:/var/lib/aide/aide.db
database_out=file:/var/lib/aide/aide.db.new
gzip_dbout=yes

# LEGION-specific rules
/usr/local/bin/legion-sidecar f+p+u+g+s+m+c+md5+sha256
/usr/local/bin/legion-prover f+p+u+g+s+m+c+md5+sha256
/etc/legion f+p+u+g+s+m+c+md5+sha256
/var/lib/legion/keys f+p+u+g+s+m+c+md5+sha256

# System files
/bin f+p+u+g+s+m+c+md5+sha256
/sbin f+p+u+g+s+m+c+md5+sha256
/usr/bin f+p+u+g+s+m+c+md5+sha256
/usr/sbin f+p+u+g+s+m+c+md5+sha256
/lib f+p+u+g+s+m+c+md5+sha256
/usr/lib f+p+u+g+s+m+c+md5+sha256

# Configuration files
/etc f+p+u+g+s+m+c+md5+sha256

# Exclude volatile directories
!/var/log
!/tmp
!/proc
!/sys
!/dev
!/run
EOF

    # Initialize AIDE database
    aide --init
    mv /var/lib/aide/aide.db.new /var/lib/aide/aide.db
    
    # Create daily check script
    cat > /etc/cron.daily/aide-check << 'EOF'
#!/bin/bash
/usr/bin/aide --check | /usr/bin/mail -s "AIDE Report $(hostname)" root
EOF
    chmod +x /etc/cron.daily/aide-check
    
    echo "✅ File integrity monitoring configured"
}

# Function to configure container runtime security
configure_container_runtime() {
    echo "🐳 Configuring container runtime security..."
    
    # Create Docker daemon configuration with security settings
    mkdir -p /etc/docker
    cat > /etc/docker/daemon.json << 'EOF'
{
  "log-driver": "json-file",
  "log-opts": {
    "max-size": "10m",
    "max-file": "3"
  },
  "live-restore": true,
  "userland-proxy": false,
  "no-new-privileges": true,
  "seccomp-profile": "/etc/docker/seccomp-profile.json",
  "apparmor-profile": "legion-container",
  "selinux-enabled": false,
  "storage-driver": "overlay2",
  "storage-opts": [
    "overlay2.override_kernel_check=true"
  ],
  "default-ulimits": {
    "nofile": {
      "Name": "nofile",
      "Hard": 64000,
      "Soft": 64000
    },
    "nproc": {
      "Name": "nproc",
      "Hard": 32768,
      "Soft": 32768
    }
  },
  "max-concurrent-downloads": 3,
  "max-concurrent-uploads": 5
}
EOF

    # Copy seccomp profile
    cp "$SCRIPT_DIR/seccomp-profile.json" /etc/docker/seccomp-profile.json
    
    # Restart Docker daemon
    systemctl restart docker
    
    echo "✅ Container runtime security configured"
}

# Function to configure system hardening
configure_system_hardening() {
    echo "⚙️  Configuring system hardening..."
    
    # Kernel parameters for security
    cat > /etc/sysctl.d/99-legion-security.conf << 'EOF'
# LEGION Security Kernel Parameters

# Network security
net.ipv4.ip_forward = 0
net.ipv4.conf.all.send_redirects = 0
net.ipv4.conf.default.send_redirects = 0
net.ipv4.conf.all.accept_redirects = 0
net.ipv4.conf.default.accept_redirects = 0
net.ipv4.conf.all.accept_source_route = 0
net.ipv4.conf.default.accept_source_route = 0
net.ipv4.conf.all.log_martians = 1
net.ipv4.conf.default.log_martians = 1
net.ipv4.icmp_echo_ignore_broadcasts = 1
net.ipv4.icmp_ignore_bogus_error_responses = 1
net.ipv4.tcp_syncookies = 1
net.ipv4.tcp_max_syn_backlog = 2048
net.ipv4.tcp_synack_retries = 2
net.ipv4.tcp_syn_retries = 5

# IPv6 security
net.ipv6.conf.all.accept_redirects = 0
net.ipv6.conf.default.accept_redirects = 0
net.ipv6.conf.all.accept_source_route = 0
net.ipv6.conf.default.accept_source_route = 0

# Memory protection
kernel.dmesg_restrict = 1
kernel.kptr_restrict = 2
kernel.yama.ptrace_scope = 1
kernel.core_uses_pid = 1
fs.suid_dumpable = 0

# Process restrictions
kernel.pid_max = 65536
vm.mmap_min_addr = 65536

# File system security
fs.protected_hardlinks = 1
fs.protected_symlinks = 1
EOF

    # Apply sysctl settings
    sysctl -p /etc/sysctl.d/99-legion-security.conf
    
    # Configure limits
    cat > /etc/security/limits.d/99-legion.conf << 'EOF'
# LEGION Security Limits
* soft nproc 32768
* hard nproc 32768
* soft nofile 65536
* hard nofile 65536
* soft core 0
* hard core 0
EOF

    echo "✅ System hardening configured"
}

# Function to setup security monitoring
setup_security_monitoring() {
    echo "📊 Setting up security monitoring..."
    
    # Create security monitoring script
    cat > /usr/local/bin/legion-security-monitor << 'EOF'
#!/bin/bash

# LEGION Security Monitoring Script
LOG_FILE="/var/log/legion/security-monitor.log"
ALERT_EMAIL="security@legion.local"

log_event() {
    echo "$(date '+%Y-%m-%d %H:%M:%S') - $1" >> "$LOG_FILE"
}

check_failed_logins() {
    local failed_count=$(grep "authentication_failure" /var/log/legion/audit.log | wc -l)
    if [ "$failed_count" -gt 10 ]; then
        log_event "HIGH: $failed_count failed login attempts detected"
        echo "High number of failed login attempts: $failed_count" | mail -s "LEGION Security Alert" "$ALERT_EMAIL"
    fi
}

check_file_integrity() {
    if aide --check > /tmp/aide-check.log 2>&1; then
        log_event "INFO: File integrity check passed"
    else
        log_event "CRITICAL: File integrity check failed"
        cat /tmp/aide-check.log | mail -s "LEGION File Integrity Alert" "$ALERT_EMAIL"
    fi
}

check_rootkit() {
    if rkhunter --check --skip-keypress --report-warnings-only > /tmp/rkhunter.log 2>&1; then
        log_event "INFO: Rootkit scan clean"
    else
        log_event "WARNING: Rootkit scan found issues"
        cat /tmp/rkhunter.log | mail -s "LEGION Rootkit Alert" "$ALERT_EMAIL"
    fi
}

check_network_connections() {
    local suspicious_connections=$(netstat -tuln | grep -E ":(22|8443)" | wc -l)
    if [ "$suspicious_connections" -gt 100 ]; then
        log_event "WARNING: High number of network connections: $suspicious_connections"
    fi
}

# Run checks
check_failed_logins
check_file_integrity
check_rootkit
check_network_connections

log_event "Security monitoring cycle completed"
EOF

    chmod +x /usr/local/bin/legion-security-monitor
    
    # Add to cron
    echo "0 */6 * * * root /usr/local/bin/legion-security-monitor" >> /etc/crontab
    
    echo "✅ Security monitoring configured"
}

# Main execution
main() {
    check_root
    
    echo "🚀 LEGION Container Security Hardening"
    echo "======================================"
    
    install_security_tools
    configure_apparmor
    configure_audit
    configure_fail2ban
    configure_network_security
    configure_file_integrity
    configure_container_runtime
    configure_system_hardening
    setup_security_monitoring
    
    echo ""
    echo "✅ LEGION container security hardening completed!"
    echo ""
    echo "📋 Security measures implemented:"
    echo "   • AppArmor mandatory access control"
    echo "   • Comprehensive audit logging"
    echo "   • Fail2ban intrusion prevention"
    echo "   • Network firewall and rate limiting"
    echo "   • File integrity monitoring (AIDE)"
    echo "   • Container runtime security"
    echo "   • System kernel hardening"
    echo "   • Automated security monitoring"
    echo ""
    echo "🔍 Monitor security logs at:"
    echo "   • /var/log/legion/security-monitor.log"
    echo "   • /var/log/audit/audit.log"
    echo "   • /var/log/fail2ban.log"
    echo ""
    echo "⚠️  Remember to:"
    echo "   • Regularly update security signatures"
    echo "   • Review audit logs daily"
    echo "   • Test incident response procedures"
    echo "   • Keep system packages updated"
}

# Execute main function
main "$@"