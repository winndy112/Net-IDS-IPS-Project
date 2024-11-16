#!/bin/bash
# Security Infrastructure Setup Script for Ubuntu WSL
# Run with sudo privileges

# Color codes for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

# Logging function
log() {
    echo -e "${GREEN}[$(date +'%Y-%m-%d %H:%M:%S')] $1${NC}"
}

warn() {
    echo -e "${YELLOW}[$(date +'%Y-%m-%d %H:%M:%S')] WARNING: $1${NC}"
}

error() {
    echo -e "${RED}[$(date +'%Y-%m-%d %H:%M:%S')] ERROR: $1${NC}"
}
check_requirements() {
    log "Checking system requirements..."
    
    # Check if running as root
    if [ "$EUID" -ne 0 ]; then 
        error "Please run as root"
        exit 1
    fi
    
    # Check if running in WSL
    if ! grep -q Microsoft /proc/version; then
        warn "This script is optimized for WSL. Some features might not work as expected."
    fi
}

setup_firewall() {
    # Ensure that installed UFW and iptables: 
    # apt-get install -y ufw
    # 
    
    log "Configuring UFW..."
    # Configure basic rules
    ### DENY ALL AND ALLOW SOMETHING
    # ufw default deny incoming
    # ufw default allow outgoing
    # # Allow my Docker subnet 
    # ufw allow from 172.17.0.0/16
    # # Allow my WSL subnet
    # ufw allow from 172.31.208.0/20
    # ufw allow 22/tcp
    # # Allow Misp-specific rules
    # ufw allow 80/tcp
    # ufw allow 443/tcp

    ### ALLOW ALL AND DENY SOMETHING
    ufw default allow incoming
    ufw default allow outgoing
    #Block port 445 for worm-infected IPs
    ufw deny from any to any port 445 proto tcp comment "Worm-Infected p445"
    # Uses valid port ranges and block port 0 attacks
    ufw deny proto tcp from any to any port 1:65535 comment "TCP port scanning"
    ufw deny proto udp from any to any port 1:65535 comment "UDP port scanning"

    # Block TCP with invalid flag and flag combinations
    ufw deny proto tcp from any to any tcp-flags FIN,SYN,RST,ACK NONE comment 'Invalid TCP flags'
    ufw deny proto tcp from any to any tcp-flags FIN,SYN FIN,SYN comment 'TCP FIN-SYN'
    # Some PoC detail how data exfiltration can also leverage ICMP flows with a C2 server, using the data payload in ICMP-PING packets (T1048).
    # ufw deny proto icmp from any to any packet-size 1025:1600 comment "ICMP size > 1024"
    # ufw deny proto icmp from any to any packet-size 1601:65535 comment "ICMP large packet attack"
    # UFW do not directly support ICMP, so need to iptables (it's a low-level than UFW, provides directly access to packets filtering)
     # Use iptables directly for ICMP rules since UFW doesn't support ICMP protocol
    iptables -A INPUT -p icmp --icmp-type any -m length --length 1025:1600 -j DROP -m comment --comment "ICMP size > 1024"
    iptables -A INPUT -p icmp --icmp-type any -m length --length 1601:65535 -j DROP -m comment --comment "ICMP large packet attack"

    #Block fragmented packets
    ufw deny from any to any proto icmp fragment comment 'ICMP fragmentation attack'
    ufw deny from any to any proto tcp tcp-flags SYN,RST SYN fragment comment 'SYN fragmented attack'
    

    echo "y" | ufw enable

    log "UFW was intalled and configured."
    log "Current UFW rules:"
    ufw status verbose
}
check_requirements
setup_firewall
