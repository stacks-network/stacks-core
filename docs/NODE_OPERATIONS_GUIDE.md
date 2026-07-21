# Stacks Node Operations Guide

A comprehensive guide for operating and maintaining a Stacks node.

## Table of Contents

1. [Node Types](#node-types)
2. [Hardware Requirements](#hardware-requirements)
3. [Installation](#installation)
4. [Configuration](#configuration)
5. [Monitoring](#monitoring)
6. [Troubleshooting](#troubleshooting)
7. [Maintenance](#maintenance)

## Node Types

### Follower Node

A follower node syncs with the network and provides API access without participating in consensus.

**Use cases:**
- Running your own API endpoint
- Blockchain data analysis
- Development and testing
- Serving dApp backends

### Miner Node

A miner node actively participates in consensus by committing BTC to mine Stacks blocks.

**Use cases:**
- Earning STX rewards
- Supporting network decentralization
- Transaction inclusion control

### Signer Node (Nakamoto)

Signer nodes participate in the threshold signature scheme for block validation.

**Use cases:**
- sBTC signing
- Block finalization
- Network security

## Hardware Requirements

### Minimum Requirements (Follower)

| Component | Specification |
|-----------|--------------|
| CPU | 4 cores |
| RAM | 16 GB |
| Storage | 500 GB SSD |
| Network | 100 Mbps |

### Recommended (Production Follower)

| Component | Specification |
|-----------|--------------|
| CPU | 8+ cores |
| RAM | 32 GB |
| Storage | 1 TB NVMe SSD |
| Network | 1 Gbps |

### Miner Requirements

| Component | Specification |
|-----------|--------------|
| CPU | 8+ cores |
| RAM | 32 GB |
| Storage | 1 TB NVMe SSD |
| Network | 1 Gbps, low latency |
| Bitcoin | Full node access |

## Installation

### From Binary

```bash
# Download latest release
VERSION="2.5.0.0.0"
wget https://github.com/stacks-network/stacks-core/releases/download/${VERSION}/linux-glibc-x64.zip
unzip linux-glibc-x64.zip

# Move binaries
sudo mv stacks-node /usr/local/bin/
sudo mv stacks-signer /usr/local/bin/
sudo mv clarity-cli /usr/local/bin/

# Verify installation
stacks-node version
```

### From Source

```bash
# Install Rust
curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh
source $HOME/.cargo/env

# Clone repository
git clone https://github.com/stacks-network/stacks-core.git
cd stacks-core

# Build
cargo build --release --workspace

# Install
sudo cp target/release/stacks-node /usr/local/bin/
sudo cp target/release/stacks-signer /usr/local/bin/
```

### Docker

```bash
# Pull image
docker pull blockstack/stacks-core:latest

# Run follower node
docker run -d \
  --name stacks-node \
  -p 20443:20443 \
  -p 20444:20444 \
  -v /data/stacks:/root/stacks-node/data \
  blockstack/stacks-core:latest \
  stacks-node start --config /config/mainnet-follower.toml
```

## Configuration

### Follower Node Configuration

```toml
# mainnet-follower.toml

[node]
working_dir = "/var/stacks"
rpc_bind = "0.0.0.0:20443"
p2p_bind = "0.0.0.0:20444"
bootstrap_node = "seeds.mainnet.hiro.so:20444"
local_peer_seed = "<random_hex_string>"

# Enable full event logging
prometheus_bind = "0.0.0.0:9153"

[burnchain]
chain = "bitcoin"
mode = "mainnet"
peer_host = "bitcoin.mainnet.stacks.co"
rpc_port = 8332
peer_port = 8333

# Use your own Bitcoin node for better reliability
# peer_host = "127.0.0.1"
# username = "bitcoin"
# password = "your_rpc_password"

[connection_options]
read_only_call_limit_write_length = 0
read_only_call_limit_read_length = 100000
read_only_call_limit_write_count = 0
read_only_call_limit_read_count = 30
read_only_call_limit_runtime = 1000000000

[fee_estimation]
cost_estimator = "naive_pessimistic"
fee_estimator = "scalar_fee_rate"
cost_metric = "proportion_dot_product"
```

### Miner Configuration

```toml
# mainnet-miner.toml

[node]
working_dir = "/var/stacks"
rpc_bind = "0.0.0.0:20443"
p2p_bind = "0.0.0.0:20444"
seed = "<your_private_key>"
mine_microblocks = true
miner = true

[burnchain]
chain = "bitcoin"
mode = "mainnet"
peer_host = "127.0.0.1"
rpc_port = 8332
peer_port = 8333
username = "bitcoin"
password = "<your_btc_rpc_password>"
satoshis_per_byte = 25
burn_fee_cap = 450000

# Commit strategy
commit_anchor_block_within = 10

[miner]
first_attempt_time_ms = 5000
subsequent_attempt_time_ms = 30000
microblock_attempt_time_ms = 15000
self_signing_seed = 1

# Mining addresses (BTC P2WPKH)
# mining_key = "<btc_private_key_wif>"
```

### Signer Configuration (Nakamoto)

```toml
# signer.toml

[signer]
db_path = "/var/stacks/signer.sqlite"
stacks_private_key = "<your_stx_private_key>"
network = "mainnet"
event_timeout_ms = 5000

# Stacks node connection
node_host = "127.0.0.1:20443"

[dkg]
# Distributed key generation settings
timeout_ms = 30000
retry_delay_ms = 5000

[signing]
# Threshold signature settings
timeout_ms = 15000
max_signing_rounds = 5
```

## Monitoring

### Prometheus Metrics

```yaml
# prometheus.yml
scrape_configs:
  - job_name: 'stacks-node'
    static_configs:
      - targets: ['localhost:9153']
    scrape_interval: 15s
```

### Key Metrics to Monitor

```promql
# Block height (should increase)
stacks_node_block_height

# Mempool size
stacks_node_mempool_tx_count

# Peer connections
stacks_node_peer_count

# RPC latency
stacks_node_rpc_request_duration_seconds

# Miner: blocks won
stacks_node_miner_blocks_won_total
```

### Health Check Script

```bash
#!/bin/bash
# health-check.sh

NODE_URL="http://localhost:20443"

# Check if node is responding
RESPONSE=$(curl -s -o /dev/null -w "%{http_code}" "${NODE_URL}/v2/info")

if [ "$RESPONSE" != "200" ]; then
    echo "ERROR: Node not responding (HTTP $RESPONSE)"
    exit 1
fi

# Get node info
NODE_INFO=$(curl -s "${NODE_URL}/v2/info")
BURN_HEIGHT=$(echo $NODE_INFO | jq -r '.burn_block_height')
STX_HEIGHT=$(echo $NODE_INFO | jq -r '.stacks_tip_height')

echo "Node Status: OK"
echo "Bitcoin Height: $BURN_HEIGHT"
echo "Stacks Height: $STX_HEIGHT"

# Check if syncing
IS_SYNCING=$(echo $NODE_INFO | jq -r '.network_id')
echo "Network: $IS_SYNCING"

# Check peer count
PEER_INFO=$(curl -s "${NODE_URL}/v2/neighbors")
PEER_COUNT=$(echo $PEER_INFO | jq '.sample | length')
echo "Peer Count: $PEER_COUNT"

if [ "$PEER_COUNT" -lt 3 ]; then
    echo "WARNING: Low peer count"
fi
```

### Grafana Dashboard

```json
{
  "dashboard": {
    "title": "Stacks Node Monitoring",
    "panels": [
      {
        "title": "Block Height",
        "type": "stat",
        "targets": [
          {
            "expr": "stacks_node_block_height",
            "legendFormat": "Current Height"
          }
        ]
      },
      {
        "title": "Mempool Size",
        "type": "graph",
        "targets": [
          {
            "expr": "stacks_node_mempool_tx_count",
            "legendFormat": "Pending Transactions"
          }
        ]
      },
      {
        "title": "Peer Connections",
        "type": "gauge",
        "targets": [
          {
            "expr": "stacks_node_peer_count",
            "legendFormat": "Peers"
          }
        ]
      }
    ]
  }
}
```

## Troubleshooting

### Node Won't Start

```bash
# Check logs for errors
journalctl -u stacks-node -f

# Common issues:
# 1. Port already in use
netstat -tlnp | grep 20443

# 2. Disk space
df -h /var/stacks

# 3. Permission issues
ls -la /var/stacks
chown -R stacks:stacks /var/stacks
```

### Sync Issues

```bash
# Check Bitcoin connection
curl -s http://localhost:20443/v2/info | jq '.burn_block_height'

# Compare with actual Bitcoin height
curl -s "https://blockchain.info/q/getblockcount"

# If behind, check Bitcoin node
bitcoin-cli getblockchaininfo
```

### Memory Issues

```bash
# Monitor memory usage
ps aux | grep stacks-node

# Increase system limits
echo "vm.max_map_count=262144" >> /etc/sysctl.conf
sysctl -p

# Consider adding swap
fallocate -l 8G /swapfile
chmod 600 /swapfile
mkswap /swapfile
swapon /swapfile
```

### Network Issues

```bash
# Check firewall
ufw status
ufw allow 20443/tcp
ufw allow 20444/tcp

# Test connectivity
nc -zv seeds.mainnet.hiro.so 20444

# Check peers
curl -s http://localhost:20443/v2/neighbors | jq '.sample | length'
```

## Maintenance

### Regular Tasks

#### Daily
- Check node is synced
- Monitor disk usage
- Review error logs

#### Weekly
- Backup chainstate (if needed)
- Update peer list
- Review performance metrics

#### Monthly
- Check for updates
- Audit security
- Clean old logs

### Backup Procedure

```bash
#!/bin/bash
# backup.sh

BACKUP_DIR="/backup/stacks"
DATA_DIR="/var/stacks"
DATE=$(date +%Y%m%d)

# Stop node
systemctl stop stacks-node

# Create backup
tar -czvf "${BACKUP_DIR}/stacks-${DATE}.tar.gz" "${DATA_DIR}"

# Start node
systemctl start stacks-node

# Cleanup old backups (keep 7 days)
find ${BACKUP_DIR} -name "stacks-*.tar.gz" -mtime +7 -delete
```

### Upgrade Procedure

```bash
#!/bin/bash
# upgrade.sh

NEW_VERSION=$1
BINARY_URL="https://github.com/stacks-network/stacks-core/releases/download/${NEW_VERSION}/linux-glibc-x64.zip"

# Download new version
cd /tmp
wget ${BINARY_URL}
unzip linux-glibc-x64.zip

# Stop node
systemctl stop stacks-node

# Backup current binary
cp /usr/local/bin/stacks-node /usr/local/bin/stacks-node.bak

# Install new version
mv stacks-node /usr/local/bin/

# Verify
stacks-node version

# Start node
systemctl start stacks-node

# Monitor logs
journalctl -u stacks-node -f
```

## Additional Resources

- [Stacks Documentation](https://docs.stacks.co)
- [Stacks Discord](https://discord.gg/stacks)
- [Node Configuration Reference](https://github.com/stacks-network/stacks-core/blob/master/docs/rpc-endpoints.md)

---

*This guide is maintained by the community. Contributions welcome!*
