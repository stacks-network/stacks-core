# Stacks Signing

Stacks signers validate and co-sign blocks produced by miners. Running a signer
requires two configuration files:

1. **Signer binary config** — configures the `stacks-signer` process
2. **Signer node config** — configures the `stacks-node` that the signer connects to

## Configuration Files

| File                                                                         | Binary          | Purpose                                                     |
| ---------------------------------------------------------------------------- | --------------- | ----------------------------------------------------------- |
| [`mainnet-signer-conf.toml`](../sample/conf/signer/mainnet-signer-conf.toml) | `stacks-signer` | Signer process settings (keys, timeouts, tenure management) |
| [`mainnet-signer.toml`](../sample/conf/mainnet-signer.toml)                  | `stacks-node`   | Node-side settings (events, auth, networking)               |

For testnet, use [`testnet-signer.toml`](../sample/conf/testnet-signer.toml) for the node-side config.

## Quick Start

### 1. Configure the Stacks Node

Use [`mainnet-signer.toml`](../sample/conf/mainnet-signer.toml) as a starting point for your node config.
Key settings:

```toml
[node]
stacker = true

[[events_observer]]
endpoint = "127.0.0.1:30000"
events_keys = ["stackerdb", "block_proposal", "burn_blocks"]

[connection_options]
auth_token = "your-secret-token"
```

### 2. Configure the Signer

Use [`mainnet-signer-conf.toml`](../sample/conf/signer/mainnet-signer-conf.toml) as a starting point.
Key settings:

```toml
stacks_private_key = "<YOUR_SIGNER_PRIVATE_KEY_HEX>"
node_host = "127.0.0.1:20443"
endpoint = "0.0.0.0:30000"
network = "mainnet"
auth_password = "your-secret-token"
db_path = "/var/lib/stacks-signer/signerdb.sqlite"
```

### 3. Verify Coordination

These settings **must** match between the node and signer configs:

| Signer Config   | Node Config                       | Must Match                    |
| --------------- | --------------------------------- | ----------------------------- |
| `auth_password` | `[connection_options] auth_token` | Exact string match            |
| `endpoint`      | `[[events_observer]] endpoint`    | Same host:port                |
| `node_host`     | `[node] rpc_bind`                 | Signer connects to node's RPC |

## Miner-Signer Interactions

If you are running both a miner and a signer, several timeout settings must be
coordinated to avoid block rejections. See the WARNING comments in
[`mainnet-miner-conf.toml`](../sample/conf/mainnet-miner-conf.toml) and
[`mainnet-signer-conf.toml`](../sample/conf/signer/mainnet-signer-conf.toml) for details.

Key interactions:

- **`tenure_extend_wait_timeout_ms`** (miner) must be >= **`block_proposal_timeout_ms`** (signer).
  The signer waits `block_proposal_timeout_ms` before marking an unresponsive miner as inactive.
  If the miner extends before the signer invalidates the new winner, the extend is rejected.

- **`tenure_timeout_secs`** (miner) should be > signer's **`tenure_idle_timeout_secs + tenure_idle_timeout_buffer_secs`** (default 62s).
  The signer computes an extend timestamp from the last block time + idle timeout + buffer.
  The miner must wait at least this long before time-based extends.

- **`min_time_between_blocks_ms`** (miner) must be >= 1000ms.
  Blocks with same-second timestamps as their parent are rejected network-wide.

## Running

```bash
# Start the node
stacks-node start --config mainnet-signer.toml

# Start the signer
stacks-signer run --config mainnet-signer-conf.toml
```

## Further Reading

- [Comprehensive signer config reference](../sample/conf/signer/mainnet-signer-conf.toml)
- [Comprehensive miner config reference](../sample/conf/mainnet-miner-conf.toml)
- [Mining documentation](mining.md)
- [Follower documentation](follower.md)
