# Running a Stacks Follower Node

A follower (or "full node") syncs the Stacks blockchain without mining or signing.
Use cases include serving RPC/API requests, running a stacks-blockchain-api instance,
or monitoring the chain.

## Quick Start

```toml
[node]
working_dir = "/stacks-data/mainnet"
rpc_bind = "0.0.0.0:20443"
p2p_bind = "0.0.0.0:20444"
miner = false
stacker = false

[burnchain]
mode = "mainnet"
peer_host = "127.0.0.1"
```

Start the node:

```bash
stacks-node start --config=mainnet-follower-conf.toml
```

## Bitcoin Node

A follower needs a Bitcoin node to sync burnchain data. For mainnet, the default
ports (`rpc_port = 8332`, `peer_port = 8333`) are used. If your Bitcoin node requires
RPC authentication, add credentials to `[burnchain]`:

```toml
[burnchain]
username = "your-bitcoin-rpc-user"
password = "your-bitcoin-rpc-password"
```

## API Integration

To run a stacks-blockchain-api service alongside the follower, enable the events
observer and transaction indexing:

```toml
[node]
txindex = true

[[events_observer]]
endpoint = "localhost:3700"
events_keys = ["*"]
timeout_ms = 60_000
```

## Upgrading to a Signer Node

A follower can be upgraded to also serve a signer by adding three settings.
See [signing.md](signing.md) for full details.

```toml
[node]
stacker = true

[[events_observer]]
endpoint = "127.0.0.1:30000"
events_keys = ["stackerdb", "block_proposal", "burn_blocks"]

[connection_options]
auth_token = "your-secret-token"
```

## Local Development (Mocknet)

For local development without a Bitcoin node, use mocknet mode:

```bash
stacks-node start --config=mocknet.toml
```

Mocknet runs a simulated burnchain in-process, removes execution cost limits,
and requires pre-funded test accounts via `[[ustx_balance]]` entries.
See [`mocknet.toml`](../sample/conf/mocknet.toml).

## Environment Variables

These environment variables affect node behavior and cannot be set via TOML:

| Variable | Purpose |
| --- | --- |
| `STACKS_EVENT_OBSERVER` | Add an event observer endpoint (all events) |
| `STACKS_WORKING_DIR` | Override `node.working_dir` |
| `STACKS_LOG_JSON` | Enable JSON-formatted logging |
| `STACKS_LOG_DEBUG` | Enable debug-level logging |
| `STACKS_LOG_TRACE` | Enable trace-level logging |

## Configuration Files

| File | Purpose |
| --- | --- |
| [`mainnet-follower-conf.toml`](../sample/conf/mainnet-follower-conf.toml) | Mainnet follower |
| [`testnet-follower-conf.toml`](../sample/conf/testnet-follower-conf.toml) | Testnet follower |
| [`mocknet.toml`](../sample/conf/mocknet.toml) | Local mocknet development |

## Further Reading

- [Mining documentation](mining.md)
- [Signing documentation](signing.md)
