# Puppet chain

## Getting started

```bash
$ cat helium.conf
chain=regtest
disablewallet=0
txindex=1
server=1
rpcuser=helium-node
rpcpassword=secret

// Start bitcoind
$ bitcoind -conf=helium.conf

// Start puppet-chain
$ DYNAMIC_GENESIS_TIMESTAMP=1 cargo run local-leader.toml.default 
```

## Setup block range config

With the following config:

```
[[blocks]]
count = 1
block_time = 20000
ignore_txs = false

[[blocks]]
count = 2
block_time = 1000
ignore_txs = true


[[blocks]]
count = 10
block_time = 30000
ignore_txs = false

```

**Puppet-chain** will:
1) mine 1 block, forward all incoming transactions during the next 20 seconds, then 
2) mine 1 block, buffer submitted transactions and wait 1 second, 
3) mine 1 block, buffer submitted transactions and wait 1 second, 
4) mine 1 block, submit all the transactions received during 2) and 3) and wait 30 seconds,
... 
