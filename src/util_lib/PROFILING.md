# Profilig Tools

## Working dir

```
$ export STACKS_WORK_DIR=~/stacks-work
```

`testnet/stacks-node/conf/mocknet-miner-conf.toml`
```
[node]
working_dir = "/home/user/stacks-work"
```

## Logging tips

```
$ STACKS_LOG_DEBUG=1 cargo run -r --bin stacks-inspect try-mine $STACKS_WORKING_DIR
...
DEBG [1661220065.247656] [src/chainstate/stacks/index/trie.rs:990] [main] Next root hash is 0000000000000000000000000000000000000000000000000000000000000000 (update_skiplist=false)
INFO [1661220065.247666] [src/chainstate/stacks/miner.rs:1454] [main] Include tx, tx: d9997fe2fc21ac04c96adad2eabaeddf6863b5233fe2b56d76d894c5d358ad8d, payload: Coinbase, origin: SP612EHTHDYDTEP4S9NF7M9KYF67XC1Z83CDYBKK
```

```
$ STACKS_LOG_JSON=1 cargo run -F slog_json -r --bin stacks-inspect try-mine $STACKS_WORKING_DIR
...
{"msg":"Tx successfully processed.","level":"INFO","ts":"2022-08-22T21:02:11.051898-05:00","thread":"main","line":261,"file":"src/chainstate/stacks/miner.rs","event_type":"success","tx_id":"37ee1f010f3e6f034359458e7df374dcfe00c4875fe2c29e55c5334b094e7d9d","event_name":"transaction_result"}
{"msg":"Post-condition check failure on fungible asset SP3K8BC0PPEVCV7NZ6QSRWPQ2JE9E5B6N3PA0KBR9.auto-alex::auto-alex owned by SP3Z7511VWR5WG9J3MAKER3NRZYKWT83K2XTP36EV: 86403982983 SentEq 0","level":"INFO","ts":"2022-08-22T21:02:18.659417-05:00","thread":"main","line":515,"file":"src/chainstate/stacks/db/transactions.rs"}
```

## Capturing Events

### Setup mock mining node
```
$ wget https://storage.googleapis.com/blockstack-publish/archiver-main/follower/mainnet-follower-latest.tar.gz
$ cargo run -r -p stacks-node --bin stacks-node start --config=conf/mainnet-mockminer-conf.toml
```

```
$ curl -s 127.0.0.1:20443/v2/info | jq .stacks_tip_height
$ curl -s seed-0.mainnet.stacks.co:20443/v2/info | jq .stacks_tip_height
```

### Record node events

```
[[events_observer]]
endpoint = "localhost:3700"
events_keys = ["*"]
```

```
$ cargo run -r --bin stacks-events | tee $STACKS_WORKING_DIR/events.log
...
{"path":"drop_mempool_tx","payload":{"dropped_txids":["0x6f78047f15ac3309153fc34be94ed8895111304336aec1ff106b7de051021e17, ..., "ts":"2022-08-12T05:03:08.577Z"}
```

## Historical Mining

### Discover first recorded block height
```
cat /Users/igor/w/stacks-work/events.log | egrep new_block | jq .payload.block_height
```

### Discover lower bound number of recorded transactions. Each line is a list of transactions.
```
cat /Users/igor/w/stacks-work/events.log | egrep new_mempool_tx | wc -l
```

### Make a snapshot of the working directory
```
$ cp -r $STACKS_WORKING_DIR $STACKS_WORKING_DIR/working_dir_snapshot
```

## Run the tip-mine benchmark
```
$ cargo run -F disable-costs -r --bin stacks-inspect tip-mine $STACKS_WORKING_DIR/working_dir_snapshot $STACKS_WORKING_DIR/events.log 71294 0
```

## Profiling using Perf and Dtrace

https://github.com/flamegraph-rs/flamegraph
`.cargo/config`

```
[target.x86_64-unknown-linux-gnu]
linker = "/usr/bin/clang"
rustflags = ["-Clink-arg=-fuse-ld=lld", "-Clink-arg=-Wl,--no-rosegment"]
```

```
$ cargo build -F disable-costs -r --bin stacks-inspect
```

```
$ cargo install flamegraph
```

### Mac

```
$ flamegraph --root -o perf.svg -e cpu-clock --min-width 1 --deterministic -- ./target/release/stacks-inspect tip-mine $STACKS_WORKING_DIR/working_dir_snapshot $STACKS_WORKING_DIR/events.log 71294 100
```

### Debian

```
# Install patched perf
sudo apt install -y git libzstd-dev libunwind-dev libcap-dev libdw-dev libdwarf-dev libbfd-dev libelf-dev systemtap-sdt-dev binutils-dev libnuma-dev libiberty-dev bison flex 
git clone https://github.com/torvalds/linux.git
git checkout v5.15
cd linux/tools/perf && make
```

`/etc/sysctl.conf`
```
$ sudo sysctl -w kernel.perf_event_paranoid=-1
$ sudo sysctl -w kernel.kptr_restrict=0
```

```
PERF=~/linux/tools/perf/perf flamegraph --cmd "record -F 97 --call-graph dwarf,65528 -g -e cpu-clock" -o perf.svg --min-width 0.5 --deterministic -- ./target/release/stacks-inspect tip-mine $STACKS_WORKING_DIR/working_dir_snapshot $STACKS_WORKING_DIR/events.log 71294 100
```

## Profiling sqlite queries

```
$ STACKS_LOG_DEBUG=1 cargo run -F profile-sqlite,disable-costs -r --bin stacks-inspect try-mine $STACKS_WORKING_DIR
...
DEBG [1661217664.809057] [src/util_lib/db.rs:666] [main] sqlite trace profile {"millis":1,"query":"SELECT value FROM data_table WHERE key = ?"}
...
```