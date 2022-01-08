export STACKS_LOG_DEBUG=1
cd testnet/stacks-node && \
cargo build --release && \
cd ../.. && \
target/release/stacks-node start --config=./testnet/stacks-node/conf/mainnet-miner-conf.toml
