run-api-proxy:
	STACKS_NODE_URL=https://stacks-node-api.mainnet.stacks.co \
	BIND_ADDRESS=127.0.0.1:8000 \
	RUST_LOG=info \
	cargo run -p api-proxy
