# stacks-inspect

A multifunction inspection CLI for Stacks chain data and networking.

Highlights:
- Decode primitives: Bitcoin headers/txs/blocks, Stacks blocks/microblocks, P2P net messages
- Chain queries: ancestors, MARF lookups, tenure info, PoX anchor evaluation
- Mining helpers: `try-mine`, `tip-mine`, sortition (anti-MEV) analysis
- Shadow chain tools: build, patch, repair, and verify shadow chainstate
- Replay: re-execute blocks and microblocks for diagnostics

Build:
```bash
cargo build -p stacks-inspect
```

Basic usage:
```bash
# Show version
cargo run -p stacks-inspect -- --version

# Example: decode a bitcoin header from file
cargo run -p stacks-inspect -- decode-bitcoin-header <HEIGHT> <PATH>

# Example: analyze anti-MEV behavior over a height range
cargo run -p stacks-inspect -- analyze-sortition-mev <burn_db> <sort_db> <chainstate_db> <start> <end> [miner advantage ...]
```

For detailed commands and flags, run:
```bash
cargo run -p stacks-inspect -- --help
```

Notes:
- Some commands expect mainnet data paths by default and may require specific network contexts.
- Operations that write data (e.g., shadow chain tools) are destructive—use copies of data directories when experimenting.
