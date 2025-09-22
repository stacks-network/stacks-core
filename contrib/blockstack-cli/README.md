# blockstack-cli

A CLI for building and signing Stacks transactions and interacting with Clarity contracts.

Features:
- `publish` — deploy Clarity smart contracts
- `contract-call` — call public functions on deployed contracts
- `token-transfer` — send STX between accounts
- Decoding helpers for transactions and payloads

Build:
```bash
cargo build -p blockstack-cli
```

Basic usage:
```bash
cargo run -p blockstack-cli --help
```

Examples:
```bash
# Publish a contract
cargo run -p blockstack-cli publish --path <CLARITY-CONTRACT-PATH> --sender <PRIVKEY> --network <NETWORK>

# Call a contract function
cargo run -p blockstack-cli contract-call --contract <PRINCIPAL.contract> --function <fn-name> --args '[(int 1)]' --sender <PRIVKEY>

# Transfer STX
cargo run -p blockstack-cli token-transfer --amount 100000 --sender <PRIVKEY> --recipient <PRINCIPAL>
```

See `--help` on each subcommand for complete options.
