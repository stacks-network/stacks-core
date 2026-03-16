<p align="left">
  <a href="https://stacks.co">
    <img alt="Stacks" src="https://i.imgur.com/zzwnCnY.png" width="250" />
  </a>
</p>

# Stacks Blockchain

Reference implementation of the [Stacks blockchain](https://github.com/stacks-network/stacks) in Rust.

Stacks is a Bitcoin layer-2 blockchain that enables decentralized apps and predictable smart contracts using the [Clarity language](https://clarity-lang.org/). Stacks implements [Proof of Transfer (PoX)](https://community.stacks.org/pox) mining that anchors to Bitcoin security. Leader election happens at the Bitcoin blockchain and Stacks (STX) miners write new blocks on the separate Stacks blockchain. With PoX there is no need to modify Bitcoin to enable smart contracts and decentralized apps.

> **Current release: [3.3.0.0.4](https://github.com/stacks-network/stacks-core/releases/latest)** — includes Nakamoto upgrade with fast blocks and Bitcoin finality.

[![License: GPL v3](https://img.shields.io/badge/License-GPLv3-blue.svg?style=flat)](https://www.gnu.org/licenses/gpl-3.0)
[![Release](https://img.shields.io/github/v/release/stacks-network/stacks-core?style=flat)](https://github.com/stacks-network/stacks-core/releases/latest)
[![Discord Chat](https://img.shields.io/discord/621759717756370964.svg)](https://stacks.chat)

## What's New in Nakamoto

The [Nakamoto upgrade](https://stacks.org/nakamoto-is-here) (activated Q4 2024) introduces major improvements:

- **Fast blocks** — transactions confirm in under 10 seconds (previously ~10 minutes)
- **Bitcoin finality** — Stacks transactions are settled on Bitcoin, making them as hard to reverse as Bitcoin transactions
- **sBTC** — the first decentralized, trust-minimized Bitcoin peg, enabling smart contracts to read and write to Bitcoin
- **Clarity 3** — new block height keywords (`stacks-block-height`, `tenure-height`) and improved timestamp handling

## Building

### 1. Download and install Rust

_For building on Windows, follow the rustup installer instructions at https://rustup.rs/._

```bash
curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh
source $HOME/.cargo/env
rustup component add rustfmt
```

- When building the [`master`](https://github.com/stacks-network/stacks-core/tree/master) branch, ensure you are using the latest stable release:

```bash
rustup update
```

### 2. Clone the source repository:

```bash
git clone --depth=1 https://github.com/stacks-network/stacks-core.git
cd stacks-core
```

### 3. Build the project

```bash
# Fully optimized release build
cargo build --release
# Faster but less optimized build. Necessary if < 16 GB RAM
cargo build --profile release-lite
```

_Note on building_: you may set `RUSTFLAGS` to build binaries for your native cpu:

```
RUSTFLAGS="-Ctarget-cpu=native"
```

or uncomment these lines in `./.cargo/config.toml`:

```toml
# [build]
# rustflags = ["-Ctarget-cpu=native"]
```

## Testing

**Run the tests:**

```bash
cargo test testnet  -- --test-threads=1
```

**Run all unit tests in parallel using [nextest](https://nexte.st/):**

_Warning, this typically takes a few minutes_

```bash
cargo nextest run
```

_On Windows, many tests will fail, mainly due to parallelism. To mitigate the issue you may need to run the tests individually._

## Run the testnet

You can observe the state machine in action locally by running:

```bash
cargo run --bin stacks-node -- start --config ./sample/conf/testnet-follower-conf.toml
```

Additional testnet documentation is available [here](./docs/testnet.md) and [here](https://docs.stacks.co/docs/nodes-and-miners/miner-testnet)

## Release Process

The release process for the stacks blockchain is [defined here](./docs/release-process.md)

## Further Reading

You can learn more by visiting [the Stacks Website](https://stacks.co) and checking out the documentation:

- [Stacks docs](https://docs.stacks.co/)
- [Stacks Improvement Proposals (SIPs)](./docs/SIPS.md)
- [Mining](./docs/mining.md)
- [Profiling](./docs/profiling.md)
- [RPC endpoints](./docs/rpc-endpoints.md)
- [Event dispatcher](./docs/event-dispatcher.md)
- [Nakamoto upgrade](https://docs.stacks.co/nakamoto-upgrade/nakamoto-in-10-minutes)
- [sBTC documentation](https://docs.stacks.co/sbtc/introduction)
- [Clarity language reference](https://docs.stacks.co/clarity/overview)
- [Clarity cookbook](https://cookbook.clarity-lang.org/)

You can also read the technical papers:

- ["PoX: Proof of Transfer Mining with Bitcoin"](https://community.stacks.org/pox), May 2020
- ["Stacks 2.0: Apps and Smart Contracts for Bitcoin"](https://stacks.org/stacks), Dec 2020
- ["sBTC: A Trustless Two-Way Bitcoin Peg"](https://stacks.org/sbtc-nakamoto), 2024

## Contributing

Contributions are welcome! Please read [CONTRIBUTING.md](./CONTRIBUTING.md) before opening a pull request. For bugs and feature requests, open an [issue](https://github.com/stacks-network/stacks-core/issues). Join the discussion on [Discord](https://stacks.chat) or the [Stacks Forum](https://forum.stacks.org/).

## Copyright and License

The code and documentation copyright are attributed to stacks.org.

This code is released under the [GPL v3 license](https://www.gnu.org/licenses/quick-guide-gplv3.en.html), and the docs are released under the [Creative Commons license](https://creativecommons.org/).
