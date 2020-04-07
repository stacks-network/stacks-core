# Stacks 2.0

Reference implementation of the [Blockstack Technical Whitepaper](https://blockstack.org/whitepaper.pdf) in Rust.

[![CircleCI](https://circleci.com/gh/blockstack/stacks-blockchain/tree/master.svg?style=svg)](https://circleci.com/gh/blockstack/stacks-blockchain/tree/master)

## Repository

| Blockstack Topic/Tech    | Where to learn more more                                                          |
| ------------------------ | --------------------------------------------------------------------------------- |
| Stacks 2.0               | [master branch](https://github.com/blockstack/stacks-blockchain/tree/master)      |
| Stacks 1.0               | [legacy branch](https://github.com/blockstack/stacks-blockchain/tree/stacks-1.0)  |
| Use the package          | [our core docs](https://docs.blockstack.org/core/naming/introduction.html)        |
| Develop a Blockstack App | [our developer docs](https://docs.blockstack.org/browser/hello-blockstack.html)   |
| Use a Blockstack App     | [our browser docs](https://docs.blockstack.org/browser/browser-introduction.html) |
| Blockstack the company   | [our website](https://blockstack.org)                                             |

## Design Thesis

Stacks 2.0 is an open-membership replicated state machine produced by the coordination of a non-enumerable set of peers.

To unpack this definition:

- A replicated state machine is two or more copies (“replicas”) of a given set of rules (a “machine”) that, in processing a common input (such as the same sequence of transactions), will arrive at the same configuration (“state”). Bitcoin is a replicated state machine — its state is the set of UTXOs, which each peer has a full copy of, and given a block, all peers will independently calculate the same new UTXO set from the existing one.
- Open-membership means that any host on the Internet can join the blockchain and independently calculate the same full replica as all other peers.
- Non-enumerable means that the set of peers that are producing the blocks don’t know about one another — they don’t know their identities, or even how many exist and are online. They are indistinguishable.

## Roadmap

- [x] [SIP 001: Burn Election](https://github.com/blockstack/stacks-blockchain/blob/master/sip/sip-001-burn-election.md)
- [x] [SIP 002: Clarity, a language for predictable smart contracts](https://github.com/blockstack/stacks-blockchain/blob/master/sip/sip-002-smart-contract-language.md)
- [x] [SIP 004: Cryptographic Committment to Materialized Views](https://github.com/blockstack/stacks-blockchain/blob/master/sip/sip-004-materialized-view.md)
- [x] [SIP 005: Blocks, Transactions, and Accounts](https://github.com/blockstack/stacks-blockchain/blob/master/sip/sip-005-blocks-and-transactions.md)
- [ ] [SIP 003: Peer Network](https://github.com/blockstack/stacks-blockchain/blob/master/sip/sip-003-peer-network.md) (Q1 2020)
- [ ] SIP 006: Clarity Execution Cost Assessment (Q1 2020)

Stacks improvement proposals (SIPs) are aimed at describing the implementation of the Stacks blockchain, as well as proposing improvements. They should contain concise technical specifications of features or standards and the rationale behind it. SIPs are intended to be the primary medium for proposing new features, for collecting community input on a system-wide issue, and for documenting design decisions.

See [SIP 000](https://github.com/blockstack/stacks-blockchain/blob/master/sip/sip-000-stacks-improvement-proposal-process.md) for more details.

### Testnet versions

- [x] **Local Testnet** is a developer local setup, mono-node, assembling SIP 001, SIP 002, SIP 004 and SIP 005. With this version, developers can not only run Stacks 2.0 on their development machines, but also write, execute, and test smart contracts. See the instructions below for more details.

- [ ] **Open Testnet** is the upcoming version of our public testnet, that we're anticipating will ship in Q2 2020. This testnet will ship with SIP 003, and will be an open-membership public network, where participants will be able to validate and participate in mining testnet blocks.

- [ ] **Mainet** is the fully functional version, that we're intending to ship in Q3 2020.

## Getting started

### Download and build stacks-blockchain

The first step is to ensure that you have Rust and the support software installed.

```bash
curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh
```

From there, you can clone this repository:

```bash
git clone https://github.com/blockstack/stacks-blockchain.git

cd stacks-blockchain
```

Then build the project:

```bash
cargo build
```

Building the project on ARM:

```bash
cargo build --features "aarch64" --no-default-features
```

Run the tests:

```bash
cargo test testnet  -- --test-threads=1
```

### Encode and sign transactions

Let's start by generating a keypair, that will be used for signing the upcoming transactions:

```bash
cargo run --bin blockstack-cli generate-sk --testnet

# Output
# {
#  secretKey: "b8d99fd45da58038d630d9855d3ca2466e8e0f89d3894c4724f0efc9ff4b51f001",
#  publicKey: "02781d2d3a545afdb7f6013a8241b9e400475397516a0d0f76863c6742210539b5",
#  stacksAddress: "ST2ZRX0K27GW0SP3GJCEMHD95TQGJMKB7G9Y0X1MH"
# }
```

We will interact with the following simple contract `kv-store`. In our examples, we will assume this contract is saved to `./kv-store.clar`:

```scheme
(define-map store ((key (buff 32))) ((value (buff 32))))

(define-public (get-value (key (buff 32)))
    (match (map-get? store {key: key})
        entry (ok (get value entry))
        (err 0)))

(define-public (set-value (key (buff 32)) (value (buff 32)))
    (begin
        (map-set store {key: key} {value: value})
        (ok 'true)))
```

We want to publish this contract on chain, then issue some transactions that interact with it by setting some keys and getting some values, so we can observe read and writes.

Our first step is to generate and sign, using your private key, the transaction that will publish the contract `kv-store`.
To do that, we will use the subcommand:

```bash
cargo run --bin blockstack-cli publish --help
```

With the following arguments:

```bash
cargo run --bin blockstack-cli publish b8d99fd45da58038d630d9855d3ca2466e8e0f89d3894c4724f0efc9ff4b51f001 0 0 kv-store ./kv-store.clar --testnet
```

This command will output the **binary format** of the transaction. In our case, we want to pipe this output and dump it to a file that will be used later in this tutorial.

```bash
cargo run --bin blockstack-cli publish b8d99fd45da58038d630d9855d3ca2466e8e0f89d3894c4724f0efc9ff4b51f001 0 0 kv-store ./kv-store.clar --testnet | xxd -r -p > tx1.bin
```

### Run the testnet

You can observe the state machine in action locally by running:

```bash
cargo run --bin blockstack-core testnet ./Stacks.toml
```

`Stacks.toml` is a configuration file that you can use for setting genesis balances or configuring Event observers.

The testnet is watching the directory specified by the key `mempool.path`. The transactions, materialized as files, will be decoded and ingested. This mechanism is a shortcut for simulating a mempool. A RPC server will soon be integrated.

### Publish your contract

Assuming that the testnet is running, we can publish our `kv-store` contract.

In another terminal (or file explorer), you can move the `tx1.bin` generated earlier, to the mempool:

```bash
cp ./tx1.bin /tmp/mempool
```

In the terminal window running the testnet, you can observe the state machine's reactions.

### Reading from / Writing to the contract

Now that our contract has been published on chain, let's try to submit some read / write transactions.
We will start by trying to read the value associated with the key `foo`.

To do that, we will use the subcommand:

```bash
cargo run --bin blockstack-cli contract-call --help
```

With the following arguments:

```bash
cargo run --bin blockstack-cli contract-call b8d99fd45da58038d630d9855d3ca2466e8e0f89d3894c4724f0efc9ff4b51f001 0 1 ST2ZRX0K27GW0SP3GJCEMHD95TQGJMKB7G9Y0X1MH kv-store get-value -e \"foo\" --testnet | xxd -r -p > tx2.bin
```

`contract-call` generates and signs a contract-call transaction.
Note: the third argument `1` is a nonce, that must be increased monotonically with each new transaction.

We can submit the transaction by moving it to the mempool path:

```bash
cp ./tx2.bin /tmp/mempool
```

Similarly, we can generate a transaction that would be setting the key `foo` to the value `bar`:

```bash
cargo run --bin blockstack-cli contract-call b8d99fd45da58038d630d9855d3ca2466e8e0f89d3894c4724f0efc9ff4b51f001 0 2 ST2ZRX0K27GW0SP3GJCEMHD95TQGJMKB7G9Y0X1MH kv-store set-value -e \"foo\" -e \"bar\" --testnet | xxd -r -p > tx3.bin
```

And submit it by moving it to the mempool path:

```bash
cp ./tx3.bin /tmp/mempool
```

Finally, we can issue a third transaction, reading the key `foo` again, for ensuring that the previous transaction has successfully updated the state machine:

```bash
cargo run --bin blockstack-cli contract-call b8d99fd45da58038d630d9855d3ca2466e8e0f89d3894c4724f0efc9ff4b51f001 0 3 ST2ZRX0K27GW0SP3GJCEMHD95TQGJMKB7G9Y0X1MH kv-store get-value -e \"foo\" --testnet | xxd -r -p > tx4.bin
```

And submit this last transaction by moving it to the mempool path:

```bash
cp ./tx4.bin /tmp/mempool
```

Congratulations, you can now [write your own smart contracts with Clarity](https://docs.blockstack.org/core/smart/overview.html).

## Platform support

Officially supported platforms: `Linux 64-bit`, `MacOS 64-bit`, `Windows 64-bit`.

Platforms with second-tier status _(builds are provided but not tested)_: `Linux ARMv7`, `Linux ARM64`.

## Community

Beyond this Github project,
Blockstack maintains a public [forum](https://forum.blockstack.org) and an
opened [Discord](https://discordapp.com/invite/9r94Xkj) channel. In addition, the project
maintains a [mailing list](https://blockstack.org/signup) which sends out
community announcements.

The greater Blockstack community regularly hosts in-person
[meetups](https://www.meetup.com/topics/blockstack/). The project's
[YouTube channel](https://www.youtube.com/channel/UC3J2iHnyt2JtOvtGVf_jpHQ) includes
videos from some of these meetups, as well as video tutorials to help new
users get started and help developers wrap their heads around the system's
design.

For help cross-compiling on memory-constrained devices, please see the community supported documentation here: [Cross Compiling](https://github.com/dantrevino/cross-compiling-stacks-blockchain/blob/master/README.md).

## Further Reading

You can learn more by visiting [the Blockstack Website](https://blockstack.org) and checking out the in-depth articles and documentation:

- [How Blockstack Works (white paper)](https://blockstack.org/docs/how-blockstack-works)
- [Blockstack General FAQ](https://blockstack.org/faq)

You can also read peer-reviewed Blockstack papers:

- ["Blockstack: A Global Naming and Storage System Secured by Blockchains"](https://www.usenix.org/system/files/conference/atc16/atc16_paper-ali.pdf), Proc. USENIX Annual Technical Conference ([ATC '16](https://www.usenix.org/conference/atc16)), June 2016
- ["Extending Existing Blockchains with Virtualchain"](https://www.zurich.ibm.com/dccl/papers/nelson_dccl.pdf), Distributed Cryptocurrencies and Consensus Ledgers ([DCCL '16](https://www.zurich.ibm.com/dccl/) workshop, at [ACM PODC 2016](https://www.podc.org/podc2016/)), July 2016

If you have high-level questions about Blockstack, try [searching our forum](https://forum.blockstack.org) and start a new question if your question is not answered there.

## Copyright and License

The code and documentation copyright are attributed to blockstack.org for the year of 2020.

This code is released under [the GPL v3 license](https://www.gnu.org/licenses/quick-guide-gplv3.en.html), and the docs are released under [the Creative Commons license](https://creativecommons.org/).
