# stacks-signer: Stacks Signer CLI

stacks-signer is a command-line interface (CLI) for executing DKG (Distributed Key Generation) rounds, signing transactions and blocks, and more within the Stacks blockchain ecosystem. This tool provides various subcommands to interact with the StackerDB contract, perform cryptographic operations, and run a Stacks compliant signer.

## Installation

To use stacks-signer, you need to build and install the Rust program. You can do this by following these steps:

1. **Clone the Repository**: Clone the stacks-signer repository from [GitHub](https://github.com/blockstack/stacks-blockchain).

   ```bash
   git clone https://github.com/blockstack/stacks-blockchain.git
   ```

2. **Build the Program**: Change to the stacks-signer directory and build the program using `cargo`.

   ```bash
   cd stacks-signer
   cargo build --release
   ```

3. **Run the Program**: You can now run the stacks-signer CLI.

   ```bash
   ./target/release/stacks-signer --help
   ```

## Usage

The stacks-signer CLI provides the following subcommands:

### `get-chunk`

Retrieve a chunk from the StackerDB instance.

```bash
./stacks-signer get-chunk --host <host> --contract <contract> --slot_id <slot_id> --slot_version <slot_version>
```

- `--host`: The stacks node host to connect to.
- `--contract`: The contract ID of the StackerDB instance.
- `--slot-id`: The slot ID to get.
- `--slot-version`: The slot version to get.

### `get-latest-chunk`

Retrieve the latest chunk from the StackerDB instance.

```bash
./stacks-signer get-latest-chunk --host <host> --contract <contract> --slot-id <slot_id>
```

- `--host`: The stacks node host to connect to.
- `--contract`: The contract ID of the StackerDB instance.
- `--slot-id`: The slot ID to get.

### `list-chunks`

List chunks from the StackerDB instance.

```bash
./stacks-signer list-chunks
```
- `--host`: The stacks node host to connect to.
- `--contract`: The contract ID of the StackerDB instance.

### `put-chunk`

Upload a chunk to the StackerDB instance.

```bash
./stacks-signer put-chunk --host <host> --contract <contract> --private_key <private_key> --slot-id <slot_id> --slot-version <slot_version> [--data <data>]
```

- `--host`: The stacks node host to connect to.
- `--contract`: The contract ID of the StackerDB instance.
- `--private_key`: The Stacks private key to use in hexademical format.
- `--slot-id`: The slot ID to get.
- `--slot-version`: The slot version to get.
- `--data`: The data to upload. If you wish to pipe data using STDIN, use with '-'.

### `dkg`

Run a distributed key generation round through stacker-db.

```bash
./stacks-signer dkg --config <config_file> 
```

- `--config`: The path to the signer configuration file.

### `dkg-sign`

Run a distributed key generation round and sign a given message through stacker-db.

```bash
./stacks-signer dkg-sign --config <config_file> [--data <data>]
```
- `--config`: The path to the signer configuration file.
- `--data`: The data to sign. If you wish to pipe data using STDIN, use with '-'.


### `dkg-sign`

Sign a given message through stacker-db.

```bash
./stacks-signer sign --config <config_file> [--data <data>]
```
- `--config`: The path to the signer configuration file.
- `--data`: The data to sign. If you wish to pipe data using STDIN, use with '-'.

### `run`

Start the signer and handle requests to sign messages and participate in DKG rounds via stacker-db.
```bash
./stacks-signer run --config <config_file>
```
- `--config`: The path to the signer configuration file.

### `generate-files`

Generate the necessary files to run a collection of signers to communicate via stacker-db.

```bash
./stacks-signer generate-files --host <host> --contract <contract>  --num-signers <num_signers> --num-keys <num_keys> --network <network> --dir <dir>
```
- `--host`: The stacks node host to connect to.
- `--contract`: The contract ID of the StackerDB signer contract.
- `--num-signers`: The number of signers to generate configuration files for.
- `--num-keys`: The total number of key ids to distribute among the signers.
- `--private-keys:` A path to a file containing a list of hexadecimal representations of Stacks private keys. Required if `--num-keys` is not set.
- `--network`: The network to use. One of "mainnet" or "testnet".
- `--dir`: The directory to write files to. Defaults to the current directory.
- `--timeout`: Optional timeout in milliseconds to use when polling for updates in the StackerDB runloop.


## `ping`

Ping is a tool that helps measure how long it takes for a stackerdb chunk update to go from sending, to the signer runloop processing the event update response. In a standard "ping" test, you set up a smart contract with the signers' addresses, allowing them to send messages through stackerdb. You need at least two signers to exchange messages. You can also try multiple simultaneous ping requests from different signers. Each signer running with the `--ping-in-millis` option actively requests pongs from any signer reachable through stackerdb replicas.

Choose a subset of nodes to participate in the benchmark. Share the secret seed among participants and pick a signer_id.

1. Use the shared secret to generate the smart contract.
2. Generate the signer config once you have decided on a signer_id among participants.
3. If not already done, add the stackerdb replica and the signer observer to the node config TOML.
4. Reboot the node and signer.
5. Publish the smart contract.

### Generating a contract

You can create a contract either by using randomly seeded private keys or by providing known addresses to the CLI. The subscripted stacks address must align with the stacks_private_key field used in the signer TOML config file.

Generate a contract with two random signers.

```
$ cargo run --bin stacks-signer -- ping generate-contract ./stackerdb.clar --seed "secret-seed" --network testnet --num-signers 2
```
Generate a contract with two known signers.
```
$ cargo run --bin stacks-signer -- ping generate-contract ./stackerdb.clar --signers SZ2J6ZY48GV1EZ5V2V5RB9MP66SW86PYKKQ9H6DPR, SPB5XD8Q2C7FWFQPM327MA8QWR6QC7HJ650HK40T
```

### Publishing the stacker db contract
You can publish the stackerdb contract like so or, alternatively, using clarinet. This command blocks until the contract source is found in the chain.

```
$ cargo run --bin stacks-signer ping publish-contract --source-file ./stackerdb.clar -c "stackerino" --network mocknet -n 0 -f 10000 --stacks-private-key <stacks-priv-key> --host "http://127.0.0.1:20443"
```

### Generating the signer config file

The next step involves creating a signer.toml. It's important to use the correct shared secret and signer_id when using the CLI to generate the corresponding private key for signing chunks. The runloop relies on the signing id to route messages to their respective senders. In the context of this tool, providing an incorrect signer_id to the CLI will result in the generation of an inaccurate config file.

Collaboration between benchmark participants is essential to pre-determine signer ids. Repeated signer ids is undefined behavior.
The parameters num-keys and num-signers only come into play if you intend to run a fully functional signer; otherwise, default to having at least one key per signer. message_keys are only needed for DKG.

```
$cargo run --bin stacks-signer -- ping generate-signer-config --save-to-file signer.0.toml -s "<shared secret seed>" --signer-id 0 -n mainnet --host 127.0.0.1:20443 -c "ST1EMWQSAEZ3VSD5TR9VY5M26E7FA52FWPS6EW59Q.hello-world" --observer-socket-address 127.0.0.1:3000  --num-keys 8 --num-signers 4
```

### Extending the node's config with signer observers

Last step is to add the stackerdb replica and the observer to the node's config file.
The following command extends a given config file and creates a new file with the extra fields.


```
$ cargo run --bin stacks-signer ping extend-node-config --contract "ST3EQ88S02BXXD0T5ZVT3KW947CRMQ1C6DMQY8H19.hello-world" extended.conf original.conf 127.0.0.1:3000

```

### Running an active ping signer.

A fully functional signer is capable of participating in DKG and responding to pings. Signers are expected to initiate ping requests arbitrarily. If you want to actively request pings, utilize the `--ping-in-millis` option to ping at regular intervals.

```
$ cargo run --bin stacks-signer run --config ./new_signer-0.toml --ping-in-millis 10000
```


## Contributing

To contribute to the stacks-signer project, please read the [Contributing Guidelines](../CONTRIBUTING.md).
## License

This program is open-source software released under the terms of the GNU General Public License (GPL). You should have received a copy of the GNU General Public License along with this program.