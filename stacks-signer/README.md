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

## Contributing

To contribute to the stacks-signer project, please read the [Contributing Guidelines](../CONTRIBUTING.md).
## License

This program is open-source software released under the terms of the GNU General Public License (GPL). You should have received a copy of the GNU General Public License along with this program.