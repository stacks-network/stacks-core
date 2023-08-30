# stacks-signer: Stacks Signer CLI

stacks-signer is a command-line interface (CLI) for executing DKG (Distributed Key Generation) rounds, signing transactions and blocks, and more within the Stacks blockchain ecosystem. This tool provides various subcommands to interact with the StackerDB, perform cryptographic operations, and manage configurations.

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

### Configuration

You can provide configuration options such as the host, contract, and private key using a TOML file. Use the `--config` option to specify the path to the configuration file. Alternatively, you can provide the necessary options directly in the command line.

```bash
./stacks-signer --config <config_file>
```

- `--config`: Path to the TOML configuration file.

## Usage

The stacks-signer CLI provides the following subcommands:

### `get-chunk`

Retrieve a chunk from the StackerDB instance.

```bash
./stacks-signer --config <config_file> get-chunk --slot_id <slot_id> --slot_version <slot_version>
```

- `--host`: The stacks node host to connect to. Required if not using the --config option.
- `--contract`: The contract ID of the StackerDB instance. Required if not using the --config option.
- `--slot_id`: The slot ID to get.
- `--slot_version`: The slot version to get.

### `get-latest-chunk`

Retrieve the latest chunk from the StackerDB instance.

```bash
./stacks-signer --config <config_file> get-latest-chunk --slot_id <slot_id>
```

- `--host`: The stacks node host to connect to. Required if not using the --config option.
- `--contract`: The contract ID of the StackerDB instance. Required if not using the --config option.
- `--slot_id`: The slot ID to get.

### `list-chunks`

List chunks from the StackerDB instance.

```bash
./stacks-signer --config <config_file> list-chunks
```

- `--host`: The stacks node host to connect to. Required if not using the --config option.
- `--contract`: The contract ID of the StackerDB instance. Required if not using the --config option.

### `put-chunk`

Upload a chunk to the StackerDB instance.

```bash
./stacks-signer --config <config_file> put-chunk --slot_id <slot_id> --slot_version <slot_version> [--data <data>]
```

- `--host`: The stacks node host to connect to. Required if not using the --config option.
- `--contract`: The contract ID of the StackerDB instance. Required if not using the --config option.
- `--slot_id`: The slot ID to get.
- `--slot_version`: The slot version to get.
- `--data`: The data to upload. If you wish to pipe data using STDIN, use with '-'.

## License

This program is open-source software released under the terms of the GNU General Public License (GPL). You should have received a copy of the GNU General Public License along with this program.