# stacks-signer: Stacks Signer CLI

stacks-signer is a command-line interface (CLI) for operating a Stacks compliant signer. This tool provides various subcommands to interact with the StackerDB contract, generate SIP voting and stacking signatures, and monitoring the Signer network for expected behaviour.

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

4. **Build with Prometheus Metrics Enabled**: You can optionally build and run the stacks-signer with monitoring metrics enabled.

   ```bash
   cd stacks-signer
   cargo build --release --features "monitoring_prom"
   cargo run --features "monitoring_prom" -p stacks-signer run --config <config_file>
   ```

You must specify the "metrics_endpoint" option in the config file to serve these metrics.
See [metrics documentation](TODO) for a complete breakdown of the available metrics.

## Usage

The stacks-signer CLI provides the following subcommands:

### `run`

Start the signer and handle requests to sign Stacks block proposals.

```bash
./stacks-signer run --config <config_file>

```

### `monitor-signers`

Periodically query the current reward cycle's signers' StackerDB slots to verify their operation.

```bash
./stacks-signer monitor-signers --host <host> --interval <interval> --max-age <max_age>

```
- `--host`: The Stacks node to connect to.
- `--interval`: The polling interval in seconds for querying stackerDB.
- `--max-age`: The max age in seconds before a signer message is considered stale. 

### `generate-stacking-signature`

Generate a signature for stacking.

```bash
./stacks-signer generate-stacking-signature --config <config_file> --pox-address <address> --reward-cycle <cycle> --period <period> --max-amount <max_amount> --auth-id <auth_id>

```
- `--config`: The path to the signer configuration file.
- `--pox-address`: The BTC address used to receive rewards
- `--reward-cycle`: The reward cycle during which this signature is used
- `--method`: Stacking metod that can be used
- `--period`: Number of cycles used as a lock period. Use `1` for stack-aggregation-commit method
- `--max-amount`: The max amount of uSTX that can be used in this unique transaction
- `--auth-id`: A unique identifier to prevent re-using this authorization
- `--json`: Output information in JSON format

### `generate-vote`

Generate a vote signature for a specific SIP

```bash
./stacks-signer generate-vote --config <config_file> --vote <yes|no> --sip <sip_number>

```
- `--config`: The path to the signer configuration file.
- `--vote`: The vote (YES or NO)
- `--sip`: the number of the SIP being voted on

### `verify-vote`

Verify the validity of a vote signature for a specific SIP.

```bash
./stacks-signer verify-vote --public-key <public_key> --signature <signature> --vote <yes|no> --sip <sip_number>

```
- `--public-key`: The stacks public key to verify against in hexadecimal format
- `--signature`: The message signature in hexadecimal format
- `--vote`: The vote (YES or NO)
- `--sip`: the number of the SIP being voted on

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

## Contributing

To contribute to the stacks-signer project, please read the [Contributing Guidelines](../CONTRIBUTING.md).

## License

This program is open-source software released under the terms of the GNU General Public License (GPL). You should have received a copy of the GNU General Public License along with this program.