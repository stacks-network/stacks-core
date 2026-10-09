# stacks-signer: Stacks Signer CLI

stacks-signer is a command-line interface (CLI) for operating a Stacks compliant signer. This tool provides various subcommands to interact with the StackerDB contract, generate SIP voting and stacking signatures, and monitoring the Signer network for expected behaviour.

## Installation

To use stacks-signer, you need to build and install the Rust program. You can do this by following these steps:

1. **Clone the Repository**: Clone the stacks-core repository, which contains stacks-signer, from [GitHub](https://github.com/stacks-network/stacks-core).

   ```bash
   git clone https://github.com/stacks-network/stacks-core.git
   ```

2. **Build the Program**: Change to the stacks-signer directory and build the program using `cargo`.

   ```bash
   cd stacks-core/stacks-signer
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

| Command | Description |
|---|---|
| [`run`](#run) | Start the signer and sign Stacks block proposals |
| [`check-config`](#check-config) | Check a config file and print its settings |
| [`monitor-signers`](#monitor-signers) | Check that the signers' StackerDB slots are kept up to date |
| [`prune-db`](#prune-db) | Prune the signer database and compact its file, with the signer stopped |
| [`generate-staking-signature`](#generate-staking-signature) | Generate a PoX-5 signer grant signature for staking |
| [`generate-vote`](#generate-vote) | Generate a vote signature for a SIP |
| [`verify-vote`](#verify-vote) | Verify a vote signature for a SIP |
| [`get-chunk`](#get-chunk) | Get a chunk from a StackerDB instance |
| [`get-latest-chunk`](#get-latest-chunk) | Get the latest chunk from a StackerDB instance |
| [`list-chunks`](#list-chunks) | List the chunks of a StackerDB instance |
| [`put-chunk`](#put-chunk) | Upload a chunk to a StackerDB instance |

### `run`

Start the signer and handle requests to sign Stacks block proposals.

```bash
./stacks-signer run --config <config_file>

```

### `check-config`

Check that a signer config file loads, and print the signer version and the resulting settings.

```bash
./stacks-signer check-config --config <config_file>

```
- `--config`: The path to the signer configuration file.

### `monitor-signers`

Periodically query the current reward cycle's signers' StackerDB slots to verify their operation.

```bash
./stacks-signer monitor-signers --host <host> --interval <interval> --max-age <max_age>

```
- `--host`: The Stacks node to connect to.
- `--interval`: The polling interval in seconds for querying stackerDB.
- `--max-age`: The max age in seconds before a signer message is considered stale. 

### `prune-db`

Prune the signer database and compact its file, with the signer stopped. The running signer
prunes its database in small batches, but a database file never gets smaller on its own: freed
space is reused, not returned to the OS. This command removes everything the signer would prune,
at full speed, then rebuilds the file in place with only its live data.

```bash
./stacks-signer prune-db --config <config_file>

```
- `--config`: The signer config; the database is its `db_path`.
- `--db-path`: The database to use instead of the config's `db_path`. The command changes the
  database in place: to keep the original, copy it and run the command on the copy.
- `--temp-dir`: Where to build the temporary copy of the live data while compacting, e.g. on
  another disk. By default it is kept in memory when the live data is small enough.
- `--no-vacuum`: Prune only, without compacting.
- `--batch-size`: Blocks removed per transaction (default 1000).
- `--dry-run`: Report the database's size and where pruning would start, and change nothing.

Notes:
- The command refuses to run while the signer, or any other process, has the database open. Keep
  the signer stopped until it finishes.
- Compacting needs about the database's live data (a few hundred MB once pruned) free next to the
  database, and as much again in memory or in `--temp-dir`. It does not need the size of the file.
- An interrupted run leaves a consistent database; running it again continues.

### `generate-staking-signature`

Generate a PoX-5 signer grant signature for staking.

```bash
./stacks-signer generate-staking-signature --config <config_file> --signer-manager <signer_manager_principal> --auth-id <auth_id>

```
- `--config`: The path to the signer configuration file.
- `--signer-manager`: The signer-manager principal authorized to register this signer key
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
