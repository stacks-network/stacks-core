# stacks-cli

A CLI for building and signing Stacks transactions and interacting with Clarity contracts.

### Features

*   **Transaction Building:**
    *   `publish`: Deploy Clarity smart contracts.
    *   `contract-call`: Call public functions on deployed contracts.
    *   `token-transfer`: Transfer STX between accounts.
*   **Key Management:**
    *   `generate-sk`: Generate a new Stacks private key.
    *   `addresses`: Derive Stacks and Bitcoin addresses from a private key.
*   **Decoding Helpers:**
    *   `decode-tx`: Decode a hex-encoded transaction.
    *   `decode-header`: Decode a hex-encoded block header.
    *   `decode-block`: Decode a hex-encoded block.
    *   `decode-microblock`: Decode a hex-encoded microblock.
    *   `decode-microblocks`: Decode a hex-encoded stream of microblocks.

### Build & Run

```bash
# Build the CLI
cargo build -p stacks-cli

# See top-level help
cargo run -p stacks-cli -- --help
```
*Note the extra `--` to pass flags to the binary instead of cargo.*

### Global Options
*   `--testnet[=<chain-id>]` - Generate a transaction for the testnet. An optional custom chain ID can be provided in hex (e.g., `--testnet=0x12345678`).

### Examples

**Note:** All arguments are positional.

```bash
# Publish a contract on testnet
cargo run -p stacks-cli -- --testnet publish <SENDER_PRIVATE_KEY> <FEE_RATE> <NONCE> <CONTRACT_NAME> <PATH_TO_CLARITY_FILE>

# Call a contract function
# Function arguments are passed using flags: -e (evaluate), -x (hex), or --hex-file
cargo run -p stacks-cli -- contract-call <SENDER_PRIVATE_KEY> <FEE_RATE> <NONCE> <CONTRACT_ADDRESS> <CONTRACT_NAME> <FUNCTION_NAME> -e "'ST1...'" -e "u100"

# Transfer STX (amount is in micro-STX, memo is optional)
cargo run -p stacks-cli -- token-transfer <SENDER_PRIVATE_KEY> <FEE_RATE> <NONCE> <RECIPIENT_ADDRESS> <AMOUNT_USTX> "my memo"

# Generate a new key and associated addresses
cargo run -p stacks-cli -- generate-sk

# Decode a hex-encoded transaction from a string or stdin
cargo run -p stacks-cli -- decode-tx <HEX_ENCODED_TRANSACTION>
```

See `--help` on each subcommand for complete options (e.g., `cargo run -p stacks-cli -- publish -h`).
