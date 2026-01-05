# clarity-cli

A command-line interface for developing, testing, and debugging Clarity smart contracts locally without needing a full Stacks node.

## Build

```bash
cargo build --release -p clarity-cli
```

The binary will be at `./target/release/clarity-cli`.

## Overview

clarity-cli provides a local VM environment for Clarity contract development. It maintains a persistent database that simulates blockchain state, allowing you to:

- Initialize a local VM with boot contracts
- Type-check contracts before deployment
- Deploy ("launch") contracts to the local state
- Execute public functions on deployed contracts
- Evaluate Clarity expressions in various contexts

All commands output JSON for easy parsing and integration with other tools.

## Commands

### `initialize`

Create and initialize a new local VM state database with boot contracts.

```bash
clarity-cli initialize [OPTIONS] <DB_PATH> [ALLOCATIONS_FILE]
```

**Arguments:**
- `DB_PATH` - Directory path for the VM state database
- `ALLOCATIONS_FILE` - Optional JSON file with initial STX allocations (or `-` for stdin)

**Options:**
- `--testnet` - Use testnet boot code and block limits (default: mainnet)
- `--epoch <EPOCH>` - Stacks epoch to use (default: 3.3)

**Example:**
```bash
# Initialize mainnet database
clarity-cli initialize ./my-db

# Initialize testnet with allocations
clarity-cli initialize --testnet ./my-db allocations.json
```

**Allocations JSON format:**
```json
[
  { "principal": "ST1PQHQKV0RJXZFY1DGX8MNSNYVE3VGZJSRTPGZGM", "amount": 1000000 },
  { "principal": "ST1PQHQKV0RJXZFY1DGX8MNSNYVE3VGZJSRTPGZGM.my-contract", "amount": 500000 }
]
```

---

### `generate-address`

Generate a random Stacks address for testing.

```bash
clarity-cli generate-address
```

**Example output:**
```json
{"address": "ST2CY5V39NHDPWSXMW9QDT3HC3GD6Q6XX4CFRK9AG"}
```

---

### `check`

Type-check a Clarity contract without deploying it.

```bash
clarity-cli check [OPTIONS] <CONTRACT_FILE> [DB_PATH]
```

**Arguments:**
- `CONTRACT_FILE` - Path to `.clar` file (or `-` for stdin)
- `DB_PATH` - Optional database path for resolving contract dependencies

**Options:**
- `--contract-id <ID>` - Contract identifier (default: transient)
- `--output-analysis` - Include contract interface analysis in output
- `--costs` - Include execution costs in output
- `--testnet` - Use testnet configuration
- `--clarity-version <VERSION>` - Clarity version (e.g., `clarity1`, `clarity2`, `clarity3`, `clarity4`)
- `--epoch <EPOCH>` - Stacks epoch (e.g., `2.1`, `2.5`, `3.0`)

**Example:**
```bash
# Basic type check
clarity-cli check my-contract.clar

# Check with cost analysis
clarity-cli check --costs --output-analysis my-contract.clar

# Check against existing database (resolves contract-call? references)
clarity-cli check my-contract.clar ./my-db

# Read from stdin
cat my-contract.clar | clarity-cli check -
```

---

### `launch`

Deploy a contract to the local VM state database.

```bash
clarity-cli launch [OPTIONS] <CONTRACT_ID> <CONTRACT_FILE> <DB_PATH>
```

**Arguments:**
- `CONTRACT_ID` - Fully qualified contract identifier (e.g., `ST1PQHQ...PGZGM.my-contract`)
- `CONTRACT_FILE` - Path to `.clar` file (or `-` for stdin)
- `DB_PATH` - Database path (must be initialized first)

**Options:**
- `--costs` - Include execution costs in output
- `--assets` - Include asset changes in output
- `--output-analysis` - Include contract interface analysis
- `--clarity-version <VERSION>` - Clarity version
- `--epoch <EPOCH>` - Stacks epoch

**Example:**
```bash
# Deploy a contract
clarity-cli launch ST1PQHQKV0RJXZFY1DGX8MNSNYVE3VGZJSRTPGZGM.tokens \
  tokens.clar ./my-db

# Deploy with full output
clarity-cli launch --costs --assets --output-analysis \
  ST1PQHQKV0RJXZFY1DGX8MNSNYVE3VGZJSRTPGZGM.tokens tokens.clar ./my-db
```

---

### `execute`

Execute a public function on a deployed contract.

```bash
clarity-cli execute [OPTIONS] <CONTRACT_ID> <FUNCTION_NAME> <SENDER> <DB_PATH> [ARGS]...
```

**Arguments:**
- `CONTRACT_ID` - Contract identifier
- `FUNCTION_NAME` - Public function name to call
- `SENDER` - Sender principal address (becomes `tx-sender`)
- `DB_PATH` - Database path
- `ARGS` - Function arguments as Clarity literals

**Options:**
- `--costs` - Include execution costs
- `--assets` - Include asset changes
- `--clarity-version <VERSION>` - Clarity version
- `--epoch <EPOCH>` - Stacks epoch

**Example:**
```bash
# Call a function with no arguments
clarity-cli execute ST1PQHQ...PGZGM.tokens get-balance \
  ST1PQHQKV0RJXZFY1DGX8MNSNYVE3VGZJSRTPGZGM ./my-db

# Call with arguments
clarity-cli execute ST1PQHQ...PGZGM.tokens transfer \
  ST1PQHQKV0RJXZFY1DGX8MNSNYVE3VGZJSRTPGZGM ./my-db \
  u100 \
  'ST2CY5V39NHDPWSXMW9QDT3HC3GD6Q6XX4CFRK9AG

# Note: Principal arguments need the Clarity quote prefix (')
```

---

### `eval`

Evaluate a Clarity expression in read-only mode within a contract's context. Advances to a new block.

```bash
clarity-cli eval [OPTIONS] <CONTRACT_ID> <DB_PATH> [PROGRAM_FILE]
```

**Arguments:**
- `CONTRACT_ID` - Contract context for evaluation
- `DB_PATH` - Database path
- `PROGRAM_FILE` - File with Clarity code (or `-` for stdin; omit for stdin)

**Options:**
- `--costs` - Include execution costs
- `--clarity-version <VERSION>` - Clarity version
- `--epoch <EPOCH>` - Stacks epoch

**Example:**
```bash
# Evaluate from file
clarity-cli eval ST1PQHQ...PGZGM.tokens ./my-db query.clar

# Evaluate from stdin
echo "(+ 1 2)" | clarity-cli eval ST1PQHQ...PGZGM.tokens ./my-db
```

---

### `eval-at-chaintip`

Like `eval`, but does **not** advance to a new block. Useful for repeated read-only queries.

```bash
clarity-cli eval-at-chaintip [OPTIONS] <CONTRACT_ID> <DB_PATH> [PROGRAM_FILE]
```

**Options:** Same as `eval`.

---

### `eval-at-block`

Evaluate at a specific historical block identified by its index block hash.

```bash
clarity-cli eval-at-block [OPTIONS] <INDEX_BLOCK_HASH> <CONTRACT_ID> <VM_DIR> [PROGRAM_FILE]
```

**Arguments:**
- `INDEX_BLOCK_HASH` - Block hash (hex string, e.g., `0x1234...`)
- `CONTRACT_ID` - Contract context
- `VM_DIR` - VM/clarity directory path
- `PROGRAM_FILE` - File with Clarity code (or `-` for stdin; omit for stdin)

**Options:**
- `--costs` - Include execution costs
- `--clarity-version <VERSION>` - Clarity version
- `--epoch <EPOCH>` - Stacks epoch

---

### `eval-raw`

Evaluate a Clarity expression without any contract or database context. Useful for quick calculations.

```bash
clarity-cli eval-raw [OPTIONS] [PROGRAM_FILE]
```

**Arguments:**
- `PROGRAM_FILE` - File with Clarity code (or `-` for stdin; omit for stdin)

**Options:**
- `--testnet` - Use testnet configuration
- `--clarity-version <VERSION>` - Clarity version
- `--epoch <EPOCH>` - Stacks epoch

**Example:**
```bash
# Quick calculation
echo "(+ 1 2)" | clarity-cli eval-raw

# From file
clarity-cli eval-raw expression.clar
```

---

### `repl`

Start an interactive REPL (Read-Eval-Print Loop) for Clarity expressions.

```bash
clarity-cli repl [OPTIONS]
```

**Options:**
- `--testnet` - Use testnet configuration
- `--clarity-version <VERSION>` - Clarity version
- `--epoch <EPOCH>` - Stacks epoch

**Example:**
```bash
clarity-cli repl --clarity-version clarity3
> (+ 1 2)
3
> (define-data-var counter uint u0)
true
> (var-set counter u10)
true
> (var-get counter)
u10
```

---

## Typical Workflow

```bash
# 1. Initialize database
clarity-cli initialize ./my-db

# 2. Check your contract
clarity-cli check my-contract.clar ./my-db

# 3. Deploy contract
clarity-cli launch ST1PQHQKV0RJXZFY1DGX8MNSNYVE3VGZJSRTPGZGM.my-contract \
  my-contract.clar ./my-db

# 4. Execute functions
clarity-cli execute ST1PQHQKV0RJXZFY1DGX8MNSNYVE3VGZJSRTPGZGM.my-contract \
  my-function ST1PQHQKV0RJXZFY1DGX8MNSNYVE3VGZJSRTPGZGM ./my-db u42

# 5. Query state
echo "(contract-call? .my-contract get-value)" | \
  clarity-cli eval-at-chaintip ST1PQHQKV0RJXZFY1DGX8MNSNYVE3VGZJSRTPGZGM.my-contract ./my-db
```

## Epoch and Clarity Version

The CLI defaults to Epoch 3.3 with Clarity 4. You can specify earlier epochs/versions for compatibility testing.

**Valid epoch values:** `1.0`, `2.0`, `2.05`, `2.1`, `2.2`, `2.3`, `2.4`, `2.5`, `3.0`, `3.1`, `3.2`, `3.3`

**Valid clarity version values:** `clarity1`, `clarity2`, `clarity3`, `clarity4`

| Epoch | Default Clarity Version |
|-------|------------------------|
| 2.0   | Clarity 1              |
| 2.05  | Clarity 1              |
| 2.1   | Clarity 2              |
| 2.2   | Clarity 2              |
| 2.3   | Clarity 2              |
| 2.4   | Clarity 2              |
| 2.5   | Clarity 2              |
| 3.0   | Clarity 3              |
| 3.1   | Clarity 3              |
| 3.2   | Clarity 3              |
| 3.3   | Clarity 4              |

See `clarity/src/vm/version.rs` for Clarity version definitions and `stacks-common/src/types/mod.rs` for epoch definitions.

## Exit Codes

- `0` - Success
- `1` - Error (check JSON output for details)

## JSON Output

All commands output JSON to stdout. Errors are also returned as JSON with an `"error"` field. Use `--costs` and `--assets` flags to include additional information in the output.
