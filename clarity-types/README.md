# Clarity Types (`clarity-types`)

[![License: GPLv3](https://img.shields.io/badge/License-GPLv3-blue.svg)](https://www.gnu.org/licenses/gpl-3.0)

A Rust crate for representing all core data types, errors, and serializable structures of the Stacks Clarity smart contract language.

## Overview

This crate provides the core components for working with Clarity data structures in Rust. It defines canonical Rust types for every Clarity value (e.g., `Value`, `TypeSignature`, `PrincipalData`) and implements the consensus-critical binary serialization and deserialization format used by the Stacks blockchain.

## Key Features

*   **Canonical Data Structures**: Rust representations for all Clarity types, including `int`, `uint`, `bool`, `principal`, `optional`, `response`, `tuple`, `list`, `buffer`, and strings.
*   **Consensus-Compatible Binary Codec**: Implements the binary serialization and deserialization format required by the Stacks blockchain.
*   **Type Safety**: Includes type-checking logic (`admits`, `least_supertype`) for validating values against type signatures.
*   **Canonical Errors**: The definitive enums for all static analysis, runtime, and internal errors that can occur during Clarity execution.

## Quick Start: Usage Examples

### Example 1: Serializing a Clarity Value to Hex

This example demonstrates how to construct a complex Clarity `(tuple)` and serialize it to its hexadecimal string representation, which is suitable for use as a transaction argument.

```rust
use clarity_types::types::{PrincipalData, TupleData, Value};

fn main() -> Result<(), Box<dyn std::error::Error>> {
    // 1. Construct the individual values that will go into our tuple.
    let id = Value::UInt(101);
    let owner = Value::Principal(PrincipalData::parse(
        "SM2J6ZY48GV1EZ5V2V5RB9MP66SW86PYKKQVX8X0G",
    )?);
    let metadata = Value::some(Value::buff_from(vec![0xde, 0xad, 0xbe, 0xef])?)?;

    // 2. Create a vec of name-value pairs for the tuple.
    let tuple_fields = vec![
        ("id".into(), id),
        ("owner".into(), owner),
        ("metadata".into(), metadata),
    ];

    // 3. Construct the tuple value.
    let my_tuple = Value::from(TupleData::from_data(tuple_fields)?);

    // 4. Serialize the tuple to its consensus-cricital hex string.
    let hex_string = my_tuple
        .serialize_to_hex()
        .map_err(|e| format!("Error serializing tuple to hex: {e:?}"))?;

    println!("Clarity Tuple: {my_tuple}");
    println!("Serialized Hex: {hex_string}");

    // The output `hex_string` can now be used in a contract-call transaction.
    assert_eq!(
        hex_string,
        "0c000000030269640100000000000000000000000000000065086d657461646174610a0200000004deadbeef056f776e65720514a46ff88886c2ef9762d970b4d2c63678835bd39d"
    );

    Ok(())
}
```

### Example 2: Deserializing a Clarity Value from Hex

This example shows the reverse process: taking a hex string and deserializing it into a structured `Value` object, while validating it against an expected type.

```rust
use clarity_types::types::{TypeSignature, Value};

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let hex_string = "0c000000030269640100000000000000000000000000000065086d657461646174610a0200000004deadbeef056f776e65720514a46ff88886c2ef9762d970b4d2c63678835bd39d";

    // 1. First, let's deserialize without a type for inspection.
    // NOTE: This is not recommended for production use with data from untrusted sources.
    let untyped_value = Value::try_deserialize_hex_untyped(hex_string)?;
    println!("Deserialized (untyped): {untyped_value}");

    // 2. For robust deserialization, we should define the expected type.
    // This can be derived from the untyped value or known from a contract's interface.
    let expected_type = TypeSignature::type_of(&untyped_value)?;
    println!("Inferred Type Signature: {expected_type}");

    // 3. Deserialize again, this time enforcing the type signature.
    // The `sanitize` flag should be `true` when reading values from the DB
    // that were stored before Stacks 2.4. For new values, it can be `false`.
    let typed_value = Value::try_deserialize_hex(hex_string, &expected_type, false)?;

    // 4. Now we can safely access the tuple's fields.
    let tuple_data = typed_value.expect_tuple()?;
    let id = tuple_data.get("id")?.clone().expect_u128()?;
    let owner = tuple_data.get("owner")?.clone().expect_principal()?;

    println!("Successfully deserialized and validated!");
    println!("ID: {id}");
    println!("Owner: {owner}");

    Ok(())
}
```

## Clarity Value Binary Format

The crate implements the standard binary format for Clarity values as defined in [SIP-005](https://github.com/stacksgov/sips/blob/main/sips/sip-005/sip-005-blocks-and-transactions.md#clarity-value-representation). At a high level, every value is encoded as: `[Type Prefix Byte] + [Payload]`.

| Type Prefix (Hex) | Clarity Type      | Payload Description                                                              |
| ----------------- | ----------------- | -------------------------------------------------------------------------------- |
| `0x00`            | `int`             | 16-byte big-endian signed integer.                                               |
| `0x01`            | `uint`            | 16-byte big-endian unsigned integer.                                             |
| `0x02`            | `(buff L)`        | 4-byte big-endian length `L`, followed by `L` raw bytes.                         |
| `0x03`            | `true`            | No payload.                                                                      |
| `0x04`            | `false`           | No payload.                                                                      |
| `0x05`            | `principal` (Std) | 1-byte version, followed by 20-byte HASH160.                                     |
| `0x06`            | `principal` (Cont)| Serialized Contract Principal (issuer) + 1-byte length-prefixed contract name.   |
| `0x07`            | `(ok V)`          | The serialized inner value `V`.                                                  |
| `0x08`            | `(err V)`         | The serialized inner value `V`.                                                  |
| `0x09`            | `none`            | No payload.                                                                      |
| `0x0a`            | `(some V)`        | The serialized inner value `V`.                                                  |
| `0x0b`            | `(list ...)`      | 4-byte big-endian element count, followed by each serialized element.            |
| `0x0c`            | `(tuple ...)`     | 4-byte big-endian entry count, followed by each serialized `(name, value)` pair. |
| `0x0d`            | `(string-ascii L)`| 4-byte big-endian length `L`, followed by `L` ASCII bytes.                       |
| `0x0e`            | `(string-utf8 L)` | 4-byte big-endian byte-length `L`, followed by `L` UTF8 bytes.                   |

## Crate Features

This crate is designed to be minimal by default. Optional functionality is available via feature flags:

*   `testing`: Enables helper functions and data structures used exclusively for unit and integration testing.
*   `slog_json`: Integrates with `slog` for structured JSON logging.
*   `wasm-web` / `wasm-deterministic`: Enables builds for WebAssembly environments with different determinism guarantees.

## License

This project is licensed under the **GNU General Public License v3.0** ([GPLv3](https://www.gnu.org/licenses/gpl-3.0.en.html)). See the `LICENSE` file for details.
