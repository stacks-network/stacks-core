# Clarity Serialization

A lightweight serialization component for Clarity values, extracted from the main Clarity VM to provide core serialization/deserialization functionality without heavy dependencies.

## Overview

This crate provides the essential types and functions needed to serialize and deserialize Clarity values, without requiring the full Clarity VM with its database dependencies like rusqlite.

## Features

- **Lightweight**: Only includes serialization-related code and minimal dependencies
- **Core Types**: Includes all essential Clarity value types (Int, UInt, Bool, Sequence, Principal, Tuple, Optional, Response, CallableContract)
- **Serialization Traits**: Provides `ClaritySerializable` and `ClarityDeserializable` traits for custom types
- **Multiple Formats**: Supports both binary and hex string serialization
- **Type Safety**: Maintains the same type safety guarantees as the full Clarity crate

## Usage

```rust
use clarity_serialization::{Value, ClaritySerializable};

// Create a value
let value = Value::UInt(42);

// Serialize to bytes
let bytes = value.serialize_to_vec()?;

// Serialize to hex string  
let hex = value.serialize_to_hex()?;

// Deserialize from bytes
let restored = Value::deserialize_from_slice(&bytes)?;

// Deserialize from hex
let restored = Value::deserialize_from_hex(&hex)?;

assert_eq!(value, restored);
```

## Custom Serialization

For custom types, use the `clarity_serializable!` macro:

```rust
use clarity_serialization::{clarity_serializable, ClaritySerializable};

#[derive(Serialize, Deserialize)]
struct MyType {
    data: String,
}

clarity_serializable!(MyType);

let my_value = MyType { data: "test".to_string() };
let serialized = my_value.serialize();
```

## Dependencies

This crate has minimal dependencies compared to the full Clarity crate:
- `serde` and `serde_json` for JSON serialization
- `stacks_common` for basic utilities (without rusqlite features)
- Standard library components

## Motivation

The original `clarity` crate includes the full Clarity VM with heavy dependencies like rusqlite, making it difficult for downstream applications that only need serialization functionality. This lightweight crate solves that by providing just the core serialization components.

## Compatibility

This crate maintains full compatibility with values serialized by the main Clarity crate, ensuring seamless interoperability.