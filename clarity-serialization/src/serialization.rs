// Copyright (C) 2013-2020 Blockstack PBC, a public benefit corporation
// Copyright (C) 2020 Stacks Open Internet Foundation
//
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.
//
// This program is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
// GNU General Public License for more details.
//
// You should have received a copy of the GNU General Public License
// along with this program.  If not, see <http://www.gnu.org/licenses/>.

//! Core serialization functionality for Clarity values

use std::io::{Read, Write};
use std::str;

use lazy_static::lazy_static;
use stacks_common::util::hash::hex_bytes;

use crate::errors::SerializationError;
use crate::types::{Value, BOUND_VALUE_SERIALIZATION_BYTES};

lazy_static! {
    pub static ref NONE_SERIALIZATION_LEN: u64 = {
        u64::try_from(Value::none().serialize_to_vec().unwrap().len()).unwrap()
    };
}

impl Value {
    /// Serialize the value to a vector of bytes
    pub fn serialize_to_vec(&self) -> Result<Vec<u8>, SerializationError> {
        let mut buffer = Vec::new();
        self.serialize_write(&mut buffer)?;
        Ok(buffer)
    }

    /// Serialize the value to a hex string
    pub fn serialize_to_hex(&self) -> Result<String, SerializationError> {
        let bytes = self.serialize_to_vec()?;
        Ok(to_hex(&bytes))
    }

    /// Deserialize a value from a byte slice
    pub fn deserialize_from_slice(bytes: &[u8]) -> Result<Value, SerializationError> {
        let mut cursor = std::io::Cursor::new(bytes);
        Value::deserialize_read(&mut cursor, None)
    }

    /// Deserialize a value from a hex string
    pub fn deserialize_from_hex(hex_str: &str) -> Result<Value, SerializationError> {
        let bytes = hex_bytes(hex_str)
            .map_err(|e| SerializationError::InvalidFormat(e.to_string()))?;
        Value::deserialize_from_slice(&bytes)
    }

    /// Write serialized value to a writer
    pub fn serialize_write<W: Write>(&self, writer: &mut W) -> Result<(), SerializationError> {
        let json = serde_json::to_string(self)
            .map_err(|e| SerializationError::SerializationError(e.to_string()))?;
        writer.write_all(json.as_bytes())?;
        Ok(())
    }

    /// Read and deserialize value from a reader
    pub fn deserialize_read<R: Read>(
        reader: &mut R,
        _expected: Option<&crate::types::TypeSignature>,
    ) -> Result<Value, SerializationError> {
        let mut buffer = Vec::new();
        reader.read_to_end(&mut buffer)?;
        
        let json_str = str::from_utf8(&buffer)
            .map_err(|e| SerializationError::DeserializationError(e.to_string()))?;
            
        let mut deserializer = serde_json::Deserializer::from_str(json_str);
        deserializer.disable_recursion_limit();
        let deserializer = serde_stacker::Deserializer::new(&mut deserializer);
        
        serde::Deserialize::deserialize(deserializer)
            .map_err(|e| SerializationError::DeserializationError(e.to_string()))
    }

    /// Get the size of the serialized value in bytes
    pub fn serialized_byte_len(&self) -> Result<u64, SerializationError> {
        let bytes = self.serialize_to_vec()?;
        Ok(bytes.len() as u64)
    }
}

/// Convert bytes to hex string representation
pub fn to_hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{:02x}", b)).collect()
}

/// Convert hex string to bytes
pub fn from_hex(hex_str: &str) -> Result<Vec<u8>, SerializationError> {
    hex_bytes(hex_str).map_err(|e| SerializationError::InvalidFormat(e.to_string()))
}

/// Validate that a hex string represents a properly serialized value
pub fn validate_serialized_value(hex_str: &str) -> Result<(), SerializationError> {
    let _value = Value::deserialize_from_hex(hex_str)?;
    Ok(())
}

/// Check if serialized size is within bounds
pub fn check_serialization_bounds(serialized_len: u64) -> Result<(), SerializationError> {
    if serialized_len > BOUND_VALUE_SERIALIZATION_BYTES as u64 {
        return Err(SerializationError::SerializationError(
            "Serialized value exceeds maximum size".to_string(),
        ));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::types::{OptionalData, ResponseData};

    #[test]
    fn test_value_serialization_roundtrip() {
        let original = Value::UInt(42);
        let serialized = original.serialize_to_vec().unwrap();
        let deserialized = Value::deserialize_from_slice(&serialized).unwrap();
        assert_eq!(original, deserialized);
    }

    #[test]
    fn test_hex_serialization_roundtrip() {
        let original = Value::Bool(true);
        let hex = original.serialize_to_hex().unwrap();
        let deserialized = Value::deserialize_from_hex(&hex).unwrap();
        assert_eq!(original, deserialized);
    }

    #[test]
    fn test_none_value() {
        let none_val = Value::none();
        let serialized = none_val.serialize_to_vec().unwrap();
        let deserialized = Value::deserialize_from_slice(&serialized).unwrap();
        assert_eq!(none_val, deserialized);
    }

    #[test]
    fn test_serialization_bounds_check() {
        let result = check_serialization_bounds(100);
        assert!(result.is_ok());

        let result = check_serialization_bounds(BOUND_VALUE_SERIALIZATION_BYTES as u64 + 1);
        assert!(result.is_err());
    }
}