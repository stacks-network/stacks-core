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

use std::fmt;

/// Errors that may occur in serialization or deserialization
#[derive(Debug, PartialEq)]
pub enum SerializationError {
    IOError(String),
    DeserializationError(String),
    SerializationError(String),
    InvalidFormat(String),
    UnexpectedType(String),
    LeftoverBytesInDeserialization,
    UnexpectedSerialization,
}

impl fmt::Display for SerializationError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match self {
            SerializationError::IOError(e) => {
                write!(f, "Serialization error caused by IO: {}", e)
            }
            SerializationError::DeserializationError(e) => {
                write!(f, "Deserialization error: {}", e)
            }
            SerializationError::SerializationError(e) => {
                write!(f, "Serialization error: {}", e)
            }
            SerializationError::InvalidFormat(e) => {
                write!(f, "Invalid format error: {}", e)
            }
            SerializationError::UnexpectedType(e) => {
                write!(f, "Unexpected type error: {}", e)
            }
            SerializationError::UnexpectedSerialization => {
                write!(f, "The serializer handled an input in an unexpected way")
            }
            SerializationError::LeftoverBytesInDeserialization => {
                write!(f, "Deserialization error: bytes left over in buffer")
            }
        }
    }
}

impl std::error::Error for SerializationError {}

impl From<std::io::Error> for SerializationError {
    fn from(e: std::io::Error) -> Self {
        SerializationError::IOError(e.to_string())
    }
}

impl From<serde_json::Error> for SerializationError {
    fn from(e: serde_json::Error) -> Self {
        SerializationError::DeserializationError(e.to_string())
    }
}