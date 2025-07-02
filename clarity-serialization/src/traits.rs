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


/// Trait for types that can be serialized to string representation
pub trait ClaritySerializable {
    fn serialize(&self) -> String;
}

/// Trait for types that can be deserialized from string representation
pub trait ClarityDeserializable<T> {
    fn deserialize(json: &str) -> Result<T, Box<dyn std::error::Error>>;
}

impl ClaritySerializable for String {
    fn serialize(&self) -> String {
        self.clone()
    }
}

impl ClarityDeserializable<String> for String {
    fn deserialize(serialized: &str) -> Result<String, Box<dyn std::error::Error>> {
        Ok(serialized.to_string())
    }
}

/// Macro to implement ClaritySerializable and ClarityDeserializable for types
/// that can be serialized/deserialized using serde_json
#[macro_export]
macro_rules! clarity_serializable {
    ($Name:ident) => {
        impl ClaritySerializable for $Name {
            fn serialize(&self) -> String {
                serde_json::to_string(self).expect("Failed to serialize value")
            }
        }
        impl ClarityDeserializable<$Name> for $Name {
            fn deserialize(json: &str) -> Result<Self, Box<dyn std::error::Error>> {
                let mut deserializer = serde_json::Deserializer::from_str(&json);
                // serde's default 128 depth limit can be exhausted
                //  by a 64-stack-depth AST, so disable the recursion limit
                deserializer.disable_recursion_limit();
                // use stacker to prevent the deserializer from overflowing.
                //  this will instead spill to the heap
                let deserializer = serde_stacker::Deserializer::new(&mut deserializer);
                serde::Deserialize::deserialize(deserializer)
                    .map_err(|e| Box::new(e) as Box<dyn std::error::Error>)
            }
        }
    };
}