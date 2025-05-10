use std::io::Cursor;

use anyhow::Result;
use blockstack_lib::chainstate::nakamoto::NakamotoBlock;
use blockstack_lib::codec::read_next;
use serde_json::{Map, Value};
use stacks_common::address::c32;

use crate::utils::config;

pub async fn fetch_nakamoto_block(height: u64) -> Result<NakamotoBlock> {
    let node_url = config::get_node_url();
    let response = reqwest::get(&format!("{}/v3/blocks/height/{}", node_url, height)).await?;
    let block_bytes = response.bytes().await?;

    let mut cursor = Cursor::new(block_bytes);
    let block: NakamotoBlock = read_next(&mut cursor)?;

    Ok(block)
}

/// Recursively transforms Principal arrays in JSON to Stacks addresses
pub fn transform_data_arrays(value: Value) -> Value {
    match value {
        Value::Object(map) => {
            // Special case: if this is a Principal object, try to convert it directly
            if map.contains_key("Principal") {
                if let Some(principal_val) = map.get("Principal") {
                    if let Some(address) = try_convert_principal_to_address(principal_val) {
                        let mut result = Map::new();
                        result.insert("type".to_string(), Value::String("principal".to_string()));
                        result.insert("value".to_string(), address);
                        return Value::Object(result);
                    }
                }
            } else if map.contains_key("UInt") {
                if let Some(uint_val) = map.get("UInt") {
                    let mut result = Map::new();
                    result.insert("type".to_string(), Value::String("uint".to_string()));
                    result.insert("value".to_string(), uint_val.clone());
                    return Value::Object(result);
                }
            } else if map.contains_key("Bool") {
                if let Some(bool_val) = map.get("Bool") {
                    let mut result = Map::new();
                    result.insert("type".to_string(), Value::String("bool".to_string()));
                    result.insert("value".to_string(), bool_val.clone());
                    return Value::Object(result);
                }
            } else if map.contains_key("Optional") {
                if let Some(opt_val) = map.get("Optional") {
                    let mut result = Map::new();
                    result.insert("type".to_string(), Value::String("optional".to_string()));
                    // Transform the inner value if it exists
                    let inner_value = if opt_val.is_null() {
                        Value::Null
                    } else {
                        let transformed = transform_data_arrays(opt_val.clone());
                        
                        // Extract optional data value
                        if let Value::Object(inner_map) = &transformed {
                            if let Some(data_val) = inner_map.get("data") {
                                data_val.clone()
                            } else {
                                transformed
                            }
                        } else {
                            transformed
                        }
                    };

                    result.insert("value".to_string(), inner_value);
                    return Value::Object(result);
                }
            }

            // Otherwise, process each key-value pair in the object
            let mut new_map = Map::new();
            for (key, val) in map {
                new_map.insert(key, transform_data_arrays(val));
            }
            Value::Object(new_map)
        }
        Value::Array(arr) => {
            // Process each value in the array
            let mut new_arr = Vec::new();
            for val in arr {
                new_arr.push(transform_data_arrays(val));
            }
            Value::Array(new_arr)
        }
        // For primitive values, return as is
        _ => value,
    }
}

/// Attempts to convert a JSON representation of a Standard Principal to a Stacks address
///
/// The expected format is a JSON object with a "Standard" field containing an array of
/// [version_number, [20 bytes as numbers]]
fn try_convert_principal_to_address(val: &Value) -> Option<Value> {
    // Check if this is a Principal object
    if !val.is_object() {
        return None;
    }

    // Try to get the Standard field
    let standard = val.get("Standard")?;

    // Check if Standard is an array with the expected format
    let array = standard.as_array()?;
    if array.len() != 2 || !array[0].is_number() || !array[1].is_array() {
        return None;
    }

    // Extract version number
    let version = array[0].as_u64().unwrap_or(0) as u8;

    // Extract bytes array
    let bytes_array = array[1].as_array()?;
    if bytes_array.len() != 20 {
        return None;
    }

    // Convert bytes array to [u8; 20]
    let mut bytes = [0u8; 20];
    for (i, byte) in bytes_array.iter().enumerate() {
        if !byte.is_number() {
            return None;
        }
        bytes[i] = byte.as_u64().unwrap_or(0) as u8;
    }

    // Convert to Stacks address
    match c32::c32_address(version, &bytes) {
        Ok(address) => Some(Value::String(address)),
        Err(_) => None,
    }
}
