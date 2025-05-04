use std::env;
use std::io::Cursor;

use actix_web::{web, App, HttpResponse, HttpServer, Responder};
use anyhow::Result;
use blockstack_lib::chainstate::nakamoto::NakamotoBlock;
use blockstack_lib::codec::read_next;
use serde::{Deserialize, Serialize};
use serde_json::{json, Map, Value};
use stacks_common::address::c32;

#[derive(Debug, Serialize, Deserialize)]
struct BlockRequest {
    url: String,
}

// Add this function to get the node URL from environment variables
fn get_node_url() -> String {
    env::var("STACKS_NODE_URL")
        .unwrap_or_else(|_| "https://stacks-node-api.mainnet.stacks.co".to_string())
}

async fn fetch_nakamoto_block(height: u64) -> Result<NakamotoBlock> {
    let node_url = get_node_url();
    let response = reqwest::get(&format!(
        "{}/v3/blocks/height/{}",
        node_url, height
    ))
    .await?;
    let block_bytes = response.bytes().await?;

    let mut cursor = Cursor::new(block_bytes);
    let block: NakamotoBlock = read_next(&mut cursor)?;

    Ok(block)
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

/// Recursively transforms Principal arrays in JSON to Stacks addresses
fn transform_principal_arrays(value: Value) -> Value {
    match value {
        Value::Object(map) => {
            // Special case: if this is a Principal object, try to convert it directly
            if map.contains_key("Principal") {
                if let Some(principal_val) = map.get("Principal") {
                    if let Some(address) = try_convert_principal_to_address(principal_val) {
                        return address;
                    }
                }
            }

            // Otherwise, process each key-value pair in the object
            let mut new_map = Map::new();
            for (key, val) in map {
                new_map.insert(key, transform_principal_arrays(val));
            }
            Value::Object(new_map)
        }
        Value::Array(arr) => {
            // Process each value in the array
            let mut new_arr = Vec::new();
            for val in arr {
                new_arr.push(transform_principal_arrays(val));
            }
            Value::Array(new_arr)
        }
        // For primitive values, return as is
        _ => value,
    }
}

async fn handler_get_nakamoto_block(height: web::Path<u64>) -> impl Responder {
    match fetch_nakamoto_block(height.into_inner()).await {
        Ok(block) => {
            // Convert the block to a JSON value and transform Principal arrays to addresses
            let block_json = serde_json::to_value(&block).unwrap_or_else(|_| json!({}));
            let transformed_json = transform_principal_arrays(block_json);
            let response = json!({ "block": transformed_json });
            HttpResponse::Ok().json(response)
        }
        Err(e) => HttpResponse::BadRequest().body(format!("Error parsing block: {}", e)),
    }
}

async fn handler_get_block_txids(height: web::Path<u64>) -> impl Responder {
    match fetch_nakamoto_block(height.into_inner()).await {
        Ok(block) => {
            // Extract transaction IDs from the block
            let tx_ids = block
                .txs
                .iter()
                .map(|tx| tx.txid().to_string())
                .collect::<Vec<_>>();
            let response = json!({ "txids": tx_ids });
            HttpResponse::Ok().json(response)
        }
        Err(e) => HttpResponse::BadRequest().body(format!("Error parsing block: {}", e)),
    }
}

#[actix_web::main]
async fn main() -> std::io::Result<()> {
    // Load environment variables from .env file in the package directory
    let env_path = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join(".env");
    // Print env_path for debugging
    println!("Loading environment variables from: {:?}", env_path);
    dotenv::from_path(env_path).ok();
    
    let bind_address = env::var("BIND_ADDRESS")
        .unwrap_or_else(|_| "127.0.0.1:8080".to_string());
    
    println!("Starting server at http://{}", bind_address);
    println!("Using Stacks node URL: {}", get_node_url());

    HttpServer::new(|| {
        App::new()
            .service(web::resource("/v3/blocks/height/{height}").route(web::get().to(handler_get_nakamoto_block)))
            .service(web::resource("/_custom/v1/blocks/height/{height}/txids").route(web::get().to(handler_get_block_txids)))
    })
    .bind(bind_address)?
    .run()
    .await
}
