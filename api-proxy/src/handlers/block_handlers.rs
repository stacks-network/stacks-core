use actix_web::{web, HttpResponse, Responder};
use serde_json::json;

use crate::services::block_service;

pub async fn get_nakamoto_block(height: web::Path<u64>) -> impl Responder {
    match block_service::fetch_nakamoto_block(height.into_inner()).await {
        Ok(block) => {
            // Convert the block to a JSON value and transform Principal arrays to addresses
            let block_json = serde_json::to_value(&block).unwrap_or_else(|_| json!({}));
            HttpResponse::Ok().json(block_json)
        }
        Err(e) => HttpResponse::BadRequest().body(format!("Error parsing block: {}", e)),
    }
}

