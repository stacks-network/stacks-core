use actix_web::{web, HttpResponse, Responder};
use serde_json::json;

use crate::services::block_service;

pub async fn get_block_txids(height: web::Path<u64>) -> impl Responder {
    match block_service::fetch_nakamoto_block(height.into_inner()).await {
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

