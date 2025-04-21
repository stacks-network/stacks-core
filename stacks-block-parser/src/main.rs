use anyhow::Result;
use blockstack_lib::chainstate::nakamoto::NakamotoBlock;
use blockstack_lib::codec::read_next;
use std::io::Cursor;
use actix_web::{web, App, HttpResponse, HttpServer, Responder};
use serde::{Deserialize, Serialize};

#[derive(Debug, Serialize, Deserialize)]
struct BlockRequest {
    url: String,
}

async fn parse_block(height: web::Path<u64>) -> impl Responder {
    match parse_block_data(height.into_inner()).await {
        Ok(block) => HttpResponse::Ok().json(block),
        Err(e) => HttpResponse::BadRequest().body(format!("Error parsing block: {}", e)),
    }
}

async fn parse_block_data(height: u64) -> Result<NakamotoBlock> {
    let response = reqwest::get(&format!("https://stacks-node-api.mainnet.stacks.co/v3/blocks/height/{}", height)).await?;
    let block_bytes = response.bytes().await?;
    
    let mut cursor = Cursor::new(block_bytes);
    let block: NakamotoBlock = read_next(&mut cursor)?;
    
    Ok(block)
}

#[actix_web::main]
async fn main() -> std::io::Result<()> {
    println!("Starting server at http://127.0.0.1:8080");
    
    HttpServer::new(|| {
        App::new()
            .service(
                web::resource("/v3/blocks/height/{height}")
                    .route(web::get().to(parse_block))
            )
    })
    .bind("127.0.0.1:8080")?
    .run()
    .await
}
