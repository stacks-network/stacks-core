mod handlers;
mod services;
mod utils;

use actix_web::{web, App, HttpServer};

use handlers::{block_handlers, custom_handlers, health_handlers};
use utils::config;

#[actix_web::main]
async fn main() -> std::io::Result<()> {
    config::load_env();
    
    let bind_address = config::get_bind_address();
    
    println!("Starting server at http://{}", bind_address);
    println!("Using Stacks node URL: {}", config::get_node_url());

    HttpServer::new(|| {
        App::new()
            // Health check endpoints
            .service(web::resource("/health").route(web::get().to(health_handlers::health_check)))
            .service(web::resource("/health/detailed").route(web::get().to(health_handlers::detailed_health_check)))
            // Block endpoints
            .service(web::resource("/v3/blocks/height/{height}").route(web::get().to(block_handlers::get_nakamoto_block)))
            // Custom endpoints
            .service(web::resource("/_custom/v1/blocks/height/{height}/txids").route(web::get().to(custom_handlers::get_block_txids)))
    })
    .bind(bind_address)?
    .run()
    .await
}
