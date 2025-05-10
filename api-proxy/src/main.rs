mod handlers;
mod services;
mod utils;

use actix_web::{web, App, HttpServer};
use log::info;
use env_logger::Env;

use handlers::{block_handlers, custom_handlers, health_handlers};
use utils::config;

#[actix_web::main]
async fn main() -> std::io::Result<()> {
    // Initialize logger
    env_logger::init_from_env(Env::default().default_filter_or("info"));

    let bind_address = config::get_bind_address();
    let node_url = config::get_node_url();

    info!("Starting server at http://{}", bind_address);
    info!("Using Stacks node URL: {}", node_url);

    HttpServer::new(|| {
        App::new()
            .service(web::resource("/v1/health").route(web::get().to(health_handlers::health_check)))
            .service(web::resource("/v1/health/detailed").route(web::get().to(health_handlers::detailed_health_check)))
            .service(web::resource("/v1/blocks/height/{height}/txids").route(web::get().to(custom_handlers::get_block_txids)))
            // Block endpoints
            .service(web::resource("/v1/proxy/v3/blocks/height/{height}").route(web::get().to(block_handlers::get_nakamoto_block)))
    })
    .bind(bind_address)?
    .run()
    .await
}
