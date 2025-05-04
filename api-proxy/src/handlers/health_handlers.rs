use actix_web::{HttpResponse, Responder};
use log::{info, warn, error};
use serde_json::json;
use std::time::{SystemTime, UNIX_EPOCH};

use crate::utils::config;

/// Simple health check that returns 200 OK
pub async fn health_check() -> impl Responder {
    info!("Health check requested");
    HttpResponse::Ok().json(json!({
        "status": "ok",
        "timestamp": SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs()
    }))
}

/// Detailed health check that verifies connectivity to the Stacks node
pub async fn detailed_health_check() -> impl Responder {
    info!("Detailed health check requested");
    let node_url = config::get_node_url();
    let start_time = SystemTime::now();

    // Try to fetch the latest block to verify node connectivity
    let node_status = match reqwest::get(&format!("{}/v2/info", node_url)).await {
        Ok(response) => {
            if response.status().is_success() {
                info!("Successfully connected to Stacks node");
                "up"
            } else {
                warn!("Stacks node returned non-success status: {}", response.status());
                "degraded"
            }
        },
        Err(e) => {
            error!("Failed to connect to Stacks node: {}", e);
            "down"
        },
    };

    let response_time = SystemTime::now()
        .duration_since(start_time)
        .unwrap_or_default()
        .as_millis();

    let status = if node_status == "up" { "ok" } else { "error" };

    let health_data = json!({
        "status": status,
        "timestamp": SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs(),
        "version": env!("CARGO_PKG_VERSION"),
        "dependencies": {
            "stacks_node": {
                "status": node_status,
                "url": node_url,
                "response_time_ms": response_time
            }
        }
    });

    // Return appropriate status code based on health
    if status == "ok" {
        HttpResponse::Ok().json(health_data)
    } else {
        HttpResponse::ServiceUnavailable().json(health_data)
    }
}
