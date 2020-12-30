#![allow(unused_variables)]

pub use stacks::monitoring::{increment_errors_emitted_counter, increment_warning_emitted_counter};

#[cfg(feature = "monitoring_prom")]
mod prometheus;

pub fn start_serving_monitoring_metrics(bind_address: String) {
    info!("Start serving prometheus metrics");
    #[cfg(feature = "monitoring_prom")]
    prometheus::start_serving_prometheus_metrics(bind_address);
}
