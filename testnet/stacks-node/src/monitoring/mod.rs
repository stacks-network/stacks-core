#![allow(unused_variables)]

pub use stacks::monitoring::{increment_errors_emitted_counter, increment_warning_emitted_counter};

#[cfg(feature = "monitoring_prom")]
mod prometheus;

#[derive(Debug)]
pub enum MonitoringError {
    AlreadyBound,
    UnableToGetAddress,
}

#[cfg(feature = "monitoring_prom")]
pub fn start_serving_monitoring_metrics(bind_address: String) -> Result<(), MonitoringError> {
    prometheus::start_serving_prometheus_metrics(bind_address)
}

#[cfg(not(feature = "monitoring_prom"))]
pub fn start_serving_monitoring_metrics(bind_address: String) -> Result<(), MonitoringError> {
    warn!("Attempted to start monitoring service at bind_address = {bind_address}, but stacks-node was built without `monitoring_prom` feature.");
    Ok(())
}
