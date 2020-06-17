pub use stacks::monitoring::{
    increment_warning_emitted_counter, 
    increment_errors_emitted_counter
};

#[cfg(feature = "prometheus")]
mod prometheus;

pub fn start_serving_monitoring_metrics(bind_address: String) {
    #[cfg(feature = "prometheus")]
    prometheus::start_serving_prometheus_metrics(bind_address);
}