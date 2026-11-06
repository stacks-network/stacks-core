use lazy_static::lazy_static;
use stacks::prometheus::{gather, opts, register_int_gauge, Encoder, IntGauge, TextEncoder};
use stacks_common::monitoring::build_info_labels;
use tiny_http::{Header, Request, Response, Server};

use super::MonitoringError;

lazy_static! {
    static ref BUILD_INFO: IntGauge = register_int_gauge!(opts!(
        "stacks_build_info",
        "Build information for the Stacks process."
    )
    .const_labels(build_info_labels(crate::version())))
    .unwrap();
}

/// Record the process build information. Repeated calls keep the same series at 1.
fn record_build_info() {
    BUILD_INFO.set(1);
}

pub fn start_serving_prometheus_metrics(bind_address: String) -> Result<(), MonitoringError> {
    record_build_info();
    let server = Server::http(bind_address).map_err(|_| {
        warn!("Prometheus monitoring: unable to bind address, will not spawn prometheus endpoint service.");
        MonitoringError::AlreadyBound
    })?;
    let local_addr = server.server_addr().to_ip().ok_or_else(|| {
        warn!("Prometheus monitoring: unable to get local bind address, will not spawn prometheus endpoint service.");
        MonitoringError::UnableToGetAddress
    })?;
    info!("Prometheus monitoring: server listening on http://{local_addr}");

    loop {
        let request = match server.recv() {
            Ok(request) => request,
            Err(err) => {
                error!("Prometheus monitoring: unable to open socket and serve metrics - {err:?}");
                continue;
            }
        };
        if let Err(err) = respond_with_metrics(request) {
            error!("Prometheus monitoring: failed to send metrics response - {err:?}");
        }
    }
}

/// Every request is answered with the encoded metrics, regardless of path.
fn respond_with_metrics(request: Request) -> std::io::Result<()> {
    debug!("Handle Prometheus polling ({:?})", request.remote_addr());
    let encoder = TextEncoder::new();
    let metric_families = gather();
    let mut buffer = vec![];
    encoder.encode(&metric_families, &mut buffer).unwrap();

    let content_type = Header::from_bytes("Content-Type", encoder.format_type())
        .expect("FATAL: invalid Content-Type header");
    request.respond(Response::from_data(buffer).with_header(content_type))
}
