use async_std::net::{TcpListener, TcpStream};
use async_std::prelude::*;
use async_std::task;
use http_types::{Body, Response, StatusCode};
use stacks::prometheus::{gather, Encoder, TextEncoder};

use super::MonitoringError;

pub fn start_serving_prometheus_metrics(bind_address: String) -> Result<(), MonitoringError> {
    task::block_on(async {
        let listener = TcpListener::bind(bind_address)
            .await
            .map_err(|_| {
                warn!("Prometheus monitoring: unable to bind address, will not spawn prometheus endpoint service.");
                MonitoringError::AlreadyBound
            })?;
        let local_addr = listener
                .local_addr()
                .map_err(|_| {
                    warn!("Prometheus monitoring: unable to get local bind address, will not spawn prometheus endpoint service.");
                    MonitoringError::UnableToGetAddress
                })?;
        info!(
            "Prometheus monitoring: server listening on http://{}",
            local_addr
        );

        let mut incoming = listener.incoming();
        while let Some(stream) = incoming.next().await {
            let stream = match stream {
                Ok(stream) => stream,
                Err(err) => {
                    error!(
                        "Prometheus monitoring: unable to open socket and serve metrics - {err:?}",
                    );
                    continue;
                }
            };
            task::spawn(async {
                if let Err(err) = accept(stream).await {
                    error!("{err}");
                }
            });
        }

        Ok::<_, MonitoringError>(())
    })
}

async fn accept(stream: TcpStream) -> http_types::Result<()> {
    debug!("Handle Prometheus polling ({})", stream.peer_addr()?);
    async_h1::accept(stream.clone(), |_| async {
        let encoder = TextEncoder::new();
        let metric_families = gather();
        let mut buffer = vec![];
        encoder.encode(&metric_families, &mut buffer).unwrap();

        let mut response = Response::new(StatusCode::Ok);
        response.append_header("Content-Type", encoder.format_type());
        response.set_body(Body::from(buffer));

        Ok(response)
    })
    .await?;
    Ok(())
}
