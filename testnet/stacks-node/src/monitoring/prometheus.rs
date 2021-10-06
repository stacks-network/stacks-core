use async_std::net::{TcpListener, TcpStream};
use async_std::prelude::*;
use async_std::task;
use stacks::prometheus::{gather, Encoder, TextEncoder};

use http_types::{Body, Response, StatusCode};

pub fn start_serving_prometheus_metrics(bind_address: String) {
    warn!("burger");
    warn!("whistle");
    let addr = bind_address.clone();

    warn!("whistle");
    async_std::task::block_on(async {
    warn!("whistle");
        let listener = TcpListener::bind(addr)
            .await
            .expect("Prometheus monitoring: unable to bind address");
        let addr = format!(
            "http://{}",
            listener
                .local_addr()
                .expect("Prometheus monitoring: unable to get addr")
        );
    warn!("whistle");
        info!("Prometheus monitoring: server listening on {}", addr);

        let mut incoming = listener.incoming();
    warn!("whistle");
        while let Some(stream) = incoming.next().await {
    warn!("whistle");
            let stream = match stream {
                Ok(stream) => stream,
                Err(err) => {
                    error!(
                        "Prometheus monitoring: unable to open socket and serve metrics - {:?}",
                        err
                    );
                    continue;
                }
            };
    warn!("whistle");
            let addr = addr.clone();

    warn!("whistle");
            task::spawn(async {
                if let Err(err) = accept(addr, stream).await {
                    eprintln!("{}", err);
                }
    warn!("whistle");
            });
        }
    });
}

async fn accept(addr: String, stream: TcpStream) -> http_types::Result<()> {
    debug!("Handle Prometheus polling ({})", stream.peer_addr()?);
    async_h1::accept(&addr, stream.clone(), |_| async {
        let encoder = TextEncoder::new();
        let metric_families = gather();
        let mut buffer = vec![];
        encoder.encode(&metric_families, &mut buffer).unwrap();

        let mut response = Response::new(StatusCode::Ok);
        response
            .append_header("Content-Type", encoder.format_type())
            .expect("Unable to set headers");
        response.set_body(Body::from(buffer));

        Ok(response)
    })
    .await?;
    Ok(())
}
