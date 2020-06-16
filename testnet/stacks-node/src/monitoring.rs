use async_std::net::{TcpListener, TcpStream};
use async_std::prelude::*;
use async_std::task;
use stacks::prometheus::{Encoder, TextEncoder, gather};

pub use stacks::monitoring::{ERRORS_EMITTED_COUNTER, WARNING_EMITTED_COUNTER};

use http_types::{
    Response, 
    StatusCode, 
    Body,
};

pub fn start_serving_prometheus_metrics(prometheus_bind: String) {
    let addr = prometheus_bind.clone();

    async_std::task::block_on(async {
        let listener = TcpListener::bind(addr).await.expect("todo(ludo)");
        let addr = format!("http://{}", listener.local_addr().expect("todo(ludo)"));
        println!("Prometheus server listening on {}", addr);
    
        let mut incoming = listener.incoming();
        while let Some(stream) = incoming.next().await {
            let stream = stream.expect("todo(ludo)");
            let addr = addr.clone();
    
            task::spawn(async {
                if let Err(err) = accept(addr, stream).await {
                    eprintln!("{}", err);
                }
            });
        }      
    });
}

async fn accept(addr: String, stream: TcpStream) -> http_types::Result<()> {
    println!("starting new connection from {}", stream.peer_addr()?);
    async_h1::accept(&addr, stream.clone(), |_| async {
        let encoder = TextEncoder::new();    
        let metric_families = gather();
        let mut buffer = vec![];
        encoder.encode(&metric_families, &mut buffer).unwrap();

        let mut response = Response::new(StatusCode::Ok);
        response.append_header("Content-Type", encoder.format_type()).expect("Unable to set headers");
        response.set_body(Body::from(buffer));

        Ok(response)
    }).await?;
    Ok(())
}
