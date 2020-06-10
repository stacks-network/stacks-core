use async_std::net::{TcpListener, TcpStream};
use async_std::prelude::*;
use async_std::task;
use prometheus::{Counter, Encoder, Gauge, HistogramVec, TextEncoder};
use http_types::{
    Response, 
    StatusCode, 
    Method, 
    headers,
    Request, 
    Url
};

use std::thread;

lazy_static! {
    pub static ref RPC_CALL_COUNTER: Counter = register_counter!(opts!(
        "example_http_requests_total",
        "Total number of HTTP requests made.",
        labels! {"handler" => "all",}
    ))
    .unwrap();
    pub static ref P2P_CONTROL_PLAN_MSG_SENT_COUNTER: Counter = register_counter!(opts!(
        "example_http_response_size_bytes",
        "The HTTP response sizes in bytes.",
        labels! {"handler" => "all",}
    ))
    .unwrap();
    pub static ref P2P_CONTROL_PLAN_MSG_RECEIVED_COUNTER: Counter = register_counter!(opts!(
        "example_http_response_size_bytes",
        "The HTTP response sizes in bytes.",
        labels! {"handler" => "all",}
    ))
    .unwrap();
    pub static ref P2P_DATA_PLAN_MSG_SENT_COUNTER: Counter = register_counter!(opts!(
        "example_http_response_size_bytes",
        "The HTTP response sizes in bytes.",
        labels! {"handler" => "all",}
    ))
    .unwrap();
    pub static ref P2P_DATA_PLAN_MSG_RECEIVED_COUNTER: Counter = register_counter!(opts!(
        "example_http_response_size_bytes",
        "The HTTP response sizes in bytes.",
        labels! {"handler" => "all",}
    ))
    .unwrap();
    pub static ref TXS_RECEIVED_COUNTER: Counter = register_counter!(opts!(
        "example_http_response_size_bytes",
        "The HTTP response sizes in bytes.",
        labels! {"handler" => "all",}
    ))
    .unwrap();
    pub static ref BTC_BLOCKS_RECEIVED_COUNTER: Counter = register_counter!(opts!(
        "example_http_response_size_bytes",
        "The HTTP response sizes in bytes.",
        labels! {"handler" => "all",}
    ))
    .unwrap();
    pub static ref BTC_OPS_SENT_COUNTER: Counter = register_counter!(opts!(
        "example_http_response_size_bytes",
        "The HTTP response sizes in bytes.",
        labels! {"handler" => "all",}
    ))
    .unwrap();
    pub static ref STX_BLOCKS_RECEIVED_COUNTER: Counter = register_counter!(opts!(
        "example_http_response_size_bytes",
        "The HTTP response sizes in bytes.",
        labels! {"handler" => "all",}
    ))
    .unwrap();
    pub static ref STX_BLOCKS_SENT_COUNTER: Counter = register_counter!(opts!(
        "example_http_response_size_bytes",
        "The HTTP response sizes in bytes.",
        labels! {"handler" => "all",}
    ))
    .unwrap();
    pub static ref WARNING_EMITTED_COUNTER: Counter = register_counter!(opts!(
        "example_http_response_size_bytes",
        "The HTTP response sizes in bytes.",
        labels! {"handler" => "all",}
    ))
    .unwrap();
    pub static ref ERRORS_EMITTED_COUNTER: Counter = register_counter!(opts!(
        "example_http_response_size_bytes",
        "The HTTP response sizes in bytes.",
        labels! {"handler" => "all",}
    ))
    .unwrap();
}

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
    
            task::spawn(async move {
                if let Err(err) = accept(addr, stream).await {
                    eprintln!("{}", err);
                }
            });
        }      
    });
}

async fn accept(addr: String, stream: TcpStream) -> http_types::Result<()> {
    println!("starting new connection from {}", stream.peer_addr()?);
    async_h1::accept(&addr, stream.clone(), |mut req| async {
        Ok(Response::new(StatusCode::Ok))
    }).await?;
    Ok(())
}