use async_std::net::{TcpListener, TcpStream};
use async_std::prelude::*;
use async_std::task;
use prometheus::{Counter, Encoder, Gauge, HistogramVec, TextEncoder};
use http_types::{
    Response, 
    StatusCode, 
    Body,
};

lazy_static! {
    pub static ref RPC_CALL_COUNTER: Counter = register_counter!(opts!(
        "stacks_node_rpc_requests_total",
        "Total number of RPC requests made.",
        labels! {"handler" => "all",}
    ))
    .unwrap();
    pub static ref P2P_CONTROL_PLAN_MSG_SENT_COUNTER: Counter = register_counter!(opts!(
        "stacks_node_p2p_control_plan_msg_sent_total",
        "Total number of messages sent to p2p control plan.",
        labels! {"handler" => "all",}
    ))
    .unwrap();
    pub static ref P2P_CONTROL_PLAN_MSG_RECEIVED_COUNTER: Counter = register_counter!(opts!(
        "stacks_node_p2p_control_plan_msg_received_total",
        "Total number of messages received from p2p control plan.",
        labels! {"handler" => "all",}
    ))
    .unwrap();
    pub static ref P2P_DATA_PLAN_MSG_SENT_COUNTER: Counter = register_counter!(opts!(
        "stacks_node_p2p_data_plan_msg_sent_total",
        "Total number of messages sent to p2p data plan.",
        labels! {"handler" => "all",}
    ))
    .unwrap();
    pub static ref P2P_DATA_PLAN_MSG_RECEIVED_COUNTER: Counter = register_counter!(opts!(
        "stacks_node_p2p_data_plan_msg_received_total",
        "Total number of messages received from p2p data plan.",
        labels! {"handler" => "all",}
    ))
    .unwrap();
    pub static ref TXS_RECEIVED_COUNTER: Counter = register_counter!(opts!(
        "stacks_node_transactions_received_total",
        "Total number of transactions received and relayed.",
        labels! {"handler" => "all",}
    ))
    .unwrap();
    pub static ref BTC_BLOCKS_RECEIVED_COUNTER: Counter = register_counter!(opts!(
        "stacks_node_btc_blocks_received_total",
        "Total number of blocks processed from the burnchain.",
        labels! {"handler" => "all",}
    ))
    .unwrap();
    pub static ref BTC_OPS_SENT_COUNTER: Counter = register_counter!(opts!(
        "stacks_node_btc_ops_sent_total",
        "Total number of ops (key registrations, block commits, user burn supports) submitted to the burnchain.",
        labels! {"handler" => "all",}
    ))
    .unwrap();
    pub static ref STX_BLOCKS_PROCESSED_COUNTER: Counter = register_counter!(opts!(
        "stacks_node_stx_blocks_processed_total",
        "Total number of stacks blocks processed.",
        labels! {"handler" => "all",}
    ))
    .unwrap();
    pub static ref STX_BLOCKS_MINED_COUNTER: Counter = register_counter!(opts!(
        "stacks_node_stx_blocks_mined_total",
        "Total number of stacks blocks mined by node.",
        labels! {"handler" => "all",}
    ))
    .unwrap();
    pub static ref WARNING_EMITTED_COUNTER: Counter = register_counter!(opts!(
        "stacks_node_warning_emitted_total",
        "Total number of warning logs emitted by node.",
        labels! {"handler" => "all",}
    ))
    .unwrap();
    pub static ref ERRORS_EMITTED_COUNTER: Counter = register_counter!(opts!(
        "stacks_node_errors_emitted_total",
        "Total number of error logs emitted by node.",
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
    async_h1::accept(&addr, stream.clone(), |mut req| async {
        RPC_CALL_COUNTER.inc();

        let encoder = TextEncoder::new();    
        let metric_families = prometheus::gather();
        let mut buffer = vec![];
        encoder.encode(&metric_families, &mut buffer).unwrap();

        let mut response = Response::new(StatusCode::Ok);
        response.append_header("Content-Type", encoder.format_type()).expect("Unable to set headers");
        response.set_body(Body::from(buffer));

        Ok(response)
    }).await?;
    Ok(())
}
