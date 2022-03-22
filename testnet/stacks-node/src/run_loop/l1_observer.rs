use std::convert::Infallible;
use std::sync::Arc;
use std::sync::Mutex;

use crate::burnchains::mock_events::MockChannels;
use crate::burnchains::mock_events::MOCK_EVENTS_STREAM;
use stacks::burnchains::events::NewBlock;
use stacks::types::chainstate::StacksBlockId;
use std::thread;
use std::thread::JoinHandle;
use tokio::sync::oneshot;
use tokio::sync::oneshot::Receiver;
use tokio::sync::oneshot::Sender;
use tokio::task::JoinError;
use warp;
use warp::Filter;

pub const EVENT_OBSERVER_PORT: u16 = 50303;

async fn handle_new_block(block: serde_json::Value) -> Result<impl warp::Reply, Infallible> {
    let parsed_block: NewBlock =
        serde_json::from_str(&block.to_string()).expect("Failed to parse events JSON");
    info!("handle_new_block receives new block {:?}", &parsed_block);
    MOCK_EVENTS_STREAM.push_block(parsed_block);
    Ok(warp::http::StatusCode::OK)
}

async fn serve(signal_receiver: Receiver<()>) -> Result<(), JoinError> {
    let new_blocks = warp::path!("new_block")
        .and(warp::post())
        .and(warp::body::json())
        .and_then(handle_new_block);

    info!("Binding warp server.");
    let (addr, server) = warp::serve(new_blocks).bind_with_graceful_shutdown(
        ([127, 0, 0, 1], EVENT_OBSERVER_PORT),
        async {
            signal_receiver.await.ok();
        },
    );

    // Spawn the server into a runtime
    info!("Spawning warp server");
    tokio::task::spawn(server).await
}

pub fn spawn() -> Sender<()> {
    let (signal_sender, signal_receiver) = oneshot::channel();
    thread::spawn(|| {
        let rt = tokio::runtime::Runtime::new().expect("Failed to initialize tokio");
        rt.block_on(serve(signal_receiver))
            .expect("block_on failed");
    });
    signal_sender
}
