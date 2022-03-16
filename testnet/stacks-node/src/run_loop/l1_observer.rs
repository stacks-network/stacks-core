use std::convert::Infallible;
use std::sync::Mutex;

use std::thread;
use std::thread::JoinHandle;
use tokio::sync::oneshot;
use tokio::sync::oneshot::Receiver;
use tokio::sync::oneshot::Sender;
use warp;
use warp::Filter;

pub const EVENT_OBSERVER_PORT: u16 = 50303;

lazy_static! {
    pub static ref NEW_BLOCKS: Mutex<Vec<serde_json::Value>> = Mutex::new(Vec::new());
}

async fn handle_new_block(block: serde_json::Value) -> Result<impl warp::Reply, Infallible> {
    info!("handle_new_block receives {:?}", &block);
    let mut blocks = NEW_BLOCKS.lock().unwrap();
    blocks.push(block);
    Ok(warp::http::StatusCode::OK)
}

use tokio::task::JoinError;
async fn serve(signal_receiver: Receiver<()>) -> Result<(), JoinError> {
    let new_blocks = warp::path!("new_block")
        .and(warp::post())
        .and(warp::body::json())
        .and_then(handle_new_block);

    info!("Binding warp server");
    let (addr, server) = warp::serve(new_blocks).bind_with_graceful_shutdown(
        ([127, 0, 0, 1], EVENT_OBSERVER_PORT),
        async {
            signal_receiver.await.ok();
        },
    );

    // Spawn the server into a runtime
    info!("Spawning warp server");
    // Spawn the server into a runtime
    tokio::task::spawn(server).await
}

pub fn spawn() -> Sender<()> {
    let (signal_sender, signal_receiver) = oneshot::channel();
    thread::spawn(|| {
        let rt = tokio::runtime::Runtime::new().expect("Failed to initialize tokio");
        rt.block_on(serve(signal_receiver));
    });
    signal_sender
}
