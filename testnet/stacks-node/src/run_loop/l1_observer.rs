use std::convert::Infallible;
use std::sync::Mutex;

use std::thread;
use std::thread::JoinHandle;
use warp;
use warp::Filter;

pub const EVENT_OBSERVER_PORT: u16 = 50303;

lazy_static! {
    pub static ref NEW_BLOCKS: Mutex<Vec<serde_json::Value>> = Mutex::new(Vec::new());
}

async fn handle_block(block: serde_json::Value) -> Result<impl warp::Reply, Infallible> {
    info!("handle_block receives {:?}", &block);
    let mut blocks = NEW_BLOCKS.lock().unwrap();
    blocks.push(block);
    Ok(warp::http::StatusCode::OK)
}

/// each path here should correspond to one of the paths listed in `event_dispatcher.rs`
async fn serve() {
    let new_blocks = warp::path!("new_block")
        .and(warp::post())
        .and(warp::body::json())
        .and_then(handle_block);

    info!("Spawning warp server");
    warp::serve(new_blocks)
        .run(([127, 0, 0, 1], EVENT_OBSERVER_PORT))
        .await
}

pub fn spawn() -> JoinHandle<()> {
    thread::spawn(|| {
        let rt = tokio::runtime::Runtime::new().expect("Failed to initialize tokio");
        rt.block_on(serve());
    })
}
