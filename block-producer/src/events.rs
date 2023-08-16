use std::convert::Infallible;
use std::sync::{Arc, Mutex, Condvar};
use std::thread;

use warp::Filter;

pub trait BurnBlockCallback: Send + Sync {
    fn burn_block(&self);
}

pub struct WaitableCounter(Mutex<u64>, Condvar);

impl WaitableCounter {
    pub fn new() -> Self {
        Self(Mutex::new(0), Condvar::new())
    }

    pub fn bump_counter(&self) {
        let mut guarded_data = self.0.lock().unwrap();
        *guarded_data += 1;
        self.1.notify_all();
    }

    pub fn wait_for_bump(&self) {
        let mut guarded_data = self.0.lock().unwrap();
        let last_value = *guarded_data;
        let mut latest_value = last_value;
        // we loop here to check against spurious wakeups
        while latest_value == last_value {
            guarded_data = self.1.wait(guarded_data).unwrap();
            latest_value = *guarded_data;
        }
    }
}

/// Listens to a a stacks-node event stream,
///  invoking a callback whenever a new burn block event arrives.
pub struct NewBlockEventListener {
    pub burn_blocks_processed: Arc<WaitableCounter>,
}

impl NewBlockEventListener {
    pub fn new() -> Self {
        Self {
            burn_blocks_processed: Arc::new(WaitableCounter::new()),
        }
    }

    async fn handle_block(burn_callback: Arc<WaitableCounter>, _block: serde_json::Value) -> Result<impl warp::Reply, Infallible> {
        burn_callback.bump_counter();
        Ok(warp::http::StatusCode::OK)
    }

    async fn handle_any() -> Result<impl warp::Reply, Infallible> {
        Ok(warp::http::StatusCode::OK)
    }

    pub fn serve(&self) -> thread::JoinHandle<()> {
        let burn_count = self.burn_blocks_processed.clone();
        let burn_count_filter = warp::any().map(move || burn_count.clone());

        let new_blocks = warp::path!("new_block")
            .and(warp::post())
            .and_then(Self::handle_any);

        let burn_blocks = warp::path!("new_burn_block")
            .and(warp::post())
            .and(burn_count_filter)
            .and(warp::body::json())
            .and_then(Self::handle_block);


        thread::spawn(move || {
            let rt = tokio::runtime::Runtime::new().expect("Failed to initialize tokio");
            rt.block_on(
                warp::serve(
                    burn_blocks
                        .or(new_blocks)
                )
                .run(([127, 0, 0, 1], 50303))
            )
        })

    }
}
