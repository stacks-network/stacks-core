use std::collections::HashSet;
use std::convert::Infallible;
use std::ops::{Bound, RangeBounds};
use std::sync::{Arc, Mutex};
use std::thread;

use libsigner::BurnBlockEvent;
use stacks::chainstate::stacks::boot::RewardSet;
use stacks::chainstate::stacks::events::StackerDBChunksEvent;
use stacks::chainstate::stacks::StacksTransaction;
use stacks::codec::StacksMessageCodec;
use stacks::config::{EventKeyType, EventObserverConfig};
use stacks::net::api::postblock_proposal::BlockValidateResponse;
use stacks::util::hash::hex_bytes;
use stacks_common::types::chainstate::StacksBlockId;
use tokio::sync::mpsc::{channel, Receiver, Sender};
use warp::Filter;
use {tokio, warp};

use crate::event_dispatcher::{MinedBlockEvent, MinedMicroblockEvent, MinedNakamotoBlockEvent};
use crate::tests::gen_random_port;
use crate::Config;

// Clones use the same underlying data.
#[derive(Clone)]
pub struct TestObserver {
    new_blocks: Arc<Mutex<Vec<serde_json::Value>>>,
    mined_blocks: Arc<Mutex<Vec<MinedBlockEvent>>>,
    mined_microblocks: Arc<Mutex<Vec<MinedMicroblockEvent>>>,
    mined_nakamoto_blocks: Arc<Mutex<Vec<MinedNakamotoBlockEvent>>>,
    new_microblocks: Arc<Mutex<Vec<serde_json::Value>>>,
    new_stackerdb_chunks: Arc<Mutex<Vec<StackerDBChunksEvent>>>,
    burn_blocks: Arc<Mutex<Vec<BurnBlockEvent>>>,
    memtxs: Arc<Mutex<Vec<String>>>,
    memtxs_dropped: Arc<Mutex<Vec<(String, String)>>>,
    attachments: Arc<Mutex<Vec<serde_json::Value>>>,
    pub proposal_responses: Arc<Mutex<Vec<BlockValidateResponse>>>, // public because there's a test that accesses it directly :(
    stacker_sets: Arc<Mutex<Vec<(StacksBlockId, u64, RewardSet)>>>,

    shutdown: Sender<()>,
    pub port: u16,
}

impl Drop for TestObserver {
    fn drop(&mut self) {
        self.clear(); // keep the memory leakage to a minimum (see comment in `serve()`)
        _ = self.shutdown.blocking_send(());
    }
}

impl TestObserver {
    pub async fn handle_proposal_response(
        &self,
        response: serde_json::Value,
    ) -> Result<impl warp::Reply, Infallible> {
        info!("Proposal response received"; "response" => %response);
        self.proposal_responses.lock().unwrap().push(
            serde_json::from_value(response)
                .expect("Failed to deserialize JSON into BlockValidateResponse"),
        );
        Ok(warp::http::StatusCode::OK)
    }

    async fn handle_burn_block(
        &self,
        burn_block: serde_json::Value,
    ) -> Result<impl warp::Reply, Infallible> {
        self.burn_blocks.lock().unwrap().push(
            serde_json::from_value(burn_block)
                .expect("Failed to deserialize JSON into BurnBlockEvent"),
        );
        Ok(warp::http::StatusCode::OK)
    }

    async fn handle_block(&self, block: serde_json::Value) -> Result<impl warp::Reply, Infallible> {
        let mut blocks = self.new_blocks.lock().unwrap();
        blocks.push(block);
        Ok(warp::http::StatusCode::OK)
    }

    async fn handle_microblocks(
        &self,
        microblocks: serde_json::Value,
    ) -> Result<impl warp::Reply, Infallible> {
        let mut microblock_events = self.new_microblocks.lock().unwrap();
        microblock_events.push(microblocks);
        Ok(warp::http::StatusCode::OK)
    }

    async fn handle_stackerdb_chunks(
        &self,
        chunks: serde_json::Value,
    ) -> Result<impl warp::Reply, Infallible> {
        debug!(
            "signer_runloop: got stackerdb chunks: {}",
            serde_json::to_string(&chunks).unwrap()
        );
        let event: StackerDBChunksEvent = serde_json::from_value(chunks).unwrap();
        let mut stackerdb_chunks = self.new_stackerdb_chunks.lock().unwrap();
        stackerdb_chunks.push(event);

        Ok(warp::http::StatusCode::OK)
    }

    async fn handle_mined_block(
        &self,
        block: serde_json::Value,
    ) -> Result<impl warp::Reply, Infallible> {
        let mut mined_blocks = self.mined_blocks.lock().unwrap();
        // assert that the mined transaction events have string-y txids
        block
            .as_object()
            .expect("Expected JSON object for mined block event")
            .get("tx_events")
            .expect("Expected tx_events key in mined block event")
            .as_array()
            .expect("Expected tx_events key to be an array in mined block event")
            .iter()
            .for_each(|txevent| {
                let txevent_obj = txevent.as_object().expect("TransactionEvent should be object");
                let inner_obj = if let Some(inner_obj) = txevent_obj.get("Success") {
                    inner_obj
                } else if let Some(inner_obj) = txevent_obj.get("ProcessingError") {
                    inner_obj
                } else if let Some(inner_obj) = txevent_obj.get("Skipped") {
                    inner_obj
                } else {
                    panic!("TransactionEvent object should have one of Success, ProcessingError, or Skipped")
                };
                inner_obj
                    .as_object()
                    .expect("TransactionEvent should be an object")
                    .get("txid")
                    .expect("Should have txid key")
                    .as_str()
                    .expect("Expected txid to be a string");
            });

        mined_blocks.push(serde_json::from_value(block).unwrap());
        Ok(warp::http::StatusCode::OK)
    }

    async fn handle_pox_stacker_set(
        &self,
        stacker_set: serde_json::Value,
    ) -> Result<impl warp::Reply, Infallible> {
        let mut stacker_sets = self.stacker_sets.lock().unwrap();
        let block_id = stacker_set
            .as_object()
            .expect("Expected JSON object for stacker set event")
            .get("block_id")
            .expect("Expected block_id field")
            .as_str()
            .expect("Expected string for block id")
            .to_string();
        let block_id = StacksBlockId::from_hex(&block_id)
            .expect("Failed to parse block id field as StacksBlockId hex");
        let cycle_number = stacker_set
            .as_object()
            .expect("Expected JSON object for stacker set event")
            .get("cycle_number")
            .expect("Expected field")
            .as_u64()
            .expect("Expected u64 for cycle number");
        let stacker_set = serde_json::from_value(
            stacker_set
                .as_object()
                .expect("Expected JSON object for stacker set event")
                .get("stacker_set")
                .expect("Expected field")
                .clone(),
        )
        .expect("Failed to parse stacker set object");
        stacker_sets.push((block_id, cycle_number, stacker_set));
        Ok(warp::http::StatusCode::OK)
    }

    /// Called by the process listening to events on a mined microblock event. The event is added
    /// to the mutex-guarded vector `MINED_MICROBLOCKS`.
    async fn handle_mined_microblock(
        &self,
        tx_event: serde_json::Value,
    ) -> Result<impl warp::Reply, Infallible> {
        let mut mined_txs = self.mined_microblocks.lock().unwrap();
        mined_txs.push(serde_json::from_value(tx_event).unwrap());
        Ok(warp::http::StatusCode::OK)
    }

    async fn handle_mined_nakamoto_block(
        &self,
        block: serde_json::Value,
    ) -> Result<impl warp::Reply, Infallible> {
        let mut mined_blocks = self.mined_nakamoto_blocks.lock().unwrap();
        // assert that the mined transaction events have string-y txids
        block
            .as_object()
            .expect("Expected JSON object for mined nakamoto block event")
            .get("tx_events")
            .expect("Expected tx_events key in mined nakamoto block event")
            .as_array()
            .expect("Expected tx_events key to be an array in mined nakamoto block event")
            .iter()
            .for_each(|txevent| {
                let txevent_obj = txevent.as_object().expect("TransactionEvent should be object");
                let inner_obj = if let Some(inner_obj) = txevent_obj.get("Success") {
                    inner_obj
                } else if let Some(inner_obj) = txevent_obj.get("ProcessingError") {
                    inner_obj
                } else if let Some(inner_obj) = txevent_obj.get("Skipped") {
                    inner_obj
                } else if let Some(inner_obj) = txevent_obj.get("Problematic") {
                    inner_obj
                } else {
                    panic!("TransactionEvent object should have one of Success, ProcessingError, Skipped, or Problematic. Had keys: {:?}", txevent_obj.keys().map(|x| x.to_string()).collect::<Vec<_>>());
                };
                inner_obj
                    .as_object()
                    .expect("TransactionEvent should be an object")
                    .get("txid")
                    .expect("Should have txid key")
                    .as_str()
                    .expect("Expected txid to be a string");
            });

        mined_blocks.push(serde_json::from_value(block).unwrap());
        Ok(warp::http::StatusCode::OK)
    }

    async fn handle_mempool_txs(
        &self,
        txs: serde_json::Value,
    ) -> Result<impl warp::Reply, Infallible> {
        let new_rawtxs = txs
            .as_array()
            .unwrap()
            .iter()
            .map(|x| x.as_str().unwrap().to_string());
        let mut memtxs = self.memtxs.lock().unwrap();
        for new_tx in new_rawtxs {
            memtxs.push(new_tx);
        }
        Ok(warp::http::StatusCode::OK)
    }

    async fn handle_mempool_drop_txs(
        &self,
        txs: serde_json::Value,
    ) -> Result<impl warp::Reply, Infallible> {
        let dropped_txids = txs
            .get("dropped_txids")
            .unwrap()
            .as_array()
            .unwrap()
            .iter()
            .map(|x| x.as_str().unwrap().to_string());
        let reason = txs.get("reason").unwrap().as_str().unwrap().to_string();

        let mut memtxs = self.memtxs_dropped.lock().unwrap();
        for new_tx in dropped_txids {
            memtxs.push((new_tx, reason.clone()));
        }
        Ok(warp::http::StatusCode::OK)
    }

    async fn handle_attachments(
        &self,
        attachments: serde_json::Value,
    ) -> Result<impl warp::Reply, Infallible> {
        let new_attachments = attachments.as_array().unwrap();
        let mut attachments = self.attachments.lock().unwrap();
        for new_attachment in new_attachments {
            attachments.push(new_attachment.clone());
        }
        Ok(warp::http::StatusCode::OK)
    }

    /// each path here should correspond to one of the paths listed in `event_dispatcher.rs`
    async fn serve(&self, port: u16, mut shutdown_signal: Receiver<()>) {
        // All this cloning and leaking means that for every test observer, we leak about a KB
        // of memory. Since this is test code, I'm considering this okay for now, we can make
        // it smarter later.
        let clone: &'static Self = Box::leak(Box::new(self.clone()));
        let new_blocks = warp::path!("new_block")
            .and(warp::post())
            .and(warp::body::json())
            .and_then(move |v| clone.handle_block(v));
        let clone: &'static Self = Box::leak(Box::new(self.clone()));
        let mempool_txs = warp::path!("new_mempool_tx")
            .and(warp::post())
            .and(warp::body::json())
            .and_then(|v| clone.handle_mempool_txs(v));
        let clone: &'static Self = Box::leak(Box::new(self.clone()));
        let mempool_drop_txs = warp::path!("drop_mempool_tx")
            .and(warp::post())
            .and(warp::body::json())
            .and_then(|v| clone.handle_mempool_drop_txs(v));
        let clone: &'static Self = Box::leak(Box::new(self.clone()));
        let new_burn_blocks = warp::path!("new_burn_block")
            .and(warp::post())
            .and(warp::body::json())
            .and_then(|v| clone.handle_burn_block(v));
        let clone: &'static Self = Box::leak(Box::new(self.clone()));
        let new_attachments = warp::path!("attachments" / "new")
            .and(warp::post())
            .and(warp::body::json())
            .and_then(|v| clone.handle_attachments(v));
        let clone: &'static Self = Box::leak(Box::new(self.clone()));
        let new_microblocks = warp::path!("new_microblocks")
            .and(warp::post())
            .and(warp::body::json())
            .and_then(|v| clone.handle_microblocks(v));
        let clone: &'static Self = Box::leak(Box::new(self.clone()));
        let mined_blocks = warp::path!("mined_block")
            .and(warp::post())
            .and(warp::body::json())
            .and_then(|v| clone.handle_mined_block(v));
        let clone: &'static Self = Box::leak(Box::new(self.clone()));
        let mined_nakamoto_blocks = warp::path!("mined_nakamoto_block")
            .and(warp::post())
            .and(warp::body::json())
            .and_then(|v| clone.handle_mined_nakamoto_block(v));
        let clone: &'static Self = Box::leak(Box::new(self.clone()));
        let mined_microblocks = warp::path!("mined_microblock")
            .and(warp::post())
            .and(warp::body::json())
            .and_then(|v| clone.handle_mined_microblock(v));
        let clone: &'static Self = Box::leak(Box::new(self.clone()));
        let new_stackerdb_chunks = warp::path!("stackerdb_chunks")
            .and(warp::post())
            .and(warp::body::json())
            .and_then(|v| clone.handle_stackerdb_chunks(v));
        let clone: &'static Self = Box::leak(Box::new(self.clone()));
        let block_proposals = warp::path!("proposal_response")
            .and(warp::post())
            .and(warp::body::json())
            .and_then(|v| clone.handle_proposal_response(v));
        let clone: &'static Self = Box::leak(Box::new(self.clone()));
        let stacker_sets = warp::path!("new_pox_set")
            .and(warp::post())
            .and(warp::body::json())
            .and_then(|v| clone.handle_pox_stacker_set(v));

        info!("Spawning event-observer warp server on port {port}");
        warp::serve(
            new_blocks
                .or(mempool_txs)
                .or(mempool_drop_txs)
                .or(new_burn_blocks)
                .or(new_attachments)
                .or(new_microblocks)
                .or(mined_blocks)
                .or(mined_microblocks)
                .or(mined_nakamoto_blocks)
                .or(new_stackerdb_chunks)
                .or(block_proposals)
                .or(stacker_sets),
        )
        .bind(([127, 0, 0, 1], port))
        .await
        .graceful(async move {
            shutdown_signal.recv().await;
        })
        .run()
        .await;
        info!("Event-observer warp server shut down");
    }
    pub fn spawn() -> TestObserver {
        Self::spawn_at(gen_random_port())
    }

    fn spawn_at(port: u16) -> TestObserver {
        let (tx, rx) = channel::<()>(1);
        let result = TestObserver {
            new_blocks: Arc::new(Mutex::new(Vec::new())),
            mined_blocks: Arc::new(Mutex::new(Vec::new())),
            mined_microblocks: Arc::new(Mutex::new(Vec::new())),
            mined_nakamoto_blocks: Arc::new(Mutex::new(Vec::new())),
            new_microblocks: Arc::new(Mutex::new(Vec::new())),
            new_stackerdb_chunks: Arc::new(Mutex::new(Vec::new())),
            burn_blocks: Arc::new(Mutex::new(Vec::new())),
            memtxs: Arc::new(Mutex::new(Vec::new())),
            memtxs_dropped: Arc::new(Mutex::new(Vec::new())),
            attachments: Arc::new(Mutex::new(Vec::new())),
            proposal_responses: Arc::new(Mutex::new(Vec::new())),
            stacker_sets: Arc::new(Mutex::new(Vec::new())),
            shutdown: tx,
            port,
        };
        let result2 = result.clone();
        thread::spawn(move || {
            let rt = tokio::runtime::Runtime::new().expect("Failed to initialize tokio");
            rt.block_on(result2.serve(port, rx));
        });
        result
    }
    pub fn clear(&self) {
        self.new_blocks.lock().unwrap().clear();
        self.mined_blocks.lock().unwrap().clear();
        self.mined_microblocks.lock().unwrap().clear();
        self.new_microblocks.lock().unwrap().clear();
        self.new_stackerdb_chunks.lock().unwrap().clear();
        self.burn_blocks.lock().unwrap().clear();
        self.memtxs.lock().unwrap().clear();
        self.memtxs_dropped.lock().unwrap().clear();
        self.attachments.lock().unwrap().clear();
        self.proposal_responses.lock().unwrap().clear();
    }

    pub fn get_stacker_sets(&self) -> Vec<(StacksBlockId, u64, RewardSet)> {
        self.stacker_sets.lock().unwrap().clone()
    }

    pub fn get_memtxs(&self) -> Vec<String> {
        self.memtxs.lock().unwrap().clone()
    }

    pub fn get_memtx_drops(&self) -> Vec<(String, String)> {
        self.memtxs_dropped.lock().unwrap().clone()
    }

    pub fn get_blocks(&self) -> Vec<serde_json::Value> {
        self.new_blocks.lock().unwrap().clone()
    }

    pub fn get_microblocks(&self) -> Vec<serde_json::Value> {
        self.new_microblocks.lock().unwrap().clone()
    }

    pub fn get_burn_blocks(&self) -> Vec<BurnBlockEvent> {
        self.burn_blocks.lock().unwrap().clone()
    }

    pub fn get_attachments(&self) -> Vec<serde_json::Value> {
        self.attachments.lock().unwrap().clone()
    }

    pub fn get_mined_blocks(&self) -> Vec<MinedBlockEvent> {
        self.mined_blocks.lock().unwrap().clone()
    }

    pub fn get_mined_microblocks(&self) -> Vec<MinedMicroblockEvent> {
        self.mined_microblocks.lock().unwrap().clone()
    }

    pub fn get_mined_nakamoto_blocks(&self) -> Vec<MinedNakamotoBlockEvent> {
        self.mined_nakamoto_blocks.lock().unwrap().clone()
    }

    pub fn get_stackerdb_chunks(&self) -> Vec<StackerDBChunksEvent> {
        self.new_stackerdb_chunks.lock().unwrap().clone()
    }

    pub fn get_proposal_responses(&self) -> Vec<BlockValidateResponse> {
        self.proposal_responses.lock().unwrap().clone()
    }

    /// Parse the StacksTransactions from a block (does not include burn ops or phantom txs)
    ///  panics on any failures to parse
    pub fn parse_transactions(block: &serde_json::Value) -> Vec<StacksTransaction> {
        block
            .get("transactions")
            .unwrap()
            .as_array()
            .unwrap()
            .iter()
            .filter_map(|tx_json| {
                // Filter out burn ops
                if let Some(burnchain_op_val) = tx_json.get("burnchain_op") {
                    if !burnchain_op_val.is_null() {
                        return None;
                    }
                }
                // Filter out phantom txs
                let tx_hex = tx_json.get("raw_tx").unwrap().as_str().unwrap();
                let tx_bytes = hex_bytes(&tx_hex[2..]).unwrap();
                let tx =
                    StacksTransaction::consensus_deserialize(&mut tx_bytes.as_slice()).unwrap();
                if tx.is_phantom() {
                    return None;
                }
                Some(tx)
            })
            .collect()
    }

    /// Get missing burn blocks for a given height range
    /// Returns Ok(..) if lookup is sucessful, whether there are missing blocks or not
    pub fn get_missing_burn_blocks(
        &self,
        range: impl RangeBounds<u64>,
    ) -> Result<Vec<u64>, String> {
        // Get set of all burn block heights
        let burn_block_heights = self
            .get_blocks()
            .into_iter()
            .map(|x| x.get("burn_block_height").unwrap().as_u64().unwrap())
            .collect::<HashSet<_>>();

        let start = match range.start_bound() {
            Bound::Unbounded => return Err("Unbounded ranges not supported".into()),
            Bound::Included(&x) => x,
            Bound::Excluded(&x) => x.saturating_add(1),
        };

        let end = match range.end_bound() {
            Bound::Unbounded => return Err("Unbounded ranges not supported".into()),
            Bound::Included(&x) => x,
            Bound::Excluded(&x) => x.saturating_sub(1),
        };

        // Find indexes in range for which we don't have burn block in set
        let missing = (start..=end)
            .filter(|i| !burn_block_heights.contains(i))
            .collect();

        Ok(missing)
    }

    /// Similar to `missing_burn_blocks()` but returns `Err(..)` if blocks are missing
    pub fn contains_burn_block_range(
        &self,
        range: impl RangeBounds<u64> + Clone,
    ) -> Result<(), String> {
        let missing = self.get_missing_burn_blocks(range.clone())?;

        if missing.is_empty() {
            Ok(())
        } else {
            Err(format!(
                "Missing the following burn blocks from {:?} to {:?}: {missing:?}",
                range.start_bound(),
                range.end_bound()
            ))
        }
    }

    pub fn register(&self, config: &mut Config, event_keys: &[EventKeyType]) {
        let port = self.port;
        config.events_observers.insert(EventObserverConfig {
            endpoint: format!("127.0.0.1:{port}"),
            events_keys: event_keys.to_vec(),
            timeout_ms: 1000,
            disable_retries: false,
        });
    }

    pub fn register_any(&self, config: &mut Config) {
        self.register(config, &[EventKeyType::AnyEvent]);
    }
}
