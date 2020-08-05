use std::{
    thread, process
};
use std::time::{
    Duration, Instant
};
use std::sync::{
    Arc, RwLock,
    atomic::{Ordering, AtomicU64}
};

use crossbeam_channel::{bounded, Sender, Receiver, TrySendError};


/// Trait for use by the ChainsCoordinator
/// 
pub trait CoordinatorNotices {
    fn notify_stacks_block_processed(&mut self);
    fn notify_sortition_processed(&mut self);
}

pub struct ArcCounterCoordinatorNotices {
    pub stacks_blocks_processed: Arc<AtomicU64>,
    pub sortitions_processed: Arc<AtomicU64>
}

impl CoordinatorNotices for () {
    fn notify_stacks_block_processed(&mut self) {}
    fn notify_sortition_processed(&mut self) {}
}

impl CoordinatorNotices for ArcCounterCoordinatorNotices {
    fn notify_stacks_block_processed(&mut self) {
        self.stacks_blocks_processed.fetch_add(1, Ordering::SeqCst);
    }
    fn notify_sortition_processed(&mut self) {
        self.sortitions_processed.fetch_add(1, Ordering::SeqCst);
    }
}

/// Structure used for communication _with_ a running
///   ChainsCoordinator
#[derive(Clone)]
pub struct CoordinatorChannels {
    // ChainsCoordinator takes two kinds of signals:
    //    new stacks block & new burn block
    // These signals can be coalesced -- the coordinator doesn't need
    //    handles _all_ new blocks whenever it processes an event
    //    because of this, we can avoid trying to set large bounds on these
    //    event channels by using a coalescing thread.
    new_stacks_block_channel: Sender<()>,
    new_burn_block_channel: Sender<()>,
    /// how many stacks blocks have been processed by this Coordinator thread since startup?
    stacks_blocks_processed: Arc<AtomicU64>,
    /// how many sortitions have been processed by this Coordinator thread since startup?
    sortitions_processed: Arc<AtomicU64>,
    stop: Sender<()>
}

/// Structure used by the Coordinator's run-loop
///   to receive signals
pub struct CoordinatorReceivers {
    pub event_stacks_block: Receiver<()>,
    pub event_burn_block: Receiver<()>,
    pub stop: Receiver<()>,
    pub stacks_blocks_processed: Arc<AtomicU64>,
    pub sortitions_processed: Arc<AtomicU64>,
}

// Singletons for ChainsCoordinator communication
//
//  these channels allow any thread to notify the ChainsCoordinator
//   instance that a new staging block is ready or a new bitcoin
//   block has arrived
//
//  using a singleton for this pretty dramatically simplifies state
//   management in the stacks-node, bitcoin indexer, and relayer, because they
//   don't need to pass around instances of the channels. however,
//   this _does_ step on the cargo test framework in silly ways, so any
//   tests which instantiate a coordinator need to call
//   CoordinatorCommunication::stop_chains_coordinator()
//   when they are done.
lazy_static! {
    static ref COORDINATOR_CHANNELS: RwLock<Option<CoordinatorChannels>> = RwLock::new(None);
}

/// Static struct used to hold all the static methods
///   for communication with the singleton
pub struct CoordinatorCommunication;

impl CoordinatorChannels {
    fn handle_result(r: Result<(), TrySendError<()>>) {
        match r {
            // don't need to do anything if the channel is full -- the coordinator
            //  will check for the new block when it processes the next block anyways
            Ok(_) | Err(TrySendError::Full(_)) => {},
            Err(TrySendError::Disconnected(_)) => {
                warn!("ChainsCoordinator hung up, exiting...");
                process::exit(-1);
            },
        }
    }

    pub fn announce_new_stacks_block(&self) {
        CoordinatorChannels::handle_result(
            self.new_stacks_block_channel.try_send(()));
    }

    pub fn announce_new_burn_block(&self) {
        CoordinatorChannels::handle_result(
            self.new_burn_block_channel.try_send(()));
    }

    pub fn stop_chains_coordinator(&self) {
        CoordinatorChannels::handle_result(
            self.stop.try_send(()));
    }

    pub fn get_stacks_blocks_processed(&self) -> u64 {
        self.stacks_blocks_processed.load(Ordering::SeqCst)
    }

    pub fn get_sortitions_processed(&self) -> u64 {
        self.sortitions_processed.load(Ordering::SeqCst)
    }

    pub fn wait_for_sortitions_processed(&self, current: u64, timeout_millis: u64) -> bool {
        let start = Instant::now();
        while self.get_sortitions_processed() <= current {
            if start.elapsed() > Duration::from_millis(timeout_millis) {
                return false;
            }
            thread::sleep(Duration::from_millis(100));
            std::sync::atomic::spin_loop_hint();
        }
        return true
    }

    pub fn wait_for_stacks_blocks_processed(&self, current: u64, timeout_millis: u64) -> bool {
        let start = Instant::now();
        while self.get_stacks_blocks_processed() <= current {
            if start.elapsed() > Duration::from_millis(timeout_millis) {
                return false;
            }
            thread::sleep(Duration::from_millis(100));
            std::sync::atomic::spin_loop_hint();
        }
        return true
    }

}

impl CoordinatorCommunication {
    pub fn cleanup_singleton() {
        info!("Dropping coordinator channel instance");
        COORDINATOR_CHANNELS.write().unwrap().take()
            .expect("FAIL: ChainsCoordinator cleaning up channels, but send channels non-existant");
    }

    pub fn shared() -> CoordinatorChannels {
        COORDINATOR_CHANNELS.read().unwrap()
            .as_ref().cloned()
            .expect("FAIL: attempted to obtain chains coordinator channels, but instance not constructed.")
    }

    pub fn announce_new_stacks_block() {
        COORDINATOR_CHANNELS.read().unwrap()
            .as_ref().expect("FAIL: attempted to obtain chains coordinator channels, but instance not constructed.")
            .announce_new_stacks_block()
    }

    pub fn announce_new_burn_block() {
        COORDINATOR_CHANNELS.read().unwrap()
            .as_ref().expect("FAIL: attempted to obtain chains coordinator channels, but instance not constructed.")
            .announce_new_burn_block()
    }

    pub fn stop_chains_coordinator() {
        COORDINATOR_CHANNELS.read().unwrap()
            .as_ref().expect("FAIL: attempted to obtain chains coordinator channels, but instance not constructed.")
            .stop_chains_coordinator()
    }

    pub fn get_stacks_blocks_processed() -> u64 {
        COORDINATOR_CHANNELS.read().unwrap()
            .as_ref().expect("FAIL: attempted to obtain chains coordinator channels, but instance not constructed.")
            .get_stacks_blocks_processed()
    }

    pub fn get_sortitions_processed() -> u64 {
        COORDINATOR_CHANNELS.read().unwrap()
            .as_ref().expect("FAIL: attempted to obtain chains coordinator channels, but instance not constructed.")
            .get_sortitions_processed()
    }

    /// wait for `current` to be surpassed, or timeout
    ///   returns `false` if timeout is reached
    ///   returns `true` if sortitions processed is passed
    pub fn wait_for_sortitions_processed(current: u64, timeout_millis: u64) -> bool {
        COORDINATOR_CHANNELS.read().unwrap()
            .as_ref().expect("FAIL: attempted to obtain chains coordinator channels, but instance not constructed.")
            .wait_for_sortitions_processed(current, timeout_millis)
    }

    /// wait for `current` to be surpassed, or timeout
    ///   returns `false` if timeout is reached
    ///   returns `true` if sortitions processed is passed
    pub fn wait_for_stacks_blocks_processed(current: u64, timeout_millis: u64) -> bool {
        COORDINATOR_CHANNELS.read().unwrap()
            .as_ref().expect("FAIL: attempted to obtain chains coordinator channels, but instance not constructed.")
            .wait_for_stacks_blocks_processed(current, timeout_millis)
    }


    pub fn instantiate_singleton() -> CoordinatorReceivers {
        let mut channel_storage = COORDINATOR_CHANNELS.write().unwrap();
        if channel_storage.is_some() {
            panic!("FAIL: attempted to start chains coordinator, but instance already constructed.");
        }

        let (stacks_block_sender, stacks_block_receiver) = bounded(1);
        let (burn_block_sender, burn_block_receiver) = bounded(1);
        let (stop_sender, stop_receiver) = bounded(1);
        let stacks_blocks_processed = Arc::new(AtomicU64::new(0));
        let sortitions_processed = Arc::new(AtomicU64::new(0));

        channel_storage.replace(CoordinatorChannels {
            new_stacks_block_channel: stacks_block_sender,
            new_burn_block_channel: burn_block_sender,
            stacks_blocks_processed: stacks_blocks_processed.clone(),
            sortitions_processed: sortitions_processed.clone(),
            stop: stop_sender,
        });

        CoordinatorReceivers {
            event_stacks_block: stacks_block_receiver,
            event_burn_block: burn_block_receiver,
            stop: stop_receiver,
            stacks_blocks_processed,
            sortitions_processed
        }
    }
}
