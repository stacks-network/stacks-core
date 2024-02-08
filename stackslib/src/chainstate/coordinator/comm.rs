// Copyright (C) 2013-2020 Blockstack PBC, a public benefit corporation
// Copyright (C) 2020 Stacks Open Internet Foundation
//
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.
//
// This program is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
// GNU General Public License for more details.
//
// You should have received a copy of the GNU General Public License
// along with this program.  If not, see <http://www.gnu.org/licenses/>.

use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Arc, Condvar, LockResult, Mutex, MutexGuard, RwLock, TryLockResult};
use std::time::{Duration, Instant};
use std::{process, thread};

/// Trait for use by the ChainsCoordinator
///
pub trait CoordinatorNotices {
    fn notify_stacks_block_processed(&mut self);
    fn notify_sortition_processed(&mut self);
}

pub struct ArcCounterCoordinatorNotices {
    pub stacks_blocks_processed: Arc<AtomicU64>,
    pub sortitions_processed: Arc<AtomicU64>,
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
    /// Mutex guarded signaling struct for communicating
    ///  to the coordinator.
    signal_bools: Arc<Mutex<SignalBools>>,
    /// Condvar for notifying on updates to signal_bools
    signal_wakeup: Arc<Condvar>,
    /// how many stacks blocks have been processed by this Coordinator thread since startup?
    stacks_blocks_processed: Arc<AtomicU64>,
    /// how many sortitions have been processed by this Coordinator thread since startup?
    sortitions_processed: Arc<AtomicU64>,
    /// Does the StackerDB need to be refreshed?
    refresh_stacker_db: Arc<AtomicBool>,
}

/// Notification struct for communicating to
///  the coordinator. Each bool indicates a notice
///  that there are new events of a type to check
struct SignalBools {
    new_stacks_block: bool,
    new_burn_block: bool,
    stop: bool,
}

/// Structure used by the Coordinator's run-loop
///   to receive signals
pub struct CoordinatorReceivers {
    /// Mutex guarded signaling struct for communicating
    ///  to the coordinator.
    signal_bools: Arc<Mutex<SignalBools>>,
    /// Condvar for notifying on updates to signal_bools.
    ///   the Condvar should only be used with the Mutex guarding
    ///   signal_bools
    signal_wakeup: Arc<Condvar>,
    pub stacks_blocks_processed: Arc<AtomicU64>,
    pub sortitions_processed: Arc<AtomicU64>,
    /// Does the StackerDB need to be refreshed?
    pub refresh_stacker_db: Arc<AtomicBool>,
}

/// Static struct used to hold all the static methods
///   for setting up the coordinator channels
pub struct CoordinatorCommunication;

#[repr(u8)]
pub enum CoordinatorEvents {
    NEW_STACKS_BLOCK = 0x01,
    NEW_BURN_BLOCK = 0x02,
    STOP = 0x04,
    TIMEOUT = 0x08,
}

impl SignalBools {
    fn activated_signal(&self) -> bool {
        self.stop || self.new_stacks_block || self.new_burn_block
    }
    fn receive_signal(&mut self) -> u8 {
        let mut bits = 0;
        if self.stop {
            bits |= CoordinatorEvents::STOP as u8;
        }
        if self.new_burn_block {
            bits |= CoordinatorEvents::NEW_BURN_BLOCK as u8;
            self.new_burn_block = false;
        }
        if self.new_stacks_block {
            bits |= CoordinatorEvents::NEW_STACKS_BLOCK as u8;
            self.new_stacks_block = false;
        }
        if bits == 0 {
            bits = CoordinatorEvents::TIMEOUT as u8;
        }
        bits
    }
}

impl CoordinatorReceivers {
    pub fn wait_on(&self) -> u8 {
        let mut signal_bools = self.signal_bools.lock().unwrap();
        if !signal_bools.activated_signal() {
            signal_bools = self.signal_wakeup.wait(signal_bools).unwrap();
        }
        signal_bools.receive_signal()
    }
}

impl CoordinatorChannels {
    pub fn announce_new_stacks_block(&self) -> bool {
        let mut bools = self.signal_bools.lock().unwrap();
        bools.new_stacks_block = true;
        self.signal_wakeup.notify_all();
        debug!("Announce new stacks block");
        !bools.stop
    }

    pub fn announce_new_burn_block(&self) -> bool {
        let mut bools = self.signal_bools.lock().unwrap();
        bools.new_burn_block = true;
        self.signal_wakeup.notify_all();
        debug!("Announce new burn block");
        !bools.stop
    }

    pub fn stop_chains_coordinator(&self) -> bool {
        let mut bools = self.signal_bools.lock().unwrap();
        bools.stop = true;
        self.signal_wakeup.notify_all();
        debug!("Stop chains coordinator");
        false
    }

    pub fn need_stackerdb_update(&self) -> bool {
        self.refresh_stacker_db.load(Ordering::SeqCst)
    }

    pub fn set_stackerdb_update(&self, needs_update: bool) {
        self.refresh_stacker_db
            .store(needs_update, Ordering::SeqCst)
    }

    pub fn is_stopped(&self) -> bool {
        let bools = self.signal_bools.lock().unwrap();
        bools.stop.clone()
    }

    pub fn get_stacks_blocks_processed(&self) -> u64 {
        self.stacks_blocks_processed.load(Ordering::SeqCst)
    }

    pub fn get_sortitions_processed(&self) -> u64 {
        self.sortitions_processed.load(Ordering::SeqCst)
    }

    pub fn wait_for_sortitions_processed(&self, current: u64, timeout_millis: u64) -> bool {
        let start = Instant::now();
        let mut ctr = 0;
        while self.get_sortitions_processed() <= current {
            if start.elapsed() > Duration::from_millis(timeout_millis) {
                return false;
            }
            thread::sleep(Duration::from_millis(100));
            std::hint::spin_loop();
            if ctr % 10 == 0 {
                debug!(
                    "Wait for sortitions processed (processed = {}, current = {}))",
                    self.get_sortitions_processed(),
                    current
                );
            }
            ctr += 1;
        }
        return true;
    }

    pub fn wait_for_stacks_blocks_processed(&self, current: u64, timeout_millis: u64) -> bool {
        let start = Instant::now();
        let mut ctr = 0;
        while self.get_stacks_blocks_processed() <= current {
            if start.elapsed() > Duration::from_millis(timeout_millis) {
                return false;
            }
            thread::sleep(Duration::from_millis(100));
            std::hint::spin_loop();
            if ctr % 10 == 0 {
                debug!(
                    "Wait for stacks blocks processed (processed = {}, current = {}))",
                    self.get_stacks_blocks_processed(),
                    current
                );
            }
            ctr += 1;
        }
        return true;
    }
}

impl CoordinatorCommunication {
    pub fn instantiate() -> (CoordinatorReceivers, CoordinatorChannels) {
        let signal_bools = Arc::new(Mutex::new(SignalBools {
            new_stacks_block: false,
            new_burn_block: false,
            stop: false,
        }));

        let signal_wakeup = Arc::new(Condvar::new());

        let stacks_blocks_processed = Arc::new(AtomicU64::new(0));
        let sortitions_processed = Arc::new(AtomicU64::new(0));
        let refresh_stacker_db = Arc::new(AtomicBool::new(false));

        let senders = CoordinatorChannels {
            signal_bools: signal_bools.clone(),
            signal_wakeup: signal_wakeup.clone(),
            stacks_blocks_processed: stacks_blocks_processed.clone(),

            sortitions_processed: sortitions_processed.clone(),
            refresh_stacker_db: refresh_stacker_db.clone(),
        };

        let rcvrs = CoordinatorReceivers {
            signal_bools: signal_bools,
            signal_wakeup: signal_wakeup,
            stacks_blocks_processed,
            sortitions_processed,
            refresh_stacker_db,
        };

        (rcvrs, senders)
    }
}
