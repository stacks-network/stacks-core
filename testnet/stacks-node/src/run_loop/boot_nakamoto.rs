// Copyright (C) 2013-2020 Blockstack PBC, a public benefit corporation
// Copyright (C) 2020-2023 Stacks Open Internet Foundation
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
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::thread::JoinHandle;
use std::time::Duration;
use std::{fs, thread};

use stacks::burnchains::Burnchain;
use stacks::chainstate::burn::db::sortdb::SortitionDB;
use stacks::chainstate::coordinator::comm::CoordinatorChannels;
use stacks::core::StacksEpochExtension;
use stacks_common::types::{StacksEpoch, StacksEpochId};

use crate::neon::Counters;
use crate::run_loop::nakamoto::RunLoop as NakaRunLoop;
use crate::run_loop::neon::RunLoop as NeonRunLoop;
use crate::Config;

/// This runloop handles booting to Nakamoto:
/// During epochs [1.0, 2.5], it runs a neon run_loop.
/// Once epoch 3.0 is reached, it stops the neon run_loop
///  and starts nakamoto.
pub struct BootRunLoop {
    config: Config,
    active_loop: InnerLoops,
    coordinator_channels: Arc<Mutex<CoordinatorChannels>>,
}

enum InnerLoops {
    Epoch2(NeonRunLoop),
    Epoch3(NakaRunLoop),
}

impl BootRunLoop {
    pub fn new(config: Config) -> Result<Self, String> {
        let (coordinator_channels, active_loop) = if !Self::reached_epoch_30_transition(&config)? {
            let neon = NeonRunLoop::new(config.clone());
            (
                neon.get_coordinator_channel().unwrap(),
                InnerLoops::Epoch2(neon),
            )
        } else {
            let naka = NakaRunLoop::new(config.clone(), None, None, None);
            (
                naka.get_coordinator_channel().unwrap(),
                InnerLoops::Epoch3(naka),
            )
        };

        Ok(BootRunLoop {
            config,
            active_loop,
            coordinator_channels: Arc::new(Mutex::new(coordinator_channels)),
        })
    }

    /// Get a mutex-guarded pointer to this run-loops coordinator channels.
    ///  The reason this must be mutex guarded is that the run loop will switch
    ///  from a "neon" coordinator to a "nakamoto" coordinator, and update the
    ///  backing coordinator channel. That way, anyone still holding the Arc<>
    ///  should be able to query the new coordinator channel.
    pub fn coordinator_channels(&self) -> Arc<Mutex<CoordinatorChannels>> {
        self.coordinator_channels.clone()
    }

    /// Get the runtime counters for the inner runloop. The nakamoto
    ///  runloop inherits the counters object from the neon node,
    ///  so no need for another layer of indirection/mutex.
    pub fn counters(&self) -> Counters {
        match &self.active_loop {
            InnerLoops::Epoch2(x) => x.get_counters(),
            InnerLoops::Epoch3(x) => x.get_counters(),
        }
    }

    /// Get the termination switch from the active run loop.
    pub fn get_termination_switch(&self) -> Arc<AtomicBool> {
        match &self.active_loop {
            InnerLoops::Epoch2(x) => x.get_termination_switch(),
            InnerLoops::Epoch3(x) => x.get_termination_switch(),
        }
    }

    /// The main entry point for the run loop. This starts either a 2.x-neon or 3.x-nakamoto
    /// node depending on the current burnchain height.
    pub fn start(&mut self, burnchain_opt: Option<Burnchain>, mine_start: u64) {
        match self.active_loop {
            InnerLoops::Epoch2(_) => return self.start_from_neon(burnchain_opt, mine_start),
            InnerLoops::Epoch3(_) => return self.start_from_naka(burnchain_opt, mine_start),
        }
    }

    fn start_from_naka(&mut self, burnchain_opt: Option<Burnchain>, mine_start: u64) {
        let InnerLoops::Epoch3(ref mut naka_loop) = self.active_loop else {
            panic!("FATAL: unexpectedly invoked start_from_naka when active loop wasn't nakamoto");
        };
        naka_loop.start(burnchain_opt, mine_start, None)
    }

    fn start_from_neon(&mut self, burnchain_opt: Option<Burnchain>, mine_start: u64) {
        let InnerLoops::Epoch2(ref mut neon_loop) = self.active_loop else {
            panic!("FATAL: unexpectedly invoked start_from_neon when active loop wasn't neon");
        };
        let termination_switch = neon_loop.get_termination_switch();
        let counters = neon_loop.get_counters();

        let boot_thread = Self::spawn_stopper(&self.config, neon_loop)
            .expect("FATAL: failed to spawn epoch-2/3-boot thread");
        let peer_network = neon_loop.start(burnchain_opt.clone(), mine_start);

        let monitoring_thread = neon_loop.take_monitoring_thread();
        // did we exit because of the epoch-3.0 transition, or some other reason?
        let exited_for_transition = boot_thread
            .join()
            .expect("FATAL: failed to join epoch-2/3-boot thread");
        if !exited_for_transition {
            info!("Shutting down epoch-2/3 transition thread");
            return;
        }
        info!("Reached Epoch-3.0 boundary, starting nakamoto node");
        termination_switch.store(true, Ordering::SeqCst);
        let naka = NakaRunLoop::new(
            self.config.clone(),
            Some(termination_switch),
            Some(counters),
            monitoring_thread,
        );
        let new_coord_channels = naka
            .get_coordinator_channel()
            .expect("FATAL: should have coordinator channel in newly instantiated runloop");
        {
            let mut coord_channel = self.coordinator_channels.lock().expect("Mutex poisoned");
            *coord_channel = new_coord_channels;
        }
        self.active_loop = InnerLoops::Epoch3(naka);
        let InnerLoops::Epoch3(ref mut naka_loop) = self.active_loop else {
            panic!("FATAL: unexpectedly found epoch2 loop after setting epoch3 active");
        };
        naka_loop.start(burnchain_opt, mine_start, peer_network)
    }

    fn spawn_stopper(
        config: &Config,
        neon: &NeonRunLoop,
    ) -> Result<JoinHandle<bool>, std::io::Error> {
        let neon_term_switch = neon.get_termination_switch();
        let config = config.clone();
        thread::Builder::new()
            .name("epoch-2/3-boot".into())
            .spawn(move || {
                loop {
                    let do_transition = Self::reached_epoch_30_transition(&config)
                        .unwrap_or_else(|err| {
                            warn!("Error checking for Epoch-3.0 transition: {err:?}. Assuming transition did not occur yet.");
                            false
                        });
                    if do_transition {
                        break;
                    }
                    if !neon_term_switch.load(Ordering::SeqCst) {
                        info!("Stop requested, exiting epoch-2/3-boot thread");
                        return false;
                    }
                    thread::sleep(Duration::from_secs(1));
                }
                // if loop exited, do the transition
                info!("Epoch-3.0 boundary reached, stopping Epoch-2.x run loop");
                neon_term_switch.store(false, Ordering::SeqCst);
                return true
            })
    }

    fn reached_epoch_30_transition(config: &Config) -> Result<bool, String> {
        let burn_height = Self::get_burn_height(config)?;
        let epochs = StacksEpoch::get_epochs(
            config.burnchain.get_bitcoin_network().1,
            config.burnchain.epochs.as_ref(),
        );
        let epoch_3 = &epochs[StacksEpoch::find_epoch_by_id(&epochs, StacksEpochId::Epoch30)
            .ok_or("No Epoch-3.0 defined")?];

        Ok(u64::from(burn_height) >= epoch_3.start_height - 1)
    }

    fn get_burn_height(config: &Config) -> Result<u32, String> {
        let burnchain = config.get_burnchain();
        let sortdb_path = config.get_burn_db_file_path();
        if fs::metadata(&sortdb_path).is_err() {
            // if the sortition db doesn't exist yet, don't try to open() it, because that creates the
            // db file even if it doesn't instantiate the tables, which breaks connect() logic.
            info!("Failed to open Sortition DB while checking current burn height, assuming height = 0");
            return Ok(0);
        }

        let Ok(sortdb) = SortitionDB::open(&sortdb_path, false, burnchain.pox_constants) else {
            info!("Failed to open Sortition DB while checking current burn height, assuming height = 0");
            return Ok(0);
        };

        let Ok(tip_sn) = SortitionDB::get_canonical_burn_chain_tip(sortdb.conn()) else {
            info!("Failed to query Sortition DB for current burn height, assuming height = 0");
            return Ok(0);
        };

        Ok(u32::try_from(tip_sn.block_height).expect("FATAL: burn height exceeded u32"))
    }
}
