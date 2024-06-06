#![forbid(missing_docs)]
/*!
# stacks-signer: a libary for creating a Stacks compliant signer. A default implementation binary is also provided.
Usage documentation can be found in the [README](https://github.com/Trust-Machines/core-eng/stacks-signer-api/README.md).
*/

// Copyright (C) 2013-2020 Blockstack PBC, a public benefit corporation
// Copyright (C) 2020-2024 Stacks Open Internet Foundation
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

/// This module stores chainstate information about Stacks, SortitionDB for
/// tracking by the signer.
pub mod chainstate;
/// The cli module for the signer binary
pub mod cli;
/// The signer client for communicating with stackerdb/stacks nodes
pub mod client;
/// The configuration module for the signer
pub mod config;
/// The monitoring server for the signer
pub mod monitoring;
/// The primary runloop for the signer
pub mod runloop;
/// The signer state module
pub mod signerdb;
/// The v0 implementation of the signer. This does not include WSTS support
pub mod v0;
/// The v1 implementation of the singer. This includes WSTS support
pub mod v1;

#[cfg(test)]
mod tests;

use std::fmt::{Debug, Display};
use std::sync::mpsc::{channel, Receiver, Sender};

use config::GlobalConfig;
use libsigner::{SignerEvent, SignerEventReceiver, SignerEventTrait};
use runloop::SignerResult;
use slog::{slog_info, slog_warn};
use stacks_common::{info, warn};

use crate::client::StacksClient;
use crate::config::SignerConfig;
use crate::runloop::{RunLoop, RunLoopCommand};

/// A trait which provides a common `Signer` interface for `v0` and `v1`
pub trait Signer<T: SignerEventTrait>: Debug + Display {
    /// Create a new `Signer` instance
    fn new(config: SignerConfig) -> Self;
    /// Update the `Signer` instance's with the next reward cycle data `SignerConfig`
    fn update_signer(&mut self, next_signer_config: &SignerConfig);
    /// Get the reward cycle of the signer
    fn reward_cycle(&self) -> u64;
    /// Process an event
    fn process_event(
        &mut self,
        stacks_client: &StacksClient,
        event: Option<&SignerEvent<T>>,
        res: Sender<Vec<SignerResult>>,
        current_reward_cycle: u64,
    );
    /// Process a command
    fn process_command(
        &mut self,
        stacks_client: &StacksClient,
        current_reward_cycle: u64,
        command: Option<RunLoopCommand>,
    );
}

/// A wrapper around the running signer type for the signer
pub type RunningSigner<T> = libsigner::RunningSigner<SignerEventReceiver<T>, Vec<SignerResult>, T>;

/// The wrapper for the runloop signer type
type RunLoopSigner<S, T> =
    libsigner::Signer<RunLoopCommand, Vec<SignerResult>, RunLoop<S, T>, SignerEventReceiver<T>, T>;

/// The spawned signer
pub struct SpawnedSigner<S: Signer<T> + Send, T: SignerEventTrait> {
    /// The underlying running signer thread handle
    running_signer: RunningSigner<T>,
    /// The command sender for interacting with the running signer
    pub cmd_send: Sender<RunLoopCommand>,
    /// The result receiver for interacting with the running signer
    pub res_recv: Receiver<Vec<SignerResult>>,
    /// Phantom data for the signer type
    _phantom: std::marker::PhantomData<S>,
}

impl<S: Signer<T> + Send, T: SignerEventTrait> SpawnedSigner<S, T> {
    /// Stop the signer thread and return the final state
    pub fn stop(self) -> Option<Vec<SignerResult>> {
        self.running_signer.stop()
    }

    /// Wait for the signer to terminate, and get the final state. WARNING: This will hang forever if the event receiver stop signal was never sent/no error occurred.
    pub fn join(self) -> Option<Vec<SignerResult>> {
        self.running_signer.join()
    }
}

impl<S: Signer<T> + Send + 'static, T: SignerEventTrait + 'static> SpawnedSigner<S, T> {
    /// Create a new spawned signer
    pub fn new(config: GlobalConfig) -> Self {
        let endpoint = config.endpoint;
        info!("Starting signer with config: {:?}", config);
        warn!(
            "Reminder: The signer is primarily designed for use with a local or subnet network stacks node. \
            It's important to exercise caution if you are communicating with an external node, \
            as this could potentially expose sensitive data or functionalities to security risks \
            if additional proper security checks are not integrated in place. \
            For more information, check the documentation at \
            https://docs.stacks.co/nakamoto-upgrade/signing-and-stacking/faq#what-should-the-networking-setup-for-my-signer-look-like."
        );
        let (cmd_send, cmd_recv) = channel();
        let (res_send, res_recv) = channel();
        let ev = SignerEventReceiver::new(config.network.is_mainnet());
        #[cfg(feature = "monitoring_prom")]
        {
            crate::monitoring::start_serving_monitoring_metrics(config.clone()).ok();
        }
        let runloop = RunLoop::new(config);
        let mut signer: RunLoopSigner<S, T> =
            libsigner::Signer::new(runloop, ev, cmd_recv, res_send);
        let running_signer = signer.spawn(endpoint).expect("Failed to spawn signer");
        SpawnedSigner {
            running_signer,
            cmd_send,
            res_recv,
            _phantom: std::marker::PhantomData,
        }
    }
}
