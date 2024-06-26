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
/// The v0 implementation of the signer. This does not include WSTS support
pub mod v0;
/// The v1 implementation of the singer. This includes WSTS support
pub mod v1;
use std::fmt::{Debug, Display};
use std::sync::mpsc::Sender;

use libsigner::{SignerEvent, SignerEventTrait};
use wsts::state_machine::OperationResult;

use crate::client::StacksClient;
use crate::config::SignerConfig;
use crate::runloop::RunLoopCommand;

/// A trait which provides a common `Signer` interface for `v1` and `v2`
pub trait Signer<T: SignerEventTrait>: Debug + Display {
    /// Create a new `Signer` instance
    fn new(config: SignerConfig) -> Self;
    /// Update the `Signer` instance's next reward cycle data with the latest `SignerConfig`
    fn update_next_signer_data(&mut self, next_signer_config: &SignerConfig);
    /// Get the reward cycle of the signer
    fn reward_cycle(&self) -> u64;
    /// Process an event
    fn process_event(
        &mut self,
        stacks_client: &StacksClient,
        event: Option<&SignerEvent<T>>,
        res: Sender<Vec<OperationResult>>,
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
