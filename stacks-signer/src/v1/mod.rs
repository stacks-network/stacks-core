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

/// The coordinator selector for the signer
pub mod coordinator;
/// The signer module for processing events
pub mod signer;
/// The state module for the signer
pub mod signerdb;

use std::sync::mpsc::{channel, Receiver, Sender};

use libsigner::v1::messages::SignerMessage;
use libsigner::SignerEventReceiver;
use slog::slog_info;
use stacks_common::info;
use wsts::state_machine::OperationResult;

use crate::config::GlobalConfig;
use crate::runloop::{RunLoop, RunLoopCommand};
use crate::v1::signer::Signer;

/// The signer type for the v1 signer
pub type RunningSigner = libsigner::RunningSigner<
    SignerEventReceiver<SignerMessage>,
    Vec<OperationResult>,
    SignerMessage,
>;

/// The spawned signer type for the v1 signer
pub struct SpawnedSigner {
    /// The underlying running signer thread handle
    running_signer: RunningSigner,
    /// The command sender for interacting with the running signer
    pub cmd_send: Sender<RunLoopCommand>,
    /// The result receiver for interacting with the running signer
    pub res_recv: Receiver<Vec<OperationResult>>,
}

impl From<GlobalConfig> for SpawnedSigner {
    fn from(config: GlobalConfig) -> Self {
        let endpoint = config.endpoint;
        info!("Starting signer with config: {}", config);
        let (cmd_send, cmd_recv) = channel();
        let (res_send, res_recv) = channel();
        let ev = SignerEventReceiver::new(config.network.is_mainnet());
        #[cfg(feature = "monitoring_prom")]
        {
            crate::monitoring::start_serving_monitoring_metrics(config.clone()).ok();
        }
        let runloop = RunLoop::new(config);
        let mut signer: libsigner::Signer<
            RunLoopCommand,
            Vec<OperationResult>,
            RunLoop<Signer, SignerMessage>,
            SignerEventReceiver<SignerMessage>,
            SignerMessage,
        > = libsigner::Signer::new(runloop, ev, cmd_recv, res_send);
        let running_signer = signer.spawn(endpoint).unwrap();
        SpawnedSigner {
            running_signer,
            cmd_send,
            res_recv,
        }
    }
}

impl SpawnedSigner {
    /// Stop the signer thread and return the final state
    pub fn stop(self) -> Option<Vec<OperationResult>> {
        self.running_signer.stop()
    }

    /// Wait for the signer to terminate, and get the final state. WARNING: This will hang forever if the event receiver stop signal was never sent/no error occurred.
    pub fn join(self) -> Option<Vec<OperationResult>> {
        self.running_signer.join()
    }
}
