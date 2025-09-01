// Copyright (C) 2025 Stacks Open Internet Foundation
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

//! Bitcoin Core module
//!
//! This module provides convenient APIs for managing a `bitcoind` process,
//! including utilities to quickly start and stop instances for testing or
//! development purposes.

use std::io::{BufRead, BufReader};
use std::process::{Child, Command, Stdio};

use crate::burnchains::rpc::bitcoin_rpc_client::BitcoinRpcClient;
use crate::Config;

// Value usable as `BurnchainConfig::peer_port` to avoid bitcoind peer port binding
pub const BURNCHAIN_CONFIG_PEER_PORT_DISABLED: u16 = 0;

/// Errors that can occur when managing a `bitcoind` process.
#[derive(Debug, thiserror::Error)]
pub enum BitcoinCoreError {
    /// Returned when the `bitcoind` process fails to start.
    #[error("bitcoind spawn failed: {0}")]
    SpawnFailed(String),
    /// Returned when an attempt to stop the `bitcoind` process fails.
    #[error("bitcoind stop failed: {0}")]
    StopFailed(String),
    /// Returned when an attempt to forcibly kill the `bitcoind` process fails.
    #[error("bitcoind kill failed: {0}")]
    KillFailed(String),
}

type BitcoinResult<T> = Result<T, BitcoinCoreError>;

/// Represents a managed `bitcoind` process instance.
pub struct BitcoinCoreController {
    /// Handle to the spawned `bitcoind` process.
    bitcoind_process: Option<Child>,
    /// Command-line arguments used to launch the process.
    args: Vec<String>,
    /// Path to the data directory used by `bitcoind`.
    data_path: String,
    /// RPC client for communicating with the `bitcoind` instance.
    rpc_client: BitcoinRpcClient,
}

impl BitcoinCoreController {
    /// Create a [`BitcoinCoreController`] from Stacks Configuration
    pub fn from_stx_config(config: &Config) -> Self {
        let client =
            BitcoinRpcClient::from_stx_config(config).expect("rpc client creation failed!");
        Self::from_stx_config_and_client(config, client)
    }

    /// Create a [`BitcoinCoreController`] from Stacks Configuration (mainly using [`stacks::config::BurnchainConfig`])
    /// and an rpc client [`BitcoinRpcClient`]
    pub fn from_stx_config_and_client(config: &Config, client: BitcoinRpcClient) -> Self {
        let mut result = BitcoinCoreController {
            bitcoind_process: None,
            args: vec![],
            data_path: config.get_burnchain_path_str(),
            rpc_client: client,
        };

        result.add_arg("-regtest");
        result.add_arg("-nodebug");
        result.add_arg("-nodebuglogfile");
        result.add_arg("-rest");
        result.add_arg("-persistmempool=1");
        result.add_arg("-dbcache=100");
        result.add_arg("-txindex=1");
        result.add_arg("-server=1");
        result.add_arg("-listenonion=0");
        result.add_arg("-rpcbind=127.0.0.1");
        result.add_arg(format!("-datadir={}", result.data_path));

        let peer_port = config.burnchain.peer_port;
        if peer_port == BURNCHAIN_CONFIG_PEER_PORT_DISABLED {
            info!("Peer Port is disabled. So `-listen=0` flag will be used");
            result.add_arg("-listen=0");
        } else {
            result.add_arg(format!("-port={peer_port}"));
        }

        result.add_arg(format!("-rpcport={}", config.burnchain.rpc_port));

        if let (Some(username), Some(password)) =
            (&config.burnchain.username, &config.burnchain.password)
        {
            result.add_arg(format!("-rpcuser={username}"));
            result.add_arg(format!("-rpcpassword={password}"));
        }

        result
    }

    /// Add argument (like "-name=value") to be used to run bitcoind process
    pub fn add_arg(&mut self, arg: impl Into<String>) -> &mut Self {
        self.args.push(arg.into());
        self
    }

    /// Start Bitcoind process
    pub fn start_bitcoind(&mut self) -> BitcoinResult<()> {
        std::fs::create_dir_all(&self.data_path).unwrap();

        let mut command = Command::new("bitcoind");
        command.stdout(Stdio::piped());

        command.args(self.args.clone());

        info!("bitcoind spawn: {command:?}");

        let mut process = match command.spawn() {
            Ok(child) => child,
            Err(e) => return Err(BitcoinCoreError::SpawnFailed(format!("{e:?}"))),
        };

        let mut out_reader = BufReader::new(process.stdout.take().unwrap());

        let mut line = String::new();
        while let Ok(bytes_read) = out_reader.read_line(&mut line) {
            if bytes_read == 0 {
                return Err(BitcoinCoreError::SpawnFailed(
                    "Bitcoind closed before spawning network".into(),
                ));
            }
            if line.contains("Done loading") {
                break;
            }
        }

        info!("bitcoind startup finished");

        self.bitcoind_process = Some(process);

        Ok(())
    }

    /// Gracefully stop bitcoind process
    pub fn stop_bitcoind(&mut self) -> BitcoinResult<()> {
        if let Some(mut bitcoind_process) = self.bitcoind_process.take() {
            let res = self
                .rpc_client
                .stop()
                .map_err(|e| BitcoinCoreError::StopFailed(format!("{e:?}")))?;
            info!("bitcoind stop started with message: '{res}'");
            bitcoind_process
                .wait()
                .map_err(|e| BitcoinCoreError::StopFailed(format!("{e:?}")))?;
            info!("bitcoind stop finished");
        }
        Ok(())
    }

    /// Kill bitcoind process
    pub fn kill_bitcoind(&mut self) -> BitcoinResult<()> {
        if let Some(mut bitcoind_process) = self.bitcoind_process.take() {
            info!("bitcoind kill started");
            bitcoind_process
                .kill()
                .map_err(|e| BitcoinCoreError::KillFailed(format!("{e:?}")))?;
            info!("bitcoind kill finished");
        }
        Ok(())
    }

    /// Check if bitcoind process is running
    pub fn is_running(&self) -> bool {
        self.bitcoind_process.is_some()
    }
}

impl Drop for BitcoinCoreController {
    fn drop(&mut self) {
        self.kill_bitcoind().unwrap();
    }
}
