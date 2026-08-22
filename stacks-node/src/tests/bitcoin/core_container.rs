// Copyright (C) 2026 Stacks Open Internet Foundation
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

//! Test helper for running a Bitcoin Core `bitcoind` regtest node in Docker.
//!
//! This module wraps a `testcontainers` container and exposes a small API to:
//! start/stop the node, add startup arguments before launch, and discover the
//! mapped host RPC port. The image is pulled from the `bitcoin/bitcoin`
//! repository.

use std::cell::OnceCell;
use std::env;
use std::time::Duration;

use stacks::config::Config;
use testcontainers::core::{IntoContainerPort, WaitFor};
use testcontainers::runners::SyncRunner;
use testcontainers::{Container, GenericImage, ImageExt};

use crate::burnchains::bitcoin::core_controller::BitcoinCoreController;
use crate::tests::test_port;

/// Default bitcoin image tag
pub const BITCOIN_DEFAULT_IMAGE_TAG: &str = "25";
/// Default RPC username used by [`BitcoinCoreContainer::new_with_defaults`].
pub const BITCOIN_RPC_USERNAME: &str = "stacksdev";
/// Default RPC password used by [`BitcoinCoreContainer::new_with_defaults`].
pub const BITCOIN_RPC_PASSWORD: &str = BITCOIN_RPC_USERNAME;
/// Internal bitcoind RPC port used for container-to-host port mapping.
const CONTAINER_INTERNAL_RPC_PORT: u16 = 18443;
/// Internal bitcoind P2P port used for container-to-host port mapping.
const CONTAINER_INTERNAL_P2P_PORT: u16 = 18444;

/// Wrapper for a Bitcoin Core test container.
///
/// Build configuration by calling [`Self::add_arg`] (or use
/// [`Self::new_with_defaults`]), then call [`Self::start`] once.
/// After startup, use [`Self::get_host_rpc_port`] to connect via RPC.
pub struct BitcoinCoreContainer {
    image_tag: String,
    raw_container: OnceCell<Container<GenericImage>>,
    /// Command-line arguments used to launch the process.
    args: Vec<String>,
}

impl BitcoinCoreContainer {
    /// Create a container for `bitcoin/bitcoin:<image_tag>` with no args.
    ///
    /// Add process arguments with [`Self::add_arg`] before calling [`Self::start`].
    pub fn new(image_tag: &str) -> Self {
        BitcoinCoreContainer {
            image_tag: image_tag.into(),
            raw_container: OnceCell::new(),
            args: vec![],
        }
    }

    /// Create a container with regtest defaults.
    pub fn new_with_defaults(image_tag: &str) -> Self {
        Self::new_with_credentials(image_tag, BITCOIN_RPC_USERNAME, BITCOIN_RPC_PASSWORD)
    }

    /// Create a regtest container with the supplied RPC credentials.
    pub fn new_with_credentials(image_tag: &str, rpc_username: &str, rpc_password: &str) -> Self {
        let mut result = Self::new(image_tag);
        result
            .add_arg("-regtest=1")
            .add_arg("-server=1")
            .add_arg("-txindex=1")
            .add_arg("-dnsseed=0")
            .add_arg("-dns=0")
            .add_arg("-discover=0")
            .add_arg("-listenonion=0")
            .add_arg("-rest=1")
            .add_arg("-rpcbind=0.0.0.0")
            .add_arg("-rpcallowip=0.0.0.0/0")
            .add_arg("-rpcallowip=::/0")
            .add_arg(&format!("-rpcuser={rpc_username}"))
            .add_arg(&format!("-rpcpassword={rpc_password}"))
            .add_arg("-fallbackfee=0.00001");
        result
    }

    /// Add argument (like "-name=value") to be used to run bitcoind process
    ///
    /// Panics if the container has already been started.
    pub fn add_arg(&mut self, arg: &str) -> &mut Self {
        if self.is_started() {
            panic!("the container is already started");
        }

        self.args.push(arg.into());
        self
    }

    /// Start the container and wait for bitcoind readiness.
    ///
    /// Readiness is detected from the `Done loading` stdout message.
    /// Panics if called more than once.
    pub fn start(&mut self) {
        if self.is_started() {
            panic!("the container is already started");
        }

        let container = GenericImage::new("bitcoin/bitcoin", &self.image_tag)
            .with_wait_for(WaitFor::message_on_stdout("Done loading"))
            .with_exposed_port(CONTAINER_INTERNAL_RPC_PORT.tcp())
            .with_exposed_port(CONTAINER_INTERNAL_P2P_PORT.tcp())
            .with_startup_timeout(Duration::from_secs(60))
            .with_cmd(self.args.clone())
            .start()
            .expect("Failed to start bitcoind container");

        _ = self.raw_container.set(container);
    }

    /// Stop the container if it is currently running.
    ///
    /// This method is idempotent; calling it on a stopped container is a no-op.
    pub fn stop(&mut self) {
        if let Some(container) = self.raw_container.take() {
            drop(container);
        }
    }

    /// Return `true` when the underlying test container has been started.
    pub fn is_started(&self) -> bool {
        self.raw_container.get().is_some()
    }

    /// Get the host-mapped RPC port for the internal Bitcoin Core RPC port.
    ///
    /// Panics if the container has not been started yet.
    pub fn get_host_rpc_port(&self) -> u16 {
        if !self.is_started() {
            panic!("the container has not been started yet");
        }

        self.raw_container
            .get()
            .unwrap()
            .get_host_port_ipv4(CONTAINER_INTERNAL_RPC_PORT)
            .expect("Failed to get mapped RPC port")
    }

    /// Get the host-mapped P2P port for the internal Bitcoin Core P2P port.
    ///
    /// Panics if the container has not been started yet.
    pub fn get_host_p2p_port(&self) -> u16 {
        if !self.is_started() {
            panic!("the container has not been started yet");
        }

        self.raw_container
            .get()
            .unwrap()
            .get_host_port_ipv4(CONTAINER_INTERNAL_P2P_PORT)
            .expect("Failed to get mapped P2P port")
    }
}

impl Drop for BitcoinCoreContainer {
    fn drop(&mut self) {
        self.stop();
    }
}

/// Bitcoin daemon owned by an integration test.
pub struct BitcoinTestDaemon {
    backend: BitcoinTestDaemonBackend,
}

enum BitcoinTestDaemonBackend {
    Native(BitcoinCoreController),
    Container(Box<BitcoinCoreContainer>),
}

impl BitcoinTestDaemon {
    /// Start a container when requested and the test uses standard burnchain
    /// ports. Tests using snapshots or custom proxy ports retain native
    /// `bitcoind` behavior.
    pub fn start(config: &mut Config) -> Self {
        let use_container = env::var("BITCOIN_TESTCONTAINERS") == Ok("1".into())
            && env::var("STACKS_TEST_SNAPSHOT") != Ok("1".into())
            && config.burnchain.rpc_port == test_port(18443)
            && config.burnchain.peer_port == test_port(18444);

        let backend = if use_container {
            let image_tag = env::var("BITCOIN_IMAGE_TAG")
                .ok()
                .filter(|tag| !tag.trim().is_empty())
                .unwrap_or_else(|| BITCOIN_DEFAULT_IMAGE_TAG.into());
            let username = config
                .burnchain
                .username
                .as_deref()
                .expect("Bitcoin integration tests require an RPC username");
            let password = config
                .burnchain
                .password
                .as_deref()
                .expect("Bitcoin integration tests require an RPC password");
            let mut container =
                BitcoinCoreContainer::new_with_credentials(&image_tag, username, password);
            container.start();
            config.burnchain.rpc_port = container.get_host_rpc_port();
            config.burnchain.peer_port = container.get_host_p2p_port();
            info!(
                "Started integration-test bitcoind container";
                "rpc_port" => config.burnchain.rpc_port,
                "peer_port" => config.burnchain.peer_port,
            );
            BitcoinTestDaemonBackend::Container(Box::new(container))
        } else {
            let mut controller = BitcoinCoreController::from_stx_config(config);
            controller
                .start_bitcoind()
                .map_err(|_e| ())
                .expect("Failed starting bitcoind");
            BitcoinTestDaemonBackend::Native(controller)
        };

        Self { backend }
    }

    /// Stop the owned daemon.
    pub fn stop(&mut self) {
        match &mut self.backend {
            BitcoinTestDaemonBackend::Native(controller) => controller.stop_bitcoind().unwrap(),
            BitcoinTestDaemonBackend::Container(container) => container.stop(),
        }
    }
}

mod tests {
    use pinny::tag;

    use super::*;

    #[tag(ci_skip)]
    #[test]
    #[ignore = "temporary promoted to integration test to exclude it from unit-test execution"]
    fn test_start_and_stop() {
        let mut container = BitcoinCoreContainer::new(BITCOIN_DEFAULT_IMAGE_TAG);

        assert!(!container.is_started());

        container.start();
        assert!(container.is_started());
        assert_ne!(0, container.get_host_rpc_port());
        assert_ne!(0, container.get_host_p2p_port());
        assert_ne!(container.get_host_rpc_port(), container.get_host_p2p_port());

        container.stop();
        assert!(!container.is_started());
    }
}
