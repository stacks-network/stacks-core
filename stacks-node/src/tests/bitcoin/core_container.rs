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
use std::time::Duration;

use testcontainers::core::WaitFor;
use testcontainers::runners::SyncRunner;
use testcontainers::{Container, GenericImage, ImageExt};

/// Default bitcoin image tag
pub const BITCOIN_DEFAULT_IMAGE_TAG: &str = "25";
/// Default RPC username used by [`BitcoinCoreContainer::new_with_defaults`].
pub const BITCOIN_RPC_USERNAME: &str = "stacksdev";
/// Default RPC password used by [`BitcoinCoreContainer::new_with_defaults`].
pub const BITCOIN_RPC_PASSWORD: &str = BITCOIN_RPC_USERNAME;
/// Internal bitcoind RPC port used for container-to-host port mapping.
const CONTAINER_INTERNAL_RPC_PORT: u16 = 18443;

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
            .add_arg(&format!("-rpcuser={BITCOIN_RPC_USERNAME}"))
            .add_arg(&format!("-rpcpassword={BITCOIN_RPC_PASSWORD}"))
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
}

impl Drop for BitcoinCoreContainer {
    fn drop(&mut self) {
        self.stop();
    }
}

mod tests {
    use super::*;

    #[test]
    fn test_start_and_stop() {
        let mut container = BitcoinCoreContainer::new(BITCOIN_DEFAULT_IMAGE_TAG);

        assert!(!container.is_started());

        container.start();
        assert!(container.is_started());
        assert_ne!(0, container.get_host_rpc_port());

        container.stop();
        assert!(!container.is_started());
    }
}
