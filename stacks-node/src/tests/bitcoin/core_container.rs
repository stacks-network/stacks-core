use std::cell::OnceCell;
use std::time::Duration;

use testcontainers::core::WaitFor;
use testcontainers::runners::SyncRunner;
use testcontainers::{Container, GenericImage, ImageExt};

pub const RPC_USERNAME: &str = "stacksdev";
pub const RPC_PASSWORD: &str = RPC_USERNAME;

pub struct BitcoinCoreContainer {
    image_tag: String,
    raw_container: OnceCell<Container<GenericImage>>,
    /// Command-line arguments used to launch the process.
    args: Vec<String>,
}

impl BitcoinCoreContainer {
    /*
    pub fn from_stx_config(config: &Config, image_tag: &str) -> Self {
        let mut result = BitcoinCoreContainer::new_with_defaults(image_tag);

        if let (Some(username), Some(password)) =
            (&config.burnchain.username, &config.burnchain.password)
        {
            result
                .add_arg(format!("-rpcuser={username}"))
                .add_arg(format!("-rpcpassword={password}"));
        }

        result
    }
    */

    pub fn new(image_tag: &str) -> Self {
        BitcoinCoreContainer {
            image_tag: image_tag.into(),
            raw_container: OnceCell::new(),
            args: vec![],
        }
    }

    pub fn new_with_defaults(image_tag: &str) -> Self {
        let mut result = Self::new(image_tag);
        result
            .set_arg("-regtest=1")
            .set_arg("-server=1")
            .set_arg("-txindex=1")
            .set_arg("-dnsseed=0")
            .set_arg("-dns=0")
            .set_arg("-discover=0")
            .set_arg("-listenonion=0")
            .set_arg("-rest=1")
            .set_arg("-rpcbind=0.0.0.0")
            .set_arg("-rpcallowip=0.0.0.0/0")
            .set_arg("-rpcallowip=::/0")
            .set_arg(format!("-rpcuser={}", RPC_USERNAME))
            .set_arg(format!("-rpcpassword={}", RPC_PASSWORD))
            .set_arg("-fallbackfee=0.00001");
        result
    }

    /// Add argument (like "-name=value") to be used to run bitcoind process
    pub fn set_arg(&mut self, arg: impl Into<String>) -> &mut Self {
        if self.is_started() {
            panic!("the container is already started");
        }

        self.args.push(arg.into());
        self
    }

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

    pub fn stop(&mut self) {
        if let Some(container) = self.raw_container.take() {
            drop(container);
        }
    }

    pub fn is_started(&self) -> bool {
        self.raw_container.get().is_some()
    }

    pub fn get_rpc_port(&self) -> u16 {
        if !self.is_started() {
            panic!("the container has not been started yet");
        }

        self.raw_container
            .get()
            .unwrap()
            .get_host_port_ipv4(18443)
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
        let mut container = BitcoinCoreContainer::new("25");
        container.set_arg("-chain=regtest").set_arg("-server");

        assert!(!container.is_started());

        container.start();
        assert!(container.is_started());
        assert_ne!(0, container.get_rpc_port());

        container.stop();
        assert!(!container.is_started());
    }
}
