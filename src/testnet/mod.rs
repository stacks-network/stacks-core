pub mod run_loop; 
pub mod mem_pool;
pub mod keychain;
pub mod burnchain;
pub mod node;
pub mod tenure;

pub use self::run_loop::{RunLoop};
pub use self::mem_pool::{MemPool, MemPoolFS};
pub use self::keychain::{Keychain};
pub use self::node::{Node, SortitionedBlock};
pub use self::burnchain::{BurnchainSimulator, BurnchainState};
pub use self::tenure::{LeaderTenure};

use std::net::SocketAddr;

#[derive(Clone)]
pub struct Config {
    pub testnet_name: String,
    pub chain: String,
    pub burnchain_path: String,
    pub burnchain_block_time: u64,
    pub node_config: Vec<NodeConfig>,
    pub sidecar_socket_address: Option<SocketAddr>,
    pub sidecar_stream_blocks: bool,
    pub sidecar_stream_transactions: bool,
}

#[derive(Clone)]
pub struct NodeConfig {
    pub name: String,
    pub path: String,
    pub mem_pool_path: String,
}

#[cfg(test)]
pub mod tests;
