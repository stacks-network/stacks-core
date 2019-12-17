pub mod run_loop; 
pub mod mem_pool;
pub mod keychain;
pub mod burnchain;
pub mod leader;

pub use self::run_loop::{RunLoop};
pub use self::mem_pool::{MemPoolFS};
pub use self::keychain::{Keychain};
pub use self::leader::{Leader, SortitionedBlock};
pub use self::burnchain::{BurnchainSimulator};

pub struct Config {
    pub testnet_name: String,
    pub chain: String,
    pub burchain_path: String,
    pub burchain_block_time: u64,
    pub leader_config: Vec<LeaderConfig>
}

#[derive(Clone)]
pub struct LeaderConfig {
    pub name: String,
    pub path: String,
    pub mem_pool_path: String,
}
