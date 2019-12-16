pub mod run_loop; 
pub mod mem_pool;
pub mod keychain;
pub mod burnchain;
pub mod leader;

pub use self::run_loop::{RunLoop};
pub use self::mem_pool::{MemPoolFS};
pub use self::keychain::{Keychain};
pub use self::leader::{Leader};
pub use self::burnchain::{BurnchainSimulator};

use std::fs;
use std::env;
use std::process;
use net::StacksMessageCodec;
use chainstate::stacks::*;
use util::hash::hex_bytes;

use chainstate::stacks::db::StacksChainState;
use chainstate::stacks::{StacksBlock, StacksMicroblock, CoinbasePayload};
use chainstate::burn::db::burndb::{BurnDB};
use address::AddressHashMode;
use burnchains::{Burnchain, BurnchainHeaderHash, Txid, PrivateKey};
use chainstate::stacks::{StacksPrivateKey};
use chainstate::burn::operations::{LeaderKeyRegisterOp, LeaderBlockCommitOp};
use chainstate::burn::SortitionHash;
use util::vrf::{VRF, VRFProof, VRFPublicKey, VRFPrivateKey};
use util::hash::Sha256Sum;
use std::collections::HashMap;
use rusqlite::{Connection, OpenFlags, NO_PARAMS};
use rand::RngCore;
use util::hash::{to_hex};
use std::{thread, time};

pub struct Config {
    pub testnet_name: String,
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

pub trait MemPool <'a> {
    fn start(&mut self);
    fn stop(&mut self);
    fn reset(&mut self);
    fn handle_incoming_tx(&mut self, tx: Txid);
    fn archive_tx(&mut self, tx: Txid);
    fn register_observer(&mut self, observer: &'a mut MemPoolObserver);
    fn unregister_observer(&mut self, observer: &'a mut MemPoolObserver);
}

pub trait MemPoolObserver {
    fn handle_received_tx(&mut self, tx: Txid);
    fn handle_archived_tx(&mut self, tx: Txid);
}


