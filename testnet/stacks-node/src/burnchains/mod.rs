use super::operations::BurnchainOpSigner;

use std::fmt;
use std::sync::Arc;
use std::time::Instant;

use reqwest::Error as ReqwestError;
use stacks::burnchains;
use stacks::burnchains::events::NewBlock;
use stacks::burnchains::indexer::BurnchainChannel;
use stacks::burnchains::Burnchain;
use stacks::chainstate::burn::db::sortdb::SortitionDB;
use stacks::chainstate::burn::operations::BlockstackOperationType;
use stacks::chainstate::burn::BlockSnapshot;
use stacks::core::StacksEpoch;

/// This module implements a burnchain controller that
/// simulates the L1 chain. This controller accepts miner
/// commitments, and uses them to produce the next simulated
/// burnchain block.
pub mod mock_events;

/// This module is for production, it's driven by the L1 chain.
pub mod l1_events;

pub mod db_indexer;

mod tests;

#[derive(Debug)]
pub enum Error {
    UnsupportedBurnchain(String),
    CoordinatorClosed,
    IndexerError(burnchains::Error),
    RPCError(String),
    BadCommitment,
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match self {
            Error::UnsupportedBurnchain(ref chain_name) => {
                write!(f, "Burnchain is not supported: {:?}", chain_name)
            }
            Error::CoordinatorClosed => write!(f, "ChainsCoordinator closed"),
            Error::IndexerError(ref e) => write!(f, "Indexer error: {:?}", e),
            Error::RPCError(ref e) => write!(f, "ControllerError(RPCError: {})", e),
            Error::BadCommitment => write!(f, "ControllerError(BadCommitment))"),
        }
    }
}

impl From<ReqwestError> for Error {
    fn from(e: ReqwestError) -> Self {
        Error::RPCError(e.to_string())
    }
}

impl From<burnchains::Error> for Error {
    fn from(e: burnchains::Error) -> Self {
        Error::IndexerError(e)
    }
}

/// The `BurnchainController` manages overall relations with the underlying burnchain.
/// In the case of a hyper-chain, the burnchain is the Stacks L1 chain.
pub trait BurnchainController {
    fn start(&mut self, target_block_height_opt: Option<u64>)
        -> Result<(BurnchainTip, u64), Error>;

    /// Returns a copy of the channel used to push
    fn get_channel(&self) -> Arc<dyn BurnchainChannel>;

    fn submit_operation(
        &mut self,
        operation: BlockstackOperationType,
        op_signer: &mut BurnchainOpSigner,
        attempt: u64,
    ) -> bool;
    fn sync(&mut self, target_block_height_opt: Option<u64>) -> Result<(BurnchainTip, u64), Error>;
    fn sortdb_ref(&self) -> &SortitionDB;
    fn sortdb_mut(&mut self) -> &mut SortitionDB;
    fn get_chain_tip(&self) -> BurnchainTip;
    fn get_headers_height(&self) -> u64;
    /// Invoke connect() on underlying burnchain and sortition databases, to perform any migration
    ///  or instantiation before other callers may use open()
    fn connect_dbs(&mut self) -> Result<(), Error>;
    fn get_stacks_epochs(&self) -> Vec<StacksEpoch>;

    fn get_burnchain(&self) -> Burnchain;
    /// Ask the burnchain controller to wait until a given sortition has been processed
    /// or if no target height is provided, wait until the sortition height has reached the
    /// burnchain height.
    fn wait_for_sortitions(
        &mut self,
        target_sortition_height: Option<u64>,
    ) -> Result<BurnchainTip, Error>;

    #[cfg(test)]
    fn bootstrap_chain(&mut self, blocks_count: u64);
}

#[derive(Debug, Clone)]
pub struct BurnchainTip {
    pub block_snapshot: BlockSnapshot,
    pub received_at: Instant,
}

pub struct PanicController();

impl BurnchainController for PanicController {
    fn start(
        &mut self,
        _target_block_height_opt: Option<u64>,
    ) -> Result<(BurnchainTip, u64), Error> {
        panic!()
    }
    fn get_channel(&self) -> Arc<dyn BurnchainChannel> {
        panic!("tbd")
    }

    fn submit_operation(
        &mut self,
        _operation: BlockstackOperationType,
        _op_signer: &mut BurnchainOpSigner,
        _attempt: u64,
    ) -> bool {
        panic!()
    }

    fn sync(
        &mut self,
        _target_block_height_opt: Option<u64>,
    ) -> Result<(BurnchainTip, u64), Error> {
        panic!()
    }

    fn sortdb_ref(&self) -> &SortitionDB {
        panic!()
    }

    fn sortdb_mut(&mut self) -> &mut SortitionDB {
        panic!()
    }

    fn get_chain_tip(&self) -> BurnchainTip {
        panic!()
    }

    fn get_headers_height(&self) -> u64 {
        panic!()
    }

    fn connect_dbs(&mut self) -> Result<(), Error> {
        panic!()
    }

    fn get_stacks_epochs(&self) -> Vec<StacksEpoch> {
        panic!()
    }

    #[cfg(test)]
    fn bootstrap_chain(&mut self, _blocks_count: u64) {
        panic!()
    }

    fn get_burnchain(&self) -> Burnchain {
        panic!()
    }

    fn wait_for_sortitions(
        &mut self,
        _target_sortition_height: Option<u64>,
    ) -> Result<BurnchainTip, Error> {
        panic!()
    }
}
