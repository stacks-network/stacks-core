pub mod bitcoin_regtest_controller;
pub mod mocknet_controller;

use std::fmt;
use std::time::Instant;

use stacks::burnchains;
use stacks::burnchains::{BurnchainStateTransitionOps, Txid};
use stacks::chainstate::burn::db::sortdb::SortitionDB;
use stacks::chainstate::burn::operations::BlockstackOperationType;
use stacks::chainstate::burn::BlockSnapshot;
use stacks::core::{StacksEpoch, StacksEpochId};

pub use self::bitcoin_regtest_controller::{make_bitcoin_indexer, BitcoinRegtestController};
pub use self::mocknet_controller::MocknetController;
use super::operations::BurnchainOpSigner;

#[derive(Debug)]
pub enum Error {
    CoordinatorClosed,
    IndexerError(burnchains::Error),
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match self {
            Error::CoordinatorClosed => write!(f, "ChainsCoordinator closed"),
            Error::IndexerError(ref e) => write!(f, "Indexer error: {:?}", e),
        }
    }
}

impl From<burnchains::Error> for Error {
    fn from(e: burnchains::Error) -> Self {
        Error::IndexerError(e)
    }
}

pub trait BurnchainController {
    fn start(&mut self, target_block_height_opt: Option<u64>)
        -> Result<(BurnchainTip, u64), Error>;
    fn submit_operation(
        &mut self,
        epoch_id: StacksEpochId,
        operation: BlockstackOperationType,
        op_signer: &mut BurnchainOpSigner,
        attempt: u64,
    ) -> Option<Txid>;
    fn sync(&mut self, target_block_height_opt: Option<u64>) -> Result<(BurnchainTip, u64), Error>;
    fn sortdb_ref(&self) -> &SortitionDB;
    fn sortdb_mut(&mut self) -> &mut SortitionDB;
    fn get_chain_tip(&self) -> BurnchainTip;
    fn get_headers_height(&self) -> u64;
    /// Invoke connect() on underlying burnchain and sortition databases, to perform any migration
    ///  or instantiation before other callers may use open()
    fn connect_dbs(&mut self) -> Result<(), Error>;
    fn get_stacks_epochs(&self) -> Vec<StacksEpoch>;

    #[cfg(test)]
    fn bootstrap_chain(&mut self, blocks_count: u64);
}

#[derive(Debug, Clone)]
pub struct BurnchainTip {
    pub block_snapshot: BlockSnapshot,
    pub state_transition: BurnchainStateTransitionOps,
    pub received_at: Instant,
}

impl BurnchainTip {
    pub fn get_winning_tx_index(&self) -> Option<u32> {
        let winning_tx_id = self.block_snapshot.winning_block_txid;
        let mut winning_tx_vtindex = None;

        for op in self.state_transition.accepted_ops.iter() {
            if let BlockstackOperationType::LeaderBlockCommit(op) = op {
                if op.txid == winning_tx_id {
                    winning_tx_vtindex = Some(op.vtxindex)
                }
            }
        }
        winning_tx_vtindex
    }
}
