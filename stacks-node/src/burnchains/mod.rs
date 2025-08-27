pub mod bitcoin;
pub mod bitcoin_regtest_controller;
pub mod mocknet_controller;
pub mod rpc;

use std::time::Instant;

use stacks::burnchains;
use stacks::burnchains::{BurnchainStateTransitionOps, Txid};
use stacks::chainstate::burn::db::sortdb::SortitionDB;
use stacks::chainstate::burn::operations::BlockstackOperationType;
use stacks::chainstate::burn::BlockSnapshot;
use stacks::core::{EpochList, StacksEpochId};
use stacks_common::codec::Error as CodecError;

pub use self::bitcoin_regtest_controller::{make_bitcoin_indexer, BitcoinRegtestController};
pub use self::mocknet_controller::MocknetController;
use super::operations::BurnchainOpSigner;

#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error("ChainsCoordinator closed")]
    CoordinatorClosed,
    #[error("Indexer error: {0}")]
    IndexerError(#[from] burnchains::Error),
    #[error("Burnchain error")]
    BurnchainError,
    #[error("Max fee rate exceeded")]
    MaxFeeRateExceeded,
    #[error("Identical operation, not submitting")]
    IdenticalOperation,
    #[error("No UTXOs available")]
    NoUTXOs,
    #[error("Transaction submission failed: {0}")]
    TransactionSubmissionFailed(String),
    #[error("Serializer error: {0}")]
    SerializerError(CodecError),
}

impl PartialEq for Error {
    fn eq(&self, other: &Self) -> bool {
        use Error::*;
        match (self, other) {
            (CoordinatorClosed, CoordinatorClosed)
            | (IndexerError(_), IndexerError(_))
            | (BurnchainError, BurnchainError)
            | (MaxFeeRateExceeded, MaxFeeRateExceeded)
            | (IdenticalOperation, IdenticalOperation)
            | (NoUTXOs, NoUTXOs)
            | (TransactionSubmissionFailed(_), TransactionSubmissionFailed(_))
            | (SerializerError(_), SerializerError(_)) => true,
            _ => false,
        }
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
    ) -> Result<Txid, Error>;
    fn sync(&mut self, target_block_height_opt: Option<u64>) -> Result<(BurnchainTip, u64), Error>;
    fn sortdb_ref(&self) -> &SortitionDB;
    fn sortdb_mut(&mut self) -> &mut SortitionDB;
    fn get_chain_tip(&self) -> BurnchainTip;
    fn get_headers_height(&self) -> u64;
    /// Invoke connect() on underlying burnchain and sortition databases, to perform any migration
    ///  or instantiation before other callers may use open()
    fn connect_dbs(&mut self) -> Result<(), Error>;
    fn get_stacks_epochs(&self) -> EpochList;

    #[cfg(test)]
    fn bootstrap_chain(&self, blocks_count: u64);
}

#[derive(Debug, Clone)]
pub struct BurnchainTip {
    pub block_snapshot: BlockSnapshot,
    pub state_transition: BurnchainStateTransitionOps,
    pub received_at: Instant,
}

impl BurnchainTip {
    pub fn get_winning_tx_index(&self) -> Option<u32> {
        let winning_tx_id = &self.block_snapshot.winning_block_txid;
        let mut winning_tx_vtindex = None;

        for op in self.state_transition.accepted_ops.iter() {
            if let BlockstackOperationType::LeaderBlockCommit(op) = op {
                if &op.txid == winning_tx_id {
                    winning_tx_vtindex = Some(op.vtxindex)
                }
            }
        }
        winning_tx_vtindex
    }
}
