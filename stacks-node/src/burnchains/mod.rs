pub mod bitcoin;
pub mod bitcoin_regtest_controller;
pub mod rpc;

use std::time::Instant;

use stacks::burnchains;
use stacks::burnchains::BurnchainStateTransitionOps;
use stacks::chainstate::burn::operations::BlockstackOperationType;
use stacks::chainstate::burn::BlockSnapshot;
use stacks_common::codec::Error as CodecError;

pub use self::bitcoin_regtest_controller::{make_bitcoin_indexer, BitcoinRegtestController};

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
