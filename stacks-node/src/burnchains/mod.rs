pub mod bitcoin;
pub mod bitcoin_regtest_controller;
pub mod rpc;

use stacks::burnchains;
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
        matches!(
            (self, other),
            (CoordinatorClosed, CoordinatorClosed)
                | (IndexerError(_), IndexerError(_))
                | (BurnchainError, BurnchainError)
                | (MaxFeeRateExceeded, MaxFeeRateExceeded)
                | (IdenticalOperation, IdenticalOperation)
                | (NoUTXOs, NoUTXOs)
                | (
                    TransactionSubmissionFailed(_),
                    TransactionSubmissionFailed(_)
                )
                | (SerializerError(_), SerializerError(_))
        )
    }
}
