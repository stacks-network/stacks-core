use crate::config::BurnchainConfig;

use super::operations::BurnchainOpSigner;

use std::fmt;
use std::sync::Arc;
use std::time::Instant;

use self::commitment::Error as CommitmentError;
use reqwest::Error as ReqwestError;
use stacks::burnchains;
use stacks::burnchains::indexer::BurnchainChannel;
use stacks::burnchains::Burnchain;
use stacks::burnchains::Txid;
use stacks::chainstate::burn::db::sortdb::SortitionDB;
use stacks::chainstate::burn::BlockSnapshot;
use stacks::chainstate::stacks::index::ClarityMarfTrieId;
use stacks::chainstate::stacks::miner::Proposal;
use stacks::core::StacksEpoch;
use stacks::types::chainstate::BlockHeaderHash;
use stacks::types::chainstate::BurnchainHeaderHash;
use stacks::util::hash::Sha512Trunc256Sum;

/// This module implements a burnchain controller that
/// simulates the L1 chain. This controller accepts miner
/// commitments, and uses them to produce the next simulated
/// burnchain block.
pub mod mock_events;

/// This module is for production, it's driven by the L1 chain.
pub mod l1_events;

pub mod db_indexer;

/// This module defines structs for producing block commitments
pub mod commitment;

#[cfg(test)]
mod tests;

#[derive(Debug)]
pub enum Error {
    UnsupportedBurnchain(String),
    CoordinatorClosed,
    IndexerError(burnchains::Error),
    RPCError(String),
    BadCommitment(CommitmentError),
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
            Error::BadCommitment(ref e) => write!(f, "ControllerError(BadCommitment: {}))", e),
        }
    }
}

impl From<ReqwestError> for Error {
    fn from(e: ReqwestError) -> Self {
        Error::RPCError(e.to_string())
    }
}

impl From<CommitmentError> for Error {
    fn from(e: CommitmentError) -> Self {
        Error::BadCommitment(e)
    }
}

impl From<burnchains::Error> for Error {
    fn from(e: burnchains::Error) -> Self {
        Error::IndexerError(e)
    }
}

pub struct ClaritySignature([u8; 65]);

/// The `BurnchainController` manages overall relations with the underlying burnchain.
/// In the case of a hyper-chain, the burnchain is the Stacks L1 chain.
pub trait BurnchainController {
    fn start(&mut self, target_block_height_opt: Option<u64>)
        -> Result<(BurnchainTip, u64), Error>;

    /// Returns a copy of the channel used to push
    fn get_channel(&self) -> Arc<dyn BurnchainChannel>;

    fn submit_commit(
        &mut self,
        committed_block_hash: BlockHeaderHash,
        target_burn_chain: BurnchainHeaderHash,
        withdrawal_merkle_root: Sha512Trunc256Sum,
        signatures: Vec<ClaritySignature>,
        op_signer: &mut BurnchainOpSigner,
        attempt: u64,
    ) -> Result<Txid, Error>;

    /// Returns the number of signatures necessary to provide
    /// to the block committer.
    fn commit_required_signatures(&self) -> u8;
    fn propose_block(
        &self,
        participant_index: u8,
        proposal: &Proposal,
    ) -> Result<ClaritySignature, Error>;

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

    fn submit_commit(
        &mut self,
        _committed_block_hash: BlockHeaderHash,
        _target_block: BurnchainHeaderHash,
        _withdrawal_merkle_root: Sha512Trunc256Sum,
        _signatures: Vec<ClaritySignature>,
        _op_signer: &mut BurnchainOpSigner,
        _attempt: u64,
    ) -> Result<Txid, Error> {
        panic!()
    }

    fn commit_required_signatures(&self) -> u8 {
        panic!()
    }

    fn propose_block(
        &self,
        _participant_index: u8,
        _proposal: &Proposal,
    ) -> Result<ClaritySignature, Error> {
        panic!()
    }
}

/// Build a `Burnchain` from values in `config`. Call `Burnchain::new`, which sets defaults
/// and then override the "first block" information using `config`.
pub fn burnchain_from_config(
    burn_db_path: &str,
    config: &BurnchainConfig,
) -> Result<Burnchain, burnchains::Error> {
    let mut burnchain = Burnchain::new(&burn_db_path, &config.chain)?;
    burnchain.first_block_hash = BurnchainHeaderHash::sentinel();
    burnchain.first_block_height = config.first_burn_header_height;
    burnchain.first_block_timestamp = 0;

    debug!("Configured burnchain: {:?}", &burnchain);
    Ok(burnchain)
}
