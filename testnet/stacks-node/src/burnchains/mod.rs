pub mod mocknet_controller;
pub mod bitcoin_regtest_controller;

pub use self::mocknet_controller::{MocknetController};
pub use self::bitcoin_regtest_controller::{BitcoinRegtestController};

use super::operations::BurnchainOpSigner;

use std::time::Instant;

use stacks::burnchains::BurnchainStateTransition;
use stacks::chainstate::burn::db::burndb::{BurnDB};
use stacks::chainstate::burn::{BlockSnapshot};
use stacks::chainstate::burn::operations::BlockstackOperationType;

pub trait BurnchainController {
    fn start(&mut self) -> BurnchainTip;
    fn submit_operation(&mut self, operation: BlockstackOperationType, op_signer: &mut BurnchainOpSigner) -> bool;
    fn sync(&mut self) -> BurnchainTip;
    fn burndb_ref(&self) -> &BurnDB;
    fn burndb_mut(&mut self) -> &mut BurnDB;
    fn get_chain_tip(&mut self) -> BurnchainTip;

    #[cfg(test)]
    fn bootstrap_chain(&mut self, blocks_count: u64);
}

#[derive(Debug, Clone)]
pub struct BurnchainTip {
    pub block_snapshot: BlockSnapshot,
    pub state_transition: BurnchainStateTransition,
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

