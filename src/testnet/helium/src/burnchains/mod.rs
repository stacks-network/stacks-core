pub mod mock_burnchain_controller;
pub mod bitcoin_regtest_controller;

pub use self::mock_burnchain_controller::{MockBurnchainController};
pub use self::bitcoin_regtest_controller::{BitcoinRegtestController};

use super::operations::{BurnchainOperationType, BurnchainOpSigner};

use stacks::burnchains::{BurnchainStateTransition};
use stacks::chainstate::burn::db::burndb::{BurnDB};
use stacks::chainstate::burn::{BlockSnapshot};

#[derive(Debug, Clone)]
pub struct BurnchainTip {
    pub block_snapshot: BlockSnapshot,
    pub state_transition: BurnchainStateTransition,
}

pub trait BurnchainController {
    fn start(&mut self) -> BurnchainTip;
    fn submit_operation(&mut self, operation: BurnchainOperationType, op_signer: &mut BurnchainOpSigner);
    fn sync(&mut self) -> BurnchainTip;
    fn burndb_mut(&mut self) -> &mut BurnDB;
    fn get_chain_tip(&mut self) -> BurnchainTip;
}