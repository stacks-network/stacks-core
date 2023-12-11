use stacks_common::types::chainstate::SortitionId;

use crate::vm::StacksEpoch;

use super::{ClarityDb, Result};

pub trait ClarityDbBurnchain: ClarityDb {
    fn get_burn_block_height(&self, sortition_id: &SortitionId) -> Result<Option<u32>>;

    /// This function obtains the stacks epoch version, which is based on the burn block height.
    /// Valid epochs include stacks 1.0, 2.0, 2.05, and so on.
    fn get_stacks_epoch(&self, height: u32) -> Result<Option<StacksEpoch>>;
}