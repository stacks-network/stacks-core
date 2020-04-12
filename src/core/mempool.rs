use burnchains::BurnchainHeaderHash;
use chainstate::burn::BlockHeaderHash;
use chainstate::stacks::{
    StacksTransaction,
    db::StacksChainState,
    db::blocks::MemPoolRejection
};
use std::io::Read;

pub struct MempoolAdmitter {
    // mempool admission should have its own chain state view.
    //   the mempool admitter interacts with the chain state
    //   exclusively in read-only fashion, however, it should have
    //   its own instance of things like the MARF index, because otherwise
    //   mempool admission tests would block with chain processing.
    chainstate: StacksChainState,
    cur_block: BlockHeaderHash,
    cur_burn_block: BurnchainHeaderHash,
}

impl MempoolAdmitter {
    pub fn new(chainstate: StacksChainState, cur_block: BlockHeaderHash, cur_burn_block: BurnchainHeaderHash) -> MempoolAdmitter {
        MempoolAdmitter { chainstate, cur_block, cur_burn_block }
    }

    pub fn set_block(&mut self, cur_block: &BlockHeaderHash, cur_burn_block: &BurnchainHeaderHash) {
        self.cur_burn_block = cur_burn_block.clone();
        self.cur_block = cur_block.clone();
    }

    pub fn will_admit_tx<R: Read>(&mut self, tx: &mut R) -> Result<StacksTransaction, MemPoolRejection> {
        self.chainstate.will_admit_mempool_tx(&self.cur_burn_block, &self.cur_block, tx)
    }
}

