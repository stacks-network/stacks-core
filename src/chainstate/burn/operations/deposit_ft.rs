use chainstate::burn::operations::DepositFtOp;
use burnchains::{StacksHyperOp, StacksHyperOpType, Burnchain};
use std::convert::TryFrom;
use chainstate::burn::operations::Error as op_error;
use clarity::types::chainstate::BurnchainHeaderHash;
use chainstate::burn::db::sortdb::SortitionHandleTx;
use chainstate::burn::operations::leader_block_commit::RewardSetInfo;

impl TryFrom<&StacksHyperOp> for DepositFtOp {
    type Error = op_error;

    fn try_from(value: &StacksHyperOp) -> Result<Self, Self::Error> {
        if let StacksHyperOpType::DepositFt {
            ref l1_contract_id,
            ref hc_contract_id,
            ref name,
            ref amount,
            ref sender,
        } = value.event {
            Ok(DepositFtOp {
                txid: value.txid.clone(),
                // use the StacksBlockId in the L1 event as the burnchain header hash
                burn_header_hash: BurnchainHeaderHash(value.in_block.0.clone()),
                l1_contract_id: l1_contract_id.clone(),
                hc_contract_id: hc_contract_id.clone(),
                name: name.clone(),
                amount: amount.clone(),
                sender: sender.clone()
            })
        } else {
            Err(op_error::InvalidInput)
        }
    }
}


impl DepositFtOp {
    pub fn check(
        &self,
        _burnchain: &Burnchain,
        _tx: &mut SortitionHandleTx,
        _reward_set_info: Option<&RewardSetInfo>,
    ) -> Result<(), op_error> {
        // good to go!
        Ok(())
    }

    #[cfg(test)]
    pub fn set_burn_height(&mut self, _height: u64) {}
}
