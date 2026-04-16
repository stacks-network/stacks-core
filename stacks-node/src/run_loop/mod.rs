pub mod boot_nakamoto;
pub mod nakamoto;
pub mod neon;

use clarity::vm::costs::ExecutionCost;
use stacks::burnchains::{PoxConstants, Txid};
use stacks::chainstate::stacks::db::StacksChainState;
use stacks::chainstate::stacks::events::StacksTransactionReceipt;
use stacks::chainstate::stacks::StacksBlock;
use stacks_common::types::chainstate::StacksBlockId;
use stacks_common::util::vrf::VRFPublicKey;

use crate::stacks::chainstate::coordinator::BlockEventDispatcher;
use crate::stacks::chainstate::stacks::index::ClarityMarfTrieId;
use crate::EventDispatcher;

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct RegisteredKey {
    /// burn block height we intended this VRF key register to land in
    pub target_block_height: u64,
    /// burn block height it actually landed in
    pub block_height: u64,
    /// offset in the block's tx list where this operation is
    pub op_vtxindex: u32,
    /// the public key itself
    pub vrf_public_key: VRFPublicKey,
    /// `memo` field that was used to register key
    /// Could be `Hash160(miner_pubkey)`, or empty
    pub memo: Vec<u8>,
}

pub fn announce_boot_receipts(
    event_dispatcher: &mut EventDispatcher,
    chainstate: &StacksChainState,
    pox_constants: &PoxConstants,
    boot_receipts: &[StacksTransactionReceipt],
) {
    let block_header_0 = StacksChainState::get_genesis_header_info(chainstate.db())
        .expect("FATAL: genesis block header not stored");
    let block_0 = StacksBlock {
        header: block_header_0
            .anchored_header
            .as_stacks_epoch2()
            .expect("FATAL: Expected a Stacks 2.0 Genesis block")
            .clone(),
        txs: vec![],
    };

    debug!("Push {} boot receipts", &boot_receipts.len());
    event_dispatcher.announce_block(
        &block_0.into(),
        &block_header_0,
        boot_receipts,
        &StacksBlockId::sentinel(),
        &Txid([0x00; 32]),
        &[],
        None,
        &block_header_0.burn_header_hash,
        block_header_0.burn_header_height,
        block_header_0.burn_header_timestamp,
        &ExecutionCost::ZERO,
        &ExecutionCost::ZERO,
        pox_constants,
        &None,
        &None,
        None,
        0,
    );
}
