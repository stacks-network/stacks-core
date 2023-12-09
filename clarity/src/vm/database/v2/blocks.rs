use stacks_common::types::chainstate::{StacksBlockId, BlockHeaderHash, BurnchainHeaderHash, VRFSeed, SortitionId};
use crate::vm::{types::{StandardPrincipalData, TupleData}, errors::InterpreterResult as Result};
use super::ClarityDb;

pub trait ClarityDbBlocks: ClarityDb {
    /// Returns the ID of a *Stacks* block, by a *Stacks* block height.
    ///
    /// Fails if `block_height` >= the "currently" under construction Stacks block height.
    fn get_index_block_header_hash(&mut self, block_height: u32) -> Result<StacksBlockId>;

    /// This is the height we are currently constructing. It comes from the MARF.
    fn get_current_block_height(&mut self) -> Result<u32>;

    /// Return the height for PoX v1 -> v2 auto unlocks
    ///   from the burn state db
    fn get_v1_unlock_height(&self) -> Result<u32>;

    /// Return the height for PoX 3 activation from the burn state db
    fn get_pox_3_activation_height(&self) -> Result<u32>;

    /// Return the height for PoX 4 activation from the burn state db
    fn get_pox_4_activation_height(&self) -> Result<u32>;

    /// Return the height for PoX v2 -> v3 auto unlocks
    ///   from the burn state db
    fn get_v2_unlock_height(&mut self) -> Result<u32>;

    /// Return the height for PoX v3 -> v4 auto unlocks
    ///   from the burn state db
    fn get_v3_unlock_height(&mut self) -> Result<u32>;

    /// Get the last-known burnchain block height.
    /// Note that this is _not_ the burnchain height in which this block was mined!
    /// This is the burnchain block height of the parent of the Stacks block at the current Stacks
    /// block height (i.e. that returned by `get_index_block_header_hash` for
    /// `get_current_block_height`).
    fn get_current_burnchain_block_height(&mut self) -> Result<u32>;

    /// Gets the [BlockHeaderHash] of the Stacks block at the given Stacks block height.
    /// TODO: Check description
    fn get_block_header_hash(&mut self, block_height: u32) -> Result<BlockHeaderHash>;

    /// Gets the block time of the Stacks block at the given Stacks block height.
    /// /// TODO: Check description
    fn get_block_time(&mut self, block_height: u32) -> Result<u64>;

    /// Gets the [BurnchainHeaderHash] of the burnchain block at the given burnchain block height.
    /// TODO: Check description
    fn get_burnchain_block_header_hash(&mut self, block_height: u32) -> Result<BurnchainHeaderHash>;

    /// 1. Get the current Stacks tip height (which is in the process of being evaluated)
    /// 2. Get the parent block's StacksBlockId, which is SHA512-256(consensus_hash, block_hash).
    ///    This is the highest Stacks block in this fork whose consensus hash is known.
    /// 3. Resolve the parent StacksBlockId to its consensus hash
    /// 4. Resolve the consensus hash to the associated SortitionId
    fn get_sortition_id_for_stacks_tip(&mut self) -> Result<Option<SortitionId>>;

    /// Fetch the burnchain block header hash for a given burnchain height.
    /// Because the burnchain can fork, we need to resolve the burnchain hash from the
    /// currently-evaluated Stacks chain tip.
    ///
    /// This way, the `BurnchainHeaderHash` returned is guaranteed to be on the burnchain fork
    /// that holds the currently-evaluated Stacks fork (even if it's not the canonical burnchain
    /// fork).
    fn get_burnchain_block_header_hash_for_burnchain_height(
        &mut self,
        burnchain_block_height: u32,
    ) -> Result<Option<BurnchainHeaderHash>>;

    /// Get the PoX reward addresses and per-address payout for a given burnchain height.  Because the burnchain can fork,
    /// we need to resolve the PoX addresses from the currently-evaluated Stacks chain tip.
    fn get_pox_payout_addrs_for_burnchain_height(
        &mut self,
        burnchain_block_height: u32,
    ) -> Result<Option<(Vec<TupleData>, u128)>>;

    /// Get the burnchain block height at the given Stacks block height.
    fn get_burnchain_block_height(&mut self, id_bhh: &StacksBlockId) -> Result<Option<u32>>;

    fn get_block_vrf_seed(&mut self, block_height: u32) -> Result<VRFSeed>;

    fn get_miner_address(&mut self, block_height: u32) -> Result<StandardPrincipalData>;

    fn get_miner_spend_winner(&mut self, block_height: u32) -> Result<u128>;

    fn get_miner_spend_total(&mut self, block_height: u32) -> Result<u128>;

    fn get_block_reward(&mut self, block_height: u32) -> Result<Option<u128>>;

    fn get_stx_btc_ops_processed(&mut self) -> Result<u64> 
    where
        Self: Sized
    {
        self.get("vm_pox::stx_btc_ops::processed_blocks")
            .map_or(Ok(0), |x| Ok(x.unwrap_or(0)))
    }

    fn set_stx_btc_ops_processed(&mut self, processed: u64) -> Result<()>
    where
        Self: Sized
    {
        self.put("vm_pox::stx_btc_ops::processed_blocks", &processed)
    }
}