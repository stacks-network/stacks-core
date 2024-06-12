// Copyright (C) 2013-2020 Blockstack PBC, a public benefit corporation
// Copyright (C) 2020-2023 Stacks Open Internet Foundation
//
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.
//
// This program is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
// GNU General Public License for more details.
//
// You should have received a copy of the GNU General Public License
// along with this program.  If not, see <http://www.gnu.org/licenses/>.

use std::collections::HashMap;

use stacks_common::types::chainstate::{BlockHeaderHash, ConsensusHash};

use crate::chainstate::burn::db::sortdb::SortitionDB;
use crate::chainstate::nakamoto::NakamotoBlock;
use crate::chainstate::stacks::db::StacksChainState;
use crate::chainstate::stacks::{Error as ChainstateError, StacksBlockHeader};
use crate::net::p2p::{PeerNetwork, PeerNetworkWorkState};
use crate::net::{
    BlocksAvailableData, BlocksData, BlocksDatum, Error as NetError, MicroblocksData,
    NakamotoBlocksData, NeighborKey, Preamble, StacksMessage, StacksMessageType,
};

/// This module contains all of the code needed to handle unsolicited messages -- that is, messages
/// that get pushed to us.  These include:
///
/// * BlocksAvailable (epoch 2.x)
/// * MicroblocksAvailable (epoch 2.x)
/// * BlocksData (epoch 2.x)
/// * NakamotoBlocksData (epoch 3.x)
///
/// Normally, the PeerNetwork will attempt to validate each message and pass it to the Relayer via
/// a NetworkResult.  However, some kinds of messages (such as these) cannot be always be
/// validated, because validation depends on chainstate data that is not yet available.  For
/// example, if this node is behind the burnchain chain tip, it will be unable to verify blocks
/// pushed to it for sortitions that have yet to be processed locally.
///
/// In the event that a message cannot be validated, the PeerNetwork will instead store these
/// messages internally (in `self.pending_messages`), and try to validate them again once the
/// burnchain view changes.
///
/// Transactions are not considered here, but are handled separately with the mempool
/// synchronization state machine.

impl PeerNetwork {
    #[cfg_attr(test, mutants::skip)]
    /// Check that the sender is authenticated.
    /// Returns Some(remote sender address) if so
    /// Returns None otherwise
    fn check_peer_authenticated(&self, event_id: usize) -> Option<NeighborKey> {
        let Some((remote_neighbor_key, remote_is_authenticated)) = self
            .peers
            .get(&event_id)
            .map(|convo| (convo.to_neighbor_key(), convo.is_authenticated()))
        else {
            test_debug!(
                "{:?}: No such neighbor event={}",
                &self.local_peer,
                event_id
            );
            return None;
        };

        if !remote_is_authenticated {
            // drop -- a correct peer will have authenticated before sending this message
            test_debug!(
                "{:?}: Unauthenticated neighbor {:?}",
                &self.local_peer,
                &remote_neighbor_key
            );
            return None;
        }
        Some(remote_neighbor_key)
    }

    /// Update a peer's inventory state to indicate that the given block is available.
    /// If updated, return the sortition height of the bit in the inv that was set.
    /// Only valid for epoch 2.x
    fn handle_unsolicited_inv_update_epoch2x(
        &mut self,
        sortdb: &SortitionDB,
        event_id: usize,
        outbound_neighbor_key: &NeighborKey,
        consensus_hash: &ConsensusHash,
        microblocks: bool,
    ) -> Result<Option<u64>, NetError> {
        let Some(inv) = self.inv_state.as_mut() else {
            return Ok(None);
        };

        let res = if microblocks {
            inv.set_microblocks_available(
                &self.burnchain,
                outbound_neighbor_key,
                sortdb,
                consensus_hash,
            )
        } else {
            inv.set_block_available(
                &self.burnchain,
                outbound_neighbor_key,
                sortdb,
                consensus_hash,
            )
        };

        let block_sortition_height = match res {
            Ok(Some(block_height)) => block_height,
            Ok(None) => {
                debug!(
                    "{:?}: We already know the inventory state in {} for {}",
                    &self.local_peer, outbound_neighbor_key, consensus_hash
                );
                return Ok(None);
            }
            Err(NetError::NotFoundError) => {
                // is this remote node simply ahead of us?
                if let Some(convo) = self.peers.get(&event_id) {
                    if self.chain_view.burn_block_height < convo.burnchain_tip_height {
                        debug!("{:?}: Unrecognized consensus hash {}; it is possible that {} is ahead of us", &self.local_peer, consensus_hash, outbound_neighbor_key);
                        return Err(NetError::NotFoundError);
                    }
                }
                // not ahead of us -- it's a bad consensus hash
                debug!("{:?}: Unrecognized consensus hash {}; assuming that {} has a different chain view", &self.local_peer, consensus_hash, outbound_neighbor_key);
                return Ok(None);
            }
            Err(NetError::InvalidMessage) => {
                // punish this peer
                info!(
                    "Peer {:?} sent an invalid update for {}",
                    &outbound_neighbor_key,
                    if microblocks {
                        "streamed microblocks"
                    } else {
                        "blocks"
                    }
                );
                self.bans.insert(event_id);

                if let Some(outbound_event_id) = self.events.get(&outbound_neighbor_key) {
                    self.bans.insert(*outbound_event_id);
                }
                return Ok(None);
            }
            Err(e) => {
                warn!(
                    "Failed to update inv state for {:?}: {:?}",
                    &outbound_neighbor_key, &e
                );
                return Ok(None);
            }
        };
        Ok(Some(block_sortition_height))
    }

    #[cfg_attr(test, mutants::skip)]
    /// Determine whether or not the system can buffer up this message, based on site-local
    /// configuration options.
    /// Return true if so, false if not
    pub(crate) fn can_buffer_data_message(
        &self,
        event_id: usize,
        msgs: &[StacksMessage],
        msg: &StacksMessage,
    ) -> bool {
        // check limits against connection opts, and if the limit is not met, then buffer up the
        // message.
        let mut blocks_available = 0;
        let mut microblocks_available = 0;
        let mut blocks_data = 0;
        let mut microblocks_data = 0;
        let mut nakamoto_blocks_data = 0;
        for stored_msg in msgs.iter() {
            match &stored_msg.payload {
                StacksMessageType::BlocksAvailable(_) => {
                    blocks_available += 1;
                    if matches!(&msg.payload, StacksMessageType::BlocksAvailable(..))
                        && blocks_available >= self.connection_opts.max_buffered_blocks_available
                    {
                        debug!(
                            "{:?}: Cannot buffer BlocksAvailable from event {} -- already have {} buffered",
                            &self.local_peer, event_id, blocks_available
                        );
                        return false;
                    }
                }
                StacksMessageType::MicroblocksAvailable(_) => {
                    microblocks_available += 1;
                    if matches!(&msg.payload, StacksMessageType::MicroblocksAvailable(..))
                        && microblocks_available
                            >= self.connection_opts.max_buffered_microblocks_available
                    {
                        debug!(
                            "{:?}: Cannot buffer MicroblocksAvailable from event {} -- already have {} buffered",
                            &self.local_peer, event_id, microblocks_available
                        );
                        return false;
                    }
                }
                StacksMessageType::Blocks(_) => {
                    blocks_data += 1;
                    if matches!(&msg.payload, StacksMessageType::Blocks(..))
                        && blocks_data >= self.connection_opts.max_buffered_blocks
                    {
                        debug!(
                            "{:?}: Cannot buffer BlocksData from event {} -- already have {} buffered",
                            &self.local_peer, event_id, blocks_data
                        );
                        return false;
                    }
                }
                StacksMessageType::Microblocks(_) => {
                    microblocks_data += 1;
                    if matches!(&msg.payload, StacksMessageType::Microblocks(..))
                        && microblocks_data >= self.connection_opts.max_buffered_microblocks
                    {
                        debug!(
                            "{:?}: Cannot buffer MicroblocksData from event {} -- already have {} buffered",
                            &self.local_peer, event_id, microblocks_data
                        );
                        return false;
                    }
                }
                StacksMessageType::NakamotoBlocks(_) => {
                    nakamoto_blocks_data += 1;
                    if matches!(&msg.payload, StacksMessageType::NakamotoBlocks(..))
                        && nakamoto_blocks_data >= self.connection_opts.max_buffered_nakamoto_blocks
                    {
                        debug!(
                            "{:?}: Cannot buffer NakamotoBlocksData from event {} -- already have {} buffered",
                            &self.local_peer, event_id, nakamoto_blocks_data
                        );
                        return false;
                    }
                }
                _ => {}
            }
        }

        true
    }

    #[cfg_attr(test, mutants::skip)]
    /// Buffer a message for re-processing once the burnchain view updates.
    /// If there is no space for the message, then silently drop it.
    /// Returns true if buffered.
    /// Returns false if not.
    pub(crate) fn buffer_data_message(&mut self, event_id: usize, msg: StacksMessage) -> bool {
        let Some(msgs) = self.pending_messages.get(&event_id) else {
            self.pending_messages.insert(event_id, vec![msg]);
            debug!(
                "{:?}: Event {} has 1 messages buffered",
                &self.local_peer, event_id
            );
            return true;
        };

        // check limits against connection opts, and if the limit is not met, then buffer up the
        // message.
        if !self.can_buffer_data_message(event_id, msgs, &msg) {
            return false;
        }

        if let Some(msgs) = self.pending_messages.get_mut(&event_id) {
            // should always be reachable
            msgs.push(msg);
            debug!(
                "{:?}: Event {} has {} messages buffered",
                &self.local_peer,
                event_id,
                msgs.len()
            );
        }
        true
    }

    /// Do we need a block or microblock stream, given its sortition's consensus hash?
    fn need_block_or_microblock_stream(
        sortdb: &SortitionDB,
        chainstate: &StacksChainState,
        consensus_hash: &ConsensusHash,
        is_microblock: bool,
    ) -> Result<bool, NetError> {
        let sn = SortitionDB::get_block_snapshot_consensus(sortdb.conn(), &consensus_hash)?
            .ok_or(ChainstateError::NoSuchBlockError)?;
        let block_hash_opt = if sn.sortition {
            Some(sn.winning_stacks_block_hash)
        } else {
            None
        };

        let inv = chainstate.get_blocks_inventory(&[(consensus_hash.clone(), block_hash_opt)])?;
        if is_microblock {
            // checking for microblock absence
            Ok(inv.microblocks_bitvec[0] == 0)
        } else {
            // checking for block absence
            Ok(inv.block_bitvec[0] == 0)
        }
    }

    /// Handle unsolicited BlocksAvailable.  If it is valid, and it represents a block that this
    /// peer does not have, then hint to the epoch2x downloader that it needs to go and fetch it.
    /// Also, update this peer's copy of the remote sender's inv to indicate that it has the block,
    /// so the downloader can eventually request the block regardless of whether or not the hint is
    /// effective.
    ///
    /// This function only accepts BlocksAvailable messages from outbound peers, since we only
    /// track inventories for outbound peers.
    ///
    /// The caller can call this in one of two ways: with `buffer` set to `true` or `false`.  If
    /// `buffer` is `true`, then the caller is asking to know if the message can be buffered if it
    /// cannot be handled.  If it is instead `false`, then the caller is asking to simply try and
    /// handle the given message.  In both cases, the blocks' validity will be checked against the
    /// sortition DB, and if they correspond to real sortitions, then the remote peer's inventory
    /// will be updated and the local peer's downloader will be alerted to this block.
    ///
    /// Errors pertaining to the validity of the message are logged but not returned.
    fn handle_unsolicited_BlocksAvailable(
        &mut self,
        sortdb: &SortitionDB,
        chainstate: &StacksChainState,
        event_id: usize,
        new_blocks: &BlocksAvailableData,
        ibd: bool,
        buffer: bool,
    ) -> bool {
        let Some(outbound_neighbor_key) = self.find_outbound_neighbor(event_id) else {
            // we only accept BlocksAvailable from outbound peers, since we only crawl invs from
            // outbound peers.
            return false;
        };

        debug!(
            "{:?}: Process BlocksAvailable from {:?} with {} entries",
            &self.local_peer,
            &outbound_neighbor_key,
            new_blocks.available.len()
        );

        let mut to_buffer = false;
        for (consensus_hash, block_hash) in new_blocks.available.iter() {
            let block_sortition_height = match self.handle_unsolicited_inv_update_epoch2x(
                sortdb,
                event_id,
                &outbound_neighbor_key,
                consensus_hash,
                false,
            ) {
                Ok(Some(bsh)) => bsh,
                Ok(None) => {
                    continue;
                }
                Err(NetError::NotFoundError) => {
                    if buffer {
                        debug!("{:?}: Will buffer BlocksAvailable for {} until the next burnchain view update", &self.local_peer, &consensus_hash);
                        to_buffer = true;
                    }
                    continue;
                }
                Err(e) => {
                    info!(
                        "{:?}: Failed to handle BlocksAvailable({}/{}) from {}: {:?}",
                        &self.local_peer, &consensus_hash, &block_hash, &outbound_neighbor_key, &e
                    );
                    continue;
                }
            };

            let need_block = match PeerNetwork::need_block_or_microblock_stream(
                sortdb,
                chainstate,
                &consensus_hash,
                false,
            ) {
                Ok(x) => x,
                Err(e) => {
                    warn!(
                        "Failed to determine if we need block for consensus hash {}: {:?}",
                        &consensus_hash, &e
                    );
                    false
                }
            };

            debug!(
                "Need block {}/{}? {}",
                &consensus_hash, &block_hash, need_block
            );

            if need_block {
                // have the downloader request this block if it's new and we don't have it
                match self.block_downloader {
                    Some(ref mut downloader) => {
                        downloader.hint_block_sortition_height_available(
                            block_sortition_height,
                            ibd,
                            need_block,
                        );

                        // advance straight to download state if we're in inv state
                        if self.work_state == PeerNetworkWorkState::BlockInvSync {
                            debug!("{:?}: advance directly to block download with knowledge of block sortition {}", &self.local_peer, block_sortition_height);
                        }
                        self.have_data_to_download = true;
                    }
                    None => {}
                }
            }
        }

        to_buffer
    }

    /// Handle unsolicited MicroblocksAvailable.  If it is valid, and it represents a microblock stream that this
    /// peer does not have, then hint to the epoch2x downloader that it needs to go and fetch it.
    /// Also, update this peer's copy of the remote sender's inv to indicate that it has the stream,
    /// so the downloader can eventually request the stream regardless of whether or not the hint is
    /// effective.
    ///
    /// This function only accepts MicroblocksAvailable messages from outbound peers, since we only
    /// track inventories for outbound peers.
    ///
    /// The caller can call this in one of two ways: with `buffer` set to `true` or `false`.  If
    /// `buffer` is `true`, then the caller is asking to know if the message can be buffered if it
    /// cannot be handled.  If it is instead `false`, then the caller is asking to simply try and
    /// handle the given message.  In both cases, the remote peer's inventory will be updated and
    /// the local peer's downloader will be alerted to the presence of these microblocks.
    ///
    /// Errors pertaining to the validity of the message are logged but not returned.
    ///
    /// Return whether or not we need to buffer this message for subsequent consideration.
    fn handle_unsolicited_MicroblocksAvailable(
        &mut self,
        sortdb: &SortitionDB,
        chainstate: &StacksChainState,
        event_id: usize,
        new_mblocks: &BlocksAvailableData,
        ibd: bool,
        buffer: bool,
    ) -> bool {
        let Some(outbound_neighbor_key) = self.find_outbound_neighbor(event_id) else {
            return false;
        };

        debug!(
            "{:?}: Process MicroblocksAvailable from {:?} with {} entries",
            &self.local_peer,
            outbound_neighbor_key,
            new_mblocks.available.len()
        );

        let mut to_buffer = false;
        for (consensus_hash, block_hash) in new_mblocks.available.iter() {
            let mblock_sortition_height = match self.handle_unsolicited_inv_update_epoch2x(
                sortdb,
                event_id,
                &outbound_neighbor_key,
                consensus_hash,
                true,
            ) {
                Ok(Some(bsh)) => bsh,
                Ok(None) => {
                    continue;
                }
                Err(NetError::NotFoundError) => {
                    if buffer {
                        debug!("{:?}: Will buffer MicroblocksAvailable for {} until the next burnchain view update", &self.local_peer, &consensus_hash);
                        to_buffer = true;
                    }
                    continue;
                }
                Err(e) => {
                    info!(
                        "{:?}: Failed to handle MicroblocksAvailable({}/{}) from {:?}: {:?}",
                        &self.local_peer, &consensus_hash, &block_hash, &outbound_neighbor_key, &e
                    );
                    continue;
                }
            };

            let need_microblock_stream = match PeerNetwork::need_block_or_microblock_stream(
                sortdb,
                chainstate,
                &consensus_hash,
                true,
            ) {
                Ok(x) => x,
                Err(e) => {
                    warn!("Failed to determine if we need microblock stream for consensus hash {}: {:?}", &consensus_hash, &e);
                    false
                }
            };

            debug!(
                "Need microblock stream {}/{}? {}",
                &consensus_hash, &block_hash, need_microblock_stream
            );

            if need_microblock_stream {
                // have the downloader request this microblock stream if it's new to us
                if let Some(downloader) = self.block_downloader.as_mut() {
                    downloader.hint_microblock_sortition_height_available(
                        mblock_sortition_height,
                        ibd,
                        need_microblock_stream,
                    );

                    // advance straight to download state if we're in inv state
                    if self.work_state == PeerNetworkWorkState::BlockInvSync {
                        debug!("{:?}: advance directly to block download with knowledge of microblock stream {}", &self.local_peer, mblock_sortition_height);
                    }
                    self.have_data_to_download = true;
                }
            }
        }
        to_buffer
    }

    /// Handle unsolicited BlocksData.
    ///
    /// Don't (yet) validate the data, but do update our inv for the peer that sent it, if we have
    /// an outbound connection to that peer.
    ///
    /// Log but do nothing with errors in validation.
    ///
    /// The caller can call this in one of two ways: with `buffer` set to `true` or `false`.  If
    /// `buffer` is `true`, then the caller is asking to know if the message can be buffered if it
    /// cannot be handled.  If it is instead `false`, then the caller is asking to simply try and
    /// handle the given message.  In both cases, the block will be checked against the local
    /// sortition DB, and if it corresponds to a sortition, the remote peer's inventory will be
    /// updated to reflect that it has it.
    ///
    /// Returns true if we have to buffer this message; false if not.
    fn handle_unsolicited_BlocksData(
        &mut self,
        sortdb: &SortitionDB,
        event_id: usize,
        new_blocks: &BlocksData,
        buffer: bool,
    ) -> bool {
        let outbound_neighbor_key_opt = self.find_outbound_neighbor(event_id);

        debug!(
            "{:?}: Process BlocksData from {:?} with {} entries",
            &self.local_peer,
            outbound_neighbor_key_opt
                .clone()
                .or_else(|| { self.check_peer_authenticated(event_id) }),
            new_blocks.blocks.len()
        );

        let mut to_buffer = false;

        for BlocksDatum(consensus_hash, block) in new_blocks.blocks.iter() {
            let sn = match SortitionDB::get_block_snapshot_consensus(
                &sortdb.conn(),
                &consensus_hash,
            ) {
                Ok(Some(sn)) => sn,
                Ok(None) => {
                    if buffer {
                        debug!(
                            "{:?}: Will buffer unsolicited BlocksData({}/{}) ({}) -- consensus hash not (yet) recognized",
                            &self.local_peer,
                            &consensus_hash,
                            &block.block_hash(),
                            StacksBlockHeader::make_index_block_hash(
                                &consensus_hash,
                                &block.block_hash()
                            )
                        );
                        to_buffer = true;
                    } else {
                        debug!(
                            "{:?}: Will drop unsolicited BlocksData({}/{}) ({}) -- consensus hash not (yet) recognized",
                            &self.local_peer,
                            &consensus_hash,
                            &block.block_hash(),
                            StacksBlockHeader::make_index_block_hash(
                                &consensus_hash,
                                &block.block_hash()
                            )
                        );
                    }
                    continue;
                }
                Err(e) => {
                    info!(
                        "{:?}: Failed to query block snapshot for {}: {:?}",
                        &self.local_peer, consensus_hash, &e
                    );
                    continue;
                }
            };

            if !sn.pox_valid {
                info!(
                    "{:?}: Failed to query snapshot for {}: not on the valid PoX fork",
                    &self.local_peer, consensus_hash
                );
                continue;
            }

            if sn.winning_stacks_block_hash != block.block_hash() {
                info!(
                    "{:?}: Ignoring block {} -- winning block was {} (sortition: {})",
                    &self.local_peer,
                    block.block_hash(),
                    sn.winning_stacks_block_hash,
                    sn.sortition
                );
                continue;
            }

            // only bother updating the inventory for this event's peer if we have an outbound
            // connection to it.
            if let Some(outbound_neighbor_key) = outbound_neighbor_key_opt.as_ref() {
                let _ = self.handle_unsolicited_inv_update_epoch2x(
                    sortdb,
                    event_id,
                    &outbound_neighbor_key,
                    &sn.consensus_hash,
                    false,
                );
            }
        }

        to_buffer
    }

    /// Handle unsolicited MicroblocksData.
    ///
    /// Don't (yet) validate the data; just verify that it connects to two existing StacksBlocks,
    /// and if so, keep it to be passed on to the relayer.
    ///
    /// Log but do nothing with errors in validation.
    ///
    /// The caller can call this in one of two ways: with `buffer` set to `true` or `false`.  If
    /// `buffer` is `true`, then the caller is asking to know if the message can be buffered if it
    /// cannot be handled.  If it is instead `false`, then the caller is asking to simply try and
    /// handle the given message.  In both cases, the microblocks will be checked against the local
    /// sortition DB and chainstate DB, and if they correspond to a missing stream between two known
    /// StacksBlocks, the remote peer's inventory will be updated to reflect that it has this
    /// stream.
    ///
    /// Returns whether or not to buffer.  If the microblocks correspond to existing chain state,
    /// then this method will indicate to the opposite of `buffer`, which ensures that the messages
    /// will never be buffered but instead processed immediately.  Otherwise, no buffering will
    /// take place.
    fn handle_unsolicited_MicroblocksData(
        &mut self,
        chainstate: &StacksChainState,
        event_id: usize,
        new_microblocks: &MicroblocksData,
        buffer: bool,
    ) -> bool {
        let outbound_neighbor_key_opt = self.find_outbound_neighbor(event_id);

        debug!(
            "{:?}: Process MicroblocksData from {:?} for {} with {} entries",
            &self.local_peer,
            outbound_neighbor_key_opt.or_else(|| { self.check_peer_authenticated(event_id) }),
            &new_microblocks.index_anchor_block,
            new_microblocks.microblocks.len()
        );

        // do we have the associated anchored block?
        match chainstate.get_block_header_hashes(&new_microblocks.index_anchor_block) {
            Ok(Some(_)) => {
                // yup; can process now
                debug!("{:?}: have microblock parent anchored block {}, so can process its microblocks", &self.local_peer, &new_microblocks.index_anchor_block);
                !buffer
            }
            Ok(None) => {
                if buffer {
                    debug!(
                        "{:?}: Will buffer unsolicited MicroblocksData({})",
                        &self.local_peer, &new_microblocks.index_anchor_block
                    );
                    true
                } else {
                    debug!(
                        "{:?}: Will not buffer unsolicited MicroblocksData({})",
                        &self.local_peer, &new_microblocks.index_anchor_block
                    );
                    false
                }
            }
            Err(e) => {
                warn!(
                    "{:?}: Failed to get header hashes for {:?}: {:?}",
                    &self.local_peer, &new_microblocks.index_anchor_block, &e
                );
                false
            }
        }
    }

    /// Check the signature of a NakamotoBlock against its sortition's reward cycle.
    /// The reward cycle must be recent.
    pub(crate) fn check_nakamoto_block_signer_signature(
        &mut self,
        reward_cycle: u64,
        nakamoto_block: &NakamotoBlock,
    ) -> bool {
        let Some(rc_data) = self.current_reward_sets.get(&reward_cycle) else {
            info!(
                "{:?}: Failed to validate Nakamoto block {}/{}: no reward set",
                self.get_local_peer(),
                &nakamoto_block.header.consensus_hash,
                &nakamoto_block.header.block_hash()
            );
            return false;
        };
        let Some(reward_set) = rc_data.reward_set() else {
            info!(
                "{:?}: No reward set for reward cycle {}",
                self.get_local_peer(),
                reward_cycle
            );
            return false;
        };

        if let Err(e) = nakamoto_block.header.verify_signer_signatures(reward_set) {
            info!(
                "{:?}: signature verification failrue for Nakamoto block {}/{} in reward cycle {}: {:?}", self.get_local_peer(), &nakamoto_block.header.consensus_hash, &nakamoto_block.header.block_hash(), reward_cycle, &e
            );
            return false;
        }
        true
    }

    #[cfg_attr(test, mutants::skip)]
    /// Find the reward cycle in which to validate the signature for this block.
    /// This may not actually correspond to the sortition for this block's tenure -- for example,
    /// it may be for a block whose sortition is about to be processed.  As such, return both the
    /// reward cycle, and whether or not it corresponds to the sortition.
    pub(crate) fn find_nakamoto_block_reward_cycle(
        &self,
        sortdb: &SortitionDB,
        nakamoto_block: &NakamotoBlock,
    ) -> (Option<u64>, bool) {
        let (reward_set_sn, can_process) = match SortitionDB::get_block_snapshot_consensus(
            &sortdb.conn(),
            &nakamoto_block.header.consensus_hash,
        ) {
            Ok(Some(sn)) => (sn, true),
            Ok(None) => {
                debug!(
                    "No sortition {} for block {}",
                    &nakamoto_block.header.consensus_hash,
                    &nakamoto_block.block_id()
                );
                // we don't have the sortition for this, so we can't process it yet (i.e. we need
                // to buffer)
                // load the tip so we can load the current reward set data
                (self.burnchain_tip.clone(), false)
            }
            Err(e) => {
                info!(
                    "{:?}: Failed to query block snapshot for {}: {:?}",
                    self.get_local_peer(),
                    &nakamoto_block.header.consensus_hash,
                    &e
                );
                return (None, false);
            }
        };

        if !reward_set_sn.pox_valid {
            info!(
                "{:?}: Failed to query snapshot for {}: not on the valid PoX fork",
                self.get_local_peer(),
                &nakamoto_block.header.consensus_hash
            );
            return (None, false);
        }

        let reward_set_sn_rc = self
            .burnchain
            .pox_reward_cycle(reward_set_sn.block_height)
            .expect("FATAL: sortition has no reward cycle");

        return (Some(reward_set_sn_rc), can_process);
    }

    /// Determine if an unsolicited NakamotoBlockData message contains data we can potentially
    /// buffer.  Returns whether or not the block can be buffered.
    pub(crate) fn is_nakamoto_block_bufferable(
        &mut self,
        sortdb: &SortitionDB,
        chainstate: &StacksChainState,
        nakamoto_block: &NakamotoBlock,
    ) -> bool {
        if chainstate
            .nakamoto_blocks_db()
            .has_nakamoto_block(&nakamoto_block.block_id())
            .unwrap_or(false)
        {
            debug!(
                "{:?}: Aleady have Nakamoto block {}",
                &self.local_peer,
                &nakamoto_block.block_id()
            );
            return false;
        }

        let (sn_rc_opt, can_process) =
            self.find_nakamoto_block_reward_cycle(sortdb, nakamoto_block);
        let Some(sn_rc) = sn_rc_opt else {
            return false;
        };

        if !self.check_nakamoto_block_signer_signature(sn_rc, nakamoto_block) {
            return false;
        }

        // the block is well-formed, but we'd buffer if we can't process it yet
        !can_process
    }

    #[cfg_attr(test, mutants::skip)]
    /// Handle an unsolicited NakamotoBlocksData message.
    ///
    /// Unlike Stacks epoch 2.x blocks, no change to the remote peer's inventory will take place.
    /// This is because a 1-bit indicates the _entire_ tenure is present for a given sortition, and
    /// this is usually impossible to tell here.  Instead, this handler will return `true` if the
    /// sortition identified by the block's consensus hash is known to this node (in which case,
    /// the relayer can store it to staging).
    ///
    /// Returns true if this message should be buffered and re-processed  
    pub(crate) fn inner_handle_unsolicited_NakamotoBlocksData(
        &mut self,
        sortdb: &SortitionDB,
        chainstate: &StacksChainState,
        remote_neighbor_key_opt: Option<NeighborKey>,
        nakamoto_blocks: &NakamotoBlocksData,
    ) -> bool {
        debug!(
            "{:?}: Process NakamotoBlocksData from {:?} with {} entries",
            &self.local_peer,
            &remote_neighbor_key_opt,
            nakamoto_blocks.blocks.len()
        );

        let mut to_buffer = false;
        for nakamoto_block in nakamoto_blocks.blocks.iter() {
            if self.is_nakamoto_block_bufferable(sortdb, chainstate, nakamoto_block) {
                debug!(
                    "{:?}: Will buffer unsolicited NakamotoBlocksData({}) ({})",
                    &self.local_peer,
                    &nakamoto_block.block_id(),
                    &nakamoto_block.header.consensus_hash,
                );
                to_buffer = true;
            };
        }
        to_buffer
    }

    /// Handle an unsolicited NakamotoBlocksData message.
    ///
    /// Unlike Stacks epoch 2.x blocks, no change to the remote peer's inventory will take place.
    /// This is because a 1-bit indicates the _entire_ tenure is present for a given sortition, and
    /// this is usually impossible to tell here.  Instead, this handler will return `true` if the
    /// sortition identified by the block's consensus hash is known to this node (in which case,
    /// the relayer can store it to staging).
    ///
    /// Returns true if this message should be buffered and re-processed  
    ///
    /// Wraps inner_handle_unsolicited_NakamotoBlocksData by resolving the event_id to the optional
    /// neighbor key.
    fn handle_unsolicited_NakamotoBlocksData(
        &mut self,
        sortdb: &SortitionDB,
        chainstate: &StacksChainState,
        event_id: usize,
        nakamoto_blocks: &NakamotoBlocksData,
    ) -> bool {
        let outbound_neighbor_key_opt = self
            .find_outbound_neighbor(event_id)
            .or_else(|| self.check_peer_authenticated(event_id));
        self.inner_handle_unsolicited_NakamotoBlocksData(
            sortdb,
            chainstate,
            outbound_neighbor_key_opt,
            nakamoto_blocks,
        )
    }

    /// Handle an unsolicited message, with either the intention of just processing it (in which
    /// case, `buffer` will be `false`), or with the intention of not only processing it, but also
    /// determining if it can be bufferred and retried later (in which case, `buffer` will be
    /// `true`).
    ///
    /// Returns (true, x) if we should buffer the message and try processing it again later.
    /// Returns (false, x) if we should *not* buffer this message, because it *won't* be valid
    /// later.
    ///
    /// Returns (x, true) if we should forward the message to the relayer, so it can be processed.
    /// Returns (x, false) if we should *not* forward the message to the relayer, because it will
    /// *not* be processed.
    fn handle_unsolicited_message(
        &mut self,
        sortdb: &SortitionDB,
        chainstate: &StacksChainState,
        event_id: usize,
        preamble: &Preamble,
        payload: &StacksMessageType,
        ibd: bool,
        buffer: bool,
    ) -> (bool, bool) {
        match payload {
            // Update our inv state for this peer, but only do so if we have an
            // outbound connection to it and it's authenticated (we don't synchronize inv
            // state with inbound peers).  Since we will have received this message
            // from an _inbound_ conversation, we need to find the reciprocal _outbound_
            // conversation and use _that_ conversation's neighbor key to identify
            // which inventory we need to update.
            StacksMessageType::BlocksAvailable(ref new_blocks) => {
                // no need to forward to relayer
                let to_buffer = self.handle_unsolicited_BlocksAvailable(
                    sortdb, chainstate, event_id, new_blocks, ibd, buffer,
                );
                (to_buffer, false)
            }
            StacksMessageType::MicroblocksAvailable(ref new_mblocks) => {
                // no need to forward to relayer
                let to_buffer = self.handle_unsolicited_MicroblocksAvailable(
                    sortdb,
                    chainstate,
                    event_id,
                    new_mblocks,
                    ibd,
                    buffer,
                );
                (to_buffer, false)
            }
            StacksMessageType::Blocks(ref new_blocks) => {
                // update inv state for this peer, and always forward to the relayer
                let to_buffer =
                    self.handle_unsolicited_BlocksData(sortdb, event_id, new_blocks, buffer);

                // forward to relayer for processing
                (to_buffer, true)
            }
            StacksMessageType::Microblocks(ref new_mblocks) => {
                // update inv state for this peer, and optionally forward to the relayer.
                // Note that if these microblocks can be processed *now*, then they *will not* be
                // buffered
                let to_buffer = self.handle_unsolicited_MicroblocksData(
                    chainstate,
                    event_id,
                    new_mblocks,
                    buffer,
                );

                // only forward to the relayer if we don't need to buffer it.
                (to_buffer, true)
            }
            StacksMessageType::NakamotoBlocks(ref new_blocks) => {
                let to_buffer = if buffer {
                    self.handle_unsolicited_NakamotoBlocksData(
                        sortdb, chainstate, event_id, new_blocks,
                    )
                } else {
                    // nothing to do if we're not querying about whether we can buffer this.
                    false
                };

                (to_buffer, true)
            }
            StacksMessageType::StackerDBPushChunk(ref data) => {
                match self.handle_unsolicited_StackerDBPushChunk(event_id, preamble, data) {
                    Ok(x) => {
                        // don't buffer, but do reject if invalid
                        (false, x)
                    }
                    Err(e) => {
                        info!(
                            "{:?}: failed to handle unsolicited {:?}: {:?}",
                            &self.local_peer, payload, &e
                        );
                        (false, false)
                    }
                }
            }
            _ => (false, true),
        }
    }

    /// Handle unsolicited messages propagated up to us from our ongoing ConversationP2Ps.
    /// Return messages that we couldn't handle here, but key them by neighbor, not event, so the
    /// relayer can do something useful with them.
    ///
    /// Invalid messages are dropped silently, with an log message.
    ///
    /// If `buffer` is true, then this message will be buffered up and tried again in a subsequent
    /// call if the handler for it deems the message valid.
    ///
    /// If `buffer` is false, then if the message handler deems the message valid, it will be
    /// forwraded to the relayer.
    ///
    /// Returns the messages to be forward to the relayer, keyed by sender.
    pub fn handle_unsolicited_messages(
        &mut self,
        sortdb: &SortitionDB,
        chainstate: &StacksChainState,
        unsolicited: HashMap<usize, Vec<StacksMessage>>,
        ibd: bool,
        buffer: bool,
    ) -> HashMap<NeighborKey, Vec<StacksMessage>> {
        let mut unhandled: HashMap<NeighborKey, Vec<StacksMessage>> = HashMap::new();
        for (event_id, messages) in unsolicited.into_iter() {
            if messages.len() == 0 {
                // no messages for this event
                continue;
            }
            if buffer && self.check_peer_authenticated(event_id).is_none() {
                if cfg!(test)
                    && self
                        .connection_opts
                        .test_disable_unsolicited_message_authentication
                {
                    test_debug!(
                        "{:?}: skip unsolicited message authentication",
                        &self.local_peer
                    );
                } else {
                    // do not buffer messages from unknown peers
                    // (but it's fine to process messages that were previosuly buffered, since the peer
                    // may have since disconnected)
                    debug!("Will not handle unsolicited messages from unauthenticated or dead event {}", event_id);
                    continue;
                }
            };
            let neighbor_key = if let Some(convo) = self.peers.get(&event_id) {
                convo.to_neighbor_key()
            } else {
                debug!(
                    "{:?}: No longer such neighbor event={}, dropping {} unsolicited messages",
                    &self.local_peer,
                    event_id,
                    messages.len()
                );
                continue;
            };

            debug!("{:?}: Process {} unsolicited messages from {:?}", &self.local_peer, messages.len(), &neighbor_key; "buffer" => %buffer);

            for message in messages.into_iter() {
                if buffer
                    && !self.can_buffer_data_message(
                        event_id,
                        self.pending_messages.get(&event_id).unwrap_or(&vec![]),
                        &message,
                    )
                {
                    // asked to buffer, but we don't have space
                    continue;
                }

                if !buffer {
                    debug!(
                        "{:?}: Re-try handling buffered message {} from {:?}",
                        &self.local_peer,
                        &message.payload.get_message_description(),
                        &neighbor_key
                    );
                }
                let (to_buffer, relay) = self.handle_unsolicited_message(
                    sortdb,
                    chainstate,
                    event_id,
                    &message.preamble,
                    &message.payload,
                    ibd,
                    buffer,
                );
                if buffer && to_buffer {
                    self.buffer_data_message(event_id, message);
                } else if relay {
                    // forward to relayer for processing
                    debug!(
                        "{:?}: Will forward message {} from {:?} to relayer",
                        &self.local_peer,
                        &message.payload.get_message_description(),
                        &neighbor_key
                    );
                    if let Some(msgs) = unhandled.get_mut(&neighbor_key) {
                        msgs.push(message);
                    } else {
                        unhandled.insert(neighbor_key.clone(), vec![message]);
                    }
                }
            }
        }
        unhandled
    }
}
