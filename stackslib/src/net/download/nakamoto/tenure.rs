// Copyright (C) 2020-2024 Stacks Open Internet Foundation
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

use std::collections::{BTreeMap, HashMap, HashSet, VecDeque};
use std::convert::TryFrom;
use std::fmt;
use std::hash::{Hash, Hasher};
use std::io::{Read, Write};
use std::net::{IpAddr, SocketAddr};
use std::time::{Duration, Instant};

use rand::seq::SliceRandom;
use rand::{thread_rng, RngCore};
use stacks_common::types::chainstate::{
    BlockHeaderHash, ConsensusHash, PoxId, SortitionId, StacksBlockId,
};
use stacks_common::types::net::{PeerAddress, PeerHost};
use stacks_common::types::StacksEpochId;
use stacks_common::util::hash::to_hex;
use stacks_common::util::secp256k1::{Secp256k1PrivateKey, Secp256k1PublicKey};
use stacks_common::util::{get_epoch_time_ms, get_epoch_time_secs, log};
use wsts::curve::point::Point;

use crate::burnchains::{Burnchain, BurnchainView, PoxConstants};
use crate::chainstate::burn::db::sortdb::{
    BlockHeaderCache, SortitionDB, SortitionDBConn, SortitionHandleConn,
};
use crate::chainstate::burn::BlockSnapshot;
use crate::chainstate::nakamoto::{
    NakamotoBlock, NakamotoBlockHeader, NakamotoChainState, NakamotoStagingBlocksConnRef,
};
use crate::chainstate::stacks::db::StacksChainState;
use crate::chainstate::stacks::{
    Error as chainstate_error, StacksBlockHeader, TenureChangePayload,
};
use crate::core::{
    EMPTY_MICROBLOCK_PARENT_HASH, FIRST_BURNCHAIN_CONSENSUS_HASH, FIRST_STACKS_BLOCK_HASH,
};
use crate::net::api::gettenureinfo::RPCGetTenureInfo;
use crate::net::chat::ConversationP2P;
use crate::net::db::{LocalPeer, PeerDB};
use crate::net::http::HttpRequestContents;
use crate::net::httpcore::{StacksHttpRequest, StacksHttpResponse};
use crate::net::inv::epoch2x::InvState;
use crate::net::inv::nakamoto::{NakamotoInvStateMachine, NakamotoTenureInv};
use crate::net::neighbors::rpc::NeighborRPC;
use crate::net::neighbors::NeighborComms;
use crate::net::p2p::PeerNetwork;
use crate::net::server::HttpPeer;
use crate::net::{Error as NetError, Neighbor, NeighborAddress, NeighborKey};
use crate::util_lib::db::{DBConn, Error as DBError};

/// A tenure that this node needs data for.
#[derive(Debug, PartialEq, Clone)]
pub struct WantedTenure {
    /// Consensus hash that identifies the start of the tenure
    pub tenure_id_consensus_hash: ConsensusHash,
    /// Winning block-commit block ID for this tenure's snapshot (NOTE THAT THIS IS NOT THE
    /// TENURE-START BLOCK FOR THIS TENURE).
    pub winning_block_id: StacksBlockId,
    /// burnchain block height of this tenure ID consensus hash
    pub burn_height: u64,
    /// Whether or not this tenure has been acted upon (i.e. set to true if there's no need to
    /// download it)
    pub processed: bool,
}

impl WantedTenure {
    pub fn new(
        tenure_id_consensus_hash: ConsensusHash,
        winning_block_id: StacksBlockId,
        burn_height: u64,
    ) -> Self {
        Self {
            tenure_id_consensus_hash,
            winning_block_id,
            burn_height,
            processed: false,
        }
    }
}

/// A tenure's start and end blocks.  This is constructed from a sequence of `WantedTenure`s and a
/// node's inventory vector over them.
#[derive(Debug, PartialEq, Clone)]
pub struct TenureStartEnd {
    /// Consensus hash that identifies the start of the tenure
    pub tenure_id_consensus_hash: ConsensusHash,
    /// Tenure-start block ID
    pub start_block_id: StacksBlockId,
    /// Last block ID
    pub end_block_id: StacksBlockId,
    /// Whether or not to fetch the end-block of this tenure directly.  This is decided based on
    /// where the tenure falls in the reward cycle (e.g. if it's the last complete tenure in the
    /// reward cycle).
    pub fetch_end_block: bool,
    /// Reward cycle of the start block
    pub start_reward_cycle: u64,
    /// Reward cycle of the end block
    pub end_reward_cycle: u64,
    /// Whether or not this tenure has been processed
    pub processed: bool,
}

pub type AvailableTenures = HashMap<ConsensusHash, TenureStartEnd>;

impl TenureStartEnd {
    pub fn new(
        tenure_id_consensus_hash: ConsensusHash,
        start_block_id: StacksBlockId,
        end_block_id: StacksBlockId,
        start_reward_cycle: u64,
        end_reward_cycle: u64,
        processed: bool,
    ) -> Self {
        Self {
            tenure_id_consensus_hash,
            start_block_id,
            end_block_id,
            start_reward_cycle,
            end_reward_cycle,
            fetch_end_block: false,
            processed,
        }
    }

    /// Given a list of wanted tenures and a peer's inventory bitvectors over the same range of
    /// tenures, calculate the list of start/end blocks for each wanted tenure.
    ///
    /// Recall that in Nakamoto, a block-commit commits to the parent tenure's first block.  So if
    /// bit i is set (i.e. `wanted_tenures[i]` has tenure data), then it really means that the tenure
    /// start block is the winning block hash in the _subsequent_ `wanted_tenures` list item for which
    /// its corresponding bit is 1.  Similarly, the end block is the winning block hash in the
    /// `wanted_tenures` list item _after that_ whose bit is 1.
    ///
    /// As such, this algorithm needs to search not only the wanted tenures and inventories for
    /// this reward cycle, but also the next.
    ///
    /// The `wanted_tenures` and `next_wanted_tenures` values must be aligned to reward cycle
    /// boundaries (mod 0).  The code uses this assumption to assign reward cycles to blocks in the
    /// `TenureStartEnd`s in the returned `AvailableTenures` map.
    ///
    /// Returns the set of available tenures for all tenures in `wanted_tenures` that can be found
    /// with the available information.
    /// Returns None if there is no inventory data for the given reward cycle.
    pub fn from_inventory(
        rc: u64,
        wanted_tenures: &[WantedTenure],
        next_wanted_tenures: Option<&[WantedTenure]>,
        pox_constants: &PoxConstants,
        first_burn_height: u64,
        invs: &NakamotoTenureInv,
    ) -> Option<AvailableTenures> {
        // if bit i is set, that means that the tenure data for the ith tenure in the sortition
        // history was present.  But given that block-commits commit to the start block of the
        // parent tenure, the start-block ID for tenure i would be the StacksBlockId for the
        // next-available tenure.  Its end-block ID would be the StacksBlockId for the
        // next-available tenure after that.
        let invbits = invs.tenures_inv.get(&rc)?;
        let mut tenure_block_ids = AvailableTenures::new();
        let mut last_tenure = 0;
        let mut last_tenure_ch = None;
        for (i, wt) in wanted_tenures.iter().enumerate() {
            // advance to next tenure-start sortition
            let bit = u16::try_from(i).expect("FATAL: more sortitions than u16::MAX");
            if !invbits.get(bit).unwrap_or(false) {
                test_debug!("i={} bit not set", i);
                /*
                i += 1;
                */
                continue;
            }

            // the last tenure we'll consider
            last_tenure = i;

            let Some(wt_start_idx) = ((i + 1)..wanted_tenures.len()).find(|j| {
                let bit = u16::try_from(*j).expect("FATAL: more sortitions than u16::MAX");
                invbits.get(bit).unwrap_or(false)
            }) else {
                test_debug!("i={} out of wanted_tenures", i);
                break;
            };

            let Some(wt_start) = wanted_tenures.get(wt_start_idx) else {
                test_debug!("i={} no start wanted tenure", i);
                break;
            };

            let Some(wt_end_index) = ((wt_start_idx + 1)..wanted_tenures.len()).find(|j| {
                let bit = u16::try_from(*j).expect("FATAL: more sortitions than u16::MAX");
                invbits.get(bit).unwrap_or(false)
            }) else {
                test_debug!("i={} out of wanted_tenures", i);
                break;
            };

            let Some(wt_end) = wanted_tenures.get(wt_end_index) else {
                test_debug!("i={} no end wanted tenure", i);
                break;
            };

            let tenure_start_end = TenureStartEnd::new(
                wt.tenure_id_consensus_hash.clone(),
                wt_start.winning_block_id.clone(),
                wt_end.winning_block_id.clone(),
                rc,
                rc,
                wt.processed,
            );
            test_debug!(
                "i={}, len={}; {:?}",
                i,
                wanted_tenures.len(),
                &tenure_start_end
            );
            last_tenure_ch = Some(wt.tenure_id_consensus_hash.clone());
            tenure_block_ids.insert(wt.tenure_id_consensus_hash.clone(), tenure_start_end);
        }

        let Some(next_wanted_tenures) = next_wanted_tenures else {
            // nothing more to do
            test_debug!("No next_wanted_tenures");
            return Some(tenure_block_ids);
        };

        // `wanted_tenures` was a full reward cycle, so be sure to fetch the tenure-end block of
        // the last tenure derived from it
        if let Some(last_tenure_ch) = last_tenure_ch.take() {
            if let Some(last_tenure) = tenure_block_ids.get_mut(&last_tenure_ch) {
                test_debug!(
                    "Will directly fetch end-block {} for tenure {}",
                    &last_tenure.end_block_id,
                    &last_tenure.tenure_id_consensus_hash
                );
                last_tenure.fetch_end_block = true;
            }
        }

        let Some(next_invbits) = invs.tenures_inv.get(&rc.saturating_add(1)) else {
            // nothing more to do
            test_debug!("no inventory for cycle {}", rc.saturating_add(1));
            return Some(tenure_block_ids);
        };

        // start iterating from `last_tenures`
        let iter_start = last_tenure;
        let iterator = wanted_tenures.get(iter_start..).unwrap_or(&[]);
        for (i, wt) in iterator.iter().enumerate() {
            test_debug!(
                "consider next wanted tenure which starts with i={} {:?}",
                iter_start + i,
                &wt
            );

            // advance to next tenure-start sortition
            let bit = u16::try_from(i + iter_start).expect("FATAL: more sortitions than u16::MAX");
            if !invbits.get(bit).unwrap_or(false) {
                test_debug!("i={} bit not set", i);
                continue;
            }

            // search the remainder of `wanted_tenures`, and if we don't find the end-tenure,
            // search `next_wanted_tenures` until we find the tenure-start wanted tenure for the
            // ith wanted_tenure
            let Some((in_next, wt_start_idx, wt_start)) = ((i + iter_start + 1)
                ..wanted_tenures.len())
                .find_map(|j| {
                    // search `wanted_tenures`
                    let bit = u16::try_from(j).expect("FATAL: more sortitions than u16::MAX");
                    if invbits.get(bit).unwrap_or(false) {
                        wanted_tenures.get(j).map(|tenure| (false, j, tenure))
                    } else {
                        None
                    }
                })
                .or_else(|| {
                    // search `next_wanted_tenures`
                    (0..next_wanted_tenures.len()).find_map(|n| {
                        let bit = u16::try_from(n).expect("FATAL: more sortitions than u16::MAX");
                        if next_invbits.get(bit).unwrap_or(false) {
                            next_wanted_tenures.get(n).map(|tenure| (true, n, tenure))
                        } else {
                            None
                        }
                    })
                })
            else {
                test_debug!(
                    "i={} out of wanted_tenures and next_wanted_tenures",
                    iter_start + i
                );
                break;
            };

            // search after the wanted tenure we just found to get the tenure-end wanted tenure. It
            // is guaranteed to be in `next_wanted_tenures`, since otherwise we would have already
            // found it
            let next_start = if in_next { wt_start_idx + 1 } else { 0 };
            let Some(wt_end) = (next_start..next_wanted_tenures.len()).find_map(|k| {
                let bit = u16::try_from(k).expect("FATAL: more sortitions than u16::MAX");
                if next_invbits.get(bit).unwrap_or(false) {
                    next_wanted_tenures.get(k)
                } else {
                    None
                }
            }) else {
                test_debug!("i={} out of next_wanted_tenures", iter_start + i);
                break;
            };

            let mut tenure_start_end = TenureStartEnd::new(
                wt.tenure_id_consensus_hash.clone(),
                wt_start.winning_block_id.clone(),
                wt_end.winning_block_id.clone(),
                rc,
                pox_constants
                    .block_height_to_reward_cycle(first_burn_height, wt_start.burn_height)
                    .expect("FATAL: tenure from before system start"),
                wt.processed,
            );
            tenure_start_end.fetch_end_block = true;

            test_debug!(
                "i={},len={},next_len={}; {:?}",
                iter_start + i,
                wanted_tenures.len(),
                next_wanted_tenures.len(),
                &tenure_start_end
            );
            tenure_block_ids.insert(wt.tenure_id_consensus_hash.clone(), tenure_start_end);
        }

        Some(tenure_block_ids)
    }
}
