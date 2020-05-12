/*
 copyright: (c) 2013-2020 by Blockstack PBC, a public benefit corporation.

 This file is part of Blockstack.

 Blockstack is free software. You may redistribute or modify
 it under the terms of the GNU General Public License as published by
 the Free Software Foundation, either version 3 of the License or
 (at your option) any later version.

 Blockstack is distributed in the hope that it will be useful,
 but WITHOUT ANY WARRANTY, including without the implied warranty of
 MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
 GNU General Public License for more details.

 You should have received a copy of the GNU General Public License
 along with Blockstack. If not, see <http://www.gnu.org/licenses/>.
*/

use net::PeerAddress;
use net::Neighbor;
use net::NeighborKey;
use net::Error as net_error;
use net::db::PeerDB;
use net::asn::ASEntry4;

use net::*;
use net::codec::*;

use net::StacksMessage;
use net::StacksP2P;
use net::GetBlocksInv;
use net::BLOCKS_INV_DATA_MAX_BITLEN;
use net::connection::ConnectionP2P;
use net::connection::ReplyHandleP2P;
use net::connection::ConnectionOptions;

use net::neighbors::MAX_NEIGHBOR_BLOCK_DELAY;

use net::db::*;

use net::p2p::PeerNetwork;

use util::db::Error as db_error;
use util::db::DBConn;
use util::secp256k1::Secp256k1PublicKey;
use util::secp256k1::Secp256k1PrivateKey;

use chainstate::burn::BlockHeaderHash;
use chainstate::burn::db::burndb;
use chainstate::burn::db::burndb::BurnDB;
use chainstate::burn::db::burndb::BurnDBConn;
use chainstate::burn::BlockSnapshot;

use chainstate::stacks::db::StacksChainState;

use burnchains::Burnchain;
use burnchains::BurnchainView;

use std::net::SocketAddr;

use std::collections::HashMap;
use std::collections::BTreeMap;
use std::collections::HashSet;

use std::io::Read;
use std::io::Write;

use std::convert::TryFrom;

use util::log;
use util::get_epoch_time_secs;
use util::hash::to_hex;

/// This module is responsible for synchronizing block inventories with other peers
#[cfg(not(test))] pub const INV_SYNC_INTERVAL : u64 = 150;
#[cfg(test)] pub const INV_SYNC_INTERVAL : u64 = 10;

#[derive(Debug, PartialEq, Clone)]
pub struct PeerBlocksInv {
    /// Bitmap of which anchored blocks this peer has
    pub block_inv: Vec<u8>,
    /// Bitmap of which microblock streams this peer has 
    pub microblocks_inv: Vec<u8>,
    /// Number of sortitions we know this peer knows about (after successive
    /// getblocksinv/blocksinv rounds)
    pub num_sortitions: u64,
    /// Time of last update, in seconds
    pub last_updated_at: u64,
    /// Burn block height of first sortition
    pub first_block_height: u64
}

impl PeerBlocksInv {
    pub fn empty(first_block_height: u64) -> PeerBlocksInv {
        PeerBlocksInv {
            block_inv: vec![],
            microblocks_inv: vec![],
            num_sortitions: 0,
            last_updated_at: 0,
            first_block_height: first_block_height
        }
    }

    pub fn new(block_inv: Vec<u8>, microblocks_inv: Vec<u8>, num_sortitions: u64, first_block_height: u64) -> PeerBlocksInv {
        assert_eq!(block_inv.len(), microblocks_inv.len());
        PeerBlocksInv {
            block_inv: block_inv,
            microblocks_inv: microblocks_inv,
            num_sortitions: num_sortitions,
            last_updated_at: get_epoch_time_secs(),
            first_block_height: first_block_height
        }
    }

    /// Does this remote neighbor have the ith block (for the ith sortition)?
    /// (note that block_height is the _absolute_ block height)
    pub fn has_ith_block(&self, block_height: u64) -> bool {
        if block_height < self.first_block_height {
            return false;
        }
        
        let sortition_height = block_height - self.first_block_height;
        let idx = (sortition_height / 8) as usize;
        let bit = sortition_height % 8;
        
        if idx >= self.block_inv.len() {
            false
        }
        else {
            (self.block_inv[idx] & (1 << bit)) != 0
        }
    }
    
    /// Does this remote neighbor have the ith microblock stream (for the ith sortition)?
    /// (note that block_height is the _absolute_ block height)
    pub fn has_ith_microblock_stream(&self, block_height: u64) -> bool {
        if block_height < self.first_block_height {
            return false;
        }
        
        let sortition_height = block_height - self.first_block_height;
        let idx = (sortition_height / 8) as usize;
        let bit = sortition_height % 8;
        
        if idx >= self.microblocks_inv.len() {
            false
        }
        else {
            (self.microblocks_inv[idx] & (1 << bit)) != 0
        }
    }

    /// Merge a blocksinv into our knowledge of what blocks exist for this neighbor.
    /// block_height corresponds to bitvec[0] & 0x01
    /// bitlen = number of sortitions represented by this inv.
    /// returns the number of bits set in each bitvec
    pub fn merge_blocks_inv(&mut self, block_height: u64, bitlen: u16, block_bitvec: Vec<u8>, microblocks_bitvec: Vec<u8>) -> (usize, usize) {
        assert!(block_height >= self.first_block_height);
        let sortition_height = block_height - self.first_block_height;

        self.num_sortitions = 
            if self.num_sortitions < sortition_height + (bitlen as u64) {
                sortition_height + (bitlen as u64)
            }
            else {
                self.num_sortitions
            };

        let mut insert_index = sortition_height;
        let mut new_blocks = 0;
        let mut new_microblocks = 0;

        // add each bit in, growing the block inv as needed
        for i in 0..bitlen {
            let idx = (i / 8) as usize;
            let bit = i % 8;
            let block_set = (block_bitvec[idx] & (1 << bit)) != 0;
            let microblock_set = (microblocks_bitvec[idx] & (1 << bit)) != 0;

            let set_idx = (insert_index / 8) as usize;
            let set_bit = insert_index % 8;
            if set_idx >= self.block_inv.len() {
                self.block_inv.resize(set_idx + 1, 0);
            }
            if set_idx >= self.microblocks_inv.len() {
                self.microblocks_inv.resize(set_idx + 1, 0);
            }

            if block_set {
                if self.block_inv[set_idx] & (1 << set_bit) == 0 {
                    // new 
                    new_blocks += 1;
                }

                self.block_inv[set_idx] |= 1 << set_bit;
            }
            if microblock_set {
                if self.microblocks_inv[set_idx] & (1 << set_bit) == 0 {
                    // new 
                    new_microblocks += 1;
                }

                self.microblocks_inv[set_idx] |= 1 << set_bit;
            }
            insert_index += 1;
        }

        self.last_updated_at = get_epoch_time_secs();

        assert!(insert_index / 8 <= self.block_inv.len() as u64);
        assert!(self.num_sortitions / 8 <= self.block_inv.len() as u64);

        (new_blocks, new_microblocks)
    }

    /// Set a block's bit as available.
    /// Return whether or not the block bit was flipped to 1.
    pub fn set_block_bit(&mut self, block_height: u64) -> bool {
        let (new_blocks, _) = self.merge_blocks_inv(block_height, 1, vec![0x01], vec![0x00]);
        new_blocks != 0
    }
    
    /// Set a confirmed microblock stream's bit as available.
    /// Return whether or not the bit was flipped to 1.
    pub fn set_microblocks_bit(&mut self, block_height: u64) -> bool {
        let (_, new_mblocks) = self.merge_blocks_inv(block_height, 1, vec![0x00], vec![0x01]);
        new_mblocks != 0
    }

    /// Count up the number of blocks represented
    pub fn num_blocks(&self) -> u64 {
        let mut total = 0;
        for i in self.first_block_height..self.num_sortitions {
            if self.has_ith_block(i) {
                total += 1;
            }
        }
        total
    }
    
    /// Count up the number of microblock streams represented
    pub fn num_microblock_streams(&self) -> u64 {
        let mut total = 0;
        for i in self.first_block_height..self.num_sortitions {
            if self.has_ith_microblock_stream(i) {
                total += 1;
            }
        }
        total
    }
}

#[derive(Debug, PartialEq, Clone)]
pub struct NeighborBlockStats {
    /// What blocks do we know this peer has?
    pub inv: PeerBlocksInv,
}

impl NeighborBlockStats {
    pub fn new(first_block_height: u64) -> NeighborBlockStats {
        NeighborBlockStats {
            inv: PeerBlocksInv::empty(first_block_height),
        }
    }

    /// Find winning sortitions corresponding to any blocks that are missing from this peer.
    /// Includes sortition_height_start; excludes sortition_height_end.
    /// Used to inform sending getblockinvs and get-requests for blocks.
    /// If the requested range isn't fully included in the bitvec we have, then the resulting
    /// vector will be truncated.
    pub fn find_missing_stacks_blocks(&self, burndb: &BurnDB, sortition_height_start: u64, sortition_height_end: u64) -> Result<Vec<Option<BlockSnapshot>>, net_error> {
        if self.inv.num_sortitions < sortition_height_start {
            return Ok(vec![]);
        }

        let mut ret = vec![];
        let ic = burndb.index_conn();
        let canonical_tip = BurnDB::get_canonical_burn_chain_tip(&ic).map_err(net_error::DBError)?;
        for height in sortition_height_start..sortition_height_end {
            if !self.inv.has_ith_block(height) {
                // of the edge of the bitmap
                break;
            }
            else {
                // is this block missing from this peer, or does it not exist in the first place?
                match BurnDB::get_block_snapshot_in_fork(&ic, height, &canonical_tip.burn_header_hash).map_err(net_error::DBError)? {
                    None => {
                        ret.push(None);
                    },
                    Some(sn) => {
                        if sn.sortition {
                            ret.push(Some(sn));
                        }
                        else {
                            ret.push(None);
                        }
                    }
                }
            }
        }
        Ok(ret)
    }
}

#[derive(Debug, Clone, PartialEq, Copy)]
pub enum InvWorkState {
    GetBlocksInvBegin,
    GetBlocksInvFinish,
    Done
}

#[derive(Debug, Clone, PartialEq, Copy)]
enum NackResult {
    Stale,
    Unstable,
    Diverged,
    Broken,
    Noop
}

pub struct InvState {
    /// What state is this state-machine in?
    state: InvWorkState,

    /// In-flight requests for block-invs
    getblocksinv_requests: HashMap<NeighborKey, ReplyHandleP2P>,
    getblocksinv_target_heights: HashMap<NeighborKey, u64>,
    pub block_invs: HashMap<NeighborKey, BlocksInvData>,

    /// Peers that we are currently synchronizing with.
    pub sync_peers: HashSet<NeighborKey>,
    /// Peers that are behind us
    pub stale_peers: HashSet<NeighborKey>,
    /// Peers that have different unstable consensus hashes from us
    pub unstable_peers: HashSet<NeighborKey>,
    /// Peers that have different stable consensus hashes from us
    pub diverged_peers: HashSet<NeighborKey>,
    /// Peers that sent protocol-violating data
    pub broken_peers: HashSet<NeighborKey>,
    /// Peers that we couldn't contact
    pub dead_peers: HashSet<NeighborKey>,
    
    /// Accumulated knowledge of which peers have which blocks.
    /// Kept separately from p2p conversations so they persist 
    /// beyond connection resets (since they can be expensive 
    /// to build up).
    pub block_stats: HashMap<NeighborKey, NeighborBlockStats>,

    /// How long is a request allowed to take?
    request_timeout: u64,
    /// First burn block height
    first_block_height: u64,

    /// Rescan height for this peer -- this is the block height at which we will periodically
    /// scan our local chain state and find out what blocks we're still missing.
    pub rescan_height: u64,
    /// Last time we did a full re-scan
    last_rescanned_at: u64,
    /// Last time we learned about new blocks
    pub last_change_at: u64,
    /// Number of times we've done a rescan
    num_rescans: u64,
    /// How often to re-sync
    sync_interval: u64,
    /// Did we learn something in this last scan?
    pub learned_data: bool,
    /// Should we do a full re-scan?
    hint_do_full_rescan: bool,
}

impl InvState {
    pub fn new(first_block_height: u64, request_timeout: u64, sync_interval: u64, initial_peers: HashSet<NeighborKey>) -> InvState {
        InvState {
            state: InvWorkState::GetBlocksInvBegin,

            getblocksinv_requests: HashMap::new(),
            getblocksinv_target_heights: HashMap::new(),
            block_invs: HashMap::new(),

            sync_peers: initial_peers,
            stale_peers: HashSet::new(),
            unstable_peers: HashSet::new(),
            diverged_peers: HashSet::new(),
            broken_peers: HashSet::new(),
            dead_peers: HashSet::new(),

            block_stats: HashMap::new(),

            request_timeout: request_timeout,
            first_block_height: first_block_height,

            rescan_height: first_block_height,
            last_rescanned_at: 0,
            num_rescans: 0,
            last_change_at: 0,
            sync_interval: sync_interval,
            learned_data: true,     // force a first-pass
            hint_do_full_rescan: true,
        }
    }

    pub fn reset(&mut self) -> () {
        self.state = InvWorkState::GetBlocksInvBegin;

        self.getblocksinv_requests.clear();
        self.getblocksinv_target_heights.clear();
        self.block_invs.clear();

        self.stale_peers.clear();
        self.unstable_peers.clear();
        self.diverged_peers.clear();
        self.broken_peers.clear();
        self.dead_peers.clear();

        // preserve block_stats
        // preserve rescan_height
    }

    pub fn set_sync_peers(&mut self, peers: HashSet<NeighborKey>) -> () {
        self.sync_peers.clear();
        self.sync_peers = peers;
    }

    /// Can we rely on the inventory from this peer? i.e. is the peer in sync with our view of the
    /// burnchain?
    pub fn is_inv_valid(&self, nk: &NeighborKey) -> bool {
        !self.diverged_peers.contains(nk) && !self.broken_peers.contains(nk)
    }

    /// Is the inventory in this peer up-to-date with the given number of sortitions (even if it's diverged)?
    pub fn is_inv_synced(&self, nk: &NeighborKey, min_num_sortitions: u64) -> bool {
        if self.broken_peers.contains(nk) {
            return false;
        }

        match self.block_stats.get(nk) {
            None => false,
            Some(ref stats) => stats.inv.num_sortitions >= min_num_sortitions
        }
    }

    /// How many sortitions do we know about from this neighbor?
    /// Ignores broken or diverged peers.
    pub fn get_inv_sortitions(&self, nk: &NeighborKey) -> u64 {
        if self.broken_peers.contains(nk) || self.diverged_peers.contains(nk) {
            return 0;
        }

        match self.block_stats.get(nk) {
            Some(stats) => stats.inv.num_sortitions,
            _ => 0
        }
    }

    /// Cull sync peers of broken peers
    pub fn cull_broken_peers(&mut self) -> () {
        for nk in self.broken_peers.iter() {
            if self.sync_peers.contains(nk) {
                debug!("Cull broken peer {:?}", nk);
                self.sync_peers.remove(nk);
            }
        }
    }

    /// Cull sync peers of stale peers 
    pub fn cull_stale_peers(&mut self) -> () {
        for nk in self.stale_peers.iter() {
            if self.sync_peers.contains(nk) {
                debug!("Cull stale peer {:?}", nk);
                self.sync_peers.remove(nk);
            }
        }
    }

    /// Cull sync peers of dead peers
    pub fn cull_dead_peers(&mut self) -> () {
        for nk in self.dead_peers.iter() {
            if self.sync_peers.contains(nk) {
                debug!("Cull dead peer {:?}", nk);
                self.sync_peers.remove(nk);
            }
        }
    }
    
    /// Cull sync peers of diverged peers
    pub fn cull_diverged_peers(&mut self) -> () {
        for nk in self.diverged_peers.iter() {
            if self.sync_peers.contains(nk) {
                debug!("Cull diverged peer {:?}", nk);
                self.sync_peers.remove(nk);
            }
        }
    }

    /// Get the list of broken peers
    pub fn get_broken_peers(&self) -> Vec<NeighborKey> {
        let mut set = HashSet::new();
        for nk in self.broken_peers.iter() {
            set.insert(nk.clone());
        }
        set.into_iter().collect()
    }
    
    /// Get the list of dead
    pub fn get_dead_peers(&self) -> Vec<NeighborKey> {
        let mut set = HashSet::new();
        for nk in self.dead_peers.iter() {
            set.insert(nk.clone());
        }
        set.into_iter().collect()
    }

    pub fn get_stats(&self, nk: &NeighborKey) -> Option<&NeighborBlockStats> {
        self.block_stats.get(nk)
    }

    pub fn add_peer(&mut self, nk: NeighborKey) -> () {
        self.block_stats.insert(nk, NeighborBlockStats::new(self.first_block_height));
    }

    pub fn del_peer(&mut self, nk: &NeighborKey) -> () {
        self.block_stats.remove(&nk);
    }

    /// Set a block or confirmed microblock stream as available, given the burn header hash and consensus hash.
    /// Used when processing a BlocksAvailable or MicroblocksAvailable message.
    /// Returns the optional block sortition height at which the block or confirmed microblock stream resides in the blockchain (returns
    /// None if its bit was already set).
    fn set_data_available(&mut self, neighbor_key: &NeighborKey, burndb: &BurnDB, consensus_hash: &ConsensusHash, burn_header_hash: &BurnchainHeaderHash, microblocks: bool) -> Result<Option<u64>, net_error> {
        let sn = match BurnDB::get_block_snapshot(burndb.conn(), burn_header_hash)? {
            Some(sn) => sn,
            None => {
                // we don't know about this block
                test_debug!("Unknown burn header {}", burn_header_hash);
                return Ok(None);
            }
        };

        if sn.consensus_hash != *consensus_hash {
            // Peer processed different burn transactions than we did for this block.
            // In PoX, this can happen if a prior reward window anchor block is missing, but we
            // haven't discovered it yet.
            // TODO: Until PoX is implemented, we can assume that this doesn't happen.
            test_debug!("Incorrect consensus hash: {} != {}", &sn.consensus_hash, consensus_hash);
            return Ok(None);
        }

        if !sn.sortition {
            // No block is available here anyway, even though the peer agrees with us on the
            // consensus hash.
            // This is bad behavior on the peer's part.
            test_debug!("No sortition at {}", burn_header_hash);
            return Err(net_error::InvalidMessage);
        }

        match self.block_stats.get_mut(neighbor_key) {
            Some(stats) => {
                // NOTE: block heights are 1-indexed in the burn DB, since the 0th snapshot block is the
                // genesis snapshot and doesn't correspond to anything (the 1st snapshot is block 0)
                let set = 
                    if microblocks {
                        debug!("Neighbor {:?} now has confirmed microblock stream at {} ({})", neighbor_key, sn.block_height - 1, burn_header_hash);
                        stats.inv.set_microblocks_bit(sn.block_height - 1)
                    }
                    else {
                        debug!("Neighbor {:?} now has block at {} ({})", neighbor_key, sn.block_height - 1, burn_header_hash);
                        stats.inv.set_block_bit(sn.block_height - 1)
                    };

                debug!("Neighbor {:?} stats: {:?}", neighbor_key, stats);
                if set {
                    let block_sortition_height = sn.block_height - 1 - burndb.first_block_height;
                    Ok(Some(block_sortition_height))
                }
                else {
                    Ok(None)
                }
            },
            None => {
                test_debug!("No inv stats for neighbor {:?}", neighbor_key);
                Ok(None)
            }
        }
    }
    
    pub fn set_block_available(&mut self, neighbor_key: &NeighborKey, burndb: &BurnDB, consensus_hash: &ConsensusHash, burn_header_hash: &BurnchainHeaderHash) -> Result<Option<u64>, net_error> {
        self.set_data_available(neighbor_key, burndb, consensus_hash, burn_header_hash, false)
    }

    pub fn set_microblocks_available(&mut self, neighbor_key: &NeighborKey, burndb: &BurnDB, consensus_hash: &ConsensusHash, burn_header_hash: &BurnchainHeaderHash) -> Result<Option<u64>, net_error> {
        self.set_data_available(neighbor_key, burndb, consensus_hash, burn_header_hash, true)
    }

    pub fn getblocksinv_begin(&mut self, requests: HashMap<NeighborKey, ReplyHandleP2P>, target_heights: HashMap<NeighborKey, u64>) -> () {
        assert_eq!(self.state, InvWorkState::GetBlocksInvBegin);
        assert_eq!(requests.len(), target_heights.len());

        self.block_invs.clear();
        self.getblocksinv_requests = requests;
        self.getblocksinv_target_heights = target_heights;
        
        self.state = InvWorkState::GetBlocksInvFinish;
    }

    /// Determine what to do with a NACK response.
    fn diagnose_nack(_nk: &NeighborKey, nack_data: NackData, chain_view: &BurnchainView, preamble_burn_block_height: u64, preamble_burn_stable_block_height: u64, preamble_burn_consensus_hash: ConsensusHash, preamble_burn_stable_consensus_hash: ConsensusHash) -> NackResult {
        let mut diverged = false;
        let mut unstable = false;
        let mut broken = false;
        let mut stale = false;

        if nack_data.error_code == NackErrorCodes::NoSuchBurnchainBlock {
            // peer nacked us -- it doesn't know about the block(s) we asked about.
            if preamble_burn_block_height < chain_view.burn_block_height {
                // Because it's stale
                test_debug!("Remote neighbor {:?} is still bootstrapping at block {}, whereas we are at block {}", _nk, preamble_burn_block_height, chain_view.burn_block_height);
                stale = true;
            }
            else {
                // Because it's diverged?
                diverged = match chain_view.last_consensus_hashes.get(&preamble_burn_stable_block_height) {
                    Some(stable_ch) => *stable_ch != preamble_burn_stable_consensus_hash,
                    None => true
                };
                // Because its view of the unstable portion of the burn chain is not the same as
                // ours?
                unstable = 
                    if chain_view.burn_block_height == preamble_burn_block_height {
                        chain_view.burn_consensus_hash != preamble_burn_consensus_hash
                    }
                    else {
                        // peer is ahead of us, so we can't tell
                        true
                    };

                if diverged {
                    debug!("Remote neighbor {:?} NACKed us because it diverged", _nk);
                }
                else if unstable {
                    debug!("Remote neighbor {:?} NACKed us because it's chain tip is different from ours", _nk);
                }
                else {
                    // something else is wrong
                    debug!("Remote neighbor {:?} NACKed us because its block height is not in the chain view", _nk);
                    broken = true;
                }
            }
        }
        else {
            // some other error
            debug!("Remote neighbor {:?} NACKed us with error code {}", _nk, nack_data.error_code);
            broken = true;
        }

        if broken {
            NackResult::Broken
        }
        else if diverged {
            NackResult::Diverged
        }
        else if stale {
            NackResult::Stale
        }
        else if unstable {
            NackResult::Unstable
        }
        else {
            NackResult::Noop
        }
    }

    /// Try to finish getting all BlocksInvData requests.
    /// Return true if this method is done -- i.e. all requests have been handled.
    /// Return false if we're not done.
    pub fn getblocksinv_try_finish(&mut self, network: &mut PeerNetwork) -> Result<bool, net_error> {
        assert_eq!(self.state, InvWorkState::GetBlocksInvFinish);

        // requests that are still pending
        let mut pending_getblocksinv_requests = HashMap::new();
        for (nk, mut rh) in self.getblocksinv_requests.drain() {
            if let Err(_e) = network.saturate_p2p_socket(rh.get_event_id(), &mut rh) {
                self.dead_peers.insert(nk);
                continue;
            }
            let res = rh.try_send_recv();
            let rh_nk = nk.clone();
            let _target_height = *self.getblocksinv_target_heights.get(&nk).expect(&format!("BUG: no target block height for request to {:?}", &nk));

            let new_rh = match res {
                Ok(message) => {
                    let preamble_burn_block_height = message.preamble.burn_block_height;
                    let preamble_burn_stable_block_height = message.preamble.burn_stable_block_height;
                    let preamble_burn_consensus_hash = message.preamble.burn_consensus_hash.clone();
                    let preamble_burn_stable_consensus_hash = message.preamble.burn_stable_consensus_hash.clone();

                    match message.payload {
                        StacksMessageType::BlocksInv(blocks_inv_data) => {
                            // got a BlocksInv!
                            // but, only accept it if the peer isn't too far ahead of us
                            debug!("Got BlocksInv response at height {} from {:?} at ({},{}): {:?}", _target_height, &nk, preamble_burn_block_height, preamble_burn_stable_block_height, &blocks_inv_data);
                            self.block_invs.insert(nk, blocks_inv_data);
                        },
                        StacksMessageType::Nack(nack_data) => {
                            debug!("Remote neighbor {:?} nack'ed our GetBlocksInv: NACK code {}", &nk, nack_data.error_code);
                            match InvState::diagnose_nack(&nk, nack_data, &network.chain_view, preamble_burn_block_height, preamble_burn_stable_block_height, preamble_burn_consensus_hash, preamble_burn_stable_consensus_hash) {
                                NackResult::Noop => {},
                                NackResult::Stale => {
                                    debug!("Peer {:?} is stale", nk);
                                    self.stale_peers.insert(nk);
                                },
                                NackResult::Unstable => {
                                    test_debug!("Peer {:?} is unstable", nk);
                                    self.unstable_peers.insert(nk);
                                },
                                NackResult::Diverged => {
                                    test_debug!("Peer {:?} is diverged", nk);
                                    self.diverged_peers.insert(nk);
                                },
                                NackResult::Broken => {
                                    debug!("Peer {:?} is broken", nk);
                                    self.broken_peers.insert(nk);
                                }
                            };
                        },
                        _ => {
                            // unexpected reply
                            debug!("Remote neighbor {:?} sent an unexpected reply of '{}'", &nk, message.get_message_name());
                            self.broken_peers.insert(nk);
                        }
                    }

                    None
                },
                Err(req_res) => {
                    match req_res {
                        Ok(same_req) => {
                            // try again 
                            Some(same_req)
                        },
                        Err(_e) => {
                            // connection broken.
                            // Don't try to contact this node again.
                            debug!("Failed to get block inventory from {:?}: {:?}", &nk, &_e);
                            self.dead_peers.insert(nk);
                            None
                        }
                    }
                }
            };

            if let Some(rh) = new_rh {
                // still working
                pending_getblocksinv_requests.insert(rh_nk, rh);
            }
        }

        debug!("Still waiting for {} blocksinv replies", pending_getblocksinv_requests.len());

        // are we done?
        if pending_getblocksinv_requests.len() == 0 {
            // don't call this again!
            self.state = InvWorkState::Done;
            return Ok(true);
        }

        self.getblocksinv_requests = pending_getblocksinv_requests;
        return Ok(false);
    }
}    

impl PeerNetwork {
    /// Given a sortition height of a block we're interested in, make a GetBlocksInv whose
    /// _lowest_ block will be at the target sortition height.
    fn make_highest_getblocksinv(&self, nk: &NeighborKey, target_block_height: u64, burndb: &BurnDB) -> Result<Option<GetBlocksInv>, net_error> {
        if target_block_height > self.chain_view.burn_block_height {
            debug!("{:?}: target block height for neighbor {:?} is {}, which is higher than our chain view height {}", &self.local_peer, nk, target_block_height, self.chain_view.burn_block_height);
            return Ok(None);
        }

        // ask for all blocks in-between target_block_height and highest_block_height
        let (mut highest_block_height, mut num_blocks) = 
            if target_block_height + (BLOCKS_INV_DATA_MAX_BITLEN as u64) < self.chain_view.burn_block_height {
                (target_block_height + (BLOCKS_INV_DATA_MAX_BITLEN as u64), BLOCKS_INV_DATA_MAX_BITLEN as u64)
            }
            else {
                (self.chain_view.burn_block_height, self.chain_view.burn_block_height - target_block_height)
            };

        // from our last conversation, if the peer knows of a higher block height than
        // target_block_height but lower than highest_block_height, use that instead.
        match self.get_convo(nk) {
            Some(convo) => {
                let stable_tip_height = convo.get_stable_burnchain_tip_height();
                let stable_tip_consensus_hash = convo.get_stable_burnchain_tip_consensus_hash();
                let tip_height = convo.get_burnchain_tip_height();
                let tip_consensus_hash = convo.get_burnchain_tip_consensus_hash();

                debug!("{:?}: chain view of {:?} is ({},{})-({},{})", &self.local_peer, nk, stable_tip_height, &stable_tip_consensus_hash, tip_height, &tip_consensus_hash);
                match BurnDB::get_block_snapshot_consensus(burndb.conn(), &tip_consensus_hash).map_err(net_error::DBError)? {
                    // we know about this peer's latest consensus hash's snapshot.  Ask for blocks
                    // no higher than its highest known block.
                    Some(_sn) => {
                        if tip_height < highest_block_height {
                            debug!("{:?}: neighbor {:?} has processed only up to burn block {} (we are targeting {} and higher)", &self.local_peer, nk, tip_height, target_block_height);

                            highest_block_height = tip_height;
                            num_blocks = if highest_block_height >= target_block_height { highest_block_height - target_block_height } else { 0 };
                        }
                    },

                    // this peer is unstable -- its tip consensus hash differs from ours, but we
                    // agree with its stable consensus hash.  Ask only for blocks no higher than
                    // its stable consensus hash.
                    None => match BurnDB::get_block_snapshot_consensus(burndb.conn(), &stable_tip_consensus_hash).map_err(net_error::DBError)? {
                        Some(_sn) => {
                            if stable_tip_height < highest_block_height {
                                test_debug!("{:?}: neighbor {:?} is unstable, and has processed only up to stable burn block {} (we are targeting {})", &self.local_peer, nk, tip_height, target_block_height);

                                highest_block_height = stable_tip_height;
                                num_blocks = if highest_block_height >= target_block_height { highest_block_height - target_block_height } else { 0 };
                            }
                        },
                        None => {
                            if stable_tip_height <= target_block_height {
                                // this peer has diverged from us
                                test_debug!("{:?}: neighbor {:?}'s highest stable consensus hash {:?} does not match any of ours", &self.local_peer, nk, &stable_tip_consensus_hash);
                                return Ok(None);
                            }
                            else if tip_height <= target_block_height {
                                // this peer is unstable
                                test_debug!("{:?}: neighbor {:?}'s highest stable consensus hash {:?} does not match our latest", &self.local_peer, nk, &stable_tip_consensus_hash);
                                return Ok(None);
                            }
                            // otherwise, this peer is simply ahead of us.
                        }
                    },
                }
            },
            // never talked to this peer before
            None => {
                debug!("{:?}: no conversation open for {}", &self.local_peer, nk);
                return Ok(None);
            }
        }

        if num_blocks == 0 {
            // target_block_height was higher than the highest known height of the remote node
            debug!("{:?}: will not request BlocksInv from {:?}, since we are sync'ed up to its highest sortition block (our target was {}, its highest block was {})", &self.local_peer, nk, target_block_height, highest_block_height);
            return Ok(None);
        }
        assert!(num_blocks <= BLOCKS_INV_DATA_MAX_BITLEN as u64);

        let ic = burndb.index_conn();
        let tip = BurnDB::get_canonical_burn_chain_tip(&ic).map_err(net_error::DBError)?;
        match BurnDB::get_consensus_at(&ic, highest_block_height, &tip.burn_header_hash).map_err(net_error::DBError)? {
            Some(ch) => {
                test_debug!("{:?}: Request BlocksInv from {:?} for {} blocks up to sortition block {}", &self.local_peer, nk, num_blocks, highest_block_height);
                Ok(Some(GetBlocksInv { consensus_hash: ch, num_blocks: num_blocks as u16 }))
            }
            None => {
                test_debug!("{:?}: Will not send BlocksInv -- unknown consensus hash at height {}", &self.local_peer, highest_block_height);
                Ok(None)        // can't ask for inv data for sortitions we haven't gotten to yet
            }
        }
    }

    /// Make a GetBlocksInv to send to our neighbors
    fn make_next_getblocksinv(&self, inv_state: &mut InvState, burndb: &BurnDB, nk: &NeighborKey) -> Result<Option<(u64, GetBlocksInv)>, net_error> {
        // target_block_height is the highest sortition height we know this node knows about.
        // Ask for block inventory data _after_ this.
        let target_block_height = match inv_state.get_stats(nk) {
            Some(ref stats) => burndb.first_block_height.checked_add(stats.inv.num_sortitions).expect("Blockchain sortition overflow"),
            None => {
                return Err(net_error::PeerNotConnected);
            }
        };

        if target_block_height < self.chain_view.burn_block_height {
            // We don't yet know all of the blocks this node knows about.
            test_debug!("{:?}: not sync'ed with {:?} yet (target {} < tip {}); make GetBlocksInv based at {}", &self.local_peer, nk, target_block_height, self.chain_view.burn_block_height, target_block_height);
            let request_opt = self.make_highest_getblocksinv(nk, target_block_height, burndb)?;
            match request_opt {
                Some(request) => Ok(Some((target_block_height, request))),
                None => {
                    debug!("{:?}: will not fetch inventory from {:?} even though target block height {} < {}", &self.local_peer, nk, target_block_height, self.chain_view.burn_block_height);
                    Ok(None)
                }
            }
        }
        else {
            // We know which blocks this node knows about, up to our chain height.
            // We may be in the process of re-scanning this node.  Proceed with the rescan request.
            test_debug!("{:?}: sync'ed up; make GetBlocksInv based at rescan height {}", &self.local_peer, inv_state.rescan_height);
            let request_opt = self.make_highest_getblocksinv(nk, inv_state.rescan_height, burndb)?;
            match request_opt {
                Some(request) => Ok(Some((inv_state.rescan_height, request))),
                None => {
                    debug!("{:?}: will not fetch inventory from {:?} rescan height {}", &self.local_peer, nk, inv_state.rescan_height);
                    Ok(None)
                }
            }
        }
    }
    
    pub fn with_inv_state<F, R>(network: &mut PeerNetwork, handler: F) -> Result<R, net_error> 
    where
        F: FnOnce(&mut PeerNetwork, &mut InvState) -> Result<R, net_error>
    {
        let mut inv_state = network.inv_state.take();
        let res = match inv_state {
            None => {
                test_debug!("{:?}: inv state not connected", &network.local_peer);
                Err(net_error::NotConnected)
            },
            Some(ref mut invs) => handler(network, invs)
        };
        network.inv_state = inv_state;
        res
    }

    /// Start requesting the next batch of block inventories
    pub fn inv_getblocksinv_begin(&mut self, burndb: &BurnDB) -> Result<(), net_error> {
        test_debug!("{:?}: getblocksinv_begin", &self.local_peer);
        PeerNetwork::with_inv_state(self, |ref mut network, ref mut inv_state| {
            let mut inv_targets : HashMap<NeighborKey, (u64, GetBlocksInv)> = HashMap::new();
            for (nk, event_id) in network.events.iter() {
                // don't talk to inbound peers; only outbound (and only ones we have the key for)
                // (we make this check each time we begin a round of inv requests, since the set of
                // available peers can change during this time).
                let is_target = match network.peers.get(event_id) {
                    Some(convo) => {
                        if !convo.is_outbound() {
                            debug!("{:?}: skip {:?}: not outbound", &network.local_peer, convo);
                            continue;
                        }
                        if !convo.is_authenticated() {
                            debug!("{:?}: skip {:?}: not authenticated", &network.local_peer, convo);
                            continue;
                        }
                        true
                    }
                    None => false
                };
                if !is_target {
                    continue;
                }

                if inv_state.get_stats(nk).is_none() {
                    // no stats on file for this node yet
                    debug!("Adding new inventory statistics for {:?}", &nk);
                    inv_state.add_peer(nk.clone());
                }

                let (target_block_height, inv) = match network.make_next_getblocksinv(inv_state, burndb, &nk)? {
                    Some(request) => request,
                    None => {
                        debug!("{:?}: skip {:?}, since we could not make a GetBlocksInv for it", &network.local_peer, &nk);
                        continue;
                    }
                };

                inv_targets.insert(nk.clone(), (target_block_height, inv));
            }

            debug!("{:?}: Will send {} getblocksinv requests (out of {} active events)", &network.local_peer, inv_targets.len(), network.events.len());

            // send to all of them 
            let mut inv_requests : HashMap<NeighborKey, ReplyHandleP2P> = HashMap::new();
            let mut inv_heights : HashMap<NeighborKey, u64> = HashMap::new();

            for (nk, (target_height, inv_request)) in inv_targets.drain() {
                debug!("{:?}: send getblocksinv request targeted at {}: {:?} to {:?}", &network.local_peer, target_height, &inv_request, &nk);

                let payload = StacksMessageType::GetBlocksInv(inv_request);
                let message = network.sign_for_peer(&nk, payload)?;
                let rh = match network.send_message(&nk, message, inv_state.request_timeout) {
                    Ok(rh) => rh,
                    Err(e) => {
                        debug!("Failed to send GetBlocksInv to {:?}: {:?}", &nk, &e);
                        continue;
                    }
                };

                inv_requests.insert(nk.clone(), rh);
                inv_heights.insert(nk, target_height);
            }

            inv_state.learned_data = false;     // haven't learned anything yet in this scan
            inv_state.getblocksinv_begin(inv_requests, inv_heights);
            Ok(())
        })
    }

    /// Finish requesting block-invs 
    pub fn inv_getblocksinv_finish(&mut self) -> Result<bool, net_error> {
        test_debug!("{:?}: getblocksinv_try_finish", &self.local_peer);
        PeerNetwork::with_inv_state(self, |ref mut network, ref mut inv_state| {
            inv_state.getblocksinv_try_finish(network)
        })
    }

    /// Get the list of outbound neighbors we can sync with 
    fn get_outbound_sync_peers(&self) -> HashSet<NeighborKey> {
        let mut cur_neighbors = HashSet::new();
        for (nk, event_id) in self.events.iter() {
            // only outbound authenticated peers
            match self.peers.get(event_id) {
                Some(convo) => {
                    if convo.is_outbound() && convo.is_authenticated() {
                        cur_neighbors.insert(nk.clone());
                    }
                },
                None => {}
            }
        }
        cur_neighbors
    }

    /// Set a hint that we learned something new, and need to sync invs again
    pub fn hint_sync_invs(&mut self) -> () {
        match self.inv_state {
            Some(ref mut inv_state) => {
                debug!("Awaken inv sync to re-scan peer block inventories");
                inv_state.learned_data = true;
                inv_state.hint_do_full_rescan = true;
            },
            None => {}
        }
    }
    
    /// Initialize inv state
    pub fn init_inv_sync(&mut self, burndb: &BurnDB) -> () {
        // find out who we'll be synchronizing with for the duration of this inv sync
        let cur_neighbors = self.get_outbound_sync_peers();
        
        debug!("{:?}: Initializing peer block inventory state with {} neighbors", &self.local_peer, cur_neighbors.len());
        self.inv_state = Some(InvState::new(burndb.first_block_height, self.connection_opts.timeout, self.connection_opts.inv_sync_interval, cur_neighbors));
    }

    /// Drive fetching block invs.
    /// Returns the list of dead and broken peers that we should disconnect from, as well as a flag
    /// to indicate if we're done with the scan.
    pub fn sync_peer_block_invs(&mut self, burndb: &BurnDB) -> Result<(bool, Vec<NeighborKey>, Vec<NeighborKey>), net_error> {
        if self.inv_state.is_none() {
            self.init_inv_sync(burndb);
        }

        match self.inv_state {
            Some(ref inv_state) => {
                // NOTE: inv_state.learned_data will be true if we called init_inv_sync()
                if !inv_state.hint_do_full_rescan && !inv_state.learned_data && inv_state.last_rescanned_at + inv_state.sync_interval >= get_epoch_time_secs() {
                    // we didn't learn anything on the last sync, and it hasn't been enough time
                    // since the last sync for us to do it again
                    debug!("{:?}: Throttle inv sync until {}s", &self.local_peer, inv_state.last_rescanned_at + inv_state.sync_interval);
                    return Ok((true, vec![], vec![]));
                }
            }
            None => {
                unreachable!();
            }
        }
        
        let mut did_cycle = false;
        let res = loop {
            let state = self.inv_state.as_ref().unwrap().state;
            
            debug!("{:?}: inv-sync state is {:?}", &self.local_peer, state);
            let done_res = match state {
                InvWorkState::GetBlocksInvBegin => {
                    self.inv_getblocksinv_begin(burndb)
                        .and_then(|_| Ok(false))
                },
                InvWorkState::GetBlocksInvFinish => {
                    self.inv_getblocksinv_finish()
                        .and_then(|d| Ok(d))
                },
                InvWorkState::Done => {
                    did_cycle = true;
                    Ok(true)
                }
            };

            if did_cycle || done_res.is_err() {
                break done_res;
            }

            let new_state = self.inv_state.as_ref().unwrap().state;
            if new_state == state {
                break done_res;
            }
        };

        let done = match res {
            Ok(d) => d,
            Err(e) => {
                warn!("Failed to exeucte inventory synchronization: {:?}", &e);
                return Err(e);
            }
        };

        if !done {
            // more work to do in this round of inv requests.
            Ok((false, vec![], vec![]))
        }
        else {
            // we'll need this below, but we can't access self inside the match 
            let cur_neighbors = self.get_outbound_sync_peers();

            // finished this round of inv requests.  Merge them into our stats
            match self.inv_state {
                Some(ref mut inv_state) => {
                    // update inv stats
                    for (nk, blocks_inv) in inv_state.block_invs.drain() {
                        match inv_state.block_stats.get_mut(&nk) {
                            Some(ref mut nk_stats) => {
                                let target_height = *inv_state.getblocksinv_target_heights.get(&nk).expect(&format!("BUG: no target height for request to {:?}", &nk));

                                debug!("{:?}: got blocksinv at block height {} from {:?}: {:?}", &self.local_peer, target_height, &nk, &blocks_inv);
                                let (new_blocks, new_microblocks) = nk_stats.inv.merge_blocks_inv(target_height, blocks_inv.bitlen, blocks_inv.block_bitvec, blocks_inv.microblocks_bitvec);
                                debug!("{:?}: {:?} has {} new blocks and {} new microblocks (total {} blocks, {} microblocks): {:?}", 
                                       &self.local_peer, &nk, new_blocks, new_microblocks, nk_stats.inv.num_blocks(), nk_stats.inv.num_microblock_streams(), &nk_stats.inv);

                                if new_blocks > 0 || new_microblocks > 0 {
                                    // learned something new
                                    inv_state.last_change_at = get_epoch_time_secs();
                                    inv_state.learned_data = true;
                                }
                            }
                            None => {}
                        }
                    }
                   
                    // stop talking to dead, broken, stale, and diverged peers
                    inv_state.cull_dead_peers();
                    inv_state.cull_broken_peers();
                    inv_state.cull_stale_peers();
                    inv_state.cull_diverged_peers();

                    assert!(burndb.first_block_height <= self.chain_view.burn_block_height);
                    let min_sortitions_to_sync = self.chain_view.burn_block_height - burndb.first_block_height;

                    // if all peers we're sync'ing with are either up-to-date with our chain view,
                    // or if we now know they're stale (i.e. we're ahead), then we're done with the
                    // scan.  We can proceed to do a re-scan.
                    if inv_state.rescan_height < self.chain_view.burn_block_height {
                        test_debug!("{:?}: Continue to sync up to block {} (at {} now)", &self.local_peer, self.chain_view.burn_block_height, inv_state.rescan_height);

                        let _old_scan_height = inv_state.rescan_height;

                        // next batch of inv data
                        inv_state.rescan_height += 
                            if inv_state.rescan_height + (BLOCKS_INV_DATA_MAX_BITLEN as u64) < self.chain_view.burn_block_height {
                                BLOCKS_INV_DATA_MAX_BITLEN as u64
                            }
                            else {
                                self.chain_view.burn_block_height - inv_state.rescan_height
                            };

                        debug!("{:?}: Advanced inv-sync rescan height to {} from {}", &self.local_peer, inv_state.rescan_height, _old_scan_height);
                    }
                    else {
                        let mut all_synced = true;
                        for nk in inv_state.sync_peers.iter() {
                            if inv_state.getblocksinv_target_heights.get(nk).is_some() && inv_state.is_inv_valid(nk) && !inv_state.is_inv_synced(nk, min_sortitions_to_sync) && !inv_state.stale_peers.contains(nk) {
                                // a non-stale peer that we're not yet fully sync'ed with yet
                                debug!("{:?} Not all neighbors sync'ed yet; still need {:?}", &self.local_peer, nk);
                                all_synced = false;
                            }
                        }

                        if all_synced {
                            // restart sync'ing with the current neighbors
                            debug!("{:?}: Inv-sync finished with all ({}) up-to-date neighbors ({} sortitions); restarting scan with {} peers", &self.local_peer, inv_state.sync_peers.len(), min_sortitions_to_sync, cur_neighbors.len());

                            inv_state.rescan_height = burndb.first_block_height;
                            inv_state.set_sync_peers(cur_neighbors);

                            if inv_state.hint_do_full_rescan {
                                // finished all scanning duties
                                inv_state.hint_do_full_rescan = false;
                            }
                            
                            inv_state.last_rescanned_at = get_epoch_time_secs();
                            inv_state.num_rescans += 1;
                        }
                    }

                    let broken = inv_state.get_broken_peers();
                    let disconnect = inv_state.get_dead_peers();

                    test_debug!("{:?}: inv scan reset", &self.local_peer);
                    inv_state.reset();
                    Ok((true, disconnect, broken))
                },
                None => {
                    Ok((true, vec![], vec![]))
                }
            }
        }
        
    }
}

#[cfg(test)]
mod test {
    use super::*;
    use net::*;
    use net::test::*;
    use chainstate::stacks::*;
    use std::collections::HashMap;

    #[test]
    fn peerblocksinv_has_ith_block() {
        let peer_inv = PeerBlocksInv::new(vec![0x55, 0x77], vec![0x11, 0x22], 16, 12345);
        let has_blocks = vec![
            true,
            false,
            true,
            false,

            true,
            false,
            true,
            false,

            true,
            true,
            true,
            false,

            true,
            true,
            true,
            false
        ];
        let has_microblocks = vec![
            true,
            false,
            false,
            false,

            true,
            false,
            false,
            false,

            false,
            true,
            false,
            false,

            false,
            true,
            false,
            false
        ];

        assert!(!peer_inv.has_ith_block(12344));
        assert!(!peer_inv.has_ith_block(12345 + 17));
        
        assert!(!peer_inv.has_ith_microblock_stream(12344));
        assert!(!peer_inv.has_ith_microblock_stream(12345 + 17));

        for i in 0..16 {
            assert_eq!(has_blocks[i], peer_inv.has_ith_block((12345 + i) as u64));
            assert_eq!(has_microblocks[i], peer_inv.has_ith_microblock_stream((12345 + i) as u64));
        }
    }

    #[test]
    fn peerblocksinv_merge() {
        let peer_inv = PeerBlocksInv::new(vec![0x00, 0x00, 0x55, 0x77], vec![0x00, 0x00, 0x55, 0x77], 32, 12345);
        
        // merge below, aligned
        let mut peer_inv_below = peer_inv.clone();
        let (new_blocks, new_microblocks) = peer_inv_below.merge_blocks_inv(12345, 16, vec![0x11, 0x22], vec![0x11, 0x22]);
        assert_eq!(new_blocks, 4);
        assert_eq!(new_microblocks, 4);
        assert_eq!(peer_inv_below.num_sortitions, 32);
        assert_eq!(peer_inv_below.block_inv, vec![0x11, 0x22, 0x55, 0x77]);
        assert_eq!(peer_inv_below.microblocks_inv, vec![0x11, 0x22, 0x55, 0x77]);

        // merge below, overlapping, aligned
        let mut peer_inv_below_overlap = peer_inv.clone();
        let (new_blocks, new_microblocks) = peer_inv_below_overlap.merge_blocks_inv(12345 + 8, 16, vec![0x11, 0x22], vec![0x11, 0x22]);
        assert_eq!(new_blocks, 4);
        assert_eq!(new_microblocks, 4);
        assert_eq!(peer_inv_below_overlap.num_sortitions, 32);
        assert_eq!(peer_inv_below_overlap.block_inv, vec![0x00, 0x11, 0x22 | 0x55, 0x77]);
        assert_eq!(peer_inv_below_overlap.microblocks_inv, vec![0x00, 0x11, 0x22 | 0x55, 0x77]);

        // merge equal, overlapping, aligned
        let mut peer_inv_equal = peer_inv.clone();
        let (new_blocks, new_microblocks) = peer_inv_equal.merge_blocks_inv(12345 + 16, 16, vec![0x11, 0x22], vec![0x11, 0x22]);
        assert_eq!(new_blocks, 0);
        assert_eq!(new_microblocks, 0);
        assert_eq!(peer_inv_equal.num_sortitions, 32);
        assert_eq!(peer_inv_equal.block_inv, vec![0x00, 0x00, 0x11 | 0x55, 0x22 | 0x77]);
        assert_eq!(peer_inv_equal.microblocks_inv, vec![0x00, 0x00, 0x11 | 0x55, 0x22 | 0x77]);

        // merge above, overlapping, aligned
        let mut peer_inv_above_overlap = peer_inv.clone();
        let (new_blocks, new_microblocks) = peer_inv_above_overlap.merge_blocks_inv(12345 + 24, 16, vec![0x11, 0x22], vec![0x11, 0x22]);
        assert_eq!(new_blocks, 2);
        assert_eq!(new_microblocks, 2);
        assert_eq!(peer_inv_above_overlap.num_sortitions, 40);
        assert_eq!(peer_inv_above_overlap.block_inv, vec![0x00, 0x00, 0x55, 0x77 | 0x11, 0x22]);
        assert_eq!(peer_inv_above_overlap.microblocks_inv, vec![0x00, 0x00, 0x55, 0x77 | 0x11, 0x22]);

        // merge above, non-overlapping, aligned
        let mut peer_inv_above = peer_inv.clone();
        let (new_blocks, new_microblocks) = peer_inv_above.merge_blocks_inv(12345 + 32, 16, vec![0x11, 0x22], vec![0x11, 0x22]);
        assert_eq!(peer_inv_above.num_sortitions, 48);
        assert_eq!(new_blocks, 4);
        assert_eq!(new_microblocks, 4);
        assert_eq!(peer_inv_above.block_inv, vec![0x00, 0x00, 0x55, 0x77, 0x11, 0x22]);
        assert_eq!(peer_inv_above.microblocks_inv, vec![0x00, 0x00, 0x55, 0x77, 0x11, 0x22]);

        // try merging unaligned
        let mut peer_inv = PeerBlocksInv::new(vec![0x00, 0x00, 0x00, 0x00], vec![0x00, 0x00, 0x00, 0x00], 32, 12345);
        for i in 0..32 {
            let (new_blocks, new_microblocks) = peer_inv.merge_blocks_inv(12345 + i, 1, vec![0x01], vec![0x01]);
            assert_eq!(new_blocks, 1);
            assert_eq!(new_microblocks, 1);
            assert_eq!(peer_inv.num_sortitions, 32);
            for j in 0..i+1 {
                assert!(peer_inv.has_ith_block(12345 + j));
                assert!(peer_inv.has_ith_microblock_stream(12345 + j));
            }
            for j in i+1..32 {
                assert!(!peer_inv.has_ith_block(12345 + j));
                assert!(!peer_inv.has_ith_microblock_stream(12345 + j));
            }
        }
        
        // try merging unaligned, with multiple blocks
        let mut peer_inv = PeerBlocksInv::new(vec![0x00, 0x00, 0x00, 0x00], vec![0x00, 0x00, 0x00, 0x00], 32, 12345);
        for i in 0..16 {
            let (new_blocks, new_microblocks) = peer_inv.merge_blocks_inv(12345 + i, 32, vec![0x01, 0x00, 0x01, 0x00], vec![0x01, 0x00, 0x01, 0x00]);
            assert_eq!(new_blocks, 2);
            assert_eq!(new_microblocks, 2);
            assert_eq!(peer_inv.num_sortitions, 32 + i);
            for j in 0..i+1 {
                assert!(peer_inv.has_ith_block(12345 + j));
                assert!(peer_inv.has_ith_block(12345 + j + 16));
                
                assert!(peer_inv.has_ith_microblock_stream(12345 + j));
                assert!(peer_inv.has_ith_microblock_stream(12345 + j + 16));
            }
            for j in i+1..16 {
                assert!(!peer_inv.has_ith_block(12345 + j));
                assert!(!peer_inv.has_ith_block(12345 + j + 16));
                
                assert!(!peer_inv.has_ith_microblock_stream(12345 + j));
                assert!(!peer_inv.has_ith_microblock_stream(12345 + j + 16));
            }
        }

        // merge 0's grows the bitvec
        let mut peer_inv = PeerBlocksInv::new(vec![0x00, 0x00, 0x00, 0x00], vec![0x00, 0x00, 0x00, 0x00], 32, 12345);
        let (new_blocks, new_microblocks) = peer_inv.merge_blocks_inv(12345 + 24, 16, vec![0x00, 0x00], vec![0x00, 0x00]);
        assert_eq!(new_blocks, 0);
        assert_eq!(new_microblocks, 0);
        assert_eq!(peer_inv.num_sortitions, 40);
        assert_eq!(peer_inv.block_inv, vec![0x00, 0x00, 0x00, 0x00, 0x00]);
        assert_eq!(peer_inv.microblocks_inv, vec![0x00, 0x00, 0x00, 0x00, 0x00]);
    }

    #[test]
    fn test_inv_set_block_microblock_bits() {
        let mut peer_inv = PeerBlocksInv::new(vec![0x01], vec![0x01], 1, 12345);

        assert!(peer_inv.set_block_bit(12345 + 1));
        assert_eq!(peer_inv.block_inv, vec![0x03]);
        assert_eq!(peer_inv.num_sortitions, 2);
        assert!(!peer_inv.set_block_bit(12345 + 1));
        assert_eq!(peer_inv.block_inv, vec![0x03]);
        assert_eq!(peer_inv.num_sortitions, 2);

        assert!(peer_inv.set_microblocks_bit(12345 + 1));
        assert_eq!(peer_inv.microblocks_inv, vec![0x03]);
        assert_eq!(peer_inv.num_sortitions, 2);
        assert!(!peer_inv.set_microblocks_bit(12345 + 1));
        assert_eq!(peer_inv.microblocks_inv, vec![0x03]);
        assert_eq!(peer_inv.num_sortitions, 2);

        assert!(peer_inv.set_block_bit(12345 + 1 + 16));
        assert_eq!(peer_inv.block_inv, vec![0x03, 0x00, 0x02]);
        assert_eq!(peer_inv.microblocks_inv, vec![0x03, 0x00, 0x00]);
        assert_eq!(peer_inv.num_sortitions, 18);
        assert!(!peer_inv.set_block_bit(12345 + 1 + 16));
        assert_eq!(peer_inv.block_inv, vec![0x03, 0x00, 0x02]);
        assert_eq!(peer_inv.microblocks_inv, vec![0x03, 0x00, 0x00]);
        assert_eq!(peer_inv.num_sortitions, 18);
        
        assert!(peer_inv.set_microblocks_bit(12345 + 1 + 32));
        assert_eq!(peer_inv.block_inv, vec![0x03, 0x00, 0x02, 0x00, 0x00]);
        assert_eq!(peer_inv.microblocks_inv, vec![0x03, 0x00, 0x00, 0x00, 0x02]);
        assert_eq!(peer_inv.num_sortitions, 34);
        assert!(!peer_inv.set_microblocks_bit(12345 + 1 + 32));
        assert_eq!(peer_inv.block_inv, vec![0x03, 0x00, 0x02, 0x00, 0x00]);
        assert_eq!(peer_inv.microblocks_inv, vec![0x03, 0x00, 0x00, 0x00, 0x02]);
        assert_eq!(peer_inv.num_sortitions, 34);
    }

    #[test]
    fn test_sync_inv_set_blocks_microblocks_available() {
        let mut peer_1_config = TestPeerConfig::new("test_sync_inv_set_blocks_microblocks_available", 31981, 41981);
        let mut peer_2_config = TestPeerConfig::new("test_sync_inv_set_blocks_microblocks_available", 31982, 41982);

        peer_1_config.burnchain.first_block_height = 5;
        peer_2_config.burnchain.first_block_height = 5;

        let mut peer_1 = TestPeer::new(peer_1_config);
        let mut peer_2 = TestPeer::new(peer_2_config);

        let num_blocks = 5;
        let first_stacks_block_height = {
            let sn = BurnDB::get_canonical_burn_chain_tip(&peer_1.burndb.as_ref().unwrap().conn()).unwrap();
            sn.block_height
        };

        for i in 0..num_blocks {
            let (burn_ops, stacks_block, microblocks) = peer_2.make_default_tenure();

            peer_1.next_burnchain_block(burn_ops.clone());
            peer_2.next_burnchain_block(burn_ops.clone());
            peer_2.process_stacks_epoch_at_tip(&stacks_block, &microblocks);
        }

        let (tip, num_burn_blocks) = {
            let sn = BurnDB::get_canonical_burn_chain_tip(peer_1.burndb.as_ref().unwrap().conn()).unwrap();
            let num_burn_blocks = sn.block_height - peer_1.config.burnchain.first_block_height;
            (sn, num_burn_blocks)
        };

        let nk = peer_1.to_neighbor().addr;

        let burndb = peer_1.burndb.take().unwrap();
        peer_1.network.init_inv_sync(&burndb);
        match peer_1.network.inv_state {
            Some(ref mut inv) => {
                inv.add_peer(nk.clone());
            },
            None => {
                panic!("No inv state");
            }
        };
        peer_1.burndb = Some(burndb);
        
        for i in 0..num_blocks {
            let burndb = peer_1.burndb.take().unwrap();
            let sn = {
                let ic = burndb.index_conn();
                let sn = BurnDB::get_block_snapshot_in_fork(&ic, i + 1 + first_stacks_block_height, &tip.burn_header_hash).unwrap().unwrap();
                eprintln!("{:?}", &sn);
                sn
            };
            peer_1.burndb = Some(burndb);
        }

        for i in 0..num_blocks {
            let burndb = peer_1.burndb.take().unwrap();
            match peer_1.network.inv_state {
                Some(ref mut inv) => {
                    assert!(!inv.block_stats.get(&nk).unwrap().inv.has_ith_block(i + first_stacks_block_height));
                    assert!(!inv.block_stats.get(&nk).unwrap().inv.has_ith_microblock_stream(i + first_stacks_block_height));

                    let sn = {
                        let ic = burndb.index_conn();
                        let sn = BurnDB::get_block_snapshot_in_fork(&ic, i + first_stacks_block_height + 1, &tip.burn_header_hash).unwrap().unwrap();
                        eprintln!("{:?}", &sn);
                        sn
                    };
                    
                    let sh = inv.set_block_available(&nk, &burndb, &sn.consensus_hash, &BurnchainHeaderHash([0xfe; 32])).unwrap();
                    assert_eq!(None, sh);
                    assert!(!inv.block_stats.get(&nk).unwrap().inv.has_ith_block(i + first_stacks_block_height));
                    assert!(!inv.block_stats.get(&nk).unwrap().inv.has_ith_microblock_stream(i + first_stacks_block_height));

                    let sh = inv.set_block_available(&nk, &burndb, &ConsensusHash([0xfe; 20]), &sn.burn_header_hash).unwrap();
                    assert_eq!(None, sh);
                    assert!(!inv.block_stats.get(&nk).unwrap().inv.has_ith_block(i + first_stacks_block_height));
                    assert!(!inv.block_stats.get(&nk).unwrap().inv.has_ith_microblock_stream(i + first_stacks_block_height));
                    
                    let sh = inv.set_block_available(&nk, &burndb, &sn.consensus_hash, &sn.burn_header_hash).unwrap();

                    assert_eq!(Some(i + first_stacks_block_height - burndb.first_block_height), sh);
                    assert!(inv.block_stats.get(&nk).unwrap().inv.has_ith_block(i + first_stacks_block_height));
                    
                    let sh = inv.set_microblocks_available(&nk, &burndb, &sn.consensus_hash, &sn.burn_header_hash).unwrap();

                    assert_eq!(Some(i + first_stacks_block_height - burndb.first_block_height), sh);
                    assert!(inv.block_stats.get(&nk).unwrap().inv.has_ith_microblock_stream(i + first_stacks_block_height));

                    assert!(inv.set_block_available(&nk, &burndb, &sn.consensus_hash, &sn.burn_header_hash).unwrap().is_none());
                    assert!(inv.set_microblocks_available(&nk, &burndb, &sn.consensus_hash, &sn.burn_header_hash).unwrap().is_none());
                },
                None => {
                    panic!("No inv state");
                }
            }
            peer_1.burndb = Some(burndb);
        }
    }
     
    #[test]
    fn test_sync_inv_diagnose_nack() {
        let peer_config = TestPeerConfig::new("test_sync_inv_diagnose_nack", 31983, 41983);
        let neighbor = peer_config.to_neighbor();
        let neighbor_key = neighbor.addr.clone();
        let nack_no_block = NackData { error_code: NackErrorCodes::NoSuchBurnchainBlock };

        let mut burnchain_view = BurnchainView {
            burn_block_height: 12346,
            burn_consensus_hash: ConsensusHash([0x11; 20]),
            burn_stable_block_height: 12340,
            burn_stable_consensus_hash: ConsensusHash([0x22; 20]),
            last_consensus_hashes: HashMap::new()
        };

        burnchain_view.make_test_data();
        let ch_12345 = burnchain_view.last_consensus_hashes.get(&12345).unwrap().clone();
        let ch_12340 = burnchain_view.last_consensus_hashes.get(&12340).unwrap().clone();
        let ch_12341 = burnchain_view.last_consensus_hashes.get(&12341).unwrap().clone();
        let ch_12339 = burnchain_view.last_consensus_hashes.get(&12339).unwrap().clone();
        let ch_12334 = burnchain_view.last_consensus_hashes.get(&12334).unwrap().clone();

        // should be stable; but got nacked (so this would be inappropriate)
        assert_eq!(NackResult::Broken, InvState::diagnose_nack(&neighbor_key, nack_no_block.clone(), &burnchain_view, 12346, 12340, ConsensusHash([0x11; 20]), ConsensusHash([0x22; 20])));
        
        // should be stale
        assert_eq!(NackResult::Stale, InvState::diagnose_nack(&neighbor_key, nack_no_block.clone(), &burnchain_view, 12345, 12339, ch_12345.clone(), ch_12339.clone()));

        // should be unstable -- chain tip consensus hash is different
        assert_eq!(NackResult::Unstable, InvState::diagnose_nack(&neighbor_key, nack_no_block.clone(), &burnchain_view, 12346, 12340, ConsensusHash([0x12; 20]), ConsensusHash([0x22; 20])));

        // should be unstable -- neighbor is ahead of us
        assert_eq!(NackResult::Unstable, InvState::diagnose_nack(&neighbor_key, nack_no_block.clone(), &burnchain_view, 12347, 12341, ConsensusHash([0x13; 20]), ch_12341.clone()));

        // should be diverged -- different stable consensus hash
        assert_eq!(NackResult::Diverged, InvState::diagnose_nack(&neighbor_key, nack_no_block.clone(), &burnchain_view, 12346, 12340, ConsensusHash([0x12; 20]), ConsensusHash([0x23; 20])));
    }

    #[test]
    #[ignore]
    fn test_sync_inv_2_peers_plain() {
        let mut peer_1_config = TestPeerConfig::new("test_sync_inv_2_peers_plain", 31992, 41992);
        let mut peer_2_config = TestPeerConfig::new("test_sync_inv_2_peers_plain", 31993, 41993);

        peer_1_config.add_neighbor(&peer_2_config.to_neighbor());
        peer_2_config.add_neighbor(&peer_1_config.to_neighbor());

        let mut peer_1 = TestPeer::new(peer_1_config);
        let mut peer_2 = TestPeer::new(peer_2_config);

        let num_blocks = (BLOCKS_INV_DATA_MAX_BITLEN * 2) as u64;
        let first_stacks_block_height = {
            let sn = BurnDB::get_canonical_burn_chain_tip(&peer_1.burndb.as_ref().unwrap().conn()).unwrap();
            sn.block_height
        };

        for i in 0..num_blocks {
            let (burn_ops, stacks_block, microblocks) = peer_2.make_default_tenure();

            peer_1.next_burnchain_block(burn_ops.clone());
            peer_2.next_burnchain_block(burn_ops.clone());

            peer_2.process_stacks_epoch_at_tip(&stacks_block, &microblocks);
        }

        let num_burn_blocks = {
            let sn = BurnDB::get_canonical_burn_chain_tip(peer_1.burndb.as_ref().unwrap().conn()).unwrap();
            sn.block_height - 1
        };
        
        let mut round = 0;
        let mut inv_1_count = 0;
        let mut inv_2_count = 0;

        while inv_1_count < num_burn_blocks || inv_2_count < num_burn_blocks {
            let _ = peer_1.step();
            let _ = peer_2.step();

            inv_1_count = match peer_1.network.inv_state {
                Some(ref inv) => {
                    info!("Peer 1 stats: {:?}", &inv.block_stats);
                    inv.get_inv_sortitions(&peer_2.to_neighbor().addr)
                },
                None => 0
            };

            inv_2_count = match peer_2.network.inv_state {
                Some(ref inv) => {
                    info!("Peer 2 stats: {:?}", &inv.block_stats);
                    inv.get_inv_sortitions(&peer_1.to_neighbor().addr)
                },
                None => 0
            };

            // nothing should break
            match peer_1.network.inv_state {
                Some(ref inv) => {
                    assert_eq!(inv.broken_peers.len(), 0);
                    assert_eq!(inv.dead_peers.len(), 0);
                    assert_eq!(inv.diverged_peers.len(), 0);
                },
                None => {}
            }

            match peer_2.network.inv_state {
                Some(ref inv) => {
                    assert_eq!(inv.broken_peers.len(), 0);
                    assert_eq!(inv.dead_peers.len(), 0);
                    assert_eq!(inv.diverged_peers.len(), 0);
                },
                None => {}
            }

            info!("Peer 1 stats: {:?}", &peer_1.network.inv_state.as_ref().unwrap().block_stats);
            info!("Peer 2 stats: {:?}", &peer_2.network.inv_state.as_ref().unwrap().block_stats);

            round += 1;
        }

        info!("Completed walk round {} step(s)", round);

        peer_1.dump_frontier();
        peer_2.dump_frontier();
        
        info!("Peer 1 stats: {:?}", &peer_1.network.inv_state.as_ref().unwrap().block_stats);
        info!("Peer 2 stats: {:?}", &peer_2.network.inv_state.as_ref().unwrap().block_stats);

        let peer_1_inv = peer_2.network.inv_state.as_ref().unwrap().block_stats.get(&peer_1.to_neighbor().addr).unwrap().inv.clone();
        let peer_2_inv = peer_1.network.inv_state.as_ref().unwrap().block_stats.get(&peer_2.to_neighbor().addr).unwrap().inv.clone();

        info!("Peer 1 inv: {:?}", &peer_1_inv);
        info!("Peer 2 inv: {:?}", &peer_2_inv);

        info!("peer 1's view of peer 2: {:?}", &peer_2_inv);

        assert_eq!(peer_2_inv.num_sortitions, num_burn_blocks);
        
        // peer 1 should have learned that peer 2 has all the blocks
        for i in 0..(num_burn_blocks - first_stacks_block_height) {
            assert!(peer_2_inv.has_ith_block(i + first_stacks_block_height));
        }

        // peer 1 should have learned that peer 2 has all the microblock streams 
        for i in 0..(num_burn_blocks - first_stacks_block_height - 1) {
            assert!(peer_2_inv.has_ith_microblock_stream(i + first_stacks_block_height));
        }

        let peer_1_inv = peer_2.network.inv_state.as_ref().unwrap().block_stats.get(&peer_1.to_neighbor().addr).unwrap().inv.clone();
        test_debug!("peer 2's view of peer 1: {:?}", &peer_1_inv);

        assert_eq!(peer_1_inv.num_sortitions, num_burn_blocks);
        
        // peer 2 should have learned that peer 1 has no blocks at all
        for i in 0..(num_burn_blocks - first_stacks_block_height) {
            assert!(!peer_1_inv.has_ith_block(i + first_stacks_block_height));
        }
    }
   
    #[test]
    #[ignore]
    fn test_sync_inv_2_peers_stale() {
        let mut peer_1_config = TestPeerConfig::new("test_sync_inv_2_peers_stale", 31994, 41995);
        let mut peer_2_config = TestPeerConfig::new("test_sync_inv_2_peers_stale", 31995, 41996);

        peer_1_config.add_neighbor(&peer_2_config.to_neighbor());
        peer_2_config.add_neighbor(&peer_1_config.to_neighbor());

        let mut peer_1 = TestPeer::new(peer_1_config);
        let mut peer_2 = TestPeer::new(peer_2_config);

        let num_blocks = (BLOCKS_INV_DATA_MAX_BITLEN * 2) as u64;
        assert!(num_blocks > peer_1.config.burnchain.consensus_hash_lifetime as u64);      // required to test that this peer will be considered stale

        let first_stacks_block_height = {
            let sn = BurnDB::get_canonical_burn_chain_tip(&peer_1.burndb.as_ref().unwrap().conn()).unwrap();
            sn.block_height
        };

        // only peer 2 makes progress
        for i in 0..num_blocks {
            let (burn_ops, stacks_block, microblocks) = peer_2.make_default_tenure();

            peer_2.next_burnchain_block(burn_ops.clone());
            peer_2.process_stacks_epoch_at_tip(&stacks_block, &microblocks);
        }

        let num_burn_blocks = {
            let sn = BurnDB::get_canonical_burn_chain_tip(peer_1.burndb.as_ref().unwrap().conn()).unwrap();
            sn.block_height - 1
        };
        
        let mut round = 0;
        let mut inv_1_count = 0;
        let mut inv_2_count = 0;

        let mut peer_1_stale = false;
        
        while !peer_1_stale && inv_1_count < first_stacks_block_height - peer_1.config.burnchain.first_block_height {
            let _ = peer_1.step();
            let _ = peer_2.step();

            inv_1_count = match peer_1.network.inv_state {
                Some(ref inv) => inv.get_inv_sortitions(&peer_2.to_neighbor().addr),
                None => 0
            };

            inv_2_count = match peer_2.network.inv_state {
                Some(ref inv) => inv.get_inv_sortitions(&peer_1.to_neighbor().addr),
                None => 0
            };

            match peer_1.network.inv_state {
                Some(ref inv) => {
                    assert_eq!(inv.broken_peers.len(), 0);
                    assert_eq!(inv.dead_peers.len(), 0);
                    assert_eq!(inv.diverged_peers.len(), 0);
                },
                None => {}
            }

            match peer_2.network.inv_state {
                Some(ref inv) => {
                    assert_eq!(inv.broken_peers.len(), 0);
                    assert_eq!(inv.dead_peers.len(), 0);
                    assert_eq!(inv.diverged_peers.len(), 0);
                    
                    if inv.stale_peers.contains(&peer_1.to_neighbor().addr) {
                        peer_1_stale = true;
                    }
                },
                None => {}
            }

            round += 1;

            test_debug!("\n\npeer_1_stale = {}, inv_1_count = {}, inv_2_count = {}, first_stacks_block_height = {}\n\n", peer_1_stale, inv_1_count, inv_2_count, first_stacks_block_height);
        }

        info!("Completed walk round {} step(s)", round);

        peer_1.dump_frontier();
        peer_2.dump_frontier();

        let peer_2_inv = peer_1.network.inv_state.as_ref().unwrap().block_stats.get(&peer_2.to_neighbor().addr).unwrap().inv.clone();
        test_debug!("peer 1's view of peer 2: {:?}", &peer_2_inv);

        // peer 1 should have learned no more than its highest number of sortitions
        assert_eq!(peer_2_inv.num_sortitions, first_stacks_block_height - peer_1.config.burnchain.first_block_height);
        for i in 0..first_stacks_block_height {
            assert!(!peer_2_inv.has_ith_block(i));
            assert!(!peer_2_inv.has_ith_microblock_stream(i));
        }

        // peer 2 should have learned no more than peer 1's highest number of sortitions
        let peer_1_inv = peer_2.network.inv_state.as_ref().unwrap().block_stats.get(&peer_1.to_neighbor().addr).unwrap().inv.clone();
        test_debug!("peer 2's view of peer 1: {:?}", &peer_1_inv);

        assert_eq!(peer_1_inv.num_sortitions, first_stacks_block_height - peer_1.config.burnchain.first_block_height);
    }
    
    #[test]
    #[ignore]
    fn test_sync_inv_2_peers_unstable() {
        let mut peer_1_config = TestPeerConfig::new("test_sync_inv_2_peers_unstable", 31996, 41997);
        let mut peer_2_config = TestPeerConfig::new("test_sync_inv_2_peers_unstable", 31997, 41998);

        peer_1_config.add_neighbor(&peer_2_config.to_neighbor());
        peer_2_config.add_neighbor(&peer_1_config.to_neighbor());

        let mut peer_1 = TestPeer::new(peer_1_config);
        let mut peer_2 = TestPeer::new(peer_2_config);

        let num_blocks = (BLOCKS_INV_DATA_MAX_BITLEN * 2) as u64;
        assert!(num_blocks > peer_1.config.burnchain.consensus_hash_lifetime as u64);      // required to test that this peer will be considered stale

        let first_stacks_block_height = {
            let sn = BurnDB::get_canonical_burn_chain_tip(&peer_1.burndb.as_ref().unwrap().conn()).unwrap();
            sn.block_height
        };

        // only peer 2 makes progress.
        // peer 1 makes _different_ progress.
        for i in 0..num_blocks {
            let (burn_ops, stacks_block, microblocks) = peer_2.make_default_tenure();

            if i + (peer_1.config.burnchain.stable_confirmations as u64) < num_blocks {
                peer_1.next_burnchain_block(burn_ops.clone());
            }
            else {
                // diverge 
                peer_1.next_burnchain_block(vec![]);
            }

            peer_2.next_burnchain_block(burn_ops.clone());

            peer_2.process_stacks_epoch_at_tip(&stacks_block, &microblocks);

        }

        let num_burn_blocks = {
            let sn = BurnDB::get_canonical_burn_chain_tip(peer_1.burndb.as_ref().unwrap().conn()).unwrap();
            sn.block_height - 1
        };
        
        let mut round = 0;
        let mut inv_1_count = 0;
        let mut inv_2_count = 0;
        
        while inv_1_count < num_burn_blocks - (peer_1.config.burnchain.stable_confirmations as u64) - peer_1.config.burnchain.first_block_height || 
              inv_2_count < num_burn_blocks - (peer_2.config.burnchain.stable_confirmations as u64) - peer_1.config.burnchain.first_block_height {
            let _ = peer_1.step();
            let _ = peer_2.step();

            inv_1_count = match peer_1.network.inv_state {
                Some(ref inv) => inv.get_inv_sortitions(&peer_2.to_neighbor().addr),
                None => 0
            };

            inv_2_count = match peer_2.network.inv_state {
                Some(ref inv) => inv.get_inv_sortitions(&peer_1.to_neighbor().addr),
                None => 0
            };

            match peer_1.network.inv_state {
                Some(ref inv) => {
                    assert_eq!(inv.broken_peers.len(), 0);
                    assert_eq!(inv.dead_peers.len(), 0);
                    assert_eq!(inv.diverged_peers.len(), 0);
                },
                None => {}
            }

            match peer_2.network.inv_state {
                Some(ref inv) => {
                    assert_eq!(inv.broken_peers.len(), 0);
                    assert_eq!(inv.dead_peers.len(), 0);
                    assert_eq!(inv.diverged_peers.len(), 0);
                },
                None => {}
            }

            round += 1;

            test_debug!("\n\ninv_1_count = {}, inv_2_count = {}, first_stacks_block_height = {}, num_bun_blocks = {}\n\n", inv_1_count, inv_2_count, first_stacks_block_height, num_burn_blocks);
        }

        info!("Completed walk round {} step(s)", round);

        peer_1.dump_frontier();
        peer_2.dump_frontier();

        let peer_2_inv = peer_1.network.inv_state.as_ref().unwrap().block_stats.get(&peer_2.to_neighbor().addr).unwrap().inv.clone();
        test_debug!("peer 1's view of peer 2: {:?}", &peer_2_inv);
        
        let peer_1_inv = peer_2.network.inv_state.as_ref().unwrap().block_stats.get(&peer_1.to_neighbor().addr).unwrap().inv.clone();
        test_debug!("peer 2's view of peer 1: {:?}", &peer_1_inv);
        
        assert_eq!(peer_2_inv.num_sortitions, num_burn_blocks - (peer_1.config.burnchain.stable_confirmations as u64));
        assert_eq!(peer_1_inv.num_sortitions, num_burn_blocks - (peer_2.config.burnchain.stable_confirmations as u64));
        
        // peer 1 should have learned that peer 2 has all the blocks, up to the point of
        // instability
        for i in 0..(num_burn_blocks - first_stacks_block_height - (peer_1.config.burnchain.stable_confirmations as u64)) {
            assert!(peer_2_inv.has_ith_block(i + first_stacks_block_height));
            assert!(peer_2_inv.has_ith_microblock_stream(i + first_stacks_block_height));
        }
        
        for i in 0..(num_burn_blocks - first_stacks_block_height - (peer_1.config.burnchain.stable_confirmations as u64)) {
            assert!(!peer_1_inv.has_ith_block(i + first_stacks_block_height));
            assert!(!peer_1_inv.has_ith_microblock_stream(i + first_stacks_block_height));
        }
    }
}
