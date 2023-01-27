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

pub mod bits;
pub mod config;
pub mod db;
pub mod selectors;
pub mod sync;

#[cfg(test)]
pub mod tests;

use crate::util_lib::db::{DBConn, DBTx};
use stacks_common::types::chainstate::ConsensusHash;
use stacks_common::util::hash::Sha512Trunc256Sum;
use stacks_common::util::secp256k1::MessageSignature;
use std::collections::{HashMap, HashSet, VecDeque};

use crate::clarity_vm::clarity::ClarityReadOnlyConnection;

use crate::chainstate::stacks::boot::{RawRewardSetEntry, RewardSet};

use crate::net::connection::ReplyHandleP2P;
use crate::net::Error as net_error;
use crate::net::Neighbor;
use crate::net::NeighborKey;
use crate::net::StackerDBChunkData;
use crate::net::StackerDBChunkInvData;
use crate::net::StackerDBGetChunkData;

use clarity::vm::ContractName;
use stacks_common::types::chainstate::StacksAddress;

/// maximum chunk inventory size
pub const STACKERDB_INV_MAX: u32 = 4096;

/// Settings for the Stacker DB
#[derive(Clone, Debug, PartialEq)]
pub struct StackerDBConfig {
    /// maximum chunk size
    pub chunk_size: u64,
    /// number of chunks in this DB
    pub num_chunks: u64,
    /// minimum time between writes to the same chunk.
    pub write_freq: u64,
    /// maximum number of times a chunk may be written to during a reward cycle.
    pub max_writes: u32,
    /// some initial peers that have replicas of this DB
    pub hint_peers: Vec<NeighborKey>,
    /// how many neighbors to connect to
    pub num_neighbors: usize,
}

/// This is a replicated database that stores fixed-length opaque blobs of data from Stackers.  Stackers get one
/// blob per reward slot they clinch.
///
/// Stackers can store whatever they like in their blobs.  In practice, this is sBTC signature
/// generation data.
pub struct StackerDB {
    conn: DBConn,
}

/// A transaction against the Stacker DB
pub struct StackerDBTx<'a> {
    sql_tx: DBTx<'a>,
    config: StackerDBConfig,
}

/// Chunk metadata from the DB
#[derive(Clone, Debug, PartialEq)]
pub struct ChunkMetadata {
    /// Reward cycle identifier
    pub rc_consensus_hash: ConsensusHash,
    /// Chunk identifier (unique for each DB instance)
    pub chunk_id: u32,
    /// Chunk version (a lamport clock)
    pub chunk_version: u32,
    /// data hash
    pub data_hash: Sha512Trunc256Sum,
    /// signature over the above
    pub signature: MessageSignature,
}

/// Set of peers for a stacker DB
pub struct StackerDBPeerSet {
    /// which contract this is a replica for
    pub smart_contract_name: ContractName,
    pub smart_contract_addr: StacksAddress,
    /// number of chunks in this DB
    pub num_chunks: usize,
    /// how frequently we accept chunk writes
    pub write_freq: u64,
    /// event handles to peers we're talking to
    pub peers: HashSet<usize>,
    /// peers that are in the process of connecting
    pub connecting: HashMap<NeighborKey, usize>,
    /// in-flight requests for the current state
    pub requests: HashMap<NeighborKey, ReplyHandleP2P>,
    /// in-flight requests for the next state
    pub next_requests: HashMap<NeighborKey, ReplyHandleP2P>,
    /// nodes that didn't reply, and can be disconnected
    pub dead: HashSet<NeighborKey>,
    /// What versions of each chunk does each neighbor have?
    pub chunk_invs: HashMap<NeighborKey, StackerDBChunkInvData>,
    /// What priority should we be fetching chunks in, and from whom?
    pub chunk_priorities: Vec<(StackerDBGetChunkData, Vec<NeighborKey>)>,
    /// Index into `chunk_priorities` at which to consider the next download.
    pub next_chunk_priority: usize,
    /// What is the expected version vector for this DB's chunks?
    pub expected_versions: Vec<u32>,
    /// Downloaded chunks
    pub downloaded_chunks: HashMap<NeighborKey, Vec<StackerDBChunkData>>,
}

/// Final result of synchronizing state with a remote set of DB replicas
pub struct StackerDBSyncResult {
    /// which contract this is a replica for
    pub smart_contract_name: ContractName,
    pub smart_contract_addr: StacksAddress,
    /// list of data to store
    pub chunks_to_store: Vec<StackerDBChunkData>,
    /// dead neighbors we can disconnect from
    pub dead: HashSet<NeighborKey>,
}

/// Possible states a DB sync state-machine can be in
pub enum StackerDBSyncState {
    ConnectBegin(Vec<Neighbor>, StackerDBPeerSet, u64),
    ConnectFinish(StackerDBPeerSet),
    GetChunkInv(StackerDBPeerSet),
    GetChunks(StackerDBPeerSet),
    Final(StackerDBSyncResult),
}

/// Top-level state machine a stacker DB
pub struct StackerDBSync {
    pub smart_contract_addr: StacksAddress,
    pub smart_contract_name: ContractName,
    pub stacker_db: StackerDB,
    pub total_stored: u64,
    state: Option<StackerDBSyncState>,
}

/// Trait to implement for loading up the config for a DB, and determining DB chunk slots.
pub trait StackerDBSelector {
    /// Load up the configuration for this DB for this reward cycle
    fn load_config(
        &self,
        clarity_conn: &ClarityReadOnlyConnection,
        rc_reward_cycle: &ConsensusHash,
    ) -> Result<StackerDBConfig, net_error>;

    /// Given a read-only connection to the clarity DB, the consensus hash of the new reward cycle,
    /// and the reward cycle participants, determine the list of DB chunk slots to be allocated for this DB
    /// for this reward cycle.  The order of this list will be used to determine chunk IDs.
    /// Entries may be duplicated.
    fn find_slots(
        &self,
        clarity_conn: &ClarityReadOnlyConnection,
        rc_reward_cycle: &ConsensusHash,
        reward_set: &RewardSet,
        registered_addrs: Vec<RawRewardSetEntry>,
    ) -> Result<Vec<(StacksAddress, u64)>, net_error>;
}

/// PoX slot selector implementation
pub struct PoxSelector {}

/// Smart contract selector implementation
pub struct SmartContractSelector {
    pub smart_contract_addr: StacksAddress,
    pub smart_contract_name: ContractName,
}
