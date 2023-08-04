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

/// # The StackerDB System
///
/// A StackerDB is a best-effort replicated database controlled by a smart contract, which Stacks
/// node operators can opt-in to hosting.  Unlike a smart contract's data space, a StackerDB's
/// data is not consensus-critical -- nodes do not need to read its state to validate the
/// blockchain.  Instead, developers use StackerDBSet to host and replicate auxiliary smart contract
/// data for the purposes of some (off-chain) application in a best-effort manner.  In doing so,
/// Stacks-powered applications are able to leverage the Stacks peer-to-peer node network to host
/// and disseminate their data without incuring the cost and performance penalties of bundling it
/// within a transaction.
///
/// ## Data Model
///
/// Data within a StackerDB is eventually-consistent.  In the absence of writes and network
/// partitions, all replicas will receive the latest data in a finite number of protocol rounds,
/// with high probability.  Given that network partitions in the peer-to-peer network are assumed
/// to be temporary, we assume that all StackerDB instances will receive the latest state in finite time.
/// Beyond this, it makes no guarantees about how quickly a write will materialize on a given replica.
///
/// The StackerDB schema is chunk-oriented.  Each StackerDB contains a fixed number of bound-size
/// _slots_, each of which contain one _chunk_.  Slots are array-indexed, and a slot may have zero
/// or one chunk.
///
/// A `write` to a StackerDB is the act of replacing one slot's chunk with new data, and a
/// `read` on a StackerDB is the act of loading one slot's chunk from the node's local replica.  Reading
/// and writing a single slot on one node is atomic.  StackerDB replication proceeds in a
/// store-and-forward manner -- newly-discovered chunks are stored to the node's local replica and
/// broadcast to a subset of neighbors who also replicate the given StackerDB.
///
/// Each slot has an associated Lamport clock, and an associated public key hash used to
/// authenticate writes.  The Lamport clock is used to identify the latest version of a slot's
/// chunk -- a node will replace an existing but stale copy of a chunk with a new chunk if its
/// Lamport clock has a strictly higher value.  The slot's metadata -- its ID, Lamport clock, and
/// data hash -- must be signed by the slot's public key hash's associated private key in order to
/// be stored.  The chunks themselves are ordered byte sequences with no mandatory internal
/// structure.
///
/// StackerDB state is ephemeral.  Chunk eviction is controlled by the smart contract.  At every
/// Bitcoin block, the node queries the smart contract for a list of slots to clear.
///
/// ## Control Plane
///
/// The smart contract to which a StackerDB is bound controls how many slots the DB has, who can
/// write to which slots (identified by public key hash), how big a slot is, and how often a
/// slot can be written to (in wall-clock time).  This smart contract is queried once per reward cycle
/// in order to configure the database.
///
/// Applications that employ StackerDBSet would deploy one or more smart contracts that list out
/// which users can store data to the StackerDB replica, and how much space they get.
///
/// ## Replication Protocol
///
/// StackerDB replication proceeds in a three-part protocol: discovery, inventory query, and
/// chunk exchange.  The discovery protocol leverages the Stacks node's neighbor-walk algorithm to
/// discover which StackerDBSet other nodes claim to replicate.  On receipt of a `Handshake` message,
/// a StackerDB-aware node replies with a `StackerDBHandshakeAccept` message which encodes both the
/// contents of a `HandshakeAccept` message as well as a list of local StackerDBSet (identified by
/// their smart contracts' addresses).  Upon receipt of a `StackerDBHandshakeAccept`, the node
/// stores the list of smart contracts in its `PeerDB` as part of the network frontier state.  In
/// doing so, nodes eventually learn of all of the StackerDBSet replicated by all other nodes.  To
/// bound the size of this state, the protocol mandates that a node can only replicate up to 256
/// StackerDBSet.  The handshake-handling code happens in net::chat::handle_handshake().
///
/// When a node begins to replicate a StackerDB, it first queries the `PeerDB` for the set of nodes
/// that claim to have copies.  This set, called the "DB neighbors", is distinct from the set
/// of neighbors the node uses to replicate blocks and transactions.  It then connects
/// to these nodes with a `Handshake` / `StackerDBHandshakeAccept` exchange (if the neighbor walk
/// has not done so already), and proceeds to query each DB's inventories by sending them
/// `StackerDBGetChunkInData` messages.
///
/// The DB inventory (`StackerDBChunkInvData`) is simply a vector of all of the remote peers' slots' versions.
/// Once the node has received all DB inventories from its neighbors, it schedules them for
/// download by prioritizing them by newest-first, and then by rarest-first, in order to ensure
/// that the latest, least-replicated data is downloaded first.
///
/// Once the node has computed its download schedule, it queries its DB neighbors for chunks with
/// the given versions (via `StackerDBGetChunkData`).  Upon receipt of a chunk, the node verifies the signature on the chunk's
/// metadata (via `SlotMetadata`), verifies that the chunk data hashes to the metadata's indicated data hash, and stores
/// the chunk (via `StackerDBSet` and `StackerDBTx`).  It will then select neighbors to which to broadcast this chunk, inferring from the
/// download schedule which DB neighbors have yet to process this particular version of the chunk.
///
/// ## Comparison to other Stacks storage
///
/// StackerDBSet differ from AtlasDBs in that data chunks are not authenticated by the blockchain,
/// but instead are authenticated by public key hashes made available from a smart contract.  As
/// such, a node can begin replicating a StackerDB whenever its operator wants -- it does not need
/// to re-synchronize blockchain state to get the list of chunk hashes.  Furthermore, StackerDB
/// state can be written to as fast as the smart contract permits -- there is no need to wait for a
/// corresponding transaction to confirm.
///
/// StackerDBSet differ from Gaia in that Stacks nodes are the principal means of storing data.  Any
/// reachable Stacks node can fulfill requests for chunks.  It is up to the StackerDB maintainer to
/// convince node operators to replicate StackerDBSet on their behalf.  In addition, StackerDB state
/// is ephemeral -- its longevity in the system depends on application endpoints re-replicating the
/// state periodically (whereas Gaia stores data for as long as the back-end storage provider's SLA
/// indicates).

#[cfg(test)]
pub mod tests;

pub mod bits;
pub mod db;

use crate::net::ContractId;
use crate::net::Neighbor;
use crate::net::NeighborKey;
use crate::net::StackerDBChunkData;

use crate::util_lib::db::{DBConn, DBTx};
use stacks_common::types::chainstate::ConsensusHash;
use stacks_common::util::hash::Sha512Trunc256Sum;
use stacks_common::util::secp256k1::MessageSignature;
use std::collections::{HashMap, HashSet};

/// maximum chunk inventory size
pub const STACKERDB_INV_MAX: u32 = 4096;

/// Final result of synchronizing state with a remote set of DB replicas
pub struct StackerDBSyncResult {
    /// which contract this is a replica for
    pub contract_id: ContractId,
    /// list of data to store
    pub chunks_to_store: Vec<StackerDBChunkData>,
    /// dead neighbors we can disconnect from
    pub dead: HashSet<NeighborKey>,
}

/// Settings for the Stacker DB
#[derive(Clone, Debug, PartialEq)]
pub struct StackerDBConfig {
    /// maximum chunk size
    pub chunk_size: u64,
    /// number of chunks in this DB.  Cannot be bigger than STACERDB_INV_MAX.
    pub num_slots: u64,
    /// minimum wall-clock time between writes to the same slot.
    pub write_freq: u64,
    /// maximum number of times a slot may be written to during a reward cycle.
    pub max_writes: u32,
    /// hint for some initial peers that have replicas of this DB
    pub hint_peers: Vec<NeighborKey>,
    /// hint for how many neighbors to connect to
    pub num_neighbors: usize,
}

impl StackerDBConfig {
    /// Config that does nothing
    pub fn noop() -> StackerDBConfig {
        StackerDBConfig {
            chunk_size: u64::MAX,
            write_freq: 0,
            max_writes: u32::MAX,
            hint_peers: vec![],
            num_neighbors: 8,
            num_slots: STACKERDB_INV_MAX.into(),
        }
    }
}

/// This is the set of replicated chunks in all stacker DBs that this node subscribes to.
///
/// Callers can query chunks from individual stacker DBs by supplying the smart contract address.
pub struct StackerDBSet {
    conn: DBConn,
}

/// A transaction against one or more stacker DBs (really, against StackerDBSet)
pub struct StackerDBTx<'a> {
    sql_tx: DBTx<'a>,
    config: StackerDBConfig,
}

/// Slot metadata from the DB.
/// This is derived state from a StackerDBChunkData message.
#[derive(Clone, Debug, PartialEq)]
pub struct SlotMetadata {
    /// Slot identifier (unique for each DB instance)
    pub slot_id: u32,
    /// Slot version (a lamport clock)
    pub slot_version: u32,
    /// data hash
    pub data_hash: Sha512Trunc256Sum,
    /// signature over the above
    pub signature: MessageSignature,
}
