// Copyright (C) 2013-2020 Blockstack PBC, a public benefit corporation
// Copyright (C) 2020 Stacks Open Internet Foundation
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
use std::fmt::Display;
use std::path::Path;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use blockstack_lib::chainstate::nakamoto::NakamotoBlock;
use blockstack_lib::chainstate::stacks::TransactionPayload;
#[cfg(any(test, feature = "testing"))]
use blockstack_lib::util_lib::db::FromColumn;
use blockstack_lib::util_lib::db::{
    query_row, query_rows, sqlite_open, table_exists, tx_begin_immediate, u64_to_sql,
    Error as DBError, FromRow,
};
use clarity::types::chainstate::{BurnchainHeaderHash, StacksAddress, StacksPublicKey};
use clarity::types::Address;
use libsigner::v0::messages::{RejectReason, RejectReasonPrefix, StateMachineUpdate};
use libsigner::v0::signer_state::GlobalStateEvaluator;
use libsigner::BlockProposal;
use rusqlite::functions::FunctionFlags;
use rusqlite::{params, Connection, Error as SqliteError, OpenFlags, OptionalExtension};
use serde::{Deserialize, Serialize};
use stacks_common::codec::{read_next, write_next, Error as CodecError, StacksMessageCodec};
use stacks_common::types::chainstate::ConsensusHash;
use stacks_common::util::get_epoch_time_secs;
use stacks_common::util::hash::Sha512Trunc256Sum;
use stacks_common::util::secp256k1::MessageSignature;
use stacks_common::{debug, define_u8_enum, error, warn};

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
/// A vote across the signer set for a block
pub struct NakamotoBlockVote {
    /// Signer signature hash (i.e. block hash) of the Nakamoto block
    pub signer_signature_hash: Sha512Trunc256Sum,
    /// Whether or not the block was rejected
    pub rejected: bool,
}

impl StacksMessageCodec for NakamotoBlockVote {
    fn consensus_serialize<W: std::io::Write>(&self, fd: &mut W) -> Result<(), CodecError> {
        write_next(fd, &self.signer_signature_hash)?;
        if self.rejected {
            write_next(fd, &1u8)?;
        }
        Ok(())
    }

    fn consensus_deserialize<R: std::io::Read>(fd: &mut R) -> Result<Self, CodecError> {
        let signer_signature_hash = read_next(fd)?;
        let rejected_byte: Option<u8> = read_next(fd).ok();
        let rejected = rejected_byte.is_some();
        Ok(Self {
            signer_signature_hash,
            rejected,
        })
    }
}

#[derive(Serialize, Deserialize, Debug, PartialEq)]
/// Struct for storing information about a burn block
pub struct BurnBlockInfo {
    /// The hash of the burn block
    pub block_hash: BurnchainHeaderHash,
    /// The height of the burn block
    pub block_height: u64,
    /// The consensus hash of the burn block
    pub consensus_hash: ConsensusHash,
    /// The hash of the parent burn block
    pub parent_burn_block_hash: BurnchainHeaderHash,
}

impl FromRow<BurnBlockInfo> for BurnBlockInfo {
    fn from_row(row: &rusqlite::Row) -> Result<Self, DBError> {
        let block_hash: BurnchainHeaderHash = row.get(0)?;
        let block_height: u64 = row.get(1)?;
        let consensus_hash: ConsensusHash = row.get(2)?;
        let parent_burn_block_hash: BurnchainHeaderHash = row.get(3)?;
        Ok(BurnBlockInfo {
            block_hash,
            block_height,
            consensus_hash,
            parent_burn_block_hash,
        })
    }
}

#[derive(Serialize, Deserialize, Debug, PartialEq, Default, Clone)]
/// Store extra version-specific info in `BlockInfo`
pub enum ExtraBlockInfo {
    #[default]
    /// Don't know what version
    None,
    /// Extra data for Signer V0
    V0,
}

define_u8_enum!(
/// Block state relative to the signer's view of the stacks blockchain
BlockState {
    /// The block has not yet been processed by the signer
    Unprocessed = 0,
    /// The block is accepted by the signer but a threshold of signers has not yet signed it
    LocallyAccepted = 1,
    /// The block is rejected by the signer but a threshold of signers has not accepted/rejected it yet
    LocallyRejected = 2,
    /// A threshold number of signers have signed the block
    GloballyAccepted = 3,
    /// A threshold number of signers have rejected the block
    GloballyRejected = 4
});

impl TryFrom<u8> for BlockState {
    type Error = String;
    fn try_from(value: u8) -> Result<BlockState, String> {
        let state = match value {
            0 => BlockState::Unprocessed,
            1 => BlockState::LocallyAccepted,
            2 => BlockState::LocallyRejected,
            3 => BlockState::GloballyAccepted,
            4 => BlockState::GloballyRejected,
            _ => return Err("Invalid block state".into()),
        };
        Ok(state)
    }
}

impl Display for BlockState {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let state = match self {
            BlockState::Unprocessed => "Unprocessed",
            BlockState::LocallyAccepted => "LocallyAccepted",
            BlockState::LocallyRejected => "LocallyRejected",
            BlockState::GloballyAccepted => "GloballyAccepted",
            BlockState::GloballyRejected => "GloballyRejected",
        };
        write!(f, "{state}")
    }
}

impl TryFrom<&str> for BlockState {
    type Error = String;
    fn try_from(value: &str) -> Result<BlockState, String> {
        let state = match value {
            "Unprocessed" => BlockState::Unprocessed,
            "LocallyAccepted" => BlockState::LocallyAccepted,
            "LocallyRejected" => BlockState::LocallyRejected,
            "GloballyAccepted" => BlockState::GloballyAccepted,
            "GloballyRejected" => BlockState::GloballyRejected,
            _ => return Err("Unparsable block state".into()),
        };
        Ok(state)
    }
}

/// Additional Info about a proposed block
#[derive(Serialize, Deserialize, Debug, PartialEq, Clone)]
pub struct BlockInfo {
    /// The block we are considering
    pub block: NakamotoBlock,
    /// The burn block height at which the block was proposed
    pub burn_block_height: u64,
    /// The reward cycle the block belongs to
    pub reward_cycle: u64,
    /// Our vote on the block if we have one yet
    pub vote: Option<NakamotoBlockVote>,
    /// Whether the block contents are valid
    pub valid: Option<bool>,
    /// Whether this block is already being signed over
    pub signed_over: bool,
    /// Time at which the proposal was received by this signer (epoch time in seconds)
    pub proposed_time: u64,
    /// Time at which the proposal was signed by this signer (epoch time in seconds)
    pub signed_self: Option<u64>,
    /// Time at which the proposal was signed by a threshold in the signer set (epoch time in seconds)
    pub signed_group: Option<u64>,
    /// The block state relative to the signer's view of the stacks blockchain
    pub state: BlockState,
    /// Consumed processing time in milliseconds to validate this block
    pub validation_time_ms: Option<u64>,
    /// Extra data specific to v0, v1, etc.
    pub ext: ExtraBlockInfo,
    /// If this signer rejected this block, what was the reason
    pub reject_reason: Option<RejectReason>,
}

impl From<BlockProposal> for BlockInfo {
    fn from(value: BlockProposal) -> Self {
        Self {
            block: value.block,
            burn_block_height: value.burn_height,
            reward_cycle: value.reward_cycle,
            vote: None,
            valid: None,
            signed_over: false,
            proposed_time: get_epoch_time_secs(),
            signed_self: None,
            signed_group: None,
            ext: ExtraBlockInfo::default(),
            state: BlockState::Unprocessed,
            validation_time_ms: None,
            reject_reason: None,
        }
    }
}
impl BlockInfo {
    /// Whether the block is a tenure change block or not
    pub fn is_tenure_change(&self) -> bool {
        self.block
            .txs
            .first()
            .map(|tx| matches!(tx.payload, TransactionPayload::TenureChange(_)))
            .unwrap_or(false)
    }

    /// Mark this block as locally accepted, valid, signed over, and records either the self or group signed timestamp in the block info if it wasn't
    ///  already set.
    pub fn mark_locally_accepted(&mut self, group_signed: bool) -> Result<(), String> {
        self.move_to(BlockState::LocallyAccepted)?;
        self.valid = Some(true);
        self.signed_over = true;
        if group_signed {
            self.signed_group.get_or_insert(get_epoch_time_secs());
        } else {
            self.signed_self.get_or_insert(get_epoch_time_secs());
        }
        Ok(())
    }

    /// Mark this block as valid, signed over, and records a group timestamp in the block info if it wasn't
    ///  already set.
    fn mark_globally_accepted(&mut self) -> Result<(), String> {
        self.move_to(BlockState::GloballyAccepted)?;
        self.valid = Some(true);
        self.signed_over = true;
        self.signed_group.get_or_insert(get_epoch_time_secs());
        Ok(())
    }

    /// Mark the block as locally rejected and invalid
    pub fn mark_locally_rejected(&mut self) -> Result<(), String> {
        self.move_to(BlockState::LocallyRejected)?;
        self.valid = Some(false);
        Ok(())
    }

    /// Mark the block as globally rejected and invalid
    fn mark_globally_rejected(&mut self) -> Result<(), String> {
        self.move_to(BlockState::GloballyRejected)?;
        self.valid = Some(false);
        Ok(())
    }

    /// Return the block's signer signature hash
    pub fn signer_signature_hash(&self) -> Sha512Trunc256Sum {
        self.block.header.signer_signature_hash()
    }

    /// Check if the block state transition is valid
    fn check_state(&self, state: BlockState) -> bool {
        let prev_state = &self.state;
        if *prev_state == state {
            return true;
        }
        match state {
            BlockState::Unprocessed => false,
            BlockState::LocallyAccepted | BlockState::LocallyRejected => !matches!(
                prev_state,
                BlockState::GloballyRejected | BlockState::GloballyAccepted
            ),
            BlockState::GloballyAccepted => !matches!(prev_state, BlockState::GloballyRejected),
            BlockState::GloballyRejected => !matches!(prev_state, BlockState::GloballyAccepted),
        }
    }

    /// Attempt to transition the block state
    pub fn move_to(&mut self, state: BlockState) -> Result<(), String> {
        if !self.check_state(state) {
            return Err(format!(
                "Invalid state transition from {} to {state}",
                self.state
            ));
        }
        self.state = state;
        Ok(())
    }

    /// Check if the block is globally accepted or rejected
    pub fn has_reached_consensus(&self) -> bool {
        matches!(
            self.state,
            BlockState::GloballyAccepted | BlockState::GloballyRejected
        )
    }

    /// Check if the block is locally accepted or rejected
    pub fn is_locally_finalized(&self) -> bool {
        matches!(
            self.state,
            BlockState::LocallyAccepted | BlockState::LocallyRejected
        )
    }
}

/// This struct manages a SQLite database connection
/// for the signer.
#[derive(Debug)]
pub struct SignerDb {
    /// Connection to the SQLite database
    db: Connection,
}

static CREATE_BLOCKS_TABLE_1: &str = "
CREATE TABLE IF NOT EXISTS blocks (
    reward_cycle INTEGER NOT NULL,
    signer_signature_hash TEXT NOT NULL,
    block_info TEXT NOT NULL,
    consensus_hash TEXT NOT NULL,
    signed_over INTEGER NOT NULL,
    stacks_height INTEGER NOT NULL,
    burn_block_height INTEGER NOT NULL,
    PRIMARY KEY (reward_cycle, signer_signature_hash)
) STRICT";

static CREATE_BLOCKS_TABLE_2: &str = "
CREATE TABLE IF NOT EXISTS blocks (
    reward_cycle INTEGER NOT NULL,
    signer_signature_hash TEXT NOT NULL,
    block_info TEXT NOT NULL,
    consensus_hash TEXT NOT NULL,
    signed_over INTEGER NOT NULL,
    broadcasted INTEGER,
    stacks_height INTEGER NOT NULL,
    burn_block_height INTEGER NOT NULL,
    PRIMARY KEY (reward_cycle, signer_signature_hash)
) STRICT";

static CREATE_INDEXES_1: &str = "
CREATE INDEX IF NOT EXISTS blocks_signed_over ON blocks (signed_over);
CREATE INDEX IF NOT EXISTS blocks_consensus_hash ON blocks (consensus_hash);
CREATE INDEX IF NOT EXISTS blocks_valid ON blocks ((json_extract(block_info, '$.valid')));
CREATE INDEX IF NOT EXISTS burn_blocks_height ON burn_blocks (block_height);
";

static CREATE_INDEXES_2: &str = r#"
CREATE INDEX IF NOT EXISTS block_signatures_on_signer_signature_hash ON block_signatures(signer_signature_hash);
"#;

static CREATE_INDEXES_3: &str = r#"
CREATE INDEX IF NOT EXISTS block_rejection_signer_addrs_on_block_signature_hash ON block_rejection_signer_addrs(signer_signature_hash);
"#;

static CREATE_INDEXES_4: &str = r#"
CREATE INDEX IF NOT EXISTS blocks_state ON blocks ((json_extract(block_info, '$.state')));
CREATE INDEX IF NOT EXISTS blocks_signed_group ON blocks ((json_extract(block_info, '$.signed_group')));
"#;

static CREATE_INDEXES_5: &str = r#"
CREATE INDEX IF NOT EXISTS blocks_signed_over ON blocks (consensus_hash, signed_over);
CREATE INDEX IF NOT EXISTS blocks_consensus_hash_state ON blocks (consensus_hash, state);
CREATE INDEX IF NOT EXISTS blocks_state ON blocks (state);
CREATE INDEX IF NOT EXISTS blocks_signed_group ON blocks (signed_group);
"#;

static CREATE_INDEXES_6: &str = r#"
CREATE INDEX IF NOT EXISTS block_validations_pending_on_added_time ON block_validations_pending(added_time ASC);
"#;

static CREATE_INDEXES_8: &str = r#"
-- Add new index for get_last_globally_accepted_block query
CREATE INDEX IF NOT EXISTS blocks_consensus_hash_state_height ON blocks (consensus_hash, state, stacks_height DESC);

-- Add new index for get_canonical_tip query
CREATE INDEX IF NOT EXISTS blocks_state_height_signed_group ON blocks (state, stacks_height DESC, signed_group DESC);

-- Index for get_first_signed_block_in_tenure
CREATE INDEX IF NOT EXISTS blocks_consensus_hash_status_height ON blocks (consensus_hash, signed_over, stacks_height ASC);

-- Index for has_unprocessed_blocks
CREATE INDEX IF NOT EXISTS blocks_reward_cycle_state on blocks (reward_cycle, state);
"#;

static CREATE_INDEXES_11: &str = r#"
CREATE INDEX IF NOT EXISTS signer_state_machine_updates_reward_cycle_received_time ON signer_state_machine_updates (reward_cycle, received_time ASC);
"#;

static CREATE_SIGNER_STATE_TABLE: &str = "
CREATE TABLE IF NOT EXISTS signer_states (
    reward_cycle INTEGER PRIMARY KEY,
    encrypted_state BLOB NOT NULL
) STRICT";

static CREATE_BURN_STATE_TABLE: &str = "
CREATE TABLE IF NOT EXISTS burn_blocks (
    block_hash TEXT PRIMARY KEY,
    block_height INTEGER NOT NULL,
    received_time INTEGER NOT NULL
) STRICT";

static CREATE_DB_CONFIG: &str = "
    CREATE TABLE db_config(
        version INTEGER NOT NULL
    ) STRICT
";

static DROP_SCHEMA_0: &str = "
   DROP TABLE IF EXISTS burn_blocks;
   DROP TABLE IF EXISTS signer_states;
   DROP TABLE IF EXISTS blocks;
   DROP TABLE IF EXISTS db_config;";

static DROP_SCHEMA_1: &str = "
   DROP TABLE IF EXISTS burn_blocks;
   DROP TABLE IF EXISTS signer_states;
   DROP TABLE IF EXISTS blocks;
   DROP TABLE IF EXISTS db_config;";

static DROP_SCHEMA_2: &str = "
    DROP TABLE IF EXISTS burn_blocks;
    DROP TABLE IF EXISTS signer_states;
    DROP TABLE IF EXISTS blocks;
    DROP TABLE IF EXISTS db_config;";

static CREATE_BLOCK_SIGNATURES_TABLE: &str = r#"
CREATE TABLE IF NOT EXISTS block_signatures (
    -- The block sighash commits to all of the stacks and burnchain state as of its parent,
    -- as well as the tenure itself so there's no need to include the reward cycle.  Just
    -- the sighash is sufficient to uniquely identify the block across all burnchain, PoX,
    -- and stacks forks.
    signer_signature_hash TEXT NOT NULL,
    -- signature itself
    signature TEXT NOT NULL,
    PRIMARY KEY (signature)
) STRICT;"#;

static CREATE_BLOCK_REJECTION_SIGNER_ADDRS_TABLE: &str = r#"
CREATE TABLE IF NOT EXISTS block_rejection_signer_addrs (
    -- The block sighash commits to all of the stacks and burnchain state as of its parent,
    -- as well as the tenure itself so there's no need to include the reward cycle.  Just
    -- the sighash is sufficient to uniquely identify the block across all burnchain, PoX,
    -- and stacks forks.
    signer_signature_hash TEXT NOT NULL,
    -- the signer address that rejected the block
    signer_addr TEXT NOT NULL,
    PRIMARY KEY (signer_addr)
) STRICT;"#;

// Migration logic necessary to move blocks from the old blocks table to the new blocks table
static MIGRATE_BLOCKS_TABLE_2_BLOCKS_TABLE_3: &str = r#"
CREATE TABLE IF NOT EXISTS temp_blocks (
    -- The block sighash commits to all of the stacks and burnchain state as of its parent,
    -- as well as the tenure itself so there's no need to include the reward cycle.  Just
    -- the sighash is sufficient to uniquely identify the block across all burnchain, PoX,
    -- and stacks forks.
    signer_signature_hash TEXT NOT NULL PRIMARY KEY,
    reward_cycle INTEGER NOT NULL,
    block_info TEXT NOT NULL,
    consensus_hash TEXT NOT NULL,
    signed_over INTEGER NOT NULL,
    broadcasted INTEGER,
    stacks_height INTEGER NOT NULL,
    burn_block_height INTEGER NOT NULL,
    valid INTEGER,
    state TEXT NOT NULL,
    signed_group INTEGER,
    signed_self INTEGER,
    proposed_time INTEGER NOT NULL,
    validation_time_ms INTEGER,
    tenure_change INTEGER NOT NULL
) STRICT;

INSERT INTO temp_blocks (
    signer_signature_hash,
    reward_cycle,
    block_info,
    consensus_hash,
    signed_over,
    broadcasted,
    stacks_height,
    burn_block_height,
    valid,
    state,
    signed_group,
    signed_self,
    proposed_time,
    validation_time_ms,
    tenure_change
)
SELECT
    signer_signature_hash,
    reward_cycle,
    block_info,
    consensus_hash,
    signed_over,
    broadcasted,
    stacks_height,
    burn_block_height,
    json_extract(block_info, '$.valid') AS valid,
    json_extract(block_info, '$.state') AS state,
    json_extract(block_info, '$.signed_group') AS signed_group,
    json_extract(block_info, '$.signed_self') AS signed_self,
    json_extract(block_info, '$.proposed_time') AS proposed_time,
    json_extract(block_info, '$.validation_time_ms') AS validation_time_ms,
    is_tenure_change(block_info) AS tenure_change
FROM blocks;

DROP TABLE blocks;

ALTER TABLE temp_blocks RENAME TO blocks;"#;

// Migration logic necessary to move burn blocks from the old burn blocks table to the new burn blocks table
// with the correct primary key
static MIGRATE_BURN_STATE_TABLE_1_TO_TABLE_2: &str = r#"
CREATE TABLE IF NOT EXISTS temp_burn_blocks (
    block_hash TEXT NOT NULL,
    block_height INTEGER NOT NULL,
    received_time INTEGER NOT NULL,
    consensus_hash TEXT PRIMARY KEY NOT NULL
) STRICT;

INSERT INTO temp_burn_blocks (block_hash, block_height, received_time, consensus_hash)
SELECT block_hash, block_height, received_time, consensus_hash
FROM (
    SELECT
        block_hash,
        block_height,
        received_time,
        consensus_hash,
        ROW_NUMBER() OVER (
            PARTITION BY consensus_hash
            ORDER BY received_time DESC
        ) AS rn
    FROM burn_blocks
    WHERE consensus_hash IS NOT NULL
      AND consensus_hash <> ''
) AS ordered
WHERE rn = 1;

DROP TABLE burn_blocks;
ALTER TABLE temp_burn_blocks RENAME TO burn_blocks;

CREATE INDEX IF NOT EXISTS idx_burn_blocks_block_hash ON burn_blocks(block_hash);
"#;

static CREATE_BLOCK_VALIDATION_PENDING_TABLE: &str = r#"
CREATE TABLE IF NOT EXISTS block_validations_pending (
    signer_signature_hash TEXT NOT NULL,
    -- the time at which the block was added to the pending table
    added_time INTEGER NOT NULL,
    PRIMARY KEY (signer_signature_hash)
) STRICT;"#;

static CREATE_TENURE_ACTIVTY_TABLE: &str = r#"
CREATE TABLE IF NOT EXISTS tenure_activity (
    consensus_hash TEXT NOT NULL PRIMARY KEY,
    last_activity_time INTEGER NOT NULL
) STRICT;"#;

static ADD_REJECT_CODE: &str = r#"
ALTER TABLE block_rejection_signer_addrs
    ADD COLUMN reject_code INTEGER;
"#;

static ADD_CONSENSUS_HASH: &str = r#"
ALTER TABLE burn_blocks
    ADD COLUMN consensus_hash TEXT;
"#;

static ADD_CONSENSUS_HASH_INDEX: &str = r#"
CREATE INDEX IF NOT EXISTS burn_blocks_ch on burn_blocks (consensus_hash);
"#;

static CREATE_SIGNER_STATE_MACHINE_UPDATES_TABLE: &str = r#"
CREATE TABLE IF NOT EXISTS signer_state_machine_updates (
    signer_addr TEXT NOT NULL,
    reward_cycle INTEGER NOT NULL,
    state_update TEXT NOT NULL,
    received_time INTEGER NOT NULL,
    PRIMARY KEY (signer_addr, reward_cycle)
) STRICT;"#;

static CREATE_BURN_BLOCK_UPDATES_RECEIVED_TIME_TABLE: &str = r#"
CREATE TABLE IF NOT EXISTS burn_block_updates_received_times (
    signer_addr TEXT NOT NULL,
    burn_block_consensus_hash TEXT NOT NULL,
    received_time INTEGER NOT NULL,
    PRIMARY KEY (signer_addr, burn_block_consensus_hash)
) STRICT;
"#;

static ADD_PARENT_BURN_BLOCK_HASH: &str = r#"
 ALTER TABLE burn_blocks
    ADD COLUMN parent_burn_block_hash TEXT;
"#;

static ADD_PARENT_BURN_BLOCK_HASH_INDEX: &str = r#"
CREATE INDEX IF NOT EXISTS burn_blocks_parent_burn_block_hash_idx on burn_blocks (parent_burn_block_hash);
"#;

static ADD_BLOCK_VALIDATED_BY_REPLAY_TXS_TABLE: &str = r#"
CREATE TABLE IF NOT EXISTS block_validated_by_replay_txs (
    signer_signature_hash TEXT NOT NULL,
    replay_tx_hash TEXT NOT NULL,
    replay_tx_exhausted INTEGER NOT NULL,
    PRIMARY KEY (signer_signature_hash, replay_tx_hash)
) STRICT;"#;

static CREATE_STACKERDB_TRACKING: &str = "
CREATE TABLE stackerdb_tracking(
   public_key TEXT NOT NULL,
   slot_id INTEGER NOT NULL,
   slot_version INTEGER NOT NULL,
   PRIMARY KEY (public_key, slot_id)
) STRICT;";

// Used by get_burn_block_received_time_from_signers
static ADD_BURN_BLOCK_RECEIVED_TIMES_CONSENSUS_HASH_INDEX: &str = r#"
CREATE INDEX IF NOT EXISTS burn_block_updates_received_times_consensus_hash ON burn_block_updates_received_times(burn_block_consensus_hash, received_time ASC);
"#;

// Used by get_last_globally_accepted_block_signed_self
static ADD_BLOCK_SIGNED_SELF_INDEX: &str = r#"
CREATE INDEX idx_blocks_query_opt ON blocks (consensus_hash, state, signed_self, burn_block_height DESC);
"#;

static DROP_BLOCK_SIGNATURES_TABLE: &str = r#"
DROP TABLE IF EXISTS block_signatures;
"#;

static CREATE_BLOCK_SIGNATURES_TABLE_V16: &str = r#"
CREATE TABLE IF NOT EXISTS block_signatures (
    -- The block sighash commits to all of the stacks and burnchain state as of its parent,
    -- as well as the tenure itself so there's no need to include the reward cycle.  Just
    -- the sighash is sufficient to uniquely identify the block across all burnchain, PoX,
    -- and stacks forks.
    signer_signature_hash TEXT NOT NULL,
    -- the signer address that signed the block
    signer_addr TEXT NOT NULL,
    -- signature itself
    signature TEXT NOT NULL,
    PRIMARY KEY (signer_signature_hash, signer_addr)
) STRICT;"#;

static DROP_BLOCK_REJECTION_SIGNER_ADDRS: &str = r#"
DROP TABLE IF EXISTS block_rejection_signer_addrs;
"#;

static CREATE_BLOCK_REJECTION_SIGNER_ADDRS_V16: &str = r#"
CREATE TABLE IF NOT EXISTS block_rejection_signer_addrs (
    -- The block sighash commits to all of the stacks and burnchain state as of its parent,
    -- as well as the tenure itself so there's no need to include the reward cycle.  Just
    -- the sighash is sufficient to uniquely identify the block across all burnchain, PoX,
    -- and stacks forks.
    signer_signature_hash TEXT NOT NULL,
    -- the signer address that rejected the block
    signer_addr TEXT NOT NULL,
    -- the reject reason code
    reject_code INTEGER NOT NULL,
    PRIMARY KEY (signer_signature_hash, signer_addr)
) STRICT;"#;

static SCHEMA_1: &[&str] = &[
    DROP_SCHEMA_0,
    CREATE_DB_CONFIG,
    CREATE_BURN_STATE_TABLE,
    CREATE_BLOCKS_TABLE_1,
    CREATE_SIGNER_STATE_TABLE,
    CREATE_INDEXES_1,
    "INSERT INTO db_config (version) VALUES (1);",
];

static SCHEMA_2: &[&str] = &[
    DROP_SCHEMA_1,
    CREATE_DB_CONFIG,
    CREATE_BURN_STATE_TABLE,
    CREATE_BLOCKS_TABLE_2,
    CREATE_SIGNER_STATE_TABLE,
    CREATE_BLOCK_SIGNATURES_TABLE,
    CREATE_INDEXES_1,
    CREATE_INDEXES_2,
    "INSERT INTO db_config (version) VALUES (2);",
];

static SCHEMA_3: &[&str] = &[
    DROP_SCHEMA_2,
    CREATE_DB_CONFIG,
    CREATE_BURN_STATE_TABLE,
    CREATE_BLOCKS_TABLE_2,
    CREATE_SIGNER_STATE_TABLE,
    CREATE_BLOCK_SIGNATURES_TABLE,
    CREATE_BLOCK_REJECTION_SIGNER_ADDRS_TABLE,
    CREATE_INDEXES_1,
    CREATE_INDEXES_2,
    CREATE_INDEXES_3,
    "INSERT INTO db_config (version) VALUES (3);",
];

static SCHEMA_4: &[&str] = &[
    CREATE_INDEXES_4,
    "INSERT OR REPLACE INTO db_config (version) VALUES (4);",
];

static SCHEMA_5: &[&str] = &[
    MIGRATE_BLOCKS_TABLE_2_BLOCKS_TABLE_3,
    CREATE_INDEXES_5,
    "DELETE FROM db_config;", // Be extra careful. Make sure there is only ever one row in the table.
    "INSERT INTO db_config (version) VALUES (5);",
];

static SCHEMA_6: &[&str] = &[
    CREATE_BLOCK_VALIDATION_PENDING_TABLE,
    CREATE_INDEXES_6,
    "INSERT OR REPLACE INTO db_config (version) VALUES (6);",
];

static SCHEMA_7: &[&str] = &[
    CREATE_TENURE_ACTIVTY_TABLE,
    "INSERT OR REPLACE INTO db_config (version) VALUES (7);",
];

static SCHEMA_8: &[&str] = &[
    CREATE_INDEXES_8,
    "INSERT INTO db_config (version) VALUES (8);",
];

static SCHEMA_9: &[&str] = &[
    ADD_REJECT_CODE,
    "INSERT INTO db_config (version) VALUES (9);",
];

static SCHEMA_10: &[&str] = &[
    ADD_CONSENSUS_HASH,
    ADD_CONSENSUS_HASH_INDEX,
    "INSERT INTO db_config (version) VALUES (10);",
];

static SCHEMA_11: &[&str] = &[
    CREATE_SIGNER_STATE_MACHINE_UPDATES_TABLE,
    CREATE_INDEXES_11,
    "INSERT INTO db_config (version) VALUES (11);",
];

static SCHEMA_12: &[&str] = &[
    MIGRATE_BURN_STATE_TABLE_1_TO_TABLE_2,
    "INSERT OR REPLACE INTO db_config (version) VALUES (12);",
];

static SCHEMA_13: &[&str] = &[
    ADD_PARENT_BURN_BLOCK_HASH,
    ADD_PARENT_BURN_BLOCK_HASH_INDEX,
    "INSERT INTO db_config (version) VALUES (13);",
];

static SCHEMA_14: &[&str] = &[
    CREATE_STACKERDB_TRACKING,
    "INSERT INTO db_config (version) VALUES (14);",
];

static SCHEMA_15: &[&str] = &[
    ADD_BLOCK_VALIDATED_BY_REPLAY_TXS_TABLE,
    "INSERT INTO db_config (version) VALUES (15);",
];

static SCHEMA_16: &[&str] = &[
    CREATE_BURN_BLOCK_UPDATES_RECEIVED_TIME_TABLE,
    ADD_BURN_BLOCK_RECEIVED_TIMES_CONSENSUS_HASH_INDEX,
    ADD_BLOCK_SIGNED_SELF_INDEX,
    DROP_BLOCK_SIGNATURES_TABLE,
    CREATE_BLOCK_SIGNATURES_TABLE_V16,
    DROP_BLOCK_REJECTION_SIGNER_ADDRS,
    CREATE_BLOCK_REJECTION_SIGNER_ADDRS_V16,
    "INSERT INTO db_config (version) VALUES (16);",
];

struct Migration {
    version: u32,
    statements: &'static [&'static str],
}

static MIGRATIONS: &[Migration] = &[
    Migration {
        version: 1,
        statements: SCHEMA_1,
    },
    Migration {
        version: 2,
        statements: SCHEMA_2,
    },
    Migration {
        version: 3,
        statements: SCHEMA_3,
    },
    Migration {
        version: 4,
        statements: SCHEMA_4,
    },
    Migration {
        version: 5,
        statements: SCHEMA_5,
    },
    Migration {
        version: 6,
        statements: SCHEMA_6,
    },
    Migration {
        version: 7,
        statements: SCHEMA_7,
    },
    Migration {
        version: 8,
        statements: SCHEMA_8,
    },
    Migration {
        version: 9,
        statements: SCHEMA_9,
    },
    Migration {
        version: 10,
        statements: SCHEMA_10,
    },
    Migration {
        version: 11,
        statements: SCHEMA_11,
    },
    Migration {
        version: 12,
        statements: SCHEMA_12,
    },
    Migration {
        version: 13,
        statements: SCHEMA_13,
    },
    Migration {
        version: 14,
        statements: SCHEMA_14,
    },
    Migration {
        version: 15,
        statements: SCHEMA_15,
    },
    Migration {
        version: 16,
        statements: SCHEMA_16,
    },
];

impl SignerDb {
    /// The current schema version used in this build of the signer binary.
    pub const SCHEMA_VERSION: u32 = 16;

    /// Create a new `SignerState` instance.
    /// This will create a new SQLite database at the given path
    /// or an in-memory database if the path is ":memory:"
    pub fn new(db_path: impl AsRef<Path>) -> Result<Self, DBError> {
        let connection = Self::connect(db_path)?;

        let mut signer_db = Self { db: connection };
        signer_db.create_or_migrate()?;

        Ok(signer_db)
    }

    /// Returns the schema version of the database
    fn get_schema_version(conn: &Connection) -> Result<u32, DBError> {
        if !table_exists(conn, "db_config")? {
            return Ok(0);
        }
        let result = conn
            .query_row("SELECT MAX(version) FROM db_config LIMIT 1", [], |row| {
                row.get(0)
            })
            .optional();
        match result {
            Ok(x) => Ok(x.unwrap_or(0)),
            Err(e) => Err(DBError::from(e)),
        }
    }

    /// Register custom scalar functions used by the database
    fn register_scalar_functions(&self) -> Result<(), DBError> {
        // Register helper function for determining if a block is a tenure change transaction
        // Required only for data migration from Schema 4 to Schema 5
        self.db.create_scalar_function(
            "is_tenure_change",
            1,
            FunctionFlags::SQLITE_UTF8 | FunctionFlags::SQLITE_DETERMINISTIC,
            |ctx| {
                let value = ctx.get::<String>(0)?;
                let block_info = serde_json::from_str::<BlockInfo>(&value)
                    .map_err(|e| SqliteError::UserFunctionError(e.into()))?;
                Ok(block_info.is_tenure_change())
            },
        )?;
        // Register helper function for extracting the burn_block from the state machine update content
        // Required only for data migration from Schema 14 to Schema 15
        self.db.create_scalar_function(
            "extract_burn_block_consensus_hash",
            1,
            FunctionFlags::SQLITE_UTF8 | FunctionFlags::SQLITE_DETERMINISTIC,
            |ctx| {
                let json_str = ctx.get::<String>(0)?;
                Self::extract_burn_block_consensus_hash_from_json(&json_str)
            },
        )?;
        Ok(())
    }

    /// Drop registered scalar functions used only for data migrations
    fn remove_scalar_functions(&self) -> Result<(), DBError> {
        self.db.remove_function("is_tenure_change", 1)?;
        self.db
            .remove_function("extract_burn_block_consensus_hash", 1)?;
        Ok(())
    }

    /// Either instantiate a new database, or migrate an existing one
    fn create_or_migrate(&mut self) -> Result<(), DBError> {
        self.register_scalar_functions()?;
        let sql_tx = tx_begin_immediate(&mut self.db)?;

        let mut current_db_version = Self::get_schema_version(&sql_tx)?;
        debug!("Current SignerDB schema version: {}", current_db_version);

        for migration in MIGRATIONS.iter() {
            if current_db_version >= migration.version {
                // don't need this migration, continue to see if we need later migrations
                continue;
            }
            if current_db_version != migration.version - 1 {
                // This implies a gap or out-of-order migration definition,
                // or the database is at a version X, and the next migration is X+2 instead of X+1.
                sql_tx.rollback()?;
                return Err(DBError::Other(format!(
                    "Migration step missing or out of order. Current DB version: {}, trying to apply migration for version: {}",
                    current_db_version, migration.version
                )));
            }
            debug!(
                "Applying SignerDB migration for schema version {}",
                migration.version
            );
            for statement in migration.statements.iter() {
                sql_tx.execute_batch(statement)?;
            }

            // Verify that the migration script updated the version correctly
            let new_version_check = Self::get_schema_version(&sql_tx)?;
            if new_version_check != migration.version {
                sql_tx.rollback()?;
                return Err(DBError::Other(format!(
                    "Migration to version {} failed to update DB version. Expected {}, got {}.",
                    migration.version, migration.version, new_version_check
                )));
            }
            current_db_version = new_version_check;
            debug!(
                "Successfully migrated to schema version {}",
                current_db_version
            );
        }

        match current_db_version.cmp(&Self::SCHEMA_VERSION) {
            std::cmp::Ordering::Less => {
                sql_tx.rollback()?;
                return Err(DBError::Other(format!(
                    "Database migration incomplete. Current version: {}, SCHEMA_VERSION: {}",
                    current_db_version,
                    Self::SCHEMA_VERSION
                )));
            }
            std::cmp::Ordering::Greater => {
                sql_tx.rollback()?;
                return Err(DBError::Other(format!(
                    "Database schema is newer than SCHEMA_VERSION. SCHEMA_VERSION = {}, Current version = {}. Did you forget to update SCHEMA_VERSION?",
                    Self::SCHEMA_VERSION, current_db_version
                )));
            }
            std::cmp::Ordering::Equal => {}
        }

        sql_tx.commit()?;
        self.remove_scalar_functions()?;
        Ok(())
    }

    fn connect(db_path: impl AsRef<Path>) -> Result<Connection, SqliteError> {
        sqlite_open(
            db_path,
            OpenFlags::SQLITE_OPEN_READ_WRITE | OpenFlags::SQLITE_OPEN_CREATE,
            false,
        )
    }

    /// Extracts the `burn_block` string from a JSON state machine update payload
    fn extract_burn_block_consensus_hash_from_json(json_str: &str) -> rusqlite::Result<String> {
        let v: serde_json::Value =
            serde_json::from_str(json_str).map_err(|e| SqliteError::UserFunctionError(e.into()))?;

        let content = &v["content"];
        let content_obj = if let Some(v0) = content.get("V0") {
            v0
        } else if let Some(v1) = content.get("V1") {
            v1
        } else {
            return Err(SqliteError::UserFunctionError(
                "Invalid \"content\" struct: Expected one of \"V0\" or \"V1\"".into(),
            ));
        };

        let burn_block_hex = content_obj
            .get("burn_block")
            .and_then(|v| v.as_str())
            .ok_or_else(|| SqliteError::UserFunctionError("Missing burn_block".into()))?;

        Ok(burn_block_hex.to_string())
    }

    /// Get the latest known version from the db for the given slot_id/pk pair
    pub fn get_latest_chunk_version(
        &self,
        pk: &StacksPublicKey,
        slot_id: u32,
    ) -> Result<Option<u32>, DBError> {
        self.db
            .query_row(
                "SELECT slot_version FROM stackerdb_tracking WHERE public_key = ? AND slot_id = ?",
                params![pk.to_hex(), slot_id],
                |row| row.get(0),
            )
            .optional()
            .map_err(DBError::from)
    }

    /// Set the latest known version for the given slot_id/pk pair
    pub fn set_latest_chunk_version(
        &self,
        pk: &StacksPublicKey,
        slot_id: u32,
        slot_version: u32,
    ) -> Result<(), DBError> {
        self.db.execute(
            "INSERT OR REPLACE INTO stackerdb_tracking (public_key, slot_id, slot_version) VALUES (?, ?, ?)",
            params![pk.to_hex(), slot_id, slot_version],
        )?;
        Ok(())
    }

    /// Get the signer state for the provided reward cycle if it exists in the database
    pub fn get_encrypted_signer_state(
        &self,
        reward_cycle: u64,
    ) -> Result<Option<Vec<u8>>, DBError> {
        query_row(
            &self.db,
            "SELECT encrypted_state FROM signer_states WHERE reward_cycle = ?",
            [u64_to_sql(reward_cycle)?],
        )
    }

    /// Insert the given state in the `signer_states` table for the given reward cycle
    pub fn insert_encrypted_signer_state(
        &self,
        reward_cycle: u64,
        encrypted_signer_state: &[u8],
    ) -> Result<(), DBError> {
        self.db.execute(
            "INSERT OR REPLACE INTO signer_states (reward_cycle, encrypted_state) VALUES (?1, ?2)",
            params![u64_to_sql(reward_cycle)?, encrypted_signer_state],
        )?;
        Ok(())
    }

    /// Fetch a block from the database using the block's
    /// `signer_signature_hash`
    pub fn block_lookup(&self, hash: &Sha512Trunc256Sum) -> Result<Option<BlockInfo>, DBError> {
        let result: Option<String> = query_row(
            &self.db,
            "SELECT block_info FROM blocks WHERE signer_signature_hash = ?",
            params![hash.to_string()],
        )?;

        try_deserialize(result)
    }

    /// Return whether there was signed block in a tenure (identified by its consensus hash)
    pub fn has_signed_block_in_tenure(&self, tenure: &ConsensusHash) -> Result<bool, DBError> {
        let query =
            "SELECT block_info FROM blocks WHERE consensus_hash = ? AND signed_over = 1 LIMIT 1";
        let result: Option<String> = query_row(&self.db, query, [tenure])?;

        Ok(result.is_some())
    }

    /// Return the first signed block in a tenure (identified by its consensus hash)
    pub fn get_first_signed_block_in_tenure(
        &self,
        tenure: &ConsensusHash,
    ) -> Result<Option<BlockInfo>, DBError> {
        let query = "SELECT block_info FROM blocks WHERE consensus_hash = ? AND signed_over = 1 ORDER BY stacks_height ASC LIMIT 1";
        let result: Option<String> = query_row(&self.db, query, [tenure])?;

        try_deserialize(result)
    }

    /// Return the count of globally accepted blocks in a tenure (identified by its consensus hash)
    pub fn get_globally_accepted_block_count_in_tenure(
        &self,
        tenure: &ConsensusHash,
    ) -> Result<u64, DBError> {
        let query = "SELECT COALESCE((MAX(stacks_height) - MIN(stacks_height) + 1), 0) AS block_count FROM blocks WHERE consensus_hash = ?1 AND state = ?2";
        let args = params![tenure, &BlockState::GloballyAccepted.to_string()];
        let block_count_opt: Option<u64> = query_row(&self.db, query, args)?;
        match block_count_opt {
            Some(block_count) => Ok(block_count),
            None => Ok(0),
        }
    }

    /// Return the last accepted block in a tenure (identified by its consensus hash).
    pub fn get_last_accepted_block(
        &self,
        tenure: &ConsensusHash,
    ) -> Result<Option<BlockInfo>, DBError> {
        let query = "SELECT block_info FROM blocks WHERE consensus_hash = ?1 AND state IN (?2, ?3) ORDER BY stacks_height DESC LIMIT 1";
        let args = params![
            tenure,
            &BlockState::GloballyAccepted.to_string(),
            &BlockState::LocallyAccepted.to_string()
        ];
        let result: Option<String> = query_row(&self.db, query, args)?;

        try_deserialize(result)
    }

    /// Return the last globally accepted block in a tenure (identified by its consensus hash).
    pub fn get_last_globally_accepted_block(
        &self,
        tenure: &ConsensusHash,
    ) -> Result<Option<BlockInfo>, DBError> {
        let query = "SELECT block_info FROM blocks WHERE consensus_hash = ?1 AND state = ?2 ORDER BY stacks_height DESC LIMIT 1";
        let args = params![tenure, &BlockState::GloballyAccepted.to_string()];
        let result: Option<String> = query_row(&self.db, query, args)?;

        try_deserialize(result)
    }

    /// Return the last globally accepted block self_signed time in a given tenure (identified by its consensus hash).
    pub fn get_last_globally_accepted_block_signed_self(
        &self,
        tenure: &ConsensusHash,
    ) -> Result<Option<SystemTime>, DBError> {
        let query = r#"
            SELECT signed_self
            FROM blocks
            WHERE consensus_hash = ?1
            AND state = ?2
            AND signed_self IS NOT NULL
            ORDER BY burn_block_height DESC
            LIMIT 1;
        "#;
        let args = params![tenure, &BlockState::GloballyAccepted.to_string()];
        let result: Option<u64> = query_row(&self.db, query, args)?;
        Ok(result.map(|signed_self| UNIX_EPOCH + Duration::from_secs(signed_self)))
    }

    /// Return the canonical tip -- the last globally accepted block.
    pub fn get_canonical_tip(&self) -> Result<Option<BlockInfo>, DBError> {
        let query = "SELECT block_info FROM blocks WHERE state = ?1 ORDER BY stacks_height DESC, signed_group DESC LIMIT 1";
        let args = params![&BlockState::GloballyAccepted.to_string()];
        let result: Option<String> = query_row(&self.db, query, args)?;

        try_deserialize(result)
    }

    /// Insert or replace a burn block into the database
    pub fn insert_burn_block(
        &mut self,
        burn_hash: &BurnchainHeaderHash,
        consensus_hash: &ConsensusHash,
        burn_height: u64,
        received_time: &SystemTime,
        parent_burn_block_hash: &BurnchainHeaderHash,
    ) -> Result<(), DBError> {
        let received_ts = received_time
            .duration_since(std::time::UNIX_EPOCH)
            .map_err(|e| DBError::Other(format!("Bad system time: {e}")))?
            .as_secs();
        debug!("Inserting burn block info";
            "burn_block_height" => burn_height,
            "burn_hash" => %burn_hash,
            "received" => received_ts,
            "ch" => %consensus_hash,
            "parent_burn_block_hash" => %parent_burn_block_hash
        );
        self.db.execute(
            "INSERT OR REPLACE INTO burn_blocks (block_hash, consensus_hash, block_height, received_time, parent_burn_block_hash) VALUES (?1, ?2, ?3, ?4, ?5)",
            params![
                burn_hash,
                consensus_hash,
                u64_to_sql(burn_height)?,
                u64_to_sql(received_ts)?,
                parent_burn_block_hash,
            ],
        )?;
        Ok(())
    }

    /// Get timestamp (epoch seconds) at which a burn block was received over the event dispatcher by this signer
    /// if that burn block has been received.
    pub fn get_burn_block_receive_time(
        &self,
        burn_hash: &BurnchainHeaderHash,
    ) -> Result<Option<u64>, DBError> {
        let query = "SELECT received_time FROM burn_blocks WHERE block_hash = ? LIMIT 1";
        let Some(receive_time_i64) = query_row::<i64, _>(&self.db, query, &[burn_hash])? else {
            return Ok(None);
        };
        let receive_time = u64::try_from(receive_time_i64).map_err(|e| {
            error!("Failed to parse db received_time as u64: {e}");
            DBError::Corruption
        })?;
        Ok(Some(receive_time))
    }

    /// Get timestamp (epoch seconds) at which a burn block was received over the event dispatcher by this signer
    /// if that burn block has been received.
    pub fn get_burn_block_receive_time_ch(
        &self,
        ch: &ConsensusHash,
    ) -> Result<Option<u64>, DBError> {
        let query = "SELECT received_time FROM burn_blocks WHERE consensus_hash = ? LIMIT 1";
        let Some(receive_time_i64) = query_row::<i64, _>(&self.db, query, &[ch])? else {
            return Ok(None);
        };
        let receive_time = u64::try_from(receive_time_i64).map_err(|e| {
            error!("Failed to parse db received_time as u64: {e}");
            DBError::Corruption
        })?;
        Ok(Some(receive_time))
    }

    /// Lookup the burn block for a given burn block hash.
    pub fn get_burn_block_by_hash(
        &self,
        burn_block_hash: &BurnchainHeaderHash,
    ) -> Result<BurnBlockInfo, DBError> {
        let query =
            "SELECT block_hash, block_height, consensus_hash, parent_burn_block_hash FROM burn_blocks WHERE block_hash = ?";
        let args = params![burn_block_hash];

        query_row(&self.db, query, args)?.ok_or(DBError::NotFoundError)
    }

    /// Lookup the burn block for a given consensus hash.
    pub fn get_burn_block_by_ch(&self, ch: &ConsensusHash) -> Result<BurnBlockInfo, DBError> {
        let query = "SELECT block_hash, block_height, consensus_hash, parent_burn_block_hash FROM burn_blocks WHERE consensus_hash = ?";
        let args = params![ch];

        query_row(&self.db, query, args)?.ok_or(DBError::NotFoundError)
    }

    /// Insert or replace a block into the database.
    /// Preserves the `broadcast` column if replacing an existing block.
    pub fn insert_block(&mut self, block_info: &BlockInfo) -> Result<(), DBError> {
        let block_json =
            serde_json::to_string(&block_info).expect("Unable to serialize block info");
        let hash = &block_info.signer_signature_hash();
        let block_id = &block_info.block.block_id();
        let signed_over = block_info.signed_over;
        let vote = block_info
            .vote
            .as_ref()
            .map(|v| if v.rejected { "REJECT" } else { "ACCEPT" });
        let broadcasted = self.get_block_broadcasted(hash)?;
        debug!("Inserting block_info.";
            "reward_cycle" => %block_info.reward_cycle,
            "burn_block_height" => %block_info.burn_block_height,
            "signer_signature_hash" => %hash,
            "block_id" => %block_id,
            "signed" => %signed_over,
            "broadcasted" => ?broadcasted,
            "vote" => vote
        );
        self.db.execute("INSERT OR REPLACE INTO blocks (reward_cycle, burn_block_height, signer_signature_hash, block_info, signed_over, broadcasted, stacks_height, consensus_hash, valid, state, signed_group, signed_self, proposed_time, validation_time_ms, tenure_change) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12, ?13, ?14, ?15)", params![
            u64_to_sql(block_info.reward_cycle)?,
            u64_to_sql(block_info.burn_block_height)?,
            hash.to_string(),
            block_json,
            &block_info.signed_over,
            &broadcasted,
            u64_to_sql(block_info.block.header.chain_length)?,
            block_info.block.header.consensus_hash.to_hex(),
            &block_info.valid, &block_info.state.to_string(),
            &block_info.signed_group,
            &block_info.signed_self,
            &block_info.proposed_time,
            &block_info.validation_time_ms,
            &block_info.is_tenure_change()
        ])?;
        Ok(())
    }

    /// Determine if there are any unprocessed blocks
    pub fn has_unprocessed_blocks(&self, reward_cycle: u64) -> Result<bool, DBError> {
        let query = "SELECT block_info FROM blocks WHERE reward_cycle = ?1 AND state = ?2 LIMIT 1";
        let result: Option<String> = query_row(
            &self.db,
            query,
            params!(
                &u64_to_sql(reward_cycle)?,
                &BlockState::Unprocessed.to_string()
            ),
        )?;

        Ok(result.is_some())
    }

    /// Record an observed block signature
    pub fn add_block_signature(
        &self,
        block_sighash: &Sha512Trunc256Sum,
        signer_addr: &StacksAddress,
        signature: &MessageSignature,
    ) -> Result<bool, DBError> {
        // Remove any block rejection entry for this signer and block hash
        let del_qry = "DELETE FROM block_rejection_signer_addrs WHERE signer_signature_hash = ?1 AND signer_addr = ?2";
        let del_args = params![block_sighash, signer_addr.to_string()];
        self.db.execute(del_qry, del_args)?;

        // Insert the block signature
        let qry = "INSERT OR IGNORE INTO block_signatures (signer_signature_hash, signer_addr, signature) VALUES (?1, ?2, ?3);";
        let args = params![
            block_sighash,
            signer_addr.to_string(),
            serde_json::to_string(signature).map_err(DBError::SerializationError)?
        ];
        let rows_added = self.db.execute(qry, args)?;

        let is_new_signature = rows_added > 0;
        if is_new_signature {
            debug!("Added block signature.";
                "signer_signature_hash" => %block_sighash,
                "signer_address" => %signer_addr,
                "signature" => %signature
            );
        } else {
            debug!("Duplicate block signature.";
                "signer_signature_hash" => %block_sighash,
                "signer_address" => %signer_addr,
                "signature" => %signature
            );
        }
        Ok(is_new_signature)
    }

    /// Get all signatures for a block
    pub fn get_block_signatures(
        &self,
        block_sighash: &Sha512Trunc256Sum,
    ) -> Result<Vec<MessageSignature>, DBError> {
        let qry = "SELECT signature FROM block_signatures WHERE signer_signature_hash = ?1";
        let args = params![block_sighash];
        let sigs_txt: Vec<String> = query_rows(&self.db, qry, args)?;
        sigs_txt
            .into_iter()
            .map(|sig_txt| serde_json::from_str(&sig_txt).map_err(|_| DBError::ParseError))
            .collect()
    }

    /// Record an observed block rejection_signature
    pub fn add_block_rejection_signer_addr(
        &self,
        block_sighash: &Sha512Trunc256Sum,
        addr: &StacksAddress,
        reject_reason: &RejectReason,
    ) -> Result<bool, DBError> {
        // If this signer/block already has a signature, do not allow a rejection
        let sig_qry = "SELECT EXISTS(SELECT 1 FROM block_signatures WHERE signer_signature_hash = ?1 AND signer_addr = ?2)";
        let sig_args = params![block_sighash, addr.to_string()];
        let exists = self.db.query_row(sig_qry, sig_args, |row| row.get(0))?;
        if exists {
            warn!("Cannot add block rejection because a signature already exists.";
                "signer_signature_hash" => %block_sighash,
                "signer_address" => %addr,
                "reject_reason" => %reject_reason
            );
            return Ok(false);
        }

        // Check if a row exists for this sighash/signer combo
        let qry = "SELECT reject_code FROM block_rejection_signer_addrs WHERE signer_signature_hash = ?1 AND signer_addr = ?2 LIMIT 1";
        let args = params![block_sighash, addr.to_string()];
        let existing_code: Option<i64> =
            self.db.query_row(qry, args, |row| row.get(0)).optional()?;

        let reject_code = RejectReasonPrefix::from(reject_reason) as i64;

        match existing_code {
            Some(code) if code == reject_code => {
                // Row exists with same reject_reason, do nothing
                debug!("Duplicate block rejection.";
                    "signer_signature_hash" => %block_sighash,
                    "signer_address" => %addr,
                    "reject_reason" => %reject_reason
                );
                Ok(false)
            }
            Some(_) => {
                // Row exists but with different reject_reason, update it
                let update_qry = "UPDATE block_rejection_signer_addrs SET reject_code = ?1 WHERE signer_signature_hash = ?2 AND signer_addr = ?3";
                let update_args = params![reject_code, block_sighash, addr.to_string()];
                self.db.execute(update_qry, update_args)?;
                debug!("Updated block rejection reason.";
                    "signer_signature_hash" => %block_sighash,
                    "signer_address" => %addr,
                    "reject_reason" => %reject_reason
                );
                Ok(true)
            }
            None => {
                // Row does not exist, insert it
                let insert_qry = "INSERT INTO block_rejection_signer_addrs (signer_signature_hash, signer_addr, reject_code) VALUES (?1, ?2, ?3)";
                let insert_args = params![block_sighash, addr.to_string(), reject_code];
                self.db.execute(insert_qry, insert_args)?;
                debug!("Inserted block rejection.";
                    "signer_signature_hash" => %block_sighash,
                    "signer_address" => %addr,
                    "reject_reason" => %reject_reason
                );
                Ok(true)
            }
        }
    }

    /// Get all signer addresses that rejected the block (and their reject codes)
    pub fn get_block_rejection_signer_addrs(
        &self,
        block_sighash: &Sha512Trunc256Sum,
    ) -> Result<Vec<(StacksAddress, RejectReasonPrefix)>, DBError> {
        let qry =
            "SELECT signer_addr, reject_code FROM block_rejection_signer_addrs WHERE signer_signature_hash = ?1";
        let args = params![block_sighash];
        let mut stmt = self.db.prepare(qry)?;

        let rows = stmt.query_map(args, |row| {
            let addr: String = row.get(0)?;
            let addr = StacksAddress::from_string(&addr).ok_or(SqliteError::InvalidColumnType(
                0,
                "signer_addr".into(),
                rusqlite::types::Type::Text,
            ))?;
            let reject_code: i64 = row.get(1)?;

            let reject_code = u8::try_from(reject_code)
                .map_err(|_| {
                    SqliteError::InvalidColumnType(
                        1,
                        "reject_code".into(),
                        rusqlite::types::Type::Integer,
                    )
                })
                .map(RejectReasonPrefix::from)?;

            Ok((addr, reject_code))
        })?;

        rows.collect::<Result<Vec<_>, _>>().map_err(|e| e.into())
    }

    /// Mark a block as having been broadcasted and therefore GloballyAccepted
    pub fn set_block_broadcasted(
        &self,
        block_sighash: &Sha512Trunc256Sum,
        ts: u64,
    ) -> Result<(), DBError> {
        let qry = "UPDATE blocks SET broadcasted = ?1 WHERE signer_signature_hash = ?2";
        let args = params![u64_to_sql(ts)?, block_sighash];

        debug!("Marking block {} as broadcasted at {}", block_sighash, ts);
        self.db.execute(qry, args)?;
        Ok(())
    }

    /// Get the timestamp at which the block was broadcasted.
    pub fn get_block_broadcasted(
        &self,
        block_sighash: &Sha512Trunc256Sum,
    ) -> Result<Option<u64>, DBError> {
        let qry =
            "SELECT IFNULL(broadcasted,0) AS broadcasted FROM blocks WHERE signer_signature_hash = ?";
        let args = params![block_sighash];

        let Some(broadcasted): Option<u64> = query_row(&self.db, qry, args)? else {
            return Ok(None);
        };
        if broadcasted == 0 {
            return Ok(None);
        }
        Ok(Some(broadcasted))
    }

    /// Get a pending block validation, sorted by the time at which it was added to the pending table.
    /// If found, remove it from the pending table.
    pub fn get_and_remove_pending_block_validation(
        &self,
    ) -> Result<Option<(Sha512Trunc256Sum, u64)>, DBError> {
        let qry = "DELETE FROM block_validations_pending WHERE signer_signature_hash = (SELECT signer_signature_hash FROM block_validations_pending ORDER BY added_time ASC LIMIT 1) RETURNING signer_signature_hash, added_time";
        let args = params![];
        let mut stmt = self.db.prepare(qry)?;
        let result: Option<(String, i64)> = stmt
            .query_row(args, |row| Ok((row.get(0)?, row.get(1)?)))
            .optional()?;
        Ok(result.and_then(|(sighash, ts_i64)| {
            let signer_sighash = Sha512Trunc256Sum::from_hex(&sighash).ok()?;
            let ts = u64::try_from(ts_i64).ok()?;
            Some((signer_sighash, ts))
        }))
    }

    /// Remove a pending block validation
    pub fn remove_pending_block_validation(
        &self,
        sighash: &Sha512Trunc256Sum,
    ) -> Result<(), DBError> {
        self.db.execute(
            "DELETE FROM block_validations_pending WHERE signer_signature_hash = ?1",
            params![sighash.to_string()],
        )?;
        Ok(())
    }

    /// Insert a pending block validation
    pub fn insert_pending_block_validation(
        &self,
        sighash: &Sha512Trunc256Sum,
        ts: u64,
    ) -> Result<(), DBError> {
        self.db.execute(
            "INSERT INTO block_validations_pending (signer_signature_hash, added_time) VALUES (?1, ?2)",
            params![sighash.to_string(), u64_to_sql(ts)?],
        )?;
        Ok(())
    }

    /// Return the start time (epoch time in seconds) and the processing time in milliseconds of the tenure (idenfitied by consensus_hash).
    fn get_tenure_times(&self, tenure: &ConsensusHash) -> Result<(u64, u64), DBError> {
        let query = "SELECT tenure_change, proposed_time, validation_time_ms FROM blocks WHERE consensus_hash = ?1 AND state = ?2 ORDER BY stacks_height DESC";
        let args = params![tenure, BlockState::GloballyAccepted.to_string()];
        let mut stmt = self.db.prepare(query)?;
        let rows = stmt.query_map(args, |row| {
            let tenure_change_block: bool = row.get(0)?;
            let proposed_time: u64 = row.get(1)?;
            let validation_time_ms: Option<u64> = row.get(2)?;
            Ok((tenure_change_block, proposed_time, validation_time_ms))
        })?;
        let mut tenure_processing_time_ms = 0_u64;
        let mut tenure_start_time = None;
        let mut nmb_rows = 0;
        for (i, row) in rows.enumerate() {
            nmb_rows += 1;
            let (tenure_change_block, proposed_time, validation_time_ms) = row?;
            tenure_processing_time_ms =
                tenure_processing_time_ms.saturating_add(validation_time_ms.unwrap_or(0));
            tenure_start_time = Some(proposed_time);
            if tenure_change_block {
                debug!("Found tenure change block {i} blocks ago in tenure {tenure}");
                break;
            }
        }
        debug!("Calculated tenure extend timestamp from {nmb_rows} blocks in tenure {tenure}");
        Ok((
            tenure_start_time.unwrap_or(get_epoch_time_secs()),
            tenure_processing_time_ms,
        ))
    }

    /// Calculate the tenure extend timestamp. If determine the timestamp for a block rejection, check_tenure_extend should be set to false to avoid recalculating
    /// the tenure extend timestamp for a tenure extend block.
    pub fn calculate_tenure_extend_timestamp(
        &self,
        tenure_idle_timeout: Duration,
        block: &NakamotoBlock,
        check_tenure_extend: bool,
    ) -> u64 {
        if check_tenure_extend && block.get_tenure_tx_payload().is_some() {
            let tenure_extend_timestamp =
                get_epoch_time_secs().wrapping_add(tenure_idle_timeout.as_secs());
            debug!("Calculated tenure extend timestamp for a tenure extend block. Rolling over timestamp: {tenure_extend_timestamp}");
            return tenure_extend_timestamp;
        }
        let tenure_idle_timeout_secs = tenure_idle_timeout.as_secs();
        let (tenure_start_time, tenure_process_time_ms) = self.get_tenure_times(&block.header.consensus_hash).inspect_err(|e| error!("Error occurred calculating tenure extend timestamp: {e:?}. Defaulting to {tenure_idle_timeout_secs} from now.")).unwrap_or((get_epoch_time_secs(), 0));
        // Plus (ms + 999)/1000 to round up to the nearest second
        let tenure_extend_timestamp = tenure_start_time
            .saturating_add(tenure_idle_timeout_secs)
            .saturating_add(tenure_process_time_ms.div_ceil(1000));
        debug!("Calculated tenure extend timestamp";
            "tenure_extend_timestamp" => tenure_extend_timestamp,
            "tenure_start_time" => tenure_start_time,
            "tenure_process_time_ms" => tenure_process_time_ms,
            "tenure_idle_timeout_secs" => tenure_idle_timeout_secs,
            "tenure_extend_in" => tenure_extend_timestamp.saturating_sub(get_epoch_time_secs()),
            "consensus_hash" => %block.header.consensus_hash,
        );
        tenure_extend_timestamp
    }

    /// Mark a block as globally accepted. This removes the block from the pending
    /// validations table. This does **not** update the block's state in SignerDb.
    pub fn mark_block_globally_accepted(&self, block_info: &mut BlockInfo) -> Result<(), DBError> {
        block_info
            .mark_globally_accepted()
            .map_err(DBError::Other)?;
        self.remove_pending_block_validation(&block_info.signer_signature_hash())?;
        Ok(())
    }

    /// Mark a block as globally rejected. This removes the block from the pending
    /// validations table. This does **not** update the block's state in SignerDb.
    pub fn mark_block_globally_rejected(&self, block_info: &mut BlockInfo) -> Result<(), DBError> {
        block_info
            .mark_globally_rejected()
            .map_err(DBError::Other)?;
        self.remove_pending_block_validation(&block_info.signer_signature_hash())?;
        Ok(())
    }
    /// Update the tenure (identified by consensus_hash) last activity timestamp
    pub fn update_last_activity_time(
        &mut self,
        tenure: &ConsensusHash,
        last_activity_time: u64,
    ) -> Result<(), DBError> {
        debug!("Updating last activity for tenure"; "consensus_hash" => %tenure, "last_activity_time" => last_activity_time);
        self.db.execute("INSERT OR REPLACE INTO tenure_activity (consensus_hash, last_activity_time) VALUES (?1, ?2)", params![tenure, u64_to_sql(last_activity_time)?])?;
        Ok(())
    }

    /// Get the last activity timestamp for a tenure (identified by consensus_hash)
    pub fn get_last_activity_time(&self, tenure: &ConsensusHash) -> Result<Option<u64>, DBError> {
        let query =
            "SELECT last_activity_time FROM tenure_activity WHERE consensus_hash = ? LIMIT 1";
        let Some(last_activity_time_i64) = query_row::<i64, _>(&self.db, query, &[tenure])? else {
            return Ok(None);
        };
        let last_activity_time = u64::try_from(last_activity_time_i64).map_err(|e| {
            error!("Failed to parse db last_activity_time as u64: {e}");
            DBError::Corruption
        })?;
        Ok(Some(last_activity_time))
    }

    /// Insert the signer state machine update
    pub fn insert_state_machine_update(
        &mut self,
        reward_cycle: u64,
        address: &StacksAddress,
        update: &StateMachineUpdate,
        received_time: &SystemTime,
    ) -> Result<(), DBError> {
        let received_ts = received_time
            .duration_since(std::time::UNIX_EPOCH)
            .map_err(|e| DBError::Other(format!("Bad system time: {e}")))?
            .as_secs();
        let update_str =
            serde_json::to_string(&update).expect("Unable to serialize state machine update");
        debug!("Inserting update.";
            "reward_cycle" => reward_cycle,
            "address" => %address,
            "active_signer_protocol_version" => update.active_signer_protocol_version,
            "local_supported_signer_protocol_version" => update.local_supported_signer_protocol_version
        );
        self.db.execute("INSERT OR REPLACE INTO signer_state_machine_updates (signer_addr, reward_cycle, state_update, received_time) VALUES (?1, ?2, ?3, ?4)", params![
            address.to_string(),
            u64_to_sql(reward_cycle)?,
            update_str,
            u64_to_sql(received_ts)?,
        ])?;

        // Conditionally insert into burn_block_updates_received_times only if missing for (signer_addr, burn_block_consensus_hash)
        let burn_block_consensus_hash = update.content.burn_block_view().0;
        self.db.execute(
            "INSERT OR IGNORE INTO burn_block_updates_received_times
            (signer_addr, burn_block_consensus_hash, received_time)
            VALUES (?1, ?2, ?3)",
            params![
                address.to_string(),
                burn_block_consensus_hash,
                u64_to_sql(received_ts)?,
            ],
        )?;
        Ok(())
    }

    #[cfg(any(test, feature = "testing"))]
    /// Clear out signer state machine updates for testing purposes ONLY.
    pub fn clear_state_machine_updates(&mut self) -> Result<(), DBError> {
        debug!("Clearing all updates.");
        self.db
            .execute("DELETE FROM signer_state_machine_updates", params![])?;
        Ok(())
    }

    /// Get the most recent signer states from the signer state machine for the given reward cycle
    pub fn get_signer_state_machine_updates(
        &mut self,
        reward_cycle: u64,
    ) -> Result<HashMap<StacksAddress, StateMachineUpdate>, DBError> {
        let query = r#"
            SELECT signer_addr, state_update
            FROM signer_state_machine_updates
            WHERE reward_cycle = ?1;
        "#;
        let args = params![u64_to_sql(reward_cycle)?];
        let mut stmt = self.db.prepare(query)?;
        let rows = stmt.query_map(args, |row| {
            let address_str: String = row.get(0)?;
            let update_str: String = row.get(1)?;
            Ok((address_str, update_str))
        })?;
        let mut result = HashMap::new();
        for row in rows {
            let (address_str, update_str) = row?;
            let address = StacksAddress::from_string(&address_str).ok_or(DBError::Corruption)?;
            let update: StateMachineUpdate = serde_json::from_str(&update_str)?;
            result.insert(address, update);
        }
        Ok(result)
    }

    /// Insert a block validated by a replay tx
    pub fn insert_block_validated_by_replay_tx(
        &self,
        signer_signature_hash: &Sha512Trunc256Sum,
        replay_tx_hash: u64,
        replay_tx_exhausted: bool,
    ) -> Result<(), DBError> {
        self.db.execute(
            "INSERT INTO block_validated_by_replay_txs (signer_signature_hash, replay_tx_hash, replay_tx_exhausted) VALUES (?1, ?2, ?3)",
            params![
                signer_signature_hash.to_string(),
                format!("{replay_tx_hash}"),
                replay_tx_exhausted
            ],
        )?;
        Ok(())
    }

    /// Get the replay tx hash for a block validation
    pub fn get_was_block_validated_by_replay_tx(
        &self,
        signer_signature_hash: &Sha512Trunc256Sum,
        replay_tx_hash: u64,
    ) -> Result<Option<BlockValidatedByReplaySet>, DBError> {
        let query = "SELECT replay_tx_hash, replay_tx_exhausted FROM block_validated_by_replay_txs WHERE signer_signature_hash = ? AND replay_tx_hash = ?";
        let args = params![
            signer_signature_hash.to_string(),
            format!("{replay_tx_hash}")
        ];
        query_row(&self.db, query, args)
    }

    /// Get the earliest received time at which the signer state update achieved
    /// a global burn view identified by the provided ConsensusHash
    pub fn get_burn_block_received_time_from_signers(
        &self,
        eval: &GlobalStateEvaluator,
        ch: &ConsensusHash,
        local_address: &StacksAddress,
    ) -> Result<Option<u64>, DBError> {
        let mut entries = Vec::new();

        // Add our own vote if we received this consensus hash
        if let Some(local_received_time) = self.get_burn_block_receive_time_ch(ch)? {
            entries.push((local_address.clone(), local_received_time));
        }

        // Query other signer received times from the DB
        let query = r#"
            SELECT signer_addr, received_time
            FROM burn_block_updates_received_times
            WHERE burn_block_consensus_hash = ?1
        "#;

        let mut stmt = self.db.prepare(query)?;
        let rows = stmt.query_map(params![ch], |row| {
            let signer_addr: String = row.get(0)?;
            let received_time: i64 = row.get(1)?;
            Ok((signer_addr, received_time))
        })?;
        for row in rows {
            let (signer_addr_str, received_time_i64) = row?;
            let address =
                StacksAddress::from_string(&signer_addr_str).ok_or(DBError::Corruption)?;

            let received_time = u64::try_from(received_time_i64).map_err(|e| {
                error!("Failed to convert received_time to u64: {e}");
                DBError::Corruption
            })?;

            entries.push((address, received_time));
        }

        // Sort by received_time ascending
        entries.sort_by_key(|(_, time)| *time);

        // Accumulate vote weight and stop when threshold is reached
        let mut vote_weight: u32 = 0;
        for (address, received_time) in entries {
            let weight = eval.address_weights.get(&address).copied().unwrap_or(0);
            vote_weight = vote_weight.saturating_add(weight);

            if eval.reached_agreement(vote_weight) {
                return Ok(Some(received_time));
            }
        }

        Ok(None)
    }
}

fn try_deserialize<T>(s: Option<String>) -> Result<Option<T>, DBError>
where
    T: serde::de::DeserializeOwned,
{
    s.as_deref()
        .map(serde_json::from_str)
        .transpose()
        .map_err(DBError::SerializationError)
}

/// For tests, a struct to represent a pending block validation
#[cfg(any(test, feature = "testing"))]
pub struct PendingBlockValidation {
    /// The signer signature hash of the block
    pub signer_signature_hash: Sha512Trunc256Sum,
    /// The time at which the block was added to the pending table
    pub added_time: u64,
}

#[cfg(any(test, feature = "testing"))]
impl FromRow<PendingBlockValidation> for PendingBlockValidation {
    fn from_row(row: &rusqlite::Row) -> Result<Self, DBError> {
        let signer_signature_hash = Sha512Trunc256Sum::from_column(row, "signer_signature_hash")?;
        let added_time = row.get_unwrap(1);
        Ok(PendingBlockValidation {
            signer_signature_hash,
            added_time,
        })
    }
}

/// A struct used to represent whether a block was validated by a transaction replay set
pub struct BlockValidatedByReplaySet {
    /// The hash of the transaction replay set that validated the block
    pub replay_tx_hash: String,
    /// Whether the transaction replay set exhausted the set of transactions
    pub replay_tx_exhausted: bool,
}

impl FromRow<BlockValidatedByReplaySet> for BlockValidatedByReplaySet {
    fn from_row(row: &rusqlite::Row) -> Result<Self, DBError> {
        let replay_tx_hash = row.get_unwrap(0);
        let replay_tx_exhausted = row.get_unwrap(1);
        Ok(BlockValidatedByReplaySet {
            replay_tx_hash,
            replay_tx_exhausted,
        })
    }
}

#[cfg(any(test, feature = "testing"))]
impl SignerDb {
    /// For tests, fetch all pending block validations
    pub fn get_all_pending_block_validations(
        &self,
    ) -> Result<Vec<PendingBlockValidation>, DBError> {
        let qry = "SELECT signer_signature_hash, added_time FROM block_validations_pending ORDER BY added_time ASC";
        query_rows(&self.db, qry, params![])
    }

    /// For tests, check if a pending block validation exists
    pub fn has_pending_block_validation(
        &self,
        sighash: &Sha512Trunc256Sum,
    ) -> Result<bool, DBError> {
        let qry = "SELECT signer_signature_hash FROM block_validations_pending WHERE signer_signature_hash = ?1";
        let args = params![sighash.to_string()];
        let sighash_opt: Option<String> = query_row(&self.db, qry, args)?;
        Ok(sighash_opt.is_some())
    }
}

/// Tests for SignerDb
#[cfg(test)]
pub mod tests {
    use std::fs;
    use std::path::PathBuf;

    use blockstack_lib::chainstate::nakamoto::{NakamotoBlock, NakamotoBlockHeader};
    use blockstack_lib::chainstate::stacks::{
        StacksTransaction, TenureChangeCause, TenureChangePayload, TransactionAuth,
        TransactionVersion,
    };
    use clarity::types::chainstate::{StacksBlockId, StacksPrivateKey, StacksPublicKey};
    use clarity::util::hash::Hash160;
    use clarity::util::secp256k1::MessageSignature;
    use libsigner::v0::messages::{StateMachineUpdateContent, StateMachineUpdateMinerState};
    use libsigner::{BlockProposal, BlockProposalData};

    use super::*;
    use crate::signerdb::NakamotoBlockVote;

    fn _wipe_db(db_path: &PathBuf) {
        if fs::metadata(db_path).is_ok() {
            fs::remove_file(db_path).unwrap();
        }
    }

    /// Override the creation of a block from a block proposal with the provided function
    pub fn create_block_override(
        overrides: impl FnOnce(&mut BlockProposal),
    ) -> (BlockInfo, BlockProposal) {
        let header = NakamotoBlockHeader::empty();
        let block = NakamotoBlock {
            header,
            txs: vec![],
        };
        let mut block_proposal = BlockProposal {
            block,
            burn_height: 7,
            reward_cycle: 42,
            block_proposal_data: BlockProposalData::empty(),
        };
        overrides(&mut block_proposal);
        (BlockInfo::from(block_proposal.clone()), block_proposal)
    }

    fn create_block() -> (BlockInfo, BlockProposal) {
        create_block_override(|_| {})
    }

    /// Create a temporary db path for testing purposes
    pub fn tmp_db_path() -> PathBuf {
        std::env::temp_dir().join(format!(
            "stacks-signer-test-{}.sqlite",
            rand::random::<u64>()
        ))
    }

    fn test_basic_signer_db_with_path(db_path: impl AsRef<Path>) {
        let mut db = SignerDb::new(db_path).expect("Failed to create signer db");
        let (block_info_1, block_proposal_1) = create_block_override(|b| {
            b.block.header.consensus_hash = ConsensusHash([0x01; 20]);
        });
        let (block_info_2, block_proposal_2) = create_block_override(|b| {
            b.block.header.consensus_hash = ConsensusHash([0x02; 20]);
        });
        db.insert_block(&block_info_1)
            .expect("Unable to insert block into db");
        let block_info = db
            .block_lookup(&block_proposal_1.block.header.signer_signature_hash())
            .unwrap()
            .expect("Unable to get block from db");

        assert_eq!(BlockInfo::from(block_proposal_1), block_info);

        // Test looking up a block with an unknown hash
        let block_info = db
            .block_lookup(&block_proposal_2.block.header.signer_signature_hash())
            .unwrap();
        assert!(block_info.is_none());

        db.insert_block(&block_info_2)
            .expect("Unable to insert block into db");
        let block_info = db
            .block_lookup(&block_proposal_2.block.header.signer_signature_hash())
            .unwrap()
            .expect("Unable to get block from db");

        assert_eq!(BlockInfo::from(block_proposal_2), block_info);
    }

    #[test]
    fn test_basic_signer_db() {
        let db_path = tmp_db_path();
        eprintln!("db path is {}", &db_path.display());
        test_basic_signer_db_with_path(db_path)
    }

    #[test]
    fn test_basic_signer_db_in_memory() {
        test_basic_signer_db_with_path(":memory:")
    }

    #[test]
    fn test_update_block() {
        let db_path = tmp_db_path();
        let mut db = SignerDb::new(db_path).expect("Failed to create signer db");
        let (block_info, block_proposal) = create_block();
        db.insert_block(&block_info)
            .expect("Unable to insert block into db");

        let block_info = db
            .block_lookup(&block_proposal.block.header.signer_signature_hash())
            .unwrap()
            .expect("Unable to get block from db");

        assert_eq!(BlockInfo::from(block_proposal.clone()), block_info);

        let old_block_info = block_info;
        let old_block_proposal = block_proposal;

        let (mut block_info, block_proposal) = create_block_override(|b| {
            b.block.header.signer_signature =
                old_block_proposal.block.header.signer_signature.clone();
        });
        assert_eq!(
            block_info.signer_signature_hash(),
            old_block_info.signer_signature_hash()
        );
        let vote = NakamotoBlockVote {
            signer_signature_hash: Sha512Trunc256Sum([0x01; 32]),
            rejected: false,
        };
        block_info.vote = Some(vote.clone());
        db.insert_block(&block_info)
            .expect("Unable to insert block into db");

        let block_info = db
            .block_lookup(&block_proposal.block.header.signer_signature_hash())
            .unwrap()
            .expect("Unable to get block from db");

        assert_ne!(old_block_info, block_info);
        assert_eq!(block_info.vote, Some(vote));
    }

    #[test]
    fn get_first_signed_block() {
        let db_path = tmp_db_path();
        let mut db = SignerDb::new(db_path).expect("Failed to create signer db");
        let (mut block_info, block_proposal) = create_block();
        db.insert_block(&block_info).unwrap();

        assert!(db
            .get_first_signed_block_in_tenure(&block_proposal.block.header.consensus_hash)
            .unwrap()
            .is_none());

        block_info
            .mark_locally_accepted(false)
            .expect("Failed to mark block as locally accepted");
        db.insert_block(&block_info).unwrap();

        let fetched_info = db
            .get_first_signed_block_in_tenure(&block_proposal.block.header.consensus_hash)
            .unwrap()
            .unwrap();
        assert_eq!(fetched_info, block_info);
    }

    #[test]
    fn insert_burn_block_get_time() {
        let db_path = tmp_db_path();
        let mut db = SignerDb::new(db_path).expect("Failed to create signer db");
        let test_burn_hash = BurnchainHeaderHash([10; 32]);
        let test_consensus_hash = ConsensusHash([13; 20]);
        let stime = SystemTime::now();
        let time_to_epoch = stime
            .duration_since(SystemTime::UNIX_EPOCH)
            .unwrap()
            .as_secs();
        db.insert_burn_block(
            &test_burn_hash,
            &test_consensus_hash,
            10,
            &stime,
            &test_burn_hash,
        )
        .unwrap();

        let stored_time = db
            .get_burn_block_receive_time(&test_burn_hash)
            .unwrap()
            .unwrap();
        assert_eq!(stored_time, time_to_epoch);
    }

    #[test]
    fn test_write_signer_state() {
        let db_path = tmp_db_path();
        let db = SignerDb::new(db_path).expect("Failed to create signer db");
        let state_0 = vec![0];
        let state_1 = vec![1; 1024];

        db.insert_encrypted_signer_state(10, &state_0)
            .expect("Failed to insert signer state");

        db.insert_encrypted_signer_state(11, &state_1)
            .expect("Failed to insert signer state");

        assert_eq!(
            db.get_encrypted_signer_state(10)
                .expect("Failed to get signer state")
                .unwrap(),
            state_0
        );
        assert_eq!(
            db.get_encrypted_signer_state(11)
                .expect("Failed to get signer state")
                .unwrap(),
            state_1
        );
        assert!(db
            .get_encrypted_signer_state(12)
            .expect("Failed to get signer state")
            .is_none());
        assert!(db
            .get_encrypted_signer_state(9)
            .expect("Failed to get signer state")
            .is_none());
    }

    #[test]
    fn test_has_unprocessed_blocks() {
        let db_path = tmp_db_path();
        let mut db = SignerDb::new(db_path).expect("Failed to create signer db");
        let (mut block_info_1, _block_proposal) = create_block_override(|b| {
            b.block.header.miner_signature = MessageSignature([0x01; 65]);
            b.burn_height = 1;
        });
        let (mut block_info_2, _block_proposal) = create_block_override(|b| {
            b.block.header.miner_signature = MessageSignature([0x02; 65]);
            b.burn_height = 2;
        });

        db.insert_block(&block_info_1)
            .expect("Unable to insert block into db");
        db.insert_block(&block_info_2)
            .expect("Unable to insert block into db");

        assert!(db
            .has_unprocessed_blocks(block_info_1.reward_cycle)
            .unwrap());

        block_info_1.state = BlockState::LocallyRejected;

        db.insert_block(&block_info_1)
            .expect("Unable to update block in db");

        assert!(db
            .has_unprocessed_blocks(block_info_1.reward_cycle)
            .unwrap());

        block_info_2.state = BlockState::LocallyAccepted;

        db.insert_block(&block_info_2)
            .expect("Unable to update block in db");

        assert!(!db
            .has_unprocessed_blocks(block_info_1.reward_cycle)
            .unwrap());
    }

    #[test]
    fn test_sqlite_version() {
        let db_path = tmp_db_path();
        let db = SignerDb::new(db_path).expect("Failed to create signer db");
        assert_eq!(
            query_row(&db.db, "SELECT sqlite_version()", []).unwrap(),
            Some("3.45.0".to_string())
        );
    }

    #[test]
    fn add_and_get_block_signatures() {
        let db_path = tmp_db_path();
        let db = SignerDb::new(db_path).expect("Failed to create signer db");

        let block_id = Sha512Trunc256Sum::from_data("foo".as_bytes());
        let address1 = StacksAddress::burn_address(false);
        let address2 = StacksAddress::burn_address(true);
        let sig1 = MessageSignature([0x11; 65]);
        let sig2 = MessageSignature([0x22; 65]);

        assert_eq!(db.get_block_signatures(&block_id).unwrap(), vec![]);

        db.add_block_signature(&block_id, &address1, &sig1).unwrap();
        assert_eq!(db.get_block_signatures(&block_id).unwrap(), vec![sig1]);

        db.add_block_signature(&block_id, &address2, &sig2).unwrap();
        assert_eq!(
            db.get_block_signatures(&block_id).unwrap(),
            vec![sig2, sig1]
        );
    }

    #[test]
    fn duplicate_block_signatures() {
        let db_path = tmp_db_path();
        let db = SignerDb::new(db_path).expect("Failed to create signer db");

        let block_id = Sha512Trunc256Sum::from_data("foo".as_bytes());
        let address = StacksAddress::burn_address(false);
        let sig1 = MessageSignature([0x11; 65]);
        let sig2 = MessageSignature([0x22; 65]);

        assert_eq!(db.get_block_signatures(&block_id).unwrap(), vec![]);

        assert!(db.add_block_signature(&block_id, &address, &sig1).unwrap());
        assert_eq!(db.get_block_signatures(&block_id).unwrap(), vec![sig1]);

        assert!(!db.add_block_signature(&block_id, &address, &sig2).unwrap());
        assert_eq!(db.get_block_signatures(&block_id).unwrap(), vec![sig1]);
    }

    #[test]
    fn add_and_get_block_rejections() {
        let db_path = tmp_db_path();
        let db = SignerDb::new(db_path).expect("Failed to create signer db");

        let block_id = Sha512Trunc256Sum::from_data("foo".as_bytes());
        let address1 = StacksAddress::burn_address(false);
        let address2 = StacksAddress::burn_address(true);

        assert_eq!(
            db.get_block_rejection_signer_addrs(&block_id).unwrap(),
            vec![]
        );

        assert!(db
            .add_block_rejection_signer_addr(
                &block_id,
                &address1,
                &RejectReason::DuplicateBlockFound,
            )
            .unwrap());
        assert_eq!(
            db.get_block_rejection_signer_addrs(&block_id).unwrap(),
            vec![(address1.clone(), RejectReasonPrefix::DuplicateBlockFound)]
        );

        assert!(db
            .add_block_rejection_signer_addr(
                &block_id,
                &address2,
                &RejectReason::InvalidParentBlock
            )
            .unwrap());
        assert_eq!(
            db.get_block_rejection_signer_addrs(&block_id).unwrap(),
            vec![
                (address2, RejectReasonPrefix::InvalidParentBlock),
                (address1, RejectReasonPrefix::DuplicateBlockFound),
            ]
        );
    }

    #[test]
    fn duplicate_block_rejections() {
        let db_path = tmp_db_path();
        let db = SignerDb::new(db_path).expect("Failed to create signer db");

        let block_id = Sha512Trunc256Sum::from_data("foo".as_bytes());
        let address = StacksAddress::burn_address(false);

        assert_eq!(
            db.get_block_rejection_signer_addrs(&block_id).unwrap(),
            vec![]
        );

        assert!(db
            .add_block_rejection_signer_addr(&block_id, &address, &RejectReason::InvalidParentBlock)
            .unwrap());
        assert_eq!(
            db.get_block_rejection_signer_addrs(&block_id).unwrap(),
            vec![(address.clone(), RejectReasonPrefix::InvalidParentBlock)]
        );

        assert!(db
            .add_block_rejection_signer_addr(&block_id, &address, &RejectReason::InvalidMiner)
            .unwrap());
        assert_eq!(
            db.get_block_rejection_signer_addrs(&block_id).unwrap(),
            vec![(address.clone(), RejectReasonPrefix::InvalidMiner)]
        );

        assert!(!db
            .add_block_rejection_signer_addr(&block_id, &address, &RejectReason::InvalidMiner)
            .unwrap());
        assert_eq!(
            db.get_block_rejection_signer_addrs(&block_id).unwrap(),
            vec![(address, RejectReasonPrefix::InvalidMiner)]
        );
    }

    #[test]
    fn reject_then_accept() {
        let db_path = tmp_db_path();
        let db = SignerDb::new(db_path).expect("Failed to create signer db");

        let block_id = Sha512Trunc256Sum::from_data("foo".as_bytes());
        let address = StacksAddress::burn_address(false);
        let sig1 = MessageSignature([0x11; 65]);

        assert_eq!(db.get_block_signatures(&block_id).unwrap(), vec![]);

        assert!(db
            .add_block_rejection_signer_addr(&block_id, &address, &RejectReason::InvalidParentBlock)
            .unwrap());
        assert_eq!(
            db.get_block_rejection_signer_addrs(&block_id).unwrap(),
            vec![(address.clone(), RejectReasonPrefix::InvalidParentBlock)]
        );

        assert!(db.add_block_signature(&block_id, &address, &sig1).unwrap());
        assert_eq!(db.get_block_signatures(&block_id).unwrap(), vec![sig1]);
        assert!(db
            .get_block_rejection_signer_addrs(&block_id)
            .unwrap()
            .is_empty());
    }

    #[test]
    fn accept_then_reject() {
        let db_path = tmp_db_path();
        let db = SignerDb::new(db_path).expect("Failed to create signer db");

        let block_id = Sha512Trunc256Sum::from_data("foo".as_bytes());
        let address = StacksAddress::burn_address(false);
        let sig1 = MessageSignature([0x11; 65]);

        assert_eq!(db.get_block_signatures(&block_id).unwrap(), vec![]);

        assert!(db.add_block_signature(&block_id, &address, &sig1).unwrap());
        assert_eq!(db.get_block_signatures(&block_id).unwrap(), vec![sig1]);
        assert!(db
            .get_block_rejection_signer_addrs(&block_id)
            .unwrap()
            .is_empty());

        assert!(!db
            .add_block_rejection_signer_addr(&block_id, &address, &RejectReason::InvalidParentBlock)
            .unwrap());
        assert_eq!(db.get_block_signatures(&block_id).unwrap(), vec![sig1]);
        assert!(db
            .get_block_rejection_signer_addrs(&block_id)
            .unwrap()
            .is_empty());
    }

    #[test]
    fn test_and_set_block_broadcasted() {
        let db_path = tmp_db_path();
        let mut db = SignerDb::new(db_path).expect("Failed to create signer db");

        let (block_info_1, _block_proposal) = create_block_override(|b| {
            b.block.header.miner_signature = MessageSignature([0x01; 65]);
            b.burn_height = 1;
        });

        db.insert_block(&block_info_1)
            .expect("Unable to insert block into db");

        assert!(db
            .get_block_broadcasted(&block_info_1.signer_signature_hash())
            .unwrap()
            .is_none());
        assert_eq!(
            db.block_lookup(&block_info_1.signer_signature_hash())
                .expect("Unable to get block from db")
                .expect("Unable to get block from db")
                .state,
            BlockState::Unprocessed
        );
        assert!(db
            .get_last_globally_accepted_block(&block_info_1.block.header.consensus_hash)
            .unwrap()
            .is_none());
        db.set_block_broadcasted(&block_info_1.signer_signature_hash(), 12345)
            .unwrap();
        assert_eq!(
            db.block_lookup(&block_info_1.signer_signature_hash())
                .expect("Unable to get block from db")
                .expect("Unable to get block from db")
                .state,
            BlockState::Unprocessed
        );
        db.insert_block(&block_info_1)
            .expect("Unable to insert block into db a second time");

        assert_eq!(
            db.get_block_broadcasted(&block_info_1.signer_signature_hash())
                .unwrap()
                .unwrap(),
            12345
        );
    }

    #[test]
    fn state_machine() {
        let (mut block, _) = create_block();
        assert_eq!(block.state, BlockState::Unprocessed);
        assert!(block.check_state(BlockState::Unprocessed));
        assert!(block.check_state(BlockState::LocallyAccepted));
        assert!(block.check_state(BlockState::LocallyRejected));
        assert!(block.check_state(BlockState::GloballyAccepted));
        assert!(block.check_state(BlockState::GloballyRejected));

        block.move_to(BlockState::LocallyAccepted).unwrap();
        assert_eq!(block.state, BlockState::LocallyAccepted);
        assert!(!block.check_state(BlockState::Unprocessed));
        assert!(block.check_state(BlockState::LocallyAccepted));
        assert!(block.check_state(BlockState::LocallyRejected));
        assert!(block.check_state(BlockState::GloballyAccepted));
        assert!(block.check_state(BlockState::GloballyRejected));

        block.move_to(BlockState::LocallyRejected).unwrap();
        assert!(!block.check_state(BlockState::Unprocessed));
        assert!(block.check_state(BlockState::LocallyAccepted));
        assert!(block.check_state(BlockState::LocallyRejected));
        assert!(block.check_state(BlockState::GloballyAccepted));
        assert!(block.check_state(BlockState::GloballyRejected));

        block.move_to(BlockState::GloballyAccepted).unwrap();
        assert_eq!(block.state, BlockState::GloballyAccepted);
        assert!(!block.check_state(BlockState::Unprocessed));
        assert!(!block.check_state(BlockState::LocallyAccepted));
        assert!(!block.check_state(BlockState::LocallyRejected));
        assert!(block.check_state(BlockState::GloballyAccepted));
        assert!(!block.check_state(BlockState::GloballyRejected));

        // Must manually override as will not be able to move from GloballyAccepted to GloballyRejected
        block.state = BlockState::GloballyRejected;
        assert!(!block.check_state(BlockState::Unprocessed));
        assert!(!block.check_state(BlockState::LocallyAccepted));
        assert!(!block.check_state(BlockState::LocallyRejected));
        assert!(!block.check_state(BlockState::GloballyAccepted));
        assert!(block.check_state(BlockState::GloballyRejected));
    }

    #[test]
    fn test_get_canonical_tip() {
        let db_path = tmp_db_path();
        let mut db = SignerDb::new(db_path).expect("Failed to create signer db");

        let (mut block_info_1, _block_proposal_1) = create_block_override(|b| {
            b.block.header.miner_signature = MessageSignature([0x01; 65]);
            b.block.header.chain_length = 1;
            b.burn_height = 1;
        });

        let (mut block_info_2, _block_proposal_2) = create_block_override(|b| {
            b.block.header.miner_signature = MessageSignature([0x02; 65]);
            b.block.header.chain_length = 2;
            b.burn_height = 2;
        });

        db.insert_block(&block_info_1)
            .expect("Unable to insert block into db");
        db.insert_block(&block_info_2)
            .expect("Unable to insert block into db");

        assert!(db.get_canonical_tip().unwrap().is_none());

        block_info_1
            .mark_globally_accepted()
            .expect("Failed to mark block as globally accepted");
        db.insert_block(&block_info_1)
            .expect("Unable to insert block into db");

        assert_eq!(db.get_canonical_tip().unwrap().unwrap(), block_info_1);

        block_info_2
            .mark_globally_accepted()
            .expect("Failed to mark block as globally accepted");
        db.insert_block(&block_info_2)
            .expect("Unable to insert block into db");

        assert_eq!(db.get_canonical_tip().unwrap().unwrap(), block_info_2);
    }

    #[test]
    fn get_accepted_blocks() {
        let db_path = tmp_db_path();
        let mut db = SignerDb::new(db_path).expect("Failed to create signer db");
        let consensus_hash_1 = ConsensusHash([0x01; 20]);
        let consensus_hash_2 = ConsensusHash([0x02; 20]);
        let consensus_hash_3 = ConsensusHash([0x03; 20]);
        let (mut block_info_1, _block_proposal) = create_block_override(|b| {
            b.block.header.consensus_hash = consensus_hash_1;
            b.block.header.miner_signature = MessageSignature([0x01; 65]);
            b.block.header.chain_length = 1;
            b.burn_height = 1;
        });
        let (mut block_info_2, _block_proposal) = create_block_override(|b| {
            b.block.header.consensus_hash = consensus_hash_1;
            b.block.header.miner_signature = MessageSignature([0x02; 65]);
            b.block.header.chain_length = 2;
            b.burn_height = 2;
        });
        let (mut block_info_3, _block_proposal) = create_block_override(|b| {
            b.block.header.consensus_hash = consensus_hash_1;
            b.block.header.miner_signature = MessageSignature([0x03; 65]);
            b.block.header.chain_length = 3;
            b.burn_height = 3;
        });
        let (mut block_info_4, _block_proposal) = create_block_override(|b| {
            b.block.header.consensus_hash = consensus_hash_2;
            b.block.header.miner_signature = MessageSignature([0x03; 65]);
            b.block.header.chain_length = 3;
            b.burn_height = 4;
        });
        block_info_1.mark_globally_accepted().unwrap();
        block_info_2.mark_locally_accepted(false).unwrap();
        block_info_3.mark_locally_accepted(false).unwrap();
        block_info_4.mark_globally_accepted().unwrap();

        db.insert_block(&block_info_1).unwrap();
        db.insert_block(&block_info_2).unwrap();
        db.insert_block(&block_info_3).unwrap();
        db.insert_block(&block_info_4).unwrap();

        // Verify tenure consensus_hash_1
        let block_info = db
            .get_last_accepted_block(&consensus_hash_1)
            .unwrap()
            .unwrap();
        assert_eq!(block_info, block_info_3);
        let block_info = db
            .get_last_globally_accepted_block(&consensus_hash_1)
            .unwrap()
            .unwrap();
        assert_eq!(block_info, block_info_1);

        // Verify tenure consensus_hash_2
        let block_info = db
            .get_last_accepted_block(&consensus_hash_2)
            .unwrap()
            .unwrap();
        assert_eq!(block_info, block_info_4);
        let block_info = db
            .get_last_globally_accepted_block(&consensus_hash_2)
            .unwrap()
            .unwrap();
        assert_eq!(block_info, block_info_4);

        // Verify tenure consensus_hash_3
        assert!(db
            .get_last_accepted_block(&consensus_hash_3)
            .unwrap()
            .is_none());
        assert!(db
            .get_last_globally_accepted_block(&consensus_hash_3)
            .unwrap()
            .is_none());
    }

    fn generate_tenure_blocks() -> Vec<BlockInfo> {
        let tenure_change_payload = TenureChangePayload {
            tenure_consensus_hash: ConsensusHash([0x04; 20]), // same as in nakamoto header
            prev_tenure_consensus_hash: ConsensusHash([0x01; 20]),
            burn_view_consensus_hash: ConsensusHash([0x04; 20]),
            previous_tenure_end: StacksBlockId([0x03; 32]),
            previous_tenure_blocks: 1,
            cause: TenureChangeCause::BlockFound,
            pubkey_hash: Hash160::from_node_public_key(&StacksPublicKey::from_private(
                &StacksPrivateKey::random(),
            )),
        };
        let tenure_change_tx_payload = TransactionPayload::TenureChange(tenure_change_payload);
        let tenure_change_tx = StacksTransaction::new(
            TransactionVersion::Testnet,
            TransactionAuth::from_p2pkh(&StacksPrivateKey::random()).unwrap(),
            tenure_change_tx_payload,
        );

        let consensus_hash_1 = ConsensusHash([0x01; 20]);
        let consensus_hash_2 = ConsensusHash([0x02; 20]);
        let (mut block_info_1, _block_proposal) = create_block_override(|b| {
            b.block.header.consensus_hash = consensus_hash_1;
            b.block.header.miner_signature = MessageSignature([0x01; 65]);
            b.block.header.chain_length = 1;
            b.burn_height = 1;
        });
        block_info_1.state = BlockState::GloballyAccepted;
        block_info_1.block.txs.push(tenure_change_tx.clone());
        block_info_1.validation_time_ms = Some(1000);
        block_info_1.proposed_time = get_epoch_time_secs() + 500;

        let (mut block_info_2, _block_proposal) = create_block_override(|b| {
            b.block.header.consensus_hash = consensus_hash_1;
            b.block.header.miner_signature = MessageSignature([0x02; 65]);
            b.block.header.chain_length = 2;
            b.burn_height = 2;
        });
        block_info_2.state = BlockState::GloballyAccepted;
        block_info_2.validation_time_ms = Some(2000);
        block_info_2.proposed_time = block_info_1.proposed_time + 5;

        let (mut block_info_3, _block_proposal) = create_block_override(|b| {
            b.block.header.consensus_hash = consensus_hash_1;
            b.block.header.miner_signature = MessageSignature([0x03; 65]);
            b.block.header.chain_length = 3;
            b.burn_height = 2;
        });
        block_info_3.state = BlockState::GloballyAccepted;
        block_info_3.block.txs.push(tenure_change_tx);
        block_info_3.validation_time_ms = Some(5000);
        block_info_3.proposed_time = block_info_1.proposed_time + 10;

        // This should have no effect on the time calculations as its not a globally accepted block
        let (mut block_info_4, _block_proposal) = create_block_override(|b| {
            b.block.header.consensus_hash = consensus_hash_1;
            b.block.header.miner_signature = MessageSignature([0x04; 65]);
            b.block.header.chain_length = 3;
            b.burn_height = 2;
        });
        block_info_4.state = BlockState::LocallyAccepted;
        block_info_4.validation_time_ms = Some(9000);
        block_info_4.proposed_time = block_info_1.proposed_time + 15;

        let (mut block_info_5, _block_proposal) = create_block_override(|b| {
            b.block.header.consensus_hash = consensus_hash_2;
            b.block.header.miner_signature = MessageSignature([0x05; 65]);
            b.block.header.chain_length = 4;
            b.burn_height = 3;
        });
        block_info_5.state = BlockState::GloballyAccepted;
        block_info_5.validation_time_ms = Some(20000);
        block_info_5.proposed_time = block_info_1.proposed_time + 20;

        // This should have no effect on the time calculations as its not a globally accepted block
        let (mut block_info_6, _block_proposal) = create_block_override(|b| {
            b.block.header.consensus_hash = consensus_hash_2;
            b.block.header.miner_signature = MessageSignature([0x06; 65]);
            b.block.header.chain_length = 5;
            b.burn_height = 3;
        });
        block_info_6.state = BlockState::LocallyAccepted;
        block_info_6.validation_time_ms = Some(40000);
        block_info_6.proposed_time = block_info_1.proposed_time + 25;

        vec![
            block_info_1,
            block_info_2,
            block_info_3,
            block_info_4,
            block_info_5,
            block_info_6,
        ]
    }

    #[test]
    fn tenure_times() {
        let db_path = tmp_db_path();
        let mut db = SignerDb::new(db_path).expect("Failed to create signer db");
        let block_infos = generate_tenure_blocks();
        let consensus_hash_1 = block_infos[0].block.header.consensus_hash;
        let consensus_hash_2 = block_infos.last().unwrap().block.header.consensus_hash;
        let consensus_hash_3 = ConsensusHash([0x03; 20]);

        db.insert_block(&block_infos[0]).unwrap();
        db.insert_block(&block_infos[1]).unwrap();

        // Verify tenure consensus_hash_1
        let (start_time, processing_time) = db.get_tenure_times(&consensus_hash_1).unwrap();
        assert_eq!(start_time, block_infos[0].proposed_time);
        assert_eq!(processing_time, 3000);

        db.insert_block(&block_infos[2]).unwrap();
        db.insert_block(&block_infos[3]).unwrap();

        let (start_time, processing_time) = db.get_tenure_times(&consensus_hash_1).unwrap();
        assert_eq!(start_time, block_infos[2].proposed_time);
        assert_eq!(processing_time, 5000);

        db.insert_block(&block_infos[4]).unwrap();
        db.insert_block(&block_infos[5]).unwrap();

        // Verify tenure consensus_hash_2
        let (start_time, processing_time) = db.get_tenure_times(&consensus_hash_2).unwrap();
        assert_eq!(start_time, block_infos[4].proposed_time);
        assert_eq!(processing_time, 20000);

        // Verify tenure consensus_hash_3 (unknown hash)
        let (start_time, validation_time) = db.get_tenure_times(&consensus_hash_3).unwrap();
        assert!(start_time < block_infos[0].proposed_time, "Should have been generated from get_epoch_time_secs() making it much older than our artificially late proposal times");
        assert_eq!(validation_time, 0);
    }

    #[test]
    fn tenure_extend_timestamp() {
        let db_path = tmp_db_path();
        let mut db = SignerDb::new(db_path).expect("Failed to create signer db");

        let block_infos = generate_tenure_blocks();
        let mut unknown_block = block_infos[0].block.clone();
        unknown_block.header.consensus_hash = ConsensusHash([0x03; 20]);

        db.insert_block(&block_infos[0]).unwrap();
        db.insert_block(&block_infos[1]).unwrap();

        let tenure_idle_timeout = Duration::from_secs(10);
        // Verify tenure consensus_hash_1
        let timestamp_hash_1_before =
            db.calculate_tenure_extend_timestamp(tenure_idle_timeout, &block_infos[0].block, true);
        assert_eq!(
            timestamp_hash_1_before,
            block_infos[0]
                .proposed_time
                .saturating_add(tenure_idle_timeout.as_secs())
                .saturating_add(3)
        );

        db.insert_block(&block_infos[2]).unwrap();
        db.insert_block(&block_infos[3]).unwrap();

        let timestamp_hash_1_after =
            db.calculate_tenure_extend_timestamp(tenure_idle_timeout, &block_infos[0].block, true);

        assert_eq!(
            timestamp_hash_1_after,
            block_infos[2]
                .proposed_time
                .saturating_add(tenure_idle_timeout.as_secs())
                .saturating_add(5)
        );

        db.insert_block(&block_infos[4]).unwrap();
        db.insert_block(&block_infos[5]).unwrap();

        // Verify tenure consensus_hash_2
        let timestamp_hash_2 = db.calculate_tenure_extend_timestamp(
            tenure_idle_timeout,
            &block_infos.last().unwrap().block,
            true,
        );
        assert_eq!(
            timestamp_hash_2,
            block_infos[4]
                .proposed_time
                .saturating_add(tenure_idle_timeout.as_secs())
                .saturating_add(20)
        );

        let now = get_epoch_time_secs().saturating_add(tenure_idle_timeout.as_secs());
        let timestamp_hash_2_no_tenure_extend =
            db.calculate_tenure_extend_timestamp(tenure_idle_timeout, &block_infos[0].block, false);
        assert_ne!(timestamp_hash_2, timestamp_hash_2_no_tenure_extend);
        assert!(now < timestamp_hash_2_no_tenure_extend);

        // Verify tenure consensus_hash_3 (unknown hash)
        let timestamp_hash_3 =
            db.calculate_tenure_extend_timestamp(tenure_idle_timeout, &unknown_block, true);
        assert!(
            timestamp_hash_3.saturating_add(tenure_idle_timeout.as_secs())
                < block_infos[0].proposed_time
        );
    }

    #[test]
    fn test_get_and_remove_pending_block_validation() {
        let db_path = tmp_db_path();
        let db = SignerDb::new(db_path).expect("Failed to create signer db");

        let pending_hash = db.get_and_remove_pending_block_validation().unwrap();
        assert!(pending_hash.is_none());

        db.insert_pending_block_validation(&Sha512Trunc256Sum([0x01; 32]), 1000)
            .unwrap();
        db.insert_pending_block_validation(&Sha512Trunc256Sum([0x02; 32]), 2000)
            .unwrap();
        db.insert_pending_block_validation(&Sha512Trunc256Sum([0x03; 32]), 3000)
            .unwrap();

        let (pending_hash, _) = db
            .get_and_remove_pending_block_validation()
            .unwrap()
            .unwrap();
        assert_eq!(pending_hash, Sha512Trunc256Sum([0x01; 32]));

        let pendings = db.get_all_pending_block_validations().unwrap();
        assert_eq!(pendings.len(), 2);

        let (pending_hash, _) = db
            .get_and_remove_pending_block_validation()
            .unwrap()
            .unwrap();
        assert_eq!(pending_hash, Sha512Trunc256Sum([0x02; 32]));

        let pendings = db.get_all_pending_block_validations().unwrap();
        assert_eq!(pendings.len(), 1);

        let (pending_hash, _) = db
            .get_and_remove_pending_block_validation()
            .unwrap()
            .unwrap();
        assert_eq!(pending_hash, Sha512Trunc256Sum([0x03; 32]));

        let pendings = db.get_all_pending_block_validations().unwrap();
        assert!(pendings.is_empty());
    }

    #[test]
    fn check_globally_signed_block_count() {
        let db_path = tmp_db_path();
        let consensus_hash_1 = ConsensusHash([0x01; 20]);
        let mut db = SignerDb::new(db_path).expect("Failed to create signer db");
        let (mut block_info, _) = create_block_override(|b| {
            b.block.header.consensus_hash = consensus_hash_1;
        });

        assert!(matches!(
            db.get_globally_accepted_block_count_in_tenure(&consensus_hash_1)
                .unwrap(),
            0
        ));

        // locally accepted still returns 0
        block_info.signed_over = true;
        block_info.state = BlockState::LocallyAccepted;
        block_info.block.header.chain_length = 1;
        db.insert_block(&block_info).unwrap();

        assert_eq!(
            db.get_globally_accepted_block_count_in_tenure(&consensus_hash_1)
                .unwrap(),
            0
        );

        block_info.signed_over = true;
        block_info.state = BlockState::GloballyAccepted;
        block_info.block.header.chain_length = 2;
        db.insert_block(&block_info).unwrap();

        block_info.signed_over = true;
        block_info.state = BlockState::GloballyAccepted;
        block_info.block.header.chain_length = 3;
        db.insert_block(&block_info).unwrap();

        assert_eq!(
            db.get_globally_accepted_block_count_in_tenure(&consensus_hash_1)
                .unwrap(),
            2
        );

        // add an unsigned block
        block_info.signed_over = false;
        block_info.state = BlockState::GloballyAccepted;
        block_info.block.header.chain_length = 4;
        db.insert_block(&block_info).unwrap();

        assert_eq!(
            db.get_globally_accepted_block_count_in_tenure(&consensus_hash_1)
                .unwrap(),
            3
        );

        // add a locally signed block
        block_info.signed_over = true;
        block_info.state = BlockState::LocallyAccepted;
        block_info.block.header.chain_length = 5;
        db.insert_block(&block_info).unwrap();

        assert_eq!(
            db.get_globally_accepted_block_count_in_tenure(&consensus_hash_1)
                .unwrap(),
            3
        );
    }

    #[test]
    fn has_signed_block() {
        let db_path = tmp_db_path();
        let consensus_hash_1 = ConsensusHash([0x01; 20]);
        let consensus_hash_2 = ConsensusHash([0x02; 20]);
        let mut db = SignerDb::new(db_path).expect("Failed to create signer db");
        let (mut block_info, _) = create_block_override(|b| {
            b.block.header.consensus_hash = consensus_hash_1;
            b.block.header.chain_length = 1;
        });

        assert!(!db.has_signed_block_in_tenure(&consensus_hash_1).unwrap());
        assert!(!db.has_signed_block_in_tenure(&consensus_hash_2).unwrap());

        block_info.signed_over = true;
        db.insert_block(&block_info).unwrap();

        assert!(db.has_signed_block_in_tenure(&consensus_hash_1).unwrap());
        assert!(!db.has_signed_block_in_tenure(&consensus_hash_2).unwrap());

        block_info.block.header.consensus_hash = consensus_hash_2;
        block_info.block.header.chain_length = 2;
        block_info.signed_over = false;

        db.insert_block(&block_info).unwrap();

        assert!(db.has_signed_block_in_tenure(&consensus_hash_1).unwrap());
        assert!(!db.has_signed_block_in_tenure(&consensus_hash_2).unwrap());

        block_info.signed_over = true;

        db.insert_block(&block_info).unwrap();

        assert!(db.has_signed_block_in_tenure(&consensus_hash_1).unwrap());
        assert!(db.has_signed_block_in_tenure(&consensus_hash_2).unwrap());
    }

    #[test]
    fn update_last_activity() {
        let db_path = tmp_db_path();
        let consensus_hash_1 = ConsensusHash([0x01; 20]);
        let consensus_hash_2 = ConsensusHash([0x02; 20]);
        let mut db = SignerDb::new(db_path).expect("Failed to create signer db");

        assert!(db
            .get_last_activity_time(&consensus_hash_1)
            .unwrap()
            .is_none());
        assert!(db
            .get_last_activity_time(&consensus_hash_2)
            .unwrap()
            .is_none());

        let time = get_epoch_time_secs();
        db.update_last_activity_time(&consensus_hash_1, time)
            .unwrap();
        let retrieved_time = db
            .get_last_activity_time(&consensus_hash_1)
            .unwrap()
            .unwrap();
        assert_eq!(time, retrieved_time);
        assert!(db
            .get_last_activity_time(&consensus_hash_2)
            .unwrap()
            .is_none());
    }

    /// BlockInfo without the `reject_reason` field for backwards compatibility testing
    #[derive(Serialize, Deserialize, Debug, PartialEq)]
    pub struct BlockInfoPrev {
        /// The block we are considering
        pub block: NakamotoBlock,
        /// The burn block height at which the block was proposed
        pub burn_block_height: u64,
        /// The reward cycle the block belongs to
        pub reward_cycle: u64,
        /// Our vote on the block if we have one yet
        pub vote: Option<NakamotoBlockVote>,
        /// Whether the block contents are valid
        pub valid: Option<bool>,
        /// Whether this block is already being signed over
        pub signed_over: bool,
        /// Time at which the proposal was received by this signer (epoch time in seconds)
        pub proposed_time: u64,
        /// Time at which the proposal was signed by this signer (epoch time in seconds)
        pub signed_self: Option<u64>,
        /// Time at which the proposal was signed by a threshold in the signer set (epoch time in seconds)
        pub signed_group: Option<u64>,
        /// The block state relative to the signer's view of the stacks blockchain
        pub state: BlockState,
        /// Consumed processing time in milliseconds to validate this block
        pub validation_time_ms: Option<u64>,
        /// Extra data specific to v0, v1, etc.
        pub ext: ExtraBlockInfo,
    }

    /// Verify that we can deserialize the old BlockInfo struct into the new version
    #[test]
    fn deserialize_old_block_info() {
        let block_info_prev = BlockInfoPrev {
            block: NakamotoBlock {
                header: NakamotoBlockHeader::genesis(),
                txs: vec![],
            },
            burn_block_height: 2,
            reward_cycle: 3,
            vote: None,
            valid: None,
            signed_over: true,
            proposed_time: 4,
            signed_self: None,
            signed_group: None,
            state: BlockState::Unprocessed,
            validation_time_ms: Some(5),
            ext: ExtraBlockInfo::default(),
        };

        let block_info: BlockInfo =
            serde_json::from_value(serde_json::to_value(&block_info_prev).unwrap()).unwrap();
        assert_eq!(block_info.block, block_info_prev.block);
        assert_eq!(
            block_info.burn_block_height,
            block_info_prev.burn_block_height
        );
        assert_eq!(block_info.reward_cycle, block_info_prev.reward_cycle);
        assert_eq!(block_info.vote, block_info_prev.vote);
        assert_eq!(block_info.valid, block_info_prev.valid);
        assert_eq!(block_info.signed_over, block_info_prev.signed_over);
        assert_eq!(block_info.proposed_time, block_info_prev.proposed_time);
        assert_eq!(block_info.signed_self, block_info_prev.signed_self);
        assert_eq!(block_info.signed_group, block_info_prev.signed_group);
        assert_eq!(block_info.state, block_info_prev.state);
        assert_eq!(
            block_info.validation_time_ms,
            block_info_prev.validation_time_ms
        );
        assert_eq!(block_info.ext, block_info_prev.ext);
        assert!(block_info.reject_reason.is_none());
    }

    #[test]
    fn insert_and_get_state_machine_updates() {
        let db_path = tmp_db_path();
        let mut db = SignerDb::new(db_path).expect("Failed to create signer db");
        let reward_cycle_1 = 1;
        let address_1 = StacksAddress::p2pkh(false, &StacksPublicKey::new());
        let update_1 = StateMachineUpdate::new(
            0,
            3,
            StateMachineUpdateContent::V0 {
                burn_block: ConsensusHash([0x55; 20]),
                burn_block_height: 100,
                current_miner: StateMachineUpdateMinerState::ActiveMiner {
                    current_miner_pkh: Hash160([0xab; 20]),
                    tenure_id: ConsensusHash([0x44; 20]),
                    parent_tenure_id: ConsensusHash([0x22; 20]),
                    parent_tenure_last_block: StacksBlockId([0x33; 32]),
                    parent_tenure_last_block_height: 1,
                },
            },
        )
        .unwrap();

        let address_2 = StacksAddress::p2pkh(false, &StacksPublicKey::new());
        let update_2 = StateMachineUpdate::new(
            0,
            4,
            StateMachineUpdateContent::V0 {
                burn_block: ConsensusHash([0x55; 20]),
                burn_block_height: 100,
                current_miner: StateMachineUpdateMinerState::NoValidMiner,
            },
        )
        .unwrap();

        let address_3 = StacksAddress::p2pkh(false, &StacksPublicKey::new());
        let update_3 = StateMachineUpdate::new(
            0,
            2,
            StateMachineUpdateContent::V0 {
                burn_block: ConsensusHash([0x66; 20]),
                burn_block_height: 101,
                current_miner: StateMachineUpdateMinerState::NoValidMiner,
            },
        )
        .unwrap();

        assert!(
            db.get_signer_state_machine_updates(reward_cycle_1)
                .unwrap()
                .is_empty(),
            "The database should be empty for reward_cycle {reward_cycle_1}"
        );

        db.insert_state_machine_update(reward_cycle_1, &address_1, &update_1, &SystemTime::now())
            .expect("Unable to insert block into db");
        db.insert_state_machine_update(reward_cycle_1, &address_2, &update_2, &SystemTime::now())
            .expect("Unable to insert block into db");
        db.insert_state_machine_update(
            reward_cycle_1 + 1,
            &address_3,
            &update_3,
            &SystemTime::now(),
        )
        .expect("Unable to insert block into db");

        let updates = db.get_signer_state_machine_updates(reward_cycle_1).unwrap();
        assert_eq!(updates.len(), 2);

        assert_eq!(updates.get(&address_1), Some(&update_1));
        assert_eq!(updates.get(&address_2), Some(&update_2));
        assert_eq!(updates.get(&address_3), None);

        db.insert_state_machine_update(reward_cycle_1, &address_2, &update_3, &SystemTime::now())
            .expect("Unable to insert block into db");
        let updates = db.get_signer_state_machine_updates(reward_cycle_1).unwrap();
        assert_eq!(updates.len(), 2);

        assert_eq!(updates.get(&address_1), Some(&update_1));
        assert_eq!(updates.get(&address_2), Some(&update_3));
        assert_eq!(updates.get(&address_3), None);

        let updates = db
            .get_signer_state_machine_updates(reward_cycle_1 + 1)
            .unwrap();
        assert_eq!(updates.len(), 1);
        assert_eq!(updates.get(&address_1), None);
        assert_eq!(updates.get(&address_2), None);
        assert_eq!(updates.get(&address_3), Some(&update_3));
    }

    #[test]
    fn burn_state_migration_consensus_hash_primary_key() {
        // Construct the old table
        let conn = rusqlite::Connection::open_in_memory().expect("Failed to create in mem db");
        conn.execute_batch(CREATE_BURN_STATE_TABLE)
            .expect("Failed to create old table");
        conn.execute_batch(ADD_CONSENSUS_HASH)
            .expect("Failed to add consensus hash to old table");
        conn.execute_batch(ADD_CONSENSUS_HASH_INDEX)
            .expect("Failed to add consensus hash index to old table");

        let consensus_hash = ConsensusHash([0; 20]);
        let total_nmb_rows = 5;
        // Fill with old data with conflicting consensus hashes
        for i in 0..=total_nmb_rows {
            let now = SystemTime::now();
            let received_ts = now.duration_since(std::time::UNIX_EPOCH).unwrap().as_secs();
            let burn_hash = BurnchainHeaderHash([i; 32]);
            let burn_height = i;
            if i % 2 == 0 {
                // Make sure we have some one empty consensus hash options that will get dropped
                conn.execute(
                    "INSERT OR REPLACE INTO burn_blocks (block_hash, block_height, received_time) VALUES (?1, ?2, ?3)",
                    params![
                        burn_hash,
                        u64_to_sql(burn_height.into()).unwrap(),
                        u64_to_sql(received_ts + i as u64).unwrap(), // Ensure increasing received_time
                    ]
                ).unwrap();
            } else {
                conn.execute(
                    "INSERT OR REPLACE INTO burn_blocks (block_hash, consensus_hash, block_height, received_time) VALUES (?1, ?2, ?3, ?4)",
                    params![
                        burn_hash,
                        consensus_hash,
                        u64_to_sql(burn_height.into()).unwrap(),
                        u64_to_sql(received_ts + i as u64).unwrap(), // Ensure increasing received_time
                    ]
                ).unwrap();
            };
        }

        // Migrate the data and make sure that the primary key conflict is resolved by using the last received time
        // and that the block height and consensus hash of the surviving row is as expected
        conn.execute_batch(MIGRATE_BURN_STATE_TABLE_1_TO_TABLE_2)
            .expect("Failed to migrate data");
        let migrated_count: u64 = conn
            .query_row("SELECT COUNT(*) FROM burn_blocks;", [], |row| row.get(0))
            .expect("Failed to get row count");

        assert_eq!(
            migrated_count, 1,
            "Expected exactly one row after migration"
        );

        let (block_height, hex_hash): (u64, String) = conn
            .query_row(
                "SELECT block_height, consensus_hash FROM burn_blocks;",
                [],
                |row| Ok((row.get(0)?, row.get(1)?)),
            )
            .expect("Failed to get block_height and consensus_hash");

        assert_eq!(
            block_height, total_nmb_rows as u64,
            "Expected block_height {total_nmb_rows} to be retained (has the latest received time)"
        );

        assert_eq!(
            hex_hash,
            consensus_hash.to_hex(),
            "Expected the surviving row to have the correct consensus_hash"
        );
    }

    #[test]
    fn insert_block_validated_by_replay_tx() {
        let db_path = tmp_db_path();
        let db = SignerDb::new(db_path).expect("Failed to create signer db");

        let signer_signature_hash = Sha512Trunc256Sum([0; 32]);
        let replay_tx_hash = 15559610262907183370_u64;
        let replay_tx_exhausted = true;

        db.insert_block_validated_by_replay_tx(
            &signer_signature_hash,
            replay_tx_hash,
            replay_tx_exhausted,
        )
        .expect("Failed to insert block validated by replay tx");

        let result = db
            .get_was_block_validated_by_replay_tx(&signer_signature_hash, replay_tx_hash)
            .expect("Failed to get block validated by replay tx")
            .expect("Expected block validation result to be stored");
        assert_eq!(result.replay_tx_hash, format!("{replay_tx_hash}"));
        assert!(result.replay_tx_exhausted);

        let replay_tx_hash = 15559610262907183369_u64;
        let replay_tx_exhausted = false;

        db.insert_block_validated_by_replay_tx(
            &signer_signature_hash,
            replay_tx_hash,
            replay_tx_exhausted,
        )
        .expect("Failed to insert block validated by replay tx");

        let result = db
            .get_was_block_validated_by_replay_tx(&signer_signature_hash, replay_tx_hash)
            .expect("Failed to get block validated by replay tx")
            .expect("Expected block validation result to be stored");
        assert_eq!(result.replay_tx_hash, format!("{replay_tx_hash}"));
        assert!(!result.replay_tx_exhausted);
    }

    #[test]
    fn check_burn_block_received_time_from_signers() {
        let db_path = tmp_db_path();
        let mut db = SignerDb::new(db_path).expect("Failed to create signer db");
        let reward_cycle_1 = 1;
        let local_address = StacksAddress::p2pkh(false, &StacksPublicKey::new());
        let address_1 = StacksAddress::p2pkh(false, &StacksPublicKey::new());
        let burn_block_1 = ConsensusHash([0x55; 20]);
        let burn_block_2 = ConsensusHash([0x66; 20]);
        let update_1 = StateMachineUpdate::new(
            0,
            3,
            StateMachineUpdateContent::V0 {
                burn_block: burn_block_1,
                burn_block_height: 100,
                current_miner: StateMachineUpdateMinerState::ActiveMiner {
                    current_miner_pkh: Hash160([0xab; 20]),
                    tenure_id: ConsensusHash([0x44; 20]),
                    parent_tenure_id: ConsensusHash([0x22; 20]),
                    parent_tenure_last_block: StacksBlockId([0x33; 32]),
                    parent_tenure_last_block_height: 1,
                },
            },
        )
        .unwrap();

        let address_2 = StacksAddress::p2pkh(false, &StacksPublicKey::new());
        let update_2 = StateMachineUpdate::new(
            0,
            4,
            StateMachineUpdateContent::V0 {
                burn_block: burn_block_1,
                burn_block_height: 100,
                current_miner: StateMachineUpdateMinerState::NoValidMiner,
            },
        )
        .unwrap();

        let address_3 = StacksAddress::p2pkh(false, &StacksPublicKey::new());
        let update_3 = StateMachineUpdate::new(
            0,
            2,
            StateMachineUpdateContent::V0 {
                burn_block: burn_block_2,
                burn_block_height: 101,
                current_miner: StateMachineUpdateMinerState::NoValidMiner,
            },
        )
        .unwrap();

        let mut address_weights = HashMap::new();
        address_weights.insert(local_address.clone(), 10);
        address_weights.insert(address_1.clone(), 10);
        address_weights.insert(address_2.clone(), 10);
        address_weights.insert(address_3.clone(), 10);
        let eval = GlobalStateEvaluator::new(HashMap::new(), address_weights);

        assert!(db
            .get_burn_block_received_time_from_signers(&eval, &burn_block_1, &local_address)
            .unwrap()
            .is_none());

        db.insert_state_machine_update(reward_cycle_1, &address_1, &update_1, &SystemTime::now())
            .expect("Unable to insert block into db");
        db.insert_state_machine_update(reward_cycle_1, &address_2, &update_2, &SystemTime::now())
            .expect("Unable to insert block into db");
        db.insert_state_machine_update(reward_cycle_1, &address_3, &update_3, &SystemTime::now())
            .expect("Unable to insert block into db");
        assert!(db
            .get_burn_block_received_time_from_signers(&eval, &burn_block_1, &local_address)
            .unwrap()
            .is_none());

        let burn_hash = BurnchainHeaderHash([10; 32]);
        let stime = SystemTime::now() + Duration::from_secs(30);
        let time_to_epoch = stime
            .duration_since(SystemTime::UNIX_EPOCH)
            .unwrap()
            .as_secs();

        db.insert_burn_block(
            &burn_hash,
            &burn_block_1,
            101,
            &stime,
            &BurnchainHeaderHash([11; 32]),
        )
        .unwrap();
        assert_eq!(
            time_to_epoch,
            db.get_burn_block_received_time_from_signers(&eval, &burn_block_1, &local_address)
                .unwrap()
                .unwrap()
        );
        assert!(db
            .get_burn_block_received_time_from_signers(&eval, &burn_block_2, &local_address)
            .unwrap()
            .is_none());
    }

    #[test]
    fn test_get_last_globally_accepted_block_signed_self() {
        let db_path = tmp_db_path();
        let mut db = SignerDb::new(db_path).expect("Failed to create signer db");

        let consensus_hash_1 = ConsensusHash([0x01; 20]);
        let consensus_hash_2 = ConsensusHash([0x02; 20]);

        // Create blocks with different burn heights and signed_self timestamps (seconds since epoch)
        let (mut block_info_1, _block_proposal) = create_block_override(|b| {
            b.block.header.consensus_hash = consensus_hash_1;
            b.block.header.miner_signature = MessageSignature([0x01; 65]);
            b.block.header.chain_length = 1;
            b.burn_height = 1;
        });
        block_info_1.mark_locally_accepted(false).unwrap();
        let (mut block_info_2, _block_proposal) = create_block_override(|b| {
            b.block.header.consensus_hash = consensus_hash_1;
            b.block.header.miner_signature = MessageSignature([0x02; 65]);
            b.block.header.chain_length = 2;
            b.burn_height = 2;
        });
        block_info_2.mark_locally_accepted(false).unwrap();
        let (mut block_info_3, _block_proposal) = create_block_override(|b| {
            b.block.header.consensus_hash = consensus_hash_2;
            b.block.header.miner_signature = MessageSignature([0x03; 65]);
            b.block.header.chain_length = 3;
            b.burn_height = 3;
        });
        block_info_3.mark_locally_accepted(false).unwrap();

        // Mark only one of the blocks as globally accepted
        block_info_1.mark_globally_accepted().unwrap();

        // Insert into db
        db.insert_block(&block_info_1).unwrap();
        db.insert_block(&block_info_2).unwrap();
        db.insert_block(&block_info_3).unwrap();

        // Query for consensus_hash_1 should return signed_self of block_info_2 (highest burn_height)
        db.get_last_globally_accepted_block_signed_self(&consensus_hash_1)
            .unwrap()
            .expect("Expected a signed_self timestamp");

        // Query for consensus_hash_2 should return none since we only contributed to a locally signed block
        let result_2 = db
            .get_last_globally_accepted_block_signed_self(&consensus_hash_2)
            .unwrap();

        assert!(result_2.is_none());

        // Query for a consensus hash with no blocks should return None
        let consensus_hash_3 = ConsensusHash([0x03; 20]);
        let result_3 = db
            .get_last_globally_accepted_block_signed_self(&consensus_hash_3)
            .unwrap();

        assert!(result_3.is_none());
    }
}
