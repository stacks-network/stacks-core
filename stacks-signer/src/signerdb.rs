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

use std::fmt::Display;
use std::path::Path;
use std::time::SystemTime;

use blockstack_lib::chainstate::nakamoto::NakamotoBlock;
use blockstack_lib::util_lib::db::{
    query_row, query_rows, sqlite_open, table_exists, tx_begin_immediate, u64_to_sql,
    Error as DBError,
};
use clarity::types::chainstate::{BurnchainHeaderHash, StacksAddress};
use clarity::util::get_epoch_time_secs;
use libsigner::BlockProposal;
use rusqlite::{
    params, Connection, Error as SqliteError, OpenFlags, OptionalExtension, Transaction,
};
use serde::{Deserialize, Serialize};
use slog::{slog_debug, slog_error};
use stacks_common::codec::{read_next, write_next, Error as CodecError, StacksMessageCodec};
use stacks_common::types::chainstate::ConsensusHash;
use stacks_common::util::hash::Sha512Trunc256Sum;
use stacks_common::util::secp256k1::MessageSignature;
use stacks_common::{debug, define_u8_enum, error};
use wsts::net::NonceRequest;

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

#[derive(Serialize, Deserialize, Debug, PartialEq, Default)]
/// Information specific to Signer V1
pub struct BlockInfoV1 {
    /// The associated packet nonce request if we have one
    pub nonce_request: Option<NonceRequest>,
}

impl From<NonceRequest> for BlockInfoV1 {
    fn from(value: NonceRequest) -> Self {
        Self {
            nonce_request: Some(value),
        }
    }
}

#[derive(Serialize, Deserialize, Debug, PartialEq, Default)]
/// Store extra version-specific info in `BlockInfo`
pub enum ExtraBlockInfo {
    #[default]
    /// Don't know what version
    None,
    /// Extra data for Signer V0
    V0,
    /// Extra data for Signer V1
    V1(BlockInfoV1),
}

impl ExtraBlockInfo {
    /// Take `nonce_request` if it exists
    pub fn take_nonce_request(&mut self) -> Option<NonceRequest> {
        match self {
            ExtraBlockInfo::None | ExtraBlockInfo::V0 => None,
            ExtraBlockInfo::V1(v1) => v1.nonce_request.take(),
        }
    }
    /// Set `nonce_request` if it exists
    pub fn set_nonce_request(&mut self, value: NonceRequest) -> Result<(), &str> {
        match self {
            ExtraBlockInfo::None | ExtraBlockInfo::V0 => Err("Field doesn't exist"),
            ExtraBlockInfo::V1(v1) => {
                v1.nonce_request = Some(value);
                Ok(())
            }
        }
    }
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
        write!(f, "{}", state)
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
#[derive(Serialize, Deserialize, Debug, PartialEq)]
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
    /// Extra data specific to v0, v1, etc.
    pub ext: ExtraBlockInfo,
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
        }
    }
}
impl BlockInfo {
    /// Create a new BlockInfo with an associated nonce request packet
    pub fn new_v1_with_request(block_proposal: BlockProposal, nonce_request: NonceRequest) -> Self {
        let mut block_info = BlockInfo::from(block_proposal);
        block_info.ext = ExtraBlockInfo::V1(BlockInfoV1::from(nonce_request));
        block_info.signed_over = true;
        block_info
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
    pub fn mark_globally_accepted(&mut self) -> Result<(), String> {
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
    pub fn mark_globally_rejected(&mut self) -> Result<(), String> {
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
            BlockState::LocallyAccepted => {
                matches!(
                    prev_state,
                    BlockState::Unprocessed | BlockState::LocallyAccepted
                )
            }
            BlockState::LocallyRejected => {
                matches!(prev_state, BlockState::Unprocessed)
            }
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
    -- signtaure itself
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

impl SignerDb {
    /// The current schema version used in this build of the signer binary.
    pub const SCHEMA_VERSION: u32 = 3;

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
            .query_row("SELECT version FROM db_config LIMIT 1", [], |row| {
                row.get(0)
            })
            .optional();
        match result {
            Ok(x) => Ok(x.unwrap_or(0)),
            Err(e) => Err(DBError::from(e)),
        }
    }

    /// Migrate from schema 0 to schema 1
    fn schema_1_migration(tx: &Transaction) -> Result<(), DBError> {
        if Self::get_schema_version(tx)? >= 1 {
            // no migration necessary
            return Ok(());
        }

        for statement in SCHEMA_1.iter() {
            tx.execute_batch(statement)?;
        }

        Ok(())
    }

    /// Migrate from schema 1 to schema 2
    fn schema_2_migration(tx: &Transaction) -> Result<(), DBError> {
        if Self::get_schema_version(tx)? >= 2 {
            // no migration necessary
            return Ok(());
        }

        for statement in SCHEMA_2.iter() {
            tx.execute_batch(statement)?;
        }

        Ok(())
    }

    /// Migrate from schema 2 to schema 3
    fn schema_3_migration(tx: &Transaction) -> Result<(), DBError> {
        if Self::get_schema_version(tx)? >= 3 {
            // no migration necessary
            return Ok(());
        }

        for statement in SCHEMA_3.iter() {
            tx.execute_batch(statement)?;
        }

        Ok(())
    }

    /// Either instantiate a new database, or migrate an existing one
    /// If the detected version of the existing database is 0 (i.e., a pre-migration
    /// logic DB, the DB will be dropped).
    fn create_or_migrate(&mut self) -> Result<(), DBError> {
        let sql_tx = tx_begin_immediate(&mut self.db)?;
        loop {
            let version = Self::get_schema_version(&sql_tx)?;
            match version {
                0 => Self::schema_1_migration(&sql_tx)?,
                1 => Self::schema_2_migration(&sql_tx)?,
                2 => Self::schema_3_migration(&sql_tx)?,
                3 => break,
                x => return Err(DBError::Other(format!(
                    "Database schema is newer than supported by this binary. Expected version = {}, Database version = {x}",
                    Self::SCHEMA_VERSION,
                ))),
            }
        }
        sql_tx.commit()?;
        Ok(())
    }

    fn connect(db_path: impl AsRef<Path>) -> Result<Connection, SqliteError> {
        sqlite_open(
            db_path,
            OpenFlags::SQLITE_OPEN_READ_WRITE | OpenFlags::SQLITE_OPEN_CREATE,
            false,
        )
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
    pub fn block_lookup(
        &self,
        reward_cycle: u64,
        hash: &Sha512Trunc256Sum,
    ) -> Result<Option<BlockInfo>, DBError> {
        let result: Option<String> = query_row(
            &self.db,
            "SELECT block_info FROM blocks WHERE reward_cycle = ? AND signer_signature_hash = ?",
            params![u64_to_sql(reward_cycle)?, hash.to_string()],
        )?;

        try_deserialize(result)
    }

    /// Return the last signed block in a tenure (identified by its consensus hash)
    pub fn get_last_signed_block_in_tenure(
        &self,
        tenure: &ConsensusHash,
    ) -> Result<Option<BlockInfo>, DBError> {
        let query = "SELECT block_info FROM blocks WHERE consensus_hash = ? AND signed_over = 1 ORDER BY stacks_height DESC LIMIT 1";
        let result: Option<String> = query_row(&self.db, query, [tenure])?;

        try_deserialize(result)
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

    /// Return the last accepted block in a tenure (identified by its consensus hash).
    pub fn get_last_accepted_block(
        &self,
        tenure: &ConsensusHash,
    ) -> Result<Option<BlockInfo>, DBError> {
        let query = "SELECT block_info FROM blocks WHERE consensus_hash = ?1 AND json_extract(block_info, '$.state') IN (?2, ?3) ORDER BY stacks_height DESC LIMIT 1";
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
        let query = "SELECT block_info FROM blocks WHERE consensus_hash = ?1 AND json_extract(block_info, '$.state') = ?2 ORDER BY stacks_height DESC LIMIT 1";
        let args = params![tenure, &BlockState::GloballyAccepted.to_string()];
        let result: Option<String> = query_row(&self.db, query, args)?;

        try_deserialize(result)
    }

    /// Insert or replace a burn block into the database
    pub fn insert_burn_block(
        &mut self,
        burn_hash: &BurnchainHeaderHash,
        burn_height: u64,
        received_time: &SystemTime,
    ) -> Result<(), DBError> {
        let received_ts = received_time
            .duration_since(std::time::UNIX_EPOCH)
            .map_err(|e| DBError::Other(format!("Bad system time: {e}")))?
            .as_secs();
        debug!("Inserting burn block info"; "burn_block_height" => burn_height, "burn_hash" => %burn_hash, "received" => received_ts);
        self.db.execute(
            "INSERT OR REPLACE INTO burn_blocks (block_hash, block_height, received_time) VALUES (?1, ?2, ?3)",
            params![
                burn_hash,
                u64_to_sql(burn_height)?,
                u64_to_sql(received_ts)?,
            ],
        )?;
        Ok(())
    }

    /// Get timestamp (epoch seconds) at which a burn block was received over the event dispatcheer by this signer
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

    /// Insert or replace a block into the database.
    /// Preserves the `broadcast` column if replacing an existing block.
    pub fn insert_block(&mut self, block_info: &BlockInfo) -> Result<(), DBError> {
        let block_json =
            serde_json::to_string(&block_info).expect("Unable to serialize block info");
        let hash = &block_info.signer_signature_hash();
        let block_id = &block_info.block.block_id();
        let signed_over = &block_info.signed_over;
        let vote = block_info
            .vote
            .as_ref()
            .map(|v| if v.rejected { "REJECT" } else { "ACCEPT" });
        let broadcasted = self.get_block_broadcasted(block_info.reward_cycle, hash)?;
        debug!("Inserting block_info.";
            "reward_cycle" => %block_info.reward_cycle,
            "burn_block_height" => %block_info.burn_block_height,
            "sighash" => %hash,
            "block_id" => %block_id,
            "signed" => %signed_over,
            "broadcasted" => ?broadcasted,
            "vote" => vote
        );
        self.db
            .execute(
                "INSERT OR REPLACE INTO blocks (reward_cycle, burn_block_height, signer_signature_hash, block_info, signed_over, broadcasted, stacks_height, consensus_hash) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8)",
                params![
                    u64_to_sql(block_info.reward_cycle)?, u64_to_sql(block_info.burn_block_height)?, hash.to_string(), block_json,
                    signed_over,
                    &broadcasted,
                    u64_to_sql(block_info.block.header.chain_length)?,
                    block_info.block.header.consensus_hash.to_hex(),
                ],
            )?;

        Ok(())
    }

    /// Determine if there are any unprocessed blocks
    pub fn has_unprocessed_blocks(&self, reward_cycle: u64) -> Result<bool, DBError> {
        let query = "SELECT block_info FROM blocks WHERE reward_cycle = ?1 AND json_extract(block_info, '$.state') = ?2 LIMIT 1";
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
        signature: &MessageSignature,
    ) -> Result<(), DBError> {
        let qry = "INSERT OR REPLACE INTO block_signatures (signer_signature_hash, signature) VALUES (?1, ?2);";
        let args = params![
            block_sighash,
            serde_json::to_string(signature).map_err(DBError::SerializationError)?
        ];

        debug!("Inserting block signature.";
            "sighash" => %block_sighash,
            "signature" => %signature);

        self.db.execute(qry, args)?;
        Ok(())
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
    ) -> Result<(), DBError> {
        let qry = "INSERT OR REPLACE INTO block_rejection_signer_addrs (signer_signature_hash, signer_addr) VALUES (?1, ?2);";
        let args = params![block_sighash, addr.to_string(),];

        debug!("Inserting block rejection.";
                "block_sighash" => %block_sighash,
                "signer_address" => %addr);

        self.db.execute(qry, args)?;
        Ok(())
    }

    /// Get all signer addresses that rejected the block
    pub fn get_block_rejection_signer_addrs(
        &self,
        block_sighash: &Sha512Trunc256Sum,
    ) -> Result<Vec<StacksAddress>, DBError> {
        let qry =
            "SELECT signer_addr FROM block_rejection_signer_addrs WHERE signer_signature_hash = ?1";
        let args = params![block_sighash];
        query_rows(&self.db, qry, args)
    }

    /// Mark a block as having been broadcasted and therefore GloballyAccepted
    pub fn set_block_broadcasted(
        &self,
        reward_cycle: u64,
        block_sighash: &Sha512Trunc256Sum,
        ts: u64,
    ) -> Result<(), DBError> {
        let qry = "UPDATE blocks SET broadcasted = ?1, block_info = json_set(block_info, '$.state', ?2) WHERE reward_cycle = ?3 AND signer_signature_hash = ?4";
        let args = params![
            u64_to_sql(ts)?,
            BlockState::GloballyAccepted.to_string(),
            u64_to_sql(reward_cycle)?,
            block_sighash
        ];

        debug!("Marking block {} as broadcasted at {}", block_sighash, ts);
        self.db.execute(qry, args)?;
        Ok(())
    }

    /// Get the timestamp at which the block was broadcasted.
    pub fn get_block_broadcasted(
        &self,
        reward_cycle: u64,
        block_sighash: &Sha512Trunc256Sum,
    ) -> Result<Option<u64>, DBError> {
        let qry =
            "SELECT IFNULL(broadcasted,0) AS broadcasted FROM blocks WHERE reward_cycle = ?1 AND signer_signature_hash = ?2";
        let args = params![u64_to_sql(reward_cycle)?, block_sighash];

        let Some(broadcasted): Option<u64> = query_row(&self.db, qry, args)? else {
            return Ok(None);
        };
        if broadcasted == 0 {
            return Ok(None);
        }
        Ok(Some(broadcasted))
    }

    /// Get the current state of a given block in the database
    pub fn get_block_state(
        &self,
        reward_cycle: u64,
        block_sighash: &Sha512Trunc256Sum,
    ) -> Result<Option<BlockState>, DBError> {
        let qry = "SELECT json_extract(block_info, '$.state') FROM blocks WHERE reward_cycle = ?1 AND signer_signature_hash = ?2 LIMIT 1";
        let args = params![&u64_to_sql(reward_cycle)?, block_sighash];
        let state_opt: Option<String> = query_row(&self.db, qry, args)?;
        let Some(state) = state_opt else {
            return Ok(None);
        };
        Ok(Some(
            BlockState::try_from(state.as_str()).map_err(|_| DBError::Corruption)?,
        ))
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

#[cfg(test)]
pub fn test_signer_db(db_path: &str) -> SignerDb {
    use std::fs;

    if fs::metadata(db_path).is_ok() {
        fs::remove_file(db_path).unwrap();
    }
    SignerDb::new(db_path).expect("Failed to create signer db")
}

#[cfg(test)]
mod tests {
    use std::fs;
    use std::path::PathBuf;

    use blockstack_lib::chainstate::nakamoto::{NakamotoBlock, NakamotoBlockHeader};
    use clarity::util::secp256k1::MessageSignature;
    use libsigner::BlockProposal;

    use super::*;
    use crate::signerdb::NakamotoBlockVote;

    fn _wipe_db(db_path: &PathBuf) {
        if fs::metadata(db_path).is_ok() {
            fs::remove_file(db_path).unwrap();
        }
    }

    fn create_block_override(
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
        };
        overrides(&mut block_proposal);
        (BlockInfo::from(block_proposal.clone()), block_proposal)
    }

    fn create_block() -> (BlockInfo, BlockProposal) {
        create_block_override(|_| {})
    }

    fn tmp_db_path() -> PathBuf {
        std::env::temp_dir().join(format!(
            "stacks-signer-test-{}.sqlite",
            rand::random::<u64>()
        ))
    }

    fn test_basic_signer_db_with_path(db_path: impl AsRef<Path>) {
        let mut db = SignerDb::new(db_path).expect("Failed to create signer db");
        let (block_info, block_proposal) = create_block();
        let reward_cycle = block_info.reward_cycle;
        db.insert_block(&block_info)
            .expect("Unable to insert block into db");
        let block_info = db
            .block_lookup(
                reward_cycle,
                &block_proposal.block.header.signer_signature_hash(),
            )
            .unwrap()
            .expect("Unable to get block from db");

        assert_eq!(BlockInfo::from(block_proposal.clone()), block_info);

        // Test looking up a block from a different reward cycle
        let block_info = db
            .block_lookup(
                reward_cycle + 1,
                &block_proposal.block.header.signer_signature_hash(),
            )
            .unwrap();
        assert!(block_info.is_none());

        // test getting the block state
        let block_state = db
            .get_block_state(
                reward_cycle,
                &block_proposal.block.header.signer_signature_hash(),
            )
            .unwrap()
            .expect("Unable to get block state from db");

        assert_eq!(block_state, BlockInfo::from(block_proposal.clone()).state);
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
        let reward_cycle = block_info.reward_cycle;
        db.insert_block(&block_info)
            .expect("Unable to insert block into db");

        let block_info = db
            .block_lookup(
                reward_cycle,
                &block_proposal.block.header.signer_signature_hash(),
            )
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
            .block_lookup(
                reward_cycle,
                &block_proposal.block.header.signer_signature_hash(),
            )
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
        let stime = SystemTime::now();
        let time_to_epoch = stime
            .duration_since(SystemTime::UNIX_EPOCH)
            .unwrap()
            .as_secs();
        db.insert_burn_block(&test_burn_hash, 10, &stime).unwrap();

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
        let sig1 = MessageSignature([0x11; 65]);
        let sig2 = MessageSignature([0x22; 65]);

        assert_eq!(db.get_block_signatures(&block_id).unwrap(), vec![]);

        db.add_block_signature(&block_id, &sig1).unwrap();
        assert_eq!(db.get_block_signatures(&block_id).unwrap(), vec![sig1]);

        db.add_block_signature(&block_id, &sig2).unwrap();
        assert_eq!(
            db.get_block_signatures(&block_id).unwrap(),
            vec![sig1, sig2]
        );
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
            .get_block_broadcasted(
                block_info_1.reward_cycle,
                &block_info_1.signer_signature_hash()
            )
            .unwrap()
            .is_none());
        assert_eq!(
            db.block_lookup(
                block_info_1.reward_cycle,
                &block_info_1.signer_signature_hash()
            )
            .expect("Unable to get block from db")
            .expect("Unable to get block from db")
            .state,
            BlockState::Unprocessed
        );
        db.set_block_broadcasted(
            block_info_1.reward_cycle,
            &block_info_1.signer_signature_hash(),
            12345,
        )
        .unwrap();
        assert_eq!(
            db.block_lookup(
                block_info_1.reward_cycle,
                &block_info_1.signer_signature_hash()
            )
            .expect("Unable to get block from db")
            .expect("Unable to get block from db")
            .state,
            BlockState::GloballyAccepted
        );
        db.insert_block(&block_info_1)
            .expect("Unable to insert block into db a second time");

        assert_eq!(
            db.get_block_broadcasted(
                block_info_1.reward_cycle,
                &block_info_1.signer_signature_hash()
            )
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
        assert!(!block.check_state(BlockState::LocallyRejected));
        assert!(block.check_state(BlockState::GloballyAccepted));
        assert!(block.check_state(BlockState::GloballyRejected));

        block.move_to(BlockState::GloballyAccepted).unwrap();
        assert_eq!(block.state, BlockState::GloballyAccepted);
        assert!(!block.check_state(BlockState::Unprocessed));
        assert!(!block.check_state(BlockState::LocallyAccepted));
        assert!(!block.check_state(BlockState::LocallyRejected));
        assert!(block.check_state(BlockState::GloballyAccepted));
        assert!(!block.check_state(BlockState::GloballyRejected));

        // Must manually override as will not be able to move from GloballyAccepted to LocallyAccepted
        block.state = BlockState::LocallyRejected;
        assert!(!block.check_state(BlockState::Unprocessed));
        assert!(!block.check_state(BlockState::LocallyAccepted));
        assert!(block.check_state(BlockState::LocallyRejected));
        assert!(block.check_state(BlockState::GloballyAccepted));
        assert!(block.check_state(BlockState::GloballyRejected));

        block.move_to(BlockState::GloballyRejected).unwrap();
        assert!(!block.check_state(BlockState::Unprocessed));
        assert!(!block.check_state(BlockState::LocallyAccepted));
        assert!(!block.check_state(BlockState::LocallyRejected));
        assert!(!block.check_state(BlockState::GloballyAccepted));
        assert!(block.check_state(BlockState::GloballyRejected));
    }
}
