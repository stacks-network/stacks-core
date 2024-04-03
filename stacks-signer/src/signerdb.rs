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

use std::path::Path;

use blockstack_lib::util_lib::db::{
    query_row, sqlite_open, table_exists, u64_to_sql, Error as DBError,
};
use rusqlite::{params, Connection, Error as SqliteError, OpenFlags, NO_PARAMS};
use slog::slog_debug;
use stacks_common::debug;
use stacks_common::util::hash::Sha512Trunc256Sum;
use wsts::traits::SignerState;

use crate::signer::BlockInfo;

/// This struct manages a SQLite database connection
/// for the signer.
#[derive(Debug)]
pub struct SignerDb {
    /// Connection to the SQLite database
    db: Connection,
}

const CREATE_BLOCKS_TABLE: &'static str = "
CREATE TABLE IF NOT EXISTS blocks (
    reward_cycle INTEGER NOT NULL,
    signer_signature_hash TEXT NOT NULL,
    block_info TEXT NOT NULL,
    PRIMARY KEY (reward_cycle, signer_signature_hash)
)";

const CREATE_SIGNER_STATE_TABLE: &'static str = "
CREATE TABLE IF NOT EXISTS signer_states (
    reward_cycle INTEGER PRIMARY KEY,
    state TEXT NOT NULL
)";

impl SignerDb {
    /// Create a new `SignerState` instance.
    /// This will create a new SQLite database at the given path
    /// or an in-memory database if the path is ":memory:"
    pub fn new(db_path: impl AsRef<Path>) -> Result<Self, DBError> {
        let connection = Self::connect(db_path)?;

        let signer_db = Self { db: connection };

        signer_db.instantiate_db()?;

        Ok(signer_db)
    }

    fn instantiate_db(&self) -> Result<(), DBError> {
        if !table_exists(&self.db, "blocks")? {
            self.db.execute(CREATE_BLOCKS_TABLE, NO_PARAMS)?;
        }

        if !table_exists(&self.db, "signer_states")? {
            self.db.execute(CREATE_SIGNER_STATE_TABLE, NO_PARAMS)?;
        }

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
    pub fn get_signer_state(&self, reward_cycle: u64) -> Result<Option<SignerState>, DBError> {
        let result: Option<String> = query_row(
            &self.db,
            "SELECT state FROM signer_states WHERE reward_cycle = ?",
            &[u64_to_sql(reward_cycle)?],
        )?;

        try_deserialize(result)
    }

    /// Insert the given state in the `signer_states` table for the given reward cycle
    pub fn insert_signer_state(
        &self,
        reward_cycle: u64,
        signer_state: &SignerState,
    ) -> Result<(), DBError> {
        let serialized_state = serde_json::to_string(signer_state)?;
        self.db.execute(
            "INSERT OR REPLACE INTO signer_states (reward_cycle, state) VALUES (?1, ?2)",
            params![&u64_to_sql(reward_cycle)?, &serialized_state],
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
            params![&u64_to_sql(reward_cycle)?, hash.to_string()],
        )?;

        try_deserialize(result)
    }

    /// Insert a block into the database.
    /// `hash` is the `signer_signature_hash` of the block.
    pub fn insert_block(
        &mut self,
        reward_cycle: u64,
        block_info: &BlockInfo,
    ) -> Result<(), DBError> {
        let block_json =
            serde_json::to_string(&block_info).expect("Unable to serialize block info");
        let hash = &block_info.signer_signature_hash();
        let block_id = &block_info.block.block_id();
        let signed_over = &block_info.signed_over;
        debug!(
            "Inserting block_info: reward_cycle = {reward_cycle}, sighash = {hash}, block_id = {block_id}, signed = {signed_over} vote = {:?}",
            block_info.vote.as_ref().map(|v| {
                if v.rejected {
                    "REJECT"
                } else {
                    "ACCEPT"
                }
            })
        );
        self.db
            .execute(
                "INSERT OR REPLACE INTO blocks (reward_cycle, signer_signature_hash, block_info) VALUES (?1, ?2, ?3)",
                params![&u64_to_sql(reward_cycle)?, hash.to_string(), &block_json],
            )?;

        Ok(())
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

    if fs::metadata(&db_path).is_ok() {
        fs::remove_file(&db_path).unwrap();
    }
    SignerDb::new(db_path).expect("Failed to create signer db")
}

#[cfg(test)]
mod tests {
    use std::fs;
    use std::path::PathBuf;

    use blockstack_lib::chainstate::nakamoto::{
        NakamotoBlock, NakamotoBlockHeader, NakamotoBlockVote,
    };
    use blockstack_lib::chainstate::stacks::ThresholdSignature;
    use num_traits::identities::Zero;
    use polynomial::Polynomial;
    use stacks_common::bitvec::BitVec;
    use stacks_common::types::chainstate::{ConsensusHash, StacksBlockId, TrieHash};
    use stacks_common::util::secp256k1::MessageSignature;
    use wsts::common::Nonce;
    use wsts::curve::point::Point;
    use wsts::curve::scalar::Scalar;
    use wsts::traits::PartyState;

    use super::*;

    fn _wipe_db(db_path: &PathBuf) {
        if fs::metadata(db_path).is_ok() {
            fs::remove_file(db_path).unwrap();
        }
    }

    fn create_block_override(
        overrides: impl FnOnce(&mut NakamotoBlock),
    ) -> (BlockInfo, NakamotoBlock) {
        let header = NakamotoBlockHeader {
            version: 1,
            chain_length: 2,
            burn_spent: 3,
            consensus_hash: ConsensusHash([0x04; 20]),
            parent_block_id: StacksBlockId([0x05; 32]),
            tx_merkle_root: Sha512Trunc256Sum([0x06; 32]),
            state_index_root: TrieHash([0x07; 32]),
            miner_signature: MessageSignature::empty(),
            signer_signature: ThresholdSignature::empty(),
            signer_bitvec: BitVec::zeros(1).unwrap(),
        };
        let mut block = NakamotoBlock {
            header,
            txs: vec![],
        };
        overrides(&mut block);
        (BlockInfo::new(block.clone()), block)
    }

    fn create_signer_state(id: u32) -> SignerState {
        let ps1 = PartyState {
            polynomial: Some(Polynomial::new(vec![1.into(), 2.into(), 3.into()])),
            private_keys: vec![(1, 45.into()), (2, 56.into())],
            nonce: Nonce::zero(),
        };

        let ps2 = PartyState {
            polynomial: Some(Polynomial::new(vec![1.into(), 2.into(), 3.into()])),
            private_keys: vec![(1, 45.into()), (2, 56.into())],
            nonce: Nonce::zero(),
        };

        SignerState {
            id,
            key_ids: vec![2, 4],
            num_keys: 12,
            num_parties: 10,
            threshold: 7,
            group_key: Point::from(Scalar::from(42)),
            parties: vec![(2, ps1), (4, ps2)],
        }
    }

    fn create_block() -> (BlockInfo, NakamotoBlock) {
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
        let reward_cycle = 1;
        let (block_info, block) = create_block();
        db.insert_block(reward_cycle, &block_info)
            .expect("Unable to insert block into db");

        let block_info = db
            .block_lookup(reward_cycle, &block.header.signer_signature_hash())
            .unwrap()
            .expect("Unable to get block from db");

        assert_eq!(BlockInfo::new(block.clone()), block_info);

        // Test looking up a block from a different reward cycle
        let block_info = db
            .block_lookup(reward_cycle + 1, &block.header.signer_signature_hash())
            .unwrap();
        assert!(block_info.is_none());
    }

    #[test]
    fn test_basic_signer_db() {
        let db_path = tmp_db_path();
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
        let reward_cycle = 42;
        let (block_info, block) = create_block();
        db.insert_block(reward_cycle, &block_info)
            .expect("Unable to insert block into db");

        let block_info = db
            .block_lookup(reward_cycle, &block.header.signer_signature_hash())
            .unwrap()
            .expect("Unable to get block from db");

        assert_eq!(BlockInfo::new(block.clone()), block_info);

        let old_block_info = block_info;
        let old_block = block;

        let (mut block_info, block) = create_block_override(|b| {
            b.header.signer_signature = old_block.header.signer_signature.clone();
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
        db.insert_block(reward_cycle, &block_info)
            .expect("Unable to insert block into db");

        let block_info = db
            .block_lookup(reward_cycle, &block.header.signer_signature_hash())
            .unwrap()
            .expect("Unable to get block from db");

        assert_ne!(old_block_info, block_info);
        assert_eq!(block_info.vote, Some(vote));
    }

    #[test]
    fn test_write_signer_state() {
        let db_path = tmp_db_path();
        let db = SignerDb::new(db_path).expect("Failed to create signer db");
        let state_0 = create_signer_state(0);
        let state_1 = create_signer_state(1);

        db.insert_signer_state(10, &state_0)
            .expect("Failed to insert signer state");

        db.insert_signer_state(11, &state_1)
            .expect("Failed to insert signer state");

        assert_eq!(
            db.get_signer_state(10)
                .expect("Failed to get signer state")
                .unwrap()
                .id,
            state_0.id
        );
        assert_eq!(
            db.get_signer_state(11)
                .expect("Failed to get signer state")
                .unwrap()
                .id,
            state_1.id
        );
        assert!(db
            .get_signer_state(12)
            .expect("Failed to get signer state")
            .is_none());
        assert!(db
            .get_signer_state(9)
            .expect("Failed to get signer state")
            .is_none());
    }
}
