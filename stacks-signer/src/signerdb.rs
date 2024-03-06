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

use std::path::PathBuf;

use blockstack_lib::util_lib::db::{
    query_row, sqlite_open, table_exists, tx_begin_immediate, Error as DBError,
};
use rusqlite::{Connection, Error as SqliteError, OpenFlags, NO_PARAMS};
use stacks_common::util::hash::Sha512Trunc256Sum;

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
    signer_signature_hash TEXT PRIMARY KEY,
    block_info TEXT NOT NULL
)";

impl SignerDb {
    /// Create a new `SignerState` instance.
    /// This will create a new SQLite database at the given path
    /// if one doesn't exist.
    pub fn new(db_path: Option<PathBuf>) -> Result<SignerDb, DBError> {
        let connection = Self::connect(&db_path)?;

        let signer_db = Self { db: connection };

        signer_db.instantiate_db()?;

        Ok(signer_db)
    }

    fn instantiate_db(&self) -> Result<(), DBError> {
        if !table_exists(&self.db, "blocks")? {
            self.db.execute(CREATE_BLOCKS_TABLE, NO_PARAMS)?;
        }

        Ok(())
    }

    fn connect(db_path: &Option<PathBuf>) -> Result<Connection, SqliteError> {
        if let Some(path) = db_path {
            sqlite_open(
                path,
                OpenFlags::SQLITE_OPEN_READ_WRITE | OpenFlags::SQLITE_OPEN_CREATE,
                false,
            )
        } else {
            Connection::open_in_memory()
        }
    }

    /// Fetch a block from the database using the block's
    /// `signer_signature_hash`
    pub fn block_lookup(&self, hash: &Sha512Trunc256Sum) -> Result<Option<BlockInfo>, DBError> {
        let result: Option<String> = query_row(
            &self.db,
            "SELECT block_info FROM blocks WHERE signer_signature_hash = ?",
            &[format!("{}", hash)],
        )?;
        if let Some(block_info) = result {
            let block_info: BlockInfo =
                serde_json::from_str(&block_info).map_err(|e| DBError::SerializationError(e))?;
            Ok(Some(block_info))
        } else {
            Ok(None)
        }
    }

    /// Insert a block into the database.
    /// `hash` is the `signer_signature_hash` of the block.
    pub fn insert_block(&mut self, block_info: &BlockInfo) -> Result<(), DBError> {
        let block_json =
            serde_json::to_string(&block_info).expect("Unable to serialize block info");
        let hash = &block_info.signer_signature_hash();
        let tx = tx_begin_immediate(&mut self.db).expect("Unable to begin tx");
        tx.execute(
            "INSERT OR REPLACE INTO blocks (signer_signature_hash, block_info) VALUES (?1, ?2)",
            &[format!("{}", hash), block_json],
        )
        .map_err(|e| {
            return DBError::Other(format!(
                "Unable to insert block into db: {:?}",
                e.to_string()
            ));
        })?;
        tx.commit().expect("Unable to commit tx");
        Ok(())
    }

    /// Remove a block
    pub fn remove_block(&mut self, hash: &Sha512Trunc256Sum) -> Result<(), DBError> {
        let tx = tx_begin_immediate(&mut self.db).expect("Unable to begin tx");
        tx.execute(
            "DELETE FROM blocks WHERE signer_signature_hash = ?",
            &[format!("{}", hash)],
        )
        .map_err(|e| DBError::from(e))?;
        tx.commit().map_err(|e| DBError::from(e))?;
        Ok(())
    }
}

#[cfg(test)]
pub fn test_signer_db(db_path: &str) -> SignerDb {
    use std::fs;

    if fs::metadata(&db_path).is_ok() {
        fs::remove_file(&db_path).unwrap();
    }
    SignerDb::new(Some(db_path.into())).expect("Failed to create signer db")
}

#[cfg(test)]
mod tests {
    use blockstack_lib::chainstate::{
        nakamoto::{NakamotoBlock, NakamotoBlockHeader, NakamotoBlockVote},
        stacks::ThresholdSignature,
    };
    use stacks_common::{
        bitvec::BitVec,
        types::chainstate::{ConsensusHash, StacksBlockId, TrieHash},
        util::secp256k1::MessageSignature,
    };

    use super::*;
    use std::fs;

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

    fn create_block() -> (BlockInfo, NakamotoBlock) {
        create_block_override(|_| {})
    }

    fn tmp_db_path() -> Option<PathBuf> {
        Some(format!("/tmp/stacks-signer-test-{}.sqlite", rand::random::<u64>()).into())
    }

    #[test]
    fn test_basic_signer_db() {
        let db_path = tmp_db_path();
        let mut db = SignerDb::new(db_path).expect("Failed to create signer db");
        let (block_info, block) = create_block();
        db.insert_block(&block_info)
            .expect("Unable to insert block into db");

        let block_info = db
            .block_lookup(&block.header.signer_signature_hash())
            .unwrap()
            .expect("Unable to get block from db");

        assert_eq!(BlockInfo::new(block.clone()), block_info);
    }

    #[test]
    fn test_update_block() {
        let db_path = tmp_db_path();
        let mut db = SignerDb::new(db_path).expect("Failed to create signer db");
        let (block_info, block) = create_block();
        db.insert_block(&block_info)
            .expect("Unable to insert block into db");

        let block_info = db
            .block_lookup(&block.header.signer_signature_hash())
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
        db.insert_block(&block_info)
            .expect("Unable to insert block into db");

        let block_info = db
            .block_lookup(&block.header.signer_signature_hash())
            .unwrap()
            .expect("Unable to get block from db");

        assert_ne!(old_block_info, block_info);
        assert_eq!(block_info.vote, Some(vote));
    }
}
