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

use blockstack_lib::core::POX_REWARD_CYCLE_LENGTH;
use blockstack_lib::util_lib::db::{
    query_row, sqlite_open, table_exists, u64_to_sql, Error as DBError,
};
use rusqlite::{params, Connection, Error as SqliteError, OpenFlags, NO_PARAMS};
use slog::slog_debug;
use stacks_common::debug;
use stacks_common::util::hash::Sha512Trunc256Sum;
use wsts::traits::SignerState;

use crate::signer::BlockInfo;

/// How many reward cycles to keep data for
const REWARD_CYLE_RENTENTION_LIMIT: u64 = 1;

/// This struct manages a SQLite database connection
/// for the signer.
#[derive(Debug)]
pub struct SignerDb {
    /// Connection to the SQLite database
    db: Connection,
}

const CREATE_BLOCKS_TABLE: &str = "
CREATE TABLE IF NOT EXISTS blocks (
    reward_cycle INTEGER NOT NULL,
    signer_signature_hash TEXT NOT NULL,
    block_info TEXT NOT NULL,
    burn_block_height INTEGER NOT NULL,
    PRIMARY KEY (reward_cycle, signer_signature_hash)
)";

const CREATE_SIGNER_STATE_TABLE: &str = "
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
            [u64_to_sql(reward_cycle)?],
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

        debug!("Inserting block_info.";
            "reward_cycle" => %block_info.reward_cycle,
            "burn_block_height" => %block_info.burn_block_height,
            "sighash" => %hash,
            "block_id" => %block_id,
            "signed" => %signed_over,
            "vote" => vote
        );
        self.db
            .execute(
                "INSERT OR REPLACE INTO blocks (reward_cycle, burn_block_height, signer_signature_hash, block_info) VALUES (?1, ?2, ?3, ?4)",
                params![u64_to_sql(block_info.reward_cycle)?, u64_to_sql(block_info.burn_block_height)?, hash.to_string(), &block_json],
            )?;

        Ok(())
    }

    /// Delete all stale signer state relative to the current reward cycle
    pub fn cleanup_stale_state(&mut self, current_reward_cycle: u64) -> Result<(), DBError> {
        let threshold_reward_cycle =
            current_reward_cycle.saturating_sub(REWARD_CYLE_RENTENTION_LIMIT);
        self.db.execute(
            "DELETE FROM signer_states WHERE reward_cycle < ?",
            params![u64_to_sql(threshold_reward_cycle)?],
        )?;
        Ok(())
    }

    /// Delete all stale signer state relative to the current reward cycle
    pub fn cleanup_stale_blocks(&mut self, current_burn_block_height: u64) -> Result<(), DBError> {
        let threshold_burn_block_height =
            current_burn_block_height.saturating_sub(POX_REWARD_CYCLE_LENGTH as u64);
        self.db.execute(
            "DELETE FROM blocks WHERE burn_block_height < ?",
            params![u64_to_sql(threshold_burn_block_height)?],
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

    if fs::metadata(db_path).is_ok() {
        fs::remove_file(db_path).unwrap();
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
    use libsigner::BlockProposalSigners;
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
        overrides: impl FnOnce(&mut BlockProposalSigners),
    ) -> (BlockInfo, BlockProposalSigners) {
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
        let block = NakamotoBlock {
            header,
            txs: vec![],
        };
        let mut block_proposal = BlockProposalSigners {
            block: block.clone(),
            burn_height: 7,
            reward_cycle: 42,
        };
        overrides(&mut block_proposal);
        (BlockInfo::from(block_proposal.clone()), block_proposal)
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

    fn create_block() -> (BlockInfo, BlockProposalSigners) {
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

    #[test]
    fn garbage_collect_state() {
        let db_path = tmp_db_path();
        let mut db = SignerDb::new(db_path).expect("Failed to create signer db");
        let reward_cycle_1 = 42;
        let reward_cycle_2 = 43;
        let reward_cycle_3 = 44;

        let state_1 = create_signer_state(1);
        let state_2 = create_signer_state(2);
        let state_3 = create_signer_state(3);

        // Insert a signer state per reward cycle
        db.insert_signer_state(reward_cycle_1, &state_1)
            .expect("Unable to insert signer state into db");
        db.insert_signer_state(reward_cycle_2, &state_2)
            .expect("Unable to insert signer state into db");
        db.insert_signer_state(reward_cycle_3, &state_3)
            .expect("Unable to insert signer state into db");

        // garbage collection for a reward cycle equal to or less than the second oldest reward cycle, should result in zero change
        db.cleanup_stale_state(reward_cycle_1.saturating_sub(1))
            .expect("Failed to garbage collect blocks");
        db.cleanup_stale_state(reward_cycle_1)
            .expect("Failed to garbage collect blocks");
        db.cleanup_stale_state(reward_cycle_2)
            .expect("Failed to garbage collect blocks");
        assert!(db.get_signer_state(reward_cycle_1).unwrap().is_some());
        assert!(db.get_signer_state(reward_cycle_2).unwrap().is_some());
        assert!(db.get_signer_state(reward_cycle_3).unwrap().is_some());

        // garbage collection where the current reward cycle is reward_cycle_3 should remove all reward cyles less than reward_cycle_2;
        db.cleanup_stale_state(reward_cycle_3)
            .expect("Failed to garbage collect blocks");
        assert!(db.get_signer_state(reward_cycle_1).unwrap().is_none());
        assert!(db.get_signer_state(reward_cycle_2).unwrap().is_some());
        assert!(db.get_signer_state(reward_cycle_3).unwrap().is_some());

        // garbage collection where the current reward cycle is greater than reward_cycle_3 + 1 should flush the rest of the database
        db.cleanup_stale_state(reward_cycle_3.wrapping_add(2))
            .expect("Failed to garbage collect blocks");
        assert!(db.get_signer_state(reward_cycle_1).unwrap().is_none());
        assert!(db.get_signer_state(reward_cycle_2).unwrap().is_none());
        assert!(db.get_signer_state(reward_cycle_3).unwrap().is_none());
    }

    #[test]
    fn garbage_collect_blocks() {
        let db_path = tmp_db_path();
        let mut db = SignerDb::new(db_path).expect("Failed to create signer db");
        let reward_cycle_1 = 42;
        let reward_cycle_2 = 43;
        let reward_cycle_3 = 44;
        let burn_block_height_1 = 1;
        let burn_block_height_2 = 2;
        let burn_block_height_3 = 3;
        let burn_block_height_4 = 4;
        let (block_info_1, block_proposal_1) = create_block_override(|b| {
            b.block.header.consensus_hash = ConsensusHash([0x10; 20]);
            b.burn_height = burn_block_height_1;
            b.reward_cycle = reward_cycle_1;
        });
        let (block_info_2, block_proposal_2) = create_block_override(|b| {
            b.block.header.consensus_hash = ConsensusHash([0x11; 20]);
            b.burn_height = burn_block_height_2;
            b.reward_cycle = reward_cycle_2;
        });
        let (block_info_3, block_proposal_3) = create_block_override(|b| {
            b.block.header.consensus_hash = ConsensusHash([0x12; 20]);
            b.burn_height = burn_block_height_3;
            b.reward_cycle = reward_cycle_2;
        });
        let (block_info_4, block_proposal_4) = create_block_override(|b| {
            b.block.header.consensus_hash = ConsensusHash([0x13; 20]);
            b.burn_height = burn_block_height_4;
            b.reward_cycle = reward_cycle_3;
        });

        // Insert at least one block for each reward cycle
        db.insert_block(&block_info_1)
            .expect("Unable to insert block into db");
        db.insert_block(&block_info_2)
            .expect("Unable to insert block into db");
        db.insert_block(&block_info_3)
            .expect("Unable to insert block into db");
        db.insert_block(&block_info_4)
            .expect("Unable to insert block into db");

        // garbage collection should only remove blocks if their insertion burn block height is older than POX_REWARD_CYCLE_LENGTHS ago
        // Therefore do not delete anything
        db.cleanup_stale_blocks(0)
            .expect("Failed to garbage collect blocks");
        db.cleanup_stale_blocks(POX_REWARD_CYCLE_LENGTH as u64)
            .expect("Failed to garbage collect blocks");
        db.cleanup_stale_blocks(
            POX_REWARD_CYCLE_LENGTH.wrapping_add(burn_block_height_1 as u32) as u64,
        )
        .expect("Failed to garbage collect blocks");
        assert!(db
            .block_lookup(
                reward_cycle_1,
                &block_proposal_1.block.header.signer_signature_hash()
            )
            .unwrap()
            .is_some());
        assert!(db
            .block_lookup(
                reward_cycle_2,
                &block_proposal_2.block.header.signer_signature_hash()
            )
            .unwrap()
            .is_some());
        assert!(db
            .block_lookup(
                reward_cycle_2,
                &block_proposal_3.block.header.signer_signature_hash()
            )
            .unwrap()
            .is_some());
        assert!(db
            .block_lookup(
                reward_cycle_3,
                &block_proposal_4.block.header.signer_signature_hash()
            )
            .unwrap()
            .is_some());

        // Delete burn block height = 1
        db.cleanup_stale_blocks(
            POX_REWARD_CYCLE_LENGTH.wrapping_add(burn_block_height_2 as u32) as u64,
        )
        .expect("Failed to garbage collect blocks");
        assert!(db
            .block_lookup(
                reward_cycle_1,
                &block_proposal_1.block.header.signer_signature_hash()
            )
            .unwrap()
            .is_none());
        assert!(db
            .block_lookup(
                reward_cycle_2,
                &block_proposal_2.block.header.signer_signature_hash()
            )
            .unwrap()
            .is_some());
        assert!(db
            .block_lookup(
                reward_cycle_2,
                &block_proposal_3.block.header.signer_signature_hash()
            )
            .unwrap()
            .is_some());
        assert!(db
            .block_lookup(
                reward_cycle_3,
                &block_proposal_4.block.header.signer_signature_hash()
            )
            .unwrap()
            .is_some());

        // Delete burn block height = 2
        db.cleanup_stale_blocks(
            POX_REWARD_CYCLE_LENGTH.wrapping_add(burn_block_height_3 as u32) as u64,
        )
        .expect("Failed to garbage collect blocks");
        assert!(db
            .block_lookup(
                reward_cycle_1,
                &block_proposal_1.block.header.signer_signature_hash()
            )
            .unwrap()
            .is_none());
        assert!(db
            .block_lookup(
                reward_cycle_2,
                &block_proposal_2.block.header.signer_signature_hash()
            )
            .unwrap()
            .is_none());
        assert!(db
            .block_lookup(
                reward_cycle_2,
                &block_proposal_3.block.header.signer_signature_hash()
            )
            .unwrap()
            .is_some());
        assert!(db
            .block_lookup(
                reward_cycle_3,
                &block_proposal_4.block.header.signer_signature_hash()
            )
            .unwrap()
            .is_some());

        // Flush everything
        db.cleanup_stale_blocks(POX_REWARD_CYCLE_LENGTH as u64 * 2)
            .expect("Failed to garbage collect blocks");
        assert!(db
            .block_lookup(
                reward_cycle_1,
                &block_proposal_1.block.header.signer_signature_hash()
            )
            .unwrap()
            .is_none());
        assert!(db
            .block_lookup(
                reward_cycle_2,
                &block_proposal_2.block.header.signer_signature_hash()
            )
            .unwrap()
            .is_none());
        assert!(db
            .block_lookup(
                reward_cycle_2,
                &block_proposal_3.block.header.signer_signature_hash()
            )
            .unwrap()
            .is_none());
        assert!(db
            .block_lookup(
                reward_cycle_3,
                &block_proposal_4.block.header.signer_signature_hash()
            )
            .unwrap()
            .is_none());
    }
}
