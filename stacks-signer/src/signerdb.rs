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
    query_row, sqlite_open, table_exists, u64_to_sql, Error as DBError, FromRow,
};
use rusqlite::{params, Connection, Error as SqliteError, OpenFlags, Row, NO_PARAMS};
use serde::Serialize;
use serde_json::Value;
use slog::slog_debug;
use stacks_common::debug;
use stacks_common::util::hash::Sha512Trunc256Sum;
use wsts::net::Packet;
use wsts::state_machine::coordinator::State as CoordinatorState;
use wsts::state_machine::signer::State as SignerState;

use crate::signer::{coordinator_state_to_string, signer_state_to_string, BlockInfo};

/// The Outbound Message info
#[derive(Debug, Serialize, Clone, PartialEq)]
pub struct OutboundMessageInfo {
    /// The messages sent to listening parties
    pub outbound_messages: Vec<Packet>,
    /// the WSTS Coordinator state at the time of sending the outbound messages
    pub coordinator_state: String,
    /// the WSTS Signer state at the time of sending the outbound messages
    pub signer_state: String,
    /// The time at which the messages were stored in the database
    pub insertion_time: chrono::DateTime<chrono::Utc>,
}

impl FromRow<OutboundMessageInfo> for OutboundMessageInfo {
    fn from_row(row: &Row) -> Result<OutboundMessageInfo, DBError> {
        let messages: Value = row.get_unwrap("messages");
        let outbound_messages = messages
            .as_array()
            .map(|values| {
                values
                    .iter()
                    .cloned()
                    .map(serde_json::from_value::<Packet>)
                    .collect::<Result<Vec<_>, serde_json::Error>>()
            })
            .ok_or_else(|| DBError::Corruption)??;
        let coordinator_state: String = row.get_unwrap("coordinator_state");
        let signer_state: String = row.get_unwrap("signer_state");
        let insertion_time: chrono::DateTime<chrono::Utc> = row.get_unwrap("insertion_time");

        Ok(OutboundMessageInfo {
            outbound_messages,
            coordinator_state,
            signer_state,
            insertion_time,
        })
    }
}

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
    encrypted_state BLOB NOT NULL
)";

const CREATE_OUTBOUND_MESSAGES_TABLE: &str = "
CREATE TABLE IF NOT EXISTS outbound_messages (
    insertion_time TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    reward_cycle INTEGER PRIMARY KEY,
    coordinator_state BLOB NOT NULL,
    signer_state BLOB NOT NULL,
    messages BLOB NOT NULL
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

        if !table_exists(&self.db, "outbound_messages")? {
            self.db.execute(CREATE_OUTBOUND_MESSAGES_TABLE, NO_PARAMS)?;
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
            params![&u64_to_sql(reward_cycle)?, &encrypted_signer_state],
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

    /// Insert the outbound messages into the database
    pub fn insert_outbound_messages(
        &self,
        reward_cycle: u64,
        coordinator_state: &CoordinatorState,
        signer_state: &SignerState,
        outbound_messages: &[Packet],
    ) -> Result<(), DBError> {
        let insertion_time = chrono::Utc::now();
        debug!(
            "Inserting {} messages at {insertion_time}.",
            outbound_messages.len()
        );
        let outbound_messages = serde_json::to_string(&outbound_messages)
            .expect("Unable to serialize outbound messages");

        self.db.execute(
            "INSERT OR REPLACE INTO outbound_messages (reward_cycle, coordinator_state, signer_state, messages, insertion_time) VALUES (?1, ?2, ?3, ?4, ?5)",
            params!(u64_to_sql(reward_cycle)?, coordinator_state_to_string(coordinator_state), signer_state_to_string(signer_state), outbound_messages, insertion_time)

        )?;
        Ok(())
    }

    /// lookup the last sent outbound messages
    pub fn outbound_messages_lookup(
        &self,
        reward_cycle: u64,
    ) -> Result<Option<OutboundMessageInfo>, DBError> {
        query_row(
            &self.db,
            "SELECT * FROM outbound_messages WHERE reward_cycle = ?",
            params![&u64_to_sql(reward_cycle)?],
        )
    }

    /// Update the last sent time of the outbound messages
    pub fn update_outbound_messages_time(&self, reward_cycle: u64) -> Result<(), DBError> {
        self.db.execute("UPDATE outbound_messages SET insertion_time = CURRENT_TIMESTAMP WHERE reward_cycle = ?", params!(u64_to_sql(reward_cycle)?))?;
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
    use rand::{thread_rng, RngCore};
    use stacks_common::bitvec::BitVec;
    use stacks_common::types::chainstate::{ConsensusHash, StacksBlockId, TrieHash};
    use stacks_common::util::secp256k1::MessageSignature;
    use wsts::net::{DkgBegin, DkgEnd, DkgPrivateBegin, Message};

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
            block,
            burn_height: 7,
            reward_cycle: 42,
        };
        overrides(&mut block_proposal);
        (BlockInfo::from(block_proposal.clone()), block_proposal)
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
    fn write_and_read_outbound_messages() {
        let db_path = tmp_db_path();
        let db = SignerDb::new(db_path).expect("Failed to create signer db");
        let coordinator_state = CoordinatorState::DkgPrivateGather;
        let signer_state = SignerState::DkgPrivateGather;
        let reward_cycle = 42;
        let mut sig_1 = [0u8; 32];
        thread_rng().fill_bytes(&mut sig_1);
        let mut sig_2 = [0u8; 32];
        thread_rng().fill_bytes(&mut sig_2);
        let outbound_message_1 = Packet {
            msg: Message::DkgBegin(DkgBegin {
                dkg_id: thread_rng().next_u64(),
            }),
            sig: sig_1.to_vec(),
        };
        let outbound_message_2 = Packet {
            msg: Message::DkgPrivateBegin(DkgPrivateBegin {
                dkg_id: thread_rng().next_u64(),
                signer_ids: vec![0, 1],
                key_ids: vec![0, 1, 2, 3],
            }),
            sig: sig_2.to_vec(),
        };
        let outbound_messages = vec![outbound_message_1.clone(), outbound_message_2.clone()];

        // We haven't added anything yet. This should be an empty database
        assert!(db
            .outbound_messages_lookup(reward_cycle)
            .expect("Failed to query empty outbound messages")
            .is_none());

        db.insert_outbound_messages(
            reward_cycle,
            &coordinator_state,
            &signer_state,
            &outbound_messages,
        )
        .expect("Failed to insert outbound messages");

        let coordinator_state_2 = CoordinatorState::DkgEndGather;
        db.insert_outbound_messages(
            reward_cycle.wrapping_add(1),
            &coordinator_state_2,
            &signer_state,
            &outbound_messages,
        )
        .expect("Failed to insert outbound messages");

        let stored_info = db
            .outbound_messages_lookup(reward_cycle)
            .expect("Failed to query outbound messaages")
            .expect("Failed to find outbound messages");
        let insertion_1 = stored_info.insertion_time;
        assert_eq!(stored_info.outbound_messages, outbound_messages);
        assert_eq!(
            stored_info.coordinator_state,
            coordinator_state_to_string(&coordinator_state)
        );
        assert_eq!(
            stored_info.signer_state,
            signer_state_to_string(&signer_state)
        );

        let stored_info = db
            .outbound_messages_lookup(reward_cycle.wrapping_add(1))
            .expect("Failed to query outbound messages")
            .expect("Failed to find outbound messages");
        assert_eq!(stored_info.outbound_messages, outbound_messages);
        assert_eq!(
            stored_info.coordinator_state,
            coordinator_state_to_string(&coordinator_state_2)
        );
        assert_eq!(
            stored_info.signer_state,
            signer_state_to_string(&signer_state)
        );

        db.insert_outbound_messages(
            reward_cycle,
            &coordinator_state,
            &signer_state,
            &outbound_messages,
        )
        .expect("Failed to insert outbound messages");
        let stored_info = db
            .outbound_messages_lookup(reward_cycle)
            .expect("Failed to query outbound messaages")
            .expect("Failed to find outbound messages");
        let insertion_2 = stored_info.insertion_time;
        assert_eq!(stored_info.outbound_messages, outbound_messages);
        assert_eq!(
            stored_info.coordinator_state,
            coordinator_state_to_string(&coordinator_state)
        );
        assert_eq!(
            stored_info.signer_state,
            signer_state_to_string(&signer_state)
        );
        assert_ne!(insertion_1, insertion_2);
    }

    #[test]
    fn update_outbound_messages_time() {
        let db_path = tmp_db_path();
        let db = SignerDb::new(db_path).expect("Failed to create signer db");
        let coordinator_state = CoordinatorState::DkgPrivateGather;
        let signer_state = SignerState::DkgPrivateGather;
        let reward_cycle = 42;
        let mut sig_1 = [0u8; 32];
        thread_rng().fill_bytes(&mut sig_1);
        let mut sig_2 = [0u8; 32];
        thread_rng().fill_bytes(&mut sig_2);
        let outbound_message_1 = Packet {
            msg: Message::DkgEnd(DkgEnd {
                dkg_id: thread_rng().next_u64(),
                signer_id: thread_rng().next_u32(),
                status: wsts::net::DkgStatus::Success,
            }),
            sig: sig_1.to_vec(),
        };
        let outbound_messages = vec![outbound_message_1.clone()];
        // We haven't added anything yet. This should be an empty database
        assert!(db
            .outbound_messages_lookup(reward_cycle)
            .expect("Failed to query empty outbound messages")
            .is_none());

        db.insert_outbound_messages(
            reward_cycle,
            &coordinator_state,
            &signer_state,
            &outbound_messages,
        )
        .expect("Failed to insert outbound messages");
        let stored_info = db
            .outbound_messages_lookup(reward_cycle)
            .expect("Failed to query outbound messaages")
            .expect("Failed to find outbound messages");
        db.update_outbound_messages_time(reward_cycle)
            .expect("Failed to update outbound messages");

        let updated_info = db
            .outbound_messages_lookup(reward_cycle)
            .expect("Failed to query outbound messaages")
            .expect("Failed to find outbound messages");
        assert_ne!(updated_info.insertion_time, stored_info.insertion_time);
    }
}
