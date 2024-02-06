use std::net::SocketAddr;

use blockstack_lib::chainstate::stacks::StacksTransaction;
// Copyright (C) 2013-2020 Blockstack PBC, a public benefit corporation
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
use clarity::vm::types::QualifiedContractIdentifier;
use hashbrown::HashMap;
use libsigner::{
    SignerMessage, SignerSession, StackerDBSession, SIGNER_SLOTS_PER_USER, TRANSACTIONS_SLOT_ID,
};
use libstackerdb::{StackerDBChunkAckData, StackerDBChunkData};
use slog::{slog_debug, slog_warn};
use stacks_common::codec::{read_next, StacksMessageCodec};
use stacks_common::types::chainstate::StacksPrivateKey;
use stacks_common::{debug, warn};

use super::ClientError;
use crate::client::retry_with_exponential_backoff;
use crate::config::Config;

/// The StackerDB client for communicating with the .signers contract
pub struct StackerDB {
    /// The stacker-db session for the signer StackerDB
    signers_stackerdb_session: StackerDBSession,
    /// The private key used in all stacks node communications
    stacks_private_key: StacksPrivateKey,
    /// A map of a slot ID to last chunk version
    slot_versions: HashMap<u32, u32>,
    /// The signer ID
    signer_id: u32,
}

impl From<&Config> for StackerDB {
    fn from(config: &Config) -> Self {
        Self {
            signers_stackerdb_session: StackerDBSession::new(
                config.node_host,
                config.stackerdb_contract_id.clone(),
            ),
            stacks_private_key: config.stacks_private_key,
            slot_versions: HashMap::new(),
            signer_id: config.signer_id,
        }
    }
}

impl StackerDB {
    /// Create a new StackerDB client
    pub fn new(
        host: SocketAddr,
        stackerdb_contract_id: QualifiedContractIdentifier,
        stacks_private_key: StacksPrivateKey,
        signer_id: u32,
    ) -> Self {
        Self {
            signers_stackerdb_session: StackerDBSession::new(host, stackerdb_contract_id),
            stacks_private_key,
            slot_versions: HashMap::new(),
            signer_id,
        }
    }

    /// Sends messages to the .signers stacker-db with an exponential backoff retry
    pub fn send_message_with_retry(
        &mut self,
        message: SignerMessage,
    ) -> Result<StackerDBChunkAckData, ClientError> {
        let message_bytes = message.serialize_to_vec();
        let slot_id = message.slot_id(self.signer_id);

        loop {
            let slot_version = *self.slot_versions.entry(slot_id).or_insert(0) + 1;
            let mut chunk = StackerDBChunkData::new(slot_id, slot_version, message_bytes.clone());
            chunk.sign(&self.stacks_private_key)?;
            debug!(
                "Sending a chunk to stackerdb slot ID {slot_id} with version {slot_version}!\n{:?}",
                &chunk
            );
            let send_request = || {
                self.signers_stackerdb_session
                    .put_chunk(&chunk)
                    .map_err(backoff::Error::transient)
            };
            let chunk_ack: StackerDBChunkAckData = retry_with_exponential_backoff(send_request)?;
            self.slot_versions.insert(slot_id, slot_version);

            if chunk_ack.accepted {
                debug!("Chunk accepted by stackerdb: {:?}", chunk_ack);
                return Ok(chunk_ack);
            } else {
                warn!("Chunk rejected by stackerdb: {:?}", chunk_ack);
            }
            if let Some(reason) = chunk_ack.reason {
                // TODO: fix this jankiness. Update stackerdb to use an error code mapping instead of just a string
                // See: https://github.com/stacks-network/stacks-blockchain/issues/3917
                if reason.contains("Data for this slot and version already exist") {
                    warn!("Failed to send message to stackerdb due to wrong version number {}. Incrementing and retrying...", slot_version);
                } else {
                    warn!("Failed to send message to stackerdb: {}", reason);
                    return Err(ClientError::PutChunkRejected(reason));
                }
            }
        }
    }

    /// Get the latest signer transactions from signer ids
    pub fn get_signer_transactions_with_retry(
        &mut self,
        signer_ids: &[u32],
    ) -> Result<Vec<StacksTransaction>, ClientError> {
        let slot_ids: Vec<_> = signer_ids
            .iter()
            .map(|id| id * SIGNER_SLOTS_PER_USER + TRANSACTIONS_SLOT_ID)
            .collect();
        debug!(
            "Getting latest chunks from stackerdb for the following signers: {:?}",
            signer_ids
        );
        let send_request = || {
            self.signers_stackerdb_session
                .get_latest_chunks(&slot_ids)
                .map_err(backoff::Error::transient)
        };
        let chunk_ack = retry_with_exponential_backoff(send_request)?;
        let mut transactions = Vec::new();
        for (i, chunk) in chunk_ack.iter().enumerate() {
            let signer_id = *signer_ids
                .get(i)
                .expect("BUG: retrieved an unequal amount of chunks to requested chunks");
            let Some(data) = chunk else {
                continue;
            };
            let Ok(message) = read_next::<SignerMessage, _>(&mut &data[..]) else {
                warn!("Failed to deserialize chunk data into a SignerMessage");
                continue;
            };

            let SignerMessage::Transactions(chunk_transactions) = message else {
                warn!("Signer wrote an unexpected type to the transactions slot");
                continue;
            };
            debug!(
                "Retrieved {} transactions from signer ID {}.",
                chunk_transactions.len(),
                signer_id
            );
            transactions.extend(chunk_transactions);
        }
        Ok(transactions)
    }

    /// Retrieve the signer contract id
    pub fn signers_contract_id(&self) -> &QualifiedContractIdentifier {
        &self.signers_stackerdb_session.stackerdb_contract_id
    }
}

#[cfg(test)]
mod tests {
    use std::thread::spawn;

    use blockstack_lib::chainstate::stacks::{
        TransactionAnchorMode, TransactionAuth, TransactionPayload, TransactionPostConditionMode,
        TransactionSmartContract, TransactionVersion,
    };
    use blockstack_lib::util_lib::strings::StacksString;
    use serial_test::serial;

    use super::*;
    use crate::client::tests::{write_response, TestConfig};

    #[test]
    #[serial]
    fn get_signer_transactions_with_retry_should_succeed() {
        let mut config = TestConfig::new();
        let sk = StacksPrivateKey::new();
        let tx = StacksTransaction {
            version: TransactionVersion::Testnet,
            chain_id: 0,
            auth: TransactionAuth::from_p2pkh(&sk).unwrap(),
            anchor_mode: TransactionAnchorMode::Any,
            post_condition_mode: TransactionPostConditionMode::Allow,
            post_conditions: vec![],
            payload: TransactionPayload::SmartContract(
                TransactionSmartContract {
                    name: "test-contract".into(),
                    code_body: StacksString::from_str("(/ 1 0)").unwrap(),
                },
                None,
            ),
        };

        let signer_message = SignerMessage::Transactions(vec![tx.clone()]);
        let message = signer_message.serialize_to_vec();

        let signer_ids = vec![0, 1];
        let h = spawn(move || {
            config
                .stackerdb
                .get_signer_transactions_with_retry(&signer_ids)
        });
        let mut response_bytes = b"HTTP/1.1 200 OK\n\n".to_vec();
        response_bytes.extend(message);
        write_response(config.mock_server, response_bytes.as_slice());

        let signer_message = SignerMessage::Transactions(vec![]);
        let message = signer_message.serialize_to_vec();
        let test_config = TestConfig::from_config(config.config);
        let mut response_bytes = b"HTTP/1.1 200 OK\n\n".to_vec();
        response_bytes.extend(message);
        write_response(test_config.mock_server, response_bytes.as_slice());

        let transactions = h.join().unwrap().unwrap();
        assert_eq!(transactions, vec![tx]);
    }

    #[test]
    #[serial]
    fn send_signer_message_with_retry_should_succeed() {
        let mut config = TestConfig::new();
        let sk = StacksPrivateKey::new();
        let tx = StacksTransaction {
            version: TransactionVersion::Testnet,
            chain_id: 0,
            auth: TransactionAuth::from_p2pkh(&sk).unwrap(),
            anchor_mode: TransactionAnchorMode::Any,
            post_condition_mode: TransactionPostConditionMode::Allow,
            post_conditions: vec![],
            payload: TransactionPayload::SmartContract(
                TransactionSmartContract {
                    name: "test-contract".into(),
                    code_body: StacksString::from_str("(/ 1 0)").unwrap(),
                },
                None,
            ),
        };

        let signer_message = SignerMessage::Transactions(vec![tx.clone()]);
        let ack = StackerDBChunkAckData {
            accepted: true,
            reason: None,
            metadata: None,
        };
        let mut response_bytes = b"HTTP/1.1 200 OK\n\n".to_vec();
        let payload = serde_json::to_string(&ack).expect("Failed to serialize ack");
        response_bytes.extend(payload.as_bytes());
        let h = spawn(move || config.stackerdb.send_message_with_retry(signer_message));
        std::thread::sleep(std::time::Duration::from_millis(100));
        write_response(config.mock_server, response_bytes.as_slice());
        assert_eq!(ack, h.join().unwrap().unwrap());
    }
}
