use std::net::SocketAddr;

use blockstack_lib::chainstate::stacks::boot::make_signers_db_name;
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
use clarity::vm::ContractName;
use hashbrown::HashMap;
use libsigner::{SignerMessage, SignerSession, StackerDBSession, TRANSACTIONS_MSG_ID};
use libstackerdb::{StackerDBChunkAckData, StackerDBChunkData};
use slog::{slog_debug, slog_warn};
use stacks_common::codec::{read_next, StacksMessageCodec};
use stacks_common::consts::SIGNER_SLOTS_PER_USER;
use stacks_common::types::chainstate::{StacksAddress, StacksPrivateKey, StacksPublicKey};
use stacks_common::{debug, warn};

use super::ClientError;
use crate::client::retry_with_exponential_backoff;
use crate::config::Config;

/// The StackerDB client for communicating with the .signers contract
pub struct StackerDB {
    /// The stacker-db session for the signer StackerDB.  Used for querying signer addresses and
    /// other system metadata.
    signers_stackerdb_session: StackerDBSession,
    /// The stacker-db sessions for each signer set and message type.
    /// Maps (signer-set, message ID) to the DB session.
    signers_message_stackerdb_sessions: HashMap<(u32, u32), StackerDBSession>,
    /// The private key used in all stacks node communications
    stacks_private_key: StacksPrivateKey,
    /// A map of a (signer-set, message ID) to last chunk version for each session
    slot_versions: HashMap<(u32, u32), HashMap<u32, u32>>,
    /// The signer ID -- the index into the signer list for this signer daemon's signing key.
    signer_slot_id: u32,
    /// Which signer set to use (0 or 1).
    /// Depends on whether or not we're signing in an even or odd reward cycle
    signer_set: u32,
}

impl From<&Config> for StackerDB {
    fn from(config: &Config) -> Self {
        let mut signers_message_stackerdb_sessions = HashMap::new();
        for signer_set in 0..2 {
            for msg_id in 0..SIGNER_SLOTS_PER_USER {
                signers_message_stackerdb_sessions.insert(
                    (signer_set, msg_id),
                    StackerDBSession::new(
                        config.node_host.clone(),
                        QualifiedContractIdentifier::new(
                            config.stackerdb_contract_id.issuer.clone(),
                            ContractName::from(make_signers_db_name(signer_set, msg_id).as_str()),
                        ),
                    ),
                );
            }
        }
        Self {
            signers_stackerdb_session: StackerDBSession::new(
                config.node_host,
                config.stackerdb_contract_id.clone(),
            ),
            signers_message_stackerdb_sessions,
            stacks_private_key: config.stacks_private_key,
            slot_versions: HashMap::new(),
            signer_slot_id: config.signer_id,
            signer_set: 0,
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
        let mut signers_message_stackerdb_sessions = HashMap::new();
        for signer_set in 0..2 {
            for msg_id in 0..SIGNER_SLOTS_PER_USER {
                signers_message_stackerdb_sessions.insert(
                    (signer_set, msg_id),
                    StackerDBSession::new(
                        host.clone(),
                        QualifiedContractIdentifier::new(
                            stackerdb_contract_id.issuer.clone(),
                            ContractName::from(make_signers_db_name(signer_set, msg_id).as_str()),
                        ),
                    ),
                );
            }
        }
        Self {
            signers_stackerdb_session: StackerDBSession::new(host, stackerdb_contract_id),
            signers_message_stackerdb_sessions,
            stacks_private_key,
            slot_versions: HashMap::new(),
            signer_slot_id: signer_id,
            signer_set: 0,
        }
    }

    /// Sends messages to the .signers stacker-db with an exponential backoff retry
    pub fn send_message_with_retry(
        &mut self,
        message: SignerMessage,
    ) -> Result<StackerDBChunkAckData, ClientError> {
        let message_bytes = message.serialize_to_vec();
        let msg_id = message.msg_id();
        let signer_set = self.signer_set;
        let slot_id = self.signer_slot_id;
        loop {
            let slot_version =
                if let Some(versions) = self.slot_versions.get_mut(&(signer_set, msg_id)) {
                    if let Some(version) = versions.get(&slot_id) {
                        *version
                    } else {
                        versions.insert(slot_id, 0);
                        1
                    }
                } else {
                    let mut versions = HashMap::new();
                    versions.insert(slot_id, 0);
                    self.slot_versions.insert((signer_set, msg_id), versions);
                    1
                };

            let mut chunk = StackerDBChunkData::new(slot_id, slot_version, message_bytes.clone());
            chunk.sign(&self.stacks_private_key)?;

            let Some(session) = self
                .signers_message_stackerdb_sessions
                .get_mut(&(signer_set, msg_id))
            else {
                panic!("FATAL: would loop forever trying to send a message with ID {}, for which we don't have a session", msg_id);
            };

            debug!(
                "Sending a chunk to stackerdb slot ID {slot_id} with version {slot_version} to contract {:?}!\n{:?}",
                &session.stackerdb_contract_id,
                &chunk
            );

            let send_request = || session.put_chunk(&chunk).map_err(backoff::Error::transient);
            let chunk_ack: StackerDBChunkAckData = retry_with_exponential_backoff(send_request)?;

            if let Some(versions) = self.slot_versions.get_mut(&(signer_set, msg_id)) {
                // NOTE: per the above, this is always executed
                versions.insert(slot_id, slot_version.saturating_add(1));
            } else {
                return Err(ClientError::NotConnected);
            }

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
                    if let Some(versions) = self.slot_versions.get_mut(&(signer_set, msg_id)) {
                        // NOTE: per the above, this is always executed
                        versions.insert(slot_id, slot_version.saturating_add(1));
                    } else {
                        return Err(ClientError::NotConnected);
                    }
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
        debug!(
            "Getting latest chunks from stackerdb for the following signers: {:?}",
            signer_ids
        );
        let Some(transactions_session) = self
            .signers_message_stackerdb_sessions
            .get_mut(&(self.signer_set, TRANSACTIONS_MSG_ID))
        else {
            return Err(ClientError::NotConnected);
        };

        let send_request = || {
            transactions_session
                .get_latest_chunks(signer_ids)
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
                if data.len() > 0 {
                    warn!("Failed to deserialize chunk data into a SignerMessage");
                    debug!(
                        "signer #{}: Failed chunk ({}): {:?}",
                        signer_id,
                        &data.len(),
                        &data[..]
                    );
                }
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

    /// Retrieve the signer set this stackerdb client is attached to
    pub fn get_signer_set(&self) -> u32 {
        self.signer_set
    }

    /// Set the signer set from a reward cycle
    pub fn set_signer_set(&mut self, set: u32) {
        self.signer_set = set
    }

    /// Set the signer slot ID
    pub fn set_signer_slot_id(&mut self, slot_id: u32) {
        self.signer_slot_id = slot_id;
    }

    /// Get our signer address
    pub fn get_signer_address(&self, mainnet: bool) -> StacksAddress {
        StacksAddress::p2pkh(
            mainnet,
            &StacksPublicKey::from_private(&self.stacks_private_key),
        )
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
