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
//
use blockstack_lib::chainstate::stacks::StacksTransaction;
use clarity::types::chainstate::StacksPrivateKey;
use libsigner::v1::messages::{MessageSlotID, SignerMessage};
use libsigner::{SignerSession, StackerDBSession};
use libstackerdb::StackerDBChunkAckData;
use slog::{slog_debug, slog_error, slog_warn};
use stacks_common::codec::read_next;
use stacks_common::{debug, error, warn};
use wsts::net::Packet;

use crate::client::stackerdb::StackerDB;
use crate::client::{retry_with_exponential_backoff, ClientError, SignerSlotID};
use crate::config::SignerConfig;

/// The session manager for communicating with the .signers contracts for the current and next reward cycle
#[derive(Debug)]
pub struct StackerDBManager {
    /// The stacker-db transaction msg session for the NEXT reward cycle
    next_transaction_session: StackerDBSession,
    /// The stacker-db sessions for each signer set and message type.
    stackerdb: StackerDB<MessageSlotID>,
}

impl From<&SignerConfig> for StackerDBManager {
    fn from(config: &SignerConfig) -> Self {
        let stackerdb = StackerDB::from(config);
        let next_transaction_session = StackerDBSession::new(
            &config.node_host,
            MessageSlotID::Transactions
                .stacker_db_contract(config.mainnet, config.reward_cycle.wrapping_add(1)),
        );
        Self {
            next_transaction_session,
            stackerdb,
        }
    }
}
impl StackerDBManager {
    /// Create a new StackerDB Manager
    pub fn new(
        host: &str,
        stacks_private_key: StacksPrivateKey,
        is_mainnet: bool,
        reward_cycle: u64,
        signer_slot_id: SignerSlotID,
    ) -> Self {
        let stackerdb = StackerDB::new(
            host,
            stacks_private_key,
            is_mainnet,
            reward_cycle,
            signer_slot_id,
        );
        let next_transaction_session = StackerDBSession::new(
            host,
            MessageSlotID::Transactions
                .stacker_db_contract(is_mainnet, reward_cycle.wrapping_add(1)),
        );
        Self {
            next_transaction_session,
            stackerdb,
        }
    }

    /// Send a message to the stackerdb with retry
    pub fn send_message_with_retry(
        &mut self,
        message: SignerMessage,
    ) -> Result<StackerDBChunkAckData, ClientError> {
        self.stackerdb.send_message_with_retry(message)
    }

    /// Sends message (as a raw msg ID and bytes) to the .signers stacker-db with an
    /// exponential backoff retry
    pub fn send_message_bytes_with_retry(
        &mut self,
        msg_id: &MessageSlotID,
        message_bytes: Vec<u8>,
    ) -> Result<StackerDBChunkAckData, ClientError> {
        self.stackerdb
            .send_message_bytes_with_retry(msg_id, message_bytes)
    }

    /// Get the ordered DKG packets from stackerdb for the signer slot IDs.
    pub fn get_dkg_packets(
        &mut self,
        signer_ids: &[SignerSlotID],
    ) -> Result<Vec<Packet>, ClientError> {
        let packet_slots = &[
            MessageSlotID::DkgBegin,
            MessageSlotID::DkgPublicShares,
            MessageSlotID::DkgPrivateBegin,
            MessageSlotID::DkgPrivateShares,
            MessageSlotID::DkgEndBegin,
            MessageSlotID::DkgEnd,
        ];
        let slot_ids = signer_ids.iter().map(|id| id.0).collect::<Vec<_>>();
        let mut packets = vec![];
        for packet_slot in packet_slots {
            let session = self
                .stackerdb
                .get_session_mut(packet_slot)
                .ok_or(ClientError::NotConnected)?;
            let messages = StackerDB::get_messages(session, &slot_ids)?;
            for message in messages {
                let SignerMessage::Packet(packet) = message else {
                    warn!("Found an unexpected type in a packet slot {packet_slot}");
                    continue;
                };
                packets.push(packet);
            }
        }
        Ok(packets)
    }

    /// Get the transactions from stackerdb for the signers
    fn get_transactions(
        transactions_session: &mut StackerDBSession,
        signer_ids: &[SignerSlotID],
    ) -> Result<Vec<StacksTransaction>, ClientError> {
        let slot_ids = signer_ids.iter().map(|id| id.0).collect::<Vec<_>>();
        let messages = StackerDB::get_messages(transactions_session, &slot_ids)?;
        let mut transactions = vec![];
        for message in messages {
            let SignerMessage::Transactions(chunk_transactions) = message else {
                warn!("Signer wrote an unexpected type to the transactions slot");
                continue;
            };
            transactions.extend(chunk_transactions);
        }
        Ok(transactions)
    }

    /// Get this signer's latest transactions from stackerdb
    pub fn get_current_transactions(&mut self) -> Result<Vec<StacksTransaction>, ClientError> {
        let signer_slot_id = self.get_signer_slot_id();
        let Some(transactions_session) =
            self.stackerdb.get_session_mut(&MessageSlotID::Transactions)
        else {
            return Err(ClientError::NotConnected);
        };
        Self::get_transactions(transactions_session, &[signer_slot_id])
    }

    /// Get the latest signer transactions from signer ids for the next reward cycle
    pub fn get_next_transactions(
        &mut self,
        signer_ids: &[SignerSlotID],
    ) -> Result<Vec<StacksTransaction>, ClientError> {
        debug!("Getting latest chunks from stackerdb for the following signers: {signer_ids:?}",);
        Self::get_transactions(&mut self.next_transaction_session, signer_ids)
    }

    /// Get the encrypted state for the given signer
    pub fn get_encrypted_signer_state(
        &mut self,
        signer_id: SignerSlotID,
    ) -> Result<Option<Vec<u8>>, ClientError> {
        debug!("Getting the persisted encrypted state for signer {signer_id}");
        let Some(state_session) = self
            .stackerdb
            .get_session_mut(&MessageSlotID::EncryptedSignerState)
        else {
            return Err(ClientError::NotConnected);
        };

        let send_request = || {
            state_session
                .get_latest_chunks(&[signer_id.0])
                .map_err(backoff::Error::transient)
        };

        let Some(chunk) = retry_with_exponential_backoff(send_request)?.pop().ok_or(
            ClientError::UnexpectedResponseFormat(format!(
                "Missing response for state session request for signer {}",
                signer_id
            )),
        )?
        else {
            debug!("No persisted state for signer {signer_id}");
            return Ok(None);
        };

        if chunk.is_empty() {
            debug!("Empty persisted state for signer {signer_id}");
            return Ok(None);
        }

        let SignerMessage::EncryptedSignerState(state) =
            read_next::<SignerMessage, _>(&mut chunk.as_slice())?
        else {
            error!("Wrong message type stored in signer state slot for signer {signer_id}");
            return Ok(None);
        };

        Ok(Some(state))
    }

    /// Retrieve the signer set this stackerdb client is attached to
    pub fn get_signer_set(&self) -> u32 {
        self.stackerdb.get_signer_set()
    }

    /// Retrieve the signer slot ID
    pub fn get_signer_slot_id(&self) -> SignerSlotID {
        self.stackerdb.get_signer_slot_id()
    }
}

#[cfg(test)]
mod tests {
    use std::thread::spawn;
    use std::time::Duration;

    use blockstack_lib::chainstate::stacks::{
        TransactionAnchorMode, TransactionAuth, TransactionPayload, TransactionPostConditionMode,
        TransactionSmartContract, TransactionVersion,
    };
    use blockstack_lib::util_lib::strings::StacksString;
    use clarity::codec::StacksMessageCodec;
    use clarity::types::chainstate::StacksPrivateKey;
    use libstackerdb::StackerDBChunkAckData;

    use super::*;
    use crate::client::tests::{generate_signer_config, mock_server_from_config, write_response};
    use crate::config::GlobalConfig;

    #[test]
    fn get_signer_transactions_should_succeed() {
        let config = GlobalConfig::load_from_file("./src/tests/conf/signer-0.toml").unwrap();
        let signer_config = generate_signer_config(&config, 5, 20);
        let mut manager = StackerDBManager::from(&signer_config);
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

        let signer_slot_ids = vec![SignerSlotID(0), SignerSlotID(1)];
        let h = spawn(move || manager.get_next_transactions(&signer_slot_ids));
        let mut response_bytes = b"HTTP/1.1 200 OK\n\n".to_vec();
        response_bytes.extend(message);
        let mock_server = mock_server_from_config(&config);
        write_response(mock_server, response_bytes.as_slice());

        let signer_message = SignerMessage::Transactions(vec![]);
        let message = signer_message.serialize_to_vec();
        let mut response_bytes = b"HTTP/1.1 200 OK\n\n".to_vec();
        response_bytes.extend(message);
        let mock_server = mock_server_from_config(&config);
        write_response(mock_server, response_bytes.as_slice());

        let transactions = h.join().unwrap().unwrap();
        assert_eq!(transactions, vec![tx]);
    }

    #[test]
    fn send_signer_message_should_succeed() {
        let config = GlobalConfig::load_from_file("./src/tests/conf/signer-1.toml").unwrap();
        let signer_config = generate_signer_config(&config, 5, 20);
        let mut stackerdb = StackerDBManager::from(&signer_config);

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

        let signer_message = SignerMessage::Transactions(vec![tx]);
        let ack = StackerDBChunkAckData {
            accepted: true,
            reason: None,
            metadata: None,
            code: None,
        };
        let mock_server = mock_server_from_config(&config);
        let h = spawn(move || stackerdb.send_message_with_retry(signer_message));
        let mut response_bytes = b"HTTP/1.1 200 OK\n\n".to_vec();
        let payload = serde_json::to_string(&ack).expect("Failed to serialize ack");
        response_bytes.extend(payload.as_bytes());
        std::thread::sleep(Duration::from_millis(500));
        write_response(mock_server, response_bytes.as_slice());
        assert_eq!(ack, h.join().unwrap().unwrap());
    }
}
