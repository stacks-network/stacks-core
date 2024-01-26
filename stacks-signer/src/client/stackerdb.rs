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
use stacks_common::codec::StacksMessageCodec;
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
        }
    }
}

impl StackerDB {
    /// Sends messages to the .signers stacker-db with an exponential backoff retry
    pub fn send_message_with_retry(
        &mut self,
        id: u32,
        message: SignerMessage,
    ) -> Result<StackerDBChunkAckData, ClientError> {
        let message_bytes = message.serialize_to_vec();
        let slot_id = message.slot_id(id);

        loop {
            let slot_version = *self.slot_versions.entry(slot_id).or_insert(0) + 1;
            let mut chunk = StackerDBChunkData::new(slot_id, slot_version, message_bytes.clone());
            chunk.sign(&self.stacks_private_key)?;
            debug!("Sending a chunk to stackerdb!\n{:?}", &chunk);
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
                if reason == "Data for this slot and version already exist" {
                    warn!("Failed to send message to stackerdb due to wrong version number {}. Incrementing and retrying...", slot_version);
                } else {
                    warn!("Failed to send message to stackerdb: {}", reason);
                    return Err(ClientError::PutChunkRejected(reason));
                }
            }
        }
    }

    /// Get the latest signer transactions from signer ids
    // TODO: update to actually retry
    pub fn get_signer_transactions(
        &mut self,
        signer_ids: &[u32],
    ) -> Result<Vec<StacksTransaction>, ClientError> {
        let slot_ids: Vec<_> = signer_ids
            .iter()
            .map(|id| id * SIGNER_SLOTS_PER_USER + TRANSACTIONS_SLOT_ID)
            .collect();

        let mut transactions = Vec::new();
        let chunks = self
            .signers_stackerdb_session
            .get_latest_chunks(&slot_ids)?;
        for chunk in chunks {
            if let Some(data) = chunk {
                let message: SignerMessage = bincode::deserialize(&data).unwrap();
                if let SignerMessage::Transactions(chunk_transactions) = message {
                    transactions.extend(chunk_transactions);
                } else {
                    warn!("Signer wrote an unexpected type to the transactions slot");
                }
            }
        }
        Ok(transactions)
    }
    /// Retrieve the signer contract id
    pub fn signers_contract_id(&self) -> &QualifiedContractIdentifier {
        &self.signers_stackerdb_session.stackerdb_contract_id
    }
}
