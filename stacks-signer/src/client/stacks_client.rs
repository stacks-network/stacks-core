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
use blockstack_lib::burnchains::Txid;
use blockstack_lib::chainstate::nakamoto::NakamotoBlock;
use blockstack_lib::chainstate::stacks::boot::{RewardSet, POX_4_NAME, SIGNERS_VOTING_NAME};
use blockstack_lib::chainstate::stacks::{
    StacksTransaction, StacksTransactionSigner, TransactionAnchorMode, TransactionAuth,
    TransactionContractCall, TransactionPayload, TransactionPostConditionMode,
    TransactionSpendingCondition, TransactionVersion,
};
use blockstack_lib::net::api::callreadonly::CallReadOnlyResponse;
use blockstack_lib::net::api::getaccount::AccountEntryResponse;
use blockstack_lib::net::api::getinfo::RPCPeerInfoData;
use blockstack_lib::net::api::getpoxinfo::RPCPoxInfoData;
use blockstack_lib::net::api::getstackers::GetStackersResponse;
use blockstack_lib::net::api::postblock_proposal::NakamotoBlockProposal;
use blockstack_lib::util_lib::boot::{boot_code_addr, boot_code_id};
use clarity::vm::types::{PrincipalData, QualifiedContractIdentifier};
use clarity::vm::{ClarityName, ContractName, Value as ClarityValue, Value};
use serde_json::json;
use slog::slog_debug;
use stacks_common::codec::StacksMessageCodec;
use stacks_common::consts::CHAIN_ID_MAINNET;
use stacks_common::debug;
use stacks_common::types::chainstate::{
    ConsensusHash, StacksAddress, StacksPrivateKey, StacksPublicKey,
};
use stacks_common::types::StacksEpochId;
use stacks_common::util::hash::Sha256Sum;
use wsts::curve::ecdsa;
use wsts::curve::point::{Compressed, Point};
use wsts::state_machine::PublicKeys;

use crate::client::{retry_with_exponential_backoff, ClientError};
use crate::config::GlobalConfig;

/// The name of the function for casting a DKG result to signer vote contract
pub const VOTE_FUNCTION_NAME: &str = "vote-for-aggregate-public-key";

/// The Stacks signer client used to communicate with the stacks node
#[derive(Clone, Debug)]
pub struct StacksClient {
    /// The stacks address of the signer
    stacks_address: StacksAddress,
    /// The private key used in all stacks node communications
    stacks_private_key: StacksPrivateKey,
    /// The stacks node HTTP base endpoint
    http_origin: String,
    /// The types of transactions
    tx_version: TransactionVersion,
    /// The chain we are interacting with
    chain_id: u32,
    /// The Client used to make HTTP connects
    stacks_node_client: reqwest::blocking::Client,
    /// The stx transaction fee to use in microstacks
    tx_fee: u64,
}

impl From<&GlobalConfig> for StacksClient {
    fn from(config: &GlobalConfig) -> Self {
        Self {
            stacks_private_key: config.stacks_private_key,
            stacks_address: config.stacks_address,
            http_origin: format!("http://{}", config.node_host),
            tx_version: config.network.to_transaction_version(),
            chain_id: config.network.to_chain_id(),
            stacks_node_client: reqwest::blocking::Client::new(),
            tx_fee: config.tx_fee,
        }
    }
}

impl StacksClient {
    /// Get our signer address
    pub fn get_signer_address(&self) -> &StacksAddress {
        &self.stacks_address
    }

    /// Calculate the coordinator address by comparing the provided public keys against the stacks tip consensus hash
    pub fn calculate_coordinator(&self, public_keys: &PublicKeys) -> (u32, ecdsa::PublicKey) {
        let stacks_tip_consensus_hash =
            match retry_with_exponential_backoff(|| {
                self.get_stacks_tip_consensus_hash()
                    .map_err(backoff::Error::transient)
            }) {
                Ok(hash) => hash,
                Err(e) => {
                    debug!("Failed to get stacks tip consensus hash: {e:?}");
                    return (
                        0,
                        public_keys.signers.get(&0).cloned().expect(
                            "FATAL: No public keys found. Signer was not properly registered",
                        ),
                    );
                }
            };
        debug!(
            "Using stacks_tip_consensus_hash {stacks_tip_consensus_hash:?} for selecting coordinator"
        );

        // Create combined hash of each signer's public key with stacks_tip_consensus_hash
        let mut selection_ids = public_keys
            .signers
            .iter()
            .map(|(&id, pk)| {
                let pk_bytes = pk.to_bytes();
                let mut buffer =
                    Vec::with_capacity(pk_bytes.len() + stacks_tip_consensus_hash.as_bytes().len());
                buffer.extend_from_slice(&pk_bytes[..]);
                buffer.extend_from_slice(stacks_tip_consensus_hash.as_bytes());
                let digest = Sha256Sum::from_data(&buffer).as_bytes().to_vec();
                (digest, id)
            })
            .collect::<Vec<_>>();

        // Sort the selection IDs based on the hash
        selection_ids.sort_by_key(|(hash, _)| hash.clone());

        // Get the first ID from the sorted list and retrieve its public key,
        // or default to the first signer if none are found
        selection_ids
            .first()
            .and_then(|(_, id)| public_keys.signers.get(id).map(|pk| (*id, *pk)))
            .expect("FATAL: No public keys found. Signer was not properly registered")
    }

    /// Retrieve the signer slots stored within the stackerdb contract
    pub fn get_stackerdb_signer_slots(
        &self,
        stackerdb_contract: &QualifiedContractIdentifier,
        page: u32,
    ) -> Result<Vec<(StacksAddress, u128)>, ClientError> {
        let function_name_str = "stackerdb-get-signer-slots-page";
        let function_name = ClarityName::from(function_name_str);
        let function_args = &[Value::UInt(page.into())];
        let value = self.read_only_contract_call(
            &stackerdb_contract.issuer.clone().into(),
            &stackerdb_contract.name,
            &function_name,
            function_args,
        )?;
        self.parse_signer_slots(value)
    }

    /// Helper function  that attempts to deserialize a clarity hext string as a list of signer slots and their associated number of signer slots
    fn parse_signer_slots(
        &self,
        value: ClarityValue,
    ) -> Result<Vec<(StacksAddress, u128)>, ClientError> {
        debug!("Parsing signer slots...");
        // Due to .signers definition, the  signer slots is always an OK result of a list of tuples of signer addresses and the number of slots they have
        // If this fails, we have bigger problems than the signer crashing...
        let value = value.clone().expect_result_ok()?;
        let values = value.expect_list()?;
        let mut signer_slots = Vec::with_capacity(values.len());
        for value in values {
            let tuple_data = value.expect_tuple()?;
            let principal_data = tuple_data.get("signer")?.clone().expect_principal()?;
            let signer = if let PrincipalData::Standard(signer) = principal_data {
                signer.into()
            } else {
                panic!("BUG: Signers stackerdb contract is corrupted");
            };
            let num_slots = tuple_data.get("num-slots")?.clone().expect_u128()?;
            signer_slots.push((signer, num_slots));
        }
        Ok(signer_slots)
    }

    /// Retrieve the stacks tip consensus hash from the stacks node
    pub fn get_stacks_tip_consensus_hash(&self) -> Result<ConsensusHash, ClientError> {
        let peer_info = self.get_peer_info()?;
        Ok(peer_info.stacks_tip_consensus_hash)
    }

    /// Determine the stacks node current epoch
    pub fn get_node_epoch(&self) -> Result<StacksEpochId, ClientError> {
        let pox_info = self.get_pox_data()?;
        let burn_block_height = self.get_burn_block_height()?;

        let epoch_25 = pox_info
            .epochs
            .iter()
            .find(|epoch| epoch.epoch_id == StacksEpochId::Epoch25)
            .ok_or(ClientError::UnsupportedStacksFeature(
                "/v2/pox must report epochs".into(),
            ))?;

        let epoch_30 = pox_info
            .epochs
            .iter()
            .find(|epoch| epoch.epoch_id == StacksEpochId::Epoch30)
            .ok_or(ClientError::UnsupportedStacksFeature(
                "/v2/pox mut report epochs".into(),
            ))?;

        if burn_block_height < epoch_25.start_height {
            Ok(StacksEpochId::Epoch24)
        } else if burn_block_height < epoch_30.start_height {
            Ok(StacksEpochId::Epoch25)
        } else {
            Ok(StacksEpochId::Epoch30)
        }
    }

    /// Submit the block proposal to the stacks node. The block will be validated and returned via the HTTP endpoint for Block events.
    pub fn submit_block_for_validation(&self, block: NakamotoBlock) -> Result<(), ClientError> {
        let block_proposal = NakamotoBlockProposal {
            block,
            chain_id: self.chain_id,
        };
        let send_request = || {
            self.stacks_node_client
                .post(self.block_proposal_path())
                .header("Content-Type", "application/json")
                .json(&block_proposal)
                .send()
                .map_err(backoff::Error::transient)
        };

        let response = retry_with_exponential_backoff(send_request)?;
        if !response.status().is_success() {
            return Err(ClientError::RequestFailure(response.status()));
        }
        Ok(())
    }

    /// Retrieve the DKG aggregate public key for the given reward cycle
    pub fn get_aggregate_public_key(
        &self,
        reward_cycle: u64,
    ) -> Result<Option<Point>, ClientError> {
        let function_name = ClarityName::from("get-aggregate-public-key");
        let pox_contract_id = boot_code_id(POX_4_NAME, self.chain_id == CHAIN_ID_MAINNET);
        let function_args = &[ClarityValue::UInt(reward_cycle as u128)];
        let value = self.read_only_contract_call(
            &pox_contract_id.issuer.into(),
            &pox_contract_id.name,
            &function_name,
            function_args,
        )?;
        self.parse_aggregate_public_key(value)
    }

    /// Retrieve the current account nonce for the provided address
    pub fn get_account_nonce(&self, address: &StacksAddress) -> Result<u64, ClientError> {
        let account_entry = self.get_account_entry(address)?;
        Ok(account_entry.nonce)
    }

    // Helper function to retrieve the peer info data from the stacks node
    fn get_peer_info(&self) -> Result<RPCPeerInfoData, ClientError> {
        debug!("Getting stacks node info...");
        let send_request = || {
            self.stacks_node_client
                .get(self.core_info_path())
                .send()
                .map_err(backoff::Error::transient)
        };
        let response = retry_with_exponential_backoff(send_request)?;
        if !response.status().is_success() {
            return Err(ClientError::RequestFailure(response.status()));
        }
        let peer_info_data = response.json::<RPCPeerInfoData>()?;
        Ok(peer_info_data)
    }

    /// Retrieve the last DKG vote round number for the current reward cycle
    pub fn get_last_round(&self, reward_cycle: u64) -> Result<u64, ClientError> {
        debug!("Getting the last DKG vote round of reward cycle {reward_cycle}...");
        let contract_addr = boot_code_addr(self.chain_id == CHAIN_ID_MAINNET);
        let contract_name = ContractName::from(SIGNERS_VOTING_NAME);
        let function_name = ClarityName::from("get-last-round");
        let function_args = &[ClarityValue::UInt(reward_cycle as u128)];
        let last_round = u64::try_from(
            self.read_only_contract_call(
                &contract_addr,
                &contract_name,
                &function_name,
                function_args,
            )?
            .expect_result_ok()?
            .expect_u128()?,
        )
        .map_err(|e| {
            ClientError::MalformedContractData(format!("Failed to convert vote round to u64: {e}"))
        })?;
        Ok(last_round)
    }

    /// Retrieve the vote of the signer for the given round
    pub fn get_signer_vote(&self, round: u128) -> Result<Option<Point>, ClientError> {
        let reward_cycle = ClarityValue::UInt(self.get_current_reward_cycle()? as u128);
        let round = ClarityValue::UInt(round);
        let signer = ClarityValue::Principal(self.stacks_address.into());
        let contract_addr = boot_code_addr(self.chain_id == CHAIN_ID_MAINNET);
        let contract_name = ContractName::from(SIGNERS_VOTING_NAME);
        let function = ClarityName::from("get-vote");
        let function_args = &[reward_cycle, round, signer];
        let value =
            self.read_only_contract_call(&contract_addr, &contract_name, &function, function_args)?;
        self.parse_aggregate_public_key(value)
    }

    /// Get whether the reward set has been determined for the provided reward cycle.
    /// i.e the node has passed the first block of the new reward cycle's prepare phase
    pub fn reward_set_calculated(&self, reward_cycle: u64) -> Result<bool, ClientError> {
        let pox_info = self.get_pox_data()?;
        let current_reward_cycle = pox_info.reward_cycle_id;
        if current_reward_cycle >= reward_cycle {
            // We have already entered into this reward cycle or beyond
            // therefore the reward set has already been calculated
            return Ok(true);
        }
        if current_reward_cycle.wrapping_add(1) != reward_cycle {
            // We are not in the prepare phase of the reward cycle as the upcoming cycle nor are we in the current reward cycle...
            return Ok(false);
        }
        let burn_block_height = self.get_burn_block_height()?;
        // Have we passed the first block of the new reward cycle's prepare phase?
        Ok(pox_info.next_cycle.prepare_phase_start_block_height < burn_block_height)
    }

    /// Get the reward set from the stacks node for the given reward cycle
    pub fn get_reward_set(&self, reward_cycle: u64) -> Result<RewardSet, ClientError> {
        debug!("Getting reward set for reward cycle {reward_cycle}...");
        let send_request = || {
            self.stacks_node_client
                .get(self.reward_set_path(reward_cycle))
                .send()
                .map_err(backoff::Error::transient)
        };
        let response = retry_with_exponential_backoff(send_request)?;
        if !response.status().is_success() {
            return Err(ClientError::RequestFailure(response.status()));
        }
        let stackers_response = response.json::<GetStackersResponse>()?;
        Ok(stackers_response.stacker_set)
    }

    // Helper function to retrieve the pox data from the stacks node
    fn get_pox_data(&self) -> Result<RPCPoxInfoData, ClientError> {
        debug!("Getting pox data...");
        let send_request = || {
            self.stacks_node_client
                .get(self.pox_path())
                .send()
                .map_err(backoff::Error::transient)
        };
        let response = retry_with_exponential_backoff(send_request)?;
        if !response.status().is_success() {
            return Err(ClientError::RequestFailure(response.status()));
        }
        let pox_info_data = response.json::<RPCPoxInfoData>()?;
        Ok(pox_info_data)
    }

    /// Helper function to retrieve the burn tip height from the stacks node
    fn get_burn_block_height(&self) -> Result<u64, ClientError> {
        let peer_info = self.get_peer_info()?;
        Ok(peer_info.burn_block_height)
    }

    /// Get the current reward cycle from the stacks node
    pub fn get_current_reward_cycle(&self) -> Result<u64, ClientError> {
        let pox_data = self.get_pox_data()?;
        Ok(pox_data.reward_cycle_id)
    }

    /// Helper function to retrieve the account info from the stacks node for a specific address
    fn get_account_entry(
        &self,
        address: &StacksAddress,
    ) -> Result<AccountEntryResponse, ClientError> {
        debug!("Getting account info...");
        let send_request = || {
            self.stacks_node_client
                .get(self.accounts_path(address))
                .send()
                .map_err(backoff::Error::transient)
        };
        let response = retry_with_exponential_backoff(send_request)?;
        if !response.status().is_success() {
            return Err(ClientError::RequestFailure(response.status()));
        }
        let account_entry = response.json::<AccountEntryResponse>()?;
        Ok(account_entry)
    }

    /// Helper function that attempts to deserialize a clarity hex string as the aggregate public key
    fn parse_aggregate_public_key(
        &self,
        value: ClarityValue,
    ) -> Result<Option<Point>, ClientError> {
        debug!("Parsing aggregate public key...");
        // Due to pox 4 definition, the aggregate public key is always an optional clarity value of 33 bytes hence the use of expect
        // If this fails, we have bigger problems than the signer crashing...
        let opt = value.clone().expect_optional()?;
        let Some(inner_data) = opt else {
            return Ok(None);
        };
        let data = inner_data.expect_buff(33)?;
        // It is possible that the point was invalid though when voted upon and this cannot be prevented by pox 4 definitions...
        // Pass up this error if the conversions fail.
        let compressed_data = Compressed::try_from(data.as_slice()).map_err(|e| {
            ClientError::MalformedClarityValue(format!(
                "Failed to convert aggregate public key to compressed data: {e}"
            ))
        })?;
        let point = Point::try_from(&compressed_data).map_err(|e| {
            ClientError::MalformedClarityValue(format!(
                "Failed to convert aggregate public key to a point: {e}"
            ))
        })?;
        Ok(Some(point))
    }

    /// Cast a vote for the given aggregate public key by broadcasting it to the mempool
    pub fn cast_vote_for_aggregate_public_key(
        &self,
        reward_cycle: u64,
        signer_index: u32,
        point: Point,
    ) -> Result<StacksTransaction, ClientError> {
        debug!("Casting vote for aggregate public key to the mempool...");
        let signed_tx =
            self.build_vote_for_aggregate_public_key(reward_cycle, signer_index, point)?;
        self.submit_tx(&signed_tx)?;
        Ok(signed_tx)
    }

    /// Helper function to create a stacks transaction for a modifying contract call
    pub fn build_vote_for_aggregate_public_key(
        &self,
        reward_cycle: u64,
        signer_index: u32,
        point: Point,
    ) -> Result<StacksTransaction, ClientError> {
        debug!("Building {VOTE_FUNCTION_NAME} transaction...");
        let round = self.get_last_round(reward_cycle)?;
        // TODO: this nonce should be calculated on the side as we may have pending transactions that are not yet confirmed...
        let nonce = self.get_account_nonce(&self.stacks_address)?;
        let contract_address = boot_code_addr(self.chain_id == CHAIN_ID_MAINNET);
        let contract_name = ContractName::from(POX_4_NAME); //TODO update this to POX_4_VOTE_NAME when the contract is deployed
        let function_name = ClarityName::from(VOTE_FUNCTION_NAME);
        let function_args = &[
            ClarityValue::UInt(signer_index as u128),
            ClarityValue::UInt(round as u128),
            ClarityValue::buff_from(point.compress().as_bytes().to_vec())?,
        ];

        let tx_payload = TransactionPayload::ContractCall(TransactionContractCall {
            address: contract_address,
            contract_name,
            function_name,
            function_args: function_args.to_vec(),
        });
        let public_key = StacksPublicKey::from_private(&self.stacks_private_key);
        let tx_auth = TransactionAuth::Standard(
            TransactionSpendingCondition::new_singlesig_p2pkh(public_key).ok_or(
                ClientError::TransactionGenerationFailure(format!(
                    "Failed to create spending condition from public key: {}",
                    public_key.to_hex()
                )),
            )?,
        );

        let mut unsigned_tx = StacksTransaction::new(self.tx_version, tx_auth, tx_payload);
        unsigned_tx.set_tx_fee(self.tx_fee);
        unsigned_tx.set_origin_nonce(nonce);

        unsigned_tx.anchor_mode = TransactionAnchorMode::Any;
        unsigned_tx.post_condition_mode = TransactionPostConditionMode::Allow;
        unsigned_tx.chain_id = self.chain_id;

        let mut tx_signer = StacksTransactionSigner::new(&unsigned_tx);
        tx_signer
            .sign_origin(&self.stacks_private_key)
            .map_err(|e| ClientError::TransactionGenerationFailure(e.to_string()))?;

        tx_signer
            .get_tx()
            .ok_or(ClientError::TransactionGenerationFailure(
                "Failed to generate transaction from a transaction signer".to_string(),
            ))
    }

    /// Helper function to submit a transaction to the Stacks node
    fn submit_tx(&self, tx: &StacksTransaction) -> Result<Txid, ClientError> {
        let txid = tx.txid();
        let tx = tx.serialize_to_vec();
        let send_request = || {
            self.stacks_node_client
                .post(self.transaction_path())
                .header("Content-Type", "application/octet-stream")
                .body(tx.clone())
                .send()
                .map_err(backoff::Error::transient)
        };
        let response = retry_with_exponential_backoff(send_request)?;
        if !response.status().is_success() {
            return Err(ClientError::RequestFailure(response.status()));
        }
        Ok(txid)
    }

    /// Makes a read only contract call to a stacks contract
    pub fn read_only_contract_call(
        &self,
        contract_addr: &StacksAddress,
        contract_name: &ContractName,
        function_name: &ClarityName,
        function_args: &[ClarityValue],
    ) -> Result<ClarityValue, ClientError> {
        debug!("Calling read-only function {function_name} with args {function_args:?}...");
        let args = function_args
            .iter()
            .filter_map(|arg| arg.serialize_to_hex().ok())
            .collect::<Vec<String>>();
        if args.len() != function_args.len() {
            return Err(ClientError::ReadOnlyFailure(
                "Failed to serialize Clarity function arguments".into(),
            ));
        }

        let body =
            json!({"sender": self.stacks_address.to_string(), "arguments": args}).to_string();
        let path = self.read_only_path(contract_addr, contract_name, function_name);
        let response = self
            .stacks_node_client
            .post(path.clone())
            .header("Content-Type", "application/json")
            .body(body.clone())
            .send()?;
        if !response.status().is_success() {
            return Err(ClientError::RequestFailure(response.status()));
        }
        let call_read_only_response = response.json::<CallReadOnlyResponse>()?;
        if !call_read_only_response.okay {
            return Err(ClientError::ReadOnlyFailure(format!(
                "{function_name}: {}",
                call_read_only_response
                    .cause
                    .unwrap_or("unknown".to_string())
            )));
        }
        let hex = call_read_only_response.result.unwrap_or_default();
        let value = ClarityValue::try_deserialize_hex_untyped(&hex)?;
        Ok(value)
    }

    fn pox_path(&self) -> String {
        format!("{}/v2/pox", self.http_origin)
    }

    fn transaction_path(&self) -> String {
        format!("{}/v2/transactions", self.http_origin)
    }

    fn read_only_path(
        &self,
        contract_addr: &StacksAddress,
        contract_name: &ContractName,
        function_name: &ClarityName,
    ) -> String {
        format!(
            "{}/v2/contracts/call-read/{contract_addr}/{contract_name}/{function_name}",
            self.http_origin
        )
    }

    fn block_proposal_path(&self) -> String {
        format!("{}/v2/block_proposal", self.http_origin)
    }

    fn core_info_path(&self) -> String {
        format!("{}/v2/info", self.http_origin)
    }

    fn accounts_path(&self, stacks_address: &StacksAddress) -> String {
        format!("{}/v2/accounts/{stacks_address}?proof=0", self.http_origin)
    }

    fn reward_set_path(&self, reward_cycle: u64) -> String {
        format!("{}/v2/stacker_set/{reward_cycle}", self.http_origin)
    }

    /// Helper function to create a stacks transaction for a modifying contract call
    #[allow(clippy::too_many_arguments)]
    pub fn build_signed_contract_call_transaction(
        contract_addr: &StacksAddress,
        contract_name: ContractName,
        function_name: ClarityName,
        function_args: &[ClarityValue],
        stacks_private_key: &StacksPrivateKey,
        tx_version: TransactionVersion,
        chain_id: u32,
        nonce: u64,
        tx_fee: u64,
    ) -> Result<StacksTransaction, ClientError> {
        let tx_payload = TransactionPayload::ContractCall(TransactionContractCall {
            address: *contract_addr,
            contract_name,
            function_name,
            function_args: function_args.to_vec(),
        });
        let public_key = StacksPublicKey::from_private(stacks_private_key);
        let tx_auth = TransactionAuth::Standard(
            TransactionSpendingCondition::new_singlesig_p2pkh(public_key).ok_or(
                ClientError::TransactionGenerationFailure(format!(
                    "Failed to create spending condition from public key: {}",
                    public_key.to_hex()
                )),
            )?,
        );

        let mut unsigned_tx = StacksTransaction::new(tx_version, tx_auth, tx_payload);

        unsigned_tx.set_tx_fee(tx_fee);
        unsigned_tx.set_origin_nonce(nonce);

        unsigned_tx.anchor_mode = TransactionAnchorMode::Any;
        unsigned_tx.post_condition_mode = TransactionPostConditionMode::Allow;
        unsigned_tx.chain_id = chain_id;

        let mut tx_signer = StacksTransactionSigner::new(&unsigned_tx);
        tx_signer
            .sign_origin(stacks_private_key)
            .map_err(|e| ClientError::TransactionGenerationFailure(e.to_string()))?;

        tx_signer
            .get_tx()
            .ok_or(ClientError::TransactionGenerationFailure(
                "Failed to generate transaction from a transaction signer".to_string(),
            ))
    }
}

#[cfg(test)]
mod tests {
    use std::io::{BufWriter, Write};
    use std::thread::spawn;

    use blockstack_lib::chainstate::nakamoto::NakamotoBlockHeader;
    use blockstack_lib::chainstate::stacks::address::PoxAddress;
    use blockstack_lib::chainstate::stacks::boot::{NakamotoSignerEntry, PoxStartCycleInfo};
    use blockstack_lib::chainstate::stacks::ThresholdSignature;
    use rand::thread_rng;
    use rand_core::RngCore;
    use serial_test::serial;
    use stacks_common::bitvec::BitVec;
    use stacks_common::consts::{CHAIN_ID_TESTNET, SIGNER_SLOTS_PER_USER};
    use stacks_common::types::chainstate::{StacksBlockId, TrieHash};
    use stacks_common::types::StacksEpochId;
    use stacks_common::util::hash::Sha512Trunc256Sum;
    use stacks_common::util::secp256k1::MessageSignature;
    use wsts::curve::scalar::Scalar;

    use super::*;
    use crate::client::tests::{
        build_account_nonce_response, build_get_aggregate_public_key_response,
        build_get_last_round_response, build_get_peer_info_response, build_get_pox_data_response,
        build_read_only_response, generate_random_consensus_hash, generate_reward_cycle_config,
        write_response, MockServerClient,
    };

    #[test]
    fn read_only_contract_call_200_success() {
        let mock = MockServerClient::new();
        let value = ClarityValue::UInt(10_u128);
        let response = build_read_only_response(&value);
        let h = spawn(move || {
            mock.client.read_only_contract_call(
                &mock.client.stacks_address,
                &ContractName::from("contract-name"),
                &ClarityName::from("function-name"),
                &[],
            )
        });
        write_response(mock.server, response.as_bytes());
        let result = h.join().unwrap().unwrap();
        assert_eq!(result, value);
    }

    #[test]
    fn read_only_contract_call_with_function_args_200_success() {
        let mock = MockServerClient::new();
        let value = ClarityValue::UInt(10_u128);
        let response = build_read_only_response(&value);
        let h = spawn(move || {
            mock.client.read_only_contract_call(
                &mock.client.stacks_address,
                &ContractName::from("contract-name"),
                &ClarityName::from("function-name"),
                &[ClarityValue::UInt(10_u128)],
            )
        });
        write_response(mock.server, response.as_bytes());
        let result = h.join().unwrap().unwrap();
        assert_eq!(result, value);
    }

    #[test]
    fn read_only_contract_call_200_failure() {
        let mock = MockServerClient::new();
        let h = spawn(move || {
            mock.client.read_only_contract_call(
                &mock.client.stacks_address,
                &ContractName::from("contract-name"),
                &ClarityName::from("function-name"),
                &[],
            )
        });
        write_response(
            mock.server,
            b"HTTP/1.1 200 OK\n\n{\"okay\":false,\"cause\":\"Some reason\"}",
        );
        let result = h.join().unwrap();
        assert!(matches!(result, Err(ClientError::ReadOnlyFailure(_))));
    }

    #[test]
    fn read_only_contract_call_400_failure() {
        let mock = MockServerClient::new();
        // Simulate a 400 Bad Request response
        let h = spawn(move || {
            mock.client.read_only_contract_call(
                &mock.client.stacks_address,
                &ContractName::from("contract-name"),
                &ClarityName::from("function-name"),
                &[],
            )
        });
        write_response(mock.server, b"HTTP/1.1 400 Bad Request\n\n");
        let result = h.join().unwrap();
        assert!(matches!(
            result,
            Err(ClientError::RequestFailure(
                reqwest::StatusCode::BAD_REQUEST
            ))
        ));
    }

    #[test]
    fn read_only_contract_call_404_failure() {
        let mock = MockServerClient::new();
        // Simulate a 400 Bad Request response
        let h = spawn(move || {
            mock.client.read_only_contract_call(
                &mock.client.stacks_address,
                &ContractName::from("contract-name"),
                &ClarityName::from("function-name"),
                &[],
            )
        });
        write_response(mock.server, b"HTTP/1.1 404 Not Found\n\n");
        let result = h.join().unwrap();
        assert!(matches!(
            result,
            Err(ClientError::RequestFailure(reqwest::StatusCode::NOT_FOUND))
        ));
    }

    #[test]
    fn valid_reward_cycle_should_succeed() {
        let mock = MockServerClient::new();
        let (pox_data_response, pox_data) = build_get_pox_data_response(None, None, None, None);
        let h = spawn(move || mock.client.get_current_reward_cycle());
        write_response(mock.server, pox_data_response.as_bytes());
        let current_cycle_id = h.join().unwrap().unwrap();
        assert_eq!(current_cycle_id, pox_data.reward_cycle_id);
    }

    #[test]
    fn invalid_reward_cycle_should_fail() {
        let mock = MockServerClient::new();
        let h = spawn(move || mock.client.get_current_reward_cycle());
        write_response(
            mock.server,
            b"HTTP/1.1 200 Ok\n\n{\"current_cycle\":{\"id\":\"fake id\", \"is_pox_active\":false}}",
        );
        let res = h.join().unwrap();
        assert!(matches!(res, Err(ClientError::ReqwestError(_))));
    }

    #[test]
    fn get_aggregate_public_key_should_succeed() {
        let orig_point = Point::from(Scalar::random(&mut rand::thread_rng()));
        let response = build_get_aggregate_public_key_response(orig_point);

        let mock = MockServerClient::new();
        let h = spawn(move || mock.client.get_aggregate_public_key(0));
        write_response(mock.server, response.as_bytes());
        let res = h.join().unwrap().unwrap();
        assert_eq!(res, Some(orig_point));

        let clarity_value = ClarityValue::none();
        let response = build_read_only_response(&clarity_value);

        let mock = MockServerClient::from_config(mock.config);
        let h = spawn(move || mock.client.get_aggregate_public_key(0));
        write_response(mock.server, response.as_bytes());

        let res = h.join().unwrap().unwrap();
        assert!(res.is_none());
    }

    #[test]
    fn parse_valid_aggregate_public_key_should_succeed() {
        let mock = MockServerClient::new();
        let orig_point = Point::from(Scalar::random(&mut rand::thread_rng()));
        let clarity_value = ClarityValue::some(
            ClarityValue::buff_from(orig_point.compress().as_bytes().to_vec())
                .expect("BUG: Failed to create clarity value from point"),
        )
        .expect("BUG: Failed to create clarity value from point");
        let result = mock
            .client
            .parse_aggregate_public_key(clarity_value)
            .unwrap();
        assert_eq!(result, Some(orig_point));

        let value = ClarityValue::none();
        let result = mock.client.parse_aggregate_public_key(value).unwrap();
        assert!(result.is_none());
    }

    #[test]
    fn parse_invalid_aggregate_public_key_should_fail() {
        let mock = MockServerClient::new();
        let value = ClarityValue::UInt(10_u128);
        let result = mock.client.parse_aggregate_public_key(value);
        assert!(result.is_err())
    }

    #[ignore]
    #[test]
    fn transaction_contract_call_should_send_bytes_to_node() {
        let mock = MockServerClient::new();
        let private_key = StacksPrivateKey::new();
        let tx = StacksClient::build_signed_contract_call_transaction(
            &mock.client.stacks_address,
            ContractName::from("contract-name"),
            ClarityName::from("function-name"),
            &[],
            &private_key,
            TransactionVersion::Testnet,
            CHAIN_ID_TESTNET,
            0,
            10_000,
        )
        .unwrap();

        let mut tx_bytes = [0u8; 1024];
        {
            let mut tx_bytes_writer = BufWriter::new(&mut tx_bytes[..]);
            tx.consensus_serialize(&mut tx_bytes_writer).unwrap();
            tx_bytes_writer.flush().unwrap();
        }

        let bytes_len = tx_bytes
            .iter()
            .enumerate()
            .rev()
            .find(|(_, &x)| x != 0)
            .unwrap()
            .0
            + 1;

        let tx_clone = tx.clone();
        let h = spawn(move || mock.client.submit_tx(&tx_clone));

        let request_bytes = write_response(
            mock.server,
            format!("HTTP/1.1 200 OK\n\n{}", tx.txid()).as_bytes(),
        );
        let returned_txid = h.join().unwrap().unwrap();

        assert_eq!(returned_txid, tx.txid());
        assert!(
            request_bytes
                .windows(bytes_len)
                .any(|window| window == &tx_bytes[..bytes_len]),
            "Request bytes did not contain the transaction bytes"
        );
    }

    #[ignore]
    #[test]
    #[serial]
    fn build_vote_for_aggregate_public_key_should_succeed() {
        let mock = MockServerClient::new();
        let point = Point::from(Scalar::random(&mut rand::thread_rng()));
        let round = rand::thread_rng().next_u64();
        let round_response = build_get_last_round_response(round);
        let nonce = thread_rng().next_u64();
        let account_nonce_response = build_account_nonce_response(nonce);

        let h = spawn(move || mock.client.build_vote_for_aggregate_public_key(0, 0, point));
        write_response(mock.server, round_response.as_bytes());
        let mock = MockServerClient::from_config(mock.config);
        write_response(mock.server, account_nonce_response.as_bytes());
        assert!(h.join().unwrap().is_ok());
    }

    #[ignore]
    #[test]
    #[serial]
    fn cast_vote_for_aggregate_public_key_should_succeed() {
        let mock = MockServerClient::new();
        let point = Point::from(Scalar::random(&mut rand::thread_rng()));
        let round = rand::thread_rng().next_u64();
        let round_response = build_get_last_round_response(round);
        let nonce = thread_rng().next_u64();
        let account_nonce_response = build_account_nonce_response(nonce);

        let h = spawn(move || mock.client.cast_vote_for_aggregate_public_key(0, 0, point));
        write_response(mock.server, round_response.as_bytes());
        let mock = MockServerClient::from_config(mock.config);
        write_response(mock.server, account_nonce_response.as_bytes());
        let mock = MockServerClient::from_config(mock.config);
        write_response(
            mock.server,
            b"HTTP/1.1 200 OK\n\n4e99f99bc4a05437abb8c7d0c306618f45b203196498e2ebe287f10497124958",
        );
        assert!(h.join().unwrap().is_ok());
    }

    #[test]
    fn core_info_call_for_consensus_hash_should_succeed() {
        let mock = MockServerClient::new();
        let h = spawn(move || mock.client.get_stacks_tip_consensus_hash());
        let (response, peer_info) = build_get_peer_info_response(None, None);
        write_response(mock.server, response.as_bytes());
        let consensus_hash = h.join().unwrap().expect("Failed to deserialize response");
        assert_eq!(consensus_hash, peer_info.stacks_tip_consensus_hash);
    }

    #[test]
    fn core_info_call_with_invalid_response_should_fail() {
        let mock = MockServerClient::new();
        let h = spawn(move || mock.client.get_stacks_tip_consensus_hash());
        write_response(
            mock.server,
            b"HTTP/1.1 200 OK\n\n4e99f99bc4a05437abb8c7d0c306618f45b203196498e2ebe287f10497124958",
        );
        assert!(h.join().unwrap().is_err());
    }

    #[test]
    fn core_info_call_for_burn_block_height_should_succeed() {
        let mock = MockServerClient::new();
        let h = spawn(move || mock.client.get_burn_block_height());
        let (response, peer_info) = build_get_peer_info_response(None, None);
        write_response(mock.server, response.as_bytes());
        let burn_block_height = h.join().unwrap().expect("Failed to deserialize response");
        assert_eq!(burn_block_height, peer_info.burn_block_height);
    }

    #[test]
    fn core_info_call_for_burn_block_height_should_fail() {
        let mock = MockServerClient::new();
        let h = spawn(move || mock.client.get_burn_block_height());
        write_response(
            mock.server,
            b"HTTP/1.1 200 OK\n\n4e99f99bc4a05437abb8c7d0c306618f45b203196498e2ebe287f10497124958",
        );
        assert!(h.join().unwrap().is_err());
    }

    #[test]
    fn get_account_nonce_should_succeed() {
        let mock = MockServerClient::new();
        let address = mock.client.stacks_address;
        let h = spawn(move || mock.client.get_account_nonce(&address));
        let nonce = thread_rng().next_u64();
        write_response(mock.server, build_account_nonce_response(nonce).as_bytes());
        let returned_nonce = h.join().unwrap().expect("Failed to deserialize response");
        assert_eq!(returned_nonce, nonce);
    }

    #[test]
    fn get_account_nonce_should_fail() {
        let mock = MockServerClient::new();
        let address = mock.client.stacks_address;
        let h = spawn(move || mock.client.get_account_nonce(&address));
        write_response(
            mock.server,
            b"HTTP/1.1 200 OK\n\n{\"nonce\":\"invalid nonce\",\"balance\":\"0x00000000000000000000000000000000\",\"locked\":\"0x00000000000000000000000000000000\",\"unlock_height\":0}"
        );
        assert!(h.join().unwrap().is_err());
    }

    #[test]
    fn parse_valid_signer_slots_should_succeed() {
        let mock = MockServerClient::new();
        let clarity_value_hex =
            "0x070b000000050c00000002096e756d2d736c6f7473010000000000000000000000000000000c067369676e6572051a8195196a9a7cf9c37cb13e1ed69a7bc047a84e050c00000002096e756d2d736c6f7473010000000000000000000000000000000c067369676e6572051a6505471146dcf722f0580911183f28bef30a8a890c00000002096e756d2d736c6f7473010000000000000000000000000000000c067369676e6572051a1d7f8e3936e5da5f32982cc47f31d7df9fb1b38a0c00000002096e756d2d736c6f7473010000000000000000000000000000000c067369676e6572051a126d1a814313c952e34c7840acec9211e1727fb80c00000002096e756d2d736c6f7473010000000000000000000000000000000c067369676e6572051a7374ea6bb39f2e8d3d334d62b9f302a977de339a";
        let value = ClarityValue::try_deserialize_hex_untyped(clarity_value_hex).unwrap();
        let signer_slots = mock.client.parse_signer_slots(value).unwrap();
        assert_eq!(signer_slots.len(), 5);
        signer_slots
            .into_iter()
            .for_each(|(_address, slots)| assert!(slots == SIGNER_SLOTS_PER_USER as u128));
    }

    #[test]
    fn get_node_epoch_should_succeed() {
        let mock = MockServerClient::new();
        // The burn block height is one BEHIND the activation height of 2.5, therefore is 2.4
        let burn_block_height: u64 = 100;
        let pox_response = build_get_pox_data_response(
            None,
            None,
            Some(burn_block_height.saturating_add(1)),
            None,
        )
        .0;
        let peer_response = build_get_peer_info_response(Some(burn_block_height), None).0;
        let h = spawn(move || mock.client.get_node_epoch());
        write_response(mock.server, pox_response.as_bytes());
        let mock = MockServerClient::from_config(mock.config);
        write_response(mock.server, peer_response.as_bytes());
        let epoch = h.join().unwrap().expect("Failed to deserialize response");
        assert_eq!(epoch, StacksEpochId::Epoch24);

        // The burn block height is the same as the activation height of 2.5, therefore is 2.5
        let pox_response = build_get_pox_data_response(None, None, Some(burn_block_height), None).0;
        let peer_response = build_get_peer_info_response(Some(burn_block_height), None).0;
        let mock = MockServerClient::from_config(mock.config);
        let h = spawn(move || mock.client.get_node_epoch());
        write_response(mock.server, pox_response.as_bytes());
        let mock = MockServerClient::from_config(mock.config);
        write_response(mock.server, peer_response.as_bytes());
        let epoch = h.join().unwrap().expect("Failed to deserialize response");
        assert_eq!(epoch, StacksEpochId::Epoch25);

        // The burn block height is the AFTER as the activation height of 2.5 but BEFORE the activation height of 3.0, therefore is 2.5
        let pox_response = build_get_pox_data_response(
            None,
            None,
            Some(burn_block_height.saturating_sub(1)),
            Some(burn_block_height.saturating_add(1)),
        )
        .0;
        let peer_response = build_get_peer_info_response(Some(burn_block_height), None).0;
        let mock = MockServerClient::from_config(mock.config);
        let h = spawn(move || mock.client.get_node_epoch());
        write_response(mock.server, pox_response.as_bytes());
        let mock = MockServerClient::from_config(mock.config);
        write_response(mock.server, peer_response.as_bytes());
        let epoch = h.join().unwrap().expect("Failed to deserialize response");
        assert_eq!(epoch, StacksEpochId::Epoch25);

        // The burn block height is the AFTER as the activation height of 2.5 and the SAME as the activation height of 3.0, therefore is 3.0
        let pox_response = build_get_pox_data_response(
            None,
            None,
            Some(burn_block_height.saturating_sub(1)),
            Some(burn_block_height),
        )
        .0;
        let peer_response = build_get_peer_info_response(Some(burn_block_height), None).0;
        let mock = MockServerClient::from_config(mock.config);
        let h = spawn(move || mock.client.get_node_epoch());
        write_response(mock.server, pox_response.as_bytes());
        let mock = MockServerClient::from_config(mock.config);
        write_response(mock.server, peer_response.as_bytes());
        let epoch = h.join().unwrap().expect("Failed to deserialize response");
        assert_eq!(epoch, StacksEpochId::Epoch30);

        // The burn block height is the AFTER as the activation height of 2.5 and AFTER the activation height of 3.0, therefore is 3.0
        let pox_response = build_get_pox_data_response(
            None,
            None,
            Some(burn_block_height.saturating_sub(1)),
            Some(burn_block_height),
        )
        .0;
        let peer_response =
            build_get_peer_info_response(Some(burn_block_height.saturating_add(1)), None).0;
        let mock = MockServerClient::from_config(mock.config);
        let h = spawn(move || mock.client.get_node_epoch());
        write_response(mock.server, pox_response.as_bytes());
        let mock = MockServerClient::from_config(mock.config);
        write_response(mock.server, peer_response.as_bytes());
        let epoch = h.join().unwrap().expect("Failed to deserialize response");
        assert_eq!(epoch, StacksEpochId::Epoch30);
    }

    #[test]
    fn get_node_epoch_should_fail() {
        let mock = MockServerClient::new();
        let h = spawn(move || mock.client.get_node_epoch());
        write_response(
            mock.server,
            b"HTTP/1.1 200 OK\n\n4e99f99bc4a05437abb8c7d0c306618f45b203196498e2ebe287f10497124958",
        );
        assert!(h.join().unwrap().is_err());
    }

    #[test]
    fn submit_block_for_validation_should_succeed() {
        let mock = MockServerClient::new();
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
        let h = spawn(move || mock.client.submit_block_for_validation(block));
        write_response(mock.server, b"HTTP/1.1 200 OK\n\n");
        assert!(h.join().unwrap().is_ok());
    }

    #[test]
    fn submit_block_for_validation_should_fail() {
        let mock = MockServerClient::new();
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
        let h = spawn(move || mock.client.submit_block_for_validation(block));
        write_response(mock.server, b"HTTP/1.1 404 Not Found\n\n");
        assert!(h.join().unwrap().is_err());
    }

    #[test]
    fn get_peer_info_should_succeed() {
        let mock = MockServerClient::new();
        let (response, peer_info) = build_get_peer_info_response(None, None);
        let h = spawn(move || mock.client.get_peer_info());
        write_response(mock.server, response.as_bytes());
        assert_eq!(h.join().unwrap().unwrap(), peer_info);
    }

    #[test]
    fn get_last_round_should_succeed() {
        let mock = MockServerClient::new();
        let round = rand::thread_rng().next_u64();
        let response = build_get_last_round_response(round);
        let h = spawn(move || mock.client.get_last_round(0));

        write_response(mock.server, response.as_bytes());
        assert_eq!(h.join().unwrap().unwrap(), round);
    }

    #[test]
    fn get_reward_set_should_succeed() {
        let mock = MockServerClient::new();
        let point = Point::from(Scalar::random(&mut rand::thread_rng())).compress();
        let mut bytes = [0u8; 33];
        bytes.copy_from_slice(point.as_bytes());
        let stacker_set = RewardSet {
            rewarded_addresses: vec![PoxAddress::standard_burn_address(false)],
            start_cycle_state: PoxStartCycleInfo {
                missed_reward_slots: vec![],
            },
            signers: Some(vec![NakamotoSignerEntry {
                signing_key: bytes,
                stacked_amt: rand::thread_rng().next_u64() as u128,
                slots: 1,
            }]),
        };
        let stackers_response = GetStackersResponse {
            stacker_set: stacker_set.clone(),
        };

        let stackers_response_json = serde_json::to_string(&stackers_response)
            .expect("Failed to serialize get stacker response");
        let response = format!("HTTP/1.1 200 OK\n\n{stackers_response_json}");
        let h = spawn(move || mock.client.get_reward_set(0));
        write_response(mock.server, response.as_bytes());
        assert_eq!(h.join().unwrap().unwrap(), stacker_set);
    }

    #[test]
    #[serial]
    fn get_reward_set_calculated() {
        // Should return TRUE as the passed in reward cycle is older than the current reward cycle of the node
        let mock = MockServerClient::new();
        let reward_cycle = 10;
        let pox_response = build_get_pox_data_response(Some(reward_cycle), None, None, None).0;
        let h = spawn(move || {
            mock.client
                .reward_set_calculated(reward_cycle.saturating_sub(1))
        });
        write_response(mock.server, pox_response.as_bytes());
        assert!(h.join().unwrap().unwrap());

        // Should return TRUE as the passed in reward cycle is the same as the current reward cycle
        let mock = MockServerClient::from_config(mock.config);
        let pox_response = build_get_pox_data_response(Some(reward_cycle), None, None, None).0;
        let h = spawn(move || mock.client.reward_set_calculated(reward_cycle));
        write_response(mock.server, pox_response.as_bytes());
        assert!(h.join().unwrap().unwrap());

        // Should return TRUE as the passed in reward cycle is the NEXT reward cycle AND the prepare phase is in its SECOND block
        let mock = MockServerClient::from_config(mock.config);
        let prepare_phase_start = 10;
        let pox_response =
            build_get_pox_data_response(Some(reward_cycle), Some(prepare_phase_start), None, None)
                .0;
        let peer_response =
            build_get_peer_info_response(Some(prepare_phase_start.saturating_add(1)), None).0;
        let h = spawn(move || {
            mock.client
                .reward_set_calculated(reward_cycle.saturating_add(1))
        });
        write_response(mock.server, pox_response.as_bytes());
        let mock = MockServerClient::from_config(mock.config);
        write_response(mock.server, peer_response.as_bytes());
        assert!(h.join().unwrap().unwrap());

        // Should return FALSE as the passed in reward cycle is NEWER than the NEXT reward cycle of the node
        let mock = MockServerClient::from_config(mock.config);
        let pox_response = build_get_pox_data_response(Some(reward_cycle), None, None, None).0;
        let h = spawn(move || {
            mock.client
                .reward_set_calculated(reward_cycle.saturating_add(2))
        });
        write_response(mock.server, pox_response.as_bytes());
        assert!(!h.join().unwrap().unwrap());

        // Should return FALSE as the passed in reward cycle is the NEXT reward cycle BUT the prepare phase is in its FIRST block
        let mock = MockServerClient::from_config(mock.config);
        let pox_response =
            build_get_pox_data_response(Some(reward_cycle), Some(prepare_phase_start), None, None)
                .0;
        let peer_response = build_get_peer_info_response(Some(prepare_phase_start), None).0;
        let h = spawn(move || {
            mock.client
                .reward_set_calculated(reward_cycle.saturating_add(1))
        });
        write_response(mock.server, pox_response.as_bytes());
        let mock = MockServerClient::from_config(mock.config);
        write_response(mock.server, peer_response.as_bytes());
        assert!(!h.join().unwrap().unwrap());
    }

    #[test]
    fn calculate_coordinator_different_consensus_hashes_produces_unique_results() {
        let number_of_tests = 5;
        let generated_public_keys = generate_reward_cycle_config(10, 4000, None).0.public_keys;
        let mut results = Vec::new();

        for _ in 0..number_of_tests {
            let mock = MockServerClient::new();
            let response = build_get_peer_info_response(None, None).0;
            let generated_public_keys = generated_public_keys.clone();
            let h = spawn(move || mock.client.calculate_coordinator(&generated_public_keys));
            write_response(mock.server, response.as_bytes());
            let result = h.join().unwrap();
            results.push(result);
        }

        // Check that not all coordinator IDs are the same
        let all_ids_same = results.iter().all(|&(id, _)| id == results[0].0);
        assert!(!all_ids_same, "Not all coordinator IDs should be the same");

        // Check that not all coordinator public keys are the same
        let all_keys_same = results
            .iter()
            .all(|&(_, key)| key.key.data == results[0].1.key.data);
        assert!(
            !all_keys_same,
            "Not all coordinator public keys should be the same"
        );
    }

    fn generate_calculate_coordinator_test_results(
        random_consensus: bool,
        count: usize,
    ) -> Vec<(u32, ecdsa::PublicKey)> {
        let mut results = Vec::new();
        let same_hash = generate_random_consensus_hash();
        let hash = if random_consensus {
            None
        } else {
            Some(same_hash)
        };
        let generated_public_keys = generate_reward_cycle_config(10, 4000, None).0.public_keys;
        for _ in 0..count {
            let mock = MockServerClient::new();
            let generated_public_keys = generated_public_keys.clone();
            let response = build_get_peer_info_response(None, hash).0;
            let h = spawn(move || mock.client.calculate_coordinator(&generated_public_keys));
            write_response(mock.server, response.as_bytes());
            let result = h.join().unwrap();
            results.push(result);
        }
        results
    }

    #[test]
    fn calculate_coordinator_results_should_vary_or_match_based_on_hash() {
        let results_with_random_hash = generate_calculate_coordinator_test_results(true, 5);
        let all_ids_same = results_with_random_hash
            .iter()
            .all(|&(id, _)| id == results_with_random_hash[0].0);
        let all_keys_same = results_with_random_hash
            .iter()
            .all(|&(_, key)| key.key.data == results_with_random_hash[0].1.key.data);
        assert!(!all_ids_same, "Not all coordinator IDs should be the same");
        assert!(
            !all_keys_same,
            "Not all coordinator public keys should be the same"
        );

        let results_with_static_hash = generate_calculate_coordinator_test_results(false, 5);
        let all_ids_same = results_with_static_hash
            .iter()
            .all(|&(id, _)| id == results_with_static_hash[0].0);
        let all_keys_same = results_with_static_hash
            .iter()
            .all(|&(_, key)| key.key.data == results_with_static_hash[0].1.key.data);
        assert!(all_ids_same, "All coordinator IDs should be the same");
        assert!(
            all_keys_same,
            "All coordinator public keys should be the same"
        );
    }
}
