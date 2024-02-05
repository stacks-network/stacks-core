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
use blockstack_lib::chainstate::stacks::boot::POX_4_NAME;
use blockstack_lib::chainstate::stacks::{
    StacksTransaction, StacksTransactionSigner, TransactionAnchorMode, TransactionAuth,
    TransactionContractCall, TransactionPayload, TransactionPostConditionMode,
    TransactionSpendingCondition, TransactionVersion,
};
use blockstack_lib::core::{
    BITCOIN_MAINNET_STACKS_25_BURN_HEIGHT, BITCOIN_MAINNET_STACKS_30_BURN_HEIGHT,
    BITCOIN_TESTNET_STACKS_25_BURN_HEIGHT, BITCOIN_TESTNET_STACKS_30_BURN_HEIGHT,
};
use blockstack_lib::net::api::callreadonly::CallReadOnlyResponse;
use blockstack_lib::net::api::getaccount::AccountEntryResponse;
use blockstack_lib::net::api::getinfo::RPCPeerInfoData;
use blockstack_lib::net::api::getpoxinfo::RPCPoxInfoData;
use blockstack_lib::net::api::postblock_proposal::NakamotoBlockProposal;
use blockstack_lib::util_lib::boot::boot_code_id;
use clarity::vm::types::{PrincipalData, QualifiedContractIdentifier};
use clarity::vm::{ClarityName, ContractName, Value as ClarityValue};
use serde_json::json;
use slog::slog_debug;
use stacks_common::codec::StacksMessageCodec;
use stacks_common::consts::CHAIN_ID_MAINNET;
use stacks_common::debug;
use stacks_common::types::chainstate::{
    ConsensusHash, StacksAddress, StacksPrivateKey, StacksPublicKey,
};
use wsts::curve::point::{Compressed, Point};

use crate::client::{retry_with_exponential_backoff, ClientError};
use crate::config::Config;

/// The Stacks signer client used to communicate with the stacks node
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
}

/// The supported epoch IDs
#[derive(Debug, PartialEq)]
pub enum EpochId {
    /// The mainnet epoch ID
    Epoch30,
    /// The testnet epoch ID
    Epoch25,
    /// Unsuporrted epoch ID
    UnsupportedEpoch,
}

impl From<&Config> for StacksClient {
    fn from(config: &Config) -> Self {
        Self {
            stacks_private_key: config.stacks_private_key,
            stacks_address: config.stacks_address,
            http_origin: format!("http://{}", config.node_host),
            tx_version: config.network.to_transaction_version(),
            chain_id: config.network.to_chain_id(),
            stacks_node_client: reqwest::blocking::Client::new(),
        }
    }
}

impl StacksClient {
    /// Retrieve the signer slots stored within the stackerdb contract
    pub fn get_stackerdb_signer_slots(
        &self,
        stackerdb_contract: &QualifiedContractIdentifier,
    ) -> Result<Vec<(StacksAddress, u128)>, ClientError> {
        let function_name_str = "stackerdb-get-signer-slots";
        let function_name = ClarityName::from(function_name_str);
        let function_args = &[];
        let value = self.read_only_contract_call_with_retry(
            &stackerdb_contract.issuer.clone().into(),
            &stackerdb_contract.name,
            &function_name,
            function_args,
        )?;
        self.parse_signer_slots(value)
    }
    /// Retrieve the stacks tip consensus hash from the stacks node
    pub fn get_stacks_tip_consensus_hash(&self) -> Result<ConsensusHash, ClientError> {
        let peer_info = self.get_peer_info()?;
        Ok(peer_info.stacks_tip_consensus_hash)
    }

    /// Determine the stacks node current epoch
    pub fn get_node_epoch(&self) -> Result<EpochId, ClientError> {
        let is_mainnet = self.chain_id == CHAIN_ID_MAINNET;
        let burn_block_height = self.get_burn_block_height()?;

        let (epoch25_activation_height, epoch_30_activation_height) = if is_mainnet {
            (
                BITCOIN_MAINNET_STACKS_25_BURN_HEIGHT,
                BITCOIN_MAINNET_STACKS_30_BURN_HEIGHT,
            )
        } else {
            (
                BITCOIN_TESTNET_STACKS_25_BURN_HEIGHT,
                BITCOIN_TESTNET_STACKS_30_BURN_HEIGHT,
            )
        };

        if burn_block_height < epoch25_activation_height {
            Ok(EpochId::UnsupportedEpoch)
        } else if burn_block_height < epoch_30_activation_height {
            Ok(EpochId::Epoch25)
        } else {
            Ok(EpochId::Epoch30)
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

    /// Retrieve the current DKG aggregate public key
    pub fn get_aggregate_public_key(&self) -> Result<Option<Point>, ClientError> {
        let reward_cycle = self.get_current_reward_cycle()?;
        let function_name_str = "get-aggregate-public-key";
        let function_name = ClarityName::from(function_name_str);
        let pox_contract_id = boot_code_id(POX_4_NAME, self.chain_id == CHAIN_ID_MAINNET);
        let function_args = &[ClarityValue::UInt(reward_cycle as u128)];
        let value = self.read_only_contract_call_with_retry(
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

    /// Helper function to retrieve the current reward cycle number from the stacks node
    fn get_current_reward_cycle(&self) -> Result<u64, ClientError> {
        let pox_data = self.get_pox_data()?;
        Ok(pox_data.reward_cycle_id)
    }

    /// Helper function to retrieve the next possible nonce for the signer from the stacks node
    #[allow(dead_code)]
    fn get_next_possible_nonce(&self) -> Result<u64, ClientError> {
        //FIXME: use updated RPC call to get mempool nonces. Depends on https://github.com/stacks-network/stacks-blockchain/issues/4000
        todo!("Get the next possible nonce from the stacks node");
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
        // Due to pox 4 definition, the aggregate public key is always an optional clarity value hence the use of expect
        // If this fails, we have bigger problems than the signer crashing...
        let value_opt = value.expect_optional()?;
        let Some(value) = value_opt else {
            return Ok(None);
        };
        // A point should have 33 bytes exactly due to the pox 4 definition hence the use of expect
        // If this fails, we have bigger problems than the signer crashing...
        let data = value.clone().expect_buff(33)?;
        // It is possible that the point was invalid though when voted upon and this cannot be prevented by pox 4 definitions...
        // Pass up this error if the conversions fail.
        let compressed_data = Compressed::try_from(data.as_slice())
            .map_err(|_e| ClientError::MalformedClarityValue(value.clone()))?;
        let point = Point::try_from(&compressed_data)
            .map_err(|_e| ClientError::MalformedClarityValue(value))?;
        Ok(Some(point))
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

    /// Sends a transaction to the stacks node for a modifying contract call
    #[allow(dead_code)]
    fn transaction_contract_call(
        &self,
        contract_addr: &StacksAddress,
        contract_name: ContractName,
        function_name: ClarityName,
        function_args: &[ClarityValue],
    ) -> Result<Txid, ClientError> {
        debug!("Making a contract call to {contract_addr}.{contract_name}...");
        let nonce = self.get_account_nonce(&self.stacks_address)?;
        // TODO: make tx_fee configurable
        let signed_tx = Self::build_signed_contract_call_transaction(
            contract_addr,
            contract_name,
            function_name,
            function_args,
            &self.stacks_private_key,
            self.tx_version,
            self.chain_id,
            nonce,
            10_000,
        )?;
        self.submit_tx(&signed_tx)
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
    pub fn read_only_contract_call_with_retry(
        &self,
        contract_addr: &StacksAddress,
        contract_name: &ContractName,
        function_name: &ClarityName,
        function_args: &[ClarityValue],
    ) -> Result<ClarityValue, ClientError> {
        debug!(
            "Calling read-only function {function_name} with args {:?}...",
            function_args
        );
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
        let send_request = || {
            self.stacks_node_client
                .post(path.clone())
                .header("Content-Type", "application/json")
                .body(body.clone())
                .send()
                .map_err(backoff::Error::transient)
        };
        let response = retry_with_exponential_backoff(send_request)?;
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

    /// Helper function to create a stacks transaction for a modifying contract call
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

        // FIXME: Because signers are given priority, we can put down a tx fee of 0
        // https://github.com/stacks-network/stacks-blockchain/issues/4006
        // Note: if set to 0 now, will cause a failure (MemPoolRejection::FeeTooLow)
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

    use libsigner::SIGNER_SLOTS_PER_USER;
    use stacks_common::consts::CHAIN_ID_TESTNET;
    use wsts::curve::scalar::Scalar;

    use super::*;
    use crate::client::tests::{write_response, TestConfig};

    #[test]
    fn read_only_contract_call_200_success() {
        let config = TestConfig::new();
        let value = ClarityValue::UInt(10_u128);
        let hex = value
            .serialize_to_hex()
            .expect("Failed to serialize hex value");
        let response_bytes = format!("HTTP/1.1 200 OK\n\n{{\"okay\":true,\"result\":\"{hex}\"}}",);
        let h = spawn(move || {
            config.client.read_only_contract_call_with_retry(
                &config.client.stacks_address,
                &ContractName::from("contract-name"),
                &ClarityName::from("function-name"),
                &[],
            )
        });
        write_response(config.mock_server, response_bytes.as_bytes());
        let result = h.join().unwrap().unwrap();
        assert_eq!(result, value);
    }

    #[test]
    fn read_only_contract_call_with_function_args_200_success() {
        let config = TestConfig::new();
        let value = ClarityValue::UInt(10_u128);
        let hex = value
            .serialize_to_hex()
            .expect("Failed to serialize hex value");
        let response_bytes = format!("HTTP/1.1 200 OK\n\n{{\"okay\":true,\"result\":\"{hex}\"}}",);
        let h = spawn(move || {
            config.client.read_only_contract_call_with_retry(
                &config.client.stacks_address,
                &ContractName::from("contract-name"),
                &ClarityName::from("function-name"),
                &[ClarityValue::UInt(10_u128)],
            )
        });
        write_response(config.mock_server, response_bytes.as_bytes());
        let result = h.join().unwrap().unwrap();
        assert_eq!(result, value);
    }

    #[test]
    fn read_only_contract_call_200_failure() {
        let config = TestConfig::new();
        let h = spawn(move || {
            config.client.read_only_contract_call_with_retry(
                &config.client.stacks_address,
                &ContractName::from("contract-name"),
                &ClarityName::from("function-name"),
                &[],
            )
        });
        write_response(
            config.mock_server,
            b"HTTP/1.1 200 OK\n\n{\"okay\":false,\"cause\":\"Some reason\"}",
        );
        let result = h.join().unwrap();
        assert!(matches!(result, Err(ClientError::ReadOnlyFailure(_))));
    }

    #[test]
    fn read_only_contract_call_400_failure() {
        let config = TestConfig::new();
        // Simulate a 400 Bad Request response
        let h = spawn(move || {
            config.client.read_only_contract_call_with_retry(
                &config.client.stacks_address,
                &ContractName::from("contract-name"),
                &ClarityName::from("function-name"),
                &[],
            )
        });
        write_response(config.mock_server, b"HTTP/1.1 400 Bad Request\n\n");
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
        let config = TestConfig::new();
        // Simulate a 400 Bad Request response
        let h = spawn(move || {
            config.client.read_only_contract_call_with_retry(
                &config.client.stacks_address,
                &ContractName::from("contract-name"),
                &ClarityName::from("function-name"),
                &[],
            )
        });
        write_response(config.mock_server, b"HTTP/1.1 404 Not Found\n\n");
        let result = h.join().unwrap();
        assert!(matches!(
            result,
            Err(ClientError::RequestFailure(reqwest::StatusCode::NOT_FOUND))
        ));
    }

    #[test]
    fn valid_reward_cycle_should_succeed() {
        let config = TestConfig::new();
        let h = spawn(move || config.client.get_current_reward_cycle());
        write_response(
            config.mock_server,
            b"HTTP/1.1 200 Ok\n\n{\"contract_id\":\"ST000000000000000000002AMW42H.pox-3\",\"pox_activation_threshold_ustx\":829371801288885,\"first_burnchain_block_height\":2000000,\"current_burnchain_block_height\":2572192,\"prepare_phase_block_length\":50,\"reward_phase_block_length\":1000,\"reward_slots\":2000,\"rejection_fraction\":12,\"total_liquid_supply_ustx\":41468590064444294,\"current_cycle\":{\"id\":544,\"min_threshold_ustx\":5190000000000,\"stacked_ustx\":853258144644000,\"is_pox_active\":true},\"next_cycle\":{\"id\":545,\"min_threshold_ustx\":5190000000000,\"min_increment_ustx\":5183573758055,\"stacked_ustx\":847278759574000,\"prepare_phase_start_block_height\":2572200,\"blocks_until_prepare_phase\":8,\"reward_phase_start_block_height\":2572250,\"blocks_until_reward_phase\":58,\"ustx_until_pox_rejection\":4976230807733304},\"min_amount_ustx\":5190000000000,\"prepare_cycle_length\":50,\"reward_cycle_id\":544,\"reward_cycle_length\":1050,\"rejection_votes_left_required\":4976230807733304,\"next_reward_cycle_in\":58,\"contract_versions\":[{\"contract_id\":\"ST000000000000000000002AMW42H.pox\",\"activation_burnchain_block_height\":2000000,\"first_reward_cycle_id\":0},{\"contract_id\":\"ST000000000000000000002AMW42H.pox-2\",\"activation_burnchain_block_height\":2422102,\"first_reward_cycle_id\":403},{\"contract_id\":\"ST000000000000000000002AMW42H.pox-3\",\"activation_burnchain_block_height\":2432545,\"first_reward_cycle_id\":412}]}",
        );
        let current_cycle_id = h.join().unwrap().unwrap();
        assert_eq!(544, current_cycle_id);
    }

    #[test]
    fn invalid_reward_cycle_should_fail() {
        let config = TestConfig::new();
        let h = spawn(move || config.client.get_current_reward_cycle());
        write_response(
            config.mock_server,
            b"HTTP/1.1 200 Ok\n\n{\"current_cycle\":{\"id\":\"fake id\", \"is_pox_active\":false}}",
        );
        let res = h.join().unwrap();
        assert!(matches!(res, Err(ClientError::ReqwestError(_))));
    }

    #[test]
    fn missing_reward_cycle_should_fail() {
        let config = TestConfig::new();
        let h = spawn(move || config.client.get_current_reward_cycle());
        write_response(
            config.mock_server,
            b"HTTP/1.1 200 Ok\n\n{\"current_cycle\":{\"is_pox_active\":false}}",
        );
        let res = h.join().unwrap();
        assert!(matches!(res, Err(ClientError::ReqwestError(_))));
    }

    #[test]
    fn get_aggregate_public_key_should_succeed() {
        let current_reward_cycle_response = b"HTTP/1.1 200 Ok\n\n{\"contract_id\":\"ST000000000000000000002AMW42H.pox-3\",\"pox_activation_threshold_ustx\":829371801288885,\"first_burnchain_block_height\":2000000,\"current_burnchain_block_height\":2572192,\"prepare_phase_block_length\":50,\"reward_phase_block_length\":1000,\"reward_slots\":2000,\"rejection_fraction\":12,\"total_liquid_supply_ustx\":41468590064444294,\"current_cycle\":{\"id\":544,\"min_threshold_ustx\":5190000000000,\"stacked_ustx\":853258144644000,\"is_pox_active\":true},\"next_cycle\":{\"id\":545,\"min_threshold_ustx\":5190000000000,\"min_increment_ustx\":5183573758055,\"stacked_ustx\":847278759574000,\"prepare_phase_start_block_height\":2572200,\"blocks_until_prepare_phase\":8,\"reward_phase_start_block_height\":2572250,\"blocks_until_reward_phase\":58,\"ustx_until_pox_rejection\":4976230807733304},\"min_amount_ustx\":5190000000000,\"prepare_cycle_length\":50,\"reward_cycle_id\":544,\"reward_cycle_length\":1050,\"rejection_votes_left_required\":4976230807733304,\"next_reward_cycle_in\":58,\"contract_versions\":[{\"contract_id\":\"ST000000000000000000002AMW42H.pox\",\"activation_burnchain_block_height\":2000000,\"first_reward_cycle_id\":0},{\"contract_id\":\"ST000000000000000000002AMW42H.pox-2\",\"activation_burnchain_block_height\":2422102,\"first_reward_cycle_id\":403},{\"contract_id\":\"ST000000000000000000002AMW42H.pox-3\",\"activation_burnchain_block_height\":2432545,\"first_reward_cycle_id\":412}]}";
        let orig_point = Point::from(Scalar::random(&mut rand::thread_rng()));
        let clarity_value = ClarityValue::some(
            ClarityValue::buff_from(orig_point.compress().as_bytes().to_vec())
                .expect("BUG: Failed to create clarity value from point"),
        )
        .expect("BUG: Failed to create clarity value from point");
        let hex = clarity_value
            .serialize_to_hex()
            .expect("Failed to serialize clarity value");
        let response = format!("HTTP/1.1 200 OK\n\n{{\"okay\":true,\"result\":\"{hex}\"}}");

        let test_config = TestConfig::new();
        let config = test_config.config;
        let h = spawn(move || test_config.client.get_aggregate_public_key());
        write_response(test_config.mock_server, current_reward_cycle_response);

        let test_config = TestConfig::from_config(config);
        write_response(test_config.mock_server, response.as_bytes());
        let res = h.join().unwrap().unwrap();
        assert_eq!(res, Some(orig_point));

        let clarity_value = ClarityValue::none();
        let hex = clarity_value
            .serialize_to_hex()
            .expect("Failed to serialize clarity value");
        let response = format!("HTTP/1.1 200 OK\n\n{{\"okay\":true,\"result\":\"{hex}\"}}");

        let test_config = TestConfig::new();
        let config = test_config.config;
        let h = spawn(move || test_config.client.get_aggregate_public_key());
        write_response(test_config.mock_server, current_reward_cycle_response);

        let test_config = TestConfig::from_config(config);
        write_response(test_config.mock_server, response.as_bytes());

        let res = h.join().unwrap().unwrap();
        assert!(res.is_none());
    }

    #[test]
    fn parse_valid_aggregate_public_key_should_succeed() {
        let config = TestConfig::new();
        let orig_point = Point::from(Scalar::random(&mut rand::thread_rng()));
        let clarity_value = ClarityValue::some(
            ClarityValue::buff_from(orig_point.compress().as_bytes().to_vec())
                .expect("BUG: Failed to create clarity value from point"),
        )
        .expect("BUG: Failed to create clarity value from point");
        let result = config
            .client
            .parse_aggregate_public_key(clarity_value)
            .unwrap();
        assert_eq!(result, Some(orig_point));

        let value = ClarityValue::none();
        let result = config.client.parse_aggregate_public_key(value).unwrap();
        assert!(result.is_none());
    }

    #[test]
    fn parse_invalid_aggregate_public_key_should_fail() {
        let config = TestConfig::new();
        let value = ClarityValue::UInt(10_u128);
        let result = config.client.parse_aggregate_public_key(value);
        assert!(result.is_err())
    }

    #[ignore]
    #[test]
    fn transaction_contract_call_should_send_bytes_to_node() {
        let config = TestConfig::new();
        let private_key = StacksPrivateKey::new();
        let tx = StacksClient::build_signed_contract_call_transaction(
            &config.client.stacks_address,
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
        let h = spawn(move || config.client.submit_tx(&tx_clone));

        let request_bytes = write_response(
            config.mock_server,
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
    fn transaction_contract_call_should_succeed() {
        let config = TestConfig::new();
        let h = spawn(move || {
            config.client.transaction_contract_call(
                &config.client.stacks_address,
                ContractName::from("contract-name"),
                ClarityName::from("function-name"),
                &[],
            )
        });
        write_response(
            config.mock_server,
            b"HTTP/1.1 200 OK\n\n4e99f99bc4a05437abb8c7d0c306618f45b203196498e2ebe287f10497124958",
        );
        assert!(h.join().unwrap().is_ok());
    }

    #[test]
    fn core_info_call_for_consensus_hash_should_succeed() {
        let config = TestConfig::new();
        let h = spawn(move || config.client.get_stacks_tip_consensus_hash());
        write_response(
            config.mock_server,
            b"HTTP/1.1 200 OK\n\n{\"stacks_tip_consensus_hash\":\"64c8c3049ff6b939c65828e3168210e6bb32d880\",\"peer_version\":4207599113,\"pox_consensus\":\"64c8c3049ff6b939c65828e3168210e6bb32d880\",\"burn_block_height\":2575799,\"stable_pox_consensus\":\"72277bf9a3b115e13c0942825480d6cee0e9a0e8\",\"stable_burn_block_height\":2575792,\"server_version\":\"stacks-node d657bdd (feat/epoch-2.4:d657bdd, release build, linux [x86_64])\",\"network_id\":2147483648,\"parent_network_id\":118034699,\"stacks_tip_height\":145152,\"stacks_tip\":\"77219884fe434c0fa270d65592b4f082ab3e5d9922ac2bdaac34310aedc3d298\",\"genesis_chainstate_hash\":\"74237aa39aa50a83de11a4f53e9d3bb7d43461d1de9873f402e5453ae60bc59b\",\"unanchored_tip\":\"dde44222b6e6d81583b6b9c55db83e8716943ae9d0dc332fc39448ddd9b99dc2\",\"unanchored_seq\":0,\"exit_at_block_height\":null,\"node_public_key\":\"023c940136d5795d9dd82c0e87f4dd6a2a1db245444e7d70e34bb9605c3c3917b0\",\"node_public_key_hash\":\"e26cce8f6abe06b9fc81c3b11bcc821d2f1b8fd0\"}",
        );
        let consensus_hash = h.join().unwrap().expect("Failed to deserialize response");
        assert_eq!(
            consensus_hash.to_hex(),
            "64c8c3049ff6b939c65828e3168210e6bb32d880"
        );
    }

    #[test]
    fn core_info_call_with_invalid_response_should_fail() {
        let config = TestConfig::new();
        let h = spawn(move || config.client.get_stacks_tip_consensus_hash());
        write_response(
            config.mock_server,
            b"HTTP/1.1 200 OK\n\n4e99f99bc4a05437abb8c7d0c306618f45b203196498e2ebe287f10497124958",
        );
        assert!(h.join().unwrap().is_err());
    }

    #[test]
    fn core_info_call_for_burn_block_height_should_succeed() {
        let config = TestConfig::new();
        let h = spawn(move || config.client.get_burn_block_height());
        write_response(
            config.mock_server,
            b"HTTP/1.1 200 OK\n\n{\"burn_block_height\":2575799,\"peer_version\":4207599113,\"pox_consensus\":\"64c8c3049ff6b939c65828e3168210e6bb32d880\",\"stable_pox_consensus\":\"72277bf9a3b115e13c0942825480d6cee0e9a0e8\",\"stable_burn_block_height\":2575792,\"server_version\":\"stacks-node d657bdd (feat/epoch-2.4:d657bdd, release build, linux [x86_64])\",\"network_id\":2147483648,\"parent_network_id\":118034699,\"stacks_tip_height\":145152,\"stacks_tip\":\"77219884fe434c0fa270d65592b4f082ab3e5d9922ac2bdaac34310aedc3d298\",\"stacks_tip_consensus_hash\":\"64c8c3049ff6b939c65828e3168210e6bb32d880\",\"genesis_chainstate_hash\":\"74237aa39aa50a83de11a4f53e9d3bb7d43461d1de9873f402e5453ae60bc59b\",\"unanchored_tip\":\"dde44222b6e6d81583b6b9c55db83e8716943ae9d0dc332fc39448ddd9b99dc2\",\"unanchored_seq\":0,\"exit_at_block_height\":null,\"node_public_key\":\"023c940136d5795d9dd82c0e87f4dd6a2a1db245444e7d70e34bb9605c3c3917b0\",\"node_public_key_hash\":\"e26cce8f6abe06b9fc81c3b11bcc821d2f1b8fd0\"}",
        );
        let burn_block_height = h.join().unwrap().expect("Failed to deserialize response");
        assert_eq!(burn_block_height, 2575799);
    }

    #[test]
    fn core_info_call_for_burn_block_height_should_fail() {
        let config = TestConfig::new();
        let h = spawn(move || config.client.get_burn_block_height());
        write_response(
            config.mock_server,
            b"HTTP/1.1 200 OK\n\n4e99f99bc4a05437abb8c7d0c306618f45b203196498e2ebe287f10497124958",
        );
        assert!(h.join().unwrap().is_err());
    }

    #[test]
    fn get_account_nonce_should_succeed() {
        let config = TestConfig::new();
        let address = config.client.stacks_address;
        let h = spawn(move || config.client.get_account_nonce(&address));
        write_response(
            config.mock_server,
            b"HTTP/1.1 200 OK\n\n{\"nonce\":0,\"balance\":\"0x00000000000000000000000000000000\",\"locked\":\"0x00000000000000000000000000000000\",\"unlock_height\":0}"
        );
        let nonce = h.join().unwrap().expect("Failed to deserialize response");
        assert_eq!(nonce, 0);
    }

    #[test]
    fn get_account_nonce_should_fail() {
        let config = TestConfig::new();
        let address = config.client.stacks_address;
        let h = spawn(move || config.client.get_account_nonce(&address));
        write_response(
            config.mock_server,
            b"HTTP/1.1 200 OK\n\n{\"nonce\":\"invalid nonce\",\"balance\":\"0x00000000000000000000000000000000\",\"locked\":\"0x00000000000000000000000000000000\",\"unlock_height\":0}"
        );
        assert!(h.join().unwrap().is_err());
    }

    #[test]
    fn parse_valid_signer_slots_should_succeed() {
        let config = TestConfig::new();
        let clarity_value_hex =
            "0x070b000000050c00000002096e756d2d736c6f7473010000000000000000000000000000000c067369676e6572051a8195196a9a7cf9c37cb13e1ed69a7bc047a84e050c00000002096e756d2d736c6f7473010000000000000000000000000000000c067369676e6572051a6505471146dcf722f0580911183f28bef30a8a890c00000002096e756d2d736c6f7473010000000000000000000000000000000c067369676e6572051a1d7f8e3936e5da5f32982cc47f31d7df9fb1b38a0c00000002096e756d2d736c6f7473010000000000000000000000000000000c067369676e6572051a126d1a814313c952e34c7840acec9211e1727fb80c00000002096e756d2d736c6f7473010000000000000000000000000000000c067369676e6572051a7374ea6bb39f2e8d3d334d62b9f302a977de339a";
        let value = ClarityValue::try_deserialize_hex_untyped(clarity_value_hex).unwrap();
        let signer_slots = config.client.parse_signer_slots(value).unwrap();
        assert_eq!(signer_slots.len(), 5);
        signer_slots
            .into_iter()
            .for_each(|(_address, slots)| assert!(slots == SIGNER_SLOTS_PER_USER as u128));
    }

    #[test]
    fn get_node_epoch_should_succeed() {
        let config = TestConfig::new();
        let h = spawn(move || config.client.get_node_epoch());
        write_response(
            config.mock_server,
            b"HTTP/1.1 200 OK\n\n{\"burn_block_height\":2575799,\"peer_version\":4207599113,\"pox_consensus\":\"64c8c3049ff6b939c65828e3168210e6bb32d880\",\"stable_pox_consensus\":\"72277bf9a3b115e13c0942825480d6cee0e9a0e8\",\"stable_burn_block_height\":2575792,\"server_version\":\"stacks-node d657bdd (feat/epoch-2.4:d657bdd, release build, linux [x86_64])\",\"network_id\":2147483648,\"parent_network_id\":118034699,\"stacks_tip_height\":145152,\"stacks_tip\":\"77219884fe434c0fa270d65592b4f082ab3e5d9922ac2bdaac34310aedc3d298\",\"stacks_tip_consensus_hash\":\"64c8c3049ff6b939c65828e3168210e6bb32d880\",\"genesis_chainstate_hash\":\"74237aa39aa50a83de11a4f53e9d3bb7d43461d1de9873f402e5453ae60bc59b\",\"unanchored_tip\":\"dde44222b6e6d81583b6b9c55db83e8716943ae9d0dc332fc39448ddd9b99dc2\",\"unanchored_seq\":0,\"exit_at_block_height\":null,\"node_public_key\":\"023c940136d5795d9dd82c0e87f4dd6a2a1db245444e7d70e34bb9605c3c3917b0\",\"node_public_key_hash\":\"e26cce8f6abe06b9fc81c3b11bcc821d2f1b8fd0\"}",
        );
        let epoch = h.join().unwrap().expect("Failed to deserialize response");
        assert_eq!(epoch, EpochId::UnsupportedEpoch);

        let config = TestConfig::new();
        let h = spawn(move || config.client.get_node_epoch());
        let height = BITCOIN_TESTNET_STACKS_25_BURN_HEIGHT;
        let response_bytes = format!("HTTP/1.1 200 OK\n\n{{\"burn_block_height\":{height},\"peer_version\":4207599113,\"pox_consensus\":\"64c8c3049ff6b939c65828e3168210e6bb32d880\",\"stable_pox_consensus\":\"72277bf9a3b115e13c0942825480d6cee0e9a0e8\",\"stable_burn_block_height\":2575792,\"server_version\":\"stacks-node d657bdd (feat/epoch-2.4:d657bdd, release build, linux [x86_64])\",\"network_id\":2147483648,\"parent_network_id\":118034699,\"stacks_tip_height\":145152,\"stacks_tip\":\"77219884fe434c0fa270d65592b4f082ab3e5d9922ac2bdaac34310aedc3d298\",\"stacks_tip_consensus_hash\":\"64c8c3049ff6b939c65828e3168210e6bb32d880\",\"genesis_chainstate_hash\":\"74237aa39aa50a83de11a4f53e9d3bb7d43461d1de9873f402e5453ae60bc59b\",\"unanchored_tip\":\"dde44222b6e6d81583b6b9c55db83e8716943ae9d0dc332fc39448ddd9b99dc2\",\"unanchored_seq\":0,\"exit_at_block_height\":null,\"node_public_key\":\"023c940136d5795d9dd82c0e87f4dd6a2a1db245444e7d70e34bb9605c3c3917b0\",\"node_public_key_hash\":\"e26cce8f6abe06b9fc81c3b11bcc821d2f1b8fd0\"}}");

        write_response(config.mock_server, response_bytes.as_bytes());
        let epoch = h.join().unwrap().expect("Failed to deserialize response");
        assert_eq!(epoch, EpochId::Epoch25);

        let config = TestConfig::new();
        let h = spawn(move || config.client.get_node_epoch());
        let height = BITCOIN_TESTNET_STACKS_30_BURN_HEIGHT;
        let response_bytes = format!("HTTP/1.1 200 OK\n\n{{\"burn_block_height\":{height},\"peer_version\":4207599113,\"pox_consensus\":\"64c8c3049ff6b939c65828e3168210e6bb32d880\",\"stable_pox_consensus\":\"72277bf9a3b115e13c0942825480d6cee0e9a0e8\",\"stable_burn_block_height\":2575792,\"server_version\":\"stacks-node d657bdd (feat/epoch-2.4:d657bdd, release build, linux [x86_64])\",\"network_id\":2147483648,\"parent_network_id\":118034699,\"stacks_tip_height\":145152,\"stacks_tip\":\"77219884fe434c0fa270d65592b4f082ab3e5d9922ac2bdaac34310aedc3d298\",\"stacks_tip_consensus_hash\":\"64c8c3049ff6b939c65828e3168210e6bb32d880\",\"genesis_chainstate_hash\":\"74237aa39aa50a83de11a4f53e9d3bb7d43461d1de9873f402e5453ae60bc59b\",\"unanchored_tip\":\"dde44222b6e6d81583b6b9c55db83e8716943ae9d0dc332fc39448ddd9b99dc2\",\"unanchored_seq\":0,\"exit_at_block_height\":null,\"node_public_key\":\"023c940136d5795d9dd82c0e87f4dd6a2a1db245444e7d70e34bb9605c3c3917b0\",\"node_public_key_hash\":\"e26cce8f6abe06b9fc81c3b11bcc821d2f1b8fd0\"}}");
        write_response(config.mock_server, response_bytes.as_bytes());
        let epoch = h.join().unwrap().expect("Failed to deserialize response");
        assert_eq!(epoch, EpochId::Epoch30);
    }

    #[test]
    fn get_node_epoch_should_fail() {
        let config = TestConfig::new();
        let h = spawn(move || config.client.get_node_epoch());
        write_response(
            config.mock_server,
            b"HTTP/1.1 200 OK\n\n4e99f99bc4a05437abb8c7d0c306618f45b203196498e2ebe287f10497124958",
        );
        assert!(h.join().unwrap().is_err());
    }
}
