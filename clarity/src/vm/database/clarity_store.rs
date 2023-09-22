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

use std::convert::TryInto;
use std::path::PathBuf;

use rusqlite::Connection;

use crate::vm::analysis::AnalysisDatabase;
use crate::vm::database::{
    BurnStateDB, ClarityDatabase, ClarityDeserializable, ClaritySerializable, HeadersDB,
    SqliteConnection, NULL_BURN_STATE_DB, NULL_HEADER_DB,
};
use crate::vm::errors::{
    CheckErrors, IncomparableError, InterpreterError, InterpreterResult as Result,
    InterpreterResult, RuntimeErrorType,
};
use crate::vm::events::StacksTransactionEvent;
use crate::vm::types::QualifiedContractIdentifier;
use stacks_common::util::hash::{hex_bytes, to_hex, Hash160, Sha512Trunc256Sum};

use crate::types::chainstate::{BlockHeaderHash, StacksBlockId, VRFSeed};
use crate::vm::contexts::GlobalContext;
use crate::vm::types::PrincipalData;
use crate::vm::Value;

pub struct NullBackingStore {}

pub type SpecialCaseHandler = &'static dyn Fn(
    // the current Clarity global context
    &mut GlobalContext,
    // the current sender
    Option<&PrincipalData>,
    // the current sponsor
    Option<&PrincipalData>,
    // the invoked contract
    &QualifiedContractIdentifier,
    // the invoked function name
    &str,
    // the function parameters
    &[Value],
    // the result of the function call
    &Value,
) -> Result<()>;

// These functions generally _do not_ return errors, rather, any errors in the underlying storage
//    will _panic_. The rationale for this is that under no condition should the interpreter
//    attempt to continue processing in the event of an unexpected storage error.
pub trait ClarityBackingStore {
    /// put K-V data into the committed datastore
    fn put_all(&mut self, items: Vec<(String, String)>);
    /// fetch K-V out of the committed datastore
    fn get(&mut self, key: &str) -> Option<String>;
    /// fetch K-V out of the committed datastore, along with the byte representation
    ///  of the Merkle proof for that key-value pair
    fn get_with_proof(&mut self, key: &str) -> Option<(String, Vec<u8>)>;
    fn has_entry(&mut self, key: &str) -> bool {
        self.get(key).is_some()
    }

    /// change the current MARF context to service reads from a different chain_tip
    ///   used to implement time-shifted evaluation.
    /// returns the previous block header hash on success
    fn set_block_hash(&mut self, bhh: StacksBlockId) -> Result<StacksBlockId>;

    /// Is None if `block_height` >= the "currently" under construction Stacks block height.
    fn get_block_at_height(&mut self, height: u32) -> Option<StacksBlockId>;

    /// this function returns the current block height, as viewed by this marfed-kv structure,
    ///  i.e., it changes on time-shifted evaluation. the open_chain_tip functions always
    ///   return data about the chain tip that is currently open for writing.
    fn get_current_block_height(&mut self) -> u32;

    fn get_open_chain_tip_height(&mut self) -> u32;
    fn get_open_chain_tip(&mut self) -> StacksBlockId;
    fn get_side_store(&mut self) -> &Connection;

    fn get_cc_special_cases_handler(&self) -> Option<SpecialCaseHandler> {
        None
    }

    /// The contract commitment is the hash of the contract, plus the block height in
    ///   which the contract was initialized.
    fn make_contract_commitment(&mut self, contract_hash: Sha512Trunc256Sum) -> String {
        let block_height = self.get_open_chain_tip_height();
        let cc = ContractCommitment {
            hash: contract_hash,
            block_height,
        };
        cc.serialize()
    }

    /// This function is used to obtain a committed contract hash, and the block header hash of the block
    ///   in which the contract was initialized. This data is used to store contract metadata in the side
    ///   store.
    fn get_contract_hash(
        &mut self,
        contract: &QualifiedContractIdentifier,
    ) -> Result<(StacksBlockId, Sha512Trunc256Sum)> {
        let key = make_contract_hash_key(contract);
        let contract_commitment = self
            .get(&key)
            .map(|x| ContractCommitment::deserialize(&x))
            .ok_or_else(|| CheckErrors::NoSuchContract(contract.to_string()))?;
        let ContractCommitment {
            block_height,
            hash: contract_hash,
        } = contract_commitment;
        let bhh = self.get_block_at_height(block_height)
            .expect("Should always be able to map from height to block hash when looking up contract information.");
        Ok((bhh, contract_hash))
    }

    fn insert_metadata(&mut self, contract: &QualifiedContractIdentifier, key: &str, value: &str) {
        let bhh = self.get_open_chain_tip();
        SqliteConnection::insert_metadata(
            self.get_side_store(),
            &bhh,
            &contract.to_string(),
            key,
            value,
        )
    }

    fn get_metadata(
        &mut self,
        contract: &QualifiedContractIdentifier,
        key: &str,
    ) -> Result<Option<String>> {
        let (bhh, _) = self.get_contract_hash(contract)?;
        Ok(SqliteConnection::get_metadata(
            self.get_side_store(),
            &bhh,
            &contract.to_string(),
            key,
        ))
    }

    fn get_metadata_manual(
        &mut self,
        at_height: u32,
        contract: &QualifiedContractIdentifier,
        key: &str,
    ) -> Result<Option<String>> {
        let bhh = self.get_block_at_height(at_height)
            .ok_or_else(|| {
                warn!("Unknown block height when manually querying metadata"; "block_height" => at_height);
                RuntimeErrorType::BadBlockHeight(at_height.to_string())
            })?;
        Ok(SqliteConnection::get_metadata(
            self.get_side_store(),
            &bhh,
            &contract.to_string(),
            key,
        ))
    }

    fn put_all_metadata(&mut self, items: Vec<((QualifiedContractIdentifier, String), String)>) {
        for ((contract, key), value) in items.into_iter() {
            self.insert_metadata(&contract, &key, &value);
        }
    }
}

// TODO: Figure out where this belongs
pub fn make_contract_hash_key(contract: &QualifiedContractIdentifier) -> String {
    format!("clarity-contract::{}", contract)
}

pub struct ContractCommitment {
    pub hash: Sha512Trunc256Sum,
    pub block_height: u32,
}

impl ClaritySerializable for ContractCommitment {
    fn serialize(&self) -> String {
        format!("{}{}", self.hash, to_hex(&self.block_height.to_be_bytes()))
    }
}

impl ClarityDeserializable<ContractCommitment> for ContractCommitment {
    fn deserialize(input: &str) -> ContractCommitment {
        assert_eq!(input.len(), 72);
        let hash = Sha512Trunc256Sum::from_hex(&input[0..64]).expect("Hex decode fail.");
        let height_bytes = hex_bytes(&input[64..72]).expect("Hex decode fail.");
        let block_height = u32::from_be_bytes(height_bytes.as_slice().try_into().unwrap());
        ContractCommitment { hash, block_height }
    }
}

impl Default for NullBackingStore {
    fn default() -> Self {
        NullBackingStore::new()
    }
}

impl NullBackingStore {
    pub fn new() -> Self {
        NullBackingStore {}
    }

    pub fn as_clarity_db(&mut self) -> ClarityDatabase {
        ClarityDatabase::new(self, &NULL_HEADER_DB, &NULL_BURN_STATE_DB)
    }

    pub fn as_analysis_db(&mut self) -> AnalysisDatabase {
        AnalysisDatabase::new(self)
    }
}

impl ClarityBackingStore for NullBackingStore {
    fn set_block_hash(&mut self, _bhh: StacksBlockId) -> Result<StacksBlockId> {
        panic!("NullBackingStore can't set block hash")
    }

    fn get(&mut self, _key: &str) -> Option<String> {
        panic!("NullBackingStore can't retrieve data")
    }

    fn get_with_proof(&mut self, _key: &str) -> Option<(String, Vec<u8>)> {
        panic!("NullBackingStore can't retrieve data")
    }

    fn get_side_store(&mut self) -> &Connection {
        panic!("NullBackingStore has no side store")
    }

    fn get_block_at_height(&mut self, _height: u32) -> Option<StacksBlockId> {
        panic!("NullBackingStore can't get block at height")
    }

    fn get_open_chain_tip(&mut self) -> StacksBlockId {
        panic!("NullBackingStore can't open chain tip")
    }

    fn get_open_chain_tip_height(&mut self) -> u32 {
        panic!("NullBackingStore can't get open chain tip height")
    }

    fn get_current_block_height(&mut self) -> u32 {
        panic!("NullBackingStore can't get current block height")
    }

    fn put_all(&mut self, mut _items: Vec<(String, String)>) {
        panic!("NullBackingStore cannot put")
    }
}

pub struct MemoryBackingStore {
    side_store: Connection,
}

impl Default for MemoryBackingStore {
    fn default() -> Self {
        MemoryBackingStore::new()
    }
}

impl MemoryBackingStore {
    pub fn new() -> MemoryBackingStore {
        let side_store = SqliteConnection::memory().unwrap();

        let mut memory_marf = MemoryBackingStore { side_store };

        memory_marf.as_clarity_db().initialize();

        memory_marf
    }

    pub fn as_clarity_db(&mut self) -> ClarityDatabase {
        ClarityDatabase::new(self, &NULL_HEADER_DB, &NULL_BURN_STATE_DB)
    }

    pub fn as_analysis_db(&mut self) -> AnalysisDatabase {
        AnalysisDatabase::new(self)
    }
}

impl ClarityBackingStore for MemoryBackingStore {
    fn set_block_hash(&mut self, bhh: StacksBlockId) -> InterpreterResult<StacksBlockId> {
        Err(RuntimeErrorType::UnknownBlockHeaderHash(BlockHeaderHash(bhh.0)).into())
    }

    fn get(&mut self, key: &str) -> Option<String> {
        SqliteConnection::get(self.get_side_store(), key)
    }

    fn get_with_proof(&mut self, key: &str) -> Option<(String, Vec<u8>)> {
        SqliteConnection::get(self.get_side_store(), key).map(|x| (x, vec![]))
    }

    fn get_side_store(&mut self) -> &Connection {
        &self.side_store
    }

    fn get_block_at_height(&mut self, height: u32) -> Option<StacksBlockId> {
        if height == 0 {
            Some(StacksBlockId([255; 32]))
        } else {
            None
        }
    }

    fn get_open_chain_tip(&mut self) -> StacksBlockId {
        StacksBlockId([255; 32])
    }

    fn get_open_chain_tip_height(&mut self) -> u32 {
        0
    }

    fn get_current_block_height(&mut self) -> u32 {
        1
    }

    fn get_cc_special_cases_handler(&self) -> Option<SpecialCaseHandler> {
        None
    }

    fn put_all(&mut self, items: Vec<(String, String)>) {
        for (key, value) in items.into_iter() {
            SqliteConnection::put(self.get_side_store(), &key, &value);
        }
    }
}
