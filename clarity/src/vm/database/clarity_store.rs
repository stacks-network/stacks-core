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

use core::panic;
use std::path::PathBuf;

use rusqlite::Connection;
use stacks_common::types::chainstate::{BlockHeaderHash, StacksBlockId, VRFSeed};
use stacks_common::util::hash::{hex_bytes, to_hex, Hash160, Sha512Trunc256Sum};

use super::structures::{
    BlockData, ContractAnalysisData, ContractData, ContractSizeData, PendingContract,
};
use crate::vm::analysis::{AnalysisDatabase, ContractAnalysis};
use crate::vm::contexts::GlobalContext;
use crate::vm::database::{
    BurnStateDB, ClarityDatabase, ClarityDeserializable, ClaritySerializable, HeadersDB,
    SqliteConnection, NULL_BURN_STATE_DB, NULL_HEADER_DB,
};
use crate::vm::errors::{
    CheckErrors, IncomparableError, InterpreterError, InterpreterResult as Result,
    InterpreterResult, RuntimeErrorType,
};
use crate::vm::events::StacksTransactionEvent;
use crate::vm::types::{PrincipalData, QualifiedContractIdentifier};
use crate::vm::{ContractContext, Value};

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
    fn put_all_data(&mut self, items: Vec<(String, String)>) -> Result<()>;
    /// fetch K-V out of the committed datastore
    fn get_data(&mut self, key: &str) -> Result<Option<String>>;
    /// fetch K-V out of the committed datastore, along with the byte representation
    ///  of the Merkle proof for that key-value pair
    fn get_data_with_proof(&mut self, key: &str) -> Result<Option<(String, Vec<u8>)>>;
    fn has_data_entry(&mut self, key: &str) -> Result<bool> {
        Ok(self.get_data(key)?.is_some())
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

        trace!("STORE get_contract_hash for {contract} and key {key}");

        let contract_commitment = self
            .get_data(&key)?
            .map(|x| ContractCommitment::deserialize(&x))
            .ok_or_else(|| CheckErrors::NoSuchContract(contract.to_string()))?;

        let ContractCommitment {
            block_height,
            hash: contract_hash,
        } = contract_commitment?;

        let bhh = self.get_block_at_height(block_height)
            .ok_or_else(|| InterpreterError::Expect("Should always be able to map from height to block hash when looking up contract information.".into()))?;
        
        Ok((bhh, contract_hash))
    }

    /// Retrieves the specified contract from the backing store. Returns
    /// [None] if the contract is not found.
    fn get_contract(
        &mut self,
        contract_identifier: &QualifiedContractIdentifier,
    ) -> Result<Option<ContractContext>> {
        trace!("STORE get_contract for {contract_identifier}");
        let (bhh, _) = self.get_contract_hash(contract_identifier)?;

        let contract = SqliteConnection::get_contract(
            self.get_side_store(),
            &contract_identifier.issuer.to_string(),
            &contract_identifier.name.to_string(),
            &bhh,
        )?;

        Ok(if let Some(data) = contract {
            let decoded = lz4_flex::block::decompress(&data.contract, data.contract_size as usize)
                .expect("ERROR: Failed to decompress contract AST.");
            Some(rmp_serde::decode::from_slice(&decoded)?)
        } else {
            None
        })
    }

    fn get_contract_size(
        &mut self,
        contract_identifier: &QualifiedContractIdentifier,
    ) -> Result<u32> {
        trace!("STORE get_contract_size for {contract_identifier}");
        let (bhh, _) = self.get_contract_hash(contract_identifier)?;

        let sizes = SqliteConnection::get_contract_sizes(
            self.get_side_store(),
            &contract_identifier.issuer.to_string(),
            &contract_identifier.name.to_string(),
            &bhh,
        )?;

        Ok(sizes.source_size + sizes.data_size)
    }

    /// Checks for the existance of the specified contract in the backing store.
    fn contract_exists(
        &mut self,
        contract_identifier: &QualifiedContractIdentifier,
    ) -> Result<bool> {
        trace!("STORE contract_exists for {contract_identifier}");

        let (bhh, _) = match self.get_contract_hash(contract_identifier) {
            Ok(x) => x,
            Err(crate::vm::errors::Error::Unchecked(CheckErrors::NoSuchContract(_))) => {
                return Ok(false)
            }
            Err(e) => return Err(e),
        };

        let result = SqliteConnection::contract_exists(
            self.get_side_store(),
            &contract_identifier.issuer.to_string(),
            &contract_identifier.name.to_string(),
            &bhh,
        )?;
        trace!("STORE contract_exists for {contract_identifier} = {result}");

        Ok(result)
    }

    /// Inserts the provided contract data into the backing store at the current
    /// chain tip.
    fn insert_contract(&mut self, data: &mut PendingContract) -> Result<ContractData> {
        trace!(
            "STORE insert_contract for {}",
            &data.contract.contract_identifier
        );
        let chain_tip_height = self.get_open_chain_tip_height();
        let chain_tip = self.get_open_chain_tip();

        // 'content-hash': src_hash
        // 'contract-src': data.source
        // 'contract-size': src_len
        let src_bytes = data.source.as_bytes();
        let src_hash = Sha512Trunc256Sum::from_data(&src_bytes);
        let src_len = src_bytes.len();

        // Compress the plain-text source code.
        let mut src_compressed = Vec::<u8>::with_capacity(src_len);
        lzzzz::lz4::compress_to_vec(
            src_bytes,
            &mut src_compressed,
            lzzzz::lz4::ACC_LEVEL_DEFAULT,
        )
        .expect("ERROR: Failed to compress contract source code.");

        // Serialize and compress the contract AST.
        let contract_serialized =
            rmp_serde::to_vec(&data.contract).expect("ERROR: Failed to serialize contract AST.");
        let contract_serialized_len = contract_serialized.len() as u32;

        let contract_compressed = lz4_flex::block::compress(&contract_serialized);

        let mut data = ContractData {
            // This id will be updated with the actual id of the contract in the
            // backing store upon insert.
            id: 0,
            issuer: data.contract.contract_identifier.issuer.to_string(),
            name: data.contract.contract_identifier.name.to_string(),
            // Plain-text contract source length, so that we know the size of
            // buffer to allocate when decompressing.
            source_size: src_len as u32,
            source: src_compressed,
            contract: contract_compressed,
            // Serialized contract length, so that we know the size of buffer
            // to allocate when decompressing.
            contract_size: contract_serialized_len,
            contract_hash: src_hash.0.to_vec(),
            data_size: data.contract.data_size as u32,
        };

        SqliteConnection::insert_contract(
            self.get_side_store(),
            &chain_tip,
            chain_tip_height,
            &mut data,
        )?;

        Ok(data)
    }

    /// Inserts the provided contract analysis data into the backing store at
    /// the current chain tip.
    fn insert_contract_analysis(
        &mut self,
        contract_id: u32,
        analysis: &ContractAnalysis,
    ) -> Result<()> {
        trace!("STORE insert_contract_analysis for {}", contract_id);
        let analysis_serialized = rmp_serde::to_vec(analysis)?;

        let mut analysis_compressed = Vec::<u8>::with_capacity(analysis_serialized.len());
        lzzzz::lz4::compress_to_vec(
            &analysis_serialized,
            &mut analysis_compressed,
            lzzzz::lz4::ACC_LEVEL_DEFAULT,
        )?;

        SqliteConnection::insert_contract_analysis(
            self.get_side_store(),
            contract_id,
            &analysis_compressed,
        )
    }

    fn insert_metadata(&mut self, contract: &QualifiedContractIdentifier, key: &str, value: &str) -> Result<()> {
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
        SqliteConnection::get_metadata(self.get_side_store(), &bhh, &contract.to_string(), key)
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
        SqliteConnection::get_metadata(self.get_side_store(), &bhh, &contract.to_string(), key)
    }

    fn put_all_metadata(
        &mut self,
        items: Vec<((QualifiedContractIdentifier, String), String)>,
    ) -> Result<()> {
        for ((contract, key), value) in items.into_iter() {
            self.insert_metadata(&contract, &key, &value)?;
        }
        Ok(())
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
    fn deserialize(input: &str) -> Result<ContractCommitment> {
        if input.len() != 72 {
            return Err(InterpreterError::Expect("Unexpected input length".into()).into());
        }
        let hash = Sha512Trunc256Sum::from_hex(&input[0..64])
            .map_err(|_| InterpreterError::Expect("Hex decode fail.".into()))?;
        let height_bytes = hex_bytes(&input[64..72])
            .map_err(|_| InterpreterError::Expect("Hex decode fail.".into()))?;
        let block_height = u32::from_be_bytes(
            height_bytes
                .as_slice()
                .try_into()
                .map_err(|_| InterpreterError::Expect("Block height decode fail.".into()))?,
        );
        Ok(ContractCommitment { hash, block_height })
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

#[allow(clippy::panic)]
impl ClarityBackingStore for NullBackingStore {
    fn set_block_hash(&mut self, _bhh: StacksBlockId) -> Result<StacksBlockId> {
        panic!("NullBackingStore can't set block hash")
    }

    fn get_data(&mut self, _key: &str) -> Result<Option<String>> {
        panic!("NullBackingStore can't retrieve data")
    }

    fn get_data_with_proof(&mut self, _key: &str) -> Result<Option<(String, Vec<u8>)>> {
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

    fn put_all_data(&mut self, mut _items: Vec<(String, String)>) -> Result<()> {
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
    #[allow(clippy::unwrap_used)]
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

    fn get_data(&mut self, key: &str) -> Result<Option<String>> {
        SqliteConnection::get_data(self.get_side_store(), key)
    }

    fn get_data_with_proof(&mut self, key: &str) -> Result<Option<(String, Vec<u8>)>> {
        Ok(SqliteConnection::get_data(self.get_side_store(), key)?.map(|x| (x, vec![])))
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

    fn put_all_data(&mut self, items: Vec<(String, String)>) -> Result<()> {
        for (key, value) in items.into_iter() {
            SqliteConnection::put_data(self.get_side_store(), &key, &value)?;
        }
        Ok(())
    }
}
