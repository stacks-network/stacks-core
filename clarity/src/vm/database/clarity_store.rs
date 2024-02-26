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
use speedy::{Readable, Writable};
use stacks_common::types::chainstate::{BlockHeaderHash, StacksBlockId, VRFSeed};
use stacks_common::util::hash::{hex_bytes, to_hex, Hash160, Sha512Trunc256Sum};

use super::structures::{
    BlockData, ContractAnalysisData, ContractData, ContractId, ContractSizeData, PendingContract, StoredContract
};
use crate::vm::analysis::ContractAnalysis;
use crate::vm::contexts::GlobalContext;
use crate::vm::database::cache::with_clarity_cache;
use crate::vm::database::{
    BurnStateDB, ClarityDatabase, ClarityDeserializable, ClaritySerializable, HeadersDB,
    SqliteConnection, NULL_BURN_STATE_DB, NULL_HEADER_DB,
};
use crate::vm::errors::{
    CheckErrors, IncomparableError, InterpreterError, InterpreterResult as Result, RuntimeErrorType,
};
use crate::vm::events::StacksTransactionEvent;
use crate::vm::types::{PrincipalData, QualifiedContractIdentifier};
use crate::vm::{ContractContext, Value};

/// TODO: Duplicate
pub struct NullBackingStore {}

/// TODO: Document this type
pub type SpecialCaseHandler = &'static dyn Fn(
    // The current Clarity global context
    &mut GlobalContext,
    // The current sender, if present.
    Option<&PrincipalData>,
    // The current sponsor, if present.
    Option<&PrincipalData>,
    // The identifier for the invoked contract.
    &QualifiedContractIdentifier,
    // The name of the function being invoked.
    &str,
    // The arguments to the function being invoked.
    &[Value],
    // The result of the function being invoked.
    &Value,
) -> Result<()>;

/// The ClarityBackingStore trait is used to abstract over the persistence layer
/// of the Clarity VM. This allows for different implementations of the backing
/// store to be used, such as in-memory stores for testing, or disk-based stores
/// for production.
///
/// The primary consumer of this trait is the [`RollbackWrapper`](super::RollbackWrapper)
/// which is used to buffer pending writes to the backing store using nested
/// transactions. This allows for the Clarity VM to perform a "dry run" of a
/// transaction, and then commit the changes to the backing store if the
/// transaction is successful.
///
/// In a live node, the primary implementor of this trait is the [`WritableMarfStore`]
/// in the `stackslib` chainstate index code. It implements 
/// [`get_side_store`](ClarityBackingStore::get_side_store) to provide a reference 
/// to its database [`Connection`] for the Clarity VM to use via this trait.
pub trait ClarityBackingStore {
    /// Accepts a list of key-value pairs and writes them to the backing store.
    fn put_all_data(&mut self, items: Vec<(String, String)>) -> Result<()>;

    /// Attempts to fetch the value associated with the provided key from the
    /// consensus-critical backing store. Returns [`None`] if the key is not found.
    fn get_data(&mut self, key: &str) -> Result<Option<String>>;

    /// Attempts to fetch the value associated with the provided key from the
    /// consensus-critical backing store, as well as the byte representation
    /// of the Merkle proof for that key-value pair. 
    ///
    /// Returns [`None`] if the key is not found.
    fn get_data_with_proof(&mut self, key: &str) -> Result<Option<(String, Vec<u8>)>>;

    /// Returns `true` if the provided key exists in the backing store, and `false`
    /// otherwise.
    fn has_data_entry(&mut self, key: &str) -> Result<bool> {
        Ok(self.get_data(key)?.is_some())
    }

    /// Change the current MARF context to service reads from a different chain_tip
    /// used to implement time-shifted evaluation.
    /// Returns the previous block header hash on success.
    fn set_block_hash(&mut self, bhh: StacksBlockId) -> Result<StacksBlockId>;

    /// Returns the index block hash for the Stacks block at the given block height.
    /// 
    /// Returns [`None`] if `block_height` >= the "currently" under construction 
    /// Stacks block height.
    fn get_block_at_height(&mut self, height: u32) -> Option<StacksBlockId>;

    /// this function returns the current block height, as viewed by this marfed-kv structure,
    ///  i.e., it changes on time-shifted evaluation. the open_chain_tip functions always
    ///   return data about the chain tip that is currently open for writing.
    fn get_current_block_height(&mut self) -> u32;

    fn get_open_chain_tip_height(&mut self) -> u32;
    fn get_open_chain_tip(&mut self) -> StacksBlockId;
    fn get_side_store(&mut self) -> &Connection;

    /// TODO: Document this function
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
    ) -> Result<Option<(StacksBlockId, Sha512Trunc256Sum)>> {
        let key = make_contract_hash_key(contract);
        let contract_commitment_serialized = self.get_data(&key)?;

        if let Some(serialized) = contract_commitment_serialized {
            let deserialized = ContractCommitment::deserialize(&serialized)
                .map_err(|e| InterpreterError::InterpreterError(e.to_string()))?;

            let bhh = self.get_block_at_height(deserialized.block_height)
                .ok_or_else(|| InterpreterError::Expect(
                    "Should always be able to map from height to block hash when looking up contract information.".into())
                )?;

            Ok(Some((bhh, deserialized.hash)))
        } else {
            Err(CheckErrors::NoSuchContract(contract.to_string()).into())
            //Ok(None)
        }
    }

    /// Retrieves the specified contract from the backing store. Returns
    /// [None] if the contract is not found.
    fn get_contract(
        &mut self,
        contract_identifier: &QualifiedContractIdentifier,
    ) -> Result<Option<StoredContract>> {
        test_debug!("STORE get_contract for {contract_identifier}");
        let (bhh, contract_hash) = match self.get_contract_hash(contract_identifier) {
            Ok(Some(x)) => x,
            Ok(None) => return Ok(None),
            Err(err) => match err {
                crate::vm::Error::Unchecked(CheckErrors::NoSuchContract(_)) => return Ok(None),
                _ => return Err(err.into()),
            }
        };

        let contract = SqliteConnection::get_contract(
            self.get_side_store(),
            &contract_identifier.issuer.to_string(),
            &contract_identifier.name.to_string(),
            &bhh,
        )?;

        Ok(if let Some(data) = contract {
            let context_decompressed =
                lz4_flex::block::decompress(&data.contract, data.contract_size as usize)?;
            //let context = rmp_serde::decode::from_slice(&context_decompressed)?;
            let context = ContractContext::read_from_buffer(&context_decompressed)
                .expect("failed to deserialize contract context");

            let src_decompressed =
                lz4_flex::block::decompress(&data.source, data.source_size as usize)?;
            test_debug!("STORE contract found with id #{}", data.id);

            Some(StoredContract {
                id: data.id,
                issuer: data.issuer,
                name: data.name,
                contract: context,
                source_size: src_decompressed.len() as u32,
                source: String::from_utf8(src_decompressed)?,
                data_size: data.data_size,
                block_hash: bhh,
                contract_hash,
            })
        } else {
            test_debug!("STORE contract was not found");
            None
        })
    }

    fn get_contract_size(
        &mut self,
        contract_identifier: &QualifiedContractIdentifier,
    ) -> Result<u32> {
        test_debug!("STORE get_contract_size for {contract_identifier}");
        let (bhh, _) = self
            .get_contract_hash(contract_identifier)?
            .ok_or(CheckErrors::NoSuchContract(contract_identifier.to_string()))?;

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
        let (bhh, _) = match self.get_contract_hash(contract_identifier) {
            Ok(Some(x)) => x,
            Ok(None) => return Ok(false),
            Err(err) => match err {
                crate::vm::Error::Unchecked(CheckErrors::NoSuchContract(_)) => return Ok(false),
                _ => return Err(err.into()),
            }
        };

        let result = SqliteConnection::contract_exists(
            self.get_side_store(),
            &contract_identifier.issuer.to_string(),
            &contract_identifier.name.to_string(),
            &bhh,
        )?;

        Ok(result)
    }

    /// Inserts the provided contract data into the backing store.
    fn insert_contract(&mut self, data: &mut PendingContract) -> Result<ContractData> {
        let contract_identifier = &data.contract.contract_identifier;
        trace!("STORE insert_contract for {contract_identifier}");
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
            &src_bytes,
            &mut src_compressed,
            lzzzz::lz4::ACC_LEVEL_DEFAULT,
        )?;

        // Serialize and compress the contract AST.
        //let contract_serialized = rmp_serde::to_vec(&data.contract)?;
        let contract_serialized = data.contract.write_to_vec()
            .expect("failed to serialize contract context");
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

        SqliteConnection::insert_contract(self.get_side_store(), &chain_tip, &mut data)?;

        Ok(data)
    }

    /// Inserts the provided contract analysis data into the backing store at
    /// the current chain tip.
    fn insert_contract_analysis(
        &mut self,
        contract_id: ContractId,
        analysis: &ContractAnalysis,
    ) -> Result<()> {
        let contract_id = match contract_id {
            ContractId::QualifiedContractIdentifier(contract_identifier) => {
                let (bhh, _) = self
                    .get_contract_hash(contract_identifier)?
                    .ok_or(CheckErrors::NoSuchContract(contract_identifier.to_string()))?;

                SqliteConnection::get_internal_contract_id(
                        self.get_side_store(), 
                        &contract_identifier.issuer.to_string(), 
                        &contract_identifier.name.to_string(), 
                        &bhh
                    )?
                    .ok_or(CheckErrors::Expects(
                        "Could not insert contract analysis because the internal contract id could not be resolved.".into())
                    )?
            }
            ContractId::Id(id) => {
                id
            }
        };

        let analysis_serialized = analysis.write_to_vec()
            .expect("failed to serialize contract context");

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
            analysis_serialized.len()
        )
    }

    fn get_contract_id(&mut self, contract_id: ContractId) -> Result<Option<u32>> {
        test_debug!("STORE get_contract_id for {contract_id:?}");
        match contract_id {
            ContractId::QualifiedContractIdentifier(contract_identifier) => {
                test_debug!("STORE get_contract_id: resolving block height for {contract_identifier}");
                match self.get_contract_hash(contract_identifier)? {
                    None => {
                        test_debug!("STORE get_contract_id: contract not found for {contract_identifier}");
                        Ok(None)
                    },
                    Some((bhh, _)) => {
                        test_debug!("STORE get_contract_id: resolved block height for {contract_identifier}: {bhh}");
                        Ok(SqliteConnection::get_internal_contract_id(
                            self.get_side_store(), 
                            &contract_identifier.issuer.to_string(), 
                            &contract_identifier.name.to_string(), 
                            &bhh)?
                            .map(|id| {
                                test_debug!("STORE get_contract_id: resolved internal contract id for {contract_identifier}: {id}");
                                with_clarity_cache(|cache| 
                                    cache.push_contract_id(contract_identifier.clone(), id)
                                );
                                id
                            })
                        )
                    }
                }
            }
            ContractId::Id(id) => {
                Ok(Some(id))
            }
        }

    }

    fn get_contract_analysis(
        &mut self,
        contract_id: ContractId,
    ) -> Result<Option<ContractAnalysis>> {
        test_debug!("STORE get_contract_analysis for {contract_id:?}");

        let contract_id = match self.get_contract_id(contract_id)? {
            Some(id) => id,
            None => return Ok(None),
        };
    
        test_debug!("STORE get_contract_analysis: fetching contract analysis for {contract_id}");
        let analysis = SqliteConnection::get_contract_analysis(
            self.get_side_store(),
            contract_id
        )?;
        
        if let Some(analysis) = analysis {
            test_debug!("STORE get_contract_analysis: contract analysis found for {contract_id}; decompressing...");
            let analysis_decompressed = lz4_flex::block::decompress(&analysis.analysis, (analysis.analysis_size + 1) as usize)
                .expect("failed to decompress contract analysis");
            test_debug!("STORE get_contract_analysis: decompression successful; deserializing...");
            //let analysis = rmp_serde::decode::from_slice(&analysis_decompressed)?;
            let analysis = ContractAnalysis::read_from_buffer(&analysis_decompressed)
                .expect("failed to deserialize contract context");
            test_debug!("STORE get_contract_analysis: deserialization successful; returning analysis");
            Ok(Some(analysis))
        } else {
            test_debug!("STORE get_contract_analysis: contract analysis NOT found for {contract_id}");
            Ok(None)
        }
    }

    #[deprecated]
    fn insert_metadata(
        &mut self,
        contract: &QualifiedContractIdentifier,
        key: &str,
        value: &str,
    ) -> Result<()> {
        let bhh = self.get_open_chain_tip();
        SqliteConnection::insert_metadata(
            self.get_side_store(),
            &bhh,
            &contract.to_string(),
            key,
            value,
        )
    }

    #[deprecated]
    fn get_metadata(
        &mut self,
        contract: &QualifiedContractIdentifier,
        key: &str,
    ) -> Result<Option<String>> {
        if let Some((bhh, _)) = self.get_contract_hash(contract)? {
            SqliteConnection::get_metadata(self.get_side_store(), &bhh, &contract.to_string(), key)
        } else {
            Ok(None)
        }
    }

    #[deprecated]
    fn get_metadata_manual(
        &mut self,
        at_height: u32,
        contract: &QualifiedContractIdentifier,
        key: &str,
    ) -> std::result::Result<Option<String>, crate::vm::errors::Error> {
        let bhh = self.get_block_at_height(at_height)
            .ok_or_else(|| {
                warn!("Unknown block height when manually querying metadata"; "block_height" => at_height);
                RuntimeErrorType::BadBlockHeight(at_height.to_string())
            })?;
        let result = SqliteConnection::get_metadata(
            self.get_side_store(),
            &bhh,
            &contract.to_string(),
            key,
        )?;
        Ok(result)
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

#[derive(Debug, PartialEq)]
#[derive(Readable, Writable)]
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
    fn deserialize(
        input: &str,
    ) -> std::result::Result<ContractCommitment, crate::vm::errors::Error> {
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
}

impl ClarityBackingStore for MemoryBackingStore {
    fn set_block_hash(&mut self, bhh: StacksBlockId) -> Result<StacksBlockId> {
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
