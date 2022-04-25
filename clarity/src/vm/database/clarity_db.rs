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

use std::collections::{HashMap, VecDeque};
use std::convert::{TryFrom, TryInto};

use crate::vm::analysis::{AnalysisDatabase, ContractAnalysis};
use crate::vm::contracts::Contract;
use crate::vm::costs::CostOverflowingMath;
use crate::vm::costs::ExecutionCost;
use crate::vm::database::structures::{
    ClarityDeserializable, ClaritySerializable, ContractMetadata, DataMapMetadata,
    DataVariableMetadata, FungibleTokenMetadata, NonFungibleTokenMetadata, STXBalance,
    STXBalanceSnapshot, SimmedBlock,
};
use crate::vm::database::ClarityBackingStore;
use crate::vm::database::RollbackWrapper;
use crate::vm::errors::{
    CheckErrors, Error, IncomparableError, InterpreterError, InterpreterResult as Result,
    RuntimeErrorType,
};
use crate::vm::representations::ClarityName;
use crate::vm::types::{
    serialization::NONE_SERIALIZATION_LEN, OptionalData, PrincipalData,
    QualifiedContractIdentifier, StandardPrincipalData, TupleData, TupleTypeSignature,
    TypeSignature, Value, NONE,
};
use stacks_common::util::hash::{to_hex, Hash160, Sha256Sum, Sha512Trunc256Sum};

use crate::types::chainstate::{
    BlockHeaderHash, BurnchainHeaderHash, SortitionId, StacksAddress, StacksBlockId, VRFSeed,
};

use crate::vm::types::byte_len_of_serialization;

use crate::types::{StacksEpoch as GenericStacksEpoch, StacksEpochId, PEER_VERSION_EPOCH_2_0};

use stacks_common::consts::{
    BITCOIN_REGTEST_FIRST_BLOCK_HASH, BITCOIN_REGTEST_FIRST_BLOCK_HEIGHT,
    BITCOIN_REGTEST_FIRST_BLOCK_TIMESTAMP, FIRST_BURNCHAIN_CONSENSUS_HASH, FIRST_STACKS_BLOCK_HASH,
};
use stacks_common::types::chainstate::ConsensusHash;

use super::clarity_store::SpecialCaseHandler;
use super::key_value_wrapper::ValueResult;

pub const STORE_CONTRACT_SRC_INTERFACE: bool = true;

pub type StacksEpoch = GenericStacksEpoch<ExecutionCost>;

#[repr(u8)]
pub enum StoreType {
    DataMap = 0x00,
    Variable = 0x01,
    FungibleToken = 0x02,
    CirculatingSupply = 0x03,
    NonFungibleToken = 0x04,
    DataMapMeta = 0x05,
    VariableMeta = 0x06,
    FungibleTokenMeta = 0x07,
    NonFungibleTokenMeta = 0x08,
    Contract = 0x09,
    SimmedBlock = 0x10,
    SimmedBlockHeight = 0x11,
    Nonce = 0x12,
    STXBalance = 0x13,
    PoxSTXLockup = 0x14,
    PoxUnlockHeight = 0x15,
}

pub struct ClarityDatabase<'a> {
    pub store: RollbackWrapper<'a>,
    headers_db: &'a dyn HeadersDB,
    burn_state_db: &'a dyn BurnStateDB,
}

pub trait HeadersDB {
    fn get_stacks_block_header_hash_for_block(
        &self,
        id_bhh: &StacksBlockId,
    ) -> Option<BlockHeaderHash>;
    fn get_burn_header_hash_for_block(&self, id_bhh: &StacksBlockId)
        -> Option<BurnchainHeaderHash>;
    fn get_consensus_hash_for_block(&self, id_bhh: &StacksBlockId) -> Option<ConsensusHash>;
    fn get_vrf_seed_for_block(&self, id_bhh: &StacksBlockId) -> Option<VRFSeed>;
    fn get_burn_block_time_for_block(&self, id_bhh: &StacksBlockId) -> Option<u64>;
    fn get_burn_block_height_for_block(&self, id_bhh: &StacksBlockId) -> Option<u32>;
    fn get_miner_address(&self, id_bhh: &StacksBlockId) -> Option<StacksAddress>;
}

pub trait BurnStateDB {
    fn get_v1_unlock_height(&self) -> u32;

    /// Returns the *burnchain block height* at that `sortition_id` is associated with.
    fn get_burn_block_height(&self, sortition_id: &SortitionId) -> Option<u32>;

    /// Returns the height of the burnchain when the Stacks chain started running.
    fn get_burn_start_height(&self) -> u32;

    fn get_pox_prepare_length(&self) -> u32;
    fn get_pox_reward_cycle_length(&self) -> u32;
    fn get_pox_rejection_fraction(&self) -> u64;

    /// Returns the burnchain header hash for the given burn block height, as queried from the given SortitionId.
    ///
    /// Returns Some if `self.get_burn_start_height() <= height < self.get_burn_block_height(sorition_id)`, and None otherwise.
    fn get_burn_header_hash(
        &self,
        height: u32,
        sortition_id: &SortitionId,
    ) -> Option<BurnchainHeaderHash>;

    /// Lookup a `SortitionId` keyed to a `ConsensusHash`.
    ///
    /// Returns None if no block found.
    fn get_sortition_id_from_consensus_hash(
        &self,
        consensus_hash: &ConsensusHash,
    ) -> Option<SortitionId>;

    /// The epoch is defined as by a start and end height. This returns
    /// the epoch enclosing `height`.
    fn get_stacks_epoch(&self, height: u32) -> Option<StacksEpoch>;
    fn get_stacks_epoch_by_epoch_id(&self, epoch_id: &StacksEpochId) -> Option<StacksEpoch>;
}

impl HeadersDB for &dyn HeadersDB {
    fn get_stacks_block_header_hash_for_block(
        &self,
        id_bhh: &StacksBlockId,
    ) -> Option<BlockHeaderHash> {
        (*self).get_stacks_block_header_hash_for_block(id_bhh)
    }
    fn get_burn_header_hash_for_block(&self, bhh: &StacksBlockId) -> Option<BurnchainHeaderHash> {
        (*self).get_burn_header_hash_for_block(bhh)
    }
    fn get_consensus_hash_for_block(&self, id_bhh: &StacksBlockId) -> Option<ConsensusHash> {
        (*self).get_consensus_hash_for_block(id_bhh)
    }
    fn get_vrf_seed_for_block(&self, bhh: &StacksBlockId) -> Option<VRFSeed> {
        (*self).get_vrf_seed_for_block(bhh)
    }
    fn get_burn_block_time_for_block(&self, bhh: &StacksBlockId) -> Option<u64> {
        (*self).get_burn_block_time_for_block(bhh)
    }
    fn get_burn_block_height_for_block(&self, bhh: &StacksBlockId) -> Option<u32> {
        (*self).get_burn_block_height_for_block(bhh)
    }
    fn get_miner_address(&self, bhh: &StacksBlockId) -> Option<StacksAddress> {
        (*self).get_miner_address(bhh)
    }
}

impl BurnStateDB for &dyn BurnStateDB {
    fn get_v1_unlock_height(&self) -> u32 {
        (*self).get_v1_unlock_height()
    }

    fn get_burn_block_height(&self, sortition_id: &SortitionId) -> Option<u32> {
        (*self).get_burn_block_height(sortition_id)
    }

    fn get_sortition_id_from_consensus_hash(
        &self,
        consensus_hash: &ConsensusHash,
    ) -> Option<SortitionId> {
        (*self).get_sortition_id_from_consensus_hash(consensus_hash)
    }

    fn get_burn_start_height(&self) -> u32 {
        (*self).get_burn_start_height()
    }

    fn get_burn_header_hash(
        &self,
        height: u32,
        sortition_id: &SortitionId,
    ) -> Option<BurnchainHeaderHash> {
        (*self).get_burn_header_hash(height, sortition_id)
    }

    fn get_stacks_epoch(&self, height: u32) -> Option<StacksEpoch> {
        (*self).get_stacks_epoch(height)
    }

    fn get_pox_prepare_length(&self) -> u32 {
        (*self).get_pox_prepare_length()
    }

    fn get_pox_reward_cycle_length(&self) -> u32 {
        (*self).get_pox_reward_cycle_length()
    }

    fn get_pox_rejection_fraction(&self) -> u64 {
        (*self).get_pox_rejection_fraction()
    }
    fn get_stacks_epoch_by_epoch_id(&self, epoch_id: &StacksEpochId) -> Option<StacksEpoch> {
        (*self).get_stacks_epoch_by_epoch_id(epoch_id)
    }
}

pub struct NullHeadersDB {}
pub struct NullBurnStateDB {
    epoch: StacksEpochId,
}

pub const NULL_HEADER_DB: NullHeadersDB = NullHeadersDB {};
pub const NULL_BURN_STATE_DB: NullBurnStateDB = NullBurnStateDB {
    epoch: StacksEpochId::Epoch20,
};

impl HeadersDB for NullHeadersDB {
    fn get_burn_header_hash_for_block(
        &self,
        id_bhh: &StacksBlockId,
    ) -> Option<BurnchainHeaderHash> {
        if *id_bhh == StacksBlockId::new(&FIRST_BURNCHAIN_CONSENSUS_HASH, &FIRST_STACKS_BLOCK_HASH)
        {
            let first_block_hash =
                BurnchainHeaderHash::from_hex(BITCOIN_REGTEST_FIRST_BLOCK_HASH).unwrap();
            Some(first_block_hash)
        } else {
            None
        }
    }
    fn get_vrf_seed_for_block(&self, _bhh: &StacksBlockId) -> Option<VRFSeed> {
        None
    }
    fn get_stacks_block_header_hash_for_block(
        &self,
        id_bhh: &StacksBlockId,
    ) -> Option<BlockHeaderHash> {
        if *id_bhh == StacksBlockId::new(&FIRST_BURNCHAIN_CONSENSUS_HASH, &FIRST_STACKS_BLOCK_HASH)
        {
            Some(FIRST_STACKS_BLOCK_HASH)
        } else {
            None
        }
    }
    fn get_consensus_hash_for_block(&self, _id_bhh: &StacksBlockId) -> Option<ConsensusHash> {
        None
    }
    fn get_burn_block_time_for_block(&self, id_bhh: &StacksBlockId) -> Option<u64> {
        if *id_bhh == StacksBlockId::new(&FIRST_BURNCHAIN_CONSENSUS_HASH, &FIRST_STACKS_BLOCK_HASH)
        {
            Some(BITCOIN_REGTEST_FIRST_BLOCK_TIMESTAMP as u64)
        } else {
            None
        }
    }
    fn get_burn_block_height_for_block(&self, id_bhh: &StacksBlockId) -> Option<u32> {
        if *id_bhh == StacksBlockId::new(&FIRST_BURNCHAIN_CONSENSUS_HASH, &FIRST_STACKS_BLOCK_HASH)
        {
            Some(BITCOIN_REGTEST_FIRST_BLOCK_HEIGHT as u32)
        } else {
            Some(1)
        }
    }
    fn get_miner_address(&self, _id_bhh: &StacksBlockId) -> Option<StacksAddress> {
        None
    }
}

impl BurnStateDB for NullBurnStateDB {
    fn get_burn_block_height(&self, _sortition_id: &SortitionId) -> Option<u32> {
        None
    }

    fn get_burn_start_height(&self) -> u32 {
        0
    }

    fn get_sortition_id_from_consensus_hash(
        &self,
        _consensus_hash: &ConsensusHash,
    ) -> Option<SortitionId> {
        None
    }

    fn get_burn_header_hash(
        &self,
        _height: u32,
        _sortition_id: &SortitionId,
    ) -> Option<BurnchainHeaderHash> {
        None
    }

    fn get_stacks_epoch(&self, _height: u32) -> Option<StacksEpoch> {
        Some(StacksEpoch {
            epoch_id: self.epoch.clone(),
            start_height: 0,
            end_height: u64::MAX,
            block_limit: ExecutionCost::max_value(),
            network_epoch: PEER_VERSION_EPOCH_2_0,
        })
    }
    fn get_stacks_epoch_by_epoch_id(&self, _epoch_id: &StacksEpochId) -> Option<StacksEpoch> {
        self.get_stacks_epoch(0)
    }

    fn get_v1_unlock_height(&self) -> u32 {
        u32::max_value()
    }

    fn get_pox_prepare_length(&self) -> u32 {
        panic!("NullBurnStateDB should not return PoX info");
    }

    fn get_pox_reward_cycle_length(&self) -> u32 {
        panic!("NullBurnStateDB should not return PoX info");
    }

    fn get_pox_rejection_fraction(&self) -> u64 {
        panic!("NullBurnStateDB should not return PoX info");
    }
}

impl<'a> ClarityDatabase<'a> {
    pub fn new(
        store: &'a mut dyn ClarityBackingStore,
        headers_db: &'a dyn HeadersDB,
        burn_state_db: &'a dyn BurnStateDB,
    ) -> ClarityDatabase<'a> {
        ClarityDatabase {
            store: RollbackWrapper::new(store),
            headers_db,
            burn_state_db,
        }
    }

    pub fn new_with_rollback_wrapper(
        store: RollbackWrapper<'a>,
        headers_db: &'a dyn HeadersDB,
        burn_state_db: &'a dyn BurnStateDB,
    ) -> ClarityDatabase<'a> {
        ClarityDatabase {
            store,
            headers_db,
            burn_state_db,
        }
    }

    pub fn initialize(&mut self) {}

    pub fn is_stack_empty(&self) -> bool {
        self.store.depth() == 0
    }

    /// Nest the key-value wrapper instance
    pub fn begin(&mut self) {
        self.store.nest();
    }

    /// Commit current key-value wrapper layer
    pub fn commit(&mut self) {
        self.store.commit();
    }

    /// Drop current key-value wrapper layer
    pub fn roll_back(&mut self) {
        self.store.rollback();
    }

    pub fn set_block_hash(
        &mut self,
        bhh: StacksBlockId,
        query_pending_data: bool,
    ) -> Result<StacksBlockId> {
        self.store.set_block_hash(bhh, query_pending_data)
    }

    pub fn put<T: ClaritySerializable>(&mut self, key: &str, value: &T) {
        self.store.put(&key, &value.serialize());
    }

    /// Like `put()`, but returns the serialized byte size of the stored value
    pub fn put_with_size<T: ClaritySerializable>(&mut self, key: &str, value: &T) -> u64 {
        let serialized = value.serialize();
        self.store.put(&key, &serialized);
        byte_len_of_serialization(&serialized)
    }

    pub fn get<T>(&mut self, key: &str) -> Option<T>
    where
        T: ClarityDeserializable<T>,
    {
        self.store.get::<T>(key)
    }

    pub fn get_value(&mut self, key: &str, expected: &TypeSignature) -> Option<ValueResult> {
        self.store.get_value(key, expected)
    }

    pub fn get_with_proof<T>(&mut self, key: &str) -> Option<(T, Vec<u8>)>
    where
        T: ClarityDeserializable<T>,
    {
        self.store.get_with_proof(key)
    }

    pub fn make_key_for_trip(
        contract_identifier: &QualifiedContractIdentifier,
        data: StoreType,
        var_name: &str,
    ) -> String {
        format!("vm::{}::{}::{}", contract_identifier, data as u8, var_name)
    }

    pub fn make_metadata_key(data: StoreType, var_name: &str) -> String {
        format!("vm-metadata::{}::{}", data as u8, var_name)
    }

    fn clarity_state_epoch_key() -> &'static str {
        "vm-epoch::epoch-version"
    }

    pub fn make_key_for_quad(
        contract_identifier: &QualifiedContractIdentifier,
        data: StoreType,
        var_name: &str,
        key_value: &str,
    ) -> String {
        format!(
            "vm::{}::{}::{}::{}",
            contract_identifier, data as u8, var_name, key_value
        )
    }

    pub fn insert_contract_hash(
        &mut self,
        contract_identifier: &QualifiedContractIdentifier,
        contract_content: &str,
    ) -> Result<()> {
        let hash = Sha512Trunc256Sum::from_data(contract_content.as_bytes());
        self.store
            .prepare_for_contract_metadata(contract_identifier, hash);
        // insert contract-size
        let key = ClarityDatabase::make_metadata_key(StoreType::Contract, "contract-size");
        self.insert_metadata(contract_identifier, &key, &(contract_content.len() as u64));

        // insert contract-src
        if STORE_CONTRACT_SRC_INTERFACE {
            let key = ClarityDatabase::make_metadata_key(StoreType::Contract, "contract-src");
            self.insert_metadata(contract_identifier, &key, &contract_content.to_string());
        }
        Ok(())
    }

    pub fn get_contract_src(
        &mut self,
        contract_identifier: &QualifiedContractIdentifier,
    ) -> Option<String> {
        let key = ClarityDatabase::make_metadata_key(StoreType::Contract, "contract-src");
        self.fetch_metadata(contract_identifier, &key)
            .ok()
            .flatten()
    }

    pub fn set_metadata(
        &mut self,
        contract_identifier: &QualifiedContractIdentifier,
        key: &str,
        data: &str,
    ) {
        self.store.insert_metadata(contract_identifier, key, data);
    }

    fn insert_metadata<T: ClaritySerializable>(
        &mut self,
        contract_identifier: &QualifiedContractIdentifier,
        key: &str,
        data: &T,
    ) {
        if self.store.has_metadata_entry(contract_identifier, key) {
            panic!(
                "Metadata entry '{}' already exists for contract: {}",
                key, contract_identifier
            );
        } else {
            self.store
                .insert_metadata(contract_identifier, key, &data.serialize());
        }
    }

    fn fetch_metadata<T>(
        &mut self,
        contract_identifier: &QualifiedContractIdentifier,
        key: &str,
    ) -> Result<Option<T>>
    where
        T: ClarityDeserializable<T>,
    {
        self.store
            .get_metadata(contract_identifier, key)
            .map(|x_opt| x_opt.map(|x| T::deserialize(&x)))
    }

    pub fn fetch_metadata_manual<T>(
        &mut self,
        at_height: u32,
        contract_identifier: &QualifiedContractIdentifier,
        key: &str,
    ) -> Result<Option<T>>
    where
        T: ClarityDeserializable<T>,
    {
        self.store
            .get_metadata_manual(at_height, contract_identifier, key)
            .map(|x_opt| x_opt.map(|x| T::deserialize(&x)))
    }

    // load contract analysis stored by an analysis_db instance.
    //   in unit testing, where the interpreter is invoked without
    //   an analysis pass, this function will fail to find contract
    //   analysis data
    pub fn load_contract_analysis(
        &mut self,
        contract_identifier: &QualifiedContractIdentifier,
    ) -> Option<ContractAnalysis> {
        self.store
            .get_metadata(contract_identifier, AnalysisDatabase::storage_key())
            // treat NoSuchContract error thrown by get_metadata as an Option::None --
            //    the analysis will propagate that as a CheckError anyways.
            .ok()?
            .map(|x| ContractAnalysis::deserialize(&x))
    }

    pub fn get_contract_size(
        &mut self,
        contract_identifier: &QualifiedContractIdentifier,
    ) -> Result<u64> {
        let key = ClarityDatabase::make_metadata_key(StoreType::Contract, "contract-size");
        let contract_size: u64 = self.fetch_metadata(contract_identifier, &key)?.expect(
            "Failed to read non-consensus contract metadata, even though contract exists in MARF.",
        );
        let key = ClarityDatabase::make_metadata_key(StoreType::Contract, "contract-data-size");
        let data_size: u64 = self.fetch_metadata(contract_identifier, &key)?.expect(
            "Failed to read non-consensus contract metadata, even though contract exists in MARF.",
        );

        // u64 overflow is _checked_ on insert into contract-data-size
        Ok(data_size + contract_size)
    }

    /// used for adding the memory usage of `define-constant` variables.
    pub fn set_contract_data_size(
        &mut self,
        contract_identifier: &QualifiedContractIdentifier,
        data_size: u64,
    ) -> Result<()> {
        let key = ClarityDatabase::make_metadata_key(StoreType::Contract, "contract-size");
        let contract_size: u64 = self.fetch_metadata(contract_identifier, &key)?.expect(
            "Failed to read non-consensus contract metadata, even though contract exists in MARF.",
        );
        contract_size.cost_overflow_add(data_size)?;

        let key = ClarityDatabase::make_metadata_key(StoreType::Contract, "contract-data-size");
        self.insert_metadata(contract_identifier, &key, &data_size);
        Ok(())
    }

    pub fn insert_contract(
        &mut self,
        contract_identifier: &QualifiedContractIdentifier,
        contract: Contract,
    ) {
        let key = ClarityDatabase::make_metadata_key(StoreType::Contract, "contract");
        self.insert_metadata(contract_identifier, &key, &contract);
    }

    pub fn has_contract(&mut self, contract_identifier: &QualifiedContractIdentifier) -> bool {
        let key = ClarityDatabase::make_metadata_key(StoreType::Contract, "contract");
        self.store.has_metadata_entry(contract_identifier, &key)
    }

    pub fn get_contract(
        &mut self,
        contract_identifier: &QualifiedContractIdentifier,
    ) -> Result<Contract> {
        let key = ClarityDatabase::make_metadata_key(StoreType::Contract, "contract");
        let data = self.fetch_metadata(contract_identifier, &key)?.expect(
            "Failed to read non-consensus contract metadata, even though contract exists in MARF.",
        );
        Ok(data)
    }

    pub fn ustx_liquid_supply_key() -> &'static str {
        "_stx-data::ustx_liquid_supply"
    }

    /// Returns the epoch version currently applied in the stored Clarity state.
    /// Since Clarity did not exist in stacks 1.0, the lowest valid epoch ID is stacks 2.0.
    /// The instantiation of subsequent epochs may bump up the epoch version in the clarity DB if
    /// Clarity is updated in that epoch.
    pub fn get_clarity_epoch_version(&mut self) -> StacksEpochId {
        match self.get(Self::clarity_state_epoch_key()) {
            Some(x) => u32::try_into(x).expect("Bad Clarity epoch version in stored Clarity state"),
            None => StacksEpochId::Epoch20,
        }
    }

    /// Should be called _after_ all of the epoch's initialization has been invoked
    pub fn set_clarity_epoch_version(&mut self, epoch: StacksEpochId) {
        self.put(Self::clarity_state_epoch_key(), &(epoch as u32))
    }

    /// Returns the _current_ total liquid ustx
    pub fn get_total_liquid_ustx(&mut self) -> u128 {
        self.get_value(
            ClarityDatabase::ustx_liquid_supply_key(),
            &TypeSignature::UIntType,
        )
        .map(|v| v.value.expect_u128())
        .unwrap_or(0)
    }

    fn set_ustx_liquid_supply(&mut self, set_to: u128) {
        self.put(
            ClarityDatabase::ustx_liquid_supply_key(),
            &Value::UInt(set_to),
        )
    }

    pub fn increment_ustx_liquid_supply(&mut self, incr_by: u128) -> Result<()> {
        let current = self.get_total_liquid_ustx();
        let next = current.checked_add(incr_by).ok_or_else(|| {
            error!("Overflowed `ustx-liquid-supply`");
            RuntimeErrorType::ArithmeticOverflow
        })?;
        self.set_ustx_liquid_supply(next);
        Ok(())
    }

    pub fn decrement_ustx_liquid_supply(&mut self, decr_by: u128) -> Result<()> {
        let current = self.get_total_liquid_ustx();
        let next = current.checked_sub(decr_by).ok_or_else(|| {
            error!("`stx-burn?` accepted that reduces `ustx-liquid-supply` below 0");
            RuntimeErrorType::ArithmeticUnderflow
        })?;
        self.set_ustx_liquid_supply(next);
        Ok(())
    }

    pub fn destroy(self) -> RollbackWrapper<'a> {
        self.store
    }

    pub fn is_in_regtest(&self) -> bool {
        cfg!(test)
    }
}

// Get block information

impl<'a> ClarityDatabase<'a> {
    /// Returns the ID of a *Stacks* block, by a *Stacks* block height.
    ///
    /// Fails if `block_height` >= the "currently" under construction Stacks block height.
    pub fn get_index_block_header_hash(&mut self, block_height: u32) -> StacksBlockId {
        self.store
            .get_block_header_hash(block_height)
            // the caller is responsible for ensuring that the block_height given
            //  is < current_block_height, so this should _always_ return a value.
            .expect("Block header hash must return for provided block height")
    }

    /// This is the height we are currently constructing. It comes from the MARF.
    pub fn get_current_block_height(&mut self) -> u32 {
        self.store.get_current_block_height()
    }

    /// Return the height for PoX v1 -> v2 auto unlocks
    ///   from the burn state db
    pub fn get_v1_unlock_height(&self) -> u32 {
        self.burn_state_db.get_v1_unlock_height()
    }

    /// Get the last-known burnchain block height.
    /// Note that this is _not_ the burnchain height in which this block was mined!
    /// This is the burnchain block height of its parent.
    pub fn get_current_burnchain_block_height(&mut self) -> u32 {
        let cur_stacks_height = self.store.get_current_block_height();
        let last_mined_bhh = if cur_stacks_height == 0 {
            return self.burn_state_db.get_burn_start_height();
        } else {
            self.get_index_block_header_hash(
                cur_stacks_height
                    .checked_sub(1)
                    .expect("BUG: cannot eval burn-block-height in boot code"),
            )
        };

        self.get_burnchain_block_height(&last_mined_bhh)
            .expect(&format!(
                "Block header hash '{}' must return for provided stacks block height {}",
                &last_mined_bhh, cur_stacks_height
            ))
    }

    pub fn get_block_header_hash(&mut self, block_height: u32) -> BlockHeaderHash {
        let id_bhh = self.get_index_block_header_hash(block_height);
        self.headers_db
            .get_stacks_block_header_hash_for_block(&id_bhh)
            .expect("Failed to get block data.")
    }

    pub fn get_block_time(&mut self, block_height: u32) -> u64 {
        let id_bhh = self.get_index_block_header_hash(block_height);
        self.headers_db
            .get_burn_block_time_for_block(&id_bhh)
            .expect("Failed to get block data.")
    }

    pub fn get_burnchain_block_header_hash(&mut self, block_height: u32) -> BurnchainHeaderHash {
        let id_bhh = self.get_index_block_header_hash(block_height);
        self.headers_db
            .get_burn_header_hash_for_block(&id_bhh)
            .expect("Failed to get block data.")
    }

    /// Fetch the burnchain block header hash for a given burnchain height.
    /// Because the burnchain can fork, we need to resolve the burnchain hash from the
    /// currently-evaluated Stacks chain tip as follows:
    ///
    /// 1. Get the current Stacks tip height (which is in the process of being evaluated)
    /// 2. Get the parent block's StacksBlockId, which is SHA512-256(consensus_hash, block_hash).
    ///    This is the highest Stacks block in this fork whose consensus hash is known.
    /// 3. Resolve the parent StacksBlockId to its consensus hash
    /// 4. Resolve the consensus hash to the associated SortitionId
    /// 5. Resolve the SortitionID at `burnchain_block_height` from the SortitionID obtained in
    ///    (4).
    ///
    /// This way, the `BurnchainHeaderHash` returned is guaranteed to be on the burnchain fork
    /// that holds the currently-evaluated Stacks fork (even if it's not the canonical burnchain
    /// fork).
    pub fn get_burnchain_block_header_hash_for_burnchain_height(
        &mut self,
        burnchain_block_height: u32,
    ) -> Option<BurnchainHeaderHash> {
        let current_stacks_height = self.get_current_block_height();

        if current_stacks_height < 1 {
            // we are in the Stacks genesis block
            return None;
        }

        // this is the StacksBlockId of the last block evaluated in this fork
        let parent_id_bhh = self.get_index_block_header_hash(current_stacks_height - 1);

        // infallible, since we always store the consensus hash with the StacksBlockId in the
        // headers DB
        let consensus_hash = self.headers_db.get_consensus_hash_for_block(&parent_id_bhh)
            .expect(&format!("FATAL: no consensus hash found for StacksBlockId {}", &parent_id_bhh));

        // infallible, since every sortition has a consensus hash
        let sortition_id = self.burn_state_db.get_sortition_id_from_consensus_hash(&consensus_hash)
            .expect(&format!("FATAL: no SortitionID found for consensus hash {}", &consensus_hash));

        self.burn_state_db
            .get_burn_header_hash(burnchain_block_height, &sortition_id)
    }

    pub fn get_burnchain_block_height(&mut self, id_bhh: &StacksBlockId) -> Option<u32> {
        self.headers_db.get_burn_block_height_for_block(id_bhh)
    }

    pub fn get_block_vrf_seed(&mut self, block_height: u32) -> VRFSeed {
        let id_bhh = self.get_index_block_header_hash(block_height);
        self.headers_db
            .get_vrf_seed_for_block(&id_bhh)
            .expect("Failed to get block data.")
    }

    pub fn get_miner_address(&mut self, block_height: u32) -> StandardPrincipalData {
        let id_bhh = self.get_index_block_header_hash(block_height);
        self.headers_db
            .get_miner_address(&id_bhh)
            .expect("Failed to get block data.")
            .into()
    }

    pub fn get_stx_btc_ops_processed(&mut self) -> u64 {
        self.get("vm_pox::stx_btc_ops::processed_blocks")
            .unwrap_or(0)
    }

    pub fn set_stx_btc_ops_processed(&mut self, processed: u64) {
        self.put("vm_pox::stx_btc_ops::processed_blocks", &processed);
    }
}

// poison-microblock

impl<'a> ClarityDatabase<'a> {
    pub fn make_microblock_pubkey_height_key(pubkey_hash: &Hash160) -> String {
        format!("microblock-pubkey-hash::{}", pubkey_hash)
    }

    pub fn make_microblock_poison_key(height: u32) -> String {
        format!("microblock-poison::{}", height)
    }

    pub fn insert_microblock_pubkey_hash_height(
        &mut self,
        pubkey_hash: &Hash160,
        height: u32,
    ) -> Result<()> {
        let key = ClarityDatabase::make_microblock_pubkey_height_key(pubkey_hash);
        let value = format!("{}", &height);
        self.put(&key, &value);
        Ok(())
    }

    pub fn get_cc_special_cases_handler(&self) -> Option<SpecialCaseHandler> {
        self.store.get_cc_special_cases_handler()
    }

    pub fn insert_microblock_poison(
        &mut self,
        height: u32,
        reporter: &StandardPrincipalData,
        seq: u16,
    ) -> Result<()> {
        let key = ClarityDatabase::make_microblock_poison_key(height);
        let value = Value::Tuple(
            TupleData::from_data(vec![
                (
                    ClarityName::try_from("reporter").expect("BUG: valid string representation"),
                    Value::Principal(PrincipalData::Standard(reporter.clone())),
                ),
                (
                    ClarityName::try_from("sequence").expect("BUG: valid string representation"),
                    Value::UInt(seq as u128),
                ),
            ])
            .expect("BUG: valid tuple representation"),
        );
        let mut value_bytes = vec![];
        value
            .serialize_write(&mut value_bytes)
            .expect("BUG: valid tuple representation did not serialize");

        let value_str = to_hex(&value_bytes);
        self.put(&key, &value_str);
        Ok(())
    }

    pub fn get_microblock_pubkey_hash_height(&mut self, pubkey_hash: &Hash160) -> Option<u32> {
        let key = ClarityDatabase::make_microblock_pubkey_height_key(pubkey_hash);
        self.get(&key).map(|height_str: String| {
            height_str
                .parse::<u32>()
                .expect("BUG: inserted non-u32 as height of microblock pubkey hash")
        })
    }

    /// Returns (who-reported-the-poison-microblock, sequence-of-microblock-fork)
    pub fn get_microblock_poison_report(
        &mut self,
        height: u32,
    ) -> Option<(StandardPrincipalData, u16)> {
        let key = ClarityDatabase::make_microblock_poison_key(height);
        self.get(&key).map(|reporter_hex_str: String| {
            let reporter_value = Value::try_deserialize_hex_untyped(&reporter_hex_str)
                .expect("BUG: failed to decode serialized poison-microblock reporter");
            let tuple_data = reporter_value.expect_tuple();
            let reporter_value = tuple_data
                .get("reporter")
                .expect("BUG: poison-microblock report has no 'reporter'")
                .to_owned();
            let seq_value = tuple_data
                .get("sequence")
                .expect("BUG: poison-microblock report has no 'sequence'")
                .to_owned();

            let reporter_principal = reporter_value.expect_principal();
            let seq_u128 = seq_value.expect_u128();

            let seq: u16 = seq_u128.try_into().expect("BUG: seq exceeds u16 max");
            if let PrincipalData::Standard(principal_data) = reporter_principal {
                (principal_data, seq)
            } else {
                panic!("BUG: poison-microblock report principal is not a standard principal");
            }
        })
    }
}

// this is used so that things like load_map, load_var, load_nft, etc.
//   will throw NoSuchFoo errors instead of NoSuchContract errors.
fn map_no_contract_as_none<T>(res: Result<Option<T>>) -> Result<Option<T>> {
    res.or_else(|e| match e {
        Error::Unchecked(CheckErrors::NoSuchContract(_)) => Ok(None),
        x => Err(x),
    })
}

// Variable Functions...
impl<'a> ClarityDatabase<'a> {
    pub fn create_variable(
        &mut self,
        contract_identifier: &QualifiedContractIdentifier,
        variable_name: &str,
        value_type: TypeSignature,
    ) -> DataVariableMetadata {
        let variable_data = DataVariableMetadata { value_type };
        let key = ClarityDatabase::make_metadata_key(StoreType::VariableMeta, variable_name);

        self.insert_metadata(contract_identifier, &key, &variable_data);
        variable_data
    }

    pub fn load_variable(
        &mut self,
        contract_identifier: &QualifiedContractIdentifier,
        variable_name: &str,
    ) -> Result<DataVariableMetadata> {
        let key = ClarityDatabase::make_metadata_key(StoreType::VariableMeta, variable_name);

        map_no_contract_as_none(self.fetch_metadata(contract_identifier, &key))?
            .ok_or(CheckErrors::NoSuchDataVariable(variable_name.to_string()).into())
    }

    #[cfg(any(test, feature = "testing"))]
    pub fn set_variable_unknown_descriptor(
        &mut self,
        contract_identifier: &QualifiedContractIdentifier,
        variable_name: &str,
        value: Value,
    ) -> Result<Value> {
        let descriptor = self.load_variable(contract_identifier, variable_name)?;
        self.set_variable(contract_identifier, variable_name, value, &descriptor)
            .map(|data| data.value)
    }

    pub fn set_variable(
        &mut self,
        contract_identifier: &QualifiedContractIdentifier,
        variable_name: &str,
        value: Value,
        variable_descriptor: &DataVariableMetadata,
    ) -> Result<ValueResult> {
        if !variable_descriptor.value_type.admits(&value) {
            return Err(
                CheckErrors::TypeValueError(variable_descriptor.value_type.clone(), value).into(),
            );
        }

        let key = ClarityDatabase::make_key_for_trip(
            contract_identifier,
            StoreType::Variable,
            variable_name,
        );

        let size = self.put_with_size(&key, &value);

        Ok(ValueResult {
            value: Value::Bool(true),
            serialized_byte_len: size,
        })
    }

    pub fn lookup_variable_unknown_descriptor(
        &mut self,
        contract_identifier: &QualifiedContractIdentifier,
        variable_name: &str,
    ) -> Result<Value> {
        let descriptor = self.load_variable(contract_identifier, variable_name)?;
        self.lookup_variable(contract_identifier, variable_name, &descriptor)
    }

    pub fn lookup_variable(
        &mut self,
        contract_identifier: &QualifiedContractIdentifier,
        variable_name: &str,
        variable_descriptor: &DataVariableMetadata,
    ) -> Result<Value> {
        let key = ClarityDatabase::make_key_for_trip(
            contract_identifier,
            StoreType::Variable,
            variable_name,
        );

        let result = self.get_value(&key, &variable_descriptor.value_type);

        match result {
            None => Ok(Value::none()),
            Some(data) => Ok(data.value),
        }
    }

    /// Same as lookup_variable, but returns the byte-size of the looked up
    ///  Clarity value as well as the value.
    pub fn lookup_variable_with_size(
        &mut self,
        contract_identifier: &QualifiedContractIdentifier,
        variable_name: &str,
        variable_descriptor: &DataVariableMetadata,
    ) -> Result<ValueResult> {
        let key = ClarityDatabase::make_key_for_trip(
            contract_identifier,
            StoreType::Variable,
            variable_name,
        );

        let result = self.get_value(&key, &variable_descriptor.value_type);

        match result {
            None => Ok(ValueResult {
                value: Value::none(),
                serialized_byte_len: *NONE_SERIALIZATION_LEN,
            }),
            Some(data) => Ok(data),
        }
    }
}

// Data Map Functions
impl<'a> ClarityDatabase<'a> {
    pub fn create_map(
        &mut self,
        contract_identifier: &QualifiedContractIdentifier,
        map_name: &str,
        key_type: TypeSignature,
        value_type: TypeSignature,
    ) -> DataMapMetadata {
        let data = DataMapMetadata {
            key_type,
            value_type,
        };

        let key = ClarityDatabase::make_metadata_key(StoreType::DataMapMeta, map_name);
        self.insert_metadata(contract_identifier, &key, &data);

        data
    }

    pub fn load_map(
        &mut self,
        contract_identifier: &QualifiedContractIdentifier,
        map_name: &str,
    ) -> Result<DataMapMetadata> {
        let key = ClarityDatabase::make_metadata_key(StoreType::DataMapMeta, map_name);

        map_no_contract_as_none(self.fetch_metadata(contract_identifier, &key))?
            .ok_or(CheckErrors::NoSuchMap(map_name.to_string()).into())
    }

    pub fn make_key_for_data_map_entry(
        contract_identifier: &QualifiedContractIdentifier,
        map_name: &str,
        key_value: &Value,
    ) -> String {
        ClarityDatabase::make_key_for_data_map_entry_serialized(
            contract_identifier,
            map_name,
            &key_value.serialize(),
        )
    }

    fn make_key_for_data_map_entry_serialized(
        contract_identifier: &QualifiedContractIdentifier,
        map_name: &str,
        key_value_serialized: &str,
    ) -> String {
        ClarityDatabase::make_key_for_quad(
            contract_identifier,
            StoreType::DataMap,
            map_name,
            key_value_serialized,
        )
    }

    pub fn fetch_entry_unknown_descriptor(
        &mut self,
        contract_identifier: &QualifiedContractIdentifier,
        map_name: &str,
        key_value: &Value,
    ) -> Result<Value> {
        let descriptor = self.load_map(contract_identifier, map_name)?;
        self.fetch_entry(contract_identifier, map_name, key_value, &descriptor)
    }

    pub fn fetch_entry(
        &mut self,
        contract_identifier: &QualifiedContractIdentifier,
        map_name: &str,
        key_value: &Value,
        map_descriptor: &DataMapMetadata,
    ) -> Result<Value> {
        if !map_descriptor.key_type.admits(key_value) {
            return Err(CheckErrors::TypeValueError(
                map_descriptor.key_type.clone(),
                (*key_value).clone(),
            )
            .into());
        }

        let key =
            ClarityDatabase::make_key_for_data_map_entry(contract_identifier, map_name, key_value);

        let stored_type = TypeSignature::new_option(map_descriptor.value_type.clone())?;
        let result = self.get_value(&key, &stored_type);

        match result {
            None => Ok(Value::none()),
            Some(data) => Ok(data.value),
        }
    }

    pub fn fetch_entry_with_size(
        &mut self,
        contract_identifier: &QualifiedContractIdentifier,
        map_name: &str,
        key_value: &Value,
        map_descriptor: &DataMapMetadata,
    ) -> Result<ValueResult> {
        if !map_descriptor.key_type.admits(key_value) {
            return Err(CheckErrors::TypeValueError(
                map_descriptor.key_type.clone(),
                (*key_value).clone(),
            )
            .into());
        }

        let key_serialized = key_value.serialize();
        let key = ClarityDatabase::make_key_for_data_map_entry_serialized(
            contract_identifier,
            map_name,
            &key_serialized,
        );

        let stored_type = TypeSignature::new_option(map_descriptor.value_type.clone())?;
        let result = self.get_value(&key, &stored_type);

        match result {
            None => Ok(ValueResult {
                value: Value::none(),
                serialized_byte_len: byte_len_of_serialization(&key_serialized),
            }),
            Some(ValueResult {
                value,
                serialized_byte_len,
            }) => Ok(ValueResult {
                value,
                serialized_byte_len: serialized_byte_len
                    .checked_add(byte_len_of_serialization(&key_serialized))
                    .expect("Overflowed Clarity key/value size"),
            }),
        }
    }

    pub fn set_entry(
        &mut self,
        contract_identifier: &QualifiedContractIdentifier,
        map_name: &str,
        key: Value,
        value: Value,
        map_descriptor: &DataMapMetadata,
    ) -> Result<ValueResult> {
        self.inner_set_entry(
            contract_identifier,
            map_name,
            key,
            value,
            false,
            map_descriptor,
        )
    }

    pub fn set_entry_unknown_descriptor(
        &mut self,
        contract_identifier: &QualifiedContractIdentifier,
        map_name: &str,
        key: Value,
        value: Value,
    ) -> Result<Value> {
        let descriptor = self.load_map(contract_identifier, map_name)?;
        self.set_entry(contract_identifier, map_name, key, value, &descriptor)
            .map(|data| data.value)
    }

    pub fn insert_entry_unknown_descriptor(
        &mut self,
        contract_identifier: &QualifiedContractIdentifier,
        map_name: &str,
        key: Value,
        value: Value,
    ) -> Result<Value> {
        let descriptor = self.load_map(contract_identifier, map_name)?;
        self.insert_entry(contract_identifier, map_name, key, value, &descriptor)
            .map(|data| data.value)
    }

    pub fn insert_entry(
        &mut self,
        contract_identifier: &QualifiedContractIdentifier,
        map_name: &str,
        key: Value,
        value: Value,
        map_descriptor: &DataMapMetadata,
    ) -> Result<ValueResult> {
        self.inner_set_entry(
            contract_identifier,
            map_name,
            key,
            value,
            true,
            map_descriptor,
        )
    }

    fn data_map_entry_exists(&mut self, key: &str, expected_value: &TypeSignature) -> Result<bool> {
        match self.get_value(key, expected_value) {
            None => Ok(false),
            Some(value) => Ok(value.value != Value::none()),
        }
    }

    fn inner_set_entry(
        &mut self,
        contract_identifier: &QualifiedContractIdentifier,
        map_name: &str,
        key_value: Value,
        value: Value,
        return_if_exists: bool,
        map_descriptor: &DataMapMetadata,
    ) -> Result<ValueResult> {
        if !map_descriptor.key_type.admits(&key_value) {
            return Err(
                CheckErrors::TypeValueError(map_descriptor.key_type.clone(), key_value).into(),
            );
        }
        if !map_descriptor.value_type.admits(&value) {
            return Err(
                CheckErrors::TypeValueError(map_descriptor.value_type.clone(), value).into(),
            );
        }

        let key_serialized = key_value.serialize();
        let key_serialized_byte_len = byte_len_of_serialization(&key_serialized);
        let key = ClarityDatabase::make_key_for_quad(
            contract_identifier,
            StoreType::DataMap,
            map_name,
            &key_serialized,
        );
        let stored_type = TypeSignature::new_option(map_descriptor.value_type.clone())?;

        if return_if_exists && self.data_map_entry_exists(&key, &stored_type)? {
            return Ok(ValueResult {
                value: Value::Bool(false),
                serialized_byte_len: key_serialized_byte_len,
            });
        }

        let placed_value = Value::some(value)?;
        let placed_size = self.put_with_size(&key, &placed_value);

        Ok(ValueResult {
            value: Value::Bool(true),
            serialized_byte_len: key_serialized_byte_len
                .checked_add(placed_size)
                .expect("Overflowed Clarity key/value size"),
        })
    }

    pub fn delete_entry(
        &mut self,
        contract_identifier: &QualifiedContractIdentifier,
        map_name: &str,
        key_value: &Value,
        map_descriptor: &DataMapMetadata,
    ) -> Result<ValueResult> {
        if !map_descriptor.key_type.admits(key_value) {
            return Err(CheckErrors::TypeValueError(
                map_descriptor.key_type.clone(),
                (*key_value).clone(),
            )
            .into());
        }

        let key_serialized = key_value.serialize();
        let key_serialized_byte_len = byte_len_of_serialization(&key_serialized);
        let key = ClarityDatabase::make_key_for_quad(
            contract_identifier,
            StoreType::DataMap,
            map_name,
            &key_serialized,
        );
        let stored_type = TypeSignature::new_option(map_descriptor.value_type.clone())?;
        if !self.data_map_entry_exists(&key, &stored_type)? {
            return Ok(ValueResult {
                value: Value::Bool(false),
                serialized_byte_len: key_serialized_byte_len,
            });
        }

        self.put(&key, &(Value::none()));

        Ok(ValueResult {
            value: Value::Bool(true),
            serialized_byte_len: key_serialized_byte_len
                .checked_add(*NONE_SERIALIZATION_LEN)
                .expect("Overflowed Clarity key/value size"),
        })
    }
}

// Asset Functions

impl<'a> ClarityDatabase<'a> {
    pub fn create_fungible_token(
        &mut self,
        contract_identifier: &QualifiedContractIdentifier,
        token_name: &str,
        total_supply: &Option<u128>,
    ) -> FungibleTokenMetadata {
        let data = FungibleTokenMetadata {
            total_supply: total_supply.clone(),
        };

        let key = ClarityDatabase::make_metadata_key(StoreType::FungibleTokenMeta, token_name);
        self.insert_metadata(contract_identifier, &key, &data);

        // total supply _is_ included in the consensus hash
        let supply_key = ClarityDatabase::make_key_for_trip(
            contract_identifier,
            StoreType::CirculatingSupply,
            token_name,
        );
        self.put(&supply_key, &(0 as u128));

        data
    }

    pub fn load_ft(
        &mut self,
        contract_identifier: &QualifiedContractIdentifier,
        token_name: &str,
    ) -> Result<FungibleTokenMetadata> {
        let key = ClarityDatabase::make_metadata_key(StoreType::FungibleTokenMeta, token_name);

        map_no_contract_as_none(self.fetch_metadata(contract_identifier, &key))?
            .ok_or(CheckErrors::NoSuchFT(token_name.to_string()).into())
    }

    pub fn create_non_fungible_token(
        &mut self,
        contract_identifier: &QualifiedContractIdentifier,
        token_name: &str,
        key_type: &TypeSignature,
    ) -> NonFungibleTokenMetadata {
        let data = NonFungibleTokenMetadata {
            key_type: key_type.clone(),
        };
        let key = ClarityDatabase::make_metadata_key(StoreType::NonFungibleTokenMeta, token_name);
        self.insert_metadata(contract_identifier, &key, &data);

        data
    }

    fn load_nft(
        &mut self,
        contract_identifier: &QualifiedContractIdentifier,
        token_name: &str,
    ) -> Result<NonFungibleTokenMetadata> {
        let key = ClarityDatabase::make_metadata_key(StoreType::NonFungibleTokenMeta, token_name);

        map_no_contract_as_none(self.fetch_metadata(contract_identifier, &key))?
            .ok_or(CheckErrors::NoSuchNFT(token_name.to_string()).into())
    }

    pub fn checked_increase_token_supply(
        &mut self,
        contract_identifier: &QualifiedContractIdentifier,
        token_name: &str,
        amount: u128,
        descriptor: &FungibleTokenMetadata,
    ) -> Result<()> {
        let key = ClarityDatabase::make_key_for_trip(
            contract_identifier,
            StoreType::CirculatingSupply,
            token_name,
        );
        let current_supply: u128 = self
            .get(&key)
            .expect("ERROR: Clarity VM failed to track token supply.");

        let new_supply = current_supply
            .checked_add(amount)
            .ok_or(RuntimeErrorType::ArithmeticOverflow)?;

        if let Some(total_supply) = descriptor.total_supply {
            if new_supply > total_supply {
                return Err(RuntimeErrorType::SupplyOverflow(new_supply, total_supply).into());
            }
        }

        self.put(&key, &new_supply);
        Ok(())
    }

    pub fn checked_decrease_token_supply(
        &mut self,
        contract_identifier: &QualifiedContractIdentifier,
        token_name: &str,
        amount: u128,
    ) -> Result<()> {
        let key = ClarityDatabase::make_key_for_trip(
            contract_identifier,
            StoreType::CirculatingSupply,
            token_name,
        );
        let current_supply: u128 = self
            .get(&key)
            .expect("ERROR: Clarity VM failed to track token supply.");

        if amount > current_supply {
            return Err(RuntimeErrorType::SupplyUnderflow(current_supply, amount).into());
        }

        let new_supply = current_supply - amount;

        self.put(&key, &new_supply);
        Ok(())
    }

    pub fn get_ft_balance(
        &mut self,
        contract_identifier: &QualifiedContractIdentifier,
        token_name: &str,
        principal: &PrincipalData,
        descriptor: Option<&FungibleTokenMetadata>,
    ) -> Result<u128> {
        if descriptor.is_none() {
            self.load_ft(contract_identifier, token_name)?;
        }

        let key = ClarityDatabase::make_key_for_quad(
            contract_identifier,
            StoreType::FungibleToken,
            token_name,
            &principal.serialize(),
        );

        let result = self.get(&key);
        match result {
            None => Ok(0),
            Some(balance) => Ok(balance),
        }
    }

    pub fn set_ft_balance(
        &mut self,
        contract_identifier: &QualifiedContractIdentifier,
        token_name: &str,
        principal: &PrincipalData,
        balance: u128,
    ) -> Result<()> {
        let key = ClarityDatabase::make_key_for_quad(
            contract_identifier,
            StoreType::FungibleToken,
            token_name,
            &principal.serialize(),
        );
        self.put(&key, &balance);

        Ok(())
    }

    pub fn get_ft_supply(
        &mut self,
        contract_identifier: &QualifiedContractIdentifier,
        token_name: &str,
    ) -> Result<u128> {
        let key = ClarityDatabase::make_key_for_trip(
            contract_identifier,
            StoreType::CirculatingSupply,
            token_name,
        );
        let supply = self
            .get(&key)
            .expect("ERROR: Clarity VM failed to track token supply.");
        Ok(supply)
    }

    pub fn get_nft_owner(
        &mut self,
        contract_identifier: &QualifiedContractIdentifier,
        asset_name: &str,
        asset: &Value,
        key_type: &TypeSignature,
    ) -> Result<PrincipalData> {
        if !key_type.admits(asset) {
            return Err(CheckErrors::TypeValueError(key_type.clone(), (*asset).clone()).into());
        }

        let key = ClarityDatabase::make_key_for_quad(
            contract_identifier,
            StoreType::NonFungibleToken,
            asset_name,
            &asset.serialize(),
        );

        let value: Option<Value> = self.get(&key);
        let owner = match value {
            Some(owner) => owner.expect_optional(),
            None => return Err(RuntimeErrorType::NoSuchToken.into()),
        };

        let principal = match owner {
            Some(value) => value.expect_principal(),
            None => return Err(RuntimeErrorType::NoSuchToken.into()),
        };

        Ok(principal)
    }

    pub fn get_nft_key_type(
        &mut self,
        contract_identifier: &QualifiedContractIdentifier,
        asset_name: &str,
    ) -> Result<TypeSignature> {
        let descriptor = self.load_nft(contract_identifier, asset_name)?;
        Ok(descriptor.key_type)
    }

    pub fn set_nft_owner(
        &mut self,
        contract_identifier: &QualifiedContractIdentifier,
        asset_name: &str,
        asset: &Value,
        principal: &PrincipalData,
        key_type: &TypeSignature,
    ) -> Result<()> {
        if !key_type.admits(asset) {
            return Err(CheckErrors::TypeValueError(key_type.clone(), (*asset).clone()).into());
        }

        let key = ClarityDatabase::make_key_for_quad(
            contract_identifier,
            StoreType::NonFungibleToken,
            asset_name,
            &asset.serialize(),
        );

        let value = Value::some(Value::Principal(principal.clone()))?;
        self.put(&key, &value);

        Ok(())
    }

    pub fn burn_nft(
        &mut self,
        contract_identifier: &QualifiedContractIdentifier,
        asset_name: &str,
        asset: &Value,
        key_type: &TypeSignature,
    ) -> Result<()> {
        if !key_type.admits(asset) {
            return Err(CheckErrors::TypeValueError(key_type.clone(), (*asset).clone()).into());
        }

        let key = ClarityDatabase::make_key_for_quad(
            contract_identifier,
            StoreType::NonFungibleToken,
            asset_name,
            &asset.serialize(),
        );

        self.put(&key, &(Value::none()));
        Ok(())
    }
}

// load/store STX token state and account nonces
impl<'a> ClarityDatabase<'a> {
    fn make_key_for_account(principal: &PrincipalData, data: StoreType) -> String {
        format!("vm-account::{}::{}", principal, data as u8)
    }

    pub fn make_key_for_account_balance(principal: &PrincipalData) -> String {
        ClarityDatabase::make_key_for_account(principal, StoreType::STXBalance)
    }

    pub fn make_key_for_account_nonce(principal: &PrincipalData) -> String {
        ClarityDatabase::make_key_for_account(principal, StoreType::Nonce)
    }

    pub fn make_key_for_account_stx_locked(principal: &PrincipalData) -> String {
        ClarityDatabase::make_key_for_account(principal, StoreType::PoxSTXLockup)
    }

    pub fn make_key_for_account_unlock_height(principal: &PrincipalData) -> String {
        ClarityDatabase::make_key_for_account(principal, StoreType::PoxUnlockHeight)
    }

    pub fn get_stx_balance_snapshot<'conn>(
        &'conn mut self,
        principal: &PrincipalData,
    ) -> STXBalanceSnapshot<'a, 'conn> {
        let stx_balance = self.get_account_stx_balance(principal);
        let cur_burn_height = self.get_current_burnchain_block_height() as u64;

        test_debug!("Balance of {} (raw={},locked={},unlock-height={},current-height={}) is {} (has_unlockable_tokens_at_burn_block={})",
            principal,
            stx_balance.amount_unlocked(),
            stx_balance.amount_locked(),
            stx_balance.unlock_height(),
            cur_burn_height,
            stx_balance.get_available_balance_at_burn_block(cur_burn_height, self.get_v1_unlock_height()),
            stx_balance.has_unlockable_tokens_at_burn_block(cur_burn_height, self.get_v1_unlock_height()));

        STXBalanceSnapshot::new(principal, stx_balance, cur_burn_height, self)
    }

    pub fn get_stx_balance_snapshot_genesis<'conn>(
        &'conn mut self,
        principal: &PrincipalData,
    ) -> STXBalanceSnapshot<'a, 'conn> {
        let stx_balance = self.get_account_stx_balance(principal);
        let cur_burn_height = 0;

        test_debug!("Balance of {} (raw={},locked={},unlock-height={},current-height={}) is {} (has_unlockable_tokens_at_burn_block={})",
            principal,
            stx_balance.amount_unlocked(),
            stx_balance.amount_locked(),
            stx_balance.unlock_height(),
            cur_burn_height,
            stx_balance.get_available_balance_at_burn_block(cur_burn_height, self.get_v1_unlock_height()),
            stx_balance.has_unlockable_tokens_at_burn_block(cur_burn_height, self.get_v1_unlock_height()));

        STXBalanceSnapshot::new(principal, stx_balance, cur_burn_height, self)
    }

    pub fn get_account_stx_balance(&mut self, principal: &PrincipalData) -> STXBalance {
        let key = ClarityDatabase::make_key_for_account_balance(principal);
        debug!("Fetching account balance"; "principal" => %principal.to_string());
        let result = self.get(&key);
        match result {
            None => STXBalance::zero(),
            Some(balance) => balance,
        }
    }

    pub fn get_account_nonce(&mut self, principal: &PrincipalData) -> u64 {
        let key = ClarityDatabase::make_key_for_account_nonce(principal);
        let result = self.get(&key);
        match result {
            None => 0,
            Some(nonce) => nonce,
        }
    }

    pub fn set_account_nonce(&mut self, principal: &PrincipalData, nonce: u64) {
        let key = ClarityDatabase::make_key_for_account_nonce(principal);
        self.put(&key, &nonce);
    }
}

// access burnchain state
impl<'a> ClarityDatabase<'a> {
    pub fn get_burn_block_height(&self, sortition_id: &SortitionId) -> Option<u32> {
        self.burn_state_db.get_burn_block_height(sortition_id)
    }

    pub fn get_burn_header_hash(
        &self,
        height: u32,
        sortition_id: &SortitionId,
    ) -> Option<BurnchainHeaderHash> {
        self.burn_state_db
            .get_burn_header_hash(height, sortition_id)
    }

    /// This function obtains the stacks epoch version, which is based on the burn block height.
    /// Valid epochs include stacks 1.0, 2.0, 2.05, and so on.
    pub fn get_stacks_epoch(&self, height: u32) -> Option<StacksEpoch> {
        self.burn_state_db.get_stacks_epoch(height)
    }
}
