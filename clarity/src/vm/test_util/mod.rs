// Copyright (C) 2026 Stacks Open Internet Foundation
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
use clarity_types::ClarityName;
#[cfg(any(test, feature = "testing"))]
use clarity_types::types::QualifiedContractIdentifier;
#[cfg(any(test, feature = "testing"))]
use rusqlite::Connection;
use stacks_common::consts::{
    BITCOIN_REGTEST_FIRST_BLOCK_HASH, BITCOIN_REGTEST_FIRST_BLOCK_HEIGHT,
    BITCOIN_REGTEST_FIRST_BLOCK_TIMESTAMP, FIRST_BURNCHAIN_CONSENSUS_HASH, FIRST_STACKS_BLOCK_HASH,
    PEER_VERSION_EPOCH_2_0,
};
use stacks_common::types::StacksEpochId;
#[cfg(any(test, feature = "testing"))]
use stacks_common::types::chainstate::TrieHash;
use stacks_common::types::chainstate::{
    BlockHeaderHash, BurnchainHeaderHash, ConsensusHash, PoxId, SortitionId, StacksAddress,
    StacksBlockId, VRFSeed,
};
use stacks_common::util::hash::Sha512Trunc256Sum;

use crate::vm::costs::ExecutionCost;
use crate::vm::database::{BurnStateDB, HeadersDB};
#[cfg(any(test, feature = "testing"))]
use crate::vm::database::{
    ClarityBackingStore, ClarityDatabase, MemoryBackingStore, NULL_BURN_STATE_DB, NULL_HEADER_DB,
};
#[cfg(any(test, feature = "testing"))]
use crate::vm::errors::{RuntimeError, VmExecutionError};
use crate::vm::representations::SymbolicExpression;
use crate::vm::types::{TupleData, Value};
use crate::vm::{StacksEpoch, execute as vm_execute, execute_on_network as vm_execute_on_network};

pub struct UnitTestBurnStateDB {
    pub epoch_id: StacksEpochId,
}
pub struct UnitTestHeaderDB {}

pub const TEST_HEADER_DB: UnitTestHeaderDB = UnitTestHeaderDB {};
pub const TEST_BURN_STATE_DB: UnitTestBurnStateDB = UnitTestBurnStateDB {
    epoch_id: StacksEpochId::Epoch20,
};
pub const TEST_BURN_STATE_DB_205: UnitTestBurnStateDB = UnitTestBurnStateDB {
    epoch_id: StacksEpochId::Epoch2_05,
};
pub const TEST_BURN_STATE_DB_21: UnitTestBurnStateDB = UnitTestBurnStateDB {
    epoch_id: StacksEpochId::Epoch21,
};

pub fn generate_test_burn_state_db(epoch_id: StacksEpochId) -> UnitTestBurnStateDB {
    if matches!(epoch_id, StacksEpochId::Epoch10) {
        panic!("Epoch 1.0 not testable");
    }
    UnitTestBurnStateDB { epoch_id }
}

pub fn execute(s: &str) -> Value {
    vm_execute(s).unwrap().unwrap()
}

pub fn execute_on_network(s: &str, use_mainnet: bool) -> Value {
    vm_execute_on_network(s, use_mainnet).unwrap().unwrap()
}

pub fn symbols_from_values(vec: Vec<Value>) -> Vec<SymbolicExpression> {
    vec.into_iter()
        .map(SymbolicExpression::atom_value)
        .collect()
}

pub fn is_committed(v: &Value) -> bool {
    eprintln!("is_committed?: {v}");

    match v {
        Value::Response(data) => data.committed,
        _ => false,
    }
}

pub fn is_err_code(v: &Value, e: u128) -> bool {
    eprintln!("is_err_code?: {v}");
    match v {
        Value::Response(data) => !data.committed && *data.data == Value::UInt(e),
        _ => false,
    }
}

pub fn is_err_code_i128(v: &Value, e: i128) -> bool {
    eprintln!("is_err_code?: {v}");
    match v {
        Value::Response(data) => !data.committed && *data.data == Value::Int(e),
        _ => false,
    }
}

fn height_to_hashed_bytes(height: u32) -> [u8; 32] {
    let input_bytes = height.to_be_bytes();
    let hash = Sha512Trunc256Sum::from_data(&input_bytes);
    hash.into_bytes()
}

fn bhh_from_height(height: u32) -> BurnchainHeaderHash {
    let mut bytes = height_to_hashed_bytes(height);
    bytes[31] = 2;
    BurnchainHeaderHash::from_bytes(&bytes[0..32]).unwrap()
}

fn consensus_hash_from_height(height: u32) -> ConsensusHash {
    let mut bytes = height_to_hashed_bytes(height);
    bytes[19] = 3;
    ConsensusHash::from_bytes(&bytes[0..20]).unwrap()
}

impl HeadersDB for UnitTestHeaderDB {
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
    fn get_vrf_seed_for_block(
        &self,
        _bhh: &StacksBlockId,
        _epoch: &StacksEpochId,
    ) -> Option<VRFSeed> {
        None
    }
    fn get_stacks_block_header_hash_for_block(
        &self,
        id_bhh: &StacksBlockId,
        _epoch: &StacksEpochId,
    ) -> Option<BlockHeaderHash> {
        if *id_bhh == StacksBlockId::new(&FIRST_BURNCHAIN_CONSENSUS_HASH, &FIRST_STACKS_BLOCK_HASH)
        {
            Some(FIRST_STACKS_BLOCK_HASH)
        } else {
            None
        }
    }
    fn get_burn_block_time_for_block(
        &self,
        id_bhh: &StacksBlockId,
        _epoch: Option<&StacksEpochId>,
    ) -> Option<u64> {
        if *id_bhh == StacksBlockId::new(&FIRST_BURNCHAIN_CONSENSUS_HASH, &FIRST_STACKS_BLOCK_HASH)
        {
            Some(BITCOIN_REGTEST_FIRST_BLOCK_TIMESTAMP as u64)
        } else {
            // for non-genesis blocks, just pick a u64 value that will increment in most
            // unit tests as blocks are built (most unit tests construct blocks using
            // incrementing high order bytes)
            Some(1 + 10 * (id_bhh.as_bytes()[0] as u64))
        }
    }
    fn get_stacks_block_time_for_block(&self, id_bhh: &StacksBlockId) -> Option<u64> {
        Some(1713799973 + 10 * (id_bhh.as_bytes()[0] as u64))
    }
    fn get_burn_block_height_for_block(&self, id_bhh: &StacksBlockId) -> Option<u32> {
        if *id_bhh == StacksBlockId::new(&FIRST_BURNCHAIN_CONSENSUS_HASH, &FIRST_STACKS_BLOCK_HASH)
        {
            Some(BITCOIN_REGTEST_FIRST_BLOCK_HEIGHT as u32)
        } else {
            Some(1 + id_bhh.as_bytes()[0] as u32)
        }
    }
    fn get_miner_address(
        &self,
        _id_bhh: &StacksBlockId,
        _epoch: &StacksEpochId,
    ) -> Option<StacksAddress> {
        None
    }

    fn get_consensus_hash_for_block(
        &self,
        id_bhh: &StacksBlockId,
        _epoch: &StacksEpochId,
    ) -> Option<ConsensusHash> {
        if *id_bhh == StacksBlockId::new(&FIRST_BURNCHAIN_CONSENSUS_HASH, &FIRST_STACKS_BLOCK_HASH)
        {
            Some(FIRST_BURNCHAIN_CONSENSUS_HASH)
        } else {
            Some(consensus_hash_from_height(id_bhh.as_bytes()[0] as u32))
        }
    }

    fn get_burnchain_tokens_spent_for_block(
        &self,
        id_bhh: &StacksBlockId,
        _epoch: &StacksEpochId,
    ) -> Option<u128> {
        // if the block is defined at all, then return a constant
        self.get_burn_block_height_for_block(id_bhh).map(|_| 2000)
    }

    fn get_burnchain_tokens_spent_for_winning_block(
        &self,
        id_bhh: &StacksBlockId,
        _epoch: &StacksEpochId,
    ) -> Option<u128> {
        // if the block is defined at all, then return a constant
        self.get_burn_block_height_for_block(id_bhh).map(|_| 1000)
    }

    fn get_tokens_earned_for_block(
        &self,
        id_bhh: &StacksBlockId,
        _epoch: &StacksEpochId,
    ) -> Option<u128> {
        // if the block is defined at all, then return a constant
        self.get_burn_block_height_for_block(id_bhh).map(|_| 3000)
    }

    fn get_stacks_height_for_tenure_height(
        &self,
        _tip: &StacksBlockId,
        tenure_height: u32,
    ) -> Option<u32> {
        Some(tenure_height)
    }
}

impl BurnStateDB for UnitTestBurnStateDB {
    fn get_tip_burn_block_height(&self) -> Option<u32> {
        Some(1)
    }

    fn get_tip_sortition_id(&self) -> Option<SortitionId> {
        let bhh = BurnchainHeaderHash::from_hex(BITCOIN_REGTEST_FIRST_BLOCK_HASH).unwrap();
        Some(SortitionId::new(&bhh, &PoxId::stubbed()))
    }

    fn get_burn_block_height(&self, _sortition_id: &SortitionId) -> Option<u32> {
        Some(1)
    }

    fn get_burn_header_hash(
        &self,
        _height: u32,
        _sortition_id: &SortitionId,
    ) -> Option<BurnchainHeaderHash> {
        Some(BurnchainHeaderHash::from_hex(BITCOIN_REGTEST_FIRST_BLOCK_HASH).unwrap())
    }

    fn get_stacks_epoch(&self, _height: u32) -> Option<StacksEpoch> {
        Some(StacksEpoch {
            epoch_id: self.epoch_id,
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
        u32::MAX
    }

    fn get_v2_unlock_height(&self) -> u32 {
        u32::MAX
    }

    fn get_v3_unlock_height(&self) -> u32 {
        u32::MAX
    }

    fn get_pox_3_activation_height(&self) -> u32 {
        u32::MAX
    }

    fn get_pox_4_activation_height(&self) -> u32 {
        u32::MAX
    }

    fn get_pox_prepare_length(&self) -> u32 {
        1
    }

    fn get_pox_reward_cycle_length(&self) -> u32 {
        1
    }

    fn get_pox_rejection_fraction(&self) -> u64 {
        1
    }
    fn get_burn_start_height(&self) -> u32 {
        0
    }
    fn get_sortition_id_from_consensus_hash(
        &self,
        consensus_hash: &ConsensusHash,
    ) -> Option<SortitionId> {
        Some(SortitionId::new(
            &bhh_from_height(consensus_hash.as_bytes()[0] as u32),
            &PoxId::stubbed(),
        ))
    }
    fn get_pox_payout_addrs(
        &self,
        _height: u32,
        _sortition_id: &SortitionId,
    ) -> Option<(Vec<TupleData>, u128)> {
        Some((
            vec![
                TupleData::from_data(vec![
                    (
                        ClarityName::from_literal("version"),
                        Value::buff_from(vec![0u8]).unwrap(),
                    ),
                    (
                        ClarityName::from_literal("hashbytes"),
                        Value::buff_from(vec![0u8; 20]).unwrap(),
                    ),
                ])
                .unwrap(),
            ],
            123,
        ))
    }
}

/// Test-only [`ClarityBackingStore`] that wraps one [`MemoryBackingStore`]
/// per logical block and supports `set_block_hash` to switch between them.
///
/// Main purpose is to support unit-testing for [`ClarityDatabase`] and
/// allow tests exercise time-shifted reads without spinning up a real MARF.
///
/// # Notes
///
/// Each block is fully isolated: writes in one block are not visible in
/// another. This means:
/// - No begin/commit semantics at the store level.
/// - No trie inheritance: child blocks do NOT see the parent block's keys.
/// - Metadata is per-block (each inner store has its own SQLite side
///   store);
#[cfg(any(test, feature = "testing"))]
pub struct TestBackingStore {
    blocks: std::collections::HashMap<StacksBlockId, MemoryBackingStore>,
    current_block: StacksBlockId,
}

#[cfg(any(test, feature = "testing"))]
impl TestBackingStore {
    /// Create a store with a single active block identified by `genesis_block`.
    pub fn new(genesis_block: StacksBlockId) -> Self {
        let mut store = TestBackingStore {
            blocks: std::collections::HashMap::new(),
            current_block: genesis_block.clone(),
        };
        store.register_block(genesis_block);
        store
    }

    /// Register a new block that can be switched to via `set_block_hash`.
    pub fn register_block(&mut self, block: StacksBlockId) {
        self.blocks.entry(block).or_default();
    }

    pub fn as_clarity_db(&mut self) -> ClarityDatabase<'_> {
        ClarityDatabase::new(self, &NULL_HEADER_DB, &NULL_BURN_STATE_DB, None)
    }

    fn block_store(&mut self) -> &mut MemoryBackingStore {
        self.blocks
            .get_mut(&self.current_block)
            .expect("BUG: current_block not registered in the store!")
    }
}

#[cfg(any(test, feature = "testing"))]
impl ClarityBackingStore for TestBackingStore {
    fn set_block_hash(&mut self, bhh: StacksBlockId) -> Result<StacksBlockId, VmExecutionError> {
        if !self.blocks.contains_key(&bhh) {
            return Err(RuntimeError::UnknownBlockHeaderHash(BlockHeaderHash(bhh.0)).into());
        }
        let prior = self.current_block.clone();
        self.current_block = bhh;
        Ok(prior)
    }

    fn get_data(&mut self, key: &str) -> Result<Option<String>, VmExecutionError> {
        self.block_store().get_data(key)
    }

    fn get_data_from_path(&mut self, hash: &TrieHash) -> Result<Option<String>, VmExecutionError> {
        self.block_store().get_data_from_path(hash)
    }

    fn get_data_with_proof(
        &mut self,
        key: &str,
    ) -> Result<Option<(String, Vec<u8>)>, VmExecutionError> {
        self.block_store().get_data_with_proof(key)
    }

    fn get_data_with_proof_from_path(
        &mut self,
        hash: &TrieHash,
    ) -> Result<Option<(String, Vec<u8>)>, VmExecutionError> {
        self.block_store().get_data_with_proof_from_path(hash)
    }

    fn get_side_store(&mut self) -> &Connection {
        self.block_store().get_side_store()
    }

    fn get_block_at_height(&mut self, height: u32) -> Option<StacksBlockId> {
        self.block_store().get_block_at_height(height)
    }

    fn get_open_chain_tip(&mut self) -> StacksBlockId {
        self.current_block.clone()
    }

    fn get_open_chain_tip_height(&mut self) -> u32 {
        self.block_store().get_open_chain_tip_height()
    }

    fn get_current_block_height(&mut self) -> u32 {
        self.block_store().get_current_block_height()
    }

    fn put_all_data(&mut self, items: Vec<(String, String)>) -> Result<(), VmExecutionError> {
        self.block_store().put_all_data(items)
    }

    fn get_contract_hash(
        &mut self,
        contract: &QualifiedContractIdentifier,
    ) -> Result<(StacksBlockId, Sha512Trunc256Sum), VmExecutionError> {
        self.block_store().get_contract_hash(contract)
    }

    fn insert_metadata(
        &mut self,
        contract: &QualifiedContractIdentifier,
        key: &str,
        value: &str,
    ) -> Result<(), VmExecutionError> {
        self.block_store().insert_metadata(contract, key, value)
    }

    fn get_metadata(
        &mut self,
        contract: &QualifiedContractIdentifier,
        key: &str,
    ) -> Result<Option<String>, VmExecutionError> {
        self.block_store().get_metadata(contract, key)
    }

    fn get_metadata_manual(
        &mut self,
        at_height: u32,
        contract: &QualifiedContractIdentifier,
        key: &str,
    ) -> Result<Option<String>, VmExecutionError> {
        self.block_store()
            .get_metadata_manual(at_height, contract, key)
    }
}
