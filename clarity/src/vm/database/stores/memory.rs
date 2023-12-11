#![allow(unused_variables)]

use crate::vm::types::{QualifiedContractIdentifier, TypeSignature, TupleData, StandardPrincipalData, FunctionType, FunctionSignature, TraitIdentifier};

use super::super::v2::*;

#[derive(Debug, Clone, Copy)]
pub struct ClarityMemoryStore {}

impl ClarityMemoryStore {
    pub fn new() -> Self {
        Self {}
    }
}

impl ClarityDb for ClarityMemoryStore {
    fn set_block_hash(
        &mut self,
        bhh: stacks_common::types::chainstate::StacksBlockId,
        query_pending_data: bool,
    ) -> Result<stacks_common::types::chainstate::StacksBlockId> {
        todo!()
    }

    fn put(
        &mut self, 
        key: &str, 
        value: &impl crate::vm::database::ClaritySerializable
    ) -> Result<()> 
    where 
        Self: Sized {
        todo!()
    }

    fn put_with_size(
        &mut self, 
        key: &str, 
        value: &impl crate::vm::database::ClaritySerializable
    ) -> Result<u64>
    where
        Self: Sized {
        todo!()
    }

    fn get<T>(&mut self, key: &str) -> Result<Option<T>>
    where
        T: crate::vm::database::ClarityDeserializable<T>,
        Self: Sized {
        todo!()
    }

    fn put_value(&mut self, key: &str, value: crate::vm::Value, epoch: &stacks_common::types::StacksEpochId) -> Result<()> {
        todo!()
    }

    fn put_value_with_size(
        &mut self,
        key: &str,
        value: crate::vm::Value,
        epoch: &stacks_common::types::StacksEpochId,
    ) -> Result<u64> {
        todo!()
    }

    fn get_value(
        &mut self,
        key: &str,
        expected: &TypeSignature,
        epoch: &stacks_common::types::StacksEpochId,
    ) -> Result<Option<crate::vm::database::key_value_wrapper::ValueResult>> {
        todo!()
    }

    fn get_with_proof<T>(&mut self, key: &str) -> Result<Option<(T, Vec<u8>)>>
    where
        T: crate::vm::database::ClarityDeserializable<T>,
        Self: Sized {
        todo!()
    }

    fn insert_contract_hash(
        &mut self,
        contract_identifier: &QualifiedContractIdentifier,
        contract_content: &str,
    ) -> Result<()> {
        todo!()
    }

    fn get_contract_src(
        &mut self,
        contract_identifier: &QualifiedContractIdentifier,
    ) -> Result<Option<String>> {
        todo!()
    }

    fn set_metadata(
        &mut self,
        contract_identifier: &QualifiedContractIdentifier,
        key: &str,
        data: &str,
    ) -> Result<()> {
        todo!()
    }

    fn insert_metadata<T: crate::vm::database::ClaritySerializable>(
        &mut self,
        contract_identifier: &QualifiedContractIdentifier,
        key: &str,
        data: &T,
    ) -> Result<()>
    where
        Self: Sized {
        todo!()
    }

    fn fetch_metadata<T>(
        &mut self,
        contract_identifier: &QualifiedContractIdentifier,
        key: &str,
    ) -> Result<Option<T>>
    where
        T: crate::vm::database::ClarityDeserializable<T>,
        Self: Sized {
        todo!()
    }

    fn fetch_metadata_manual<T>(
        &mut self,
        at_height: u32,
        contract_identifier: &QualifiedContractIdentifier,
        key: &str,
    ) -> Result<Option<T>>
    where
        Self: Sized {
        todo!()
    }

    fn load_contract_analysis(
        &mut self,
        contract_identifier: &QualifiedContractIdentifier,
    ) -> Result<Option<crate::vm::analysis::ContractAnalysis>> {
        todo!()
    }

    fn get_contract_size(
        &mut self,
        contract_identifier: &QualifiedContractIdentifier,
    ) -> Result<u64> {
        todo!()
    }

    fn set_contract_data_size(
        &mut self,
        contract_identifier: &QualifiedContractIdentifier,
        data_size: u64,
    ) -> Result<()> {
        todo!()
    }

    fn insert_contract(
        &mut self,
        contract_identifier: &QualifiedContractIdentifier,
        contract: crate::vm::contracts::Contract,
    ) -> Result<()> {
        todo!()
    }

    fn has_contract(
        &mut self, 
        contract_identifier: &QualifiedContractIdentifier
    ) -> Result<bool> {
        todo!()
    }

    fn get_contract(
        &mut self,
        contract_identifier: &QualifiedContractIdentifier,
    ) -> Result<crate::vm::contracts::Contract> {
        todo!()
    }

    fn make_contract_commitment(
        &mut self, 
        contract_hash: stacks_common::util::hash::Sha512Trunc256Sum
    ) -> Result<String> {
        todo!()
    }
}

impl TransactionalClarityDb for ClarityMemoryStore {
    fn begin(&mut self) {
        todo!()
    }

    fn commit(&mut self) {
        todo!()
    }

    fn rollback(&mut self) {
        todo!()
    }

    fn from_rollback_wrapper(wrapper: crate::vm::database::RollbackWrapper<Self>) -> Self where Self: Sized {
        todo!()
    }
}

impl UndoLog for ClarityMemoryStore {
    type DB = Self;

    fn nest(&mut self) -> UndoRecord {
        todo!()
    }

    fn depth(&self) -> usize {
        todo!()
    }

    fn is_stack_empty(&self) -> bool {
        todo!()
    }
}

impl ClarityDbBlocks for ClarityMemoryStore {
    fn get_index_block_header_hash(&mut self, block_height: u32) -> Result<stacks_common::types::chainstate::StacksBlockId> {
        todo!()
    }

    fn get_current_block_height(&mut self) -> Result<u32> {
        todo!()
    }

    fn get_v1_unlock_height(&self) -> Result<u32> {
        todo!()
    }

    fn get_pox_3_activation_height(&self) -> Result<u32> {
        todo!()
    }

    fn get_pox_4_activation_height(&self) -> Result<u32> {
        todo!()
    }

    fn get_v2_unlock_height(&mut self) -> Result<u32> {
        todo!()
    }

    fn get_v3_unlock_height(&mut self) -> Result<u32> {
        todo!()
    }

    fn get_current_burnchain_block_height(&mut self) -> Result<u32> {
        todo!()
    }

    fn get_block_header_hash(&mut self, block_height: u32) -> Result<stacks_common::types::chainstate::BlockHeaderHash> {
        todo!()
    }

    fn get_block_time(&mut self, block_height: u32) -> Result<u64> {
        todo!()
    }

    fn get_burnchain_block_header_hash(&mut self, block_height: u32) -> Result<stacks_common::types::chainstate::BurnchainHeaderHash> {
        todo!()
    }

    fn get_sortition_id_for_stacks_tip(&mut self) -> Result<Option<stacks_common::types::chainstate::SortitionId>> {
        todo!()
    }

    fn get_burnchain_block_header_hash_for_burnchain_height(
        &mut self,
        burnchain_block_height: u32,
    ) -> Result<Option<stacks_common::types::chainstate::BurnchainHeaderHash>> {
        todo!()
    }

    fn get_pox_payout_addrs_for_burnchain_height(
        &mut self,
        burnchain_block_height: u32,
    ) -> Result<Option<(Vec<TupleData>, u128)>> {
        todo!()
    }

    fn get_burnchain_block_height(&mut self, id_bhh: &stacks_common::types::chainstate::StacksBlockId) -> Result<Option<u32>> {
        todo!()
    }

    fn get_block_vrf_seed(&mut self, block_height: u32) -> Result<stacks_common::types::chainstate::VRFSeed> {
        todo!()
    }

    fn get_miner_address(&mut self, block_height: u32) -> Result<StandardPrincipalData> {
        todo!()
    }

    fn get_miner_spend_winner(&mut self, block_height: u32) -> Result<u128> {
        todo!()
    }

    fn get_miner_spend_total(&mut self, block_height: u32) -> Result<u128> {
        todo!()
    }

    fn get_block_reward(&mut self, block_height: u32) -> Result<Option<u128>> {
        todo!()
    }
}

impl ClarityDbAssets for ClarityMemoryStore {}

impl ClarityDbMaps for ClarityMemoryStore {
    fn set_entry(
        &mut self,
        contract_identifier: &QualifiedContractIdentifier,
        map_name: &str,
        key: crate::vm::Value,
        value: crate::vm::Value,
        map_descriptor: &crate::vm::database::DataMapMetadata,
        epoch: &stacks_common::types::StacksEpochId,
    ) -> Result<crate::vm::database::key_value_wrapper::ValueResult> {
        todo!()
    }
}

impl ClarityDbVars for ClarityMemoryStore {}

impl ClarityDbMicroblocks for ClarityMemoryStore {
    fn get_cc_special_cases_handler(
        &self
    ) -> Result<Option<crate::vm::database::SpecialCaseHandler<Self>>>
    where 
        Self: Sized {
        todo!()
    }
}

impl ClarityDbStx for ClarityMemoryStore {}

impl ClarityDbUstx for ClarityMemoryStore {}

impl ClarityDbAnalysis for ClarityMemoryStore {
    fn execute<F, T, E>(&mut self, f: F) -> std::result::Result<T, E>
    where
        Self: Sized,
        F: FnOnce(&mut Self) -> std::result::Result<T, E> {
        todo!()
    }

    fn storage_key() -> &'static str where Self: Sized {
        todo!()
    }

    #[cfg(test)]
    fn test_insert_contract_hash(&mut self, contract_identifier: &QualifiedContractIdentifier) {
        todo!()
    }

    fn has_contract(&mut self, contract_identifier: &QualifiedContractIdentifier) -> bool {
        todo!()
    }

    fn load_contract_non_canonical(
        &mut self,
        contract_identifier: &QualifiedContractIdentifier,
    ) -> Option<crate::vm::analysis::ContractAnalysis> {
        todo!()
    }

    fn load_contract(
        &mut self,
        contract_identifier: &QualifiedContractIdentifier,
        epoch: &stacks_common::types::StacksEpochId,
    ) -> Option<crate::vm::analysis::ContractAnalysis> {
        todo!()
    }

    fn insert_contract_analysis(
        &mut self,
        contract_identifier: &QualifiedContractIdentifier,
        contract: &crate::vm::analysis::ContractAnalysis,
    ) -> crate::vm::analysis::CheckResult<()> {
        todo!()
    }

    fn get_clarity_version(
        &mut self,
        contract_identifier: &QualifiedContractIdentifier,
    ) -> crate::vm::analysis::CheckResult<crate::vm::ClarityVersion> {
        todo!()
    }

    fn get_public_function_type(
        &mut self,
        contract_identifier: &QualifiedContractIdentifier,
        function_name: &str,
        epoch: &stacks_common::types::StacksEpochId,
    ) -> crate::vm::analysis::CheckResult<Option<FunctionType>> {
        todo!()
    }

    fn get_read_only_function_type(
        &mut self,
        contract_identifier: &QualifiedContractIdentifier,
        function_name: &str,
        epoch: &stacks_common::types::StacksEpochId,
    ) -> crate::vm::analysis::CheckResult<Option<FunctionType>> {
        todo!()
    }

    fn get_defined_trait(
        &mut self,
        contract_identifier: &QualifiedContractIdentifier,
        trait_name: &str,
        epoch: &stacks_common::types::StacksEpochId,
    ) -> crate::vm::analysis::CheckResult<Option<std::collections::BTreeMap<crate::vm::ClarityName, FunctionSignature>>> {
        todo!()
    }

    fn get_implemented_traits(
        &mut self,
        contract_identifier: &QualifiedContractIdentifier,
    ) -> crate::vm::analysis::CheckResult<std::collections::BTreeSet<TraitIdentifier>> {
        todo!()
    }
}

impl ClarityDbKvStore for ClarityMemoryStore {
    fn kv_put_all(&mut self, items: Vec<(String, String)>) -> Result<()> {
        todo!()
    }

    fn kv_get_with_proof(&mut self, key: &str) -> Result<Option<(String, Vec<u8>)>> {
        todo!()
    }

    fn kv_has_entry(&mut self, key: &str) -> Result<bool> {
        todo!()
    }

    fn kv_set_block_hash(&mut self, bhh: stacks_common::types::chainstate::StacksBlockId) -> Result<stacks_common::types::chainstate::StacksBlockId> {
        todo!()
    }

    fn kv_get_block_at_height(&mut self, height: u32) -> Result<Option<stacks_common::types::chainstate::StacksBlockId>> {
        todo!()
    }

    fn kv_get_current_block_height(&mut self) -> Result<u32> {
        todo!()
    }

    fn kv_get_open_chain_tip_height(&mut self) -> Result<u32> {
        todo!()
    }

    fn kv_get_open_chain_tip(&mut self) -> Result<stacks_common::types::chainstate::StacksBlockId> {
        todo!()
    }

    fn kv_get_contract_hash(
        &mut self,
        contract: &QualifiedContractIdentifier,
    ) -> Result<(stacks_common::types::chainstate::StacksBlockId, stacks_common::util::hash::Sha512Trunc256Sum)> 
    where
        Self: Sized {
        todo!()
    }

    fn kv_insert_metadata(
        &mut self, 
        contract: &QualifiedContractIdentifier, 
        key: &str, 
        value: &str
    ) -> Result<()> {
        todo!()
    }

    fn kv_get_metadata(
        &mut self,
        contract: &QualifiedContractIdentifier,
        key: &str,
    ) -> Result<Option<String>> {
        todo!()
    }

    fn kv_get_metadata_manual(
        &mut self,
        at_height: u32,
        contract: &QualifiedContractIdentifier,
        key: &str,
    ) -> Result<Option<String>> {
        todo!()
    }
}