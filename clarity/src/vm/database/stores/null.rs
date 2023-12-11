use stacks_common::types::{StacksEpochId, chainstate::{BlockHeaderHash, BurnchainHeaderHash, SortitionId, VRFSeed, StacksBlockId}};

use crate::vm::database::{ClaritySerializable, ClarityDeserializable, key_value_wrapper, DataMapMetadata, SpecialCaseHandler};

use super::super::v2::*;

pub struct ClarityNullStore {}

impl ClarityNullStore {
    pub fn new() -> Self {
        Self {}
    }
}

impl ClarityDb for ClarityNullStore {
    fn set_block_hash(
        &mut self,
        bhh: StacksBlockId,
        query_pending_data: bool,
    ) -> Result<StacksBlockId> {
        todo!()
    }

    fn put(
        &mut self, 
        key: &str, 
        value: &impl ClaritySerializable
    ) -> Result<()> 
    where 
        Self: Sized {
        todo!()
    }

    fn put_with_size(
        &mut self, 
        key: &str, 
        value: &impl ClaritySerializable
    ) -> Result<u64>
    where
        Self: Sized {
        todo!()
    }

    fn get<T>(&mut self, key: &str) -> Result<Option<T>>
    where
        T: ClarityDeserializable<T>,
        Self: Sized {
        todo!()
    }

    fn put_value(&mut self, key: &str, value: crate::vm::Value, epoch: &StacksEpochId) -> Result<()> {
        todo!()
    }

    fn put_value_with_size(
        &mut self,
        key: &str,
        value: crate::vm::Value,
        epoch: &StacksEpochId,
    ) -> Result<u64> {
        todo!()
    }

    fn get_value(
        &mut self,
        key: &str,
        expected: &crate::vm::types::TypeSignature,
        epoch: &StacksEpochId,
    ) -> Result<Option<key_value_wrapper::ValueResult>> {
        todo!()
    }

    fn get_with_proof<T>(&mut self, key: &str) -> Result<Option<(T, Vec<u8>)>>
    where
        T: ClarityDeserializable<T>,
        Self: Sized {
        todo!()
    }

    fn insert_contract_hash(
        &mut self,
        contract_identifier: &crate::vm::types::QualifiedContractIdentifier,
        contract_content: &str,
    ) -> Result<()> {
        todo!()
    }

    fn get_contract_src(
        &mut self,
        contract_identifier: &crate::vm::types::QualifiedContractIdentifier,
    ) -> Result<Option<String>> {
        todo!()
    }

    fn set_metadata(
        &mut self,
        contract_identifier: &crate::vm::types::QualifiedContractIdentifier,
        key: &str,
        data: &str,
    ) -> Result<()> {
        todo!()
    }

    fn insert_metadata<T: ClaritySerializable>(
        &mut self,
        contract_identifier: &crate::vm::types::QualifiedContractIdentifier,
        key: &str,
        data: &T,
    ) -> Result<()>
    where
        Self: Sized {
        todo!()
    }

    fn fetch_metadata<T>(
        &mut self,
        contract_identifier: &crate::vm::types::QualifiedContractIdentifier,
        key: &str,
    ) -> Result<Option<T>>
    where
        T: ClarityDeserializable<T>,
        Self: Sized {
        todo!()
    }

    fn fetch_metadata_manual<T>(
        &mut self,
        at_height: u32,
        contract_identifier: &crate::vm::types::QualifiedContractIdentifier,
        key: &str,
    ) -> Result<Option<T>>
    where
        Self: Sized {
        todo!()
    }

    fn load_contract_analysis(
        &mut self,
        contract_identifier: &crate::vm::types::QualifiedContractIdentifier,
    ) -> Result<Option<crate::vm::analysis::ContractAnalysis>> {
        todo!()
    }

    fn get_contract_size(
        &mut self,
        contract_identifier: &crate::vm::types::QualifiedContractIdentifier,
    ) -> Result<u64> {
        todo!()
    }

    fn set_contract_data_size(
        &mut self,
        contract_identifier: &crate::vm::types::QualifiedContractIdentifier,
        data_size: u64,
    ) -> Result<()> {
        todo!()
    }

    fn insert_contract(
        &mut self,
        contract_identifier: &crate::vm::types::QualifiedContractIdentifier,
        contract: crate::vm::contracts::Contract,
    ) -> Result<()> {
        todo!()
    }

    fn has_contract(
        &mut self, 
        contract_identifier: &crate::vm::types::QualifiedContractIdentifier
    ) -> Result<bool> {
        todo!()
    }

    fn get_contract(
        &mut self,
        contract_identifier: &crate::vm::types::QualifiedContractIdentifier,
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

impl TransactionalClarityDb for ClarityNullStore {
    fn begin(&mut self) {
        todo!()
    }

    fn commit(&mut self) {
        todo!()
    }

    fn rollback(&mut self) {
        todo!()
    }

    fn from_rollback_wrapper(wrapper: key_value_wrapper::RollbackWrapper<Self>) -> Self where Self: Sized {
        todo!()
    }
}

impl UndoLog for ClarityNullStore {
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

impl ClarityDbBlocks for ClarityNullStore {
    fn get_index_block_header_hash(&mut self, block_height: u32) -> Result<StacksBlockId> {
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

    fn get_block_header_hash(&mut self, block_height: u32) -> Result<BlockHeaderHash> {
        todo!()
    }

    fn get_block_time(&mut self, block_height: u32) -> Result<u64> {
        todo!()
    }

    fn get_burnchain_block_header_hash(&mut self, block_height: u32) -> Result<BurnchainHeaderHash> {
        todo!()
    }

    fn get_sortition_id_for_stacks_tip(&mut self) -> Result<Option<SortitionId>> {
        todo!()
    }

    fn get_burnchain_block_header_hash_for_burnchain_height(
        &mut self,
        burnchain_block_height: u32,
    ) -> Result<Option<BurnchainHeaderHash>> {
        todo!()
    }

    fn get_pox_payout_addrs_for_burnchain_height(
        &mut self,
        burnchain_block_height: u32,
    ) -> Result<Option<(Vec<crate::vm::types::TupleData>, u128)>> {
        todo!()
    }

    fn get_burnchain_block_height(&mut self, id_bhh: &StacksBlockId) -> Result<Option<u32>> {
        todo!()
    }

    fn get_block_vrf_seed(&mut self, block_height: u32) -> Result<VRFSeed> {
        todo!()
    }

    fn get_miner_address(&mut self, block_height: u32) -> Result<crate::vm::types::StandardPrincipalData> {
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

impl ClarityDbAssets for ClarityNullStore {}

impl ClarityDbMaps for ClarityNullStore {
    fn set_entry(
        &mut self,
        contract_identifier: &crate::vm::types::QualifiedContractIdentifier,
        map_name: &str,
        key: crate::vm::Value,
        value: crate::vm::Value,
        map_descriptor: &DataMapMetadata,
        epoch: &StacksEpochId,
    ) -> Result<key_value_wrapper::ValueResult> {
        todo!()
    }
}

impl ClarityDbVars for ClarityNullStore {}

impl ClarityDbMicroblocks for ClarityNullStore {
    fn get_cc_special_cases_handler(
        &self
    ) -> Result<Option<SpecialCaseHandler<Self>>>
    where 
        Self: Sized {
        todo!()
    }
}

impl ClarityDbStx for ClarityNullStore {}

impl ClarityDbUstx for ClarityNullStore {}

impl ClarityDbAnalysis for ClarityNullStore {
    fn execute<F, T, E>(&mut self, f: F) -> std::prelude::v1::Result<T, E>
    where
        Self: Sized,
        F: FnOnce(&mut Self) -> std::prelude::v1::Result<T, E> {
        todo!()
    }

    fn storage_key() -> &'static str where Self: Sized {
        todo!()
    }

    #[cfg(test)]
    fn test_insert_contract_hash(&mut self, contract_identifier: &crate::vm::types::QualifiedContractIdentifier) {
        todo!()
    }

    fn has_contract(&mut self, contract_identifier: &crate::vm::types::QualifiedContractIdentifier) -> bool {
        todo!()
    }

    fn load_contract_non_canonical(
        &mut self,
        contract_identifier: &crate::vm::types::QualifiedContractIdentifier,
    ) -> Option<crate::vm::analysis::ContractAnalysis> {
        todo!()
    }

    fn load_contract(
        &mut self,
        contract_identifier: &crate::vm::types::QualifiedContractIdentifier,
        epoch: &StacksEpochId,
    ) -> Option<crate::vm::analysis::ContractAnalysis> {
        todo!()
    }

    fn insert_contract_analysis(
        &mut self,
        contract_identifier: &crate::vm::types::QualifiedContractIdentifier,
        contract: &crate::vm::analysis::ContractAnalysis,
    ) -> crate::vm::analysis::CheckResult<()> {
        todo!()
    }

    fn get_clarity_version(
        &mut self,
        contract_identifier: &crate::vm::types::QualifiedContractIdentifier,
    ) -> crate::vm::analysis::CheckResult<crate::vm::ClarityVersion> {
        todo!()
    }

    fn get_public_function_type(
        &mut self,
        contract_identifier: &crate::vm::types::QualifiedContractIdentifier,
        function_name: &str,
        epoch: &StacksEpochId,
    ) -> crate::vm::analysis::CheckResult<Option<crate::vm::types::FunctionType>> {
        todo!()
    }

    fn get_read_only_function_type(
        &mut self,
        contract_identifier: &crate::vm::types::QualifiedContractIdentifier,
        function_name: &str,
        epoch: &StacksEpochId,
    ) -> crate::vm::analysis::CheckResult<Option<crate::vm::types::FunctionType>> {
        todo!()
    }

    fn get_defined_trait(
        &mut self,
        contract_identifier: &crate::vm::types::QualifiedContractIdentifier,
        trait_name: &str,
        epoch: &StacksEpochId,
    ) -> crate::vm::analysis::CheckResult<Option<std::collections::BTreeMap<crate::vm::ClarityName, crate::vm::types::FunctionSignature>>> {
        todo!()
    }

    fn get_implemented_traits(
        &mut self,
        contract_identifier: &crate::vm::types::QualifiedContractIdentifier,
    ) -> crate::vm::analysis::CheckResult<std::collections::BTreeSet<crate::vm::types::TraitIdentifier>> {
        todo!()
    }
}

impl ClarityDbKvStore for ClarityNullStore {
    fn kv_put_all(&mut self, items: Vec<(String, String)>) -> Result<()> {
        todo!()
    }

    fn kv_get_with_proof(&mut self, key: &str) -> Result<Option<(String, Vec<u8>)>> {
        todo!()
    }

    fn kv_has_entry(&mut self, key: &str) -> Result<bool> {
        todo!()
    }

    fn kv_set_block_hash(&mut self, bhh: StacksBlockId) -> Result<StacksBlockId> {
        todo!()
    }

    fn kv_get_block_at_height(&mut self, height: u32) -> Result<Option<StacksBlockId>> {
        todo!()
    }

    fn kv_get_current_block_height(&mut self) -> Result<u32> {
        todo!()
    }

    fn kv_get_open_chain_tip_height(&mut self) -> Result<u32> {
        todo!()
    }

    fn kv_get_open_chain_tip(&mut self) -> Result<StacksBlockId> {
        todo!()
    }

    fn kv_get_contract_hash(
        &mut self,
        contract: &crate::vm::types::QualifiedContractIdentifier,
    ) -> Result<(StacksBlockId, stacks_common::util::hash::Sha512Trunc256Sum)> 
    where
        Self: Sized {
        todo!()
    }

    fn kv_insert_metadata(
        &mut self, 
        contract: &crate::vm::types::QualifiedContractIdentifier, 
        key: &str, 
        value: &str
    ) -> Result<()> {
        todo!()
    }

    fn kv_get_metadata(
        &mut self,
        contract: &crate::vm::types::QualifiedContractIdentifier,
        key: &str,
    ) -> Result<Option<String>> {
        todo!()
    }

    fn kv_get_metadata_manual(
        &mut self,
        at_height: u32,
        contract: &crate::vm::types::QualifiedContractIdentifier,
        key: &str,
    ) -> Result<Option<String>> {
        todo!()
    }
}