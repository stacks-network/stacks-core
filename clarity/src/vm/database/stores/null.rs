use super::super::v2::*;

pub struct NullClarityStore {}

impl NullClarityStore {
    pub fn new() -> Self {
        Self {}
    }
}

impl ClarityDb for NullClarityStore {
    fn set_block_hash(
        &mut self,
        bhh: stacks_common::types::chainstate::StacksBlockId,
        query_pending_data: bool,
    ) -> crate::vm::errors::InterpreterResult<stacks_common::types::chainstate::StacksBlockId> {
        todo!()
    }

    fn put(
        &mut self, 
        key: &str, 
        value: &impl crate::vm::database::ClaritySerializable
    ) -> crate::vm::errors::InterpreterResult<()> 
    where 
        Self: Sized {
        todo!()
    }

    fn put_with_size(
        &mut self, 
        key: &str, 
        value: &impl crate::vm::database::ClaritySerializable
    ) -> crate::vm::errors::InterpreterResult<u64>
    where
        Self: Sized {
        todo!()
    }

    fn get<T>(&mut self, key: &str) -> crate::vm::errors::InterpreterResult<Option<T>>
    where
        T: crate::vm::database::ClarityDeserializable<T>,
        Self: Sized {
        todo!()
    }

    fn put_value(&mut self, key: &str, value: crate::vm::Value, epoch: &stacks_common::types::StacksEpochId) -> crate::vm::errors::InterpreterResult<()> {
        todo!()
    }

    fn put_value_with_size(
        &mut self,
        key: &str,
        value: crate::vm::Value,
        epoch: &stacks_common::types::StacksEpochId,
    ) -> crate::vm::errors::InterpreterResult<u64> {
        todo!()
    }

    fn get_value(
        &mut self,
        key: &str,
        expected: &crate::vm::types::TypeSignature,
        epoch: &stacks_common::types::StacksEpochId,
    ) -> crate::vm::errors::InterpreterResult<Option<crate::vm::database::key_value_wrapper::ValueResult>> {
        todo!()
    }

    fn get_with_proof<T>(&mut self, key: &str) -> crate::vm::errors::InterpreterResult<Option<(T, Vec<u8>)>>
    where
        T: crate::vm::database::ClarityDeserializable<T>,
        Self: Sized {
        todo!()
    }

    fn insert_contract_hash(
        &mut self,
        contract_identifier: &crate::vm::types::QualifiedContractIdentifier,
        contract_content: &str,
    ) -> crate::vm::errors::InterpreterResult<()> {
        todo!()
    }

    fn get_contract_src(
        &mut self,
        contract_identifier: &crate::vm::types::QualifiedContractIdentifier,
    ) -> crate::vm::errors::InterpreterResult<Option<String>> {
        todo!()
    }

    fn set_metadata(
        &mut self,
        contract_identifier: &crate::vm::types::QualifiedContractIdentifier,
        key: &str,
        data: &str,
    ) -> crate::vm::errors::InterpreterResult<()> {
        todo!()
    }

    fn insert_metadata<T: crate::vm::database::ClaritySerializable>(
        &mut self,
        contract_identifier: &crate::vm::types::QualifiedContractIdentifier,
        key: &str,
        data: &T,
    ) -> crate::vm::errors::InterpreterResult<()>
    where
        Self: Sized {
        todo!()
    }

    fn fetch_metadata<T>(
        &mut self,
        contract_identifier: &crate::vm::types::QualifiedContractIdentifier,
        key: &str,
    ) -> crate::vm::errors::InterpreterResult<Option<T>>
    where
        T: crate::vm::database::ClarityDeserializable<T>,
        Self: Sized {
        todo!()
    }

    fn fetch_metadata_manual<T>(
        &mut self,
        at_height: u32,
        contract_identifier: &crate::vm::types::QualifiedContractIdentifier,
        key: &str,
    ) -> crate::vm::errors::InterpreterResult<Option<T>>
    where
        Self: Sized {
        todo!()
    }

    fn load_contract_analysis(
        &mut self,
        contract_identifier: &crate::vm::types::QualifiedContractIdentifier,
    ) -> crate::vm::errors::InterpreterResult<Option<crate::vm::analysis::ContractAnalysis>> {
        todo!()
    }

    fn get_contract_size(
        &mut self,
        contract_identifier: &crate::vm::types::QualifiedContractIdentifier,
    ) -> crate::vm::errors::InterpreterResult<u64> {
        todo!()
    }

    fn set_contract_data_size(
        &mut self,
        contract_identifier: &crate::vm::types::QualifiedContractIdentifier,
        data_size: u64,
    ) -> crate::vm::errors::InterpreterResult<()> {
        todo!()
    }

    fn insert_contract(
        &mut self,
        contract_identifier: &crate::vm::types::QualifiedContractIdentifier,
        contract: crate::vm::contracts::Contract,
    ) -> crate::vm::errors::InterpreterResult<()> {
        todo!()
    }

    fn has_contract(
        &mut self, 
        contract_identifier: &crate::vm::types::QualifiedContractIdentifier
    ) -> crate::vm::errors::InterpreterResult<bool> {
        todo!()
    }

    fn get_contract(
        &mut self,
        contract_identifier: &crate::vm::types::QualifiedContractIdentifier,
    ) -> crate::vm::errors::InterpreterResult<crate::vm::contracts::Contract> {
        todo!()
    }
}

impl TransactionalClarityDb for NullClarityStore {
    fn begin(&mut self) {
        todo!()
    }

    fn commit(&mut self) {
        todo!()
    }

    fn rollback(&mut self) {
        todo!()
    }
}

impl ClarityDbBlocks for NullClarityStore {
    fn get_index_block_header_hash(&mut self, block_height: u32) -> crate::vm::errors::InterpreterResult<stacks_common::types::chainstate::StacksBlockId> {
        todo!()
    }

    fn get_current_block_height(&mut self) -> crate::vm::errors::InterpreterResult<u32> {
        todo!()
    }

    fn get_v1_unlock_height(&self) -> crate::vm::errors::InterpreterResult<u32> {
        todo!()
    }

    fn get_pox_3_activation_height(&self) -> crate::vm::errors::InterpreterResult<u32> {
        todo!()
    }

    fn get_pox_4_activation_height(&self) -> crate::vm::errors::InterpreterResult<u32> {
        todo!()
    }

    fn get_v2_unlock_height(&mut self) -> crate::vm::errors::InterpreterResult<u32> {
        todo!()
    }

    fn get_v3_unlock_height(&mut self) -> crate::vm::errors::InterpreterResult<u32> {
        todo!()
    }

    fn get_current_burnchain_block_height(&mut self) -> crate::vm::errors::InterpreterResult<u32> {
        todo!()
    }

    fn get_block_header_hash(&mut self, block_height: u32) -> crate::vm::errors::InterpreterResult<stacks_common::types::chainstate::BlockHeaderHash> {
        todo!()
    }

    fn get_block_time(&mut self, block_height: u32) -> crate::vm::errors::InterpreterResult<u64> {
        todo!()
    }

    fn get_burnchain_block_header_hash(&mut self, block_height: u32) -> crate::vm::errors::InterpreterResult<stacks_common::types::chainstate::BurnchainHeaderHash> {
        todo!()
    }

    fn get_sortition_id_for_stacks_tip(&mut self) -> crate::vm::errors::InterpreterResult<Option<stacks_common::types::chainstate::SortitionId>> {
        todo!()
    }

    fn get_burnchain_block_header_hash_for_burnchain_height(
        &mut self,
        burnchain_block_height: u32,
    ) -> crate::vm::errors::InterpreterResult<Option<stacks_common::types::chainstate::BurnchainHeaderHash>> {
        todo!()
    }

    fn get_pox_payout_addrs_for_burnchain_height(
        &mut self,
        burnchain_block_height: u32,
    ) -> crate::vm::errors::InterpreterResult<Option<(Vec<crate::vm::types::TupleData>, u128)>> {
        todo!()
    }

    fn get_burnchain_block_height(&mut self, id_bhh: &stacks_common::types::chainstate::StacksBlockId) -> crate::vm::errors::InterpreterResult<Option<u32>> {
        todo!()
    }

    fn get_block_vrf_seed(&mut self, block_height: u32) -> crate::vm::errors::InterpreterResult<stacks_common::types::chainstate::VRFSeed> {
        todo!()
    }

    fn get_miner_address(&mut self, block_height: u32) -> crate::vm::errors::InterpreterResult<crate::vm::types::StandardPrincipalData> {
        todo!()
    }

    fn get_miner_spend_winner(&mut self, block_height: u32) -> crate::vm::errors::InterpreterResult<u128> {
        todo!()
    }

    fn get_miner_spend_total(&mut self, block_height: u32) -> crate::vm::errors::InterpreterResult<u128> {
        todo!()
    }

    fn get_block_reward(&mut self, block_height: u32) -> crate::vm::errors::InterpreterResult<Option<u128>> {
        todo!()
    }
}

impl ClarityDbAssets for NullClarityStore {}

impl ClarityDbMaps for NullClarityStore {
    fn set_entry(
        &mut self,
        contract_identifier: &crate::vm::types::QualifiedContractIdentifier,
        map_name: &str,
        key: crate::vm::Value,
        value: crate::vm::Value,
        map_descriptor: &crate::vm::database::DataMapMetadata,
        epoch: &stacks_common::types::StacksEpochId,
    ) -> crate::vm::errors::InterpreterResult<crate::vm::database::key_value_wrapper::ValueResult> {
        todo!()
    }
}

impl ClarityDbVars for NullClarityStore {}

impl ClarityDbMicroblocks for NullClarityStore {
    fn get_cc_special_cases_handler(
        &self
    ) -> crate::vm::errors::InterpreterResult<Option<crate::vm::database::SpecialCaseHandler<Self>>>
    where 
        Self: Sized {
        todo!()
    }
}

impl ClarityDbStx for NullClarityStore {}

impl ClarityDbUstx for NullClarityStore {}