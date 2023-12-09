use std::collections::{BTreeMap, BTreeSet};

use stacks_common::types::StacksEpochId;

use crate::vm::{types::{QualifiedContractIdentifier, FunctionType, FunctionSignature, TraitIdentifier}, analysis::{ContractAnalysis, CheckResult}, ClarityVersion, ClarityName};

use super::transactional::TransactionalClarityDb;

pub trait ClarityDbAnalysis: TransactionalClarityDb
{
     fn execute<F, T, E>(&mut self, f: F) -> Result<T, E>
    where
        Self: Sized,
        F: FnOnce(&mut Self) -> Result<T, E>;

     fn storage_key() -> &'static str where Self: Sized;

    // used by tests to ensure that
    //   the contract -> contract hash key exists in the marf
    //    even if the contract isn't published.
    #[cfg(test)]
     fn test_insert_contract_hash(&mut self, contract_identifier: &QualifiedContractIdentifier);

     fn has_contract(&mut self, contract_identifier: &QualifiedContractIdentifier) -> bool;

    /// Load a contract from the database, without canonicalizing its types.
     fn load_contract_non_canonical(
        &mut self,
        contract_identifier: &QualifiedContractIdentifier,
    ) -> Option<ContractAnalysis>;

     fn load_contract(
        &mut self,
        contract_identifier: &QualifiedContractIdentifier,
        epoch: &StacksEpochId,
    ) -> Option<ContractAnalysis>;

     fn insert_contract_analysis(
        &mut self,
        contract_identifier: &QualifiedContractIdentifier,
        contract: &ContractAnalysis,
    ) -> CheckResult<()>;

     fn get_clarity_version(
        &mut self,
        contract_identifier: &QualifiedContractIdentifier,
    ) -> CheckResult<ClarityVersion>;

     fn get_public_function_type(
        &mut self,
        contract_identifier: &QualifiedContractIdentifier,
        function_name: &str,
        epoch: &StacksEpochId,
    ) -> CheckResult<Option<FunctionType>>;

     fn get_read_only_function_type(
        &mut self,
        contract_identifier: &QualifiedContractIdentifier,
        function_name: &str,
        epoch: &StacksEpochId,
    ) -> CheckResult<Option<FunctionType>>;

     fn get_defined_trait(
        &mut self,
        contract_identifier: &QualifiedContractIdentifier,
        trait_name: &str,
        epoch: &StacksEpochId,
    ) -> CheckResult<Option<BTreeMap<ClarityName, FunctionSignature>>>;

     fn get_implemented_traits(
        &mut self,
        contract_identifier: &QualifiedContractIdentifier,
    ) -> CheckResult<BTreeSet<TraitIdentifier>>;
}