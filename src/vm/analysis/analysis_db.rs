use std::collections::HashMap;

use vm::types::{TypeSignature, FunctionType, QualifiedContractIdentifier};
use vm::database::{KeyValueStorage, ClaritySerializable, ClarityDeserializable, RollbackWrapper};
use vm::analysis::errors::{CheckError, CheckErrors, CheckResult};
use vm::analysis::type_checker::{ContractAnalysis};
use vm::analysis::cost_counter::{ContractCostAnalysis, SimpleCostSpecification};

pub struct AnalysisDatabase <'a> {
    store: RollbackWrapper <'a>
}

impl ClaritySerializable for ContractAnalysis {
    fn serialize(&self) -> String {
        serde_json::to_string(self)
            .expect("Failed to serialize vm.Value")
    }
}

impl ClarityDeserializable<ContractAnalysis> for ContractAnalysis {
    fn deserialize(json: &str) -> Self {
        serde_json::from_str(json)
            .expect("Failed to serialize vm.Value")
    }
}


impl ClaritySerializable for ContractCostAnalysis {
    fn serialize(&self) -> String {
        serde_json::to_string(self)
            .expect("Failed to serialize vm.Value")
    }
}

impl ClarityDeserializable<ContractCostAnalysis> for ContractCostAnalysis {
    fn deserialize(json: &str) -> Self {
        serde_json::from_str(json)
            .expect("Failed to serialize vm.Value")
    }
}

impl <'a> AnalysisDatabase <'a> {
    pub fn new(store: Box<dyn KeyValueStorage + 'a>) -> AnalysisDatabase<'a> {
        AnalysisDatabase {
            store: RollbackWrapper::new(store)
        }
    }

    pub fn memory() -> AnalysisDatabase<'a> {
        let store: HashMap<String, String> = HashMap::new();
        Self::new(Box::new(store))
    }

    pub fn execute <F, T, E> (&mut self, f: F) -> Result<T,E> where F: FnOnce(&mut Self) -> Result<T,E>, {
        self.begin();
        let result = f(self)
            .or_else(|e| {
                self.roll_back();
                Err(e)
            })?;
        self.commit();
        Ok(result)
    }

    pub fn begin(&mut self) {
        self.store.nest();
    }

    pub fn commit(&mut self) {
        self.store.commit();
    }

    pub fn roll_back(&mut self) {
        self.store.rollback();
    }

    fn put <T: ClaritySerializable> (&mut self, key: &str, value: &T) {
        self.store.put(&key, &value.serialize());
    }

    fn get <T> (&mut self, key: &str) -> Option<T> where T: ClarityDeserializable<T> {
        self.store.get(&key)
            .map(|x| T::deserialize(&x))
    }

    // Creates the key used to store the given contract in the underlying Key-Value store.
    fn make_storage_key(prefix: &'static str, contract_identifier: &QualifiedContractIdentifier) -> String {
        format!("analysis::{}::{}", prefix, contract_identifier)
    }

    fn load_contract(&mut self, contract_identifier: &QualifiedContractIdentifier) -> Option<ContractAnalysis> {
        let key = AnalysisDatabase::make_storage_key("types", contract_identifier);
        self.get(&key)
    }

    pub fn insert_contract(&mut self, contract_identifier: &QualifiedContractIdentifier, contract: &ContractAnalysis) -> CheckResult<()> {
        let key = AnalysisDatabase::make_storage_key("types", contract_identifier);
        if self.store.has_entry(&key) {
            return Err(CheckError::new(CheckErrors::ContractAlreadyExists(contract_identifier.to_string())))
        }
        self.put(&key, contract);
        Ok(())
    }

    pub fn get_public_function_type(&mut self, contract_identifier: &QualifiedContractIdentifier, function_name: &str) -> CheckResult<Option<FunctionType>> {
        let contract = self.load_contract(contract_identifier)
            .ok_or(CheckErrors::NoSuchContract(contract_identifier.to_string()))?;
        Ok(contract.get_public_function_type(function_name)
           .cloned())
    }

    pub fn get_read_only_function_type(&mut self, contract_identifier: &QualifiedContractIdentifier, function_name: &str) -> CheckResult<Option<FunctionType>> {
        let contract = self.load_contract(contract_identifier)
            .ok_or(CheckErrors::NoSuchContract(contract_identifier.to_string()))?;
        Ok(contract.get_read_only_function_type(function_name)
           .cloned())
    }

    pub fn get_map_type(&mut self, contract_identifier: &QualifiedContractIdentifier, map_name: &str) -> CheckResult<(TypeSignature, TypeSignature)> {
        let contract = self.load_contract(contract_identifier)
            .ok_or(CheckErrors::NoSuchContract(contract_identifier.to_string()))?;
        let map_type = contract.get_map_type(map_name)
            .ok_or(CheckErrors::NoSuchMap(map_name.to_string()))?;
        Ok(map_type.clone())
    }

    pub fn get_contract_function_cost(&mut self, contract_identifier: &QualifiedContractIdentifier, function_name: &str) -> Option<SimpleCostSpecification> {
        let contract = self.load_contract(contract_identifier)?;
        contract.cost_analysis.as_ref()?.get_function_cost(function_name)
    }

    pub fn get_contract_size(&mut self, contract_identifier: &QualifiedContractIdentifier) -> Option<u64> {
        let key = AnalysisDatabase::make_storage_key("size", contract_identifier);
        self.get(&key)
    }
}
