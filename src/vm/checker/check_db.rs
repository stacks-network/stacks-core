use std::collections::HashMap;

use vm::database::{KeyValueStorage, ClaritySerializable, ClarityDeserializable, KeyType, RollbackWrapper};
use vm::checker::errors::{CheckError, CheckErrors, CheckResult};
use vm::types::TypeSignature;
use vm::checker::typecheck::{ContractAnalysis, FunctionType};
use util::hash::Sha256Sum;

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

impl <'a> AnalysisDatabase <'a> {
    pub fn new(store: Box<KeyValueStorage + 'a>) -> AnalysisDatabase<'a> {
        AnalysisDatabase {
            store: RollbackWrapper::new(store)
        }
    }

    pub fn memory() -> AnalysisDatabase<'a> {
        let store: HashMap<KeyType, String> = HashMap::new();
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

    fn put(&mut self, key: &KeyType, value: &ClaritySerializable) {
        self.store.put(&key, &value.serialize());
    }

    fn get <T> (&self, key: &KeyType) -> Option<T> where T: ClarityDeserializable<T> {
        self.store.get(&key)
            .map(|x| T::deserialize(&x))
    }

    fn make_key(contract_name: &str) -> KeyType {
        let string = format!("analysis::{}", contract_name);
        let Sha256Sum(hash_data) = Sha256Sum::from_data(string.as_bytes());
        hash_data
    }

    fn load_contract(&self, contract_name: &str) -> Option<ContractAnalysis> {
        let key = AnalysisDatabase::make_key(contract_name);
        self.get(&key)
    }

    pub fn insert_contract(&mut self, contract_name: &str, contract: &ContractAnalysis) -> CheckResult<()> {
        let key = AnalysisDatabase::make_key(contract_name);
        if self.store.has_entry(&key) {
            return Err(CheckError::new(CheckErrors::ContractAlreadyExists(contract_name.to_string())))
        }
        self.put(&key, contract);
        Ok(())
    }

    pub fn get_public_function_type(&self, contract_name: &str, function_name: &str) -> CheckResult<Option<FunctionType>> {
        let contract = self.load_contract(contract_name)
            .ok_or(CheckErrors::NoSuchContract(contract_name.to_string()))?;
        Ok(contract.get_public_function_type(function_name)
           .cloned())
    }

    pub fn get_read_only_function_type(&self, contract_name: &str, function_name: &str) -> CheckResult<Option<FunctionType>> {
        let contract = self.load_contract(contract_name)
            .ok_or(CheckErrors::NoSuchContract(contract_name.to_string()))?;
        Ok(contract.get_read_only_function_type(function_name)
           .cloned())
    }

    pub fn get_map_type(&self, contract_name: &str, map_name: &str) -> CheckResult<(TypeSignature, TypeSignature)> {
        let contract = self.load_contract(contract_name)
            .ok_or(CheckErrors::NoSuchContract(contract_name.to_string()))?;
        let map_type = contract.get_map_type(map_name)
            .ok_or(CheckErrors::NoSuchMap(map_name.to_string()))?;
        Ok(map_type.clone())
    }
}
