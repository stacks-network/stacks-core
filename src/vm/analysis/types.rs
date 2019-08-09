use std::collections::{BTreeMap};
use vm::types::{TypeSignature, FunctionType};

const DESERIALIZE_FAIL_MESSAGE: &str = "PANIC: Failed to deserialize bad database data in contract analysis.";
const SERIALIZE_FAIL_MESSAGE: &str = "PANIC: Failed to deserialize bad database data in contract analysis.";

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ContractAnalysis {
    // matt: is okay to let these new fields end up in the db?
    // #[serde(skip)]
    pub private_function_types: BTreeMap<String, FunctionType>,
    pub variable_types: BTreeMap<String, TypeSignature>,
    pub public_function_types: BTreeMap<String, FunctionType>,
    pub read_only_function_types: BTreeMap<String, FunctionType>,
    pub map_types: BTreeMap<String, (TypeSignature, TypeSignature)>,
    pub persisted_variable_types: BTreeMap<String, TypeSignature>,
}

impl ContractAnalysis {
    pub fn new() -> ContractAnalysis {
        ContractAnalysis {
            private_function_types: BTreeMap::new(),
            public_function_types: BTreeMap::new(),
            read_only_function_types: BTreeMap::new(),
            variable_types: BTreeMap::new(),
            map_types: BTreeMap::new(),
            persisted_variable_types: BTreeMap::new(),
        }
    }

    pub fn add_map_type(&mut self, name: &str, key_type: &TypeSignature, map_type: &TypeSignature) {
        self.map_types.insert(name.to_string(), (key_type.clone(),
                                                 map_type.clone()));
    }
    
    pub fn add_variable_type(&mut self, name: &str, variable_type: &TypeSignature) {
        self.variable_types.insert(name.to_string(), variable_type.clone());
    }
    
    pub fn add_persisted_variable_type(&mut self, name: &str, persisted_variable_type: &TypeSignature) {
        self.persisted_variable_types.insert(name.to_string(), persisted_variable_type.clone());
    }

    pub fn add_read_only_function(&mut self, name: &str, function_type: &FunctionType) {
        self.read_only_function_types.insert(name.to_string(), function_type.clone());
    }

    pub fn add_public_function(&mut self, name: &str, function_type: &FunctionType) {
        self.public_function_types.insert(name.to_string(), function_type.clone());
    }

    pub fn add_private_function(&mut self, name: &str, function_type: &FunctionType) {
        self.private_function_types.insert(name.to_string(), function_type.clone());
    }

    pub fn get_public_function_type(&self, name: &str) -> Option<&FunctionType> {
        self.public_function_types.get(name)
    }

    pub fn get_read_only_function_type(&self, name: &str) -> Option<&FunctionType> {
        self.read_only_function_types.get(name)
    }

    pub fn get_private_function(&self, name: &str) -> Option<&FunctionType> {
        self.private_function_types.get(name)
    }

    pub fn get_map_type(&self, name: &str) -> Option<&(TypeSignature, TypeSignature)> {
        self.map_types.get(name)
    }

    pub fn get_variable_type(&self, name: &str) -> Option<&TypeSignature> {
        self.variable_types.get(name)
    }

    pub fn get_persisted_variable_type(&self, name: &str) -> Option<&TypeSignature> {
        self.persisted_variable_types.get(name)
    }

    pub fn deserialize(json: &str) -> ContractAnalysis {
        serde_json::from_str(json)
            .expect(DESERIALIZE_FAIL_MESSAGE)
    }

    pub fn serialize(&self) -> String {
        serde_json::to_string(self)
            .expect(SERIALIZE_FAIL_MESSAGE)
    }
}