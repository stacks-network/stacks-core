use std::collections::{HashMap, BTreeMap};
use vm::representations::{SymbolicExpression};
use vm::types::{TypeSignature};

use vm::contexts::MAX_CONTEXT_DEPTH;

use vm::checker::errors::{CheckResult, CheckError, CheckErrors};
use vm::checker::typecheck::{FunctionType};

const DESERIALIZE_FAIL_MESSAGE: &str = "PANIC: Failed to deserialize bad database data in contract analysis.";
const SERIALIZE_FAIL_MESSAGE: &str = "PANIC: Failed to deserialize bad database data in contract analysis.";

pub struct TypeMap {
    map: HashMap<u64, TypeSignature>
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ContractAnalysis {
    // matt: is okay to let these new fields end up in the db?
    // #[serde(skip)]
    private_function_types: BTreeMap<String, FunctionType>,
    variable_types: BTreeMap<String, TypeSignature>,
    public_function_types: BTreeMap<String, FunctionType>,
    read_only_function_types: BTreeMap<String, FunctionType>,
    map_types: BTreeMap<String, (TypeSignature, TypeSignature)>,
    persisted_variable_types: BTreeMap<String, TypeSignature>,
}

pub struct TypingContext <'a> {
    pub variable_types: HashMap<String, TypeSignature>,
    pub parent: Option<&'a TypingContext<'a>>,
    pub depth: u16
}

pub struct ContractContext {
    map_types: HashMap<String, (TypeSignature, TypeSignature)>,
    variable_types: HashMap<String, TypeSignature>,
    private_function_types: HashMap<String, FunctionType>,
    public_function_types: HashMap<String, FunctionType>,
    read_only_function_types: HashMap<String, FunctionType>,
    persisted_variable_types: HashMap<String, TypeSignature>,
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

    pub fn deserialize(json: &str) -> ContractAnalysis {
        serde_json::from_str(json)
            .expect(DESERIALIZE_FAIL_MESSAGE)
    }

    pub fn serialize(&self) -> String {
        serde_json::to_string(self)
            .expect(SERIALIZE_FAIL_MESSAGE)
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
}

impl TypeMap {
    pub fn new() -> TypeMap {
        TypeMap { map: HashMap::new() }
    }

    pub fn set_type(&mut self, expr: &SymbolicExpression, type_sig: TypeSignature) -> CheckResult<()> {
        if self.map.insert(expr.id, type_sig).is_some() {
            Err(CheckError::new(CheckErrors::TypeAlreadyAnnotatedFailure))
        } else {
            Ok(())
        }
    }

    pub fn get_type(&self, expr: &SymbolicExpression) -> CheckResult<&TypeSignature> {
        self.map.get(&expr.id)
            .ok_or(CheckError::new(CheckErrors::TypeNotAnnotatedFailure))
    }
}

impl ContractContext {
    pub fn new() -> ContractContext {
        ContractContext {
            variable_types: HashMap::new(),
            private_function_types: HashMap::new(),
            public_function_types: HashMap::new(),
            read_only_function_types: HashMap::new(),
            map_types: HashMap::new(),
            persisted_variable_types: HashMap::new(),
        }
    }

    pub fn check_name_used(&self, name: &str) -> CheckResult<()> {
        if self.variable_types.contains_key(name) ||
            self.persisted_variable_types.contains_key(name) ||
            self.private_function_types.contains_key(name) ||
            self.public_function_types.contains_key(name) ||
            self.map_types.contains_key(name) {
                Err(CheckError::new(CheckErrors::NameAlreadyUsed(name.to_string())))
            } else {
                Ok(())
            }
    }

    fn check_function_type(&mut self, f_name: &str) -> CheckResult<()> {
        self.check_name_used(f_name)?;
        Ok(())
    }

    pub fn add_public_function_type(&mut self, name: String, func_type: FunctionType) -> CheckResult<()> {
        self.check_function_type(&name)?;
        self.public_function_types.insert(name, func_type);
        Ok(())
    }

    pub fn add_read_only_function_type(&mut self, name: String, func_type: FunctionType) -> CheckResult<()> {
        self.check_function_type(&name)?;
        self.read_only_function_types.insert(name, func_type);
        Ok(())
    }

    pub fn add_private_function_type(&mut self, name: String, func_type: FunctionType) -> CheckResult<()> {
        self.check_function_type(&name)?;
        self.private_function_types.insert(name, func_type);
        Ok(())
    }

    pub fn add_map_type(&mut self, map_name: String, map_type: (TypeSignature, TypeSignature)) -> CheckResult<()> {
        self.check_name_used(&map_name)?;
        self.map_types.insert(map_name, map_type);
        Ok(())
    }

    pub fn add_variable_type(&mut self, const_name: String, var_type: TypeSignature) -> CheckResult<()> {
        self.check_name_used(&const_name)?;
        self.variable_types.insert(const_name, var_type);
        Ok(())
    }

    pub fn add_persisted_variable_type(&mut self, var_name: String, var_type: TypeSignature) -> CheckResult<()> {
        self.check_name_used(&var_name)?;
        self.persisted_variable_types.insert(var_name, var_type);
        Ok(())
    }

    pub fn get_map_type(&self, map_name: &str) -> Option<&(TypeSignature, TypeSignature)> {
        self.map_types.get(map_name)
    }

    pub fn get_variable_type(&self, name: &str) -> Option<&TypeSignature> {
        self.variable_types.get(name)
    }

    pub fn get_persisted_variable_type(&self, name: &str) -> Option<&TypeSignature> {
        self.persisted_variable_types.get(name)
    }

    pub fn get_function_type(&self, name: &str) -> Option<&FunctionType> {
        if let Some(f_type) = self.public_function_types.get(name) {
            Some(f_type)
        } else if let Some(f_type) =  self.private_function_types.get(name){
            Some(f_type)
        } else {
            self.read_only_function_types.get(name)
        }
    }

    pub fn to_contract_analysis(&self) -> ContractAnalysis {
        let mut contract_analysis = ContractAnalysis::new();

        for (name, function_type) in self.public_function_types.iter() {
            contract_analysis.add_public_function(name, function_type);
        }

        for (name, function_type) in self.read_only_function_types.iter() {
            contract_analysis.add_read_only_function(name, function_type);
        }

        for (name, (key_type, map_type)) in self.map_types.iter() {
            contract_analysis.add_map_type(name, key_type, map_type);
        }

        for (name, function_type) in self.private_function_types.iter() {
            contract_analysis.add_private_function(name, function_type);
        }

        for (name, variable_type) in self.variable_types.iter() {
            contract_analysis.add_variable_type(name, variable_type);
        }

        for (name, persisted_variable_type) in self.persisted_variable_types.iter() {
            contract_analysis.add_persisted_variable_type(name, persisted_variable_type);
        }

        contract_analysis
    }
}

impl <'a> TypingContext <'a> {
    pub fn new() -> TypingContext<'static> {
        TypingContext {
            variable_types: HashMap::new(),
            depth: 0,
            parent: None
        }
    }

    pub fn extend<'b>(&'b self) -> CheckResult<TypingContext<'b>> {
        if self.depth >= MAX_CONTEXT_DEPTH {
            Err(CheckError::new(CheckErrors::MaxContextDepthReached))
        } else {
            Ok(TypingContext {
                variable_types: HashMap::new(),
                parent: Some(self),
                depth: self.depth + 1
            })
        }
    }

    pub fn lookup_variable_type(&self, name: &str) -> Option<&TypeSignature> {
        match self.variable_types.get(name) {
            Some(value) => Some(value),
            None => {
                match self.parent {
                    Some(parent) => parent.lookup_variable_type(name),
                    None => None
                }
            }
        }
    }
}
