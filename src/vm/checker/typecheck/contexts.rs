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
    public_function_types: BTreeMap<String, FunctionType>
}

pub struct TypingContext <'a> {
    pub variable_types: HashMap<String, TypeSignature>,
    pub parent: Option<&'a TypingContext<'a>>,
    pub depth: u16
}

pub struct ContractContext {
    pub map_types: HashMap<String, (TypeSignature, TypeSignature)>,
    pub variable_types: HashMap<String, TypeSignature>,
    pub function_types: HashMap<String, FunctionType>,
    pub public_function_types: HashMap<String, FunctionType>,
}


impl ContractAnalysis {
    pub fn new() -> ContractAnalysis {
        ContractAnalysis {
            public_function_types: BTreeMap::new()
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

    pub fn add_public_function(&mut self, name: &str, function_type: &FunctionType) {
        self.public_function_types.insert(name.to_string(), function_type.clone());
    }

    pub fn get_public_function_type(&self, name: &str) -> Option<&FunctionType> {
        self.public_function_types.get(name)
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
            function_types: HashMap::new(),
            public_function_types: HashMap::new(),
            map_types: HashMap::new(),
        }
    }
    pub fn get_map_type(&self, map_name: &str) -> Option<&(TypeSignature, TypeSignature)> {
        self.map_types.get(map_name)
    }

    pub fn get_variable_type(&self, name: &str) -> Option<&TypeSignature> {
        self.variable_types.get(name)
    }

    pub fn get_function_type(&self, name: &str) -> Option<&FunctionType> {
        match self.public_function_types.get(name) {
            Some(f_type) => Some(f_type),
            None => self.function_types.get(name)
        }
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
