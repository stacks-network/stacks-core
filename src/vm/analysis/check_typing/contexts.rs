use std::collections::{HashMap, BTreeMap, HashSet};
use vm::representations::{SymbolicExpression};
use vm::types::{TypeSignature, FunctionType};

use vm::contexts::MAX_CONTEXT_DEPTH;

use vm::analysis::errors::{CheckResult, CheckError, CheckErrors};
use vm::analysis::types::{ContractAnalysis};

pub struct TypeMap {
    map: HashMap<u64, TypeSignature>
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
    tokens: HashSet<String>,
    assets: HashMap<String, TypeSignature>
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
            tokens: HashSet::new(),
            assets: HashMap::new(),
        }
    }

    pub fn check_name_used(&self, name: &str) -> CheckResult<()> {
        if self.variable_types.contains_key(name) ||
            self.persisted_variable_types.contains_key(name) ||
            self.private_function_types.contains_key(name) ||
            self.public_function_types.contains_key(name) ||
            self.tokens.contains(name) ||
            self.assets.contains_key(name) ||
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

    pub fn token_exists(&self, name: &str) -> bool {
        self.tokens.contains(name)
    }

    pub fn get_asset_type(&self, name: &str) -> Option<&TypeSignature> {
        self.assets.get(name)
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

    pub fn add_token(&mut self, token_name: String) -> CheckResult<()> {
        self.check_name_used(&token_name)?;
        self.tokens.insert(token_name);
        Ok(())
    }

    pub fn add_asset(&mut self, asset_name: String, asset_type: TypeSignature) -> CheckResult<()> {
        self.check_name_used(&asset_name)?;
        self.assets.insert(asset_name, asset_type);
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

    pub fn update_contract_analysis(&self, contract_analysis: &mut ContractAnalysis) {

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
