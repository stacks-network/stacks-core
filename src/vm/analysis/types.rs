use std::collections::{BTreeMap, BTreeSet};
use vm::{SymbolicExpression};
use vm::types::{TypeSignature, FunctionType};
use vm::analysis::analysis_db::{AnalysisDatabase};
use vm::analysis::errors::{CheckResult};

const DESERIALIZE_FAIL_MESSAGE: &str = "PANIC: Failed to deserialize bad database data in contract analysis.";
const SERIALIZE_FAIL_MESSAGE: &str = "PANIC: Failed to deserialize bad database data in contract analysis.";

pub trait AnalysisPass {
    fn run_pass(contract_analysis: &mut ContractAnalysis, analysis_db: &mut AnalysisDatabase) -> CheckResult<()>;
}

#[derive(Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ContractAnalysis {
    // matt: is okay to let these new fields end up in the db?
    pub private_function_types: BTreeMap<String, FunctionType>,
    pub variable_types: BTreeMap<String, TypeSignature>,
    pub public_function_types: BTreeMap<String, FunctionType>,
    pub read_only_function_types: BTreeMap<String, FunctionType>,
    pub map_types: BTreeMap<String, (TypeSignature, TypeSignature)>,
    pub persisted_variable_types: BTreeMap<String, TypeSignature>,
    pub fungible_tokens: BTreeSet<String>,
    pub non_fungible_tokens: BTreeMap<String, TypeSignature>,
    #[serde(skip)]
    pub top_level_expression_sorting: Option<Vec<usize>>,
    #[serde(skip)]
    pub expressions: Vec<SymbolicExpression>,
}

impl ContractAnalysis {
    pub fn new(expressions: Vec<SymbolicExpression>) -> ContractAnalysis {
        ContractAnalysis {
            expressions: expressions,
            private_function_types: BTreeMap::new(),
            public_function_types: BTreeMap::new(),
            read_only_function_types: BTreeMap::new(),
            variable_types: BTreeMap::new(),
            map_types: BTreeMap::new(),
            persisted_variable_types: BTreeMap::new(),
            top_level_expression_sorting: Some(Vec::new()),
            tokens: BTreeSet::new(),
            assets: BTreeMap::new()
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

    pub fn expressions_iter(&self) -> ExpressionsIterator {
        let expressions = &self.expressions[..];
        let sorting = match self.top_level_expression_sorting {
            Some(ref exprs_ids) => Some(exprs_ids[..].to_vec()),
            None => None
        };

        ExpressionsIterator {
            expressions: expressions,
            sorting: sorting,
            index: 0,
        }
    }
}

pub struct ExpressionsIterator <'a> {
    expressions: &'a [SymbolicExpression],
    sorting: Option<Vec<usize>>,
    index: usize,
}

impl <'a> Iterator for ExpressionsIterator <'a> {
    type Item = &'a SymbolicExpression;

    fn next(&mut self) -> Option<&'a SymbolicExpression> {
        if self.index >= self.expressions.len() {
            return None;
        }
        let expr_index = match self.sorting {
            Some(ref indirections) => indirections[self.index],
            None => self.index
        };
        let result = &self.expressions[expr_index];
        self.index += 1;
        Some(result)
    }
}
