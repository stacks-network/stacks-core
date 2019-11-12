use std::collections::{BTreeMap, BTreeSet};
use vm::{SymbolicExpression, ClarityName};
use vm::types::{TypeSignature, FunctionType, QualifiedContractIdentifier};
use vm::analysis::analysis_db::{AnalysisDatabase};
use vm::analysis::errors::{CheckResult};
use vm::analysis::type_checker::contexts::TypeMap;
use vm::analysis::cost_counter::{ContractCostAnalysis, ExecutionCost};

const DESERIALIZE_FAIL_MESSAGE: &str = "PANIC: Failed to deserialize bad database data in contract analysis.";
const SERIALIZE_FAIL_MESSAGE: &str = "PANIC: Failed to deserialize bad database data in contract analysis.";

pub trait AnalysisPass {
    fn run_pass(contract_analysis: &mut ContractAnalysis, analysis_db: &mut AnalysisDatabase) -> CheckResult<()>;
}

#[derive(Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ContractAnalysis {
    pub contract_identifier: QualifiedContractIdentifier,
    #[serde(skip)]
    pub type_map: Option<TypeMap>,
    // matt: is okay to let these new fields end up in the db?
    pub private_function_types: BTreeMap<ClarityName, FunctionType>,
    pub variable_types: BTreeMap<ClarityName, TypeSignature>,
    pub public_function_types: BTreeMap<ClarityName, FunctionType>,
    pub read_only_function_types: BTreeMap<ClarityName, FunctionType>,
    pub map_types: BTreeMap<ClarityName, (TypeSignature, TypeSignature)>,
    pub persisted_variable_types: BTreeMap<ClarityName, TypeSignature>,
    pub fungible_tokens: BTreeSet<ClarityName>,
    pub non_fungible_tokens: BTreeMap<ClarityName, TypeSignature>,
    pub cost_analysis: Option<ContractCostAnalysis>,
    pub instantiation_cost: Option<ExecutionCost>,
    #[serde(skip)]
    pub top_level_expression_sorting: Option<Vec<usize>>,
    #[serde(skip)]
    pub expressions: Vec<SymbolicExpression>,
}

impl ContractAnalysis {
    pub fn new(contract_identifier: QualifiedContractIdentifier, expressions: Vec<SymbolicExpression>) -> ContractAnalysis {
        ContractAnalysis {
            contract_identifier,
            expressions,
            type_map: None, cost_analysis: None, instantiation_cost: None,
            private_function_types: BTreeMap::new(),
            public_function_types: BTreeMap::new(),
            read_only_function_types: BTreeMap::new(),
            variable_types: BTreeMap::new(),
            map_types: BTreeMap::new(),
            persisted_variable_types: BTreeMap::new(),
            top_level_expression_sorting: Some(Vec::new()),
            fungible_tokens: BTreeSet::new(),
            non_fungible_tokens: BTreeMap::new()
        }
    }

    pub fn add_map_type(&mut self, name: ClarityName, key_type: TypeSignature, map_type: TypeSignature) {
        self.map_types.insert(name, (key_type, map_type));
    }
    
    pub fn add_variable_type(&mut self, name: ClarityName, variable_type: TypeSignature) {
        self.variable_types.insert(name, variable_type);
    }
    
    pub fn add_persisted_variable_type(&mut self, name: ClarityName, persisted_variable_type: TypeSignature) {
        self.persisted_variable_types.insert(name, persisted_variable_type);
    }

    pub fn add_read_only_function(&mut self, name: ClarityName, function_type: FunctionType) {
        self.read_only_function_types.insert(name, function_type);
    }

    pub fn add_public_function(&mut self, name: ClarityName, function_type: FunctionType) {
        self.public_function_types.insert(name, function_type);
    }

    pub fn add_private_function(&mut self, name: ClarityName, function_type: FunctionType) {
        self.private_function_types.insert(name, function_type);
    }

    pub fn add_non_fungible_token(&mut self, name: ClarityName, nft_type: TypeSignature) {
        self.non_fungible_tokens.insert(name, nft_type);
    }

    pub fn add_fungible_token(&mut self, name: ClarityName) {
        self.fungible_tokens.insert(name);
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
