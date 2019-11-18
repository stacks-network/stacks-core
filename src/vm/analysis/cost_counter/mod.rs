pub mod constants; 
pub mod costs;
pub mod natives;
pub mod common_costs;

#[cfg(test)]
mod tests;

pub use self::costs::{CostOverflowingMath, ExecutionCost, CostFunctions, CostSpecification, SimpleCostSpecification};
use self::natives::{SpecialCostType};

use std::collections::{HashMap, BTreeMap};
use std::iter::FromIterator;

use vm::representations::{SymbolicExpression, SymbolicExpressionType, depth_traverse, ClarityName};
use vm::representations::SymbolicExpressionType::{AtomValue, Atom, List, LiteralValue};
use vm::types::{Value, PrincipalData, TypeSignature, TupleTypeSignature, FunctionArg, BUFF_32,
                FunctionType, FixedFunction, parse_name_type_pairs};
use vm::functions::{define::DefineFunctionsParsed, NativeFunctions};
use vm::variables::NativeVariables;
use vm::MAX_CONTEXT_DEPTH;

use super::type_checker::contexts::{TypeMap};

use super::AnalysisDatabase;
pub use super::types::{ContractAnalysis, AnalysisPass};

pub use super::errors::{CheckResult, CheckError, CheckErrors};

pub const TYPE_ANNOTATED_FAIL: &'static str = "Type should be annotated";

pub struct CostContext {
    context_depth: u64,
    defined_functions: HashMap<String, SimpleCostSpecification>,
}

pub struct CostCounter <'a, 'b> {
    pub type_map: &'a TypeMap,
    pub analysis: &'a ContractAnalysis,
    pub cost_context: CostContext,
    pub db: &'a mut AnalysisDatabase <'b>
}

#[derive(Debug, Deserialize, Serialize, PartialEq, Eq)]
pub struct ContractCostAnalysis {
    defined_functions: BTreeMap<String, SimpleCostSpecification>
}

impl ContractCostAnalysis {
    pub fn get_function_cost(&self, function_name: &str) -> Option<SimpleCostSpecification> {
        self.defined_functions.get(function_name).cloned()
    }
}

impl CostContext {
    fn new() -> CostContext {
        CostContext {
            context_depth: 0,
            defined_functions: HashMap::new(),
        }
    }

    fn increment_context_depth(&mut self) -> CheckResult<()> {
        if self.context_depth >= (MAX_CONTEXT_DEPTH as u64) {
            return Err(CheckErrors::MaxContextDepthReached.into());
        }
        self.context_depth = self.context_depth.checked_add(1)
            .expect("Unexpected context depth overflow.");
        Ok(())
    }

    fn decrement_context_depth(&mut self) {
        assert!(self.context_depth >= 1);
        self.context_depth -= 1;
    }

    fn get_defined_function_cost_spec(&self, function_name: &str) -> Option<&SimpleCostSpecification> {
        self.defined_functions.get(function_name)
    }
}

impl From<CostContext> for ContractCostAnalysis {
    fn from(mut ctxt: CostContext) -> ContractCostAnalysis {
        ContractCostAnalysis {
            defined_functions: BTreeMap::from_iter(ctxt.defined_functions.drain())
        }
    }
}

impl <'a, 'b> AnalysisPass for CostCounter <'a, 'b> {
    fn run_pass(contract_analysis: &mut ContractAnalysis, analysis_db: &mut AnalysisDatabase) -> CheckResult<()> {
        let (instantiation_cost, cost_analysis, size) = {
            let counter = CostCounter::new(analysis_db,
                                           contract_analysis.type_map.as_ref()
                                           .expect("Type mapping must have been set"),
                                           contract_analysis);
            counter.run()
        }?;

        contract_analysis.cost_analysis = Some(cost_analysis);
        contract_analysis.instantiation_cost = Some(instantiation_cost);
        contract_analysis.contract_size = Some(size);

        Ok(())
    }
}

impl <'a, 'b> CostCounter <'a, 'b> {
    fn new(db: &'a mut AnalysisDatabase<'b>, type_map: &'a TypeMap, analysis: &'a ContractAnalysis) -> CostCounter<'a, 'b> {
        Self {
            db, type_map, analysis,
            cost_context: CostContext::new()
        }
    }

    // Return the non-analysis cost of _instantiating_ the contract
    //  and the execution cost analysis 
    pub fn run(mut self) -> CheckResult<(ExecutionCost, ContractCostAnalysis, u64)> {
        let mut evaluation_cost = ExecutionCost::zero();
        for exp in self.analysis.expressions_iter() {
            evaluation_cost.add(&self.handle_top_level_expression(exp)?)?;
        }

        // add the cost of _storing_ the contract
        let mut contract_size = 0;
        for exp in self.analysis.expressions_iter() {
            contract_size = contract_size.cost_overflow_add(
                common_costs::get_expression_size(exp)?)?;
        }

        evaluation_cost.add(&common_costs::contract_storage_cost(contract_size)?)?;

        let contract_cost_analysis = ContractCostAnalysis::from(self.cost_context);

        Ok((evaluation_cost, contract_cost_analysis, contract_size))
    }

    // Handle a top level expression,
    //    if defining a function, add that function to the cost context.
    //    otherwise, return the execution cost of instantiating the contract context (i.e., evaluating 
    //      plain expressions, constants, persisted variables).
    fn handle_top_level_expression(&mut self, expression: &SymbolicExpression) -> CheckResult<ExecutionCost> {
        let define_type = match DefineFunctionsParsed::try_parse(expression)? {
            Some(define_type) => define_type,
            // not a define statement, but just a normal expression. return the execution cost of that expression.
            None => return self.handle_expression(expression)
        };
        let execution_cost = match define_type {
            DefineFunctionsParsed::Constant { name, value } => {
                let mut evaluation_cost = self.handle_expression(value)?;
                evaluation_cost.add(&common_costs::get_binding_cost(name)?)?;
                evaluation_cost
            },
            DefineFunctionsParsed::PrivateFunction { signature, body } |
            DefineFunctionsParsed::PublicFunction { signature, body } |
            DefineFunctionsParsed::ReadOnlyFunction { signature, body } => {
                let evaluation_cost = common_costs::parse_signature_cost(signature)?;
                let execution_cost = self.handle_expression(body)?;

                let function_name = signature[0].match_atom().expect("Function signature should be name");
                self.cost_context.defined_functions.insert(function_name.clone().into(),
                                                           SimpleCostSpecification::from(execution_cost));
                evaluation_cost
            },
            DefineFunctionsParsed::NonFungibleToken { name, nft_type } => {
                let mut evaluation_cost = common_costs::get_binding_cost(name)?;
                let compute_type_cost = common_costs::parse_type_cost(nft_type)?;
                evaluation_cost.add(&compute_type_cost)?;
                evaluation_cost
            }
            DefineFunctionsParsed::BoundedFungibleToken { name, max_supply } => {
                let mut evaluation_cost = common_costs::get_binding_cost(name)?;
                let compute_supply_cost = self.handle_expression(max_supply)?;
                evaluation_cost.add(&compute_supply_cost)?;
                evaluation_cost
            },
            DefineFunctionsParsed::UnboundedFungibleToken { name } => {
                common_costs::get_binding_cost(name)?
            },
            DefineFunctionsParsed::Map { name, key_type, value_type } => {
                let mut evaluation_cost = common_costs::get_binding_cost(name)?;
                let key_cost = common_costs::parse_type_cost(key_type)?;
                let value_cost = common_costs::parse_type_cost(value_type)?;
                evaluation_cost.add(&key_cost)?;
                evaluation_cost.add(&value_cost)?;
                evaluation_cost
            },
            DefineFunctionsParsed::PersistedVariable  { name, data_type, initial } => {
                let mut evaluation_cost = common_costs::get_binding_cost(name)?;
                let type_cost = common_costs::parse_type_cost(data_type)?;
                let initial_eval_cost = self.handle_expression(initial)?;
                evaluation_cost.add(&type_cost)?;
                evaluation_cost.add(&initial_eval_cost)?;
                evaluation_cost
            }
        };
        Ok(execution_cost)
    }

    fn handle_special_function(&mut self, function: &SpecialCostType, args: &[SymbolicExpression])
                               -> CheckResult<ExecutionCost> {
        natives::handle_special_function(self, function, args)
    }

    fn handle_variable_lookup(&mut self, variable_name: &str) -> CheckResult<ExecutionCost> {
        match get_reserved_name_cost(variable_name) {
            Some(mut reserved_name_cost) => {
                reserved_name_cost.add_runtime(variable_name.len() as u64)?;
                Ok(reserved_name_cost)
            },
            None => {
                common_costs::get_variable_lookup_cost(variable_name, self.cost_context.context_depth)
            }
        }
    }

    fn handle_simple_function_args(&mut self, args: &[SymbolicExpression]) -> CheckResult<u64> {
        let argument_cost = self.handle_all_expressions(args)?;
        let mut argument_len = 0;
        for arg in args {
            let arg_type = self.type_map.get_type(arg)
                .expect(&format!("{}: {}", TYPE_ANNOTATED_FAIL, arg));
            argument_len = u64::from(arg_type.size()).cost_overflow_add(argument_len)?;
        }

        Ok(argument_len)
    }

    fn handle_function_application(&mut self, function_name: &str, args: &[SymbolicExpression]) -> CheckResult<ExecutionCost> {
        if let Some(native_function) = NativeFunctions::lookup_by_name(function_name) {
            match natives::get_native_function_cost_spec(&native_function) {
                CostSpecification::Special(cost_type) => self.handle_special_function(&cost_type, args),
                CostSpecification::Simple(cost_type) => {
                    let arguments_size = self.handle_simple_function_args(args)?;
                    cost_type.compute_cost(arguments_size)
                }
            }
        } else {
            // not a native function, so try to find in context
            let arguments_size = self.handle_simple_function_args(args)?;
            let simple_cost_spec = self.cost_context.get_defined_function_cost_spec(function_name)
                .ok_or_else(|| CheckErrors::UnknownFunction(function_name.to_string()))?;
            simple_cost_spec.compute_cost(arguments_size)
        }
    }

    fn handle_all_expressions(&mut self, exprs: &[SymbolicExpression]) -> CheckResult<ExecutionCost> {
        let mut total_cost = ExecutionCost::zero();
        for expr in exprs {
            let cost = self.handle_expression(expr)?;
            total_cost.add(&cost)?;
        }
        Ok(total_cost)
    }

    fn handle_expression(&mut self, expr: &SymbolicExpression) -> CheckResult<ExecutionCost> {
        match expr.expr {
            AtomValue(ref value) | LiteralValue(ref value) => Ok(ExecutionCost::runtime(value.size() as u64)),
            Atom(ref variable_name) => self.handle_variable_lookup(variable_name),
            List(ref children) => {
                let (function_expr, args) = children.split_first().expect("Bad function application");
                let function_name = function_expr.match_atom()
                    .expect(&format!("Bad function name: {}", function_expr));
                self.handle_function_application(&function_name, args)
            }
        }
    }
}

pub fn get_reserved_name_cost(name: &str) -> Option<ExecutionCost> {
    match NativeVariables::lookup_by_name(name) {
        Some(NativeVariables::TxSender) | Some(NativeVariables::ContractCaller) => {
            // cost of cloning the principal
            Some(ExecutionCost::runtime(constants::RESERVED_VAR_PRINCIPAL_COST))
        },
        Some(NativeVariables::BurnBlockHeight) | Some(NativeVariables::BlockHeight) => {
            // cost of looking up and cloning the block height
            Some(ExecutionCost {
                runtime: constants::BLOCK_HEIGHT_LOOKUP_COST,
                read_count: 1, read_length: BUFF_32.size() as u64,
                write_length: 0, write_count: 0 })
        },
        Some(NativeVariables::NativeNone) => {
            // cost of cloning a none type
            Some(ExecutionCost::runtime(constants::RESERVED_VAR_NONE_COST))
        },
        None => None,
    }
}

