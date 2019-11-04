use std::collections::{HashMap, BTreeMap};
use vm::representations::{SymbolicExpression, ClarityName};
use vm::representations::SymbolicExpressionType::{AtomValue, Atom, List, LiteralValue};
use vm::types::{Value, PrincipalData, TypeSignature, TupleTypeSignature, FunctionArg, BUFF_32,
                FunctionType, FixedFunction, parse_name_type_pairs};
use vm::functions::{NativeFunctions, handle_binding_list};
use vm::functions::define::DefineFunctionsParsed;
use vm::variables::NativeVariables;
use vm::MAX_CONTEXT_DEPTH;

pub mod constants; 

use super::type_checker::contexts::{TypeMap};

use super::AnalysisDatabase;
pub use super::types::{ContractAnalysis, AnalysisPass};

pub use super::errors::{CheckResult, CheckError, CheckErrors};

pub const TYPE_ANNOTATED_FAIL: &'static str = "Type should be annotated";

pub enum CostSpecification {
    Simple(SimpleCostSpecification),
    Special(SpecialCostType),
}

pub enum SpecialCostType { ContractCall, If, Map, Filter, 
                           Fold, Let, TupleCons, TupleGet,
                           // these are special because the runtime cost is
                           //   associated with the _stored type_, not the arguments.
                           FetchVar, FetchEntry, FetchContractEntry,
                           // these are special because they only should measure
                           //   one of their arguments
                           SetVar, SetEntry, InsertEntry, DeleteEntry,
                           MintAsset, TransferAsset, GetAssetOwner
}

#[derive(Debug, Deserialize, Serialize, Clone)]
pub enum CostFunctions {
    Constant(u64),
    Linear(u64, u64),
    NLogN(u64, u64),
}

#[derive(Debug, Deserialize, Serialize, Clone)]
pub struct SimpleCostSpecification {
    write_count: CostFunctions,
    write_length: CostFunctions,
    read_count: CostFunctions,
    read_length: CostFunctions,
    runtime: CostFunctions,
}

pub struct ExecutionCost {
    write_length: u64,
    write_count: u64,
    read_length: u64,
    read_count: u64,
    runtime: u64
}

pub struct CostContext {
    context_depth: u64,
    defined_functions: HashMap<String, SimpleCostSpecification>,
}

pub struct CostCounter <'a, 'b> {
    type_map: TypeMap,
    analysis: &'a ContractAnalysis,
    cost_context: CostContext,
    db: &'a mut AnalysisDatabase <'b>
}

#[derive(Debug, Deserialize, Serialize)]
pub struct ContractCostAnalysis {
    defined_functions: BTreeMap<String, SimpleCostSpecification>
}

trait CostOverflowingMath <T> {
    fn cost_overflow_mul(self, other: T) -> CheckResult<T>;
    fn cost_overflow_add(self, other: T) -> CheckResult<T>;
}

impl CostOverflowingMath <u64> for u64 {
    fn cost_overflow_mul(self, other: u64) -> CheckResult<u64> {
        self.checked_mul(other)
            .ok_or_else(|| CheckErrors::CostOverflow.into())
    }
    fn cost_overflow_add(self, other: u64) -> CheckResult<u64> {
        self.checked_add(other)
            .ok_or_else(|| CheckErrors::CostOverflow.into())
    }
}

impl ContractCostAnalysis {
    pub fn get_function_cost(&self, function_name: &str) -> Option<SimpleCostSpecification> {
        self.defined_functions.get(function_name).cloned()
    }
}

// ONLY WORKS IF INPUT IS u64
fn int_log2(input: u64) -> u64 {
    (64 - input.leading_zeros()).into()
}

impl CostFunctions {
    pub fn compute_cost(&self, input: u64) -> CheckResult<u64> {
        match self {
            CostFunctions::Constant(val) => Ok(*val),
            CostFunctions::Linear(a, b) => { a.cost_overflow_mul(input)?
                                             .cost_overflow_add(*b) }
            CostFunctions::NLogN(a, b) => {
                if input == 0 {
                    return Err(CheckErrors::CostOverflow.into());
                }
                // a*input*log(input)) + b
                int_log2(input)
                    .cost_overflow_mul(input)?
                    .cost_overflow_mul(*a)?
                    .cost_overflow_add(*b)
            }
        }
    }
}

impl SimpleCostSpecification {
    pub fn new_diskless(runtime: CostFunctions) -> SimpleCostSpecification {
        SimpleCostSpecification {
            write_length: CostFunctions::Constant(0),
            write_count: CostFunctions::Constant(0),
            read_count: CostFunctions::Constant(0),
            read_length: CostFunctions::Constant(0),
            runtime
        }
    }

    pub fn compute_cost(&self, input: u64) -> CheckResult<ExecutionCost> {
        Ok(ExecutionCost {
            write_length: self.write_length.compute_cost(input)?,
            write_count:  self.write_count.compute_cost(input)?,
            read_count:   self.read_count.compute_cost(input)?,
            read_length:  self.read_length.compute_cost(input)?,
            runtime:      self.runtime.compute_cost(input)?
        })
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

impl ExecutionCost {
    fn zero() -> ExecutionCost {
        Self { runtime: 0, write_length: 0, read_count: 0, write_count: 0, read_length: 0 }
    }

    fn runtime(runtime: u64) -> ExecutionCost {
        Self { runtime, write_length: 0, read_count: 0, write_count: 0, read_length: 0 }
    }

    fn add_runtime(&mut self, runtime: u64) -> CheckResult<()> {
        self.runtime = self.runtime.cost_overflow_add(runtime)?;
        Ok(())
    }

    fn add(&mut self, other: &ExecutionCost) -> CheckResult<()> {
        self.runtime = self.runtime.cost_overflow_add(other.runtime)?;
        self.read_count   = self.read_count.cost_overflow_add(other.read_count)?;
        self.read_length  = self.read_length.cost_overflow_add(other.read_length)?;
        self.write_length = self.write_length.cost_overflow_add(other.write_length)?;
        self.write_count  = self.write_count.cost_overflow_add(other.write_count)?;
        Ok(())
    }

    fn multiply(&mut self, times: u64) -> CheckResult<()> {
        self.runtime = self.runtime.cost_overflow_mul(times)?;
        self.read_count   = self.read_count.cost_overflow_mul(times)?;
        self.read_length  = self.read_length.cost_overflow_mul(times)?;
        self.write_length = self.write_length.cost_overflow_mul(times)?;
        self.write_count  = self.write_count.cost_overflow_mul(times)?;
        Ok(())
    }

    fn max_cost(first: ExecutionCost, second: ExecutionCost) -> ExecutionCost {
        Self {
            runtime: first.runtime.max(second.runtime),
            write_length: first.write_length.max(second.write_length),
            write_count:  first.write_count.max(second.write_count),
            read_count:   first.read_count.max(second.read_count),
            read_length:  first.read_length.max(second.read_length)
        }
    }
}

fn parse_signature_cost(signature: &[SymbolicExpression]) -> ExecutionCost {
    panic!("Not implemented");
}

impl <'a, 'b> CostCounter <'a, 'b> {
    fn new(db: &'a mut AnalysisDatabase<'b>, type_map: TypeMap, analysis: &'a ContractAnalysis) -> CostCounter<'a, 'b> {
        Self {
            db, type_map, analysis,
            cost_context: CostContext::new()
        }
    }

    // Handle a top level expression,
    //    if defining a function, add that function to the cost context.
    //    otherwise, return the execution of instantiating the contract context (i.e., evaluating 
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
                evaluation_cost.add_runtime(name.len() as u64)?;
                evaluation_cost
            },
            DefineFunctionsParsed::PrivateFunction { signature, body } => {
                let signature_parsing_cost = parse_signature_cost(signature);
                let mut evaluation_cost = self.handle_expression(body)?;
                evaluation_cost.add(&signature_parsing_cost)?;
                evaluation_cost
            },
            _ => {
                panic!("Not implemented")
            }
        };
        Ok(execution_cost)
    }

    fn handle_variable_lookup(&mut self, variable_name: &str) -> CheckResult<ExecutionCost> {
        match get_reserved_name_cost(variable_name) {
            Some(mut reserved_name_cost) => {
                reserved_name_cost.add_runtime(variable_name.len() as u64)?;
                Ok(reserved_name_cost)
            },
            None => {
                let mut lookup_cost = ExecutionCost::runtime(variable_name.len() as u64);
                lookup_cost.multiply(self.cost_context.context_depth)?;
                Ok(lookup_cost)
            }
        }
    }

    fn handle_special_function(&mut self, function: &SpecialCostType, args: &[SymbolicExpression]) -> CheckResult<ExecutionCost> {
        use self::CostFunctions::{Constant, Linear};
        use self::SpecialCostType::*;
        match function {
            // assert argument lengths, because this pass _must_ have occurred _after_
            //   other checks.
            ContractCall => {
                assert!(args.len() >= 2);

                let contract_id = match args[0].match_literal_value() {
                    Some(Value::Principal(PrincipalData::Contract(ref contract_id))) => contract_id,
                    _ => return Err(CheckErrors::ContractCallExpectName.into())
                };
                let function_name = args[1].match_atom().expect("Function argument should have been atom.");
                let cost_spec = self.db.get_contract_function_cost(&contract_id, function_name)
                    .expect("Public function should exist");
                // BASE COST:
                //   RUNTIME = linear cost of hashing function_name + some constant
                //   READS = 1
                let mut total_cost = ExecutionCost {
                    write_length: 0, write_count: 0, read_count: 1,
                    read_length: self.db.get_contract_size(&contract_id).expect("Contract should exist"),
                    runtime: 1+(function_name.len() as u64) };
                let arg_size = self.handle_simple_function_args(&args[2..])?;
                let exec_cost = cost_spec.compute_cost(arg_size)?;

                total_cost.add(&exec_cost)?;

                Ok(total_cost)
            },
            If => {
                assert_eq!(args.len(), 3);

                let mut conditional_cost = self.handle_expression(&args[0])?;
                let branch_1_cost = self.handle_expression(&args[1])?;
                let branch_2_cost = self.handle_expression(&args[2])?;

                conditional_cost.add(&ExecutionCost::max_cost(branch_1_cost, branch_2_cost))?;

                Ok(conditional_cost)
            },
            Map | Filter => {
                assert_eq!(args.len(), 2);

                let function_name = args[0].match_atom()
                    .expect("Function argument should have been atom.");
                let list_arg_type = match self.type_map.get_type(&args[1]) {
                    Some(TypeSignature::ListType(l)) => l,
                    x => panic!("Expected list type, but annotated type was: {:#?}", x)
                };
                let list_item_type = list_arg_type.get_list_item_type();
                let list_max_len = list_arg_type.get_max_len();

                let function_spec = self.cost_context.get_defined_function_cost_spec(function_name)
                    .ok_or_else(|| CheckErrors::UnknownFunction(function_name.to_string()))?;
                let mut single_execution_cost = function_spec.compute_cost(list_item_type.size().into())?;

                single_execution_cost.multiply(list_max_len.into())?;

                // base cost: looking up function name in context.
                //   O(1) + O(function_name)
                single_execution_cost.add(&get_function_lookup_cost(function_name)?)?;

                Ok(single_execution_cost)
            },
            Fold => {
                assert_eq!(args.len(), 3);

                let function_name = args[0].match_atom()
                    .expect("Function argument should have been atom.");
                let list_arg_type = match self.type_map.get_type(&args[1]) {
                    Some(TypeSignature::ListType(l)) => l,
                    x => panic!("Expected list type, but annotated type was: {:#?}", x)
                };
                let initial_value_type = self.type_map.get_type(&args[2])
                    .expect("Expected a type annotation");

                let list_item_type = list_arg_type.get_list_item_type();
                let list_max_len = list_arg_type.get_max_len();

                let function_spec = self.cost_context.get_defined_function_cost_spec(function_name)
                    .ok_or_else(|| CheckErrors::UnknownFunction(function_name.to_string()))?;

                let function_arg_len = u64::from(list_item_type.size())
                    .cost_overflow_add(u64::from(initial_value_type.size()))?;

                let mut single_execution_cost = function_spec.compute_cost(function_arg_len)?;

                single_execution_cost.multiply(list_max_len.into())?;

                // base cost: looking up function name in context.
                //   O(1) + O(function_name)
                single_execution_cost.add(&get_function_lookup_cost(function_name)?)?;

                Ok(single_execution_cost)

            },
            Let => {
                assert!(args.len() >= 2);

                let bindings = args[0].match_list()
                    .expect("Let expression must be supplied a binding list.");

                let mut binding_cost = ExecutionCost::runtime(constants::LET_CONSTANT_COST);

                handle_binding_list(bindings, |var_name, var_sexp| {
                    // the cost of binding the name.
                    binding_cost.add(&get_binding_cost(var_name)?)?;

                    // the cost of calculating the bound value
                    binding_cost.add(
                        &self.handle_expression(var_sexp)?)
                })?;

                // evaluation of let bodies occur at context depth + 1.
                self.cost_context.increment_context_depth()?;

                binding_cost.add(
                    &self.handle_all_expressions(&args[1..])?)?;

                self.cost_context.decrement_context_depth();

                Ok(binding_cost)
            },
            TupleCons => {
                assert!(args.len() >= 1);

                let mut binding_cost = ExecutionCost::runtime(constants::TUPLE_CONS_CONSTANT_COST);
                handle_binding_list(args, |var_name, var_sexp| {
                    // the cost of binding the name.
                    binding_cost.add(&get_binding_cost(var_name)?)?;

                    // the cost of calculating the bound value
                    binding_cost.add(
                        &self.handle_expression(var_sexp)?)
                })?;

                Ok(binding_cost)
            },
            TupleGet => {
                assert!(args.len() == 2);

                let tuple_length = match self.type_map.get_type(&args[1]).expect(TYPE_ANNOTATED_FAIL) {
                    TypeSignature::TupleType(tuple_data) => tuple_data.len(),
                    _ => panic!("Expected tuple type")
                };

                let var_name = args[0].match_atom().expect("Tuple get should be atom name.");

                // the cost of a lookup
                let mut lookup_cost = SimpleCostSpecification::new_diskless(CostFunctions::NLogN(1, 1))
                    .compute_cost(tuple_length)?;
                // you always do a O(n) equality check on names in lookups.
                lookup_cost.add_runtime(var_name.len() as u64)?;

                Ok(lookup_cost)
            },
            FetchEntry => {
                assert!(args.len() == 2);
                let map_name = args[0].match_atom().expect("Argument should be atomic name.");
                let key_tuple = &args[1];

                let key_tuple_size = u64::from(self.type_map.get_type(key_tuple)
                                               .expect(TYPE_ANNOTATED_FAIL)
                                               .size());
                // the cost of the hash lookup...
                let mut hash_cost = get_hash_cost(map_name.len() as u64, key_tuple_size)?;

                // the cost of the database read...
                let value_tuple_size = u64::from(self.analysis.get_map_type(map_name)
                                                 .expect("Map should exist")
                                                 .1.size());
                let read_cost = SimpleCostSpecification {
                    read_count: Constant(1),
                    read_length: Constant(value_tuple_size as u64),
                    write_length: Constant(0), write_count: Constant(0),
                    runtime: Linear(constants::LOOKUP_RUNTIME_COST_A, constants::LOOKUP_RUNTIME_COST_B),
                }.compute_cost(value_tuple_size)?;

                hash_cost.add(&read_cost)?;

                Ok(hash_cost)
            },
            FetchVar => {
                assert!(args.len() == 1);
                let var_name = args[0].match_atom().expect("Argument should be atomic name.");

                // the cost of the hash lookup...
                let mut hash_cost = get_hash_cost(var_name.len() as u64, 0)?;

                // the cost of the database read...
                let value_size = u64::from(self.analysis.get_persisted_variable_type(var_name)
                                                 .expect("Variable should exist").size());
                let read_cost = SimpleCostSpecification {
                    read_count: Constant(1),
                    read_length: Constant(value_size as u64),
                    write_length: Constant(0), write_count: Constant(0),
                    runtime: Linear(constants::LOOKUP_RUNTIME_COST_A, constants::LOOKUP_RUNTIME_COST_B),
                }.compute_cost(value_size)?;

                hash_cost.add(&read_cost)?;

                Ok(hash_cost)
            },
            FetchContractEntry => {
                assert!(args.len() == 3);
                let contract = match args[0].match_literal_value() {
                    Some(Value::Principal(PrincipalData::Contract(x))) => x,
                    _ => panic!("Argument should be literal contract identifier")
                };

                let map_name = args[1].match_atom().expect("Argument should be atomic name.");
                let key_tuple = &args[2];

                let key_tuple_size = u64::from(self.type_map.get_type(key_tuple).expect(TYPE_ANNOTATED_FAIL)
                                               .size());
                // the cost of the hash lookup...
                let mut hash_cost = get_hash_cost(map_name.len() as u64, key_tuple_size)?;

                // the cost of the database read...
                let value_tuple_size = u64::from(self.db.get_map_type(contract, map_name)
                                                 .expect("Map should exist")
                                                 .1.size());
                let read_cost = SimpleCostSpecification {
                    read_count: Constant(1),
                    read_length: Constant(value_tuple_size as u64),
                    write_length: Constant(0), write_count: Constant(0),
                    runtime: Linear(constants::LOOKUP_RUNTIME_COST_A, constants::LOOKUP_RUNTIME_COST_B),
                }.compute_cost(value_tuple_size)?;

                hash_cost.add(&read_cost)?;

                Ok(hash_cost)
            },
            SetVar => {
                assert!(args.len() == 2);
                let var_name = args[0].match_atom().expect("Argument should be atomic name.");
                let value_arg = &args[1];
                let value_size =  u64::from(self.type_map.get_type(value_arg)
                                            .expect(TYPE_ANNOTATED_FAIL)
                                            .size());

                // the cost of the hash lookup...
                let mut hash_cost = get_hash_cost(var_name.len() as u64, 0)?;

                // the cost of the database op...
                let write_cost = SimpleCostSpecification {
                    read_count: Constant(0), read_length: Constant(0),
                    write_length: Constant(value_size), write_count: Constant(1),
                    runtime: Linear(constants::DB_WRITE_RUNTIME_COST_A, constants::DB_WRITE_RUNTIME_COST_B),
                }.compute_cost(value_size)?;

                hash_cost.add(&write_cost)?;

                // the cost of computing the value arg
                hash_cost.add(&self.handle_expression(value_arg)?)?;

                Ok(hash_cost)
            },
            SetEntry => {
                assert!(args.len() == 3);
                let map_name = args[0].match_atom().expect("Argument should be atomic name.");
                let key_tuple = &args[1];
                let value_tuple = &args[2];

                let value_size =  u64::from(self.type_map.get_type(value_tuple)
                                            .expect(TYPE_ANNOTATED_FAIL)
                                            .size());

                let key_size =  u64::from(self.type_map.get_type(key_tuple)
                                          .expect(TYPE_ANNOTATED_FAIL)
                                          .size());
                // the cost of the hash lookup...
                let mut hash_cost = get_hash_cost(map_name.len() as u64, key_size)?;

                // the cost of the database op...
                let write_cost = SimpleCostSpecification {
                    read_count: Constant(0), read_length: Constant(0),
                    write_length: Constant(value_size), write_count: Constant(1),
                    runtime: Linear(constants::DB_WRITE_RUNTIME_COST_A, constants::DB_WRITE_RUNTIME_COST_B),
                }.compute_cost(value_size)?;

                hash_cost.add(&write_cost)?;

                // the cost of computing the key, value args
                hash_cost.add(&self.handle_expression(key_tuple)?)?;
                hash_cost.add(&self.handle_expression(value_tuple)?)?;

                Ok(hash_cost)
            },
            InsertEntry => {
                assert!(args.len() == 3);
                let map_name = args[0].match_atom().expect("Argument should be atomic name.");
                let key_tuple = &args[1];
                let value_tuple = &args[2];

                let value_size =  u64::from(self.type_map.get_type(value_tuple)
                                            .expect(TYPE_ANNOTATED_FAIL)
                                            .size());

                let key_size =  u64::from(self.type_map.get_type(key_tuple)
                                          .expect(TYPE_ANNOTATED_FAIL)
                                          .size());
                // the cost of the hash lookup...
                let mut hash_cost = get_hash_cost(map_name.len() as u64, key_size)?;

                // the cost of the database op...
                let write_cost = SimpleCostSpecification {
                    read_count: Constant(1), read_length: Constant(0),
                    write_length: Constant(value_size), write_count: Constant(1),
                    runtime: Linear(constants::DB_WRITE_RUNTIME_COST_A, constants::DB_WRITE_RUNTIME_COST_B),
                }.compute_cost(value_size)?;

                hash_cost.add(&write_cost)?;

                // the cost of computing the key, value args
                hash_cost.add(&self.handle_expression(key_tuple)?)?;
                hash_cost.add(&self.handle_expression(value_tuple)?)?;

                Ok(hash_cost)
            },
            DeleteEntry => {
                assert!(args.len() == 2);
                let map_name = args[0].match_atom().expect("Argument should be atomic name.");
                let key_tuple = &args[1];

                let key_size =  u64::from(self.type_map.get_type(key_tuple)
                                          .expect(TYPE_ANNOTATED_FAIL)
                                          .size());
                // the cost of the hash lookup...
                let mut hash_cost = get_hash_cost(map_name.len() as u64, key_size)?;

                // the cost of the database op...
                let write_cost = SimpleCostSpecification {
                    read_count: Constant(1), read_length: Constant(0),
                    write_length: Constant(1), write_count: Constant(1),
                    runtime: Linear(constants::DB_WRITE_RUNTIME_COST_A, constants::DB_WRITE_RUNTIME_COST_B),
                }.compute_cost(1)?;

                hash_cost.add(&write_cost)?;

                // the cost of computing the key, value args
                hash_cost.add(&self.handle_expression(key_tuple)?)?;

                Ok(hash_cost)
            },
            MintAsset => {
                assert!(args.len() == 3);
                let asset_name = args[0].match_atom().expect("Argument should be atomic name.");
                let asset_key = &args[1];
                let asset_owner = &args[2];

                let key_size =  u64::from(self.type_map.get_type(asset_key)
                                          .expect(TYPE_ANNOTATED_FAIL)
                                          .size());
                // the cost of the hash lookup...
                let mut hash_cost = get_hash_cost(asset_name.len() as u64, key_size)?;

                // the cost of the database op...
                let write_cost = SimpleCostSpecification {
                    read_count: Constant(1), read_length: Linear(1, 0),
                    write_count: Constant(1), write_length: Linear(1, 0),
                    runtime: Linear(constants::DB_WRITE_RUNTIME_COST_A, constants::DB_WRITE_RUNTIME_COST_B),
                }.compute_cost(constants::ASSET_OWNER_LENGTH)?;

                hash_cost.add(&write_cost)?;

                // the cost of computing the key, value args
                hash_cost.add(&self.handle_expression(asset_key)?)?;
                hash_cost.add(&self.handle_expression(asset_owner)?)?;

                Ok(hash_cost)
            },
            TransferAsset => {
                assert!(args.len() == 4);
                let asset_name = args[0].match_atom().expect("Argument should be atomic name.");
                let asset_key = &args[1];
                let asset_sender = &args[2];
                let asset_receiver = &args[3];

                let key_size =  u64::from(self.type_map.get_type(asset_key)
                                          .expect(TYPE_ANNOTATED_FAIL)
                                          .size());
                // the cost of the hash lookup...
                let mut hash_cost = get_hash_cost(asset_name.len() as u64, key_size)?;
                // you do two lookups
                hash_cost.multiply(2)?;

                // the cost of the database ops...
                let write_cost = SimpleCostSpecification {
                    read_count: Constant(1), read_length: Linear(1, 0),
                    write_count: Constant(1), write_length: Linear(1, 0),
                    runtime: Linear(2*constants::DB_WRITE_RUNTIME_COST_A, 2*constants::DB_WRITE_RUNTIME_COST_B),
                }.compute_cost(constants::ASSET_OWNER_LENGTH)?;

                hash_cost.add(&write_cost)?;

                // the cost of computing the key, value args
                hash_cost.add(&self.handle_expression(asset_key)?)?;
                hash_cost.add(&self.handle_expression(asset_sender)?)?;
                hash_cost.add(&self.handle_expression(asset_receiver)?)?;

                Ok(hash_cost)
            },
            GetAssetOwner => {
                assert!(args.len() == 2);
                let asset_name = args[0].match_atom().expect("Argument should be atomic name.");
                let asset_key = &args[1];

                let key_size =  u64::from(self.type_map.get_type(asset_key)
                                          .expect(TYPE_ANNOTATED_FAIL)
                                          .size());
                // the cost of the hash lookup...
                let mut hash_cost = get_hash_cost(asset_name.len() as u64, key_size)?;

                // the cost of the database ops...
                let write_cost = SimpleCostSpecification {
                    read_count: Constant(1), read_length: Linear(1, 0),
                    write_count: Constant(0), write_length: Constant(0),
                    runtime: Linear(constants::LOOKUP_RUNTIME_COST_A, constants::LOOKUP_RUNTIME_COST_B),
                }.compute_cost(constants::ASSET_OWNER_LENGTH)?;

                hash_cost.add(&write_cost)?;

                // the cost of computing the key, value args
                hash_cost.add(&self.handle_expression(asset_key)?)?;

                Ok(hash_cost)
            },
        }
    }

    fn handle_simple_function_args(&mut self, args: &[SymbolicExpression]) -> CheckResult<u64> {
        let argument_cost = self.handle_all_expressions(args)?;
        let mut argument_len = 0;
        for arg in args {
            let arg_type = self.type_map.get_type(arg)
                .ok_or(CheckErrors::TypeAnnotationExpectedFailure)?;
            argument_len = u64::from(arg_type.size()).cost_overflow_add(argument_len)?;
        }

        Ok(argument_len)
    }

    fn handle_function_application(&mut self, function_name: &str, args: &[SymbolicExpression]) -> CheckResult<ExecutionCost> {
        if let Some(native_function) = NativeFunctions::lookup_by_name(function_name) {
            match get_native_function_cost_spec(&native_function) {
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
                let (function_expr, args) = children.split_first()
                    .ok_or(CheckErrors::NonFunctionApplication)?;
                let function_name = function_expr.match_atom()
                    .ok_or(CheckErrors::BadFunctionName)?;
                self.handle_function_application(&function_name, args)
            }
        }
    }
}

fn get_hash_cost(name_size: u64, type_size: u64) -> CheckResult<ExecutionCost> {
    SimpleCostSpecification::new_diskless(CostFunctions::Linear(constants::DB_HASH_COST_A, constants::DB_HASH_COST_B))
        .compute_cost(type_size.cost_overflow_add(name_size)?)
}

fn get_binding_cost(name: &str) -> CheckResult<ExecutionCost> {
    SimpleCostSpecification::new_diskless(CostFunctions::Linear(constants::BINDING_COST_A, constants::BINDING_COST_B))
        .compute_cost(name.len() as u64)
}

fn get_function_lookup_cost(name: &str) -> CheckResult<ExecutionCost> {
    // hashing function name => linear.
    //   
    SimpleCostSpecification::new_diskless(CostFunctions::Linear(constants::FUNC_LOOKUP_COST_A, constants::FUNC_LOOKUP_COST_B))
        .compute_cost(name.len() as u64)
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

// note: this could be refactored to return static pointers.
pub fn get_native_function_cost_spec(func: &NativeFunctions) -> CostSpecification {
    use self::CostFunctions::{Constant, Linear};
    use vm::functions::NativeFunctions::*;

    let result = match func {
        ContractCall => { return CostSpecification::Special(SpecialCostType::ContractCall) },
        If =>           { return CostSpecification::Special(SpecialCostType::If) },
        Map =>          { return CostSpecification::Special(SpecialCostType::Map) },
        Filter =>       { return CostSpecification::Special(SpecialCostType::Filter) },
        Fold =>         { return CostSpecification::Special(SpecialCostType::Fold) },
        Let =>          { return CostSpecification::Special(SpecialCostType::Let) },
        TupleCons =>    { return CostSpecification::Special(SpecialCostType::TupleCons) },
        TupleGet =>     { return CostSpecification::Special(SpecialCostType::TupleGet) },
        Asserts =>  SimpleCostSpecification::new_diskless(Linear(constants::ASSERTS_COST_A,  constants::ASSERTS_COST_B)),

        // cost of arithmetics is linear in the number of arguments.
        Add =>      SimpleCostSpecification::new_diskless(Linear(constants::ADD_COST_A,      0)),
        Multiply => SimpleCostSpecification::new_diskless(Linear(constants::MULTIPLY_COST_A, 0)),
        Divide =>   SimpleCostSpecification::new_diskless(Linear(constants::DIVIDE_COST_A,   0)),
        Subtract => SimpleCostSpecification::new_diskless(Linear(constants::SUBTRACT_COST_A, 0)),

        // these arith. ops are _constant_ since they are of fixed length integers.
        CmpGeq | CmpLeq | CmpLess | CmpGreater =>
                        SimpleCostSpecification::new_diskless(Constant(constants::COMPARE_COST)),
        ToUInt | ToInt => 
                        SimpleCostSpecification::new_diskless(Constant(constants::INT_CAST_COST)),
        Modulo      =>  SimpleCostSpecification::new_diskless(Constant(constants::MOD_COST)),
        Power       =>  SimpleCostSpecification::new_diskless(Constant(constants::POW_COST)),
        BitwiseXOR  =>  SimpleCostSpecification::new_diskless(Constant(constants::XOR_COST)),

        And | Or => SimpleCostSpecification::new_diskless(Linear(constants::AND_OR_COST_A, 0)),

        Not => SimpleCostSpecification::new_diskless(Constant(constants::NOT_COST)),
        Equals => SimpleCostSpecification::new_diskless(Linear(constants::EQUALS_COST_A, 0)),

        // ensure this is a constant cost, since length is cached from list constructor.
        Len => SimpleCostSpecification::new_diskless(Constant(constants::LEN_COST)),

        ListCons => SimpleCostSpecification::new_diskless(Linear(constants::LIST_CONS_A, 0)),
        Begin => SimpleCostSpecification::new_diskless(Constant(constants::BEGIN_COST)),
        Sha512Trunc256 =>
                     SimpleCostSpecification::new_diskless(Linear(constants::SHA512T_A, constants::SHA512T_B)),
        Hash160 =>   SimpleCostSpecification::new_diskless(Linear(constants::HASH160_A, constants::HASH160_B)),
        Sha256 =>    SimpleCostSpecification::new_diskless(Linear(constants::SHA256_A,  constants::SHA256_B)),
        Sha512 =>    SimpleCostSpecification::new_diskless(Linear(constants::SHA512_A,  constants::SHA512_B)),
        Keccak256 => SimpleCostSpecification::new_diskless(Linear(constants::KECC256_A, constants::KECC256_B)),

        ConsSome | ConsOkay | ConsError 
                             => SimpleCostSpecification::new_diskless(Linear(constants::CONS_OPTION_A, constants::CONS_OPTION_B)),
        DefaultTo            => SimpleCostSpecification::new_diskless(Linear(constants::DEFAULT_TO_A,  constants::DEFAULT_TO_B)),
        Expects | ExpectsErr => SimpleCostSpecification::new_diskless(Linear(constants::EXPECTS_A,     constants::EXPECTS_B)),
        Print =>                SimpleCostSpecification::new_diskless(Linear(constants::PRINT_A, constants::PRINT_B)),

        IsOkay | IsNone => SimpleCostSpecification::new_diskless(Constant(constants::IS_OPTION_COST)),
        AsContract =>      SimpleCostSpecification::new_diskless(Constant(constants::AS_CONTRACT_COST)),

        // Fetches need to be handled specially.
        //    read runtime costs are linear (may be super-linear to parse) in the _stored type_, not the
        //      argument length
        FetchVar => { return CostSpecification::Special(SpecialCostType::FetchVar) },
        FetchEntry => { return CostSpecification::Special(SpecialCostType::FetchEntry) },
        FetchContractEntry => { return CostSpecification::Special(SpecialCostType::FetchContractEntry) },
        SetVar  => { return CostSpecification::Special(SpecialCostType::SetVar) },
        SetEntry => { return CostSpecification::Special(SpecialCostType::SetEntry) },
        InsertEntry => { return CostSpecification::Special(SpecialCostType::InsertEntry) },
        DeleteEntry => { return CostSpecification::Special(SpecialCostType::DeleteEntry) },
        GetBlockInfo => SimpleCostSpecification {
            read_count: Constant(1),
            read_length: Constant(constants::GET_BLOCK_INFO_READ_LEN),
            write_length: Constant(0), write_count: Constant(0),
            runtime: Constant(constants::GET_BLOCK_INFO_COST)
        },
        MintAsset => { return CostSpecification::Special(SpecialCostType::MintAsset) },
        TransferAsset => { return CostSpecification::Special(SpecialCostType::TransferAsset) },
        TransferToken => SimpleCostSpecification {
            read_count: Constant(1), write_count: Constant(1),
            read_length: Constant(constants::TRANSFER_TOKEN_READ_LEN),
            write_length: Constant(constants::TRANSFER_TOKEN_WRITE_LEN),
            runtime: Constant(constants::TRANSFER_TOKEN_COST),
        },
        MintToken => SimpleCostSpecification {
            read_count: Constant(1), write_count: Constant(1),            
            read_length: Constant(constants::MINT_TOKEN_READ_LEN),
            write_length: Constant(constants::MINT_TOKEN_WRITE_LEN),
            runtime: Constant(constants::MINT_TOKEN_COST),
        },
        GetTokenBalance => SimpleCostSpecification {
            read_count: Constant(1), read_length: Constant(constants::GET_TOKEN_BALANCE_READ_LEN),
            write_length: Constant(0), write_count: Constant(0),
            runtime: Constant(constants::GET_TOKEN_BALANCE_COST),
        },
        GetAssetOwner => { return CostSpecification::Special(SpecialCostType::GetAssetOwner) },
        AtBlock => SimpleCostSpecification {
            read_count: Constant(1), read_length: Constant(constants::AT_BLOCK_READ_LEN),
            write_length: Constant(0), write_count: Constant(0),
            runtime: Constant(constants::AT_BLOCK_COST),
        },
    };

    CostSpecification::Simple(result)
}

