use vm::representations::{SymbolicExpression, ClarityName};
use vm::representations::SymbolicExpressionType::{AtomValue, Atom, List, LiteralValue};
use vm::types::{Value, PrincipalData, TypeSignature, TupleTypeSignature, FunctionArg,
                FunctionType, FixedFunction, parse_name_type_pairs};
use vm::functions::{NativeFunctions, handle_binding_list};
use vm::functions::define::DefineFunctionsParsed;
use vm::variables::NativeVariables;
use vm::MAX_CONTEXT_DEPTH;

use super::type_checker::contexts::{TypeMap};

use super::AnalysisDatabase;
pub use super::types::{ContractAnalysis, AnalysisPass};

pub use super::errors::{CheckResult, CheckError, CheckErrors};

pub enum CostSpecification {
    Simple(SimpleCostSpecification),
    Special(SpecialCostType),
}

pub enum SpecialCostType { ContractCall, If, Map, Filter, Fold, Let, TupleCons, TupleGet }

pub enum CostFunctions {
    Constant(u64),
    Linear(u64, u64),
}

pub struct SimpleCostSpecification {
    write_length: CostFunctions,
    read_count: CostFunctions,
    runtime: CostFunctions,
}


pub struct ExecutionCost {
    write_length: u64,
    read_count: u64,
    runtime: u64
}

pub struct ContractContext {}

pub struct CostContext {
    context_depth: u64,
}

pub struct CostCounter <'a, 'b> {
    contract_context: ContractContext,
    type_map: TypeMap,
    cost_context: CostContext,
    db: &'a mut AnalysisDatabase <'b>
}

#[derive(PartialEq, Eq, Debug, Deserialize, Serialize)]
pub struct ContractCostAnalysis {}

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
        panic!("Not implemented")
    }
}

impl CostFunctions {
    pub fn compute_cost(&self, input: u64) -> CheckResult<u64> {
        match self {
            CostFunctions::Constant(val) => Ok(*val),
            CostFunctions::Linear(a, b) => { a.cost_overflow_mul(input)?
                                             .cost_overflow_add(*b) }
        }
    }
}

impl SimpleCostSpecification {
    pub fn new_diskless(runtime: CostFunctions) -> SimpleCostSpecification {
        SimpleCostSpecification {
            write_length: CostFunctions::Constant(0),
            read_count: CostFunctions::Constant(0),
            runtime
        }
    }

    pub fn compute_cost(&self, input: u64) -> CheckResult<ExecutionCost> {
        Ok(ExecutionCost {
            write_length: self.write_length.compute_cost(input)?,
            read_count:   self.read_count.compute_cost(input)?,
            runtime:      self.runtime.compute_cost(input)?
        })
    }
}

impl CostContext {
    fn new() -> CostContext {
        CostContext {
            context_depth: 0
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
}

impl ContractContext {
    pub fn new() -> ContractContext {
        Self {}
    }
    pub fn get_defined_function_cost_spec(&self, function_name: &str) -> Option<SimpleCostSpecification> {
        panic!("Not implemented")
    }
}

impl ExecutionCost {
    fn zero() -> ExecutionCost {
        Self { runtime: 0, write_length: 0, read_count: 0 }
    }

    fn runtime(runtime: u64) -> ExecutionCost {
        Self { runtime, write_length: 0, read_count: 0 }
    }

    fn add_runtime(&mut self, runtime: u64) -> CheckResult<()> {
        self.runtime = self.runtime.cost_overflow_add(runtime)?;
        Ok(())
    }

    fn add(&mut self, other: &ExecutionCost) -> CheckResult<()> {
        self.runtime = self.runtime.cost_overflow_add(other.runtime)?;
        self.read_count = self.runtime.cost_overflow_add(other.read_count)?;
        self.write_length = self.runtime.cost_overflow_add(other.write_length)?;
        Ok(())
    }

    fn multiply(&mut self, times: u64) -> CheckResult<()> {
        self.runtime = self.runtime.cost_overflow_mul(times)?;
        self.read_count = self.runtime.cost_overflow_mul(times)?;
        self.write_length = self.runtime.cost_overflow_mul(times)?;
        Ok(())
    }

    fn max_cost(first: ExecutionCost, second: ExecutionCost) -> ExecutionCost {
        Self {
            runtime: first.runtime.max(second.runtime),
            write_length: first.write_length.max(second.write_length),
            read_count: first.read_count.max(second.read_count)
        }
    }
}

impl <'a, 'b> CostCounter <'a, 'b> {
    fn new(db: &'a mut AnalysisDatabase<'b>, type_map: TypeMap) -> CostCounter<'a, 'b> {
        Self {
            db, type_map,
            contract_context: ContractContext::new(),
            cost_context: CostContext::new()
        }
    }

    fn handle_variable_lookup(&mut self, variable_name: &str) -> CheckResult<ExecutionCost> {
        let mut compute_cost = get_reserved_name_cost(variable_name)
            .unwrap_or(ExecutionCost::zero());
        // add lookup cost
        compute_cost.add_runtime(variable_name.len() as u64)?;
        Ok(compute_cost)
    }

    fn handle_special_function(&mut self, function: SpecialCostType, args: &[SymbolicExpression]) -> CheckResult<ExecutionCost> {
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
                let function_name = args[1].match_atom()
                    .ok_or(CheckErrors::ContractCallExpectName)?;
                let cost = self.db.get_contract_function_cost(&contract_id, function_name)
                    .ok_or_else(|| CheckErrors::NoSuchPublicFunction(contract_id.to_string(), function_name.to_string()))?;
                // BASE COST:
                //   RUNTIME = linear cost of hashing function_name + some constant
                //   READS = 1
                let mut total_cost = ExecutionCost { write_length: 0,
                                                     read_count: 1,
                                                     runtime: 1+(function_name.len() as u64) };
                let exec_cost = self.handle_simple_function(cost, &args[2..])?;

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
                    .expect("Analysis Failure: Function argument should have been atom.");
                let list_arg_type = match self.type_map.get_type(&args[1]) {
                    Some(TypeSignature::ListType(l)) => l,
                    x => panic!("Analysis Failure: Expected list type, but annotated type was: {:#?}", x)
                };
                let list_item_type = list_arg_type.get_list_item_type();
                let list_max_len = list_arg_type.get_max_len();

                let function_spec = self.contract_context.get_defined_function_cost_spec(function_name)
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
                    .expect("Analysis Failure: Function argument should have been atom.");
                let list_arg_type = match self.type_map.get_type(&args[1]) {
                    Some(TypeSignature::ListType(l)) => l,
                    x => panic!("Analysis Failure: Expected list type, but annotated type was: {:#?}", x)
                };
                let initial_value_type = self.type_map.get_type(&args[2])
                    .expect("Analysis Failure: Expected a type annotation");

                let list_item_type = list_arg_type.get_list_item_type();
                let list_max_len = list_arg_type.get_max_len();

                let function_spec = self.contract_context.get_defined_function_cost_spec(function_name)
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
                    .expect("Analysis Failure: Let expression must be supplied a binding list.");

                let mut binding_cost = ExecutionCost::runtime(1);

                handle_binding_list(bindings, |var_name, var_sexp| {
                    // the cost of binding the name.
                    binding_cost.add_runtime(var_name.len() as u64)?;

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
            TupleCons => panic!("Unimplemented"),
            TupleGet => panic!("Unimplemented"),
        }
    }

    fn handle_simple_function(&mut self, function_spec: SimpleCostSpecification, args: &[SymbolicExpression]) -> CheckResult<ExecutionCost> {
        let argument_cost = self.handle_all_expressions(args)?;
        let mut argument_len = 0;
        for arg in args {
            let arg_type = self.type_map.get_type(arg)
                .ok_or(CheckErrors::TypeAnnotationExpectedFailure)?;
            argument_len = u64::from(arg_type.size()).cost_overflow_add(argument_len)?;
        }

        function_spec.compute_cost(argument_len)
    }

    fn handle_function_application(&mut self, function_name: &str, args: &[SymbolicExpression]) -> CheckResult<ExecutionCost> {
        if let Some(native_function) = NativeFunctions::lookup_by_name(function_name) {
            match get_native_function_cost_spec(&native_function) {
                CostSpecification::Special(cost_type) => self.handle_special_function(cost_type, args),
                CostSpecification::Simple(cost_type) => self.handle_simple_function(cost_type, args),
            }
        } else {
            // not a native function, so try to find in context
            let simple_cost_spec = self.contract_context.get_defined_function_cost_spec(function_name)
                .ok_or_else(|| CheckErrors::UnknownFunction(function_name.to_string()))?;
            self.handle_simple_function(simple_cost_spec, args)
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

fn get_function_lookup_cost(name: &str) -> CheckResult<ExecutionCost> {
    // hashing function name => linear.
    //   
    let lookup_spec = SimpleCostSpecification::new_diskless(CostFunctions::Linear(1, 1));
    lookup_spec.compute_cost(name.len() as u64)
}

pub fn get_reserved_name_cost(name: &str) -> Option<ExecutionCost> {
    panic!("Not implemented")
}

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
        Add | Subtract | Multiply | Divide => SimpleCostSpecification::new_diskless(Linear(1, 0)),
        CmpGeq | CmpLeq | CmpLess | CmpGreater => SimpleCostSpecification::new_diskless(Constant(1)),
        ToUInt | ToInt => SimpleCostSpecification::new_diskless(Constant(1)),
        Modulo | Power | BitwiseXOR => SimpleCostSpecification::new_diskless(Constant(1)),
        And | Or | Not => SimpleCostSpecification::new_diskless(Constant(1)),
        Equals => SimpleCostSpecification::new_diskless(Linear(1, 0)),
        ListCons => SimpleCostSpecification::new_diskless(Linear(1, 0)),
        FetchVar => SimpleCostSpecification {
            read_count: Constant(1),
            write_length: Constant(0),
            runtime: Linear(1, 1),
        },
        SetVar | SetEntry | InsertEntry | DeleteEntry => SimpleCostSpecification {
            read_count: Constant(1),
            write_length: Linear(1, 1),
            runtime: Linear(1, 1),
        },
        FetchEntry | FetchContractEntry => SimpleCostSpecification {
            read_count: Constant(1),
            write_length: Constant(0),
            runtime: Linear(1, 1),
        },
        Begin => SimpleCostSpecification::new_diskless(Constant(1)),
        // Note: these hash functions will have different costs after benchmarking,
        //    but for now, they can all be linear(1,1).
        Hash160 | Sha256 | Sha512 | Sha512Trunc256 | Keccak256 => SimpleCostSpecification::new_diskless(Linear(1, 1)),
        Print => SimpleCostSpecification::new_diskless(Linear(1, 1)),
        AsContract => SimpleCostSpecification::new_diskless(Constant(1)),
        GetBlockInfo => SimpleCostSpecification {
            read_count: Constant(1),
            write_length: Constant(0),
            runtime: Constant(1)
        },
        ConsSome | ConsOkay | ConsError => SimpleCostSpecification::new_diskless(Linear(1, 1)),
        DefaultTo | Expects | ExpectsErr => SimpleCostSpecification::new_diskless(Linear(1, 1)),
        IsOkay | IsNone => SimpleCostSpecification::new_diskless(Constant(1)),
        MintAsset | TransferAsset => SimpleCostSpecification {
            read_count: Constant(1),
            write_length: Linear(1, 1),
            runtime: Linear(1, 1),
        },
        MintToken | TransferToken => SimpleCostSpecification {
            read_count: Constant(1),
            write_length: Constant(1),
            runtime: Constant(1),
        },
        GetTokenBalance => SimpleCostSpecification {
            read_count: Constant(1),
            write_length: Constant(0),
            runtime: Constant(1),
        },
        GetAssetOwner => SimpleCostSpecification {
            read_count: Constant(1),
            write_length: Constant(0),
            runtime: Linear(1,1), // computing marf key hash is linear with input size
        },
        AtBlock => SimpleCostSpecification {
            read_count: Constant(1),
            write_length: Constant(0),
            runtime: Constant(1),
        },
    };

    CostSpecification::Simple(result)
}

