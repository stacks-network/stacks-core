// Copyright (C) 2013-2020 Blockstack PBC, a public benefit corporation
// Copyright (C) 2020 Stacks Open Internet Foundation
//
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.
//
// This program is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
// GNU General Public License for more details.
//
// You should have received a copy of the GNU General Public License
// along with this program.  If not, see <http://www.gnu.org/licenses/>.
pub mod diagnostic;
pub mod errors;

#[macro_use]
pub mod costs;

pub mod types;

pub mod contracts;

pub mod ast;
pub mod contexts;
pub mod database;
pub mod representations;

pub mod callables;
pub mod functions;
pub mod variables;

pub mod analysis;
pub mod docs;
pub mod version;

pub mod coverage;

pub mod events;

#[cfg(feature = "rusqlite")]
pub mod tooling;

#[cfg(any(test, feature = "testing"))]
pub mod tests;

#[cfg(any(test, feature = "testing"))]
pub mod test_util;

pub mod clarity;

use std::collections::BTreeMap;

pub use clarity_types::MAX_CALL_STACK_DEPTH;
use costs::CostErrors;
use stacks_common::types::StacksEpochId;

use self::analysis::ContractAnalysis;
use self::ast::ContractAST;
use self::costs::ExecutionCost;
use self::diagnostic::Diagnostic;
use crate::vm::callables::CallableType;
pub use crate::vm::contexts::{
    CallStack, ContractContext, Environment, LocalContext, MAX_CONTEXT_DEPTH,
};
use crate::vm::contexts::{ExecutionTimeTracker, GlobalContext};
use crate::vm::costs::cost_functions::ClarityCostFunction;
use crate::vm::costs::{
    runtime_cost, CostOverflowingMath, CostTracker, LimitedCostTracker, MemoryConsumer,
};
// publish the non-generic StacksEpoch form for use throughout module
pub use crate::vm::database::clarity_db::StacksEpoch;
use crate::vm::errors::{
    CheckErrors, Error, InterpreterError, InterpreterResult as Result, RuntimeErrorType,
};
use crate::vm::events::StacksTransactionEvent;
use crate::vm::functions::define::DefineResult;
pub use crate::vm::functions::stx_transfer_consolidated;
pub use crate::vm::representations::{
    ClarityName, ContractName, SymbolicExpression, SymbolicExpressionType,
};
pub use crate::vm::types::Value;
use crate::vm::types::{PrincipalData, TypeSignature};
pub use crate::vm::version::ClarityVersion;

#[derive(Debug, Clone)]
pub struct ParsedContract {
    pub contract_identifier: String,
    pub code: String,
    pub function_args: BTreeMap<String, Vec<String>>,
    pub ast: ContractAST,
    pub analysis: ContractAnalysis,
}

#[derive(Debug, Clone)]
pub struct ContractEvaluationResult {
    pub result: Option<Value>,
    pub contract: ParsedContract,
}

#[derive(Debug, Clone)]
pub struct SnippetEvaluationResult {
    pub result: Value,
}

#[derive(Debug, Clone)]
#[allow(clippy::large_enum_variant)]
pub enum EvaluationResult {
    Contract(ContractEvaluationResult),
    Snippet(SnippetEvaluationResult),
}

#[derive(Debug, Clone)]
pub struct ExecutionResult {
    pub result: EvaluationResult,
    pub events: Vec<StacksTransactionEvent>,
    pub cost: Option<CostSynthesis>,
    pub diagnostics: Vec<Diagnostic>,
}

#[derive(Clone, Debug, Serialize)]
pub struct CostSynthesis {
    pub total: ExecutionCost,
    pub limit: ExecutionCost,
    pub memory: u64,
    pub memory_limit: u64,
}

impl CostSynthesis {
    pub fn from_cost_tracker(cost_tracker: &LimitedCostTracker) -> CostSynthesis {
        CostSynthesis {
            total: cost_tracker.get_total(),
            limit: cost_tracker.get_limit(),
            memory: cost_tracker.get_memory(),
            memory_limit: cost_tracker.get_memory_limit(),
        }
    }
}

/// EvalHook defines an interface for hooks to execute during evaluation.
pub trait EvalHook {
    // Called before the expression is evaluated
    fn will_begin_eval(
        &mut self,
        _env: &mut Environment,
        _context: &LocalContext,
        _expr: &SymbolicExpression,
    );

    // Called after the expression is evaluated
    fn did_finish_eval(
        &mut self,
        _env: &mut Environment,
        _context: &LocalContext,
        _expr: &SymbolicExpression,
        _res: &core::result::Result<Value, crate::vm::errors::Error>,
    );

    // Called upon completion of the execution
    fn did_complete(&mut self, _result: core::result::Result<&mut ExecutionResult, String>);
}

fn lookup_variable(name: &str, context: &LocalContext, env: &mut Environment) -> Result<Value> {
    if name.starts_with(char::is_numeric) || name.starts_with('\'') {
        Err(InterpreterError::BadSymbolicRepresentation(format!(
            "Unexpected variable name: {name}"
        ))
        .into())
    } else if let Some(value) = variables::lookup_reserved_variable(name, context, env)? {
        Ok(value)
    } else {
        runtime_cost(
            ClarityCostFunction::LookupVariableDepth,
            env,
            context.depth(),
        )?;
        if let Some(value) = context.lookup_variable(name) {
            runtime_cost(ClarityCostFunction::LookupVariableSize, env, value.size()?)?;
            Ok(value.clone())
        } else if let Some(value) = env.contract_context.lookup_variable(name).cloned() {
            runtime_cost(ClarityCostFunction::LookupVariableSize, env, value.size()?)?;
            let (value, _) =
                Value::sanitize_value(env.epoch(), &TypeSignature::type_of(&value)?, value)
                    .ok_or_else(|| CheckErrors::CouldNotDetermineType)?;
            Ok(value)
        } else if let Some(callable_data) = context.lookup_callable_contract(name) {
            if env.contract_context.get_clarity_version() < &ClarityVersion::Clarity2 {
                Ok(callable_data.contract_identifier.clone().into())
            } else {
                Ok(Value::CallableContract(callable_data.clone()))
            }
        } else {
            Err(CheckErrors::UndefinedVariable(name.to_string()).into())
        }
    }
}

pub fn lookup_function(name: &str, env: &mut Environment) -> Result<CallableType> {
    runtime_cost(ClarityCostFunction::LookupFunction, env, 0)?;

    if let Some(result) =
        functions::lookup_reserved_functions(name, env.contract_context.get_clarity_version())
    {
        Ok(result)
    } else {
        let user_function = env
            .contract_context
            .lookup_function(name)
            .ok_or(CheckErrors::UndefinedFunction(name.to_string()))?;
        Ok(CallableType::UserFunction(user_function))
    }
}

fn add_stack_trace(result: &mut Result<Value>, env: &Environment) {
    if let Err(Error::Runtime(_, ref mut stack_trace)) = result {
        if stack_trace.is_none() {
            stack_trace.replace(env.call_stack.make_stack_trace());
        }
    }
}

pub fn apply(
    function: &CallableType,
    args: &[SymbolicExpression],
    env: &mut Environment,
    context: &LocalContext,
) -> Result<Value> {
    let identifier = function.get_identifier();
    // Aaron: in non-debug executions, we shouldn't track a full call-stack.
    //        only enough to do recursion detection.

    // do recursion check on user functions.
    let track_recursion = matches!(function, CallableType::UserFunction(_));
    if track_recursion && env.call_stack.contains(&identifier) {
        return Err(CheckErrors::CircularReference(vec![identifier.to_string()]).into());
    }

    if env.call_stack.depth() >= MAX_CALL_STACK_DEPTH {
        return Err(RuntimeErrorType::MaxStackDepthReached.into());
    }

    if let CallableType::SpecialFunction(_, function) = function {
        env.call_stack.insert(&identifier, track_recursion);
        let mut resp = function(args, env, context);
        add_stack_trace(&mut resp, env);
        env.call_stack.remove(&identifier, track_recursion)?;
        resp
    } else {
        let mut used_memory = 0;
        let mut evaluated_args = Vec::with_capacity(args.len());
        env.call_stack.incr_apply_depth();
        for arg_x in args.iter() {
            let arg_value = match eval(arg_x, env, context) {
                Ok(x) => x,
                Err(e) => {
                    env.drop_memory(used_memory)?;
                    env.call_stack.decr_apply_depth();
                    return Err(e);
                }
            };
            let arg_use = arg_value.get_memory_use()?;
            match env.add_memory(arg_use) {
                Ok(_x) => {}
                Err(e) => {
                    env.drop_memory(used_memory)?;
                    env.call_stack.decr_apply_depth();
                    return Err(Error::from(e));
                }
            };
            used_memory += arg_value.get_memory_use()?;
            evaluated_args.push(arg_value);
        }
        env.call_stack.decr_apply_depth();

        env.call_stack.insert(&identifier, track_recursion);
        let mut resp = match function {
            CallableType::NativeFunction(_, function, cost_function) => {
                runtime_cost(cost_function.clone(), env, evaluated_args.len())
                    .map_err(Error::from)
                    .and_then(|_| function.apply(evaluated_args, env))
            }
            CallableType::NativeFunction205(_, function, cost_function, cost_input_handle) => {
                let cost_input = if env.epoch() >= &StacksEpochId::Epoch2_05 {
                    cost_input_handle(evaluated_args.as_slice())?
                } else {
                    evaluated_args.len() as u64
                };
                runtime_cost(cost_function.clone(), env, cost_input)
                    .map_err(Error::from)
                    .and_then(|_| function.apply(evaluated_args, env))
            }
            CallableType::UserFunction(function) => function.apply(&evaluated_args, env),
            _ => return Err(InterpreterError::Expect("Should be unreachable.".into()).into()),
        };
        add_stack_trace(&mut resp, env);
        env.drop_memory(used_memory)?;
        env.call_stack.remove(&identifier, track_recursion)?;
        resp
    }
}

fn check_max_execution_time_expired(global_context: &GlobalContext) -> Result<()> {
    match global_context.execution_time_tracker {
        ExecutionTimeTracker::NoTracking => Ok(()),
        ExecutionTimeTracker::MaxTime {
            start_time,
            max_duration,
        } => {
            if start_time.elapsed() >= max_duration {
                Err(CostErrors::ExecutionTimeExpired.into())
            } else {
                Ok(())
            }
        }
    }
}

pub fn eval(
    exp: &SymbolicExpression,
    env: &mut Environment,
    context: &LocalContext,
) -> Result<Value> {
    use crate::vm::representations::SymbolicExpressionType::{
        Atom, AtomValue, Field, List, LiteralValue, TraitReference,
    };

    check_max_execution_time_expired(env.global_context)?;

    if let Some(mut eval_hooks) = env.global_context.eval_hooks.take() {
        for hook in eval_hooks.iter_mut() {
            hook.will_begin_eval(env, context, exp);
        }
        env.global_context.eval_hooks = Some(eval_hooks);
    }

    let res = match exp.expr {
        AtomValue(ref value) | LiteralValue(ref value) => Ok(value.clone()),
        Atom(ref value) => lookup_variable(value, context, env),
        List(ref children) => {
            let (function_variable, rest) = children
                .split_first()
                .ok_or(CheckErrors::NonFunctionApplication)?;

            let function_name = function_variable
                .match_atom()
                .ok_or(CheckErrors::BadFunctionName)?;
            let f = lookup_function(function_name, env)?;
            apply(&f, rest, env, context)
        }
        TraitReference(_, _) | Field(_) => {
            return Err(InterpreterError::BadSymbolicRepresentation(
                "Unexpected trait reference".into(),
            )
            .into())
        }
    };

    if let Some(mut eval_hooks) = env.global_context.eval_hooks.take() {
        for hook in eval_hooks.iter_mut() {
            hook.did_finish_eval(env, context, exp, &res);
        }
        env.global_context.eval_hooks = Some(eval_hooks);
    }

    res
}

pub fn is_reserved(name: &str, version: &ClarityVersion) -> bool {
    functions::lookup_reserved_functions(name, version).is_some()
        || variables::is_reserved_name(name, version)
}

/// This function evaluates a list of expressions, sharing a global context.
/// It returns the final evaluated result.
/// Used for the initialization of a new contract.
pub fn eval_all(
    expressions: &[SymbolicExpression],
    contract_context: &mut ContractContext,
    global_context: &mut GlobalContext,
    sponsor: Option<PrincipalData>,
) -> Result<Option<Value>> {
    let mut last_executed = None;
    let context = LocalContext::new();
    let mut total_memory_use = 0;

    let publisher: PrincipalData = contract_context.contract_identifier.issuer.clone().into();

    finally_drop_memory!(global_context, total_memory_use; {
        for exp in expressions {
            let try_define = global_context.execute(|context| {
                let mut call_stack = CallStack::new();
                let mut env = Environment::new(
                    context, contract_context, &mut call_stack, Some(publisher.clone()), Some(publisher.clone()), sponsor.clone());
                functions::define::evaluate_define(exp, &mut env)
            })?;
            match try_define {
                DefineResult::Variable(name, value) => {
                    runtime_cost(ClarityCostFunction::BindName, global_context, 0)?;
                    let value_memory_use = value.get_memory_use()?;
                    global_context.add_memory(value_memory_use)?;
                    total_memory_use += value_memory_use;

                    contract_context.variables.insert(name, value);
                },
                DefineResult::Function(name, value) => {
                    runtime_cost(ClarityCostFunction::BindName, global_context, 0)?;

                    contract_context.functions.insert(name, value);
                },
                DefineResult::PersistedVariable(name, value_type, value) => {
                    runtime_cost(ClarityCostFunction::CreateVar, global_context, value_type.size()?)?;
                    contract_context.persisted_names.insert(name.clone());

                    global_context.add_memory(value_type.type_size()
                                              .map_err(|_| InterpreterError::Expect("Type size should be realizable".into()))? as u64)?;

                    global_context.add_memory(value.size()? as u64)?;

                    let data_type = global_context.database.create_variable(&contract_context.contract_identifier, &name, value_type)?;
                    global_context.database.set_variable(&contract_context.contract_identifier, &name, value, &data_type, &global_context.epoch_id)?;

                    contract_context.meta_data_var.insert(name, data_type);
                },
                DefineResult::Map(name, key_type, value_type) => {
                    runtime_cost(ClarityCostFunction::CreateMap, global_context,
                                  u64::from(key_type.size()?).cost_overflow_add(
                                      u64::from(value_type.size()?))?)?;
                    contract_context.persisted_names.insert(name.clone());

                    global_context.add_memory(key_type.type_size()
                                              .map_err(|_| InterpreterError::Expect("Type size should be realizable".into()))? as u64)?;
                    global_context.add_memory(value_type.type_size()
                                              .map_err(|_| InterpreterError::Expect("Type size should be realizable".into()))? as u64)?;

                    let data_type = global_context.database.create_map(&contract_context.contract_identifier, &name, key_type, value_type)?;

                    contract_context.meta_data_map.insert(name, data_type);
                },
                DefineResult::FungibleToken(name, total_supply) => {
                    runtime_cost(ClarityCostFunction::CreateFt, global_context, 0)?;
                    contract_context.persisted_names.insert(name.clone());

                    global_context.add_memory(TypeSignature::UIntType.type_size()
                                              .map_err(|_| InterpreterError::Expect("Type size should be realizable".into()))? as u64)?;

                    let data_type = global_context.database.create_fungible_token(&contract_context.contract_identifier, &name, &total_supply)?;

                    contract_context.meta_ft.insert(name, data_type);
                },
                DefineResult::NonFungibleAsset(name, asset_type) => {
                    runtime_cost(ClarityCostFunction::CreateNft, global_context, asset_type.size()?)?;
                    contract_context.persisted_names.insert(name.clone());

                    global_context.add_memory(asset_type.type_size()
                                              .map_err(|_| InterpreterError::Expect("Type size should be realizable".into()))? as u64)?;

                    let data_type = global_context.database.create_non_fungible_token(&contract_context.contract_identifier, &name, &asset_type)?;

                    contract_context.meta_nft.insert(name, data_type);
                },
                DefineResult::Trait(name, trait_type) => {
                    contract_context.defined_traits.insert(name, trait_type);
                },
                DefineResult::UseTrait(_name, _trait_identifier) => {},
                DefineResult::ImplTrait(trait_identifier) => {
                    contract_context.implemented_traits.insert(trait_identifier);
                },
                DefineResult::NoDefine => {
                    // not a define function, evaluate normally.
                    global_context.execute(|global_context| {
                        let mut call_stack = CallStack::new();
                        let mut env = Environment::new(
                            global_context, contract_context, &mut call_stack, Some(publisher.clone()), Some(publisher.clone()), sponsor.clone());

                        let result = eval(exp, &mut env, &context)?;
                        last_executed = Some(result);
                        Ok(())
                    })?;
                }
            }
        }

        contract_context.data_size = total_memory_use;
        Ok(last_executed)
    })
}

/// Run provided program in a brand new environment, with a transient, empty
/// database. Only used for testing
/// This method executes the program in Epoch 2.0 *and* Epoch 2.05 and asserts
/// that the result is the same before returning the result
#[cfg(any(test, feature = "testing"))]
pub fn execute_on_network(program: &str, use_mainnet: bool) -> Result<Option<Value>> {
    let epoch_200_result = execute_with_parameters(
        program,
        ClarityVersion::Clarity2,
        StacksEpochId::Epoch20,
        use_mainnet,
    );
    let epoch_205_result = execute_with_parameters(
        program,
        ClarityVersion::Clarity2,
        StacksEpochId::Epoch2_05,
        use_mainnet,
    );

    assert_eq!(
        epoch_200_result, epoch_205_result,
        "Epoch 2.0 and 2.05 should have same execution result, but did not for program `{program}`"
    );
    epoch_205_result
}

/// Runs `program` in a test environment with the provided parameters.
#[cfg(any(test, feature = "testing"))]
pub fn execute_with_parameters_and_call_in_global_context<F>(
    program: &str,
    clarity_version: ClarityVersion,
    epoch: StacksEpochId,
    use_mainnet: bool,
    mut global_context_function: F,
) -> Result<Option<Value>>
where
    F: FnMut(&mut GlobalContext) -> Result<()>,
{
    use crate::vm::database::MemoryBackingStore;
    use crate::vm::tests::test_only_mainnet_to_chain_id;
    use crate::vm::types::QualifiedContractIdentifier;

    let contract_id = QualifiedContractIdentifier::transient();
    let mut contract_context = ContractContext::new(contract_id.clone(), clarity_version);
    let mut marf = MemoryBackingStore::new();
    let conn = marf.as_clarity_db();
    let chain_id = test_only_mainnet_to_chain_id(use_mainnet);
    let mut global_context = GlobalContext::new(
        use_mainnet,
        chain_id,
        conn,
        LimitedCostTracker::new_free(),
        epoch,
    );
    global_context.execute(|g| {
        global_context_function(g)?;
        let parsed =
            ast::build_ast(&contract_id, program, &mut (), clarity_version, epoch)?.expressions;
        eval_all(&parsed, &mut contract_context, g, None)
    })
}

#[cfg(any(test, feature = "testing"))]
pub fn execute_with_parameters(
    program: &str,
    clarity_version: ClarityVersion,
    epoch: StacksEpochId,
    use_mainnet: bool,
) -> Result<Option<Value>> {
    execute_with_parameters_and_call_in_global_context(
        program,
        clarity_version,
        epoch,
        use_mainnet,
        |_| Ok(()),
    )
}

/// Execute for test with `version`, Epoch20, testnet.
#[cfg(any(test, feature = "testing"))]
pub fn execute_against_version(program: &str, version: ClarityVersion) -> Result<Option<Value>> {
    execute_with_parameters(program, version, StacksEpochId::Epoch20, false)
}

/// Execute for test in Clarity1, Epoch20, testnet.
#[cfg(any(test, feature = "testing"))]
pub fn execute(program: &str) -> Result<Option<Value>> {
    execute_with_parameters(
        program,
        ClarityVersion::Clarity1,
        StacksEpochId::Epoch20,
        false,
    )
}

/// Execute for test in Clarity1, Epoch20, testnet.
#[cfg(any(test, feature = "testing"))]
pub fn execute_with_limited_execution_time(
    program: &str,
    max_execution_time: std::time::Duration,
) -> Result<Option<Value>> {
    execute_with_parameters_and_call_in_global_context(
        program,
        ClarityVersion::Clarity1,
        StacksEpochId::Epoch20,
        false,
        |g| {
            g.set_max_execution_time(max_execution_time);
            Ok(())
        },
    )
}

/// Execute for test in Clarity2, Epoch21, testnet.
#[cfg(any(test, feature = "testing"))]
pub fn execute_v2(program: &str) -> Result<Option<Value>> {
    execute_with_parameters(
        program,
        ClarityVersion::Clarity2,
        StacksEpochId::Epoch21,
        false,
    )
}

#[cfg(test)]
mod test {
    use std::collections::HashMap;
    use std::env;
    use std::fs::File;
    use std::time::{Duration, Instant};

    use clarity_types::types::ResponseData;
    use perf_event::events::Hardware;
    use perf_event::{Builder, Counter};
    use stacks_common::consts::CHAIN_ID_TESTNET;
    use stacks_common::types::StacksEpochId;

    use super::ClarityVersion;
    use crate::vm::callables::{DefineType, DefinedFunction};
    use crate::vm::contexts::{Environment, LocalContext};
    use crate::vm::costs::LimitedCostTracker;
    use crate::vm::database::MemoryBackingStore;
    use crate::vm::errors::Error;
    use crate::vm::functions::NativeFunctions;
    use crate::vm::types::{QualifiedContractIdentifier, TypeSignature, Value};
    use crate::vm::variables::NativeVariables;
    use crate::vm::{
        ast, eval, eval_all, CallStack, ContractContext, EvalHook, GlobalContext,
        SymbolicExpression, SymbolicExpressionType,
    };

    #[test]
    fn test_simple_user_function() {
        //
        //  test program:
        //  (define (do_work x) (+ 5 x))
        //  (define a 59)
        //  (do_work a)
        //
        let content = [SymbolicExpression::list(vec![
            SymbolicExpression::atom("do_work".into()),
            SymbolicExpression::atom("a".into()),
        ])];

        let func_body = SymbolicExpression::list(vec![
            SymbolicExpression::atom("+".into()),
            SymbolicExpression::atom_value(Value::Int(5)),
            SymbolicExpression::atom("x".into()),
        ]);

        let func_args = vec![("x".into(), TypeSignature::IntType)];
        let user_function = DefinedFunction::new(
            func_args,
            func_body,
            DefineType::Private,
            &"do_work".into(),
            "",
        );

        let context = LocalContext::new();
        let mut contract_context = ContractContext::new(
            QualifiedContractIdentifier::transient(),
            ClarityVersion::Clarity1,
        );

        let mut marf = MemoryBackingStore::new();
        let mut global_context = GlobalContext::new(
            false,
            CHAIN_ID_TESTNET,
            marf.as_clarity_db(),
            LimitedCostTracker::new_free(),
            StacksEpochId::Epoch2_05,
        );

        contract_context
            .variables
            .insert("a".into(), Value::Int(59));
        contract_context
            .functions
            .insert("do_work".into(), user_function);

        let mut call_stack = CallStack::new();
        let mut env = Environment::new(
            &mut global_context,
            &contract_context,
            &mut call_stack,
            None,
            None,
            None,
        );
        assert_eq!(Ok(Value::Int(64)), eval(&content[0], &mut env, &context));
    }

    struct PerfEventExprState {
        start_instant: Instant,
        children_duration: Duration,
        perf_counter_instructions: Counter,
        perf_counter_cpu_cycles: Counter,
        perf_counter_ref_cpu_cycles: Counter,
        children_perf_counter_instructions: u64,
        children_perf_counter_cpu_cycles: u64,
        children_perf_counter_ref_cpu_cycles: u64,
    }

    impl PerfEventExprState {
        fn new(
            perf_counter_instructions: Counter,
            perf_counter_cpu_cycles: Counter,
            perf_counter_ref_cpu_cycles: Counter,
        ) -> Self {
            Self {
                start_instant: Instant::now(),
                children_duration: Duration::default(),
                perf_counter_instructions,
                perf_counter_cpu_cycles,
                perf_counter_ref_cpu_cycles,
                children_perf_counter_instructions: 0,
                children_perf_counter_cpu_cycles: 0,
                children_perf_counter_ref_cpu_cycles: 0,
            }
        }
    }

    #[derive(Serialize)]
    struct PerfEventExprCounter {
        expression: String,
        args: Vec<String>,
        calls: u64,
        duration: Duration,
        instructions: u64,
        cpu_cycles: u64,
        ref_cpu_cycles: u64,
        avg_instructions: u64,
        avg_cpu_cycles: u64,
        avg_ref_cpu_cycles: u64,
    }

    impl PerfEventExprCounter {
        fn new() -> Self {
            Self {
                expression: String::default(),
                args: vec![],
                calls: 0,
                duration: Duration::default(),
                instructions: 0,
                cpu_cycles: 0,
                ref_cpu_cycles: 0,
                avg_instructions: 0,
                avg_cpu_cycles: 0,
                avg_ref_cpu_cycles: 0,
            }
        }
    }

    #[derive(Default)]

    pub struct PerfEventCounterHook {
        functions_ids: HashMap<u64, String>,
        expression_states: HashMap<u64, PerfEventExprState>,
        expression_counters: HashMap<String, PerfEventExprCounter>,
        call_stack: Vec<u64>,
    }

    impl PerfEventCounterHook {
        pub fn new() -> Self {
            Self::default()
        }
    }

    impl EvalHook for PerfEventCounterHook {
        fn will_begin_eval(
            &mut self,

            env: &mut Environment,

            _context: &LocalContext,

            expr: &SymbolicExpression,
        ) {
            let mut key = None;
            let mut function_args = vec![];

            if let SymbolicExpressionType::Atom(atom) = &expr.expr {
                if let Some(_native_variable) = NativeVariables::lookup_by_name_at_version(
                    atom.as_str(),
                    &ClarityVersion::latest(),
                ) {
                    key = Some(atom.as_str().to_string());
                }
            } else if let SymbolicExpressionType::List(list) = &expr.expr {
                if let Some((function_name, args)) = list.split_first() {
                    if let Some(function_name) = function_name.match_atom() {
                        if let Some(_native_function) = NativeFunctions::lookup_by_name_at_version(
                            function_name,
                            &ClarityVersion::latest(),
                        ) {
                            let function_name_and_args =
                                format!("{} ({:?})", function_name, args).to_string();

                            for arg in args {
                                function_args.push(arg.expr.to_string());
                            }

                            key = Some(function_name_and_args);
                        }
                    }
                }
            };

            if key.is_none() {
                return;
            }

            let function_key = key.unwrap().to_string();

            let counter = self
                .expression_counters
                .entry(function_key.clone())
                .or_insert(PerfEventExprCounter::new());

            counter.expression = function_key.clone();
            counter.args = function_args;
            counter.calls += 1;

            let current_cost = env.global_context.cost_track.get_total();

            self.functions_ids.insert(expr.id, function_key);

            self.call_stack.push(expr.id);

            let mut perf_event_instructions = Builder::new(Hardware::INSTRUCTIONS).build().unwrap();
            let mut perf_event_cpu_cycles = Builder::new(Hardware::CPU_CYCLES).build().unwrap();
            let mut perf_event_ref_cpu_cycles =
                Builder::new(Hardware::REF_CPU_CYCLES).build().unwrap();

            perf_event_instructions.enable().unwrap();
            perf_event_cpu_cycles.enable().unwrap();
            perf_event_ref_cpu_cycles.enable().unwrap();

            self.expression_states.insert(
                expr.id,
                PerfEventExprState::new(
                    perf_event_instructions,
                    perf_event_cpu_cycles,
                    perf_event_ref_cpu_cycles,
                ),
            );
        }

        fn did_finish_eval(
            &mut self,

            env: &mut Environment,

            _context: &LocalContext,

            expr: &SymbolicExpression,

            _res: &Result<Value, Error>,
        ) {
            if self.expression_states.contains_key(&expr.id) {
                let state = self.expression_states.get_mut(&expr.id).unwrap();

                state.perf_counter_instructions.disable().unwrap();
                state.perf_counter_cpu_cycles.disable().unwrap();
                state.perf_counter_ref_cpu_cycles.disable().unwrap();

                let mut instructions = state.perf_counter_instructions.read().unwrap();
                let mut cpu_cycles = state.perf_counter_cpu_cycles.read().unwrap();
                let mut ref_cpu_cycles = state.perf_counter_ref_cpu_cycles.read().unwrap();

                let function_name = self.functions_ids.get(&expr.id).unwrap().to_string();

                let elapsed = state.start_instant.elapsed();

                let counter = self.expression_counters.get_mut(&function_name).unwrap();

                let duration = elapsed - state.children_duration;

                counter.duration += duration;

                let children_instructions = state.children_perf_counter_instructions;
                instructions -= children_instructions;
                counter.instructions += instructions;
                counter.avg_instructions = counter.instructions / counter.calls;

                let children_cpu_cycles = state.children_perf_counter_cpu_cycles;
                cpu_cycles -= children_cpu_cycles;
                counter.cpu_cycles += cpu_cycles;
                counter.avg_cpu_cycles = counter.cpu_cycles / counter.calls;

                let children_ref_cpu_cycles = state.children_perf_counter_ref_cpu_cycles;
                ref_cpu_cycles -= children_ref_cpu_cycles;
                counter.ref_cpu_cycles += ref_cpu_cycles;
                counter.avg_ref_cpu_cycles = counter.ref_cpu_cycles / counter.calls;

                let _expr_id = self.call_stack.pop().unwrap();

                for expr_id in self.call_stack.iter().rev() {
                    let state = self.expression_states.get_mut(expr_id).unwrap();

                    state.children_duration += duration;

                    state.children_perf_counter_instructions += instructions;
                    state.children_perf_counter_cpu_cycles += cpu_cycles;
                    state.children_perf_counter_ref_cpu_cycles += ref_cpu_cycles;
                }
            }
        }

        fn did_complete(
            &mut self,

            _result: core::result::Result<&mut crate::vm::ExecutionResult, String>,
        ) {
        }
    }

    #[test]
    fn test_native_functions_benchmark() {
        let Ok(json_path) = env::var("CLARITY_BENCHMARK") else {
            return;
        };

        let benchmark_iterations: u32 = env::var("CLARITY_BENCHMARK_ITERATIONS")
            .ok()
            .and_then(|v| v.parse().ok())
            .unwrap_or(1);

        let context = LocalContext::new();
        let mut contract_context = ContractContext::new(
            QualifiedContractIdentifier::transient(),
            ClarityVersion::latest(),
        );

        let mut marf = MemoryBackingStore::new();
        let mut global_context = GlobalContext::new(
            false,
            CHAIN_ID_TESTNET,
            marf.as_clarity_db(),
            LimitedCostTracker::new_free(),
            StacksEpochId::latest(),
        );

        let call_stack = CallStack::new();

        let mut perf_event_counter_hook = PerfEventCounterHook::new();

        let program = r#"
        (+ 1 1)
        (+ 1 1 1)
        (+ 1 1 1 1)
        (- 1 1)
        (- 1 1 1)
        (- 1 1 1 1)
        (* 1 1)
        (* 1 1 1)
        (* 1 1 1 1)
        (sha256 0x12)
        (sha256 0x1234)
        (sha256 0x12345678)
        (sha256 0x1234567812345678123456781234567812345678)
        (sha512 0x12)
        (sha512 0x1234)
        (sha512 0x12345678)
        (sha512 0x1234567812345678123456781234567812345678)
        (keccak256 0x12)
        (keccak256 0x1234)
        (keccak256 0x12345678)
        (keccak256 0x1234567812345678123456781234567812345678)
        (to-ascii? 1)
        (to-ascii? 10)
        (to-ascii? 100)
        (to-ascii? 1000)
        (to-ascii? 10000)
        (to-ascii? u2)
        (to-ascii? u30)
        (to-ascii? u400)
        (to-ascii? u5000)
        (to-ascii? u60000)
        (to-ascii? true)
        (to-ascii? false)
        (to-ascii? 'ST1HTBVD3JG9C05J7HBJTHGR0GGW7KXW28M5JS8QE)
        (to-ascii? tx-sender)
        (to-ascii? 'ST1HTBVD3JG9C05J7HBJTHGR0GGW7KXW28M5JS8QE.dummy001)
        (to-ascii? 'ST1HTBVD3JG9C05J7HBJTHGR0GGW7KXW28M5JS8QE.dummy0123456789)
        (to-ascii? 0x01)
        (to-ascii? 0x0102)
        (to-ascii? 0x010203)
        (to-ascii? 0x0102030405060708090A0B0C0D0E0F)
        (to-ascii? u"A")
        (to-ascii? u"AB")
        (to-ascii? u"ABCDEFGHIJKLMNOPQRSTUVWXYZ")
        (contract-hash? current-contract)
        (as-contract? ((with-stx u100)) (+ 1 1) (+ 2 2))
        (as-contract? ((with-all-assets-unsafe)) (+ 1 1) (+ 2 2))
        (restrict-assets? tx-sender () (+ u1 u2))
        (as-contract? () (+ u1 u2))
        (secp256r1-verify 0xc3abef6a775793dfbc8e0719e7a1de1fc2f90d37a7912b1ce8e300a5a03b06a8 0xf2b8c0645caa7250e3b96d633cf40a88456e4ffbddffb69200c4e019039dfd31f153a6d5c3dc192a5574f3a261b1b70570971b92d8ebf86c17b7670d13591c4e 0x031e18532fd4754c02f3041d9c75ceb33b83ffd81ac7ce4fe882ccb1c98bc5896e)
        (secp256k1-verify 0x89171d7815da4bc1f644665a3234bc99d1680afa0b3285eff4878f4275fbfa89 0x54cd3f378a424a3e50ff1c911b7d80cf424e1b86dddecadbcf39077e62fa1e54ee6514347c1608df2c3995e7356f2d60a1fab60878214642134d78cd923ce27a01 0x0256b328b30c8bf5839e24058747879408bdb36241dc9c2e7c619faa12b2920967)
        "#;

        {
            global_context.add_eval_hook(&mut perf_event_counter_hook);
            let value = Value::string_ascii_from_bytes("1".into()).unwrap();
            let response = Value::Response(ResponseData {
                committed: true,
                data: Box::new(value),
            });

            let contract_id = QualifiedContractIdentifier::transient();

            let parsed = ast::build_ast(
                &contract_id,
                program,
                &mut (),
                ClarityVersion::latest(),
                StacksEpochId::latest(),
            )
            .unwrap()
            .expressions;

            for _ in 0..benchmark_iterations {
                eval_all(&parsed, &mut contract_context, &mut global_context, None).unwrap();
            }
        }

        let mut results: HashMap<String, Vec<PerfEventExprCounter>> = HashMap::new();

        for (key, value) in perf_event_counter_hook.expression_counters {
            let symbol_name = key.split_whitespace().next().unwrap();
            let counter = results.entry(symbol_name.to_string()).or_insert(vec![]);
            counter.push(value);
            counter.sort_by_key(|peec| peec.expression.clone());
        }

        let file = File::create(json_path).unwrap();

        let benchmark_value = serde_json::json!(results);

        serde_json::to_writer_pretty(file, &benchmark_value).unwrap();
    }
}
