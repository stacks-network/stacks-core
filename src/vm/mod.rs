extern crate regex;

pub mod errors;
pub mod diagnostic;
pub mod types;

pub mod contracts;

mod representations;
pub mod ast;
pub mod contexts;
pub mod database;

mod functions;
mod variables;
mod callables;

pub mod docs;
pub mod analysis;

#[cfg(test)]
mod tests;

pub use vm::types::Value;
use vm::callables::CallableType;
use vm::contexts::{ContractContext, LocalContext, Environment, CallStack};
use vm::contexts::{GlobalContext};
use vm::functions::define::DefineResult;
use vm::errors::{Error, InterpreterError, RuntimeErrorType, UncheckedError, InterpreterResult as Result};
use vm::database::{memory_db};
use vm::types::QualifiedContractIdentifier;

pub use vm::representations::{SymbolicExpression, SymbolicExpressionType, ClarityName, ContractName};

const MAX_CALL_STACK_DEPTH: usize = 128;

fn lookup_variable(name: &str, context: &LocalContext, env: &mut Environment) -> Result<Value> {
    if name.starts_with(char::is_numeric) || name.starts_with('\'') {
        Err(InterpreterError::BadSymbolicRepresentation(format!("Unexpected variable name: {}", name)).into())
    } else {
        if let Some(value) = variables::lookup_reserved_variable(name, context, env)? {
            Ok(value)
        } else if let Some(value) = context.lookup_variable(name) {
            Ok(value)
        } else if let Some(value) = env.contract_context.lookup_variable(name) {
            Ok(value)
        } else {
            Err(UncheckedError::UndefinedVariable(name.to_string()).into())
        }
    }
}

pub fn lookup_function(name: &str, env: &Environment)-> Result<CallableType> {
    if let Some(result) = functions::lookup_reserved_functions(name) {
        Ok(result)
    } else {
        let user_function = env.contract_context.lookup_function(name).ok_or(
            UncheckedError::UndefinedFunction(name.to_string()))?;
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

pub fn apply(function: &CallableType, args: &[SymbolicExpression],
             env: &mut Environment, context: &LocalContext) -> Result<Value> {
    let identifier = function.get_identifier();
    // Aaron: in non-debug executions, we shouldn't track a full call-stack.
    //        only enough to do recursion detection.

    // do recursion check on user functions.
    let track_recursion = match function {
        CallableType::UserFunction(_) => true,
        _ => false
    };

    if track_recursion && env.call_stack.contains(&identifier) {
        return Err(UncheckedError::RecursionDetected.into())
    }

    if env.call_stack.depth() >= MAX_CALL_STACK_DEPTH {
        return Err(RuntimeErrorType::MaxStackDepthReached.into())
    }

    if let CallableType::SpecialFunction(_, function) = function {
        env.call_stack.insert(&identifier, track_recursion);
        let mut resp = function(args, env, context);
        add_stack_trace(&mut resp, env);
        env.call_stack.remove(&identifier, track_recursion)?;
        resp
    } else {
        let eval_tried: Result<Vec<Value>> =
            args.iter().map(|x| eval(x, env, context)).collect();
        let evaluated_args = eval_tried?;
        env.call_stack.insert(&identifier, track_recursion);
        let mut resp = match function {
            CallableType::NativeFunction(_, function) => function(&evaluated_args),
            CallableType::UserFunction(function) => function.apply(&evaluated_args, env),
            _ => panic!("Should be unreachable.")
        };
        add_stack_trace(&mut resp, env);
        env.call_stack.remove(&identifier, track_recursion)?;
        resp
    }
            
}

pub fn eval <'a> (exp: &SymbolicExpression, env: &'a mut Environment, context: &LocalContext) -> Result<Value> {
    use vm::representations::SymbolicExpressionType::{AtomValue, Atom, List};

    match exp.expr {
        AtomValue(ref value) => Ok(value.clone()),
        Atom(ref value) => lookup_variable(&value, context, env),
        List(ref children) => {
            let (function_variable, rest) = children.split_first()
                .ok_or(UncheckedError::InvalidArguments(
                    "List expressions (...) are function applications, and must be supplied with function names to apply.".to_string()))?;
            match function_variable.expr {
                Atom(ref value) => {
                    let f = lookup_function(&value, env)?;
                    apply(&f, &rest, env, context)
                },
                _ => Err(UncheckedError::TryEvalToFunction.into())
            }
        }
    }
}


pub fn is_reserved(name: &str) -> bool {
    if let Some(_result) = functions::lookup_reserved_functions(name) {
        true
    } else if variables::is_reserved_name(name) {
        true
    } else {
        false
    }
}

/* This function evaluates a list of expressions, sharing a global context.
 * It returns the final evaluated result.
 */
fn eval_all (expressions: &[SymbolicExpression],
             contract_context: &mut ContractContext,
             global_context: &mut GlobalContext) -> Result<Option<Value>> {
    let mut last_executed = None;
    let context = LocalContext::new();

    for exp in expressions {
        let try_define = {
            global_context.execute(|context| {
                let mut call_stack = CallStack::new();
                let mut env = Environment::new(
                    context, contract_context, &mut call_stack, None, None);
                functions::define::evaluate_define(exp, &mut env)
            })?
        };
        match try_define {
            DefineResult::Variable(name, value) => {
                contract_context.variables.insert(name, value);
            },
            DefineResult::Function(name, value) => {
                contract_context.functions.insert(name, value);
            },
            DefineResult::PersistedVariable(name, value_type, value) => {
                global_context.database.create_variable(&contract_context.contract_identifier, &name, value_type);
                global_context.database.set_variable(&contract_context.contract_identifier, &name, value)?;
            },
            DefineResult::Map(name, key_type, value_type) => {
                global_context.database.create_map(&contract_context.contract_identifier, &name, key_type, value_type);
            },
            DefineResult::FungibleToken(name, total_supply) => {
                global_context.database.create_fungible_token(&contract_context.contract_identifier, &name, &total_supply);
            },
            DefineResult::NonFungibleAsset(name, asset_type) => {
                global_context.database.create_non_fungible_token(&contract_context.contract_identifier, &name, &asset_type);
            },
            DefineResult::NoDefine => {
                // not a define function, evaluate normally.
                global_context.execute(|global_context| {
                    let mut call_stack = CallStack::new();
                    let mut env = Environment::new(
                        global_context, contract_context, &mut call_stack, None, None);

                    let result = eval(exp, &mut env, &context)?;
                    last_executed = Some(result);
                    Ok(())
                })?;
            }
        }
    }

    Ok(last_executed)
}

/* Run provided program in a brand new environment, with a transient, empty
 *  database.
 */
pub fn execute(program: &str) -> Result<Option<Value>> {
    let contract_id = QualifiedContractIdentifier::transient();
    let mut contract_context = ContractContext::new(contract_id.clone());
    let conn = memory_db();
    let mut global_context = GlobalContext::new(conn);
    global_context.execute(|g| {
        let parsed = ast::parse(&contract_id, program)?;
        eval_all(&parsed, &mut contract_context, g)
    })
}


#[cfg(test)]
mod test {
    use vm::database::memory_db;
    use vm::{Value, LocalContext, GlobalContext, ContractContext, Environment, SymbolicExpression, CallStack};
    use vm::types::{TypeSignature, AtomTypeIdentifier, QualifiedContractIdentifier};
    use vm::callables::{DefinedFunction, DefineType};
    use vm::eval;

    #[test]
    fn test_simple_user_function() {
        //
        //  test program:
        //  (define (do_work x) (+ 5 x))
        //  (define a 59)
        //  (do_work a)
        //
        let content = [ SymbolicExpression::list(
            Box::new([ SymbolicExpression::atom("do_work".into()),
                       SymbolicExpression::atom("a".into()) ])) ];

        let func_body = SymbolicExpression::list(
            Box::new([ SymbolicExpression::atom("+".into()),
                       SymbolicExpression::atom_value(Value::Int(5)),
                       SymbolicExpression::atom("x".into())]));

        let func_args = vec![("x".into(), AtomTypeIdentifier::IntType.into())];
        let user_function = DefinedFunction::new(func_args, func_body, DefineType::Private,
                                                 &"do_work".into(), &"");

        let context = LocalContext::new();
        let mut contract_context = ContractContext::new(QualifiedContractIdentifier::transient());
        let mut global_context = GlobalContext::new(memory_db());

        contract_context.variables.insert("a".into(), Value::Int(59));
        contract_context.functions.insert("do_work".into(), user_function);

        let mut call_stack = CallStack::new();
        let mut env = Environment::new(&mut global_context, &contract_context, &mut call_stack, None, None);
        assert_eq!(Ok(Value::Int(64)), eval(&content[0], &mut env, &context));
    }
}
