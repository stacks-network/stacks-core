extern crate regex;

pub mod errors;
pub mod types;

pub mod contracts;

mod representations;
mod parser;
mod contexts;
mod database;

mod functions;
mod variables;
mod callables;
mod tests;

use vm::types::Value;
use vm::callables::CallableType;
use vm::representations::SymbolicExpression;
use vm::contexts::{Context, Environment};
use vm::database::ContractDatabase;
use vm::functions::define::DefineResult;
use vm::errors::{Error, InterpreterResult as Result};

const MAX_CALL_STACK_DEPTH: usize = 256;

fn lookup_variable(name: &str, context: &Context, env: &Environment) -> Result<Value> {
    if name.starts_with(char::is_numeric) || name.starts_with('\'') {
        Err(Error::BadSymbolicRepresentation(format!("Unexpected variable name: {}", name)))
    } else {
        if let Some(value) = context.lookup_variable(name) {
            Ok(value)
        } else if let Some(value) = env.global_context.lookup_variable(name) {
            Ok(value)
        } else {
            Err(Error::Undefined(format!("No such variable found in context: {}", name)))
        }
    }
}

// Aaron:: todo -- now that global_context is an immutable reference when it's used here,
//         I am pretty sure we can return a reference with lifetime 'a here.
pub fn lookup_function<'a> (name: &str, env: &Environment)-> Result<CallableType<'a>> {
    if let Some(result) = functions::lookup_reserved_functions(name) {
        Ok(result)
    } else {
        if let Some(func) = env.global_context.lookup_function(name) {
            Ok(CallableType::UserFunction(func))
        } else {
            Err(Error::Undefined(format!("No such function found in context: {}", name)))
        }
    }
}

pub fn apply(function: &CallableType, args: &[SymbolicExpression],
             env: &mut Environment, context: &Context) -> Result<Value> {
    if let CallableType::SpecialFunction(function) = function {
        function(&args, env, context)
    } else {
        let eval_tried: Result<Vec<Value>> =
            args.iter().map(|x| eval(x, env, context)).collect();
        match eval_tried {
            Ok(evaluated_args) => {
                match function {
                    CallableType::NativeFunction(function) => function(&evaluated_args),
                    CallableType::UserFunction(function) => {
                        // check for recursion.
                        // TODO: we must check for recursion during our static checks!
                        let identifier = function.get_identifier();
                        if env.call_stack.contains(&identifier) {
                            Err(Error::RecursionDetected)
                        } else if env.call_stack.depth() >= MAX_CALL_STACK_DEPTH {
                            Err(Error::MaxStackDepthReached)
                        } else {
                            env.call_stack.insert(&identifier);
                            let resp = function.apply(&evaluated_args, env);
                            env.call_stack.remove(&identifier);
                            resp
                        }
                    },
                    _ => panic!("Should be unreachable.")
                }
            },
            Err(e) => Err(e)
        }
    }
}

pub fn eval <'a> (exp: &SymbolicExpression, env: &'a mut Environment, context: &Context) -> Result<Value> {
    match exp {
        &SymbolicExpression::AtomValue(ref value) => Ok(value.clone()),
        &SymbolicExpression::Atom(ref value) => lookup_variable(&value, context, env),
        &SymbolicExpression::NamedParameter(ref _name) => 
            Err(Error::InvalidArguments("Cannot eval a named parameter".to_string())),
        &SymbolicExpression::List(ref children) => {
            if let Some((function_variable, rest)) = children.split_first() {
                match function_variable {
                    &SymbolicExpression::Atom(ref value) => {
                        let f = lookup_function(&value, env)?;
                        apply(&f, &rest, env, context)
                    },
                    _ => Err(Error::TryEvalToFunction)
                }
            } else {
                Ok(Value::Void)
            }
        }
    }
}


pub fn is_reserved(name: &str) -> bool {
    if let Some(_result) = functions::lookup_reserved_functions(name) {
        true
    } else if variables::is_reserved_variable(name) {
        true
    } else {
        false
    }
}

/* This function evaluates a list of expressions, sharing a global context.
 * It returns the final evaluated result.
 */
fn eval_all(expressions: &[SymbolicExpression],
            database: &mut ContractDatabase,
            global_context: &mut Context) -> Result<Value> {

    let mut last_executed = None;
    let context = Context::new();

    for exp in expressions {
        let try_define = {
            let mut env = Environment::new(
                global_context, database);

            functions::define::evaluate_define(exp, &mut env)
        }?;
        match try_define {
            DefineResult::Variable(name, value) => {
                global_context.variables.insert(name, value);
            },
            DefineResult::Function(name, value) => {
                global_context.functions.insert(name, value);
            },
            DefineResult::Map(name, key_type, value_type) => {
                database.create_map(&name, key_type, value_type);
            },
            DefineResult::NoDefine => {
                // not a define function, evaluate normally.
                let mut env = Environment::new(
                    global_context, database);
                last_executed = Some(eval(exp, &mut env, &context));
            }
        }
    }

    if let Some(result) = last_executed {
        result
    } else {
        Ok(Value::Void)
    }
}

/* Run provided program in a brand new environment, with a transient, empty
 *  database.
 */
pub fn execute(program: &str) -> Result<Value> {
    let mut global_context = Context::new();
    let mut db_instance = Box::new(database::MemoryContractDatabase::new());

    let parsed = parser::parse(program)?;
    eval_all(&parsed, &mut *db_instance, &mut global_context)
}
