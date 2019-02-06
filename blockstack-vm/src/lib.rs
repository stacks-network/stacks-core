pub mod types;
pub mod representations;
pub mod parser;
pub mod contexts;
pub mod errors;
pub mod database;

mod functions;

use types::{Value, CallableType};
use representations::SymbolicExpression;
use contexts::{Context, Environment};
use functions::define::DefineResult;
use errors::{Error, InterpreterResult as Result};

const MAX_CALL_STACK_DEPTH: usize = 128;

fn lookup_variable(name: &str, context: &Context, env: &Environment) -> Result<Value> {
    // TODO: all handling of literals should be done by the lexer. not here.
    if name.starts_with(char::is_numeric) {
        // first off, are we talking about a constant?
        match i128::from_str_radix(name, 10) {
            Ok(parsed) => Ok(Value::Int(parsed)),
            Err(_e) => Err(Error::Generic("Failed to parse native int!".to_string()))
        }
    } else if name.starts_with('\'') {
        // Quoted! true or false?
        match &name as &str {
            "'null" => Ok(Value::Void),
            "'true" => Ok(Value::Bool(true)),
            "'false" => Ok(Value::Bool(false)),
            _ => Err(Error::NotImplemented)
        }
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


/* This function evaluates a list of expressions, sharing a global context.
 * It returns the final evaluated result.
 */
pub fn eval_all(expressions: &[SymbolicExpression],
                contract_db: Option<Box<database::ContractDatabase>>) -> Result<Value> {
    let db_instance = match contract_db {
        Some(db) => db,
        None => Box::new(database::MemoryContractDatabase::new())
    };
    let mut env = Environment::new(db_instance);
    let mut last_executed = None;
    let context = Context::new();

    for exp in expressions {
        let try_define = functions::define::evaluate_define(exp, &mut env)?;
        match try_define {
            DefineResult::Variable(name, value) => {
                env.global_context.variables.insert(name, value);
            },
            DefineResult::Function(name, value) => {
                env.global_context.functions.insert(name, value);
            },
            DefineResult::Map(name, key_type, value_type) => {
                env.database.create_map(&name, key_type, value_type);
            },
            DefineResult::NoDefine => {
                // not a define function, evaluate normally.
                last_executed = Some(eval(exp, &mut env, &context));
            }
        }
    }

    if let Some(result) = last_executed {
        result
    } else {
        Err(Error::Generic("Failed to get response from eval()".to_string()))
    }
}

pub fn execute(program: &str) -> Result<Value> {
    let parsed = parser::parse(program)?;
    eval_all(&parsed, None)
}
