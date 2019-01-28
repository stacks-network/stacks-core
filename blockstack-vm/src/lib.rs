pub mod types;
pub mod representations;
pub mod parser;
pub mod contexts;
pub mod errors;
pub mod database;

mod functions;

use types::{ValueType, CallableType};
use representations::SymbolicExpression;
use contexts::{Context, Environment};
use functions::define::DefineResult;
use errors::Error;

type InterpreterResult = Result<ValueType, Error>;

fn lookup_variable(name: &str, context: &Context, env: &Environment) -> InterpreterResult {
    // first off, are we talking about a constant?
    if name.starts_with(char::is_numeric) {
        match i128::from_str_radix(name, 10) {
            Ok(parsed) => Ok(ValueType::IntType(parsed)),
            Err(_e) => Err(Error::Generic("Failed to parse native int!".to_string()))
        }
    } else if name.starts_with('\'') {
        // Quoted! true or false?
        match &name as &str {
            "'true" => Ok(ValueType::BoolType(true)),
            "'false" => Ok(ValueType::BoolType(false)),
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

pub fn lookup_function<'a> (name: &str, env: &Environment)-> Result<CallableType<'a>, Error> {
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
             env: &mut Environment, context: &Context) -> InterpreterResult {
    if let CallableType::SpecialFunction(function) = function {
        function(&args, env, context)
    } else {
        let eval_tried: Result<Vec<ValueType>, errors::Error> =
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

pub fn eval <'a> (exp: &SymbolicExpression, env: &'a mut Environment, context: &Context) -> InterpreterResult {
    match exp {
        &SymbolicExpression::AtomValue(ref value) => Ok(value.clone()),
        &SymbolicExpression::Atom(ref value) => lookup_variable(&value, context, env),
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
                Ok(ValueType::VoidType)
            }
        }
    }
}


/* This function evaluates a list of expressions, sharing a global context.
 * It returns the final evaluated result.
 */
pub fn eval_all(expressions: &[SymbolicExpression]) -> InterpreterResult {
    let mut env = Environment::new();
    let mut last_executed = None;
    let context = Context::new();

    for exp in expressions {
        let try_define = functions::define::evaluate_define(exp, &mut env)?;
        match try_define {
            DefineResult::Variable(name, value) => {
                env.global_context.variables.insert(name, value);
            },
            DefineResult::Function(name, value) => {
                env.global_context.functions.insert(name, Box::new(value));
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

pub fn execute(program: &str) -> InterpreterResult {
    let parsed = parser::parse(program)?;
    eval_all(&parsed)
}
