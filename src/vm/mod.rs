extern crate regex;

pub mod errors;
pub mod types;

pub mod contracts;

mod representations;
pub mod parser;
pub mod contexts;
pub mod database;

mod functions;
mod variables;
mod callables;

pub mod checker;

#[cfg(test)]
mod tests;

use vm::types::Value;
use vm::callables::CallableType;
use vm::contexts::{ContractContext, LocalContext, Environment, CallStack};
use vm::contexts::{GlobalContext};
use vm::functions::define::DefineResult;
use vm::errors::{Error, ErrType, InterpreterResult as Result};
use vm::database::{ContractDatabaseConnection};

pub use vm::representations::{SymbolicExpression, SymbolicExpressionType};

const MAX_CALL_STACK_DEPTH: usize = 256;

fn lookup_variable(name: &str, context: &LocalContext, env: &Environment) -> Result<Value> {
    if name.starts_with(char::is_numeric) || name.starts_with('\'') {
        Err(Error::new(ErrType::BadSymbolicRepresentation(format!("Unexpected variable name: {}", name))))
    } else {
        if let Some(value) = variables::lookup_reserved_variable(name, context, env)? {
            Ok(value)
        }else if let Some(value) = context.lookup_variable(name) {
            Ok(value)
        } else if let Some(value) = env.contract_context.lookup_variable(name) {
            Ok(value)
        } else {
            Err(Error::new(ErrType::UndefinedVariable(name.to_string())))
        }
    }
}

pub fn lookup_function(name: &str, env: &Environment)-> Result<CallableType> {
    if let Some(result) = functions::lookup_reserved_functions(name) {
        Ok(result)
    } else {
        let user_function = env.contract_context.lookup_function(name).ok_or(
            Error::new(ErrType::UndefinedFunction(name.to_string())))?;
        Ok(CallableType::UserFunction(user_function))
    }
}

fn add_stack_trace(result: &mut Result<Value>, env: &Environment) {
    if let Err(ref mut e) = result {
        if e.stack_trace.is_none() {
            e.stack_trace.replace(env.call_stack.make_stack_trace());
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
        return Err(Error::new(ErrType::RecursionDetected))
    }

    if env.call_stack.depth() >= MAX_CALL_STACK_DEPTH {
        return Err(Error::new(ErrType::MaxStackDepthReached))
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
            if let Some((function_variable, rest)) = children.split_first() {
                match function_variable.expr {
                    Atom(ref value) => {
                        let f = lookup_function(&value, env)?;
                        apply(&f, &rest, env, context)
                    },
                    _ => Err(Error::new(ErrType::TryEvalToFunction))
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
fn eval_all (expressions: &[SymbolicExpression],
             contract_context: &mut ContractContext,
             global_context: &mut GlobalContext) -> Result<Value> {
    let mut last_executed = None;
    let context = LocalContext::new();

    for exp in expressions {
        let try_define = {
            let mut global_context = GlobalContext::begin_from(&mut global_context.database);
            let define_result = {
                let mut call_stack = CallStack::new();
                let mut env = Environment::new(
                    &mut global_context, contract_context, &mut call_stack, None);
                functions::define::evaluate_define(exp, &mut env)
            }?;
            global_context.commit();
            define_result
        };
        match try_define {
            DefineResult::Variable(name, value) => {
                contract_context.variables.insert(name, value);
            },
            DefineResult::Function(name, value) => {
                contract_context.functions.insert(name, value);
            },
            DefineResult::Map(name, key_type, value_type) => {
                global_context.database.create_map(&contract_context.name, &name, key_type, value_type)?;
            },
            DefineResult::NoDefine => {
                // not a define function, evaluate normally.
                let mut global_context = GlobalContext::begin_from(&mut global_context.database);
                {
                    let mut call_stack = CallStack::new();
                    let mut env = Environment::new(
                        &mut global_context, contract_context, &mut call_stack, None);
                    last_executed = Some(eval(exp, &mut env, &context));
                }
                global_context.commit();
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
    let mut contract_context = ContractContext::new("transient".to_string());
    let mut conn = ContractDatabaseConnection::memory()?;
    let mut global_context = GlobalContext::begin_from(&mut conn);
    let result = {
        let parsed = parser::parse(program)?;
        eval_all(&parsed, &mut contract_context, &mut global_context)
    }?;
    global_context.commit();
    Ok(result)
}


#[cfg(test)]
mod test {
    use vm::database::ContractDatabaseConnection;
    use vm::{Value, LocalContext, GlobalContext, ContractContext, Environment, SymbolicExpression, CallStack};
    use vm::types::{TypeSignature, AtomTypeIdentifier};
    use vm::callables::DefinedFunction;
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
            Box::new([ SymbolicExpression::atom("do_work".to_string()),
                       SymbolicExpression::atom("a".to_string()) ])) ];

        let func_body = SymbolicExpression::list(
            Box::new([ SymbolicExpression::atom("+".to_string()),
                       SymbolicExpression::atom_value(Value::Int(5)),
                       SymbolicExpression::atom("x".to_string())]));

        let func_args = vec![("x".to_string(), TypeSignature::new_atom(AtomTypeIdentifier::IntType))];
        let user_function = DefinedFunction::new_private(func_args, func_body,
                                                         &"do_work", &"");

        let context = LocalContext::new();
        let mut contract_context = ContractContext::new("transient".to_string());

        let mut conn = ContractDatabaseConnection::memory().unwrap();
        let mut global_context = GlobalContext::begin_from(&mut conn);

        contract_context.variables.insert("a".to_string(), Value::Int(59));
        contract_context.functions.insert("do_work".to_string(), user_function);

        let mut call_stack = CallStack::new();
        let mut env = Environment::new(&mut global_context, &contract_context, &mut call_stack, None);
        assert_eq!(Ok(Value::Int(64)), eval(&content[0], &mut env, &context));
    }
}
