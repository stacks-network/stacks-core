pub mod types;
pub mod representations;
pub mod parser;
pub mod contexts;
pub mod errors;

mod functions;

use types::{ValueType, CallableType};
use representations::SymbolicExpression;
use contexts::{Context, CallStack};
use functions::define::DefineResult;
use errors::Error;

type InterpreterResult = Result<ValueType, Error>;

fn lookup_variable(name: &str, context: &Context) -> InterpreterResult {
    // first off, are we talking about a constant?
    if name.starts_with(char::is_numeric) {
        match u64::from_str_radix(name, 10) {
            Ok(parsed) => Ok(ValueType::IntType(parsed)),
            Err(_e) => Err(Error::Generic("Failed to parse native int!".to_string()))
        }
    } else {
        match context.lookup_variable(name) {
            Some(value) => Ok(value),
            None => Err(Error::Generic(format!("No such variable found in context: {}", name)))
        }
    }
}

pub fn lookup_function<'a> (name: &str, context: &'a Context)-> CallableType<'a> {
    match functions::lookup_reserved_functions(name) {
        Some(result) => result,
        _ => {
            match context.lookup_function(name) {
                Some(func) => { 
                    CallableType::UserFunction(func)
                }
                None => panic!("Crash and burn")
            }
        }
    }
}

pub fn apply(function: &CallableType, args: &[SymbolicExpression],
             context: &Context, call_stack: &mut CallStack, global_context: &Context) -> InterpreterResult {
    if let CallableType::SpecialFunction(function) = function {
        function(&args, &context, call_stack, global_context)
    } else {
        let eval_tried: Result<Vec<ValueType>, errors::Error> =
            args.iter().map(|x| eval(x, context, call_stack, global_context)).collect();
        match eval_tried {
            Ok(evaluated_args) => {
                match function {
                    CallableType::NativeFunction(function) => function(&evaluated_args),
                    CallableType::UserFunction(function) => {
                        // check for recursion.
                        // TODO: we must check for recursion during our static checks!
                        let identifier = function.get_identifier();
                        if call_stack.contains(&identifier) {
                            panic!("Recursion detected");
                        } else {
                            call_stack.insert(&identifier);
                            let resp = function.apply(&evaluated_args, call_stack, global_context);
                            call_stack.remove(&identifier);
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

pub fn eval <'a> (exp: &SymbolicExpression, context: &'a Context<'a>,
                  call_stack: &mut CallStack, global_context: &'a Context<'a>) -> InterpreterResult {
    match exp {
        &SymbolicExpression::AtomValue(ref value) => Ok(value.clone()),
        &SymbolicExpression::Atom(ref value) => lookup_variable(&value, context),
        &SymbolicExpression::List(ref children) => {
            if let Some((function_variable, rest)) = children.split_first() {
                match function_variable {
                    &SymbolicExpression::Atom(ref value) => {
                        let f = lookup_function(&value, &context);
                        apply(&f, &rest, context, call_stack, global_context)
                    },
                    _ => panic!("Attempt to evaluate to function. Illegal!")
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
pub fn eval_all(expressions: &[SymbolicExpression]) -> Result<InterpreterResult, Error> {
    let mut context = Context::new();
    let mut call_stack = CallStack::new();
    let mut last_executed = None;
    for exp in expressions {
        let try_define = functions::define::evaluate_define(exp, &context)?;
        match try_define {
            DefineResult::Variable(name, value) => { context.variables.insert(name, value); },
            DefineResult::Function(name, value) => {
                context.functions.insert(name, Box::new(value));
            },
            DefineResult::NoDefine => {
                // not a define function, evaluate normally.
                last_executed = Some(eval(exp, &context, &mut call_stack, &context));
            }
        }
    }

    if let Some(result) = last_executed {
        Ok(result)
    } else {
        Err(Error::Generic("Failed to get response from eval()".to_string()))
    }
}
