use super::InterpreterResult;
use super::super::errors::Error;
use super::super::types::{Value, TypeSignature};
use super::super::types::Value::{List};
use super::super::representations::SymbolicExpression;
use super::super::representations::SymbolicExpression::{AtomValue};
use super::super::{Context,Environment,eval,apply,lookup_function};

pub fn list_cons(args: &[Value]) -> InterpreterResult {
    let list_type = TypeSignature::construct_parent_list_type(args)?;
    let mut list_contents = Vec::new();
    for item in args {
        list_contents.push(item.clone());
    }
    Ok(List(list_contents, list_type))
}

pub fn list_fold(args: &[SymbolicExpression], env: &mut Environment, context: &Context) -> InterpreterResult {
    if args.len() != 3 {
        return Err(Error::InvalidArguments(format!("Wrong number of arguments ({}) to fold", args.len())))
    }
    if let SymbolicExpression::Atom(ref function_name) = args[0] {
        let function = lookup_function(&function_name, env)?;
        let list = eval(&args[1], env, context)?;
        let initial = eval(&args[2], env, context)?;
        match list {
            List(vector, _) => vector.iter().try_fold(
                initial,
                |acc, x| {
                    let argument = [ AtomValue(x.clone()), AtomValue(acc) ];
                    apply(&function, &argument, env, context)
                }),
            _ => Err(Error::TypeError("List".to_string(), list))
        }
    } else {
        Err(Error::InvalidArguments("Fold must be called with a function name. We do not support eval'ing to functions.".to_string()))
    }
}

pub fn list_map(args: &[SymbolicExpression], env: &mut Environment, context: &Context) -> InterpreterResult {
    if args.len() != 2 {
        return Err(Error::InvalidArguments(format!("Wrong number of arguments ({}) to map", args.len())))
    }
    if let SymbolicExpression::Atom(ref function_name) = args[0] {
        let function = lookup_function(&function_name, env)?;

        let list = eval(&args[1], env, context)?;
        match list {
            List(vector, _) => {
                let result: Result<Vec<_>, Error> = vector.iter().map(|x| {
                    let argument = [ SymbolicExpression::AtomValue(x.clone()) ];
                    apply(&function, &argument, env, context)
                }).collect();
                let as_vec = result?;
                list_cons(&as_vec)
            },
            _ => Err(Error::TypeError("List".to_string(), list))
        }
    } else {
        Err(Error::InvalidArguments("Map must be called with a function name. We do not support eval'ing to functions.".to_string()))
    }
}
