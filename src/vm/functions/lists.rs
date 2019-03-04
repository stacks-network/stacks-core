use vm::errors::{Error, ErrType, InterpreterResult as Result};
use vm::types::Value;
use vm::representations::SymbolicExpression;
use vm::representations::SymbolicExpression::{AtomValue};
use vm::{LocalContext, Environment, eval, apply, lookup_function};

pub fn list_cons(args: &[Value]) -> Result<Value> {
    Value::new_list(args)
}

pub fn list_fold(args: &[SymbolicExpression], env: &mut Environment, context: &LocalContext) -> Result<Value> {
    if args.len() != 3 {
        return Err(Error::new(ErrType::InvalidArguments(format!("Wrong number of arguments ({}) to fold", args.len()))))
    }
    if let SymbolicExpression::Atom(ref function_name) = args[0] {
        let function = lookup_function(&function_name, env)?;
        let list = eval(&args[1], env, context)?;
        let initial = eval(&args[2], env, context)?;
        match list {
            Value::List(list_data) => list_data.data.iter().try_fold(
                initial,
                |acc, x| {
                    let argument = [ AtomValue(x.clone()), AtomValue(acc) ];
                    apply(&function, &argument, env, context)
                }),
            _ => Err(Error::new(ErrType::TypeError("List".to_string(), list)))
        }
    } else {
        Err(Error::new(ErrType::InvalidArguments("Fold must be called with a function name. We do not support eval'ing to functions.".to_string())))
    }
}

pub fn list_map(args: &[SymbolicExpression], env: &mut Environment, context: &LocalContext) -> Result<Value> {
    if args.len() != 2 {
        return Err(Error::new(ErrType::InvalidArguments(format!("Wrong number of arguments ({}) to map", args.len()))))
    }
    if let SymbolicExpression::Atom(ref function_name) = args[0] {
        let function = lookup_function(&function_name, env)?;

        let list = eval(&args[1], env, context)?;
        match list {
            Value::List(list_data) => {
                let result: Result<Vec<_>> = list_data.data.iter().map(|x| {
                    let argument = [ AtomValue(x.clone()) ];
                    apply(&function, &argument, env, context)
                }).collect();
                let as_vec = result?;
                Value::list_from(as_vec)
            },
            _ => Err(Error::new(ErrType::TypeError("List".to_string(), list)))
        }
    } else {
        Err(Error::new(ErrType::InvalidArguments("Map must be called with a function name. We do not support eval'ing to functions.".to_string())))
    }
}
