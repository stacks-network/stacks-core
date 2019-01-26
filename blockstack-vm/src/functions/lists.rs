use super::InterpreterResult;
use super::super::errors::Error;
use super::super::types::ValueType;
use super::super::types::ValueType::{ListType};
use super::super::representations::SymbolicExpression;
use super::super::representations::SymbolicExpression::{AtomValue};
use super::super::{Context,CallStack,eval,apply,lookup_function};

pub fn list_cons(args: &[ValueType]) -> InterpreterResult {
    Ok(ListType(args.iter().map(|x| x.clone()).collect()))
}

pub fn list_fold(args: &[SymbolicExpression], context: &Context,
                 call_stack: &mut CallStack, global: &Context) -> InterpreterResult {
    if args.len() != 3 {
        return Err(Error::InvalidArguments(format!("Wrong number of arguments ({}) to fold", args.len())))
    }
    if let SymbolicExpression::Atom(ref function_name) = args[0] {
        let function = lookup_function(&function_name, context)?;
        let list = eval(&args[1], context, call_stack, global)?;
        let initial = eval(&args[2], context, call_stack, global)?;
        match list {
            ListType(vector) => vector.iter().try_fold(
                initial,
                |acc, x| {
                    let argument = [ AtomValue(x.clone()), AtomValue(acc) ];
                    apply(&function, &argument, context, call_stack, global)
                }),
            _ => Err(Error::TypeError("List".to_string(), list))
        }
    } else {
        Err(Error::InvalidArguments("Fold must be called with a function name. We do not support eval'ing to functions.".to_string()))
    }
}

pub fn list_map(args: &[SymbolicExpression], context: &Context,
            call_stack: &mut CallStack, global: &Context) -> InterpreterResult {
    if args.len() != 2 {
        return Err(Error::InvalidArguments(format!("Wrong number of arguments ({}) to map", args.len())))
    }
    if let SymbolicExpression::Atom(ref function_name) = args[0] {
        let function = lookup_function(&function_name, context)?;
        let list = eval(&args[1], context, call_stack, global)?;
        match list {
            ListType(vector) => {
                let result: Result<Vec<_>, Error> = vector.iter().map(|x| {
                    let argument = [ SymbolicExpression::AtomValue(x.clone()) ];
                    apply(&function, &argument, context, call_stack, global)
                }).collect();
                let vec = result?;
                Ok(ListType(vec))
            },
            _ => Err(Error::TypeError("List".to_string(), list))
        }
    } else {
        Err(Error::InvalidArguments("Map must be called with a function name. We do not support eval'ing to functions.".to_string()))
    }
}
