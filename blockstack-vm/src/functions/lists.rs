use super::InterpreterResult;
use super::super::errors::Error;
use super::super::types::{ValueType, TypeSignature};
use super::super::types::ValueType::{ListType};
use super::super::representations::SymbolicExpression;
use super::super::representations::SymbolicExpression::{AtomValue};
use super::super::{Context,Environment,eval,apply,lookup_function};

pub fn list_cons(args: &[ValueType]) -> InterpreterResult {
    if let Some((first, _rest)) = args.split_first() {
        let list_type = TypeSignature::get_list_type_for(first)?;
        let list_result: Result<Vec<_>, Error> = args.iter().map(|x| {
            let x_type = TypeSignature::get_list_type_for(x)?;
            if x_type == list_type {
                Ok(x.clone())
            } else {
                Err(Error::InvalidArguments("List must be composed of a single type".to_string()))
            }
        }).collect();
        let list_contents = list_result?;

        Ok(ListType(list_contents, list_type))
    } else {
        Ok(ListType(Vec::new(), TypeSignature::get_empty_list_type()))
    }
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
            ListType(vector, _) => vector.iter().try_fold(
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
            ListType(vector, _) => {
                let mut result_value_type: Option<TypeSignature> = None;
                let result: Result<Vec<_>, Error> = vector.iter().map(|x| {
                    let argument = [ SymbolicExpression::AtomValue(x.clone()) ];
                    let value = apply(&function, &argument, env, context)?;
                    let value_type = TypeSignature::get_list_type_for(&value)?;
                    if let Some(ref all_type) = result_value_type {
                        if *all_type == value_type {
                            Ok(value)
                        } else {
                            Err(Error::InvalidArguments("Results of map must all be of a single type".to_string()))
                        }
                    } else {
                        result_value_type = Some(value_type);
                        Ok(value)
                    }
                }).collect();
                let vec = result?;
                match result_value_type {
                    Some(value_type) => Ok(ListType(vec, value_type)),
                    None => Ok(ListType(Vec::new(), TypeSignature::get_empty_list_type()))
                }
            },
            _ => Err(Error::TypeError("List".to_string(), list))
        }
    } else {
        Err(Error::InvalidArguments("Map must be called with a function name. We do not support eval'ing to functions.".to_string()))
    }
}
