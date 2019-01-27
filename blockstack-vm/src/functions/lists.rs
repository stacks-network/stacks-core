use super::InterpreterResult;
use super::super::errors::Error;
use super::super::types::{ValueType, ListTypeIdentifier};
use super::super::types::ValueType::{ListType, IntType, VoidType, BoolType, BufferType};
use super::super::representations::SymbolicExpression;
use super::super::representations::SymbolicExpression::{AtomValue};
use super::super::{Context,CallStack,eval,apply,lookup_function};

fn get_list_type_for(x: &ValueType) -> Result<(ListTypeIdentifier, u8), Error> {
    match x {
        VoidType => Err(Error::InvalidArguments("Cannot construct list of void types".to_string())),
        IntType(_r) => Ok((ListTypeIdentifier::IntType, 0)),
        BoolType(_r) => Ok((ListTypeIdentifier::BoolType, 0)),
        BufferType(_r) => Ok((ListTypeIdentifier::BufferType, 0)),
        ListType(_r, (identifier, list_order)) => Ok((identifier.clone(), list_order + 1))
    }
}

pub fn list_cons(args: &[ValueType]) -> InterpreterResult {
    if let Some((first, _rest)) = args.split_first() {
        let list_type = get_list_type_for(first)?;
        let list_result: Result<Vec<_>, Error> = args.iter().map(|x| {
            let x_type = get_list_type_for(x)?;
            if x_type == list_type {
                Ok(x.clone())
            } else {
                Err(Error::InvalidArguments("List must be composed of a single type".to_string()))
            }
        }).collect();
        let list_contents = list_result?;

        Ok(ListType(list_contents, list_type))
    } else {
        Ok(ListType(Vec::new(),
                    (ListTypeIdentifier::IntType, 0)))        
    }
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
            ListType(vector, _) => vector.iter().try_fold(
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
            ListType(vector, _) => {
                let mut result_value_type: Option<(ListTypeIdentifier, u8)> = None;
                let result: Result<Vec<_>, Error> = vector.iter().map(|x| {
                    let argument = [ SymbolicExpression::AtomValue(x.clone()) ];
                    let value = apply(&function, &argument, context, call_stack, global)?;
                    let value_type = get_list_type_for(&value)?;
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
                    None => Ok(ListType(Vec::new(),
                                        (ListTypeIdentifier::IntType, 0)))
                }
            },
            _ => Err(Error::TypeError("List".to_string(), list))
        }
    } else {
        Err(Error::InvalidArguments("Map must be called with a function name. We do not support eval'ing to functions.".to_string()))
    }
}
