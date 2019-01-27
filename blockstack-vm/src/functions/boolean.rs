use super::super::types::ValueType;
use super::super::errors::Error;
use super::super::representations::SymbolicExpression;
use super::super::{Context,CallStack,eval,InterpreterResult};

fn type_force_bool(value: &ValueType) -> Result<bool, Error> {
    match *value {
        ValueType::BoolType(boolean) => Ok(boolean),
        _ => Err(Error::TypeError("BoolType".to_string(), value.clone()))
    }
}

pub fn special_or(args: &[SymbolicExpression], context: &Context, call_stack: &mut CallStack, global: &Context) -> InterpreterResult {
    if args.len() < 1 {
        return Err(Error::InvalidArguments("(or ...) requires at least 1 argument".to_string()))
    }

    for arg in args.iter() {
        let evaluated = eval(&arg, context, call_stack, global)?;
        let result = type_force_bool(&evaluated)?;
        if result {
            return Ok(ValueType::BoolType(true))
        }
    }

    Ok(ValueType::BoolType(false))
}

pub fn special_and(args: &[SymbolicExpression], context: &Context, call_stack: &mut CallStack, global: &Context) -> InterpreterResult {
    if args.len() < 1 {
        return Err(Error::InvalidArguments("(and ...) requires at least 1 argument".to_string()))
    }

    for arg in args.iter() {
        let evaluated = eval(&arg, context, call_stack, global)?;
        let result = type_force_bool(&evaluated)?;
        if !result {
            return Ok(ValueType::BoolType(false))
        }
    }

    Ok(ValueType::BoolType(true))
}

pub fn native_not(args: &[ValueType]) -> InterpreterResult {
    if args.len() != 1 {
        return Err(Error::InvalidArguments("(not ...) requires exactly 1 argument".to_string()))
    }
    let value = type_force_bool(&args[0])?;
    Ok(ValueType::BoolType(!value))
}
