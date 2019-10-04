use vm::functions::NativeFunctions;
use vm::representations::{SymbolicExpression};
use vm::types::{ TypeSignature, FunctionType };

use vm::analysis::type_checker::{
    TypeResult, TypingContext, CheckResult, check_argument_count, CheckErrors, no_type, TypeChecker};
use super::{TypedNativeFunction, SimpleNativeFunction};

fn get_simple_native_or_user_define(function_name: &str, checker: &TypeChecker) -> CheckResult<FunctionType> {
    if let Some(ref native_function) = NativeFunctions::lookup_by_name(function_name) {
        if let TypedNativeFunction::Simple(SimpleNativeFunction(function_type)) = TypedNativeFunction::type_native_function(native_function) {
            Ok(function_type)
        } else {
            Err(CheckErrors::IllegalOrUnknownFunctionApplication(function_name.to_string()).into())
        }
    } else {
        checker.get_function_type(function_name)
            .ok_or(CheckErrors::IllegalOrUnknownFunctionApplication(function_name.to_string()).into())
    }
}

pub fn check_special_map(checker: &mut TypeChecker, args: &[SymbolicExpression], context: &TypingContext) -> TypeResult {
    check_argument_count(2, args)?;
    
    let function_name = args[0].match_atom()
        .ok_or(CheckErrors::NonFunctionApplication)?;
    // we will only lookup native or defined functions here.
    //   you _cannot_ map a special function.
    let function_type = get_simple_native_or_user_define(function_name, checker)?;
    
    checker.type_map.set_type(&args[0], no_type())?;
    
    let argument_type = checker.type_check(&args[1], context)?;
    
    let (argument_items_type, argument_length) = match argument_type {
        TypeSignature::ListType(list_data) => Ok(list_data.destruct()),
        _ => Err(CheckErrors::ExpectedListApplication)
    }?;
    
    let mapped_type = function_type.check_args(&[argument_items_type])?;
    
    TypeSignature::list_of(mapped_type, argument_length)
        .map_err(|_| CheckErrors::ConstructedListTooLarge.into())
}

pub fn check_special_filter(checker: &mut TypeChecker, args: &[SymbolicExpression], context: &TypingContext) -> TypeResult {
    check_argument_count(2, args)?;
    
    let function_name = args[0].match_atom()
        .ok_or(CheckErrors::NonFunctionApplication)?;
    // we will only lookup native or defined functions here.
    //   you _cannot_ map a special function.
    let function_type = get_simple_native_or_user_define(function_name, checker)?;
    
    checker.type_map.set_type(&args[0], no_type())?;
    
    let argument_type = checker.type_check(&args[1], context)?;

    {
        let argument_items_type = match &argument_type {
            TypeSignature::ListType(list_data) => Ok(list_data.get_list_item_type()),
            _ => Err(CheckErrors::ExpectedListApplication)
        }?;
    
        let filter_type = function_type.check_args(&[argument_items_type.clone()])?;

        if TypeSignature::BoolType != filter_type {
            return Err(CheckErrors::TypeError(TypeSignature::BoolType, filter_type).into())
        }
    }

    Ok(argument_type)
}

pub fn check_special_fold(checker: &mut TypeChecker, args: &[SymbolicExpression], context: &TypingContext) -> TypeResult {
    check_argument_count(3, args)?;
    
    let function_name = args[0].match_atom()
        .ok_or(CheckErrors::NonFunctionApplication)?;
    // we will only lookup native or defined functions here.
    //   you _cannot_ fold a special function.
    let function_type = get_simple_native_or_user_define(function_name, checker)?;
    
    checker.type_map.set_type(&args[0], no_type())?;
    
    let list_argument_type = checker.type_check(&args[1], context)?;

    let list_items_type = match list_argument_type {
        TypeSignature::ListType(list_data) => Ok(list_data.destruct().0),
        _ => Err(CheckErrors::ExpectedListApplication)
    }?;

    let initial_value_type = checker.type_check(&args[2], context)?;

    // fold: f(A, B) -> A
    //     where A = initial_value_type
    //           B = list items type
    
    // f must accept the initial value and the list items type
    let return_type = function_type.check_args(&[list_items_type.clone(), initial_value_type])?;

    // f must _also_ accepts its own return type!
    let return_type = function_type.check_args(&[return_type, list_items_type])?;
    
    Ok(return_type)
}
