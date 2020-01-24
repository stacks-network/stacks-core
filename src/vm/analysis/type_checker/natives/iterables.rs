use vm::functions::NativeFunctions;
use vm::representations::{SymbolicExpression, SymbolicExpressionType};
use vm::types::{ TypeSignature, FunctionType };
use vm::types::{Value, MAX_VALUE_SIZE};
pub use vm::types::signatures::{ListTypeData, BufferLength};
use std::convert::TryFrom;
use std::convert::TryInto;

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
        
    let argument_type = checker.type_check(&args[1], context)?;
    
    match argument_type {
        TypeSignature::ListType(list_data) => {
            let (arg_items_type, arg_length) = list_data.destruct();
            let mapped_type = function_type.check_args(&[arg_items_type])?;
            TypeSignature::list_of(mapped_type, arg_length)
                .map_err(|_| CheckErrors::ConstructedListTooLarge.into())
        },
        TypeSignature::BufferType(buffer_data) => {
            let mapped_type = function_type.check_args(&[TypeSignature::min_buffer()])?;
            TypeSignature::list_of(mapped_type, buffer_data.into())
                .map_err(|_| CheckErrors::ConstructedListTooLarge.into())
        },
        _ => Err(CheckErrors::ExpectedListOrBuffer(argument_type).into())
    }
}

pub fn check_special_filter(checker: &mut TypeChecker, args: &[SymbolicExpression], context: &TypingContext) -> TypeResult {
    check_argument_count(2, args)?;
    
    let function_name = args[0].match_atom()
        .ok_or(CheckErrors::NonFunctionApplication)?;
    // we will only lookup native or defined functions here.
    //   you _cannot_ map a special function.
    let function_type = get_simple_native_or_user_define(function_name, checker)?;
        
    let argument_type = checker.type_check(&args[1], context)?;

    {
        let input_type = match argument_type {
            TypeSignature::ListType(ref list_data) => Ok(list_data.clone().destruct().0),
            TypeSignature::BufferType(_) => Ok(TypeSignature::min_buffer()),
            _ => Err(CheckErrors::ExpectedListOrBuffer(argument_type.clone()))
        }?;
    
        let filter_type = function_type.check_args(&[input_type])?;

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
    
    let argument_type = checker.type_check(&args[1], context)?;

    let input_type = match argument_type {
        TypeSignature::ListType(list_data) => Ok(list_data.destruct().0),
        TypeSignature::BufferType(_) => Ok(TypeSignature::min_buffer()),
        _ => Err(CheckErrors::ExpectedListOrBuffer(argument_type))
    }?;

    let initial_value_type = checker.type_check(&args[2], context)?;

    // fold: f(A, B) -> A
    //     where A = initial_value_type
    //           B = list items type
    
    // f must accept the initial value and the list items type
    let return_type = function_type.check_args(&[input_type.clone(), initial_value_type])?;

    // f must _also_ accepts its own return type!
    let return_type = function_type.check_args(&[input_type, return_type])?;
    
    Ok(return_type)
}

pub fn check_special_concat(checker: &mut TypeChecker, args: &[SymbolicExpression], context: &TypingContext) -> TypeResult {
    check_argument_count(2, args)?;
    
    let lhs_type = checker.type_check(&args[0], context)?;
    match lhs_type {
        TypeSignature::ListType(lhs_list) => {
            let rhs_type = checker.type_check(&args[1], context)?;
            if let TypeSignature::ListType(rhs_list) = rhs_type {
                let (lhs_entry_type, lhs_max_len) = lhs_list.destruct();
                let (rhs_entry_type, rhs_max_len) = rhs_list.destruct();

                if lhs_entry_type.admits_type(&rhs_entry_type) {
                    let new_len = lhs_max_len.checked_add(rhs_max_len)
                        .ok_or(CheckErrors::MaxLengthOverflow)?;
                    let return_type = TypeSignature::list_of(lhs_entry_type, new_len)?;
                    return Ok(return_type);
                } else {
                    return Err(CheckErrors::TypeError(lhs_entry_type, rhs_entry_type).into());
                }
            } else {
                return Err(CheckErrors::TypeError(rhs_type.clone(), TypeSignature::ListType(lhs_list)).into());
            }
        },
        TypeSignature::BufferType(lhs_buff_len) => {
            let rhs_type = checker.type_check(&args[1], context)?;
            if let TypeSignature::BufferType(rhs_buff_len) = rhs_type {
                let size: u32 = u32::from(lhs_buff_len).checked_add(u32::from(rhs_buff_len))
                    .ok_or(CheckErrors::MaxLengthOverflow)?;
                let return_type = TypeSignature::BufferType(size.try_into()?);
                return Ok(return_type);
            } else {
                return Err(CheckErrors::TypeError(rhs_type.clone(), TypeSignature::max_buffer()).into());
            }
        },
        _ => Err(CheckErrors::ExpectedListOrBuffer(lhs_type.clone()).into())
    }
}

pub fn check_special_append(checker: &mut TypeChecker, args: &[SymbolicExpression], context: &TypingContext) -> TypeResult {
    check_argument_count(2, args)?;

    let lhs_type = checker.type_check(&args[0], context)?;
    match lhs_type {
        TypeSignature::ListType(lhs_list) => {
            let rhs_type = checker.type_check(&args[1], context)?;
            let (lhs_entry_type, lhs_max_len) = lhs_list.destruct();

            if lhs_entry_type.admits_type(&rhs_type) {
                let new_len = lhs_max_len.checked_add(1)
                    .ok_or(CheckErrors::MaxLengthOverflow)?;
                let return_type = TypeSignature::list_of(lhs_entry_type, new_len)?;
                return Ok(return_type);
            } else {
                return Err(CheckErrors::TypeError(lhs_entry_type, rhs_type).into());
            }
        },
        _ => Err(CheckErrors::ExpectedListApplication.into())
    }
}

pub fn check_special_as_max_len(checker: &mut TypeChecker, args: &[SymbolicExpression], context: &TypingContext) -> TypeResult {
    check_argument_count(2, args)?;

    let expected_len = match args[1].expr {
        SymbolicExpressionType::LiteralValue(Value::UInt(expected_len)) => expected_len,
        _ => {
            let expected_len_type = checker.type_check(&args[1], context)?;
            return Err(CheckErrors::TypeError(TypeSignature::UIntType, expected_len_type).into())
        }
    };
    checker.type_map.set_type(&args[1], TypeSignature::UIntType)?;

    let expected_len = u32::try_from(expected_len)
        .map_err(|_e| CheckErrors::MaxLengthOverflow)?;

    let iterable = checker.type_check(&args[0], context)?;
    match iterable {
        TypeSignature::ListType(list) => {
            let (lhs_entry_type, _) = list.destruct();
            let resized_list = ListTypeData::new_list(lhs_entry_type, expected_len)?;
            Ok(TypeSignature::OptionalType(Box::new(TypeSignature::ListType(resized_list))))
        },
        TypeSignature::BufferType(_) => {
            Ok(TypeSignature::OptionalType(Box::new(TypeSignature::BufferType(BufferLength::try_from(expected_len).unwrap()))))
        },
        _ => Err(CheckErrors::ExpectedListOrBuffer(iterable).into())
    }
}

pub fn check_special_len(checker: &mut TypeChecker, args: &[SymbolicExpression], context: &TypingContext) -> TypeResult {
    check_argument_count(1, args)?;

    let collection_type = checker.type_check(&args[0], context)?;

    match collection_type {
        TypeSignature::ListType(_) | TypeSignature::BufferType(_) => Ok(()),
        _ => Err(CheckErrors::ExpectedListOrBuffer(collection_type.clone()))
    }?;

    Ok(TypeSignature::UIntType)
}
