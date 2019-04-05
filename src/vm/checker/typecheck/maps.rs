use std::collections::HashMap;
use vm::representations::{SymbolicExpression, SymbolicExpressionType};
use vm::representations::SymbolicExpressionType::{AtomValue, Atom, List};
use vm::types::{AtomTypeIdentifier, TypeSignature, Value, TupleTypeSignature, parse_name_type_pairs};
use vm::errors::{ErrType as InterpError};

use super::{TypeResult, TypeMap, TypingContext, type_check, 
            CheckError, CheckResult, CheckErrors, no_type};


pub fn type_check_define_map(map_expression: &[SymbolicExpression],
                         context: &TypingContext, type_map: &mut TypeMap) -> CheckResult<(String, (TypeSignature, TypeSignature))> {
    if map_expression.len() != 4 {
        return Err(CheckError::new(CheckErrors::IncorrectArgumentCount(3, map_expression.len() - 2)))
    }

    type_map.set_type(&map_expression[0], no_type())?;
    type_map.set_type(&map_expression[1], no_type())?;
    type_map.set_type(&map_expression[2], no_type())?;
    type_map.set_type(&map_expression[3], no_type())?;
    // should we set the type of the subexpressions of the signature to no-type as well?

    let map_name = map_expression[1].match_atom()
        .ok_or(CheckError::new(CheckErrors::BadMapName))?;
    let key_type = &map_expression[2];
    let value_type = &map_expression[3];

    let key_type = TypeSignature::new_tuple(
        TupleTypeSignature::parse_name_type_pair_list(key_type)
            .map_err(|_| { CheckError::new(CheckErrors::BadMapTypeDefinition) })?)
        .map_err(|_| { CheckError::new(CheckErrors::BadMapTypeDefinition) })?;
    let value_type = TypeSignature::new_tuple(
        TupleTypeSignature::parse_name_type_pair_list(value_type)
            .map_err(|_| { CheckError::new(CheckErrors::BadMapTypeDefinition) })?)
        .map_err(|_| { CheckError::new(CheckErrors::BadMapTypeDefinition) })?;


    Ok((map_name.to_string(), (key_type, value_type)))
}

pub fn check_special_fetch_entry(args: &[SymbolicExpression], context: &TypingContext, type_map: &mut TypeMap) -> TypeResult {
    if args.len() < 2 {
        return Err(CheckError::new(CheckErrors::IncorrectArgumentCount(2, args.len())))
    }

    let map_name = args[0].match_atom()
        .ok_or(CheckError::new(CheckErrors::BadMapName))?;

    type_map.set_type(&args[0], no_type())?;

    let key_type = type_check(&args[1], context, type_map)?;

    let (expected_key_type, value_type) = context.get_map_type(map_name)
        .ok_or(CheckError::new(CheckErrors::NoSuchMap(map_name.clone())))?;

    if !expected_key_type.admits_type(&key_type) {
        return Err(CheckError::new(CheckErrors::TypeError(expected_key_type.clone(), key_type)))
    } else {
        return Ok(value_type.clone())
    }
}

pub fn check_special_delete_entry(args: &[SymbolicExpression], context: &TypingContext, type_map: &mut TypeMap) -> TypeResult {
    if args.len() < 2 {
        return Err(CheckError::new(CheckErrors::IncorrectArgumentCount(2, args.len())))
    }

    let map_name = args[0].match_atom()
        .ok_or(CheckError::new(CheckErrors::BadMapName))?;

    type_map.set_type(&args[0], no_type())?;

    let key_type = type_check(&args[1], context, type_map)?;

    let (expected_key_type, _) = context.get_map_type(map_name)
        .ok_or(CheckError::new(CheckErrors::NoSuchMap(map_name.clone())))?;

    if !expected_key_type.admits_type(&key_type) {
        return Err(CheckError::new(CheckErrors::TypeError(expected_key_type.clone(), key_type)))
    } else {
        return Ok(TypeSignature::new_atom(AtomTypeIdentifier::BoolType))
    }
}

pub fn check_special_set_entry(args: &[SymbolicExpression], context: &TypingContext, type_map: &mut TypeMap) -> TypeResult {
    if args.len() < 3 {
        return Err(CheckError::new(CheckErrors::IncorrectArgumentCount(3, args.len())))
    }

    let map_name = args[0].match_atom()
        .ok_or(CheckError::new(CheckErrors::BadMapName))?;

    type_map.set_type(&args[0], no_type())?;

    let key_type = type_check(&args[1], context, type_map)?;
    let value_type = type_check(&args[2], context, type_map)?;

    let (expected_key_type, expected_value_type) = context.get_map_type(map_name)
        .ok_or(CheckError::new(CheckErrors::NoSuchMap(map_name.clone())))?;

    if !expected_key_type.admits_type(&key_type) {
        return Err(CheckError::new(CheckErrors::TypeError(expected_key_type.clone(), key_type)))
    } else if !expected_value_type.admits_type(&value_type) {
        return Err(CheckError::new(CheckErrors::TypeError(expected_key_type.clone(), key_type)))
    } else {
        return Ok(TypeSignature::new_atom(AtomTypeIdentifier::VoidType))
    }
}

pub fn check_special_insert_entry(args: &[SymbolicExpression], context: &TypingContext, type_map: &mut TypeMap) -> TypeResult {
    if args.len() < 3 {
        return Err(CheckError::new(CheckErrors::IncorrectArgumentCount(3, args.len())))
    }

    let map_name = args[0].match_atom()
        .ok_or(CheckError::new(CheckErrors::BadMapName))?;

    type_map.set_type(&args[0], no_type())?;

    let key_type = type_check(&args[1], context, type_map)?;
    let value_type = type_check(&args[2], context, type_map)?;

    let (expected_key_type, expected_value_type) = context.get_map_type(map_name)
        .ok_or(CheckError::new(CheckErrors::NoSuchMap(map_name.clone())))?;

    if !expected_key_type.admits_type(&key_type) {
        return Err(CheckError::new(CheckErrors::TypeError(expected_key_type.clone(), key_type)))
    } else if !expected_value_type.admits_type(&value_type) {
        return Err(CheckError::new(CheckErrors::TypeError(expected_key_type.clone(), key_type)))
    } else {
        return Ok(TypeSignature::new_atom(AtomTypeIdentifier::BoolType))
    }
}
