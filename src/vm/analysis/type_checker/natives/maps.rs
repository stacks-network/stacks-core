use vm::representations::{SymbolicExpression, SymbolicExpressionType};
use vm::types::{TypeSignature, Value, PrincipalData};

use vm::functions::tuples;
use vm::functions::tuples::TupleDefinitionType::{Implicit, Explicit};

use super::check_special_tuple_cons;
use vm::analysis::type_checker::{TypeResult, TypingContext, 
                                 check_arguments_at_least,
                                 CheckError, CheckErrors, no_type, TypeChecker};

pub fn check_special_fetch_entry(checker: &mut TypeChecker, args: &[SymbolicExpression], context: &TypingContext) -> TypeResult {

    check_arguments_at_least(2, args)?;

    let map_name = args[0].match_atom()
        .ok_or(CheckErrors::BadMapName)?;

    let key_type = match tuples::get_definition_type_of_tuple_argument(&args[1]) {
        Implicit(ref inner_expr) => check_special_tuple_cons(checker, inner_expr, context)?,
        Explicit => checker.type_check(&args[1], context)?
    };

    let (expected_key_type, value_type) = checker.contract_context.get_map_type(map_name)
        .ok_or(CheckErrors::NoSuchMap(map_name.to_string()))?;

    let option_type = TypeSignature::new_option(value_type.clone());

    if !expected_key_type.admits_type(&key_type) {
        return Err(CheckError::new(CheckErrors::TypeError(expected_key_type.clone(), key_type)))
    } else {
        return Ok(option_type)
    }
}

pub fn check_special_fetch_contract_entry(checker: &mut TypeChecker, args: &[SymbolicExpression], context: &TypingContext) -> TypeResult {
    check_arguments_at_least(3, args)?;
    

    let contract_identifier = match args[0].expr {
        SymbolicExpressionType::LiteralValue(Value::Principal(PrincipalData::Contract(ref contract_identifier))) => contract_identifier,
        _ => return Err(CheckError::new(CheckErrors::ContractCallExpectName))
    };

    let map_name = args[1].match_atom()
        .ok_or(CheckErrors::BadMapName)?;
    
    checker.type_map.set_type(&args[1], no_type())?;
    
    let key_type = match tuples::get_definition_type_of_tuple_argument(&args[2]) {
        Implicit(ref inner_expr) => check_special_tuple_cons(checker, inner_expr, context)?,
        Explicit => checker.type_check(&args[2], context)?
    };
    
    let (expected_key_type, value_type) = checker.db.get_map_type(&contract_identifier, map_name)?;

    let option_type = TypeSignature::new_option(value_type);
    
    if !expected_key_type.admits_type(&key_type) {
        return Err(CheckError::new(CheckErrors::TypeError(expected_key_type.clone(), key_type)))
    } else {
        return Ok(option_type)
    }
}

pub fn check_special_delete_entry(checker: &mut TypeChecker, args: &[SymbolicExpression], context: &TypingContext) -> TypeResult {
    check_arguments_at_least(2, args)?;

    let map_name = args[0].match_atom()
        .ok_or(CheckErrors::BadMapName)?;

    let key_type = match tuples::get_definition_type_of_tuple_argument(&args[1]) {
        Implicit(ref inner_expr) => check_special_tuple_cons(checker, inner_expr, context)?,
        Explicit => checker.type_check(&args[1], context)?
    };
    
    let (expected_key_type, _) = checker.contract_context.get_map_type(map_name)
        .ok_or(CheckErrors::NoSuchMap(map_name.to_string()))?;
    
    if !expected_key_type.admits_type(&key_type) {
        return Err(CheckError::new(CheckErrors::TypeError(expected_key_type.clone(), key_type)))
    } else {
        return Ok(TypeSignature::BoolType)
    }
}

pub fn check_special_set_entry(checker: &mut TypeChecker, args: &[SymbolicExpression], context: &TypingContext) -> TypeResult {
    check_arguments_at_least(3, args)?;
    
    let map_name = args[0].match_atom()
        .ok_or(CheckErrors::BadMapName)?;
        
    let key_type = match tuples::get_definition_type_of_tuple_argument(&args[1]) {
        Implicit(ref inner_expr) => check_special_tuple_cons(checker, inner_expr, context)?,
        Explicit => checker.type_check(&args[1], context)?
    };

    let value_type = match tuples::get_definition_type_of_tuple_argument(&args[2]) {
        Implicit(ref inner_expr) => check_special_tuple_cons(checker, inner_expr, context)?,
        Explicit => checker.type_check(&args[2], context)?
    };
    
    let (expected_key_type, expected_value_type) = checker.contract_context.get_map_type(map_name)
        .ok_or(CheckErrors::NoSuchMap(map_name.to_string()))?;
    
    if !expected_key_type.admits_type(&key_type) {
        return Err(CheckError::new(CheckErrors::TypeError(expected_key_type.clone(), key_type)))
    } else if !expected_value_type.admits_type(&value_type) {
        return Err(CheckError::new(CheckErrors::TypeError(expected_value_type.clone(), value_type)))
    } else {
        return Ok(TypeSignature::BoolType)
    }
}

pub fn check_special_insert_entry(checker: &mut TypeChecker, args: &[SymbolicExpression], context: &TypingContext) -> TypeResult {
    check_arguments_at_least(3, args)?;
    
    let map_name = args[0].match_atom()
        .ok_or(CheckErrors::BadMapName)?;
        
    let key_type = match tuples::get_definition_type_of_tuple_argument(&args[1]) {
        Implicit(ref inner_expr) => check_special_tuple_cons(checker, inner_expr, context)?,
        Explicit => checker.type_check(&args[1], context)?
    };
    
    let value_type = match tuples::get_definition_type_of_tuple_argument(&args[2]) {
        Implicit(ref inner_expr) => check_special_tuple_cons(checker, inner_expr, context)?,
        Explicit => checker.type_check(&args[2], context)?
    };
        
    let (expected_key_type, expected_value_type) = checker.contract_context.get_map_type(map_name)
        .ok_or(CheckErrors::NoSuchMap(map_name.to_string()))?;
    
    if !expected_key_type.admits_type(&key_type) {
        return Err(CheckError::new(CheckErrors::TypeError(expected_key_type.clone(), key_type)))
    } else if !expected_value_type.admits_type(&value_type) {
        return Err(CheckError::new(CheckErrors::TypeError(expected_value_type.clone(), value_type)))
    } else {
        return Ok(TypeSignature::BoolType)
    }
}
