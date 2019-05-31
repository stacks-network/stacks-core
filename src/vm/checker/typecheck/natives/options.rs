use vm::representations::{SymbolicExpression};
use vm::types::{AtomTypeIdentifier, TypeSignature};

use vm::checker::typecheck::{TypeResult, TypingContext, 
                             CheckError, CheckErrors, no_type, TypeChecker};


pub fn check_special_okay(checker: &mut TypeChecker, args: &[SymbolicExpression], context: &TypingContext) -> TypeResult {
    if args.len() != 1 {
        return Err(CheckError::new(CheckErrors::IncorrectArgumentCount(1, args.len())))        
    }
    
    let inner_type = checker.type_check(&args[0], context)?;
    let resp_type = TypeSignature::new_atom(
        AtomTypeIdentifier::ResponseType(Box::new((inner_type.clone(), no_type()))));
    Ok(resp_type)
}

pub fn check_special_error(checker: &mut TypeChecker, args: &[SymbolicExpression], context: &TypingContext) -> TypeResult {
    if args.len() != 1 {
        return Err(CheckError::new(CheckErrors::IncorrectArgumentCount(1, args.len())))        
    }
    
    let inner_type = checker.type_check(&args[0], context)?;
    let resp_type = TypeSignature::new_atom(
        AtomTypeIdentifier::ResponseType(Box::new((no_type(), inner_type.clone()))));
    Ok(resp_type)
}

pub fn check_special_is_okay(checker: &mut TypeChecker, args: &[SymbolicExpression], context: &TypingContext) -> TypeResult {
    if args.len() != 1 {
        return Err(CheckError::new(CheckErrors::IncorrectArgumentCount(1, args.len())))
    }
    
    let input = checker.type_check(&args[0], context)?;

    if let Some(AtomTypeIdentifier::ResponseType(_types)) = input.match_atomic() {
        return Ok(TypeSignature::new_atom(AtomTypeIdentifier::BoolType))
    } else {
        return Err(CheckError::new(CheckErrors::ExpectedResponseType))
    }
}

pub fn check_special_is_none(checker: &mut TypeChecker, args: &[SymbolicExpression], context: &TypingContext) -> TypeResult {
    if args.len() != 1 {
        return Err(CheckError::new(CheckErrors::IncorrectArgumentCount(1, args.len())))
    }
    
    let input = checker.type_check(&args[0], context)?;

    if let Some(AtomTypeIdentifier::OptionalType(_type)) = input.match_atomic() {
        return Ok(TypeSignature::new_atom(AtomTypeIdentifier::BoolType))
    } else {
        return Err(CheckError::new(CheckErrors::ExpectedOptionalType))
    }
}

pub fn check_special_default_to(checker: &mut TypeChecker, args: &[SymbolicExpression], context: &TypingContext) -> TypeResult {
    if args.len() != 2 {
        return Err(CheckError::new(CheckErrors::IncorrectArgumentCount(2, args.len())))        
    }
    
    let default = checker.type_check(&args[0], context)?;
    let input = checker.type_check(&args[1], context)?;

    if let Some(AtomTypeIdentifier::OptionalType(input_type)) = input.match_atomic() {
        if input_type.admits_type(&default) {
            return Ok((**input_type).clone())
        } else if default.admits_type(&input_type) {
            return Ok(default)
        } else {
            return Err(CheckError::new(CheckErrors::DefaultTypesMustMatch((**input_type).clone(), default)))
        }
    } else {
        return Err(CheckError::new(CheckErrors::ExpectedOptionalType))
    }
}

pub fn check_special_expects(checker: &mut TypeChecker, args: &[SymbolicExpression], context: &TypingContext) -> TypeResult {
    if args.len() != 2 {
        return Err(CheckError::new(CheckErrors::IncorrectArgumentCount(2, args.len())))        
    }
    
    let input = checker.type_check(&args[0], context)?;
    let on_error = checker.type_check(&args[1], context)?;

    checker.track_return_type(on_error)?;

    match input.match_atomic() {
        Some(AtomTypeIdentifier::OptionalType(input_type)) => Ok((**input_type).clone()),
        Some(AtomTypeIdentifier::ResponseType(response_type)) => Ok((**response_type).0.clone()),
        _ => Err(CheckError::new(CheckErrors::ExpectedOptionalType))
    }
}
