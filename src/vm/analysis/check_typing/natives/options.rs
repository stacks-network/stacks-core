use vm::representations::{SymbolicExpression};
use vm::types::{AtomTypeIdentifier, TypeSignature};

use vm::analysis::check_typing::{TypeResult, TypingContext, check_argument_count,
                             CheckError, CheckErrors, no_type, CheckTyping};


pub fn check_special_okay(checker: &mut CheckTyping, args: &[SymbolicExpression], context: &TypingContext) -> TypeResult {
    check_argument_count(1, args)?;
    
    let inner_type = checker.type_check(&args[0], context)?;
    let resp_type = TypeSignature::new_atom(
        AtomTypeIdentifier::ResponseType(Box::new((inner_type, no_type()))));
    Ok(resp_type)
}

pub fn check_special_some(checker: &mut CheckTyping, args: &[SymbolicExpression], context: &TypingContext) -> TypeResult {
    check_argument_count(1, args)?;
    
    let inner_type = checker.type_check(&args[0], context)?;
    let resp_type = TypeSignature::new_atom(
        AtomTypeIdentifier::OptionalType(Box::new(inner_type)));
    Ok(resp_type)
}

pub fn check_special_error(checker: &mut CheckTyping, args: &[SymbolicExpression], context: &TypingContext) -> TypeResult {
    check_argument_count(1, args)?;
    
    let inner_type = checker.type_check(&args[0], context)?;
    let resp_type = TypeSignature::new_atom(
        AtomTypeIdentifier::ResponseType(Box::new((no_type(), inner_type))));
    Ok(resp_type)
}

pub fn check_special_is_okay(checker: &mut CheckTyping, args: &[SymbolicExpression], context: &TypingContext) -> TypeResult {
    check_argument_count(1, args)?;
    
    let input = checker.type_check(&args[0], context)?;

    if let Some(AtomTypeIdentifier::ResponseType(_types)) = input.match_atomic() {
        return Ok(TypeSignature::new_atom(AtomTypeIdentifier::BoolType))
    } else {
        return Err(CheckErrors::ExpectedResponseType(input.clone()).into())
    }
}

pub fn check_special_is_none(checker: &mut CheckTyping, args: &[SymbolicExpression], context: &TypingContext) -> TypeResult {
    check_argument_count(1, args)?;
    
    let input = checker.type_check(&args[0], context)?;

    if let Some(AtomTypeIdentifier::OptionalType(_type)) = input.match_atomic() {
        return Ok(TypeSignature::new_atom(AtomTypeIdentifier::BoolType))
    } else {
        return Err(CheckErrors::ExpectedOptionalType(input.clone()).into())
    }
}

pub fn check_special_default_to(checker: &mut CheckTyping, args: &[SymbolicExpression], context: &TypingContext) -> TypeResult {
    check_argument_count(2, args)?;
    
    let default = checker.type_check(&args[0], context)?;
    let input = checker.type_check(&args[1], context)?;

    if let TypeSignature::Atom(AtomTypeIdentifier::OptionalType(input_type)) = input {
        let contained_type = *input_type;
        TypeSignature::most_admissive(default, contained_type)
            .map_err(|(a,b)| CheckErrors::DefaultTypesMustMatch(a, b).into())
    } else {
        return Err(CheckErrors::ExpectedOptionalType(input).into())
    }
}

pub fn check_special_expects(checker: &mut CheckTyping, args: &[SymbolicExpression], context: &TypingContext) -> TypeResult {
    check_argument_count(2, args)?;
    
    let input = checker.type_check(&args[0], context)?;
    let on_error = checker.type_check(&args[1], context)?;

    checker.track_return_type(on_error)?;

    if let TypeSignature::Atom(atomic_type) = input {
        match atomic_type {
            AtomTypeIdentifier::OptionalType(input_type) => Ok(*input_type),
            AtomTypeIdentifier::ResponseType(response_type) => { 
                let ok_type = response_type.0;
                if ok_type.is_no_type() {
                    Err(CheckErrors::CouldNotDetermineResponseOkType.into())
                } else {
                    Ok(ok_type)
                }
            },
            _ => Err(CheckErrors::ExpectedOptionalType(atomic_type.into()).into())
        }
    } else {
        Err(CheckErrors::ExpectedOptionalType(input).into())
    }
}

pub fn check_special_expects_err(checker: &mut CheckTyping, args: &[SymbolicExpression], context: &TypingContext) -> TypeResult {
    check_argument_count(2, args)?;
    
    let input = checker.type_check(&args[0], context)?;
    let on_error = checker.type_check(&args[1], context)?;

    checker.track_return_type(on_error)?;

    if let TypeSignature::Atom(AtomTypeIdentifier::ResponseType(response_type)) = input {
        let err_type = response_type.1;
        if err_type.is_no_type() {
            Err(CheckErrors::CouldNotDetermineResponseErrType.into())
        } else {
            Ok(err_type)
        }
    } else {
        Err(CheckErrors::ExpectedResponseType(input).into())
    }
}
