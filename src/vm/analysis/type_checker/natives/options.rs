use vm::representations::{SymbolicExpression};
use vm::types::{TypeSignature};

use vm::analysis::type_checker::{TypeResult, TypingContext, check_argument_count,
                                 CheckError, CheckErrors, no_type, TypeChecker};


pub fn check_special_okay(checker: &mut TypeChecker, args: &[SymbolicExpression], context: &TypingContext) -> TypeResult {
    check_argument_count(1, args)?;
    
    let inner_type = checker.type_check(&args[0], context)?;
    let resp_type = TypeSignature::new_response(inner_type, no_type());
    Ok(resp_type)
}

pub fn check_special_some(checker: &mut TypeChecker, args: &[SymbolicExpression], context: &TypingContext) -> TypeResult {
    check_argument_count(1, args)?;
    
    let inner_type = checker.type_check(&args[0], context)?;
    let resp_type = TypeSignature::new_option(inner_type);
    Ok(resp_type)
}

pub fn check_special_error(checker: &mut TypeChecker, args: &[SymbolicExpression], context: &TypingContext) -> TypeResult {
    check_argument_count(1, args)?;
    
    let inner_type = checker.type_check(&args[0], context)?;
    let resp_type = TypeSignature::new_response(no_type(), inner_type);
    Ok(resp_type)
}

pub fn check_special_is_okay(checker: &mut TypeChecker, args: &[SymbolicExpression], context: &TypingContext) -> TypeResult {
    check_argument_count(1, args)?;
    
    let input = checker.type_check(&args[0], context)?;

    if let TypeSignature::ResponseType(_types) = input {
        return Ok(TypeSignature::BoolType)
    } else {
        return Err(CheckErrors::ExpectedResponseType(input.clone()).into())
    }
}

pub fn check_special_is_none(checker: &mut TypeChecker, args: &[SymbolicExpression], context: &TypingContext) -> TypeResult {
    check_argument_count(1, args)?;
    
    let input = checker.type_check(&args[0], context)?;

    if let TypeSignature::OptionalType(_type) = input {
        return Ok(TypeSignature::BoolType)
    } else {
        return Err(CheckErrors::ExpectedOptionalType(input.clone()).into())
    }
}

pub fn check_special_default_to(checker: &mut TypeChecker, args: &[SymbolicExpression], context: &TypingContext) -> TypeResult {
    check_argument_count(2, args)?;
    
    let default = checker.type_check(&args[0], context)?;
    let input = checker.type_check(&args[1], context)?;

    if let TypeSignature::OptionalType(input_type) = input {
        let contained_type = *input_type;
        TypeSignature::least_supertype(&default, &contained_type)
            .map_err(|_| CheckErrors::DefaultTypesMustMatch(default, contained_type).into())
    } else {
        return Err(CheckErrors::ExpectedOptionalType(input).into())
    }
}

pub fn check_special_expects(checker: &mut TypeChecker, args: &[SymbolicExpression], context: &TypingContext) -> TypeResult {
    check_argument_count(2, args)?;
    
    let input = checker.type_check(&args[0], context)?;
    let on_error = checker.type_check(&args[1], context)?;

    checker.track_return_type(on_error)?;

    match input {
        TypeSignature::OptionalType(input_type) => Ok(*input_type),
        TypeSignature::ResponseType(response_type) => { 
            let ok_type = response_type.0;
            if ok_type.is_no_type() {
                Err(CheckErrors::CouldNotDetermineResponseOkType.into())
            } else {
                Ok(ok_type)
            }
        },
        _ => Err(CheckErrors::ExpectedOptionalType(input).into())
    }
}

pub fn check_special_expects_err(checker: &mut TypeChecker, args: &[SymbolicExpression], context: &TypingContext) -> TypeResult {
    check_argument_count(2, args)?;
    
    let input = checker.type_check(&args[0], context)?;
    let on_error = checker.type_check(&args[1], context)?;

    checker.track_return_type(on_error)?;

    if let TypeSignature::ResponseType(response_type) = input {
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
