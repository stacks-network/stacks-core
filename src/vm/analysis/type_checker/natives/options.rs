use vm::representations::{SymbolicExpression, ClarityName};
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

pub fn check_special_is_response(checker: &mut TypeChecker, args: &[SymbolicExpression], context: &TypingContext) -> TypeResult {
    check_argument_count(1, args)?;
    
    let input = checker.type_check(&args[0], context)?;

    if let TypeSignature::ResponseType(_types) = input {
        return Ok(TypeSignature::BoolType)
    } else {
        return Err(CheckErrors::ExpectedResponseType(input.clone()).into())
    }
}

pub fn check_special_is_optional(checker: &mut TypeChecker, args: &[SymbolicExpression], context: &TypingContext) -> TypeResult {
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

pub fn check_special_asserts(checker: &mut TypeChecker, args: &[SymbolicExpression], context: &TypingContext) -> TypeResult {
    check_argument_count(2, args)?;

    checker.type_check_expects(&args[0], context, &TypeSignature::BoolType)?;
    let on_error = checker.type_check(&args[1], context)?;

    checker.track_return_type(on_error)?;

    Ok(TypeSignature::BoolType)
}

fn inner_unwrap(input: TypeSignature) -> TypeResult {
    match input {
        TypeSignature::OptionalType(input_type) => {
            if input_type.is_no_type() {
                Err(CheckErrors::CouldNotDetermineResponseOkType.into())
            } else {
                Ok(*input_type)
            }
        }
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

fn inner_unwrap_err(input: TypeSignature) -> TypeResult {
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

pub fn check_special_unwrap_or_ret(checker: &mut TypeChecker, args: &[SymbolicExpression], context: &TypingContext) -> TypeResult {
    check_argument_count(2, args)?;
    
    let input = checker.type_check(&args[0], context)?;
    let on_error = checker.type_check(&args[1], context)?;

    checker.track_return_type(on_error)?;

    inner_unwrap(input)
}

pub fn check_special_unwrap_err_or_ret(checker: &mut TypeChecker, args: &[SymbolicExpression], context: &TypingContext) -> TypeResult {
    check_argument_count(2, args)?;
    
    let input = checker.type_check(&args[0], context)?;
    let on_error = checker.type_check(&args[1], context)?;

    checker.track_return_type(on_error)?;

    inner_unwrap_err(input)
}

pub fn check_special_try_bang(checker: &mut TypeChecker, args: &[SymbolicExpression], context: &TypingContext) -> TypeResult {
    check_argument_count(1, args)?;
    
    let input = checker.type_check(&args[0], context)?;

    match input {
        TypeSignature::OptionalType(input_type) => {
            if input_type.is_no_type() {
                Err(CheckErrors::CouldNotDetermineResponseOkType.into())
            } else {
                checker.track_return_type(TypeSignature::new_option(TypeSignature::NoType))?;
                Ok(*input_type)
            }
        }
        TypeSignature::ResponseType(response_type) => { 
            let (ok_type, err_type) = *response_type;
            if ok_type.is_no_type() {
                Err(CheckErrors::CouldNotDetermineResponseOkType.into())
            } else if err_type.is_no_type() {
                Err(CheckErrors::CouldNotDetermineResponseErrType.into())
            } else {
                checker.track_return_type(TypeSignature::new_response(TypeSignature::NoType,
                                                                      err_type))?;
                Ok(ok_type)
            }
        },
        _ => Err(CheckErrors::ExpectedOptionalType(input).into())
    }
}

pub fn check_special_unwrap(checker: &mut TypeChecker, args: &[SymbolicExpression], context: &TypingContext) -> TypeResult {
    check_argument_count(1, args)?;
    
    let input = checker.type_check(&args[0], context)?;

    inner_unwrap(input)
}

pub fn check_special_unwrap_err(checker: &mut TypeChecker, args: &[SymbolicExpression], context: &TypingContext) -> TypeResult {
    check_argument_count(1, args)?;
    
    let input = checker.type_check(&args[0], context)?;

    inner_unwrap_err(input)
}

fn eval_with_new_binding(body: &SymbolicExpression, bind_name: ClarityName, bind_type: TypeSignature, 
                         checker: &mut TypeChecker, context: &TypingContext) -> TypeResult {
    let mut inner_context = context.extend()?;

    checker.contract_context.check_name_used(&bind_name)?;

    if inner_context.lookup_variable_type(&bind_name).is_some() {
        return Err(CheckErrors::NameAlreadyUsed(bind_name.into()).into())
    }

    inner_context.variable_types.insert(bind_name, bind_type);

    checker.type_check(body, &inner_context)
}

pub fn check_special_match_opt(checker: &mut TypeChecker, args: &[SymbolicExpression], context: &TypingContext) -> TypeResult {
    check_argument_count(4, args)?;
    
    let input = checker.type_check(&args[0], context)?;
    let bind_name = args[1].match_atom()
        .ok_or_else(|| CheckErrors::ExpectedName)?
        .clone();
    let some_branch = &args[2];
    let none_branch = &args[3];

    if let TypeSignature::OptionalType(option_type) = input {
        if option_type.is_no_type() {
            return Err(CheckErrors::CouldNotDetermineMatchTypes.into())
        }

        let some_branch_type = eval_with_new_binding(some_branch, bind_name, *option_type,
                                                     checker, context)?;
        let none_branch_type = checker.type_check(none_branch, context)?;

        TypeSignature::least_supertype(&some_branch_type, &none_branch_type)
            .map_err(|_| CheckErrors::MatchArmsMustMatch(some_branch_type, none_branch_type).into())
    } else {
        Err(CheckErrors::ExpectedOptionalType(input.clone()).into())
    }
}

pub fn check_special_match_resp(checker: &mut TypeChecker, args: &[SymbolicExpression], context: &TypingContext) -> TypeResult {
    check_argument_count(5, args)?;
    
    let input = checker.type_check(&args[0], context)?;
    let ok_bind_name = args[1].match_atom()
        .ok_or_else(|| CheckErrors::ExpectedName)?
        .clone();
    let ok_branch = &args[2];
    let err_bind_name = args[3].match_atom()
        .ok_or_else(|| CheckErrors::ExpectedName)?
        .clone();
    let err_branch = &args[4];

    if let TypeSignature::ResponseType(resp_type) = input {
        let (ok_type, err_type) = *resp_type;

        if ok_type.is_no_type() || err_type.is_no_type() {
            return Err(CheckErrors::CouldNotDetermineMatchTypes.into())
        }

        let ok_branch_type = eval_with_new_binding(ok_branch, ok_bind_name, ok_type, checker, context)?;
        let err_branch_type = eval_with_new_binding(err_branch, err_bind_name, err_type, checker, context)?;

        TypeSignature::least_supertype(&ok_branch_type, &err_branch_type)
            .map_err(|_| CheckErrors::MatchArmsMustMatch(ok_branch_type, err_branch_type).into())
    } else {
        Err(CheckErrors::ExpectedResponseType(input.clone()).into())
    }
}
