use vm::representations::{SymbolicExpression};
use vm::types::{TypeSignature, AtomTypeIdentifier, TupleTypeSignature, BlockInfoProperty, MAX_VALUE_SIZE};
use super::{TypeChecker, TypingContext, TypeResult, FunctionType, no_type, check_atomic_type}; 
use vm::checker::errors::{CheckError, CheckErrors, CheckResult, check_argument_count};

pub fn check_special_get_owner(checker: &mut TypeChecker, args: &[SymbolicExpression], context: &TypingContext) -> TypeResult {
    check_argument_count(2, args)?;

    let asset_name = args[0].match_atom()
        .ok_or(CheckErrors::BadAssetName)?;
    checker.type_map.set_type(&args[0], no_type())?;

    let supplied_asset_type = checker.type_check(&args[1], context)?;

    let expected_asset_type = checker.contract_context.get_asset_type(asset_name)
        .ok_or(CheckErrors::NoSuchAsset(asset_name.clone()))?;

    if !expected_asset_type.admits_type(&supplied_asset_type) {
        Err(CheckErrors::TypeError(expected_asset_type.clone(), supplied_asset_type).into())
    } else {
        Ok(AtomTypeIdentifier::OptionalType(
            Box::new(AtomTypeIdentifier::PrincipalType.into())).into())
    }
}

pub fn check_special_get_balance(checker: &mut TypeChecker, args: &[SymbolicExpression], context: &TypingContext) -> TypeResult {
    check_argument_count(2, args)?;

    let asset_name = args[0].match_atom()
        .ok_or(CheckErrors::BadTokenName)?;
    checker.type_map.set_type(&args[0], no_type())?;

    if !checker.contract_context.token_exists(asset_name) {
        return Err(CheckErrors::NoSuchToken(asset_name.clone()).into());
    }

    let supplied_owner_type = checker.type_check(&args[1], context)?;
    let expected_owner_type: TypeSignature = AtomTypeIdentifier::PrincipalType.into();

    if !expected_owner_type.admits_type(&supplied_owner_type) {
        Err(CheckErrors::TypeError(expected_owner_type, supplied_owner_type).into())
    } else {
        Ok(AtomTypeIdentifier::IntType.into())
    }
}

pub fn check_special_mint_asset(checker: &mut TypeChecker, args: &[SymbolicExpression], context: &TypingContext) -> TypeResult {
    check_argument_count(3, args)?;

    let asset_name = args[0].match_atom()
        .ok_or(CheckErrors::BadAssetName)?;
    checker.type_map.set_type(&args[0], no_type())?;

    let supplied_asset_type = checker.type_check(&args[1], context)?;
    let supplied_owner_type = checker.type_check(&args[2], context)?;

    let expected_owner_type: TypeSignature = AtomTypeIdentifier::PrincipalType.into();
    let expected_asset_type = checker.contract_context.get_asset_type(asset_name)
        .ok_or(CheckErrors::NoSuchAsset(asset_name.clone()))?;

    if !expected_asset_type.admits_type(&supplied_asset_type) {
        return Err(CheckErrors::TypeError(expected_asset_type.clone(), supplied_asset_type).into())
    }

    if !expected_owner_type.admits_type(&supplied_owner_type) {
        return Err(CheckErrors::TypeError(expected_owner_type, supplied_owner_type).into())
    }

    Ok(AtomTypeIdentifier::ResponseType(
        Box::new((AtomTypeIdentifier::BoolType.into(),
                  AtomTypeIdentifier::IntType.into()))).into())
}

pub fn check_special_mint_token(checker: &mut TypeChecker, args: &[SymbolicExpression], context: &TypingContext) -> TypeResult {
    check_argument_count(3, args)?;

    let asset_name = args[0].match_atom()
        .ok_or(CheckErrors::BadTokenName)?;
    checker.type_map.set_type(&args[0], no_type())?;

    let supplied_amount = checker.type_check(&args[1], context)?;
    let supplied_owner_type = checker.type_check(&args[2], context)?;

    let expected_amount: TypeSignature = AtomTypeIdentifier::IntType.into();
    let expected_owner_type: TypeSignature = AtomTypeIdentifier::PrincipalType.into();

    if !checker.contract_context.token_exists(asset_name) {
        return Err(CheckErrors::NoSuchToken(asset_name.clone()).into());
    }

    if !expected_amount.admits_type(&supplied_amount) {
        return Err(CheckErrors::TypeError(expected_amount, supplied_amount).into())
    }

    if !expected_owner_type.admits_type(&supplied_owner_type) {
        Err(CheckErrors::TypeError(expected_owner_type, supplied_owner_type).into())
    } else {
        Ok(AtomTypeIdentifier::ResponseType(
            Box::new((AtomTypeIdentifier::BoolType.into(),
                      AtomTypeIdentifier::IntType.into()))).into())
    }
}

pub fn check_special_transfer_asset(checker: &mut TypeChecker, args: &[SymbolicExpression], context: &TypingContext) -> TypeResult {
    check_argument_count(4, args)?;

    let asset_name = args[0].match_atom()
        .ok_or(CheckErrors::BadAssetName)?;
    checker.type_map.set_type(&args[0], no_type())?;

    let supplied_asset_type = checker.type_check(&args[1], context)?;
    let supplied_owner_type = checker.type_check(&args[2], context)?;
    let supplied_recipient_type = checker.type_check(&args[3], context)?;

    let expected_owner_type: TypeSignature = AtomTypeIdentifier::PrincipalType.into();
    let expected_asset_type = checker.contract_context.get_asset_type(asset_name)
        .ok_or(CheckErrors::NoSuchAsset(asset_name.clone()))?;

    if !expected_asset_type.admits_type(&supplied_asset_type) {
        return Err(CheckErrors::TypeError(expected_asset_type.clone(), supplied_asset_type).into())
    }

    if !expected_owner_type.admits_type(&supplied_owner_type) {
        return Err(CheckErrors::TypeError(expected_owner_type, supplied_owner_type).into())
    } else if !expected_owner_type.admits_type(&supplied_recipient_type) {
        return Err(CheckErrors::TypeError(expected_owner_type, supplied_recipient_type).into())
    }

    Ok(AtomTypeIdentifier::ResponseType(
        Box::new((AtomTypeIdentifier::BoolType.into(),
                  AtomTypeIdentifier::IntType.into()))).into())
}

pub fn check_special_transfer_token(checker: &mut TypeChecker, args: &[SymbolicExpression], context: &TypingContext) -> TypeResult {
    check_argument_count(4, args)?;

    let asset_name = args[0].match_atom()
        .ok_or(CheckErrors::BadTokenName)?;
    checker.type_map.set_type(&args[0], no_type())?;


    let supplied_amount = checker.type_check(&args[1], context)?;
    let supplied_owner_type = checker.type_check(&args[2], context)?;
    let supplied_recipient_type = checker.type_check(&args[3], context)?;

    let expected_amount: TypeSignature = AtomTypeIdentifier::IntType.into();
    let expected_owner_type: TypeSignature = AtomTypeIdentifier::PrincipalType.into();

    if !checker.contract_context.token_exists(asset_name) {
        return Err(CheckErrors::NoSuchToken(asset_name.clone()).into());
    }

    if !expected_amount.admits_type(&supplied_amount) {
        return Err(CheckErrors::TypeError(expected_amount, supplied_amount).into())
    }

    if !expected_owner_type.admits_type(&supplied_owner_type) {
        return Err(CheckErrors::TypeError(expected_owner_type, supplied_owner_type).into())
    } else if !expected_owner_type.admits_type(&supplied_recipient_type) {
        return Err(CheckErrors::TypeError(expected_owner_type, supplied_recipient_type).into())
    }

    Ok(AtomTypeIdentifier::ResponseType(
        Box::new((AtomTypeIdentifier::BoolType.into(),
                  AtomTypeIdentifier::IntType.into()))).into())
}
