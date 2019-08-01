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

    let expected_owner_type: TypeSignature = AtomTypeIdentifier::PrincipalType.into();
    checker.type_check_expects(&args[1], context, &expected_owner_type)?;

    Ok(AtomTypeIdentifier::IntType.into())
}

pub fn check_special_mint_asset(checker: &mut TypeChecker, args: &[SymbolicExpression], context: &TypingContext) -> TypeResult {
    check_argument_count(3, args)?;

    let asset_name = args[0].match_atom()
        .ok_or(CheckErrors::BadAssetName)?;
    checker.type_map.set_type(&args[0], no_type())?;

    let expected_owner_type: TypeSignature = AtomTypeIdentifier::PrincipalType.into();
    let expected_asset_type = checker.contract_context.get_asset_type(asset_name)
        .ok_or(CheckErrors::NoSuchAsset(asset_name.clone()))?
        .clone(); // this clone shouldn't be strictly necessary, but to use `type_check_expects` with this, it would have to be.

    checker.type_check_expects(&args[1], context, &expected_asset_type)?;
    checker.type_check_expects(&args[2], context, &expected_owner_type)?;

    Ok(AtomTypeIdentifier::ResponseType(
        Box::new((AtomTypeIdentifier::BoolType.into(),
                  AtomTypeIdentifier::IntType.into()))).into())
}

pub fn check_special_mint_token(checker: &mut TypeChecker, args: &[SymbolicExpression], context: &TypingContext) -> TypeResult {
    check_argument_count(3, args)?;

    let asset_name = args[0].match_atom()
        .ok_or(CheckErrors::BadTokenName)?;
    checker.type_map.set_type(&args[0], no_type())?;

    let expected_amount: TypeSignature = AtomTypeIdentifier::IntType.into();
    let expected_owner_type: TypeSignature = AtomTypeIdentifier::PrincipalType.into();

    checker.type_check_expects(&args[1], context, &expected_amount)?;
    checker.type_check_expects(&args[2], context, &expected_owner_type)?;


    if !checker.contract_context.token_exists(asset_name) {
        return Err(CheckErrors::NoSuchToken(asset_name.clone()).into());
    }
    
    Ok(AtomTypeIdentifier::ResponseType(
        Box::new((AtomTypeIdentifier::BoolType.into(),
                  AtomTypeIdentifier::IntType.into()))).into())
}

pub fn check_special_transfer_asset(checker: &mut TypeChecker, args: &[SymbolicExpression], context: &TypingContext) -> TypeResult {
    check_argument_count(4, args)?;

    let asset_name = args[0].match_atom()
        .ok_or(CheckErrors::BadAssetName)?;
    checker.type_map.set_type(&args[0], no_type())?;

    let expected_owner_type: TypeSignature = AtomTypeIdentifier::PrincipalType.into();
    let expected_asset_type = checker.contract_context.get_asset_type(asset_name)
        .ok_or(CheckErrors::NoSuchAsset(asset_name.clone()))?
        .clone();

    checker.type_check_expects(&args[1], context, &expected_asset_type)?;
    checker.type_check_expects(&args[2], context, &expected_owner_type)?; // owner
    checker.type_check_expects(&args[3], context, &expected_owner_type)?; // recipient

    Ok(AtomTypeIdentifier::ResponseType(
        Box::new((AtomTypeIdentifier::BoolType.into(),
                  AtomTypeIdentifier::IntType.into()))).into())
}

pub fn check_special_transfer_token(checker: &mut TypeChecker, args: &[SymbolicExpression], context: &TypingContext) -> TypeResult {
    check_argument_count(4, args)?;

    let asset_name = args[0].match_atom()
        .ok_or(CheckErrors::BadTokenName)?;
    checker.type_map.set_type(&args[0], no_type())?;

    let expected_amount: TypeSignature = AtomTypeIdentifier::IntType.into();
    let expected_owner_type: TypeSignature = AtomTypeIdentifier::PrincipalType.into();

    checker.type_check_expects(&args[1], context, &expected_amount)?;
    checker.type_check_expects(&args[2], context, &expected_owner_type)?; // owner
    checker.type_check_expects(&args[3], context, &expected_owner_type)?; // recipient

    if !checker.contract_context.token_exists(asset_name) {
        return Err(CheckErrors::NoSuchToken(asset_name.clone()).into());
    }

    Ok(AtomTypeIdentifier::ResponseType(
        Box::new((AtomTypeIdentifier::BoolType.into(),
                  AtomTypeIdentifier::IntType.into()))).into())
}
