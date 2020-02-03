use vm::functions::tuples;
use vm::functions::tuples::TupleDefinitionType::{Implicit, Explicit};

use vm::types::{Value, OptionalData, BuffData, PrincipalData, BlockInfoProperty, TypeSignature};
use vm::representations::{SymbolicExpression};
use vm::errors::{Error, InterpreterError, CheckErrors, RuntimeErrorType, InterpreterResult as Result, check_argument_count};
use vm::{eval, LocalContext, Environment};

enum MintAssetErrorCodes { ALREADY_EXIST = 1 }
enum MintTokenErrorCodes { NON_POSITIVE_AMOUNT = 1 }
enum TransferAssetErrorCodes { NOT_OWNED_BY = 1, SENDER_IS_RECIPIENT = 2, DOES_NOT_EXIST = 3 }
enum TransferTokenErrorCodes { NOT_ENOUGH_BALANCE = 1, SENDER_IS_RECIPIENT = 2, NON_POSITIVE_AMOUNT = 3 }
enum StxErrorCodes { NOT_ENOUGH_BALANCE = 1, SENDER_IS_RECIPIENT = 2, NON_POSITIVE_AMOUNT = 3, SENDER_IS_NOT_TX_SENDER = 4 }

macro_rules! clarity_ecode {
    ($thing:expr) => {
        Ok(Value::error(Value::UInt($thing as u128)))
    }
}

pub fn special_stx_transfer(args: &[SymbolicExpression],
                            env: &mut Environment,
                            context: &LocalContext) -> Result<Value> {
    check_argument_count(3, args)?;

    let amount_val = eval(&args[0], env, context)?;
    let from_val   = eval(&args[1], env, context)?;
    let to_val     = eval(&args[2], env, context)?;

    if let (Value::Principal(ref from), Value::Principal(ref to), Value::UInt(amount)) = (&from_val, to_val, amount_val) {
        if amount <= 0 {
            return clarity_ecode!(StxErrorCodes::NON_POSITIVE_AMOUNT)
        }

        if from == to {
            return clarity_ecode!(StxErrorCodes::SENDER_IS_RECIPIENT)
        }

        if Some(&from_val) != env.sender.as_ref() {
            return clarity_ecode!(StxErrorCodes::SENDER_IS_NOT_TX_SENDER)
        }

        let from_bal = env.global_context.database.get_account_stx_balance(&from);
        let to_bal = env.global_context.database.get_account_stx_balance(&to);

        if from_bal < amount {
            return clarity_ecode!(StxErrorCodes::NOT_ENOUGH_BALANCE)
        }

        let final_from_bal = from_bal - amount;
        let final_to_bal = to_bal.checked_add(amount)
            .ok_or(RuntimeErrorType::ArithmeticOverflow)?;

        env.global_context.database.set_account_stx_balance(&from, final_from_bal);
        env.global_context.database.set_account_stx_balance(&to,   final_to_bal);

        env.global_context.log_stx_transfer(&from, amount)?;

        Ok(Value::okay(Value::Bool(true)))

    } else {
        Err(CheckErrors::BadTransferSTXArguments.into())
    }
}

pub fn special_stx_burn(args: &[SymbolicExpression],
                        env: &mut Environment,
                        context: &LocalContext) -> Result<Value> {
    check_argument_count(2, args)?;

    let amount_val = eval(&args[0], env, context)?;
    let from_val   = eval(&args[1], env, context)?;

    if let (Value::Principal(ref from), Value::UInt(amount)) = (&from_val, amount_val) {
        if amount <= 0 {
            return clarity_ecode!(StxErrorCodes::NON_POSITIVE_AMOUNT)
        }

        if Some(&from_val) != env.sender.as_ref() {
            return clarity_ecode!(StxErrorCodes::SENDER_IS_NOT_TX_SENDER)
        }

        let from_bal = env.global_context.database.get_account_stx_balance(&from);

        if from_bal < amount {
            return clarity_ecode!(StxErrorCodes::NOT_ENOUGH_BALANCE)
        }

        let final_from_bal = from_bal - amount;

        env.global_context.database.set_account_stx_balance(&from, final_from_bal);

        env.global_context.log_stx_burn(&from, amount)?;

        Ok(Value::okay(Value::Bool(true)))

    } else {
        Err(CheckErrors::BadTransferSTXArguments.into())
    }
}

pub fn special_mint_token(args: &[SymbolicExpression],
                          env: &mut Environment,
                          context: &LocalContext) -> Result<Value> {
    check_argument_count(3, args)?;

    let token_name = args[0].match_atom()
        .ok_or(CheckErrors::BadTokenName)?;

    let amount = eval(&args[1], env, context)?;
    let to =     eval(&args[2], env, context)?;

    if let (Value::UInt(amount),
            Value::Principal(ref to_principal)) = (amount, to) {
        if amount <= 0 {
            return clarity_ecode!(MintTokenErrorCodes::NON_POSITIVE_AMOUNT);
        }

        env.global_context.database.checked_increase_token_supply(
            &env.contract_context.contract_identifier, token_name, amount)?;

        let to_bal = env.global_context.database.get_ft_balance(&env.contract_context.contract_identifier, token_name, to_principal)?;

        let final_to_bal = to_bal.checked_add(amount)
            .ok_or(RuntimeErrorType::ArithmeticOverflow)?;

        env.global_context.database.set_ft_balance(&env.contract_context.contract_identifier, token_name, to_principal, final_to_bal)?;

        Ok(Value::okay(Value::Bool(true)))
    } else {
        Err(CheckErrors::BadMintFTArguments.into())
    }
}

pub fn special_mint_asset(args: &[SymbolicExpression],
                          env: &mut Environment,
                          context: &LocalContext) -> Result<Value> {
    check_argument_count(3, args)?;

    let asset_name = args[0].match_atom()
        .ok_or(CheckErrors::BadTokenName)?;

    let asset =  eval(&args[1], env, context)?;
    let to    =  eval(&args[2], env, context)?;

    let expected_asset_type = env.global_context.database.get_nft_key_type(&env.contract_context.contract_identifier, asset_name)?;

    if !expected_asset_type.admits(&asset) {
        return Err(CheckErrors::TypeValueError(expected_asset_type, asset).into())
    }

    if let Value::Principal(ref to_principal) = to {
        match env.global_context.database.get_nft_owner(&env.contract_context.contract_identifier, asset_name, &asset) {
            Err(Error::Runtime(RuntimeErrorType::NoSuchToken, _)) => Ok(()),
            Ok(_owner) => return clarity_ecode!(MintAssetErrorCodes::ALREADY_EXIST),
            Err(e) => Err(e)
        }?;

        env.global_context.database.set_nft_owner(&env.contract_context.contract_identifier, asset_name, &asset, to_principal)?;

        Ok(Value::okay(Value::Bool(true)))
    } else {
        Err(CheckErrors::TypeValueError(TypeSignature::PrincipalType, to).into())
    }
}

pub fn special_transfer_asset(args: &[SymbolicExpression],
                              env: &mut Environment,
                              context: &LocalContext) -> Result<Value> {
    check_argument_count(4, args)?;

    let asset_name = args[0].match_atom()
        .ok_or(CheckErrors::BadTokenName)?;

    let asset =  eval(&args[1], env, context)?;
    let from  =  eval(&args[2], env, context)?;
    let to    =  eval(&args[3], env, context)?;

    let expected_asset_type = env.global_context.database.get_nft_key_type(&env.contract_context.contract_identifier, asset_name)?;

    if !expected_asset_type.admits(&asset) {
        return Err(CheckErrors::TypeValueError(expected_asset_type, asset).into())
    }

    if let (Value::Principal(ref from_principal),
            Value::Principal(ref to_principal)) = (from, to) {

        if from_principal == to_principal {
            return clarity_ecode!(TransferAssetErrorCodes::SENDER_IS_RECIPIENT)
        }

        let current_owner = match env.global_context.database.get_nft_owner(&env.contract_context.contract_identifier, asset_name, &asset) {
            Ok(owner) => Ok(owner),
            Err(Error::Runtime(RuntimeErrorType::NoSuchToken, _)) => {
                return clarity_ecode!(TransferAssetErrorCodes::DOES_NOT_EXIST)
            },
            Err(e) => Err(e)
        }?;
            

        if current_owner != *from_principal {
            return clarity_ecode!(TransferAssetErrorCodes::NOT_OWNED_BY)
        }

        env.global_context.database.set_nft_owner(&env.contract_context.contract_identifier, asset_name, &asset, to_principal)?;

        env.global_context.log_asset_transfer(from_principal, &env.contract_context.contract_identifier, asset_name, asset);

        Ok(Value::okay(Value::Bool(true)))
    } else {
        Err(CheckErrors::BadTransferNFTArguments.into())
    }
}

pub fn special_transfer_token(args: &[SymbolicExpression],
                              env: &mut Environment,
                              context: &LocalContext) -> Result<Value> {
    check_argument_count(4, args)?;

    let token_name = args[0].match_atom()
        .ok_or(CheckErrors::BadTokenName)?;

    let amount = eval(&args[1], env, context)?;
    let from =   eval(&args[2], env, context)?;
    let to =     eval(&args[3], env, context)?;

    if let (Value::UInt(amount),
            Value::Principal(ref from_principal),
            Value::Principal(ref to_principal)) = (amount, from, to) {
        if amount <= 0 {
            return clarity_ecode!(TransferTokenErrorCodes::NON_POSITIVE_AMOUNT)
        }

        if from_principal == to_principal {
            return clarity_ecode!(TransferTokenErrorCodes::SENDER_IS_RECIPIENT)
        }

        let from_bal = env.global_context.database.get_ft_balance(&env.contract_context.contract_identifier, token_name, from_principal)?;

        if from_bal < amount {
            return clarity_ecode!(TransferTokenErrorCodes::NOT_ENOUGH_BALANCE)
        }

        let final_from_bal = from_bal - amount;

        let to_bal = env.global_context.database.get_ft_balance(&env.contract_context.contract_identifier, token_name, to_principal)?;

        let final_to_bal = to_bal.checked_add(amount)
            .ok_or(RuntimeErrorType::ArithmeticOverflow)?;

        env.global_context.database.set_ft_balance(&env.contract_context.contract_identifier, token_name, from_principal, final_from_bal)?;
        env.global_context.database.set_ft_balance(&env.contract_context.contract_identifier, token_name, to_principal, final_to_bal)?;

        env.global_context.log_token_transfer(from_principal, &env.contract_context.contract_identifier, token_name, amount)?;

        Ok(Value::okay(Value::Bool(true)))
    } else {
        Err(CheckErrors::BadTransferFTArguments.into())
    }
}

pub fn special_get_balance(args: &[SymbolicExpression],
                           env: &mut Environment,
                           context: &LocalContext) -> Result<Value> {
    check_argument_count(2, args)?;

    let token_name = args[0].match_atom()
        .ok_or(CheckErrors::BadTokenName)?;

    let owner = eval(&args[1], env, context)?;

    if let Value::Principal(ref principal) = owner {
        let balance = env.global_context.database.get_ft_balance(&env.contract_context.contract_identifier, token_name, principal)?;
        Ok(Value::UInt(balance))
    } else {
        Err(CheckErrors::TypeValueError(TypeSignature::PrincipalType, owner).into())
    }

}

pub fn special_get_owner(args: &[SymbolicExpression],
                         env: &mut Environment,
                         context: &LocalContext) -> Result<Value> {
    check_argument_count(2, args)?;

    let asset_name = args[0].match_atom()
        .ok_or(CheckErrors::BadTokenName)?;

    let asset = eval(&args[1], env, context)?;
    let expected_asset_type = env.global_context.database.get_nft_key_type(&env.contract_context.contract_identifier, asset_name)?;

    if !expected_asset_type.admits(&asset) {
        return Err(CheckErrors::TypeValueError(expected_asset_type, asset).into())
    }

    match env.global_context.database.get_nft_owner(&env.contract_context.contract_identifier, asset_name, &asset) {
        Ok(owner) => Ok(Value::some(Value::Principal(owner))),
        Err(Error::Runtime(RuntimeErrorType::NoSuchToken, _)) => Ok(Value::none()),
        Err(e) => Err(e)
    }
}
