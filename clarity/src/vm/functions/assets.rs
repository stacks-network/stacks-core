// Copyright (C) 2013-2020 Blockstack PBC, a public benefit corporation
// Copyright (C) 2020-2026 Stacks Open Internet Foundation
//
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.
//
// This program is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
// GNU General Public License for more details.
//
// You should have received a copy of the GNU General Public License
// along with this program.  If not, see <http://www.gnu.org/licenses/>.

use stacks_common::types::StacksEpochId;

use crate::vm::contexts::{ExecutionState, InvocationContext};
use crate::vm::costs::cost_functions::ClarityCostFunction;
use crate::vm::costs::{CostTracker, runtime_cost};
use crate::vm::database::STXBalance;
use crate::vm::errors::{
    RuntimeCheckErrorKind, RuntimeError, VmExecutionError, VmInternalError, check_argument_count,
};
use crate::vm::representations::SymbolicExpression;
use crate::vm::types::{
    AssetIdentifier, BuffData, CallableData, PrincipalData, SequenceData, TupleData, TypeSignature,
    Value,
};
use crate::vm::{LocalContext, ValueRef, eval};

/// Normalize a CallableContract value (with no trait) back to its canonical
/// Principal form. This is applied to NFT identifier values so that
/// downstream consumers (asset map, events, postcondition checks) always
/// see the canonical representation.
fn normalize_asset_value(value: ValueRef) -> ValueRef {
    if let Value::CallableContract(CallableData {
        contract_identifier,
        trait_identifier: None,
    }) = value.as_ref()
    {
        ValueRef::Owned(Value::Principal(PrincipalData::Contract(
            contract_identifier.clone(),
        )))
    } else {
        value
    }
}

enum MintAssetErrorCodes {
    ALREADY_EXIST = 1,
}
enum MintTokenErrorCodes {
    NON_POSITIVE_AMOUNT = 1,
}
enum TransferAssetErrorCodes {
    NOT_OWNED_BY = 1,
    SENDER_IS_RECIPIENT = 2,
    DOES_NOT_EXIST = 3,
}
enum TransferTokenErrorCodes {
    NOT_ENOUGH_BALANCE = 1,
    SENDER_IS_RECIPIENT = 2,
    NON_POSITIVE_AMOUNT = 3,
}

enum BurnAssetErrorCodes {
    NOT_OWNED_BY = 1,
    DOES_NOT_EXIST = 3,
}
enum BurnTokenErrorCodes {
    NOT_ENOUGH_BALANCE_OR_NON_POSITIVE = 1,
}

enum StxErrorCodes {
    NOT_ENOUGH_BALANCE = 1,
    SENDER_IS_RECIPIENT = 2,
    NON_POSITIVE_AMOUNT = 3,
    SENDER_IS_NOT_TX_SENDER = 4,
}

macro_rules! clarity_ecode {
    ($thing:expr) => {
        Ok(Value::err_uint($thing as u128))
    };
}

switch_on_global_epoch!(special_mint_asset(
    special_mint_asset_v200,
    special_mint_asset_v205
));

switch_on_global_epoch!(special_transfer_asset(
    special_transfer_asset_v200,
    special_transfer_asset_v205
));

switch_on_global_epoch!(special_get_owner(
    special_get_owner_v200,
    special_get_owner_v205
));

switch_on_global_epoch!(special_burn_asset(
    special_burn_asset_v200,
    special_burn_asset_v205
));

pub fn special_stx_balance(
    args: &[SymbolicExpression],
    exec_state: &mut ExecutionState,
    invoke_ctx: &InvocationContext,
    context: &LocalContext,
) -> Result<Value, VmExecutionError> {
    check_argument_count(1, args)?;

    runtime_cost(ClarityCostFunction::StxBalance, exec_state, 0)?;

    let owner = eval(&args[0], exec_state, invoke_ctx, context)?;

    if let Value::Principal(principal) = owner.as_ref() {
        let balance = {
            let mut snapshot = exec_state
                .global_context
                .database
                .get_stx_balance_snapshot(principal)?;
            snapshot.get_available_balance()?
        };
        Ok(Value::UInt(balance))
    } else {
        Err(RuntimeCheckErrorKind::TypeValueError(
            Box::new(TypeSignature::PrincipalType),
            owner.as_ref().to_error_string(),
        )
        .into())
    }
}

/// Do a "consolidated" STX transfer.
/// If the 'from' principal has locked STX, and they have unlocked, then process the STX unlock
/// and update its balance in addition to spending tokens out of it.
pub fn stx_transfer_consolidated(
    exec_state: &mut ExecutionState,
    invoke_ctx: &InvocationContext,
    from: &PrincipalData,
    to: &PrincipalData,
    amount: u128,
    memo: &BuffData,
) -> Result<Value, VmExecutionError> {
    if amount == 0 {
        return clarity_ecode!(StxErrorCodes::NON_POSITIVE_AMOUNT);
    }

    if from == to {
        return clarity_ecode!(StxErrorCodes::SENDER_IS_RECIPIENT);
    }

    if Some(from) != invoke_ctx.sender.as_ref() {
        return clarity_ecode!(StxErrorCodes::SENDER_IS_NOT_TX_SENDER);
    }

    // loading from/to principals and balances
    exec_state.add_memory(TypeSignature::PrincipalType.size()?.into())?;
    exec_state.add_memory(TypeSignature::PrincipalType.size()?.into())?;
    // loading from's locked amount and height
    // TODO: this does not count the inner stacks block header load, but arguably,
    // this could be optimized away, so it shouldn't penalize the caller.
    exec_state.add_memory(STXBalance::unlocked_and_v1_size as u64)?;
    exec_state.add_memory(STXBalance::unlocked_and_v1_size as u64)?;

    let mut sender_snapshot = exec_state
        .global_context
        .database
        .get_stx_balance_snapshot(from)?;
    if !sender_snapshot.can_transfer(amount)? {
        return clarity_ecode!(StxErrorCodes::NOT_ENOUGH_BALANCE);
    }

    sender_snapshot.transfer_to(to, amount)?;

    exec_state.global_context.log_stx_transfer(from, amount)?;
    exec_state.register_stx_transfer_event(from.clone(), to.clone(), amount, memo.clone())?;
    Ok(Value::okay_true())
}

pub fn special_stx_transfer(
    args: &[SymbolicExpression],
    exec_state: &mut ExecutionState,
    invoke_ctx: &InvocationContext,
    context: &LocalContext,
) -> Result<Value, VmExecutionError> {
    check_argument_count(3, args)?;

    runtime_cost(ClarityCostFunction::StxTransfer, exec_state, 0)?;

    let amount_val = eval(&args[0], exec_state, invoke_ctx, context)?;
    let from_val = eval(&args[1], exec_state, invoke_ctx, context)?;
    let to_val = eval(&args[2], exec_state, invoke_ctx, context)?;
    let memo_val = Value::Sequence(SequenceData::Buffer(BuffData::empty()));

    if let (
        Value::Principal(from),
        Value::Principal(to),
        Value::UInt(amount),
        Value::Sequence(SequenceData::Buffer(memo)),
    ) = (
        from_val.as_ref(),
        to_val.as_ref(),
        amount_val.as_ref(),
        &memo_val,
    ) {
        stx_transfer_consolidated(exec_state, invoke_ctx, from, to, *amount, memo)
    } else {
        Err(RuntimeCheckErrorKind::Unreachable("Bad transfer STX args".to_string()).into())
    }
}

pub fn special_stx_transfer_memo(
    args: &[SymbolicExpression],
    exec_state: &mut ExecutionState,
    invoke_ctx: &InvocationContext,
    context: &LocalContext,
) -> Result<Value, VmExecutionError> {
    check_argument_count(4, args)?;
    runtime_cost(ClarityCostFunction::StxTransferMemo, exec_state, 0)?;

    let amount_val = eval(&args[0], exec_state, invoke_ctx, context)?;
    let from_val = eval(&args[1], exec_state, invoke_ctx, context)?;
    let to_val = eval(&args[2], exec_state, invoke_ctx, context)?;
    let memo_val = eval(&args[3], exec_state, invoke_ctx, context)?;

    if let (
        Value::Principal(from),
        Value::Principal(to),
        Value::UInt(amount),
        Value::Sequence(SequenceData::Buffer(memo)),
    ) = (
        from_val.as_ref(),
        to_val.as_ref(),
        amount_val.as_ref(),
        memo_val.as_ref(),
    ) {
        stx_transfer_consolidated(exec_state, invoke_ctx, from, to, *amount, memo)
    } else {
        Err(RuntimeCheckErrorKind::Unreachable("Bad transfer STX args".to_string()).into())
    }
}

#[allow(clippy::unnecessary_fallible_conversions)]
pub fn special_stx_account(
    args: &[SymbolicExpression],
    exec_state: &mut ExecutionState,
    invoke_ctx: &InvocationContext,
    context: &LocalContext,
) -> Result<Value, VmExecutionError> {
    check_argument_count(1, args)?;

    runtime_cost(ClarityCostFunction::StxGetAccount, exec_state, 0)?;

    let owner = eval(&args[0], exec_state, invoke_ctx, context)?;
    let principal = if let Value::Principal(p) = owner.as_ref() {
        p
    } else {
        return Err(RuntimeCheckErrorKind::TypeValueError(
            Box::new(TypeSignature::PrincipalType),
            owner.as_ref().to_error_string(),
        )
        .into());
    };

    let stx_balance = exec_state
        .global_context
        .database
        .get_stx_balance_snapshot(principal)?
        .canonical_balance_repr()?;
    let v1_unlock_ht = exec_state.global_context.database.get_v1_unlock_height();
    let v2_unlock_ht = exec_state.global_context.database.get_v2_unlock_height()?;
    let v3_unlock_ht = exec_state.global_context.database.get_v3_unlock_height()?;

    Ok(TupleData::from_data(vec![
        (
            "unlocked"
                .try_into()
                .map_err(|_| VmInternalError::Expect("Bad special tuple name".into()))?,
            Value::UInt(stx_balance.amount_unlocked()),
        ),
        (
            "locked"
                .try_into()
                .map_err(|_| VmInternalError::Expect("Bad special tuple name".into()))?,
            Value::UInt(stx_balance.amount_locked()),
        ),
        (
            "unlock-height"
                .try_into()
                .map_err(|_| VmInternalError::Expect("Bad special tuple name".into()))?,
            Value::UInt(u128::from(stx_balance.effective_unlock_height(
                v1_unlock_ht,
                v2_unlock_ht,
                v3_unlock_ht,
            ))),
        ),
    ])
    .map(Value::Tuple)?)
}

pub fn special_stx_burn(
    args: &[SymbolicExpression],
    exec_state: &mut ExecutionState,
    invoke_ctx: &InvocationContext,
    context: &LocalContext,
) -> Result<Value, VmExecutionError> {
    check_argument_count(2, args)?;

    runtime_cost(ClarityCostFunction::StxTransfer, exec_state, 0)?;

    let amount_val = eval(&args[0], exec_state, invoke_ctx, context)?;
    let from_val = eval(&args[1], exec_state, invoke_ctx, context)?;

    if let (Value::Principal(from), Value::UInt(amount)) = (from_val.as_ref(), amount_val.as_ref())
    {
        if *amount == 0 {
            return clarity_ecode!(StxErrorCodes::NON_POSITIVE_AMOUNT);
        }

        if Some(from) != invoke_ctx.sender.as_ref() {
            return clarity_ecode!(StxErrorCodes::SENDER_IS_NOT_TX_SENDER);
        }

        exec_state.add_memory(TypeSignature::PrincipalType.size()?.into())?;
        exec_state.add_memory(STXBalance::unlocked_and_v1_size.try_into().map_err(|_| {
            RuntimeCheckErrorKind::Unreachable(
                "BUG: STXBalance::unlocked_and_v1_size does not fit into a u64".into(),
            )
        })?)?;

        let mut burner_snapshot = exec_state
            .global_context
            .database
            .get_stx_balance_snapshot(from)?;
        if !burner_snapshot.can_transfer(*amount)? {
            return clarity_ecode!(StxErrorCodes::NOT_ENOUGH_BALANCE);
        }

        burner_snapshot.debit(*amount)?;
        burner_snapshot.save()?;

        exec_state
            .global_context
            .database
            .decrement_ustx_liquid_supply(*amount)?;

        exec_state.global_context.log_stx_burn(from, *amount)?;
        exec_state.register_stx_burn_event(from.clone(), *amount)?;

        Ok(Value::okay_true())
    } else {
        Err(RuntimeCheckErrorKind::Unreachable("Bad transfer STX args".to_string()).into())
    }
}

pub fn special_mint_token(
    args: &[SymbolicExpression],
    exec_state: &mut ExecutionState,
    invoke_ctx: &InvocationContext,
    context: &LocalContext,
) -> Result<Value, VmExecutionError> {
    check_argument_count(3, args)?;

    runtime_cost(ClarityCostFunction::FtMint, exec_state, 0)?;

    let token_name = args[0]
        .match_atom()
        .ok_or(RuntimeCheckErrorKind::Unreachable(
            "Bad token name".to_string(),
        ))?;

    let amount = eval(&args[1], exec_state, invoke_ctx, context)?;
    let to = eval(&args[2], exec_state, invoke_ctx, context)?;

    if let (Value::UInt(amount), Value::Principal(to_principal)) = (amount.as_ref(), to.as_ref()) {
        if *amount == 0 {
            return clarity_ecode!(MintTokenErrorCodes::NON_POSITIVE_AMOUNT);
        }

        let ft_info = invoke_ctx.contract_context.meta_ft.get(token_name).ok_or(
            RuntimeCheckErrorKind::Unreachable(format!("No such FT: {token_name}")),
        )?;

        exec_state
            .global_context
            .database
            .checked_increase_token_supply(
                &invoke_ctx.contract_context.contract_identifier,
                token_name,
                *amount,
                ft_info,
            )?;

        let to_bal = exec_state.global_context.database.get_ft_balance(
            &invoke_ctx.contract_context.contract_identifier,
            token_name,
            to_principal,
            Some(ft_info),
        )?;

        let final_to_bal = to_bal
            .checked_add(*amount)
            .ok_or_else(|| VmInternalError::Expect("STX overflow".into()))?;

        exec_state.add_memory(TypeSignature::PrincipalType.size()?.into())?;
        exec_state.add_memory(TypeSignature::UIntType.size()?.into())?;

        exec_state.global_context.database.set_ft_balance(
            &invoke_ctx.contract_context.contract_identifier,
            token_name,
            to_principal,
            final_to_bal,
        )?;

        let asset_identifier = AssetIdentifier {
            contract_identifier: invoke_ctx.contract_context.contract_identifier.clone(),
            asset_name: token_name.clone(),
        };
        exec_state.register_ft_mint_event(to_principal.clone(), *amount, asset_identifier)?;

        Ok(Value::okay_true())
    } else {
        Err(RuntimeCheckErrorKind::Unreachable("Bad mint FT args".to_string()).into())
    }
}

pub fn special_mint_asset_v200(
    args: &[SymbolicExpression],
    exec_state: &mut ExecutionState,
    invoke_ctx: &InvocationContext,
    context: &LocalContext,
) -> Result<Value, VmExecutionError> {
    check_argument_count(3, args)?;

    let asset_name = args[0]
        .match_atom()
        .ok_or(RuntimeCheckErrorKind::Unreachable(
            "Bad token name".to_string(),
        ))?;

    let asset = eval(&args[1], exec_state, invoke_ctx, context)?;
    let to = eval(&args[2], exec_state, invoke_ctx, context)?;

    let nft_metadata = invoke_ctx.contract_context.meta_nft.get(asset_name).ok_or(
        RuntimeCheckErrorKind::Unreachable(format!("No such NFT: {asset_name}")),
    )?;
    let expected_asset_type = &nft_metadata.key_type;

    runtime_cost(
        ClarityCostFunction::NftMint,
        exec_state,
        expected_asset_type.size()?,
    )?;

    if !expected_asset_type.admits(exec_state.epoch(), asset.as_ref())? {
        return Err(RuntimeCheckErrorKind::TypeValueError(
            Box::new(expected_asset_type.clone()),
            asset.as_ref().to_error_string(),
        )
        .into());
    }

    if let Value::Principal(to_principal) = to.as_ref() {
        match exec_state.global_context.database.get_nft_owner(
            &invoke_ctx.contract_context.contract_identifier,
            asset_name,
            asset.as_ref(),
            expected_asset_type,
        ) {
            Err(VmExecutionError::Runtime(RuntimeError::NoSuchToken, _)) => Ok(()),
            Ok(_owner) => return clarity_ecode!(MintAssetErrorCodes::ALREADY_EXIST),
            Err(e) => Err(e),
        }?;

        exec_state.add_memory(TypeSignature::PrincipalType.size()?.into())?;
        exec_state.add_memory(expected_asset_type.size()?.into())?;

        let epoch = *exec_state.epoch();
        exec_state.global_context.database.set_nft_owner(
            &invoke_ctx.contract_context.contract_identifier,
            asset_name,
            asset.as_ref(),
            to_principal,
            expected_asset_type,
            &epoch,
        )?;

        let asset_identifier = AssetIdentifier {
            contract_identifier: invoke_ctx.contract_context.contract_identifier.clone(),
            asset_name: asset_name.clone(),
        };
        let asset = asset.clone_with_cost(exec_state)?;
        exec_state.register_nft_mint_event(to_principal.clone(), asset, asset_identifier)?;

        Ok(Value::okay_true())
    } else {
        Err(RuntimeCheckErrorKind::TypeValueError(
            Box::new(TypeSignature::PrincipalType),
            to.as_ref().to_error_string(),
        )
        .into())
    }
}

/// The Stacks v205 version of mint_asset uses the actual stored size of the
///  asset as input to the cost tabulation. Otherwise identical to v200.
pub fn special_mint_asset_v205(
    args: &[SymbolicExpression],
    exec_state: &mut ExecutionState,
    invoke_ctx: &InvocationContext,
    context: &LocalContext,
) -> Result<Value, VmExecutionError> {
    check_argument_count(3, args)?;

    let asset_name = args[0]
        .match_atom()
        .ok_or(RuntimeCheckErrorKind::Unreachable(
            "Bad token name".to_string(),
        ))?;

    let asset = normalize_asset_value(eval(&args[1], exec_state, invoke_ctx, context)?);
    let to = eval(&args[2], exec_state, invoke_ctx, context)?;

    let nft_metadata = invoke_ctx.contract_context.meta_nft.get(asset_name).ok_or(
        RuntimeCheckErrorKind::Unreachable(format!("No such NFT: {asset_name}")),
    )?;
    let expected_asset_type = &nft_metadata.key_type;

    let asset_size = asset
        .as_ref()
        .serialized_size()
        .map_err(|e| VmInternalError::Expect(e.to_string()))? as u64;
    runtime_cost(ClarityCostFunction::NftMint, exec_state, asset_size)?;

    if !expected_asset_type.admits(exec_state.epoch(), asset.as_ref())? {
        return Err(RuntimeCheckErrorKind::TypeValueError(
            Box::new(expected_asset_type.clone()),
            asset.as_ref().to_error_string(),
        )
        .into());
    }

    if let Value::Principal(to_principal) = to.as_ref() {
        match exec_state.global_context.database.get_nft_owner(
            &invoke_ctx.contract_context.contract_identifier,
            asset_name,
            asset.as_ref(),
            expected_asset_type,
        ) {
            Err(VmExecutionError::Runtime(RuntimeError::NoSuchToken, _)) => Ok(()),
            Ok(_owner) => return clarity_ecode!(MintAssetErrorCodes::ALREADY_EXIST),
            Err(e) => Err(e),
        }?;

        exec_state.add_memory(TypeSignature::PrincipalType.size()?.into())?;
        exec_state.add_memory(asset_size)?;

        let epoch = *exec_state.epoch();
        exec_state.global_context.database.set_nft_owner(
            &invoke_ctx.contract_context.contract_identifier,
            asset_name,
            asset.as_ref(),
            to_principal,
            expected_asset_type,
            &epoch,
        )?;

        let asset_identifier = AssetIdentifier {
            contract_identifier: invoke_ctx.contract_context.contract_identifier.clone(),
            asset_name: asset_name.clone(),
        };
        let asset = asset.clone_with_cost(exec_state)?;
        exec_state.register_nft_mint_event(to_principal.clone(), asset, asset_identifier)?;

        Ok(Value::okay_true())
    } else {
        Err(RuntimeCheckErrorKind::TypeValueError(
            Box::new(TypeSignature::PrincipalType),
            to.as_ref().to_error_string(),
        )
        .into())
    }
}

pub fn special_transfer_asset_v200(
    args: &[SymbolicExpression],
    exec_state: &mut ExecutionState,
    invoke_ctx: &InvocationContext,
    context: &LocalContext,
) -> Result<Value, VmExecutionError> {
    check_argument_count(4, args)?;

    let asset_name = args[0]
        .match_atom()
        .ok_or(RuntimeCheckErrorKind::Unreachable(
            "Bad token name".to_string(),
        ))?;

    let asset = eval(&args[1], exec_state, invoke_ctx, context)?;
    let from = eval(&args[2], exec_state, invoke_ctx, context)?;
    let to = eval(&args[3], exec_state, invoke_ctx, context)?;

    let nft_metadata = invoke_ctx.contract_context.meta_nft.get(asset_name).ok_or(
        RuntimeCheckErrorKind::Unreachable(format!("No such NFT: {asset_name}")),
    )?;
    let expected_asset_type = &nft_metadata.key_type;

    runtime_cost(
        ClarityCostFunction::NftTransfer,
        exec_state,
        expected_asset_type.size()?,
    )?;

    if !expected_asset_type.admits(exec_state.epoch(), asset.as_ref())? {
        return Err(RuntimeCheckErrorKind::TypeValueError(
            Box::new(expected_asset_type.clone()),
            asset.as_ref().to_error_string(),
        )
        .into());
    }

    if let (Value::Principal(from_principal), Value::Principal(to_principal)) =
        (from.as_ref(), to.as_ref())
    {
        if from_principal == to_principal {
            return clarity_ecode!(TransferAssetErrorCodes::SENDER_IS_RECIPIENT);
        }

        let current_owner = match exec_state.global_context.database.get_nft_owner(
            &invoke_ctx.contract_context.contract_identifier,
            asset_name,
            asset.as_ref(),
            expected_asset_type,
        ) {
            Ok(owner) => Ok(owner),
            Err(VmExecutionError::Runtime(RuntimeError::NoSuchToken, _)) => {
                return clarity_ecode!(TransferAssetErrorCodes::DOES_NOT_EXIST);
            }
            Err(e) => Err(e),
        }?;

        if current_owner != *from_principal {
            return clarity_ecode!(TransferAssetErrorCodes::NOT_OWNED_BY);
        }

        exec_state.add_memory(TypeSignature::PrincipalType.size()?.into())?;
        exec_state.add_memory(expected_asset_type.size()?.into())?;

        let epoch = *exec_state.epoch();
        exec_state.global_context.database.set_nft_owner(
            &invoke_ctx.contract_context.contract_identifier,
            asset_name,
            asset.as_ref(),
            to_principal,
            expected_asset_type,
            &epoch,
        )?;

        let asset = asset.clone_with_cost(exec_state)?;
        exec_state.global_context.log_asset_transfer(
            from_principal,
            &invoke_ctx.contract_context.contract_identifier,
            asset_name,
            asset.clone(),
        )?;

        let asset_identifier = AssetIdentifier {
            contract_identifier: invoke_ctx.contract_context.contract_identifier.clone(),
            asset_name: asset_name.clone(),
        };
        exec_state.register_nft_transfer_event(
            from_principal.clone(),
            to_principal.clone(),
            asset,
            asset_identifier,
        )?;

        Ok(Value::okay_true())
    } else {
        Err(RuntimeCheckErrorKind::Unreachable("Bad transfer NFT args".to_string()).into())
    }
}

/// The Stacks v205 version of transfer_asset uses the actual stored size of the
///  asset as input to the cost tabulation. Otherwise identical to v200.
pub fn special_transfer_asset_v205(
    args: &[SymbolicExpression],
    exec_state: &mut ExecutionState,
    invoke_ctx: &InvocationContext,
    context: &LocalContext,
) -> Result<Value, VmExecutionError> {
    check_argument_count(4, args)?;

    let asset_name = args[0]
        .match_atom()
        .ok_or(RuntimeCheckErrorKind::Unreachable(
            "Bad token name".to_string(),
        ))?;

    let asset = normalize_asset_value(eval(&args[1], exec_state, invoke_ctx, context)?);
    let from = eval(&args[2], exec_state, invoke_ctx, context)?;
    let to = eval(&args[3], exec_state, invoke_ctx, context)?;

    let nft_metadata = invoke_ctx.contract_context.meta_nft.get(asset_name).ok_or(
        RuntimeCheckErrorKind::Unreachable(format!("No such NFT: {asset_name}")),
    )?;
    let expected_asset_type = &nft_metadata.key_type;

    let asset_size = asset
        .as_ref()
        .serialized_size()
        .map_err(|e| VmInternalError::Expect(e.to_string()))? as u64;
    runtime_cost(ClarityCostFunction::NftTransfer, exec_state, asset_size)?;

    if !expected_asset_type.admits(exec_state.epoch(), asset.as_ref())? {
        return Err(RuntimeCheckErrorKind::TypeValueError(
            Box::new(expected_asset_type.clone()),
            asset.as_ref().to_error_string(),
        )
        .into());
    }

    if let (Value::Principal(from_principal), Value::Principal(to_principal)) =
        (from.as_ref(), to.as_ref())
    {
        if from_principal == to_principal {
            return clarity_ecode!(TransferAssetErrorCodes::SENDER_IS_RECIPIENT);
        }

        let current_owner = match exec_state.global_context.database.get_nft_owner(
            &invoke_ctx.contract_context.contract_identifier,
            asset_name,
            asset.as_ref(),
            expected_asset_type,
        ) {
            Ok(owner) => Ok(owner),
            Err(VmExecutionError::Runtime(RuntimeError::NoSuchToken, _)) => {
                return clarity_ecode!(TransferAssetErrorCodes::DOES_NOT_EXIST);
            }
            Err(e) => Err(e),
        }?;

        if current_owner != *from_principal {
            return clarity_ecode!(TransferAssetErrorCodes::NOT_OWNED_BY);
        }

        exec_state.add_memory(TypeSignature::PrincipalType.size()?.into())?;
        exec_state.add_memory(asset_size)?;

        let epoch = *exec_state.epoch();
        exec_state.global_context.database.set_nft_owner(
            &invoke_ctx.contract_context.contract_identifier,
            asset_name,
            asset.as_ref(),
            to_principal,
            expected_asset_type,
            &epoch,
        )?;

        let asset = asset.clone_with_cost(exec_state)?;
        exec_state.global_context.log_asset_transfer(
            from_principal,
            &invoke_ctx.contract_context.contract_identifier,
            asset_name,
            asset.clone(),
        )?;

        let asset_identifier = AssetIdentifier {
            contract_identifier: invoke_ctx.contract_context.contract_identifier.clone(),
            asset_name: asset_name.clone(),
        };
        exec_state.register_nft_transfer_event(
            from_principal.clone(),
            to_principal.clone(),
            asset,
            asset_identifier,
        )?;

        Ok(Value::okay_true())
    } else {
        Err(RuntimeCheckErrorKind::Unreachable("Bad transfer NFT args".to_string()).into())
    }
}

pub fn special_transfer_token(
    args: &[SymbolicExpression],
    exec_state: &mut ExecutionState,
    invoke_ctx: &InvocationContext,
    context: &LocalContext,
) -> Result<Value, VmExecutionError> {
    check_argument_count(4, args)?;

    runtime_cost(ClarityCostFunction::FtTransfer, exec_state, 0)?;

    let token_name = args[0]
        .match_atom()
        .ok_or(RuntimeCheckErrorKind::Unreachable(
            "Bad token name".to_string(),
        ))?;

    let amount = eval(&args[1], exec_state, invoke_ctx, context)?;
    let from = eval(&args[2], exec_state, invoke_ctx, context)?;
    let to = eval(&args[3], exec_state, invoke_ctx, context)?;

    if let (Value::UInt(amount), Value::Principal(from_principal), Value::Principal(to_principal)) =
        (amount.as_ref(), from.as_ref(), to.as_ref())
    {
        if *amount == 0 {
            return clarity_ecode!(TransferTokenErrorCodes::NON_POSITIVE_AMOUNT);
        }

        if from_principal == to_principal {
            return clarity_ecode!(TransferTokenErrorCodes::SENDER_IS_RECIPIENT);
        }

        let ft_info = invoke_ctx.contract_context.meta_ft.get(token_name).ok_or(
            RuntimeCheckErrorKind::Unreachable(format!("No such FT: {token_name}")),
        )?;

        let from_bal = exec_state.global_context.database.get_ft_balance(
            &invoke_ctx.contract_context.contract_identifier,
            token_name,
            from_principal,
            Some(ft_info),
        )?;

        if from_bal < *amount {
            return clarity_ecode!(TransferTokenErrorCodes::NOT_ENOUGH_BALANCE);
        }

        let final_from_bal = from_bal - *amount;

        let to_bal = exec_state.global_context.database.get_ft_balance(
            &invoke_ctx.contract_context.contract_identifier,
            token_name,
            to_principal,
            Some(ft_info),
        )?;

        // `ArithmeticOverflow` in this function is **unreachable** in normal Clarity execution because:
        // - the total liquid ustx supply will overflow before such an overflowing transfer is allowed.
        let final_to_bal = to_bal
            .checked_add(*amount)
            .ok_or(RuntimeError::ArithmeticOverflow)?;

        exec_state.add_memory(TypeSignature::PrincipalType.size()?.into())?;
        exec_state.add_memory(TypeSignature::PrincipalType.size()?.into())?;
        exec_state.add_memory(TypeSignature::UIntType.size()?.into())?;
        exec_state.add_memory(TypeSignature::UIntType.size()?.into())?;

        exec_state.global_context.database.set_ft_balance(
            &invoke_ctx.contract_context.contract_identifier,
            token_name,
            from_principal,
            final_from_bal,
        )?;
        exec_state.global_context.database.set_ft_balance(
            &invoke_ctx.contract_context.contract_identifier,
            token_name,
            to_principal,
            final_to_bal,
        )?;

        exec_state.global_context.log_token_transfer(
            from_principal,
            &invoke_ctx.contract_context.contract_identifier,
            token_name,
            *amount,
        )?;

        let asset_identifier = AssetIdentifier {
            contract_identifier: invoke_ctx.contract_context.contract_identifier.clone(),
            asset_name: token_name.clone(),
        };
        exec_state.register_ft_transfer_event(
            from_principal.clone(),
            to_principal.clone(),
            *amount,
            asset_identifier,
        )?;

        Ok(Value::okay_true())
    } else {
        Err(RuntimeCheckErrorKind::Unreachable("Bad transfer FT args".to_string()).into())
    }
}

pub fn special_get_balance(
    args: &[SymbolicExpression],
    exec_state: &mut ExecutionState,
    invoke_ctx: &InvocationContext,
    context: &LocalContext,
) -> Result<Value, VmExecutionError> {
    check_argument_count(2, args)?;

    runtime_cost(ClarityCostFunction::FtBalance, exec_state, 0)?;

    let token_name = args[0]
        .match_atom()
        .ok_or(RuntimeCheckErrorKind::Unreachable(
            "Bad token name".to_string(),
        ))?;

    let owner = eval(&args[1], exec_state, invoke_ctx, context)?;

    if let Value::Principal(principal) = owner.as_ref() {
        let ft_info = invoke_ctx.contract_context.meta_ft.get(token_name).ok_or(
            RuntimeCheckErrorKind::Unreachable(format!("No such FT: {token_name}")),
        )?;

        let balance = exec_state.global_context.database.get_ft_balance(
            &invoke_ctx.contract_context.contract_identifier,
            token_name,
            principal,
            Some(ft_info),
        )?;
        Ok(Value::UInt(balance))
    } else {
        Err(RuntimeCheckErrorKind::TypeValueError(
            Box::new(TypeSignature::PrincipalType),
            owner.as_ref().to_error_string(),
        )
        .into())
    }
}

pub fn special_get_owner_v200(
    args: &[SymbolicExpression],
    exec_state: &mut ExecutionState,
    invoke_ctx: &InvocationContext,
    context: &LocalContext,
) -> Result<Value, VmExecutionError> {
    check_argument_count(2, args)?;

    let asset_name = args[0]
        .match_atom()
        .ok_or(RuntimeCheckErrorKind::Unreachable(
            "Bad token name".to_string(),
        ))?;

    let asset = eval(&args[1], exec_state, invoke_ctx, context)?;

    let nft_metadata = invoke_ctx.contract_context.meta_nft.get(asset_name).ok_or(
        RuntimeCheckErrorKind::Unreachable(format!("No such NFT: {asset_name}")),
    )?;
    let expected_asset_type = &nft_metadata.key_type;

    runtime_cost(
        ClarityCostFunction::NftOwner,
        exec_state,
        expected_asset_type.size()?,
    )?;

    if !expected_asset_type.admits(exec_state.epoch(), asset.as_ref())? {
        return Err(RuntimeCheckErrorKind::TypeValueError(
            Box::new(expected_asset_type.clone()),
            asset.as_ref().to_error_string(),
        )
        .into());
    }

    match exec_state.global_context.database.get_nft_owner(
        &invoke_ctx.contract_context.contract_identifier,
        asset_name,
        asset.as_ref(),
        expected_asset_type,
    ) {
        Ok(owner) => Ok(Value::some(Value::Principal(owner)).map_err(|_| {
            VmInternalError::Expect("Principal should always fit in optional.".into())
        })?),
        Err(VmExecutionError::Runtime(RuntimeError::NoSuchToken, _)) => Ok(Value::none()),
        Err(e) => Err(e),
    }
}

/// The Stacks v205 version of get_owner uses the actual stored size of the
///  asset as input to the cost tabulation. Otherwise identical to v200.
pub fn special_get_owner_v205(
    args: &[SymbolicExpression],
    exec_state: &mut ExecutionState,
    invoke_ctx: &InvocationContext,
    context: &LocalContext,
) -> Result<Value, VmExecutionError> {
    check_argument_count(2, args)?;

    let asset_name = args[0]
        .match_atom()
        .ok_or(RuntimeCheckErrorKind::Unreachable(
            "Bad token name".to_string(),
        ))?;

    let asset = eval(&args[1], exec_state, invoke_ctx, context)?;

    let nft_metadata = invoke_ctx.contract_context.meta_nft.get(asset_name).ok_or(
        RuntimeCheckErrorKind::Unreachable(format!("No such NFT: {asset_name}")),
    )?;
    let expected_asset_type = &nft_metadata.key_type;

    let asset_size = asset
        .as_ref()
        .serialized_size()
        .map_err(|e| VmInternalError::Expect(e.to_string()))? as u64;
    runtime_cost(ClarityCostFunction::NftOwner, exec_state, asset_size)?;

    if !expected_asset_type.admits(exec_state.epoch(), asset.as_ref())? {
        return Err(RuntimeCheckErrorKind::TypeValueError(
            Box::new(expected_asset_type.clone()),
            asset.as_ref().to_error_string(),
        )
        .into());
    }

    match exec_state.global_context.database.get_nft_owner(
        &invoke_ctx.contract_context.contract_identifier,
        asset_name,
        asset.as_ref(),
        expected_asset_type,
    ) {
        Ok(owner) => Ok(Value::some(Value::Principal(owner)).map_err(|_| {
            VmInternalError::Expect("Principal should always fit in optional.".into())
        })?),
        Err(VmExecutionError::Runtime(RuntimeError::NoSuchToken, _)) => Ok(Value::none()),
        Err(e) => Err(e),
    }
}

pub fn special_get_token_supply(
    args: &[SymbolicExpression],
    exec_state: &mut ExecutionState,
    invoke_ctx: &InvocationContext,
    _context: &LocalContext,
) -> Result<Value, VmExecutionError> {
    check_argument_count(1, args)?;

    runtime_cost(ClarityCostFunction::FtSupply, exec_state, 0)?;

    let token_name = args[0]
        .match_atom()
        .ok_or(RuntimeCheckErrorKind::Unreachable(
            "Bad token name".to_string(),
        ))?;

    let supply = exec_state
        .global_context
        .database
        .get_ft_supply(&invoke_ctx.contract_context.contract_identifier, token_name)?;
    Ok(Value::UInt(supply))
}

pub fn special_burn_token(
    args: &[SymbolicExpression],
    exec_state: &mut ExecutionState,
    invoke_ctx: &InvocationContext,
    context: &LocalContext,
) -> Result<Value, VmExecutionError> {
    check_argument_count(3, args)?;

    runtime_cost(ClarityCostFunction::FtBurn, exec_state, 0)?;

    let token_name = args[0]
        .match_atom()
        .ok_or(RuntimeCheckErrorKind::Unreachable(
            "Bad token name".to_string(),
        ))?;

    let amount = eval(&args[1], exec_state, invoke_ctx, context)?;
    let from = eval(&args[2], exec_state, invoke_ctx, context)?;

    if let (Value::UInt(amount), Value::Principal(burner)) = (amount.as_ref(), from.as_ref()) {
        if *amount == 0 {
            return clarity_ecode!(BurnTokenErrorCodes::NOT_ENOUGH_BALANCE_OR_NON_POSITIVE);
        }

        let burner_bal = exec_state.global_context.database.get_ft_balance(
            &invoke_ctx.contract_context.contract_identifier,
            token_name,
            burner,
            None,
        )?;

        if *amount > burner_bal {
            return clarity_ecode!(BurnTokenErrorCodes::NOT_ENOUGH_BALANCE_OR_NON_POSITIVE);
        }

        exec_state
            .global_context
            .database
            .checked_decrease_token_supply(
                &invoke_ctx.contract_context.contract_identifier,
                token_name,
                *amount,
            )?;

        let final_burner_bal = burner_bal - amount;

        exec_state.global_context.database.set_ft_balance(
            &invoke_ctx.contract_context.contract_identifier,
            token_name,
            burner,
            final_burner_bal,
        )?;

        let asset_identifier = AssetIdentifier {
            contract_identifier: invoke_ctx.contract_context.contract_identifier.clone(),
            asset_name: token_name.clone(),
        };
        exec_state.register_ft_burn_event(burner.clone(), *amount, asset_identifier)?;

        exec_state.add_memory(TypeSignature::PrincipalType.size()?.into())?;
        exec_state.add_memory(TypeSignature::UIntType.size()?.into())?;

        exec_state.global_context.log_token_transfer(
            burner,
            &invoke_ctx.contract_context.contract_identifier,
            token_name,
            *amount,
        )?;

        Ok(Value::okay_true())
    } else {
        Err(RuntimeCheckErrorKind::Unreachable("Bad burn FT args".to_string()).into())
    }
}

pub fn special_burn_asset_v200(
    args: &[SymbolicExpression],
    exec_state: &mut ExecutionState,
    invoke_ctx: &InvocationContext,
    context: &LocalContext,
) -> Result<Value, VmExecutionError> {
    check_argument_count(3, args)?;

    runtime_cost(ClarityCostFunction::NftBurn, exec_state, 0)?;

    let asset_name = args[0]
        .match_atom()
        .ok_or(RuntimeCheckErrorKind::Unreachable(
            "Bad token name".to_string(),
        ))?;

    let asset = eval(&args[1], exec_state, invoke_ctx, context)?;
    let sender = eval(&args[2], exec_state, invoke_ctx, context)?;

    let nft_metadata = invoke_ctx.contract_context.meta_nft.get(asset_name).ok_or(
        RuntimeCheckErrorKind::Unreachable(format!("No such NFT: {asset_name}")),
    )?;
    let expected_asset_type = &nft_metadata.key_type;

    runtime_cost(
        ClarityCostFunction::NftBurn,
        exec_state,
        expected_asset_type.size()?,
    )?;

    if !expected_asset_type.admits(exec_state.epoch(), asset.as_ref())? {
        return Err(RuntimeCheckErrorKind::TypeValueError(
            Box::new(expected_asset_type.clone()),
            asset.as_ref().to_error_string(),
        )
        .into());
    }

    if let Value::Principal(sender_principal) = sender.as_ref() {
        let owner = match exec_state.global_context.database.get_nft_owner(
            &invoke_ctx.contract_context.contract_identifier,
            asset_name,
            asset.as_ref(),
            expected_asset_type,
        ) {
            Err(VmExecutionError::Runtime(RuntimeError::NoSuchToken, _)) => {
                return clarity_ecode!(BurnAssetErrorCodes::DOES_NOT_EXIST);
            }
            Ok(owner) => Ok(owner),
            Err(e) => Err(e),
        }?;

        if &owner != sender_principal {
            return clarity_ecode!(BurnAssetErrorCodes::NOT_OWNED_BY);
        }

        exec_state.add_memory(TypeSignature::PrincipalType.size()?.into())?;
        exec_state.add_memory(expected_asset_type.size()?.into())?;

        let epoch = *exec_state.epoch();
        exec_state.global_context.database.burn_nft(
            &invoke_ctx.contract_context.contract_identifier,
            asset_name,
            asset.as_ref(),
            expected_asset_type,
            &epoch,
        )?;

        let asset = asset.clone_with_cost(exec_state)?;
        exec_state.global_context.log_asset_transfer(
            sender_principal,
            &invoke_ctx.contract_context.contract_identifier,
            asset_name,
            asset.clone(),
        )?;

        let asset_identifier = AssetIdentifier {
            contract_identifier: invoke_ctx.contract_context.contract_identifier.clone(),
            asset_name: asset_name.clone(),
        };
        exec_state.register_nft_burn_event(sender_principal.clone(), asset, asset_identifier)?;

        Ok(Value::okay_true())
    } else {
        Err(RuntimeCheckErrorKind::TypeValueError(
            Box::new(TypeSignature::PrincipalType),
            sender.as_ref().to_error_string(),
        )
        .into())
    }
}

/// The Stacks v205 version of burn_asset uses the actual stored size of the
///  asset as input to the cost tabulation. Otherwise identical to v200.
pub fn special_burn_asset_v205(
    args: &[SymbolicExpression],
    exec_state: &mut ExecutionState,
    invoke_ctx: &InvocationContext,
    context: &LocalContext,
) -> Result<Value, VmExecutionError> {
    check_argument_count(3, args)?;

    runtime_cost(ClarityCostFunction::NftBurn, exec_state, 0)?;

    let asset_name = args[0]
        .match_atom()
        .ok_or(RuntimeCheckErrorKind::Unreachable(
            "Bad token name".to_string(),
        ))?;

    let asset = normalize_asset_value(eval(&args[1], exec_state, invoke_ctx, context)?);
    let sender = eval(&args[2], exec_state, invoke_ctx, context)?;

    let nft_metadata = invoke_ctx.contract_context.meta_nft.get(asset_name).ok_or(
        RuntimeCheckErrorKind::Unreachable(format!("No such NFT: {asset_name}")),
    )?;
    let expected_asset_type = &nft_metadata.key_type;

    let asset_size = asset
        .as_ref()
        .serialized_size()
        .map_err(|e| VmInternalError::Expect(e.to_string()))? as u64;
    runtime_cost(ClarityCostFunction::NftBurn, exec_state, asset_size)?;

    if !expected_asset_type.admits(exec_state.epoch(), asset.as_ref())? {
        return Err(RuntimeCheckErrorKind::TypeValueError(
            Box::new(expected_asset_type.clone()),
            asset.as_ref().to_error_string(),
        )
        .into());
    }

    if let Value::Principal(sender_principal) = sender.as_ref() {
        let owner = match exec_state.global_context.database.get_nft_owner(
            &invoke_ctx.contract_context.contract_identifier,
            asset_name,
            asset.as_ref(),
            expected_asset_type,
        ) {
            Err(VmExecutionError::Runtime(RuntimeError::NoSuchToken, _)) => {
                return clarity_ecode!(BurnAssetErrorCodes::DOES_NOT_EXIST);
            }
            Ok(owner) => Ok(owner),
            Err(e) => Err(e),
        }?;

        if &owner != sender_principal {
            return clarity_ecode!(BurnAssetErrorCodes::NOT_OWNED_BY);
        }

        exec_state.add_memory(TypeSignature::PrincipalType.size()?.into())?;
        exec_state.add_memory(asset_size)?;

        let epoch = *exec_state.epoch();
        exec_state.global_context.database.burn_nft(
            &invoke_ctx.contract_context.contract_identifier,
            asset_name,
            asset.as_ref(),
            expected_asset_type,
            &epoch,
        )?;

        let asset = asset.clone_with_cost(exec_state)?;
        exec_state.global_context.log_asset_transfer(
            sender_principal,
            &invoke_ctx.contract_context.contract_identifier,
            asset_name,
            asset.clone(),
        )?;

        let asset_identifier = AssetIdentifier {
            contract_identifier: invoke_ctx.contract_context.contract_identifier.clone(),
            asset_name: asset_name.clone(),
        };
        exec_state.register_nft_burn_event(sender_principal.clone(), asset, asset_identifier)?;

        Ok(Value::okay_true())
    } else {
        Err(RuntimeCheckErrorKind::TypeValueError(
            Box::new(TypeSignature::PrincipalType),
            sender.as_ref().to_error_string(),
        )
        .into())
    }
}
