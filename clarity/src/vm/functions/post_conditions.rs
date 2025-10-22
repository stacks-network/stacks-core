// Copyright (C) 2025 Stacks Open Internet Foundation
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

use std::collections::HashMap;

use clarity_types::types::{AssetIdentifier, PrincipalData, StandardPrincipalData};

use crate::vm::analysis::type_checker::v2_1::natives::post_conditions::MAX_ALLOWANCES;
use crate::vm::contexts::AssetMap;
use crate::vm::costs::cost_functions::ClarityCostFunction;
use crate::vm::costs::{constants as cost_constants, runtime_cost, CostTracker, MemoryConsumer};
use crate::vm::errors::{
    check_arguments_at_least, CheckErrorKind, InterpreterResult, VmInternalError,
};
use crate::vm::functions::NativeFunctions;
use crate::vm::representations::SymbolicExpression;
use crate::vm::types::Value;
use crate::vm::{eval, Environment, LocalContext};

pub struct StxAllowance {
    amount: u128,
}

pub struct FtAllowance {
    asset: AssetIdentifier,
    amount: u128,
}

pub struct NftAllowance {
    asset: AssetIdentifier,
    asset_ids: Vec<Value>,
}

pub struct StackingAllowance {
    amount: u128,
}

pub enum Allowance {
    Stx(StxAllowance),
    Ft(FtAllowance),
    Nft(NftAllowance),
    Stacking(StackingAllowance),
    All,
}

impl Allowance {
    /// Returns the size in bytes of the allowance when stored in memory.
    /// This is used to account for memory usage when evaluating `as-contract?`
    /// and `restrict-assets?` expressions.
    pub fn size_in_bytes(&self) -> Result<usize, VmInternalError> {
        match self {
            Allowance::Stx(_) => Ok(std::mem::size_of::<StxAllowance>()),
            Allowance::Ft(ft) => Ok(std::mem::size_of::<FtAllowance>()
                + std::mem::size_of::<StandardPrincipalData>()
                + ft.asset.contract_identifier.name.len() as usize
                + ft.asset.asset_name.len() as usize),
            Allowance::Nft(nft) => {
                let mut total_size = std::mem::size_of::<NftAllowance>()
                    + std::mem::size_of::<StandardPrincipalData>()
                    + nft.asset.contract_identifier.name.len() as usize
                    + nft.asset.asset_name.len() as usize;

                for id in &nft.asset_ids {
                    let memory_use = id.get_memory_use().map_err(|e| {
                        VmInternalError::Expect(format!("Failed to calculate memory use: {e}"))
                    })?;
                    total_size += memory_use as usize;
                }

                Ok(total_size)
            }
            Allowance::Stacking(_) => Ok(std::mem::size_of::<StackingAllowance>()),
            Allowance::All => Ok(0),
        }
    }
}

fn eval_allowance(
    allowance_expr: &SymbolicExpression,
    env: &mut Environment,
    context: &LocalContext,
) -> InterpreterResult<Allowance> {
    let list = allowance_expr
        .match_list()
        .ok_or(CheckErrorKind::NonFunctionApplication)?;
    let (name_expr, rest) = list
        .split_first()
        .ok_or(CheckErrorKind::NonFunctionApplication)?;
    let name = name_expr
        .match_atom()
        .ok_or(CheckErrorKind::BadFunctionName)?;
    let Some(ref native_function) = NativeFunctions::lookup_by_name_at_version(
        name,
        env.contract_context.get_clarity_version(),
    ) else {
        return Err(CheckErrorKind::ExpectedAllowanceExpr(name.to_string()).into());
    };

    match native_function {
        NativeFunctions::AllowanceWithStx => {
            if rest.len() != 1 {
                return Err(CheckErrorKind::IncorrectArgumentCount(1, rest.len()).into());
            }
            let amount = eval(&rest[0], env, context)?;
            let amount = amount.expect_u128()?;
            Ok(Allowance::Stx(StxAllowance { amount }))
        }
        NativeFunctions::AllowanceWithFt => {
            if rest.len() != 3 {
                return Err(CheckErrorKind::IncorrectArgumentCount(3, rest.len()).into());
            }

            let contract_value = eval(&rest[0], env, context)?;
            let contract = contract_value.clone().expect_principal()?;
            let contract_identifier = match contract {
                PrincipalData::Standard(_) => {
                    return Err(CheckErrorKind::ExpectedContractPrincipalValue(
                        contract_value.into(),
                    )
                    .into());
                }
                PrincipalData::Contract(c) => c,
            };

            let asset_name = eval(&rest[1], env, context)?;
            let asset_name = asset_name.expect_string_ascii()?.as_str().into();

            let asset = AssetIdentifier {
                contract_identifier,
                asset_name,
            };

            let amount = eval(&rest[2], env, context)?;
            let amount = amount.expect_u128()?;

            Ok(Allowance::Ft(FtAllowance { asset, amount }))
        }
        NativeFunctions::AllowanceWithNft => {
            if rest.len() != 3 {
                return Err(CheckErrorKind::IncorrectArgumentCount(3, rest.len()).into());
            }

            let contract_value = eval(&rest[0], env, context)?;
            let contract = contract_value.clone().expect_principal()?;
            let contract_identifier = match contract {
                PrincipalData::Standard(_) => {
                    return Err(CheckErrorKind::ExpectedContractPrincipalValue(
                        contract_value.into(),
                    )
                    .into());
                }
                PrincipalData::Contract(c) => c,
            };

            let asset_name = eval(&rest[1], env, context)?;
            let asset_name = asset_name.expect_string_ascii()?.as_str().into();

            let asset = AssetIdentifier {
                contract_identifier,
                asset_name,
            };

            let asset_id_list = eval(&rest[2], env, context)?;
            let asset_ids = asset_id_list.expect_list()?;

            Ok(Allowance::Nft(NftAllowance { asset, asset_ids }))
        }
        NativeFunctions::AllowanceWithStacking => {
            if rest.len() != 1 {
                return Err(CheckErrorKind::IncorrectArgumentCount(1, rest.len()).into());
            }
            let amount = eval(&rest[0], env, context)?;
            let amount = amount.expect_u128()?;
            Ok(Allowance::Stacking(StackingAllowance { amount }))
        }
        NativeFunctions::AllowanceAll => {
            if !rest.is_empty() {
                return Err(CheckErrorKind::IncorrectArgumentCount(1, rest.len()).into());
            }
            Ok(Allowance::All)
        }
        _ => Err(CheckErrorKind::ExpectedAllowanceExpr(name.to_string()).into()),
    }
}

/// Handles the function `restrict-assets?`
pub fn special_restrict_assets(
    args: &[SymbolicExpression],
    env: &mut Environment,
    context: &LocalContext,
) -> InterpreterResult<Value> {
    // (restrict-assets? asset-owner ((with-stx|with-ft|with-nft|with-stacking)*) expr-body1 expr-body2 ... expr-body-last)
    // arg1 => asset owner to protect
    // arg2 => list of asset allowances
    // arg3..n => body
    check_arguments_at_least(3, args)?;

    let asset_owner_expr = &args[0];
    let allowance_list = args[1]
        .match_list()
        .ok_or(CheckErrorKind::ExpectedListOfAllowances(
            "restrict-assets?".into(),
            2,
        ))?;
    let body_exprs = &args[2..];

    let asset_owner = eval(asset_owner_expr, env, context)?;
    let asset_owner = asset_owner.expect_principal()?;

    runtime_cost(
        ClarityCostFunction::RestrictAssets,
        env,
        allowance_list.len(),
    )?;

    if allowance_list.len() > MAX_ALLOWANCES {
        return Err(CheckErrorKind::TooManyAllowances(MAX_ALLOWANCES, allowance_list.len()).into());
    }

    let mut allowances = Vec::with_capacity(allowance_list.len());
    for allowance in allowance_list {
        allowances.push(eval_allowance(allowance, env, context)?);
    }

    // Create a new evaluation context, so that we can rollback if the
    // post-conditions are violated
    env.global_context.begin();

    // Evaluate the body expressions inside a closure so `?` only exits the closure
    let eval_result: InterpreterResult<Option<Value>> = (|| -> InterpreterResult<Option<Value>> {
        let mut last_result = None;
        for expr in body_exprs {
            let result = eval(expr, env, context)?;
            last_result.replace(result);
        }
        Ok(last_result)
    })();

    let asset_maps = env.global_context.get_readonly_asset_map()?;

    // If the allowances are violated:
    // - Rollback the context
    // - Return an error with the index of the violated allowance
    match check_allowances(&asset_owner, allowances, asset_maps) {
        Ok(None) => {}
        Ok(Some(violation_index)) => {
            env.global_context.roll_back()?;
            return Value::error(Value::UInt(violation_index));
        }
        Err(e) => {
            env.global_context.roll_back()?;
            return Err(e);
        }
    }

    env.global_context.commit()?;

    // No allowance violation, so handle the result of the body evaluation
    match eval_result {
        Ok(Some(last)) => {
            // body completed successfully — commit and return ok(last)
            Value::okay(last)
        }
        Ok(None) => {
            // Body had no expressions (shouldn't happen due to argument checks)
            Err(VmInternalError::Expect("Failed to get body result".into()).into())
        }
        Err(e) => {
            // Runtime error inside body, pass it up
            Err(e)
        }
    }
}

/// Handles the function `as-contract?`
pub fn special_as_contract(
    args: &[SymbolicExpression],
    env: &mut Environment,
    context: &LocalContext,
) -> InterpreterResult<Value> {
    // (as-contract? ((with-stx|with-ft|with-nft|with-stacking)*) expr-body1 expr-body2 ... expr-body-last)
    // arg1 => list of asset allowances
    // arg2..n => body
    check_arguments_at_least(2, args)?;

    let allowance_list = args[0]
        .match_list()
        .ok_or(CheckErrorKind::ExpectedListOfAllowances(
            "as-contract?".into(),
            1,
        ))?;
    let body_exprs = &args[1..];

    runtime_cost(
        ClarityCostFunction::AsContractSafe,
        env,
        allowance_list.len(),
    )?;

    let mut memory_use = 0u64;

    finally_drop_memory!( env, memory_use; {
        let mut allowances = Vec::with_capacity(allowance_list.len());
        for allowance_expr in allowance_list {
            let allowance = eval_allowance(allowance_expr, env, context)?;
            let allowance_memory = u64::try_from(allowance.size_in_bytes()?)
                .map_err(|_| VmInternalError::Expect("Allowance size too large".into()))?;
            env.add_memory(allowance_memory)?;
            memory_use += allowance_memory;
            allowances.push(allowance);
        }

        env.add_memory(cost_constants::AS_CONTRACT_MEMORY)?;
        memory_use += cost_constants::AS_CONTRACT_MEMORY;

        let contract_principal: PrincipalData = env.contract_context.contract_identifier.clone().into();
        let mut nested_env = env.nest_as_principal(contract_principal.clone());

        // Create a new evaluation context, so that we can rollback if the
        // post-conditions are violated
        nested_env.global_context.begin();

        // Evaluate the body expressions inside a closure so `?` only exits the closure
        let eval_result: InterpreterResult<Option<Value>> = (|| -> InterpreterResult<Option<Value>> {
            let mut last_result = None;
            for expr in body_exprs {
                let result = eval(expr, &mut nested_env, context)?;
                last_result.replace(result);
            }
            Ok(last_result)
        })();

        let asset_maps = nested_env.global_context.get_readonly_asset_map()?;

        // If the allowances are violated:
        // - Rollback the context
        // - Return an error with the index of the violated allowance
        match check_allowances(&contract_principal, allowances, asset_maps) {
            Ok(None) => {}
            Ok(Some(violation_index)) => {
                nested_env.global_context.roll_back()?;
                return Value::error(Value::UInt(violation_index));
            }
            Err(e) => {
                nested_env.global_context.roll_back()?;
                return Err(e);
            }
        }

        nested_env.global_context.commit()?;

        // No allowance violation, so handle the result of the body evaluation
        match eval_result {
            Ok(Some(last)) => {
                // body completed successfully — commit and return ok(last)
                Value::okay(last)
            }
            Ok(None) => {
                // Body had no expressions (shouldn't happen due to argument checks)
                Err(VmInternalError::Expect("Failed to get body result".into()).into())
            }
            Err(e) => {
                // Runtime error inside body, pass it up
                Err(e)
            }
        }
    })
}

/// Check the allowances against the asset map. If any assets moved without a
/// corresponding allowance return a `Some` with an index of the violated
/// allowance, or 128 if an asset with no allowance caused the violation. If all
/// allowances are satisfied, return `Ok(None)`.
fn check_allowances(
    owner: &PrincipalData,
    allowances: Vec<Allowance>,
    assets: &AssetMap,
) -> InterpreterResult<Option<u128>> {
    // Elements are (index in allowances, amount)
    let mut stx_allowances: Vec<(usize, u128)> = Vec::new();
    // Map assets to a vector of (index in allowances, amount)
    let mut ft_allowances: HashMap<AssetIdentifier, Vec<(usize, u128)>> = HashMap::new();
    // Map assets to a tuple with the first allowance's index and a vector of
    // asset identifiers. We use Vec instead of HashSet because:
    // 1. Most NFT IDs are simple (`uint`s), making Value::eq() very fast
    // 2. Linear search through ≤128 items is cache-friendly and fast
    // 3. Avoids serialization cost during both setup and lookup phases
    // 4. Simpler implementation with lower memory overhead (no cloning or
    //    space used for serialization)
    let mut nft_allowances: HashMap<AssetIdentifier, (usize, Vec<Value>)> = HashMap::new();
    // Elements are (index in allowances, amount)
    let mut stacking_allowances: Vec<(usize, u128)> = Vec::new();

    for (i, allowance) in allowances.into_iter().enumerate() {
        match allowance {
            Allowance::All => {
                // any asset movement is allowed
                return Ok(None);
            }
            Allowance::Stx(stx) => {
                stx_allowances.push((i, stx.amount));
            }
            Allowance::Ft(ft) => {
                ft_allowances
                    .entry(ft.asset)
                    .or_default()
                    .push((i, ft.amount));
            }
            Allowance::Nft(nft) => {
                let (_, vec) = nft_allowances
                    .entry(nft.asset)
                    .or_insert_with(|| (i, Vec::new()));
                vec.extend(nft.asset_ids);
            }
            Allowance::Stacking(stacking) => {
                stacking_allowances.push((i, stacking.amount));
            }
        }
    }

    // Check STX movements
    if let Some(stx_moved) = assets.get_stx(owner) {
        // If there are no allowances for STX, any movement is a violation
        if stx_allowances.is_empty() {
            return Ok(Some(MAX_ALLOWANCES as u128));
        }

        // Check against the STX allowances
        for (index, allowance) in &stx_allowances {
            if stx_moved > *allowance {
                return Ok(Some(u128::try_from(*index).map_err(|_| {
                    VmInternalError::Expect("failed to convert index to u128".into())
                })?));
            }
        }
    }

    // Check STX burns
    if let Some(stx_burned) = assets.get_stx_burned(owner) {
        // If there are no allowances for STX, any burn is a violation
        if stx_allowances.is_empty() {
            return Ok(Some(MAX_ALLOWANCES as u128));
        }

        // Check against the STX allowances
        for (index, allowance) in &stx_allowances {
            if stx_burned > *allowance {
                return Ok(Some(u128::try_from(*index).map_err(|_| {
                    VmInternalError::Expect("failed to convert index to u128".into())
                })?));
            }
        }
    }

    // Check FT movements
    if let Some(ft_moved) = assets.get_all_fungible_tokens(owner) {
        for (asset, amount_moved) in ft_moved {
            // Build merged allowance list: exact-match entries + wildcard entries for the same contract
            let mut merged: Vec<(usize, u128)> = Vec::new();

            if let Some(allowance_vec) = ft_allowances.get(asset) {
                merged.extend(allowance_vec.iter().cloned());
            }

            if let Some(wildcard_vec) = ft_allowances.get(&AssetIdentifier {
                contract_identifier: asset.contract_identifier.clone(),
                asset_name: "*".into(),
            }) {
                merged.extend(wildcard_vec.iter().cloned());
            }

            if merged.is_empty() {
                // No allowance for this asset, any movement is a violation
                return Ok(Some(MAX_ALLOWANCES as u128));
            }

            // Sort by allowance index so we check allowances in order
            merged.sort_by_key(|(idx, _)| *idx);

            for (index, allowance) in merged {
                if *amount_moved > allowance {
                    return Ok(Some(u128::try_from(index).map_err(|_| {
                        VmInternalError::Expect("failed to convert index to u128".into())
                    })?));
                }
            }
        }
    }

    // Check NFT movements
    if let Some(nft_moved) = assets.get_all_nonfungible_tokens(owner) {
        for (asset, ids_moved) in nft_moved {
            let mut merged: Vec<(usize, &Vec<Value>)> = Vec::new();
            if let Some((index, allowance_vec)) = nft_allowances.get(asset) {
                merged.push((*index, allowance_vec));
            }

            if let Some((index, allowance_vec)) = nft_allowances.get(&AssetIdentifier {
                contract_identifier: asset.contract_identifier.clone(),
                asset_name: "*".into(),
            }) {
                merged.push((*index, allowance_vec));
            }

            if merged.is_empty() {
                // No allowance for this asset, any movement is a violation
                return Ok(Some(MAX_ALLOWANCES as u128));
            }

            // Sort by allowance index so we check allowances in order
            merged.sort_by_key(|(idx, _)| *idx);

            for (index, allowance_vec) in merged {
                // Check against the NFT allowances
                for id_moved in ids_moved {
                    if !allowance_vec.contains(id_moved) {
                        return Ok(Some(u128::try_from(index).map_err(|_| {
                            VmInternalError::Expect("failed to convert index to u128".into())
                        })?));
                    }
                }
            }
        }
    }

    // Check stacking
    if let Some(stx_stacked) = assets.get_stacking(owner) {
        // If there are no allowances for stacking, any stacking is a violation
        if stacking_allowances.is_empty() {
            return Ok(Some(MAX_ALLOWANCES as u128));
        }

        // Check against the stacking allowances
        for (index, allowance) in &stacking_allowances {
            if stx_stacked > *allowance {
                return Ok(Some(u128::try_from(*index).map_err(|_| {
                    VmInternalError::Expect("failed to convert index to u128".into())
                })?));
            }
        }
    }

    Ok(None)
}

/// Handles all allowance functions, always returning an error, since these are
/// not allowed outside of specific contexts (in `restrict-assets?` and
/// `as-contract?`). When called in the appropriate context, they are handled
/// by the above `eval_allowance` function.
pub fn special_allowance(
    _args: &[SymbolicExpression],
    _env: &mut Environment,
    _context: &LocalContext,
) -> InterpreterResult<Value> {
    Err(CheckErrorKind::AllowanceExprNotAllowed.into())
}
