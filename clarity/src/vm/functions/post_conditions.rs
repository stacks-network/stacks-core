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

use std::collections::{HashMap, HashSet};

use clarity_types::types::{AssetIdentifier, PrincipalData};

use crate::vm::contexts::AssetMap;
use crate::vm::costs::cost_functions::ClarityCostFunction;
use crate::vm::costs::{constants as cost_constants, runtime_cost, CostTracker};
use crate::vm::errors::{
    check_arguments_at_least, CheckErrors, InterpreterError, InterpreterResult,
};
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

fn eval_allowance(
    allowance_expr: &SymbolicExpression,
    env: &mut Environment,
    context: &LocalContext,
) -> InterpreterResult<Allowance> {
    let list = allowance_expr
        .match_list()
        .ok_or(CheckErrors::NonFunctionApplication)?;
    let (name_expr, rest) = list
        .split_first()
        .ok_or(CheckErrors::NonFunctionApplication)?;
    let name = name_expr.match_atom().ok_or(CheckErrors::BadFunctionName)?;

    match name.as_str() {
        "with-stx" => {
            if rest.len() != 1 {
                return Err(CheckErrors::IncorrectArgumentCount(1, rest.len()).into());
            }
            let amount = eval(&rest[0], env, context)?;
            let amount = amount.expect_u128()?;
            Ok(Allowance::Stx(StxAllowance { amount }))
        }
        "with-ft" => {
            if rest.len() != 3 {
                return Err(CheckErrors::IncorrectArgumentCount(3, rest.len()).into());
            }

            let contract_value = eval(&rest[0], env, context)?;
            let contract = contract_value.clone().expect_principal()?;
            let contract_identifier = match contract {
                PrincipalData::Standard(_) => {
                    return Err(
                        CheckErrors::ExpectedContractPrincipalValue(contract_value.into()).into(),
                    );
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
        "with-nft" => {
            if rest.len() != 3 {
                return Err(CheckErrors::IncorrectArgumentCount(3, rest.len()).into());
            }

            let contract_value = eval(&rest[0], env, context)?;
            let contract = contract_value.clone().expect_principal()?;
            let contract_identifier = match contract {
                PrincipalData::Standard(_) => {
                    return Err(
                        CheckErrors::ExpectedContractPrincipalValue(contract_value.into()).into(),
                    );
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
        "with-stacking" => {
            if rest.len() != 1 {
                return Err(CheckErrors::IncorrectArgumentCount(1, rest.len()).into());
            }
            let amount = eval(&rest[0], env, context)?;
            let amount = amount.expect_u128()?;
            Ok(Allowance::Stacking(StackingAllowance { amount }))
        }
        "with-all-assets-unsafe" => {
            if !rest.is_empty() {
                return Err(CheckErrors::IncorrectArgumentCount(1, rest.len()).into());
            }
            Ok(Allowance::All)
        }
        _ => Err(CheckErrors::ExpectedAllowanceExpr(name.to_string()).into()),
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
        .ok_or(CheckErrors::ExpectedListOfAllowances(
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

    let mut allowances = Vec::with_capacity(allowance_list.len());
    for allowance in allowance_list {
        allowances.push(eval_allowance(allowance, env, context)?);
    }

    // Create a new evaluation context, so that we can rollback if the
    // post-conditions are violated
    env.global_context.begin();

    // evaluate the body expressions
    let mut last_result = None;
    for expr in body_exprs {
        let result = eval(expr, env, context)?;
        last_result.replace(result);
    }

    let asset_maps = env.global_context.get_readonly_asset_map()?;

    // If the allowances are violated:
    // - Rollback the context
    // - Emit an event
    if let Some(violation_index) = check_allowances(&asset_owner, &allowances, asset_maps)? {
        env.global_context.roll_back()?;
        // TODO: Emit an event about the allowance violation
        return Value::error(Value::Int(violation_index));
    }

    env.global_context.commit()?;

    // Wrap the result in an `ok` value
    Value::okay(
        // last_result should always be Some(...), because of the arg len check above.
        last_result.ok_or_else(|| InterpreterError::Expect("Failed to get let result".into()))?,
    )
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
        .ok_or(CheckErrors::ExpectedListOfAllowances(
            "as-contract?".into(),
            1,
        ))?;
    let body_exprs = &args[1..];

    runtime_cost(
        ClarityCostFunction::AsContractSafe,
        env,
        allowance_list.len(),
    )?;

    let mut allowances = Vec::with_capacity(allowance_list.len());
    for allowance in allowance_list {
        allowances.push(eval_allowance(allowance, env, context)?);
    }

    let mut memory_use = 0;

    finally_drop_memory!( env, memory_use; {
        env.add_memory(cost_constants::AS_CONTRACT_MEMORY)?;
        memory_use += cost_constants::AS_CONTRACT_MEMORY;

        let contract_principal: PrincipalData = env.contract_context.contract_identifier.clone().into();
        let mut nested_env = env.nest_as_principal(contract_principal.clone());

        // Create a new evaluation context, so that we can rollback if the
        // post-conditions are violated
        nested_env.global_context.begin();

        // evaluate the body expressions
        let mut last_result = None;
        for expr in body_exprs {
            // TODO: handle runtime errors inside the body expressions correctly
            // (ensure that the context is always popped and asset maps are checked against allowances)
            let result = eval(expr, &mut nested_env, context)?;
            last_result.replace(result);
        }

        let asset_maps = nested_env.global_context.get_readonly_asset_map()?;

        // If the allowances are violated:
        // - Rollback the context
        // - Emit an event
        match check_allowances(&contract_principal, &allowances, asset_maps) {
            Ok(None) => {}
            Ok(Some(violation_index)) => {
                nested_env.global_context.roll_back()?;
                // TODO: Emit an event about the allowance violation
                return Value::error(Value::Int(violation_index));
            }
            Err(e) => {
                nested_env.global_context.roll_back()?;
                return Err(e);
            }
        }

        nested_env.global_context.commit()?;

        // Wrap the result in an `ok` value
        Value::okay(
            // last_result should always be Some(...), because of the arg len check above.
            last_result.ok_or_else(|| InterpreterError::Expect("Failed to get let result".into()))?,
        )
    })
}

/// Check the allowances against the asset map. If any assets moved without a
/// corresponding allowance return a `Some` with an index of the violated
/// allowance, or -1 if an asset with no allowance caused the violation. If all
/// allowances are satisfied, return `Ok(None)`.
fn check_allowances(
    owner: &PrincipalData,
    allowances: &[Allowance],
    assets: &AssetMap,
) -> InterpreterResult<Option<i128>> {
    // Elements are (index in allowances, amount)
    let mut stx_allowances: Vec<(usize, u128)> = Vec::new();
    // Map assets to a vector of (index in allowances, amount)
    let mut ft_allowances: HashMap<&AssetIdentifier, Vec<(usize, u128)>> = HashMap::new();
    // Map assets to a tuple with the first allowance's index and a hashset of
    // serialized asset identifiers
    let mut nft_allowances: HashMap<&AssetIdentifier, (usize, HashSet<String>)> = HashMap::new();
    // Elements are (index in allowances, amount)
    let mut stacking_allowances: Vec<(usize, u128)> = Vec::new();

    for (i, allowance) in allowances.iter().enumerate() {
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
                    .entry(&ft.asset)
                    .or_default()
                    .push((i, ft.amount));
            }
            Allowance::Nft(nft) => {
                let (_, set) = nft_allowances
                    .entry(&nft.asset)
                    .or_insert_with(|| (i, HashSet::new()));
                for id in &nft.asset_ids {
                    set.insert(id.serialize_to_hex()?);
                }
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
            return Ok(Some(-1));
        }

        // Check against the STX allowances
        for (index, allowance) in &stx_allowances {
            if stx_moved > *allowance {
                return Ok(Some(i128::try_from(*index).map_err(|_| {
                    InterpreterError::Expect("failed to convert index to i128".into())
                })?));
            }
        }
    }

    // Check STX burns
    if let Some(stx_burned) = assets.get_stx_burned(owner) {
        // If there are no allowances for STX, any burn is a violation
        if stx_allowances.is_empty() {
            return Ok(Some(-1));
        }

        // Check against the STX allowances
        for (index, allowance) in &stx_allowances {
            if stx_burned > *allowance {
                return Ok(Some(i128::try_from(*index).map_err(|_| {
                    InterpreterError::Expect("failed to convert index to i128".into())
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
                return Ok(Some(-1));
            }

            // Sort by allowance index so we check allowances in order
            merged.sort_by_key(|(idx, _)| *idx);

            for (index, allowance) in merged {
                if *amount_moved > allowance {
                    return Ok(Some(i128::try_from(index).map_err(|_| {
                        InterpreterError::Expect("failed to convert index to i128".into())
                    })?));
                }
            }
        }
    }

    // Check NFT movements
    if let Some(nft_moved) = assets.get_all_nonfungible_tokens(owner) {
        for (asset, ids_moved) in nft_moved {
            let mut merged: Vec<(usize, HashSet<String>)> = Vec::new();
            if let Some((index, allowance_map)) = nft_allowances.get(asset) {
                merged.push((*index, allowance_map.clone()));
            }

            if let Some((index, allowance_map)) = nft_allowances.get(&AssetIdentifier {
                contract_identifier: asset.contract_identifier.clone(),
                asset_name: "*".into(),
            }) {
                merged.push((*index, allowance_map.clone()));
            }

            if merged.is_empty() {
                // No allowance for this asset, any movement is a violation
                return Ok(Some(-1));
            }

            // Sort by allowance index so we check allowances in order
            merged.sort_by_key(|(idx, _)| *idx);

            for (index, allowance_map) in merged {
                // Check against the NFT allowances
                for id_moved in ids_moved {
                    if !allowance_map.contains(&id_moved.serialize_to_hex()?) {
                        return Ok(Some(i128::try_from(index).map_err(|_| {
                            InterpreterError::Expect("failed to convert index to i128".into())
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
            return Ok(Some(-1));
        }

        // Check against the stacking allowances
        for (index, allowance) in &stacking_allowances {
            if stx_stacked > *allowance {
                return Ok(Some(i128::try_from(*index).map_err(|_| {
                    InterpreterError::Expect("failed to convert index to i128".into())
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
    Err(CheckErrors::AllowanceExprNotAllowed.into())
}
