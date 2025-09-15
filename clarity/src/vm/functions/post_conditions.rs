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

use crate::vm::costs::cost_functions::ClarityCostFunction;
use crate::vm::costs::runtime_cost;
use crate::vm::errors::{
    check_arguments_at_least, CheckErrors, InterpreterError, InterpreterResult,
};
use crate::vm::representations::SymbolicExpression;
use crate::vm::types::{QualifiedContractIdentifier, Value};
use crate::vm::{eval, Environment, LocalContext};

struct StxAllowance {
    amount: u128,
}

struct FtAllowance {
    contract: QualifiedContractIdentifier,
    token: String,
    amount: u128,
}

struct NftAllowance {
    contract: QualifiedContractIdentifier,
    token: String,
    asset_id: Value,
}

struct StackingAllowance {
    amount: u128,
}

enum Allowance {
    Stx(StxAllowance),
    Ft(FtAllowance),
    Nft(NftAllowance),
    Stacking(StackingAllowance),
    All,
}

fn eval_allowance(
    _allowance_expr: &SymbolicExpression,
    _env: &mut Environment,
    _context: &LocalContext,
) -> InterpreterResult<Allowance> {
    // FIXME: Placeholder
    Ok(Allowance::All)
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
        .ok_or(CheckErrors::RestrictAssetsExpectedListOfAllowances)?;
    let body_exprs = &args[2..];

    let _asset_owner = eval(asset_owner_expr, env, context)?;

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

    // TODO: Check the post-conditions and rollback if they are violated

    env.global_context.commit()?;

    // last_result should always be Some(...), because of the arg len check above.
    last_result.ok_or_else(|| InterpreterError::Expect("Failed to get let result".into()).into())
}
