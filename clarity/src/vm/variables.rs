// Copyright (C) 2013-2020 Blockstack PBC, a public benefit corporation
// Copyright (C) 2020 Stacks Open Internet Foundation
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

use crate::vm::contexts::{Environment, LocalContext};
use crate::vm::errors::{InterpreterResult as Result, RuntimeErrorType};
use crate::vm::types::BuffData;
use crate::vm::types::Value;
use std::convert::TryFrom;

use crate::vm::costs::cost_functions::ClarityCostFunction;
use crate::vm::costs::runtime_cost;

define_named_enum!(NativeVariables {
    ContractCaller("contract-caller"), TxSender("tx-sender"), BlockHeight("block-height"),
    BurnBlockHeight("burn-block-height"), NativeNone("none"),
    NativeTrue("true"), NativeFalse("false"),
    TotalLiquidMicroSTX("stx-liquid-supply"),
    Regtest("is-in-regtest"),
});

pub fn is_reserved_name(name: &str) -> bool {
    NativeVariables::lookup_by_name(name).is_some()
}

pub fn lookup_reserved_variable(
    name: &str,
    _context: &LocalContext,
    env: &mut Environment,
) -> Result<Option<Value>> {
    if let Some(variable) = NativeVariables::lookup_by_name(name) {
        match variable {
            NativeVariables::TxSender => {
                let sender = env
                    .sender
                    .clone()
                    .ok_or(RuntimeErrorType::NoSenderInContext)?;
                Ok(Some(Value::Principal(sender)))
            }
            NativeVariables::ContractCaller => {
                let sender = env
                    .caller
                    .clone()
                    .ok_or(RuntimeErrorType::NoSenderInContext)?;
                Ok(Some(Value::Principal(sender)))
            }
            NativeVariables::BlockHeight => {
                runtime_cost(ClarityCostFunction::FetchVar, env, 1)?;
                let block_height = env.global_context.database.get_current_block_height();
                Ok(Some(Value::UInt(block_height as u128)))
            }
            NativeVariables::BurnBlockHeight => {
                runtime_cost(ClarityCostFunction::FetchVar, env, 1)?;
                let burn_block_height = env
                    .global_context
                    .database
                    .get_current_burnchain_block_height();
                Ok(Some(Value::UInt(burn_block_height as u128)))
            }
            NativeVariables::NativeNone => Ok(Some(Value::none())),
            NativeVariables::NativeTrue => Ok(Some(Value::Bool(true))),
            NativeVariables::NativeFalse => Ok(Some(Value::Bool(false))),
            NativeVariables::TotalLiquidMicroSTX => {
                runtime_cost(ClarityCostFunction::FetchVar, env, 1)?;
                let liq = env.global_context.database.get_total_liquid_ustx();
                Ok(Some(Value::UInt(liq)))
            }
            NativeVariables::Regtest => {
                let reg = env.global_context.database.is_in_regtest();
                Ok(Some(Value::Bool(reg)))
            }
        }
    } else {
        Ok(None)
    }
}
