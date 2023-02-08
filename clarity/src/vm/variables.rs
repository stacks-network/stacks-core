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
use std::convert::TryFrom;

use crate::vm::contexts::{Environment, LocalContext};
use crate::vm::errors::{InterpreterResult as Result, RuntimeErrorType};
use crate::vm::types::BuffData;
use crate::vm::types::Value;
use crate::vm::ClarityVersion;

use crate::vm::costs::cost_functions::ClarityCostFunction;
use crate::vm::costs::runtime_cost;

define_versioned_named_enum!(NativeVariables(ClarityVersion) {
    ContractCaller("contract-caller", ClarityVersion::Clarity1),
    TxSender("tx-sender", ClarityVersion::Clarity1),
    BlockHeight("block-height", ClarityVersion::Clarity1),
    BurnBlockHeight("burn-block-height", ClarityVersion::Clarity1),
    NativeNone("none", ClarityVersion::Clarity1),
    NativeTrue("true", ClarityVersion::Clarity1),
    NativeFalse("false", ClarityVersion::Clarity1),
    TotalLiquidMicroSTX("stx-liquid-supply", ClarityVersion::Clarity1),
    Regtest("is-in-regtest", ClarityVersion::Clarity1),
    TxSponsor("tx-sponsor?", ClarityVersion::Clarity2),
    Mainnet("is-in-mainnet", ClarityVersion::Clarity2),
    ChainId("chain-id", ClarityVersion::Clarity2),
});

impl NativeVariables {
    pub fn lookup_by_name_at_version(
        name: &str,
        version: &ClarityVersion,
    ) -> Option<NativeVariables> {
        NativeVariables::lookup_by_name(name).and_then(|native_function| {
            if &native_function.get_version() <= version {
                Some(native_function)
            } else {
                None
            }
        })
    }
}

pub fn is_reserved_name(name: &str, version: &ClarityVersion) -> bool {
    NativeVariables::lookup_by_name_at_version(name, version).is_some()
}

pub fn lookup_reserved_variable(
    name: &str,
    _context: &LocalContext,
    env: &mut Environment,
) -> Result<Option<Value>> {
    if let Some(variable) =
        NativeVariables::lookup_by_name_at_version(name, env.contract_context.get_clarity_version())
    {
        match variable {
            NativeVariables::TxSender => {
                let sender = env
                    .sender
                    .clone()
                    .ok_or(RuntimeErrorType::NoSenderInContext)?;
                Ok(Some(Value::Principal(sender)))
            }
            NativeVariables::ContractCaller => {
                let caller = env
                    .caller
                    .clone()
                    .ok_or(RuntimeErrorType::NoCallerInContext)?;
                Ok(Some(Value::Principal(caller)))
            }
            NativeVariables::TxSponsor => {
                let sponsor = match env.sponsor.clone() {
                    None => Value::none(),
                    Some(p) => Value::some(Value::Principal(p))
                        .expect("ERROR: principal should be a valid Clarity object"),
                };
                Ok(Some(sponsor))
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
            NativeVariables::Mainnet => {
                let mainnet = env.global_context.mainnet;
                Ok(Some(Value::Bool(mainnet)))
            }
            NativeVariables::ChainId => {
                let chain_id = env.global_context.chain_id;
                Ok(Some(Value::UInt(chain_id.into())))
            }
        }
    } else {
        Ok(None)
    }
}
