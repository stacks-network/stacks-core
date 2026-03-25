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

use clarity_types::types::PrincipalData;
use stacks_common::types::StacksEpochId;

use super::errors::VmInternalError;
use crate::vm::ClarityVersion;
use crate::vm::contexts::{ExecutionState, InvocationContext};
use crate::vm::costs::cost_functions::ClarityCostFunction;
use crate::vm::costs::runtime_cost;
use crate::vm::errors::{RuntimeError, VmExecutionError};
use crate::vm::types::Value;

define_versioned_named_enum_with_max!(NativeVariables(ClarityVersion) {
    ContractCaller("contract-caller", ClarityVersion::Clarity1, None),
    TxSender("tx-sender", ClarityVersion::Clarity1, None),
    BlockHeight("block-height", ClarityVersion::Clarity1, Some(ClarityVersion::Clarity2)),
    BurnBlockHeight("burn-block-height", ClarityVersion::Clarity1, None),
    NativeNone("none", ClarityVersion::Clarity1, None),
    NativeTrue("true", ClarityVersion::Clarity1, None),
    NativeFalse("false", ClarityVersion::Clarity1, None),
    TotalLiquidMicroSTX("stx-liquid-supply", ClarityVersion::Clarity1, None),
    Regtest("is-in-regtest", ClarityVersion::Clarity1, None),
    TxSponsor("tx-sponsor?", ClarityVersion::Clarity2, None),
    Mainnet("is-in-mainnet", ClarityVersion::Clarity2, None),
    ChainId("chain-id", ClarityVersion::Clarity2, None),
    StacksBlockHeight("stacks-block-height", ClarityVersion::Clarity3, None),
    TenureHeight("tenure-height", ClarityVersion::Clarity3, None),
    StacksBlockTime("stacks-block-time", ClarityVersion::Clarity4, None),
    CurrentContract("current-contract", ClarityVersion::Clarity4, None)
});

pub fn is_reserved_name(name: &str, version: &ClarityVersion) -> bool {
    NativeVariables::lookup_by_name_at_version(name, version).is_some()
}

pub fn lookup_reserved_variable(
    name: &str,
    exec_state: &mut ExecutionState,
    invoke_ctx: &InvocationContext,
) -> Result<Option<Value>, VmExecutionError> {
    if let Some(variable) = NativeVariables::lookup_by_name_at_version(
        name,
        invoke_ctx.contract_context.get_clarity_version(),
    ) {
        match variable {
            NativeVariables::TxSender => {
                // This `NoSenderInContext` is **unreachable** in standard Clarity VM execution.
                // - Every function call (public, private, or trait) is executed with a valid caller context.
                let sender = invoke_ctx
                    .sender
                    .clone()
                    .ok_or(RuntimeError::NoSenderInContext)?;
                Ok(Some(Value::Principal(sender)))
            }
            NativeVariables::ContractCaller => {
                // This `NoCallerInContext` is **unreachable** in standard Clarity VM execution.
                // -  Every on-chain transaction and contract-call has a well-defined sender.
                let caller = invoke_ctx
                    .caller
                    .clone()
                    .ok_or(RuntimeError::NoCallerInContext)?;
                Ok(Some(Value::Principal(caller)))
            }
            NativeVariables::TxSponsor => {
                let sponsor = match invoke_ctx.sponsor.clone() {
                    None => Value::none(),
                    Some(p) => Value::some(Value::Principal(p)).map_err(|_| {
                        VmInternalError::Expect(
                            "ERROR: principal should be a valid Clarity object".into(),
                        )
                    })?,
                };
                Ok(Some(sponsor))
            }
            NativeVariables::BlockHeight => {
                runtime_cost(ClarityCostFunction::FetchVar, exec_state, 1)?;
                // In epoch 2.x, the `block-height` keyword returns the Stacks block height.
                // For Clarity 1 and Clarity 2 contracts executing in epoch 3, `block-height`
                // is equal to the tenure height instead of the Stacks block height. This change
                // is made to maintain a similar pace at which this value increments (e.g. for use
                // as an expiration). In Clarity 3, `block-height` is removed to avoid confusion.
                // It is replaced with two new keywords: `stacks-block-height` and `tenure-height`.
                if exec_state.global_context.epoch_id < StacksEpochId::Epoch30 {
                    let block_height = exec_state
                        .global_context
                        .database
                        .get_current_block_height();
                    Ok(Some(Value::UInt(block_height as u128)))
                } else {
                    let tenure_height = exec_state.global_context.database.get_tenure_height()?;
                    Ok(Some(Value::UInt(tenure_height as u128)))
                }
            }
            NativeVariables::BurnBlockHeight => {
                runtime_cost(ClarityCostFunction::FetchVar, exec_state, 1)?;
                let burn_block_height = exec_state
                    .global_context
                    .database
                    .get_current_burnchain_block_height()?;
                Ok(Some(Value::UInt(u128::from(burn_block_height))))
            }
            NativeVariables::NativeNone => Ok(Some(Value::none())),
            NativeVariables::NativeTrue => Ok(Some(Value::Bool(true))),
            NativeVariables::NativeFalse => Ok(Some(Value::Bool(false))),
            NativeVariables::TotalLiquidMicroSTX => {
                runtime_cost(ClarityCostFunction::FetchVar, exec_state, 1)?;
                let liq = exec_state.global_context.database.get_total_liquid_ustx()?;
                Ok(Some(Value::UInt(liq)))
            }
            NativeVariables::Regtest => {
                let reg = exec_state.global_context.database.is_in_regtest();
                Ok(Some(Value::Bool(reg)))
            }
            NativeVariables::Mainnet => {
                let mainnet = exec_state.global_context.mainnet;
                Ok(Some(Value::Bool(mainnet)))
            }
            NativeVariables::ChainId => {
                let chain_id = exec_state.global_context.chain_id;
                Ok(Some(Value::UInt(chain_id.into())))
            }
            NativeVariables::StacksBlockHeight => {
                runtime_cost(ClarityCostFunction::FetchVar, exec_state, 1)?;
                let block_height = exec_state
                    .global_context
                    .database
                    .get_current_block_height();
                Ok(Some(Value::UInt(block_height as u128)))
            }
            NativeVariables::TenureHeight => {
                runtime_cost(ClarityCostFunction::FetchVar, exec_state, 1)?;
                let tenure_height = exec_state.global_context.database.get_tenure_height()?;
                Ok(Some(Value::UInt(tenure_height as u128)))
            }
            NativeVariables::CurrentContract => {
                let contract = invoke_ctx.contract_context.contract_identifier.clone();
                Ok(Some(Value::Principal(PrincipalData::Contract(contract))))
            }
            NativeVariables::StacksBlockTime => {
                runtime_cost(ClarityCostFunction::FetchVar, exec_state, 1)?;
                let block_time = exec_state
                    .global_context
                    .database
                    .get_current_block_time()?;
                Ok(Some(Value::UInt(u128::from(block_time))))
            }
        }
    } else {
        Ok(None)
    }
}

#[cfg(test)]
mod test {
    use clarity_types::types::QualifiedContractIdentifier;
    use stacks_common::consts::CHAIN_ID_TESTNET;

    use super::*;
    use crate::vm::contexts::GlobalContext;
    use crate::vm::costs::LimitedCostTracker;
    use crate::vm::database::MemoryBackingStore;
    use crate::vm::{CallStack, ClarityVersion, ContractContext};

    #[test]
    fn trigger_no_caller_in_context() {
        let mut call_stack = CallStack::new();
        let contract = QualifiedContractIdentifier::transient();
        let contract_context = ContractContext::new(contract.clone(), ClarityVersion::Clarity1);
        let mut marf = MemoryBackingStore::new();
        let mut global_context = GlobalContext::new(
            false,
            CHAIN_ID_TESTNET,
            marf.as_clarity_db(),
            LimitedCostTracker::new_free(),
            StacksEpochId::Epoch2_05,
        );
        let mut exec_state = ExecutionState {
            global_context: &mut global_context,
            call_stack: &mut call_stack,
        };
        let invoke_ctx = InvocationContext {
            contract_context: &contract_context,
            sender: Some(PrincipalData::Standard(contract.issuer.clone())),
            caller: None, // <- intentionally missing
            sponsor: None,
            is_contract_deploy: false,
        };

        let res = lookup_reserved_variable("contract-caller", &mut exec_state, &invoke_ctx);
        assert!(matches!(
            res,
            Err(VmExecutionError::Runtime(
                RuntimeError::NoCallerInContext,
                _
            ))
        ));
    }

    #[test]
    fn trigger_no_sender_in_context() {
        let mut call_stack = CallStack::new();
        let contract = QualifiedContractIdentifier::transient();
        let contract_context = ContractContext::new(contract.clone(), ClarityVersion::Clarity1);
        let mut marf = MemoryBackingStore::new();
        let mut global_context = GlobalContext::new(
            false,
            CHAIN_ID_TESTNET,
            marf.as_clarity_db(),
            LimitedCostTracker::new_free(),
            StacksEpochId::Epoch2_05,
        );
        let mut exec_state = ExecutionState {
            global_context: &mut global_context,
            call_stack: &mut call_stack,
        };
        let invoke_ctx = InvocationContext {
            contract_context: &contract_context,
            sender: None, // <- intentionally missing
            caller: Some(PrincipalData::Standard(contract.issuer.clone())),
            sponsor: None,
            is_contract_deploy: false,
        };
        let res = lookup_reserved_variable("tx-sender", &mut exec_state, &invoke_ctx);
        assert!(matches!(
            res,
            Err(VmExecutionError::Runtime(
                RuntimeError::NoSenderInContext,
                _
            ))
        ));
    }
}
