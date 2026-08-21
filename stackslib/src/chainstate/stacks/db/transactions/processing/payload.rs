// Copyright (C) 2026 Stacks Open Internet Foundation
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

//! Execution of Stacks transaction payloads.

use clarity::vm::clarity::TransactionConnection as _;
use clarity::vm::contexts::AssetMap;
use clarity::vm::errors::VmExecutionError;
use clarity::vm::types::{
    BuffData, PrincipalData, QualifiedContractIdentifier, StacksAddressExtensions as _, Value,
};
use clarity::vm::ClarityVersion;

use super::post_conditions;
use crate::chainstate::nakamoto::miner::MinerTenureInfoCause;
use crate::chainstate::stacks::db::transactions::{
    handle_clarity_runtime_error, log_unreachable_error, ClarityRuntimeTxError,
};
use crate::chainstate::stacks::db::{StacksAccount, StacksChainState};
use crate::chainstate::stacks::events::StacksTransactionReceipt;
use crate::chainstate::stacks::miner::TransactionResourceBudgets;
use crate::chainstate::stacks::{Error, StacksTransaction, TransactionPayload};
use crate::clarity_vm::clarity::{
    ClarityConnection as _, ClarityError, ClarityTransactionConnection,
};
use crate::core::StacksEpochId;
use crate::util_lib::strings::VecDisplay;

/// Process the transaction's payload, and run the post-conditions against the resulting state.
///
/// NOTE: this does not verify that the transaction can be processed in the clarity_tx's Stacks
/// epoch.  This check must be performed by the caller before processing the block, e.g. via
/// StacksBlock::validate_transactions_static().
///
/// Returns the stacks transaction receipt
pub fn process(
    clarity_tx: &mut ClarityTransactionConnection,
    tx: &StacksTransaction,
    origin_account: &StacksAccount,
    resource_budgets: &TransactionResourceBudgets,
) -> Result<StacksTransactionReceipt, Error> {
    match tx.payload {
        TransactionPayload::TokenTransfer(ref addr, ref amount, ref memo) => {
            // post-conditions are not allowed for this variant, since they're non-sensical.
            // Their presence in this variant makes the transaction invalid.
            if !tx.post_conditions.is_empty() {
                let msg = "Invalid Stacks transaction: TokenTransfer transactions do not support post-conditions".to_string();
                info!("{}", &msg; "txid" => %tx.txid());

                return Err(Error::InvalidStacksTransaction(msg, false));
            }

            if *addr == origin_account.principal {
                let msg = "Invalid TokenTransfer: address tried to send to itself".to_string();
                info!("{}", &msg; "txid" => %tx.txid());
                return Err(Error::InvalidStacksTransaction(msg, false));
            }

            let cost_before = clarity_tx.cost_so_far();
            let (value, _asset_map, events) = clarity_tx
                .run_stx_transfer(
                    &origin_account.principal,
                    addr,
                    u128::from(*amount),
                    &BuffData {
                        data: Vec::from(memo.0),
                    },
                )
                .map_err(Error::ClarityError)?;

            let mut total_cost = clarity_tx.cost_so_far();
            total_cost
                .sub(&cost_before)
                .expect("BUG: total block cost decreased");

            let receipt =
                StacksTransactionReceipt::from_stx_transfer(tx.clone(), events, value, total_cost);
            Ok(receipt)
        }
        TransactionPayload::ContractCall(ref contract_call) => {
            // if this calls a function that doesn't exist or is syntactically invalid, then the
            // transaction is invalid (since this can be checked statically by the miner).
            // if on the other hand the contract being called has a runtime error, then the
            // transaction is still valid, but no changes will materialize besides debiting the
            // tx fee.
            let contract_id = contract_call.to_clarity_contract_id();
            let cost_before = clarity_tx.cost_so_far();
            let sponsor = tx.sponsor_address().map(|a| a.to_account_principal());
            let epoch_id = clarity_tx.get_epoch();

            let contract_call_resp = clarity_tx.run_contract_call(
                &origin_account.principal,
                sponsor.as_ref(),
                &contract_id,
                &contract_call.function_name,
                &contract_call.function_args,
                |asset_map, _| {
                    post_conditions::check(
                        &tx.post_conditions,
                        &tx.post_condition_mode,
                        origin_account,
                        asset_map,
                        epoch_id,
                        tx.txid(),
                    )
                    .expect("FATAL: error while evaluating post-conditions")
                },
                resource_budgets.get_execution_budget(),
            );

            let mut total_cost = clarity_tx.cost_so_far();
            total_cost
                .sub(&cost_before)
                .expect("BUG: total block cost decreased");

            let (result, asset_map, events, vm_error) = match contract_call_resp {
                Ok((return_value, asset_map, events)) => {
                    info!("Contract-call successfully processed";
                          "txid" => %tx.txid(),
                          "origin" => %origin_account.principal,
                          "origin_nonce" => %origin_account.nonce,
                          "contract_name" => %contract_id,
                          "function_name" => %contract_call.function_name,
                          "function_args" => %VecDisplay(&contract_call.function_args),
                          "return_value" => %return_value,
                          "cost" => ?total_cost);
                    (return_value, asset_map, events, None)
                }
                Err(e) => {
                    log_unreachable_error(&e, &tx.txid());
                    match handle_clarity_runtime_error(e) {
                        ClarityRuntimeTxError::Acceptable { error, err_type } => {
                            info!("Contract-call processed with {}", err_type;
                                      "txid" => %tx.txid(),
                                      "origin" => %origin_account.principal,
                                      "origin_nonce" => %origin_account.nonce,
                                      "contract_name" => %contract_id,
                                      "function_name" => %contract_call.function_name,
                                      "function_args" => %VecDisplay(&contract_call.function_args),
                                      "error" => ?error);
                            (
                                Value::err_none(),
                                AssetMap::new(),
                                vec![],
                                Some(error.to_string()),
                            )
                        }
                        ClarityRuntimeTxError::AbortedByCallback {
                            output,
                            assets_modified,
                            tx_events,
                            reason,
                        } => {
                            info!("Contract-call aborted by post-condition";
                                      "txid" => %tx.txid(),
                                      "origin" => %origin_account.principal,
                                      "origin_nonce" => %origin_account.nonce,
                                      "contract_name" => %contract_id,
                                      "function_name" => %contract_call.function_name,
                                      "function_args" => %VecDisplay(&contract_call.function_args));
                            let receipt = StacksTransactionReceipt::from_condition_aborted_contract_call(
                                    tx.clone(),
                                    tx_events,
                                    output.expect("BUG: Post condition contract call must provide would-have-been-returned value"),
                                    assets_modified.get_stx_burned_total()?,
                                    total_cost,
                                    reason,
                                );
                            return Ok(receipt);
                        }
                        ClarityRuntimeTxError::CostError(cost_after, budget) => {
                            warn!("Block compute budget exceeded: if included, this will invalidate a block"; "txid" => %tx.txid(), "cost" => %cost_after, "budget" => %budget);
                            return Err(Error::CostOverflowError(cost_before, cost_after, budget));
                        }
                        ClarityRuntimeTxError::AnalysisError(runtime_check_err) => {
                            if epoch_id >= StacksEpochId::Epoch21 {
                                // in 2.1 and later, this is a permitted runtime error.  take the
                                // fee from the payer and keep the tx.
                                info!("Contract-call encountered an analysis error at runtime";
                                      "txid" => %tx.txid(),
                                      "origin" => %origin_account.principal,
                                      "origin_nonce" => %origin_account.nonce,
                                      "contract_name" => %contract_id,
                                      "function_name" => %contract_call.function_name,
                                      "function_args" => %VecDisplay(&contract_call.function_args),
                                      "error" => %runtime_check_err);

                                let receipt =
                                    StacksTransactionReceipt::from_runtime_failure_contract_call(
                                        tx.clone(),
                                        total_cost,
                                        runtime_check_err,
                                    );
                                return Ok(receipt);
                            } else {
                                // prior to 2.1, this is not permitted in a block.
                                warn!("Unexpected analysis error invalidating transaction: if included, this will invalidate a block";
                                          "txid" => %tx.txid(),
                                          "origin" => %origin_account.principal,
                                          "origin_nonce" => %origin_account.nonce,
                                           "contract_name" => %contract_id,
                                           "function_name" => %contract_call.function_name,
                                           "function_args" => %VecDisplay(&contract_call.function_args),
                                           "error" => %runtime_check_err);
                                return Err(Error::ClarityError(ClarityError::Interpreter(
                                    VmExecutionError::RuntimeCheck(runtime_check_err),
                                )));
                            }
                        }
                        ClarityRuntimeTxError::ExecutionResourceBudgetExceeded(s) => {
                            warn!("Transaction exceeded miner execution resource limit; will be dropped from mempool";
                                          "error" => s.clone(),
                                          "txid" => %tx.txid(),
                                          "origin" => %origin_account.principal,
                                          "origin_nonce" => %origin_account.nonce,
                                           "contract_name" => %contract_id,
                                           "function_name" => %contract_call.function_name,
                                           "function_args" => %VecDisplay(&contract_call.function_args));
                            return Err(Error::ExecutionResourceBudgetExceeded(s));
                        }
                        ClarityRuntimeTxError::Rejectable(e) => {
                            error!("Unexpected error in validating transaction: if included, this will invalidate a block";
                                       "txid" => %tx.txid(),
                                       "origin" => %origin_account.principal,
                                       "origin_nonce" => %origin_account.nonce,
                                       "contract_name" => %contract_id,
                                       "function_name" => %contract_call.function_name,
                                       "function_args" => %VecDisplay(&contract_call.function_args),
                                       "error" => ?e);
                            return Err(Error::ClarityError(e));
                        }
                    }
                }
            };

            let receipt = StacksTransactionReceipt::from_contract_call(
                tx.clone(),
                events,
                result,
                asset_map.get_stx_burned_total()?,
                total_cost,
                vm_error,
            );
            Ok(receipt)
        }
        TransactionPayload::SmartContract(ref smart_contract, ref version_opt) => {
            let epoch_id = clarity_tx.get_epoch();
            let clarity_version =
                version_opt.unwrap_or(ClarityVersion::default_for_epoch(clarity_tx.get_epoch()));
            let issuer_principal = match origin_account.principal {
                PrincipalData::Standard(ref p) => p.clone(),
                _ => {
                    unreachable!(
                        "BUG: transaction issued by something other than a standard principal"
                    );
                }
            };

            let contract_id =
                QualifiedContractIdentifier::new(issuer_principal, smart_contract.name.clone());
            let contract_code_str = smart_contract.code_body.to_string();

            // can't be instantiated already -- if this fails, then the transaction is invalid
            // (because this can be checked statically by the miner before mining the block).
            if StacksChainState::get_contract(clarity_tx, &contract_id)?.is_some() {
                let msg = format!("Duplicate contract '{}'", &contract_id);
                info!("{}", &msg);

                return Err(Error::InvalidStacksTransaction(msg, false));
            }

            let cost_before = clarity_tx.cost_so_far();

            // analysis pass -- if this fails, then the transaction is still accepted, but nothing is stored or processed.
            // The reason for this is that analyzing the transaction is itself an expensive
            // operation, and the paying account will need to be debited the fee regardless.
            //
            // `max_analysis_time` bounds the analysis phase on the
            // non-consensus voting paths (mining / block-proposal validation); it is
            // `None` on deterministic replay/commit (consensus stays deterministic).
            let analysis_resp = clarity_tx.analyze_smart_contract(
                &contract_id,
                clarity_version,
                &contract_code_str,
                resource_budgets.get_analysis_budget(),
            );
            let (contract_ast, contract_analysis) = match analysis_resp {
                Ok(x) => x,
                Err(e) => {
                    log_unreachable_error(&e, &tx.txid());
                    match e {
                        ClarityError::CostError(ref cost_after, ref budget) => {
                            warn!(
                                "Block compute budget exceeded on {}: cost before={}, after={}, budget={}",
                                tx.txid(),
                                &cost_before,
                                cost_after,
                                budget
                            );
                            return Err(Error::CostOverflowError(
                                cost_before,
                                cost_after.clone(),
                                budget.clone(),
                            ));
                        }
                        ClarityError::AnalysisResourceBudgetExceeded(s) => {
                            // The analysis phase exceeded its wall-clock deadline or allocation limit (on a voting path only).
                            warn!("Contract analysis exceeded the analysis resource budget; tx will be dropped from the mempool";
                                  "error" => s.clone(),
                                  "txid" => %tx.txid(),
                                  "contract_name" => %contract_id,
                            );
                            return Err(Error::AnalysisResourceBudgetExceeded(s));
                        }
                        other_error => {
                            if let ClarityError::Parse(err) = &other_error {
                                if err.rejectable_in_epoch(clarity_tx.get_epoch()) {
                                    info!(
                                        "Transaction {} is problematic and should have prevented this block from being relayed",
                                        tx.txid()
                                    );
                                    return Err(Error::ClarityError(other_error));
                                }
                            }
                            if let ClarityError::StaticCheck(err) = &other_error {
                                if err.err.rejectable_in_epoch(clarity_tx.get_epoch()) {
                                    info!(
                                        "Transaction {} is problematic and should have prevented this block from being relayed",
                                        tx.txid()
                                    );
                                    return Err(Error::ClarityError(other_error));
                                }
                            }
                            // this analysis isn't free -- convert to runtime error
                            let mut analysis_cost = clarity_tx.cost_so_far();
                            analysis_cost
                                .sub(&cost_before)
                                .expect("BUG: total block cost decreased");

                            info!(
                                "Runtime error in contract analysis for {contract_id}: {other_error:?}";
                                "txid" => %tx.txid(),
                            );
                            let receipt = StacksTransactionReceipt::from_analysis_failure(
                                tx.clone(),
                                analysis_cost,
                                other_error,
                            );

                            // abort now -- no burns
                            return Ok(receipt);
                        }
                    }
                }
            };

            let mut analysis_cost = clarity_tx.cost_so_far();
            analysis_cost
                .sub(&cost_before)
                .expect("BUG: total block cost decreased");
            let sponsor = tx.sponsor_address().map(|a| a.to_account_principal());

            // execution -- if this fails due to a runtime error, then the transaction is still
            // accepted, but the contract does not materialize (but the sender is out their fee).
            let initialize_resp = clarity_tx.initialize_smart_contract(
                &contract_id,
                clarity_version,
                &contract_ast,
                &contract_code_str,
                sponsor,
                |asset_map, _| {
                    post_conditions::check(
                        &tx.post_conditions,
                        &tx.post_condition_mode,
                        origin_account,
                        asset_map,
                        epoch_id,
                        tx.txid(),
                    )
                    .expect("FATAL: error while evaluating post-conditions")
                },
                resource_budgets.get_execution_budget(),
            );

            let mut total_cost = clarity_tx.cost_so_far();
            total_cost
                .sub(&cost_before)
                .expect("BUG: total block cost decreased");

            let (asset_map, events) = match initialize_resp {
                Ok(x) => {
                    // store analysis -- if this fails, then the have some pretty bad problems
                    clarity_tx
                        .save_analysis(&contract_id, &contract_analysis)
                        .expect("FATAL: failed to store contract analysis");
                    x
                }
                Err(e) => {
                    log_unreachable_error(&e, &tx.txid());
                    match handle_clarity_runtime_error(e) {
                        ClarityRuntimeTxError::Acceptable { error, err_type } => {
                            info!("Smart-contract processed with {}", err_type;
                                      "txid" => %tx.txid(),
                                      "contract" => %contract_id,
                                      "error" => ?error);
                            // When top-level code in a contract publish causes a runtime error,
                            // the transaction is accepted, but the contract is not created.
                            //   Return a tx receipt with an `err_none()` result to indicate
                            //   that the transaction failed during execution.
                            let receipt = StacksTransactionReceipt {
                                transaction: tx.clone().into(),
                                events: vec![],
                                post_condition_aborted: false,
                                result: Value::err_none(),
                                stx_burned: 0,
                                contract_analysis: Some(contract_analysis),
                                execution_cost: total_cost,
                                microblock_header: None,
                                tx_index: 0,
                                vm_error: Some(error.to_string()),
                                problematic_skipped: None,
                            };
                            return Ok(receipt);
                        }
                        ClarityRuntimeTxError::AbortedByCallback {
                            assets_modified,
                            tx_events,
                            reason,
                            ..
                        } => {
                            let receipt =
                                StacksTransactionReceipt::from_condition_aborted_smart_contract(
                                    tx.clone(),
                                    tx_events,
                                    assets_modified.get_stx_burned_total()?,
                                    contract_analysis,
                                    total_cost,
                                    reason,
                                );
                            return Ok(receipt);
                        }
                        ClarityRuntimeTxError::CostError(cost_after, budget) => {
                            warn!("Block compute budget exceeded: if included, this will invalidate a block";
                                      "txid" => %tx.txid(),
                                      "cost" => %cost_after,
                                      "budget" => %budget);
                            return Err(Error::CostOverflowError(cost_before, cost_after, budget));
                        }
                        ClarityRuntimeTxError::AnalysisError(runtime_check_err) => {
                            if epoch_id >= StacksEpochId::Epoch21 {
                                // in 2.1 and later, this is a permitted runtime error.  take the
                                // fee from the payer and keep the tx.
                                info!("Smart-contract encountered an analysis error at runtime";
                                      "txid" => %tx.txid(),
                                      "contract" => %contract_id,
                                      "error" => %runtime_check_err);

                                let receipt =
                                    StacksTransactionReceipt::from_runtime_failure_smart_contract(
                                        tx.clone(),
                                        total_cost,
                                        contract_analysis,
                                        runtime_check_err,
                                    );
                                return Ok(receipt);
                            } else {
                                // prior to 2.1, this is not permitted in a block.
                                warn!("Unexpected analysis error invalidating transaction: if included, this will invalidate a block";
                                      "txid" => %tx.txid(),
                                      "contract" => %contract_id,
                                      "error" => %runtime_check_err);
                                return Err(Error::ClarityError(ClarityError::Interpreter(
                                    VmExecutionError::RuntimeCheck(runtime_check_err),
                                )));
                            }
                        }
                        ClarityRuntimeTxError::ExecutionResourceBudgetExceeded(s) => {
                            warn!("Transaction exceeded miner execution resource limit; will be dropped from mempool";
                                          "error" => s.clone(),
                                          "txid" => %tx.txid(),
                                          "contract" => %contract_id);
                            return Err(Error::ExecutionResourceBudgetExceeded(s));
                        }
                        ClarityRuntimeTxError::Rejectable(e) => {
                            error!("Unexpected error invalidating transaction: if included, this will invalidate a block";
                                       "txid" => %tx.txid(),
                                       "contract_name" => %contract_id,
                                       "error" => ?e);
                            return Err(Error::ClarityError(e));
                        }
                    }
                }
            };

            let receipt = StacksTransactionReceipt::from_smart_contract(
                tx.clone(),
                events,
                asset_map.get_stx_burned_total()?,
                contract_analysis,
                total_cost,
            );
            Ok(receipt)
        }
        TransactionPayload::PoisonMicroblock(ref mblock_header_1, ref mblock_header_2) => {
            // post-conditions are not allowed for this variant, since they're non-sensical.
            // Their presence in this variant makes the transaction invalid.
            if !tx.post_conditions.is_empty() {
                let msg = "Invalid Stacks transaction: PoisonMicroblock transactions do not support post-conditions".to_string();
                info!("{}", &msg);

                return Err(Error::InvalidStacksTransaction(msg, false));
            }

            let cost_before = clarity_tx.cost_so_far();
            let res = clarity_tx.run_poison_microblock(
                &origin_account.principal,
                mblock_header_1,
                mblock_header_2,
            )?;
            let mut cost = clarity_tx.cost_so_far();
            cost.sub(&cost_before)
                .expect("BUG: running poison microblock tx has negative cost");

            let receipt = StacksTransactionReceipt::from_poison_microblock(tx.clone(), res, cost);

            Ok(receipt)
        }
        TransactionPayload::Coinbase(..) => {
            // NOTE: technically, post-conditions are allowed (even if they're non-sensical).

            let receipt = StacksTransactionReceipt::from_coinbase(tx.clone());
            Ok(receipt)
        }
        TransactionPayload::TenureChange(ref payload) => {
            // post-conditions are not allowed for this variant, since they're non-sensical.
            // Their presence in this variant makes the transaction invalid.
            if !tx.post_conditions.is_empty() {
                let msg = "Invalid Stacks transaction: TenureChange transactions do not support post-conditions".to_string();
                info!("{msg}");

                return Err(Error::InvalidStacksTransaction(msg, false));
            }

            if !payload.cause.is_new_tenure() {
                debug!(
                    "TenureChange {:?} extends existing block tenure (confirms {} blocks)",
                    &payload.cause, &payload.previous_tenure_blocks
                );
            }

            // defensive check -- this tenure change variant must be supported in this epoch
            // (or we have a problem).  This should get caught earlier in append_block(), but
            // this is kept here as an added layer of redundancy
            let epoch_id = clarity_tx.get_epoch();
            if MinerTenureInfoCause::from(payload.cause).is_sip034_tenure_extension()
                && !epoch_id.supports_specific_budget_extends()
            {
                let msg = format!(
                    "Invalid Stacks transaction: TenureChange cause variant {:?} is not supported in epoch {:?}",
                    &payload.cause, &epoch_id
                );
                info!("{msg}");
                return Err(Error::InvalidStacksTransaction(msg, false));
            }

            let receipt = StacksTransactionReceipt::from_tenure_change(tx.clone());
            Ok(receipt)
        }
    }
}
