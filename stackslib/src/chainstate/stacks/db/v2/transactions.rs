use std::collections::{BTreeMap, btree_map::Entry};

use clarity::vm::{
    types::{PrincipalData, TupleData, BuffData, StacksAddressExtensions, QualifiedContractIdentifier}, 
    database::NULL_BURN_STATE_DB, ContractName, ast::{ASTRules, errors::ParseErrors}, 
    events::{StacksTransactionEvent, STXEventType, STXMintEventData}, 
    Value, costs::ExecutionCost, tests::BurnStateDB, 
    errors::{CheckErrors, Error as InterpreterError}, clarity::TransactionConnection, contexts::AssetMap, ClarityVersion
};
use stacks_common::{
    types::{chainstate::{StacksAddress, StacksBlockId, TrieHash, ConsensusHash, BlockHeaderHash}, Address, StacksEpochId}, 
    address::{
        C32_ADDRESS_VERSION_MAINNET_SINGLESIG, C32_ADDRESS_VERSION_MAINNET_MULTISIG, 
        C32_ADDRESS_VERSION_TESTNET_SINGLESIG, C32_ADDRESS_VERSION_TESTNET_MULTISIG
    }, util::hash::Hash160
};

use crate::{
    burnchains::bitcoin::address::LegacyBitcoinAddress, 
    chainstate::stacks::{
            address::StacksAddressExtensions as ChainstateStacksAddressExtensions,
            Error, events::StacksTransactionReceipt, TransactionVersion, boot, TransactionPayload, 
            TransactionSmartContract, StacksTransaction, TokenTransferMemo, StacksBlockHeader, 
            db::StacksHeaderInfo, 
            index::{
                ClarityMarfTrieId, db::DbConnection, trie_db::TrieDb, marf::MARF
            }
    }, 
    util_lib::{
        boot::{boot_code_addr, boot_code_tx_auth, boot_code_acc, boot_code_id}, 
        strings::{StacksString, VecDisplay}
    }, 
    core::{
        BURNCHAIN_BOOT_CONSENSUS_HASH, BOOT_BLOCK_HASH, FIRST_BURNCHAIN_CONSENSUS_HASH, 
        FIRST_STACKS_BLOCK_HASH, MAINNET_2_0_GENESIS_ROOT_HASH
    }, 
    net::atlas::BNS_CHARS_REGEX, 
    clarity_vm::clarity::{
        ClarityBlockConnection, ClarityConnection, ClarityInstance, ClarityTransactionConnection,
        Error as clarity_error,
    },
};

use super::{
    super::{ChainStateBootData, ClarityTx, DBConfig, CHAINSTATE_VERSION, StacksAccount, transactions::ClarityRuntimeTxError},
    utils::ChainStateUtils,
    StacksChainStateImpl
};

impl<Conn> StacksChainStateImpl<Conn>
where
    Conn: DbConnection + TrieDb
{
    /// Process the transaction's payload, and run the post-conditions against the resulting state.
    ///
    /// NOTE: this does not verify that the transaction can be processed in the clarity_tx's Stacks
    /// epoch.  This check must be performed by the caller before processing the block, e.g. via
    /// StacksBlock::validate_transactions_static().
    ///
    /// Returns the stacks transaction receipt
    pub fn process_transaction_payload(
        clarity_tx: &mut ClarityTransactionConnection,
        tx: &StacksTransaction,
        origin_account: &StacksAccount,
        ast_rules: ASTRules,
    ) -> Result<StacksTransactionReceipt, Error> {
        match tx.payload {
            TransactionPayload::TokenTransfer(ref addr, ref amount, ref memo) => {
                // post-conditions are not allowed for this variant, since they're non-sensical.
                // Their presence in this variant makes the transaction invalid.
                if tx.post_conditions.len() > 0 {
                    let msg = format!("Invalid Stacks transaction: TokenTransfer transactions do not support post-conditions");
                    warn!("{}", &msg);

                    return Err(Error::InvalidStacksTransaction(msg, false));
                }

                if *addr == origin_account.principal {
                    let msg = format!("Invalid TokenTransfer: address tried to send to itself");
                    warn!("{}", &msg);
                    return Err(Error::InvalidStacksTransaction(msg, false));
                }

                let cost_before = clarity_tx.cost_so_far();
                let (value, _asset_map, events) = clarity_tx
                    .run_stx_transfer(
                        &origin_account.principal,
                        addr,
                        u128::from(*amount),
                        &BuffData {
                            data: Vec::from(memo.0.clone()),
                        },
                    )
                    .map_err(Error::ClarityError)?;

                let mut total_cost = clarity_tx.cost_so_far();
                total_cost
                    .sub(&cost_before)
                    .expect("BUG: total block cost decreased");

                let receipt = StacksTransactionReceipt::from_stx_transfer(
                    tx.clone(),
                    events,
                    value,
                    total_cost,
                );
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
                        !ChainStateUtils::check_transaction_postconditions(
                            &tx.post_conditions,
                            &tx.post_condition_mode,
                            origin_account,
                            asset_map,
                        )
                    },
                );

                let mut total_cost = clarity_tx.cost_so_far();
                total_cost
                    .sub(&cost_before)
                    .expect("BUG: total block cost decreased");

                let (result, asset_map, events) = match contract_call_resp {
                    Ok((return_value, asset_map, events)) => {
                        info!("Contract-call successfully processed";
                              "contract_name" => %contract_id,
                              "function_name" => %contract_call.function_name,
                              "function_args" => %VecDisplay(&contract_call.function_args),
                              "return_value" => %return_value,
                              "cost" => ?total_cost);
                        (return_value, asset_map, events)
                    }
                    Err(e) => match ChainStateUtils::handle_clarity_runtime_error(e) {
                        ClarityRuntimeTxError::Acceptable { error, err_type } => {
                            info!("Contract-call processed with {}", err_type;
                                      "contract_name" => %contract_id,
                                      "function_name" => %contract_call.function_name,
                                      "function_args" => %VecDisplay(&contract_call.function_args),
                                      "error" => ?error);
                            (Value::err_none(), AssetMap::new(), vec![])
                        }
                        ClarityRuntimeTxError::AbortedByCallback(value, assets, events) => {
                            info!("Contract-call aborted by post-condition";
                                      "contract_name" => %contract_id,
                                      "function_name" => %contract_call.function_name,
                                      "function_args" => %VecDisplay(&contract_call.function_args));
                            let receipt = StacksTransactionReceipt::from_condition_aborted_contract_call(
                                    tx.clone(),
                                    events,
                                    value.expect("BUG: Post condition contract call must provide would-have-been-returned value"),
                                    assets.get_stx_burned_total(),
                                    total_cost);
                            return Ok(receipt);
                        }
                        ClarityRuntimeTxError::CostError(cost_after, budget) => {
                            warn!("Block compute budget exceeded: if included, this will invalidate a block"; "txid" => %tx.txid(), "cost" => %cost_after, "budget" => %budget);
                            return Err(Error::CostOverflowError(cost_before, cost_after, budget));
                        }
                        ClarityRuntimeTxError::AnalysisError(check_error) => {
                            if epoch_id >= StacksEpochId::Epoch21 {
                                // in 2.1 and later, this is a permitted runtime error.  take the
                                // fee from the payer and keep the tx.
                                warn!("Contract-call encountered an analysis error at runtime";
                                      "contract_name" => %contract_id,
                                      "function_name" => %contract_call.function_name,
                                      "function_args" => %VecDisplay(&contract_call.function_args),
                                      "error" => %check_error);

                                let receipt =
                                    StacksTransactionReceipt::from_runtime_failure_contract_call(
                                        tx.clone(),
                                        total_cost,
                                        check_error,
                                    );
                                return Ok(receipt);
                            } else {
                                // prior to 2.1, this is not permitted in a block.
                                warn!("Unexpected analysis error invalidating transaction: if included, this will invalidate a block";
                                           "contract_name" => %contract_id,
                                           "function_name" => %contract_call.function_name,
                                           "function_args" => %VecDisplay(&contract_call.function_args),
                                           "error" => %check_error);
                                return Err(Error::ClarityError(clarity_error::Interpreter(
                                    InterpreterError::Unchecked(check_error),
                                )));
                            }
                        }
                        ClarityRuntimeTxError::Rejectable(e) => {
                            error!("Unexpected error in validating transaction: if included, this will invalidate a block";
                                       "contract_name" => %contract_id,
                                       "function_name" => %contract_call.function_name,
                                       "function_args" => %VecDisplay(&contract_call.function_args),
                                       "error" => ?e);
                            return Err(Error::ClarityError(e));
                        }
                    },
                };

                let receipt = StacksTransactionReceipt::from_contract_call(
                    tx.clone(),
                    events,
                    result,
                    asset_map.get_stx_burned_total(),
                    total_cost,
                );
                Ok(receipt)
            }
            TransactionPayload::SmartContract(ref smart_contract, ref version_opt) => {
                let epoch_id = clarity_tx.get_epoch();
                let clarity_version = version_opt
                    .unwrap_or(ClarityVersion::default_for_epoch(clarity_tx.get_epoch()));
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
                if Self::get_contract(clarity_tx, &contract_id)?.is_some() {
                    let msg = format!("Duplicate contract '{}'", &contract_id);
                    warn!("{}", &msg);

                    return Err(Error::InvalidStacksTransaction(msg, false));
                }

                let cost_before = clarity_tx.cost_so_far();

                // analysis pass -- if this fails, then the transaction is still accepted, but nothing is stored or processed.
                // The reason for this is that analyzing the transaction is itself an expensive
                // operation, and the paying account will need to be debited the fee regardless.
                let analysis_resp = clarity_tx.analyze_smart_contract(
                    &contract_id,
                    clarity_version,
                    &contract_code_str,
                    ast_rules,
                );
                let (contract_ast, contract_analysis) = match analysis_resp {
                    Ok(x) => x,
                    Err(e) => {
                        match e {
                            clarity_error::CostError(ref cost_after, ref budget) => {
                                warn!("Block compute budget exceeded on {}: cost before={}, after={}, budget={}", tx.txid(), &cost_before, cost_after, budget);
                                return Err(Error::CostOverflowError(
                                    cost_before,
                                    cost_after.clone(),
                                    budget.clone(),
                                ));
                            }
                            other_error => {
                                if ast_rules == ASTRules::PrecheckSize {
                                    // a [Vary]ExpressionDepthTooDeep error in this situation
                                    // invalidates the block, since this should have prevented the
                                    // block from getting relayed in the first place
                                    if let clarity_error::Parse(ref parse_error) = &other_error {
                                        match parse_error.err {
                                            ParseErrors::ExpressionStackDepthTooDeep
                                            | ParseErrors::VaryExpressionStackDepthTooDeep => {
                                                info!("Transaction {} is problematic and should have prevented this block from being relayed", tx.txid());
                                                return Err(Error::ClarityError(other_error));
                                            }
                                            _ => {}
                                        }
                                    }
                                }
                                if let clarity_error::Analysis(err) = &other_error {
                                    if let CheckErrors::SupertypeTooLarge = err.err {
                                        info!("Transaction {} is problematic and should have prevented this block from being relayed", tx.txid());
                                        return Err(Error::ClarityError(other_error));
                                    }
                                }
                                // this analysis isn't free -- convert to runtime error
                                let mut analysis_cost = clarity_tx.cost_so_far();
                                analysis_cost
                                    .sub(&cost_before)
                                    .expect("BUG: total block cost decreased");

                                warn!(
                                    "Runtime error in contract analysis for {}: {:?}",
                                    &contract_id, &other_error;
                                    "txid" => %tx.txid(),
                                    "AST rules" => %format!("{:?}", &ast_rules)
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
                        !ChainStateUtils::check_transaction_postconditions(
                            &tx.post_conditions,
                            &tx.post_condition_mode,
                            origin_account,
                            asset_map,
                        )
                    },
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
                    Err(e) => match ChainStateUtils::handle_clarity_runtime_error(e) {
                        ClarityRuntimeTxError::Acceptable { error, err_type } => {
                            info!("Smart-contract processed with {}", err_type;
                                      "txid" => %tx.txid(),
                                      "contract" => %contract_id,
                                      "code" => %contract_code_str,
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
                            };
                            return Ok(receipt);
                        }
                        ClarityRuntimeTxError::AbortedByCallback(_, assets, events) => {
                            let receipt =
                                StacksTransactionReceipt::from_condition_aborted_smart_contract(
                                    tx.clone(),
                                    events,
                                    assets.get_stx_burned_total(),
                                    contract_analysis,
                                    total_cost,
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
                        ClarityRuntimeTxError::AnalysisError(check_error) => {
                            if epoch_id >= StacksEpochId::Epoch21 {
                                // in 2.1 and later, this is a permitted runtime error.  take the
                                // fee from the payer and keep the tx.
                                warn!("Smart-contract encountered an analysis error at runtime";
                                      "txid" => %tx.txid(),
                                      "contract" => %contract_id,
                                      "code" => %contract_code_str,
                                      "error" => %check_error);

                                let receipt =
                                    StacksTransactionReceipt::from_runtime_failure_smart_contract(
                                        tx.clone(),
                                        total_cost,
                                        contract_analysis,
                                        check_error,
                                    );
                                return Ok(receipt);
                            } else {
                                // prior to 2.1, this is not permitted in a block.
                                warn!("Unexpected analysis error invalidating transaction: if included, this will invalidate a block";
                                      "txid" => %tx.txid(),
                                      "contract" => %contract_id,
                                      "code" => %contract_code_str,
                                      "error" => %check_error);
                                return Err(Error::ClarityError(clarity_error::Interpreter(
                                    InterpreterError::Unchecked(check_error),
                                )));
                            }
                        }
                        ClarityRuntimeTxError::Rejectable(e) => {
                            error!("Unexpected error invalidating transaction: if included, this will invalidate a block";
                                       "txid" => %tx.txid(),
                                       "contract_name" => %contract_id,
                                       "code" => %contract_code_str,
                                       "error" => ?e);
                            return Err(Error::ClarityError(e));
                        }
                    },
                };

                let receipt = StacksTransactionReceipt::from_smart_contract(
                    tx.clone(),
                    events,
                    asset_map.get_stx_burned_total(),
                    contract_analysis,
                    total_cost,
                );
                Ok(receipt)
            }
            TransactionPayload::PoisonMicroblock(ref mblock_header_1, ref mblock_header_2) => {
                // post-conditions are not allowed for this variant, since they're non-sensical.
                // Their presence in this variant makes the transaction invalid.
                if tx.post_conditions.len() > 0 {
                    let msg = format!("Invalid Stacks transaction: PoisonMicroblock transactions do not support post-conditions");
                    warn!("{}", &msg);

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

                let receipt =
                    StacksTransactionReceipt::from_poison_microblock(tx.clone(), res, cost);

                Ok(receipt)
            }
            TransactionPayload::Coinbase(..) => {
                // no-op; not handled here
                // NOTE: technically, post-conditions are allowed (even if they're non-sensical).

                let receipt = StacksTransactionReceipt::from_coinbase(tx.clone());
                Ok(receipt)
            }
            TransactionPayload::TenureChange(ref payload, ref signature) => {
                // post-conditions are not allowed for this variant, since they're non-sensical.
                // Their presence in this variant makes the transaction invalid.
                if tx.post_conditions.len() > 0 {
                    let msg = format!("Invalid Stacks transaction: TenureChange transactions do not support post-conditions");
                    warn!("{msg}");

                    return Err(Error::InvalidStacksTransaction(msg, false));
                }

                // TODO: More checks before adding to block?

                let receipt = StacksTransactionReceipt::from_tenure_change(tx.clone());
                Ok(receipt)
            }
        }
    }
}