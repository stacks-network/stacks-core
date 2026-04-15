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

use clarity::boot_util::boot_code_id;
use clarity::vm::contexts::{ExecutionState, GlobalContext};
use clarity::vm::costs::cost_functions::ClarityCostFunction;
use clarity::vm::costs::runtime_cost;
use clarity::vm::database::{ClarityDatabase, STXBalance};
use clarity::vm::errors::{RuntimeError, VmExecutionError};
use clarity::vm::events::{STXEventType, STXLockEventData, StacksTransactionEvent};
use clarity::vm::types::{PrincipalData, QualifiedContractIdentifier};
use clarity::vm::Value;
use stacks_common::{debug, error};

use crate::events::synthesize_pox_event_info;
use crate::{LockingError, POX_5_NAME};

/// Parse the returned value from PoX-5 `stake`, `stake-pooled`, `stake-extend`,
/// and `stake-extend-pooled` functions into (stacker, amount-ustx, unlock-burn-height).
/// These functions return `(ok { stacker, amount-ustx, unlock-burn-height, ... })`.
fn parse_pox_stake_result(result: &Value) -> std::result::Result<(PrincipalData, u128, u64), u128> {
    match result
        .clone()
        .expect_result()
        .expect("FATAL: unexpected clarity value")
    {
        Ok(res) => {
            let tuple_data = res.expect_tuple().expect("FATAL: unexpected clarity value");
            let stacker = tuple_data
                .get("stacker")
                .expect("FATAL: no 'stacker'")
                .to_owned()
                .expect_principal()
                .expect("FATAL: unexpected clarity value");

            let amount_ustx = tuple_data
                .get("amount-ustx")
                .expect("FATAL: no 'amount-ustx'")
                .to_owned()
                .expect_u128()
                .expect("FATAL: unexpected clarity value");

            let unlock_burn_height = tuple_data
                .get("unlock-burn-height")
                .expect("FATAL: no 'unlock-burn-height'")
                .to_owned()
                .expect_u128()
                .expect("FATAL: unexpected clarity value")
                .try_into()
                .expect("FATAL: 'unlock-burn-height' overflow");

            Ok((stacker, amount_ustx, unlock_burn_height))
        }
        Err(e) => Err(e.expect_u128().expect("FATAL: unexpected clarity value")),
    }
}

/// Parse the returned value from PoX-5 `stake-update` and `stake-update-pooled` functions
/// into (stacker, amount-ustx). These return `(ok { stacker, amount-ustx, unlock-burn-height, ... })`.
fn parse_pox_stake_update_result(
    result: &Value,
) -> std::result::Result<(PrincipalData, u128), u128> {
    match result
        .clone()
        .expect_result()
        .expect("FATAL: unexpected clarity value")
    {
        Ok(res) => {
            let tuple_data = res.expect_tuple().expect("FATAL: unexpected clarity value");
            let stacker = tuple_data
                .get("stacker")
                .expect("FATAL: no 'stacker'")
                .to_owned()
                .expect_principal()
                .expect("FATAL: unexpected clarity value");

            let amount_ustx = tuple_data
                .get("amount-ustx")
                .expect("FATAL: no 'amount-ustx'")
                .to_owned()
                .expect_u128()
                .expect("FATAL: unexpected clarity value");

            Ok((stacker, amount_ustx))
        }
        Err(e) => Err(e.expect_u128().expect("FATAL: unexpected clarity value")),
    }
}

/////////////////////// PoX-5 /////////////////////////////////

/// Lock up STX for PoX for a time.  Does NOT touch the account nonce.
pub fn pox_lock_v5(
    db: &mut ClarityDatabase,
    principal: &PrincipalData,
    lock_amount: u128,
    unlock_burn_height: u64,
) -> Result<(), LockingError> {
    assert!(unlock_burn_height > 0);
    assert!(lock_amount > 0);

    let mut snapshot = db.get_stx_balance_snapshot(principal)?;

    if snapshot.has_locked_tokens()? {
        return Err(LockingError::PoxAlreadyLocked);
    }
    if !snapshot.can_transfer(lock_amount)? {
        return Err(LockingError::PoxInsufficientBalance);
    }
    snapshot.lock_tokens_v5(lock_amount, unlock_burn_height)?;

    debug!(
        "PoX v5 lock applied";
        "pox_locked_ustx" => snapshot.balance().amount_locked(),
        "available_ustx" => snapshot.balance().amount_unlocked(),
        "unlock_burn_height" => unlock_burn_height,
        "account" => %principal,
    );

    snapshot.save()?;
    Ok(())
}

/// Extend a STX lock up for PoX for a time.  Does NOT touch the account nonce.
/// Returns Ok(lock_amount) when successful
///
/// # Errors
/// - Returns Error::PoxExtendNotLocked if this function was called on an account
///   which isn't locked. This *should* have been checked by the PoX v5 contract,
///   so this should surface in a panic.
pub fn pox_lock_extend_v5(
    db: &mut ClarityDatabase,
    principal: &PrincipalData,
    unlock_burn_height: u64,
) -> Result<u128, LockingError> {
    assert!(unlock_burn_height > 0);

    let mut snapshot = db.get_stx_balance_snapshot(principal)?;

    if !snapshot.has_locked_tokens()? {
        return Err(LockingError::PoxExtendNotLocked);
    }

    snapshot.extend_lock_v5(unlock_burn_height)?;

    let amount_locked = snapshot.balance().amount_locked();

    debug!(
        "PoX v5 lock applied";
        "pox_locked_ustx" => amount_locked,
        "available_ustx" => snapshot.balance().amount_unlocked(),
        "unlock_burn_height" => unlock_burn_height,
        "account" => %principal,
    );

    snapshot.save()?;
    Ok(amount_locked)
}

/// Increase a STX lock up for PoX-5.  Does NOT touch the account nonce.
/// Returns Ok( account snapshot ) when successful
///
/// # Errors
/// - Returns Error::PoxExtendNotLocked if this function was called on an account
///   which isn't locked. This *should* have been checked by the PoX v5 contract,
///   so this should surface in a panic.
pub fn pox_lock_increase_v5(
    db: &mut ClarityDatabase,
    principal: &PrincipalData,
    new_total_locked: u128,
) -> Result<STXBalance, LockingError> {
    assert!(new_total_locked > 0);

    let mut snapshot = db.get_stx_balance_snapshot(principal)?;

    if !snapshot.has_locked_tokens()? {
        return Err(LockingError::PoxExtendNotLocked);
    }

    let bal = snapshot.canonical_balance_repr()?;
    let total_amount = bal
        .amount_unlocked()
        .checked_add(bal.amount_locked())
        .expect("STX balance overflowed u128");
    if total_amount < new_total_locked {
        return Err(LockingError::PoxInsufficientBalance);
    }

    if bal.amount_locked() > new_total_locked {
        return Err(LockingError::PoxInvalidIncrease);
    }

    snapshot.increase_lock_v5(new_total_locked)?;

    let out_balance = snapshot.canonical_balance_repr()?;

    debug!(
        "PoX v5 lock increased";
        "pox_locked_ustx" => out_balance.amount_locked(),
        "available_ustx" => out_balance.amount_unlocked(),
        "unlock_burn_height" => out_balance.unlock_height(),
        "account" => %principal,
    );

    snapshot.save()?;
    Ok(out_balance)
}

/// Handle responses from stake and stake-pooled in pox-5 -- functions that *lock up* STX
fn handle_stake_lockup_pox_v5(
    global_context: &mut GlobalContext,
    function_name: &str,
    value: &Value,
) -> Result<Option<StacksTransactionEvent>, VmExecutionError> {
    debug!(
        "Handle special-case contract-call to {:?} {function_name} (which returned {value:?})",
        boot_code_id(POX_5_NAME, global_context.mainnet)
    );
    runtime_cost(
        ClarityCostFunction::StxTransfer,
        &mut global_context.cost_track,
        1,
    )?;

    let (stacker, locked_amount, unlock_height) = match parse_pox_stake_result(value) {
        Ok(x) => x,
        Err(_) => {
            return Ok(None);
        }
    };

    match pox_lock_v5(
        &mut global_context.database,
        &stacker,
        locked_amount,
        unlock_height,
    ) {
        Ok(_) => {
            // Log the stacking in the asset map
            global_context.log_stacking(&stacker, locked_amount)?;

            let event =
                StacksTransactionEvent::STXEvent(STXEventType::STXLockEvent(STXLockEventData {
                    locked_amount,
                    unlock_height,
                    locked_address: stacker,
                    contract_identifier: boot_code_id(POX_5_NAME, global_context.mainnet),
                }));
            Ok(Some(event))
        }
        Err(LockingError::DefunctPoxContract) => Err(VmExecutionError::Runtime(
            RuntimeError::DefunctPoxContract,
            None,
        )),
        Err(LockingError::PoxAlreadyLocked) => Err(VmExecutionError::Runtime(
            RuntimeError::PoxAlreadyLocked,
            None,
        )),
        Err(e) => {
            panic!(
                "FATAL: failed to lock {locked_amount} from {stacker} until {unlock_height}: '{e:?}'"
            );
        }
    }
}

/// Handle responses from stake-extend and stake-extend-pooled in pox-5 -- functions that
/// *extend already-locked* STX.
fn handle_stake_lockup_extension_pox_v5(
    global_context: &mut GlobalContext,
    function_name: &str,
    value: &Value,
) -> Result<Option<StacksTransactionEvent>, VmExecutionError> {
    debug!(
        "Handle special-case contract-call to {:?} {function_name} (which returned {value:?})",
        boot_code_id(POX_5_NAME, global_context.mainnet),
    );

    runtime_cost(
        ClarityCostFunction::StxTransfer,
        &mut global_context.cost_track,
        1,
    )?;

    let (stacker, _amount_ustx, unlock_height) = match parse_pox_stake_result(value) {
        Ok(x) => x,
        Err(_) => {
            return Ok(None);
        }
    };

    match pox_lock_extend_v5(&mut global_context.database, &stacker, unlock_height) {
        Ok(locked_amount) => {
            // Log the extension in the asset map.  Note that the amount locked
            // doesn't change when you extend, so we log the same amount.
            global_context.log_stacking(&stacker, locked_amount)?;

            let event =
                StacksTransactionEvent::STXEvent(STXEventType::STXLockEvent(STXLockEventData {
                    locked_amount,
                    unlock_height,
                    locked_address: stacker,
                    contract_identifier: boot_code_id(POX_5_NAME, global_context.mainnet),
                }));
            Ok(Some(event))
        }
        Err(LockingError::DefunctPoxContract) => Err(VmExecutionError::Runtime(
            RuntimeError::DefunctPoxContract,
            None,
        )),
        Err(e) => {
            panic!("FATAL: failed to extend lock from {stacker} until {unlock_height}: '{e:?}'");
        }
    }
}

/// Handle responses from stake-update and stake-update-pooled in pox-5 -- functions
/// that *increase already-locked* STX amounts.
fn handle_stake_lockup_increase_pox_v5(
    global_context: &mut GlobalContext,
    function_name: &str,
    value: &Value,
) -> Result<Option<StacksTransactionEvent>, VmExecutionError> {
    debug!(
        "Handle special-case contract-call";
        "contract" => ?boot_code_id(POX_5_NAME, global_context.mainnet),
        "function" => function_name,
        "return-value" => %value,
    );

    runtime_cost(
        ClarityCostFunction::StxTransfer,
        &mut global_context.cost_track,
        1,
    )?;

    let (stacker, total_locked) = match parse_pox_stake_update_result(value) {
        Ok(x) => x,
        Err(_) => {
            return Ok(None);
        }
    };
    match pox_lock_increase_v5(&mut global_context.database, &stacker, total_locked) {
        Ok(new_balance) => {
            // Log the increase in the asset map.  Note that we log the new total locked amount, not the increase.
            global_context.log_stacking(&stacker, new_balance.amount_locked())?;

            let event =
                StacksTransactionEvent::STXEvent(STXEventType::STXLockEvent(STXLockEventData {
                    locked_amount: new_balance.amount_locked(),
                    unlock_height: new_balance.unlock_height(),
                    locked_address: stacker,
                    contract_identifier: boot_code_id(POX_5_NAME, global_context.mainnet),
                }));

            Ok(Some(event))
        }
        Err(LockingError::DefunctPoxContract) => Err(VmExecutionError::Runtime(
            RuntimeError::DefunctPoxContract,
            None,
        )),
        Err(e) => {
            panic!("FATAL: failed to increase lock from {stacker}: '{e:?}'");
        }
    }
}

/// Handle special cases when calling into the PoX-5 API contract
pub fn handle_contract_call(
    global_context: &mut GlobalContext,
    sender_opt: Option<&PrincipalData>,
    contract_id: &QualifiedContractIdentifier,
    function_name: &str,
    args: &[Value],
    value: &Value,
) -> Result<(), VmExecutionError> {
    // Generate a synthetic print event for all functions that alter stacking state
    let print_event_opt = if let Value::Response(response) = value {
        if response.committed {
            // method succeeded.  Synthesize event info, but default to no event report if we fail
            // for some reason.
            // Failure to synthesize an event due to a bug is *NOT* an excuse to crash the whole
            // network!  Event capture is not consensus-critical.
            let event_info_opt = match synthesize_pox_event_info(
                global_context,
                contract_id,
                sender_opt,
                function_name,
                args,
                response,
            ) {
                Ok(Some(event_info)) => Some(event_info),
                Ok(None) => None,
                Err(e) => {
                    error!("Failed to synthesize PoX-5 event info: {e:?}");
                    None
                }
            };
            if let Some(event_info) = event_info_opt {
                let event_response =
                    Value::okay(event_info).expect("FATAL: failed to construct (ok event-info)");
                let tx_event = ExecutionState::construct_print_transaction_event(
                    contract_id.clone(),
                    event_response,
                );
                Some(tx_event)
            } else {
                None
            }
        } else {
            None
        }
    } else {
        None
    };

    // Execute function specific logic to complete the lock-up
    let lock_event_opt = match function_name {
        "stake" | "stake-pooled" => {
            handle_stake_lockup_pox_v5(global_context, function_name, value)?
        }
        "stake-extend" | "stake-extend-pooled" => {
            handle_stake_lockup_extension_pox_v5(global_context, function_name, value)?
        }
        "stake-update" | "stake-update-pooled" => {
            handle_stake_lockup_increase_pox_v5(global_context, function_name, value)?
        }
        _ => None,
    };

    // append the lockup event, so it looks as if the print event happened before the lock-up
    if let Some((batch, _)) = global_context.event_batches.last_mut() {
        if let Some(print_event) = print_event_opt {
            batch.events.push(print_event);
        }
        if let Some(lock_event) = lock_event_opt {
            batch.events.push(lock_event);
        }
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use clarity::consts::CHAIN_ID_TESTNET;
    use clarity::types::StacksEpochId;
    use clarity::vm::contexts::GlobalContext;
    use clarity::vm::costs::LimitedCostTracker;
    use clarity::vm::database::MemoryBackingStore;
    use clarity::vm::types::{StandardPrincipalData, TupleData};
    use clarity::vm::Value;

    use super::*;

    /// Helper: build a pox-5 stake/stake-extend ok response tuple
    fn make_stake_ok_response(
        stacker: &PrincipalData,
        amount_ustx: u128,
        unlock_burn_height: u64,
    ) -> Value {
        Value::okay(Value::Tuple(
            TupleData::from_data(vec![
                ("stacker".into(), Value::Principal(stacker.clone())),
                ("amount-ustx".into(), Value::UInt(amount_ustx)),
                (
                    "unlock-burn-height".into(),
                    Value::UInt(unlock_burn_height as u128),
                ),
            ])
            .unwrap(),
        ))
        .unwrap()
    }

    /// Helper: set up a GlobalContext with a funded account
    fn setup_global_context<'a>(
        store: &'a mut MemoryBackingStore,
        stacker: &PrincipalData,
        total_amount: u128,
    ) -> GlobalContext<'a, 'a> {
        let db = store.as_clarity_db();
        let mut global_context = GlobalContext::new(
            false,
            CHAIN_ID_TESTNET,
            db,
            LimitedCostTracker::new_free(),
            StacksEpochId::Epoch35,
        );
        global_context.begin();
        {
            let mut snapshot = global_context
                .database
                .get_stx_balance_snapshot(stacker)
                .unwrap();
            snapshot.credit(total_amount).expect("Failed to credit");
            snapshot.save().expect("Failed to save");
        }
        global_context
    }

    // ── Parser tests ──

    #[test]
    fn parse_pox_stake_result_ok() {
        let stacker: PrincipalData = StandardPrincipalData::transient().into();
        let response = make_stake_ok_response(&stacker, 500_000, 10_000);
        let (parsed_stacker, amount, height) = parse_pox_stake_result(&response).unwrap();
        assert_eq!(parsed_stacker, stacker);
        assert_eq!(amount, 500_000);
        assert_eq!(height, 10_000);
    }

    #[test]
    fn parse_pox_stake_result_err() {
        let response = Value::error(Value::UInt(1)).unwrap();
        let err = parse_pox_stake_result(&response).unwrap_err();
        assert_eq!(err, 1);
    }

    #[test]
    fn parse_pox_stake_update_result_ok() {
        let stacker: PrincipalData = StandardPrincipalData::transient().into();
        let response = make_stake_ok_response(&stacker, 750_000, 10_000);
        let (parsed_stacker, amount) = parse_pox_stake_update_result(&response).unwrap();
        assert_eq!(parsed_stacker, stacker);
        assert_eq!(amount, 750_000);
    }

    #[test]
    fn parse_pox_stake_update_result_err() {
        let response = Value::error(Value::UInt(9)).unwrap();
        let err = parse_pox_stake_update_result(&response).unwrap_err();
        assert_eq!(err, 9);
    }

    // ── Handler tests ──

    #[test]
    fn handle_stake_lockup_applies_lock() {
        let stacker: PrincipalData = StandardPrincipalData::transient().into();
        let total_amount = 1_000_000;
        let lock_amount = 500_000u128;
        let unlock_height = 10_000u64;

        let mut store = MemoryBackingStore::new();
        let mut global_context = setup_global_context(&mut store, &stacker, total_amount);

        let response = make_stake_ok_response(&stacker, lock_amount, unlock_height);
        let event = handle_stake_lockup_pox_v5(&mut global_context, "stake", &response)
            .expect("handler should succeed");

        // Should produce an STXLockEvent
        assert!(event.is_some());
        let event = event.unwrap();
        match event {
            StacksTransactionEvent::STXEvent(STXEventType::STXLockEvent(data)) => {
                assert_eq!(data.locked_amount, lock_amount);
                assert_eq!(data.unlock_height, unlock_height);
                assert_eq!(data.locked_address, stacker);
            }
            other => panic!("Expected STXLockEvent, got: {other:?}"),
        }

        // Verify the lock was actually applied to the account
        let balance = global_context
            .database
            .get_account_stx_balance(&stacker)
            .expect("Failed to get balance");
        assert_eq!(balance.amount_locked(), lock_amount);
        assert_eq!(balance.amount_unlocked(), total_amount - lock_amount);
    }

    #[test]
    fn handle_stake_lockup_on_error_response_is_noop() {
        let stacker: PrincipalData = StandardPrincipalData::transient().into();
        let mut store = MemoryBackingStore::new();
        let mut global_context = setup_global_context(&mut store, &stacker, 1_000_000);

        let err_response = Value::error(Value::UInt(1)).unwrap();
        let event = handle_stake_lockup_pox_v5(&mut global_context, "stake", &err_response)
            .expect("handler should succeed");

        assert!(event.is_none());

        // Account should be unchanged
        let balance = global_context
            .database
            .get_account_stx_balance(&stacker)
            .expect("Failed to get balance");
        assert_eq!(balance.amount_locked(), 0);
    }

    #[test]
    fn handle_stake_extend_applies_extension() {
        let stacker: PrincipalData = StandardPrincipalData::transient().into();
        let total_amount = 1_000_000;
        let lock_amount = 500_000u128;
        let initial_unlock = 10_000u64;
        let extended_unlock = 15_000u64;

        let mut store = MemoryBackingStore::new();
        let mut global_context = setup_global_context(&mut store, &stacker, total_amount);

        // First, lock the tokens
        pox_lock_v5(
            &mut global_context.database,
            &stacker,
            lock_amount,
            initial_unlock,
        )
        .expect("initial lock should succeed");

        // Now extend
        let response = make_stake_ok_response(&stacker, lock_amount, extended_unlock);
        let event =
            handle_stake_lockup_extension_pox_v5(&mut global_context, "stake-extend", &response)
                .expect("handler should succeed");

        assert!(event.is_some());
        match event.unwrap() {
            StacksTransactionEvent::STXEvent(STXEventType::STXLockEvent(data)) => {
                assert_eq!(data.locked_amount, lock_amount);
                assert_eq!(data.unlock_height, extended_unlock);
            }
            other => panic!("Expected STXLockEvent, got: {other:?}"),
        }
    }

    #[test]
    fn handle_stake_update_applies_increase() {
        let stacker: PrincipalData = StandardPrincipalData::transient().into();
        let total_amount = 1_000_000;
        let initial_lock = 300_000u128;
        let new_total_locked = 500_000u128;
        let unlock_height = 10_000u64;

        let mut store = MemoryBackingStore::new();
        let mut global_context = setup_global_context(&mut store, &stacker, total_amount);

        // First, lock some tokens
        pox_lock_v5(
            &mut global_context.database,
            &stacker,
            initial_lock,
            unlock_height,
        )
        .expect("initial lock should succeed");

        // Now increase via stake-update
        // The update result returns the new total amount-ustx
        let response = make_stake_ok_response(&stacker, new_total_locked, unlock_height);
        let event =
            handle_stake_lockup_increase_pox_v5(&mut global_context, "stake-update", &response)
                .expect("handler should succeed");

        assert!(event.is_some());
        match event.unwrap() {
            StacksTransactionEvent::STXEvent(STXEventType::STXLockEvent(data)) => {
                assert_eq!(data.locked_amount, new_total_locked);
                assert_eq!(data.unlock_height, unlock_height);
            }
            other => panic!("Expected STXLockEvent, got: {other:?}"),
        }

        // Verify the balance reflects the increase
        let balance = global_context
            .database
            .get_account_stx_balance(&stacker)
            .expect("Failed to get balance");
        assert_eq!(balance.amount_locked(), new_total_locked);
        assert_eq!(balance.amount_unlocked(), total_amount - new_total_locked);
    }

    // ── Error / edge-case tests ──

    #[test]
    #[should_panic(expected = "FATAL")]
    fn handle_stake_lockup_insufficient_balance_panics() {
        let stacker: PrincipalData = StandardPrincipalData::transient().into();
        let total_amount = 100_000;
        let lock_amount = 500_000u128; // more than the account has

        let mut store = MemoryBackingStore::new();
        let mut global_context = setup_global_context(&mut store, &stacker, total_amount);

        let response = make_stake_ok_response(&stacker, lock_amount, 10_000);
        // The contract would prevent this, so hitting this path is a FATAL panic
        let _ = handle_stake_lockup_pox_v5(&mut global_context, "stake", &response);
    }

    #[test]
    #[should_panic(expected = "FATAL")]
    fn handle_stake_extend_on_unlocked_account_panics() {
        let stacker: PrincipalData = StandardPrincipalData::transient().into();
        let mut store = MemoryBackingStore::new();
        let mut global_context = setup_global_context(&mut store, &stacker, 1_000_000);

        // No tokens locked — extend should panic
        let response = make_stake_ok_response(&stacker, 500_000, 15_000);
        let _ =
            handle_stake_lockup_extension_pox_v5(&mut global_context, "stake-extend", &response);
    }

    #[test]
    #[should_panic(expected = "FATAL")]
    fn handle_stake_update_on_unlocked_account_panics() {
        let stacker: PrincipalData = StandardPrincipalData::transient().into();
        let mut store = MemoryBackingStore::new();
        let mut global_context = setup_global_context(&mut store, &stacker, 1_000_000);

        // No tokens locked — increase should panic
        let response = make_stake_ok_response(&stacker, 500_000, 10_000);
        let _ = handle_stake_lockup_increase_pox_v5(&mut global_context, "stake-update", &response);
    }

    // ── Pooled variant tests ──

    #[test]
    fn handle_stake_pooled_lockup_applies_lock() {
        let stacker: PrincipalData = StandardPrincipalData::transient().into();
        let total_amount = 1_000_000;
        let lock_amount = 500_000u128;
        let unlock_height = 10_000u64;

        let mut store = MemoryBackingStore::new();
        let mut global_context = setup_global_context(&mut store, &stacker, total_amount);

        let response = make_stake_ok_response(&stacker, lock_amount, unlock_height);
        let event = handle_stake_lockup_pox_v5(&mut global_context, "stake-pooled", &response)
            .expect("handler should succeed");

        assert!(event.is_some());
        match event.unwrap() {
            StacksTransactionEvent::STXEvent(STXEventType::STXLockEvent(data)) => {
                assert_eq!(data.locked_amount, lock_amount);
                assert_eq!(data.unlock_height, unlock_height);
                assert_eq!(data.locked_address, stacker);
            }
            other => panic!("Expected STXLockEvent, got: {other:?}"),
        }

        let balance = global_context
            .database
            .get_account_stx_balance(&stacker)
            .expect("Failed to get balance");
        assert_eq!(balance.amount_locked(), lock_amount);
    }

    #[test]
    fn handle_stake_extend_pooled_applies_extension() {
        let stacker: PrincipalData = StandardPrincipalData::transient().into();
        let total_amount = 1_000_000;
        let lock_amount = 500_000u128;
        let initial_unlock = 10_000u64;
        let extended_unlock = 15_000u64;

        let mut store = MemoryBackingStore::new();
        let mut global_context = setup_global_context(&mut store, &stacker, total_amount);

        pox_lock_v5(
            &mut global_context.database,
            &stacker,
            lock_amount,
            initial_unlock,
        )
        .expect("initial lock should succeed");

        let response = make_stake_ok_response(&stacker, lock_amount, extended_unlock);
        let event = handle_stake_lockup_extension_pox_v5(
            &mut global_context,
            "stake-extend-pooled",
            &response,
        )
        .expect("handler should succeed");

        assert!(event.is_some());
        match event.unwrap() {
            StacksTransactionEvent::STXEvent(STXEventType::STXLockEvent(data)) => {
                assert_eq!(data.locked_amount, lock_amount);
                assert_eq!(data.unlock_height, extended_unlock);
            }
            other => panic!("Expected STXLockEvent, got: {other:?}"),
        }
    }

    #[test]
    fn handle_stake_update_pooled_applies_increase() {
        let stacker: PrincipalData = StandardPrincipalData::transient().into();
        let total_amount = 1_000_000;
        let initial_lock = 300_000u128;
        let new_total_locked = 500_000u128;
        let unlock_height = 10_000u64;

        let mut store = MemoryBackingStore::new();
        let mut global_context = setup_global_context(&mut store, &stacker, total_amount);

        pox_lock_v5(
            &mut global_context.database,
            &stacker,
            initial_lock,
            unlock_height,
        )
        .expect("initial lock should succeed");

        let response = make_stake_ok_response(&stacker, new_total_locked, unlock_height);
        let event = handle_stake_lockup_increase_pox_v5(
            &mut global_context,
            "stake-update-pooled",
            &response,
        )
        .expect("handler should succeed");

        assert!(event.is_some());
        match event.unwrap() {
            StacksTransactionEvent::STXEvent(STXEventType::STXLockEvent(data)) => {
                assert_eq!(data.locked_amount, new_total_locked);
                assert_eq!(data.unlock_height, unlock_height);
            }
            other => panic!("Expected STXLockEvent, got: {other:?}"),
        }

        let balance = global_context
            .database
            .get_account_stx_balance(&stacker)
            .expect("Failed to get balance");
        assert_eq!(balance.amount_locked(), new_total_locked);
    }
}
