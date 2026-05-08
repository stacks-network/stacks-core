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
use clarity::vm::contexts::GlobalContext;
use clarity::vm::costs::cost_functions::ClarityCostFunction;
use clarity::vm::costs::runtime_cost;
use clarity::vm::database::{ClarityDatabase, STXBalance};
use clarity::vm::errors::{RuntimeError, VmExecutionError};
use clarity::vm::events::{STXEventType, STXLockEventData, StacksTransactionEvent};
use clarity::vm::types::{PrincipalData, QualifiedContractIdentifier};
use clarity::vm::Value;
use stacks_common::debug;

use crate::{LockingError, POX_5_NAME};

/// Parse the returned value from PoX-5 `stake`, `stake-update`, and
/// `register-for-bond` functions into (staker, amount-ustx, unlock-burn-height).
/// These functions return `(ok { staker, amount-ustx, unlock-burn-height, ... })`.
fn parse_pox_stake_result(result: &Value) -> std::result::Result<(PrincipalData, u128, u64), u128> {
    match result
        .clone()
        .expect_result()
        .expect("FATAL: unexpected clarity value")
    {
        Ok(res) => {
            let tuple_data = res.expect_tuple().expect("FATAL: unexpected clarity value");
            let staker = tuple_data
                .get("staker")
                .expect("FATAL: no 'staker'")
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

            Ok((staker, amount_ustx, unlock_burn_height))
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

/// Reschedule a pox-5 STX lock to unlock at `unlock_burn_height`. Used by
/// `unstake`, which moves the unlock to the start of the next reward
/// cycle. The locked amount is unchanged. Does NOT touch the account
/// nonce.
///
/// # Errors
/// - Returns Error::PoxUnstakeNotLocked if this function was called on an account
///   which isn't locked. This *should* have been checked by the PoX v5 contract,
///   so this should surface in a panic.
pub fn pox_unstake_v5(
    db: &mut ClarityDatabase,
    principal: &PrincipalData,
    unlock_burn_height: u64,
) -> Result<(), LockingError> {
    assert!(unlock_burn_height > 0);

    let mut snapshot = db.get_stx_balance_snapshot(principal)?;

    if !snapshot.has_locked_tokens()? {
        return Err(LockingError::PoxUnstakeNotLocked);
    }

    snapshot.update_unlock_v5(unlock_burn_height)?;

    debug!(
        "PoX v5 unstake scheduled";
        "pox_locked_ustx" => snapshot.balance().amount_locked(),
        "unlock_burn_height" => unlock_burn_height,
        "account" => %principal,
    );

    snapshot.save()?;
    Ok(())
}

/// Extend a STX lock up for PoX for a time and/or increase the amount locked.
/// Does NOT touch the account nonce.
/// Returns Ok(lock_amount) when successful
///
/// # Errors
/// - Returns Error::PoxExtendNotLocked if this function was called on an account
///   which isn't locked. This *should* have been checked by the PoX v5 contract,
///   so this should surface in a panic.
pub fn pox_lock_update_v5(
    db: &mut ClarityDatabase,
    principal: &PrincipalData,
    unlock_burn_height: u64,
    new_total_locked: u128,
) -> Result<STXBalance, LockingError> {
    assert!(unlock_burn_height > 0);
    assert!(new_total_locked > 0);

    let mut snapshot = db.get_stx_balance_snapshot(principal)?;

    if !snapshot.has_locked_tokens()? {
        return Err(LockingError::PoxExtendNotLocked);
    }

    snapshot.update_unlock_v5(unlock_burn_height)?;

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
        "PoX v5 lock updated";
        "pox_locked_ustx" => out_balance.amount_locked(),
        "available_ustx" => out_balance.amount_unlocked(),
        "unlock_burn_height" => unlock_burn_height,
        "account" => %principal,
    );

    snapshot.save()?;
    Ok(out_balance)
}

/// Handle responses from stake in pox-5 -- functions that *lock up* STX
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

    let (staker, locked_amount, unlock_height) = match parse_pox_stake_result(value) {
        Ok(x) => x,
        Err(_) => {
            return Ok(None);
        }
    };

    match pox_lock_v5(
        &mut global_context.database,
        &staker,
        locked_amount,
        unlock_height,
    ) {
        Ok(_) => {
            // Log the staking in the asset map
            global_context.log_stacking(&staker, locked_amount)?;

            let event =
                StacksTransactionEvent::STXEvent(STXEventType::STXLockEvent(STXLockEventData {
                    locked_amount,
                    unlock_height,
                    locked_address: staker,
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
                "FATAL: failed to lock {locked_amount} from {staker} until {unlock_height}: '{e:?}'"
            );
        }
    }
}

/// Handle responses from stake-extend and stake-extend-pooled in pox-5 -- functions that
/// *extend already-locked* STX.
fn handle_stake_lockup_update_pox_v5(
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

    let (staker, amount_ustx, unlock_height) = match parse_pox_stake_result(value) {
        Ok(x) => x,
        Err(_) => {
            return Ok(None);
        }
    };

    match pox_lock_update_v5(
        &mut global_context.database,
        &staker,
        unlock_height,
        amount_ustx,
    ) {
        Ok(_) => {
            // Log the extension in the asset map.
            global_context.log_stacking(&staker, amount_ustx)?;

            let event =
                StacksTransactionEvent::STXEvent(STXEventType::STXLockEvent(STXLockEventData {
                    locked_amount: amount_ustx,
                    unlock_height,
                    locked_address: staker,
                    contract_identifier: boot_code_id(POX_5_NAME, global_context.mainnet),
                }));
            Ok(Some(event))
        }
        Err(LockingError::DefunctPoxContract) => Err(VmExecutionError::Runtime(
            RuntimeError::DefunctPoxContract,
            None,
        )),
        Err(e) => {
            panic!("FATAL: failed to extend lock from {staker} until {unlock_height}: '{e:?}'");
        }
    }
}

/// Handle the response from `unstake` in pox-5 — reschedules the
/// already-locked STX to unlock at the start of the next reward cycle.
fn handle_unstake_pox_v5(
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

    let (staker, locked_amount, unlock_height) = match parse_pox_stake_result(value) {
        Ok(x) => x,
        Err(_) => {
            return Ok(None);
        }
    };

    match pox_unstake_v5(&mut global_context.database, &staker, unlock_height) {
        Ok(()) => {
            // Emit a lock event reflecting the new (earlier) unlock-height.
            // The locked amount is unchanged.
            let event =
                StacksTransactionEvent::STXEvent(STXEventType::STXLockEvent(STXLockEventData {
                    locked_amount,
                    unlock_height,
                    locked_address: staker,
                    contract_identifier: boot_code_id(POX_5_NAME, global_context.mainnet),
                }));
            Ok(Some(event))
        }
        Err(LockingError::DefunctPoxContract) => Err(VmExecutionError::Runtime(
            RuntimeError::DefunctPoxContract,
            None,
        )),
        Err(e) => {
            panic!("FATAL: failed to unstake {staker} until {unlock_height}: '{e:?}'");
        }
    }
}

/// Handle special cases when calling into the PoX-5 API contract
pub fn handle_contract_call(
    global_context: &mut GlobalContext,
    _sender_opt: Option<&PrincipalData>,
    _contract_id: &QualifiedContractIdentifier,
    function_name: &str,
    _args: &[Value],
    value: &Value,
) -> Result<(), VmExecutionError> {
    // Execute function specific logic to complete the lock-up
    let lock_event_opt = match function_name {
        "stake" | "register-for-bond" => {
            handle_stake_lockup_pox_v5(global_context, function_name, value)?
        }
        "stake-update" => handle_stake_lockup_update_pox_v5(global_context, function_name, value)?,
        "unstake" => handle_unstake_pox_v5(global_context, function_name, value)?,
        _ => None,
    };

    // append the lockup event
    if let Some((batch, _)) = global_context.event_batches.last_mut() {
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
    use clarity::vm::{ClarityName, ContractName, Value};

    use super::*;

    /// Helper: build a pox-5 stake ok response tuple
    fn make_stake_ok_response(
        staker: &PrincipalData,
        amount_ustx: u128,
        unlock_burn_height: u64,
    ) -> Value {
        let signer = match staker {
            PrincipalData::Standard(data) => {
                Value::Principal(PrincipalData::Contract(QualifiedContractIdentifier::new(
                    data.clone(),
                    ContractName::from_literal("signer"),
                )))
            }
            PrincipalData::Contract(_) => staker.clone().into(),
        };

        Value::okay(Value::Tuple(
            TupleData::from_data(vec![
                (ClarityName::from_literal("signer"), signer),
                (
                    ClarityName::from_literal("staker"),
                    Value::Principal(staker.clone()),
                ),
                (
                    ClarityName::from_literal("amount-ustx"),
                    Value::UInt(amount_ustx),
                ),
                (ClarityName::from_literal("num-cycle"), Value::UInt(1)),
                (
                    ClarityName::from_literal("first-reward-cycle"),
                    Value::UInt(2),
                ),
                (
                    ClarityName::from_literal("unlock-burn-height"),
                    Value::UInt(unlock_burn_height as u128),
                ),
                (ClarityName::from_literal("unlock-cycle"), Value::UInt(3)),
            ])
            .unwrap(),
        ))
        .unwrap()
    }

    /// Helper: build a pox-5 stake/stake-update ok response tuple
    fn make_stake_update_ok_response(
        staker: &PrincipalData,
        amount_ustx: u128,
        unlock_burn_height: u64,
    ) -> Value {
        let signer = match staker {
            PrincipalData::Standard(data) => {
                Value::Principal(PrincipalData::Contract(QualifiedContractIdentifier::new(
                    data.clone(),
                    ContractName::from_literal("signer"),
                )))
            }
            PrincipalData::Contract(_) => staker.clone().into(),
        };

        Value::okay(Value::Tuple(
            TupleData::from_data(vec![
                (ClarityName::from_literal("signer"), signer),
                (
                    ClarityName::from_literal("staker"),
                    Value::Principal(staker.clone()),
                ),
                (
                    ClarityName::from_literal("amount-ustx"),
                    Value::UInt(amount_ustx),
                ),
                (ClarityName::from_literal("num-cycle"), Value::UInt(1)),
                (
                    ClarityName::from_literal("prev-unlock-height"),
                    Value::UInt(2),
                ),
                (
                    ClarityName::from_literal("unlock-burn-height"),
                    Value::UInt(unlock_burn_height as u128),
                ),
                (ClarityName::from_literal("unlock-cycle"), Value::UInt(3)),
            ])
            .unwrap(),
        ))
        .unwrap()
    }

    /// Helper: build a pox-5 register-for-bond ok response tuple
    fn make_register_for_bond_ok_response(
        staker: &PrincipalData,
        amount_ustx: u128,
        unlock_burn_height: u64,
    ) -> Value {
        let signer = match staker {
            PrincipalData::Standard(data) => {
                Value::Principal(PrincipalData::Contract(QualifiedContractIdentifier::new(
                    data.clone(),
                    ContractName::from_literal("signer"),
                )))
            }
            PrincipalData::Contract(_) => staker.clone().into(),
        };

        Value::okay(Value::Tuple(
            TupleData::from_data(vec![
                (ClarityName::from_literal("signer"), signer),
                (
                    ClarityName::from_literal("staker"),
                    Value::Principal(staker.clone()),
                ),
                (
                    ClarityName::from_literal("amount-ustx"),
                    Value::UInt(amount_ustx),
                ),
                (ClarityName::from_literal("bond-index"), Value::UInt(0)),
                (
                    ClarityName::from_literal("first-reward-cycle"),
                    Value::UInt(2),
                ),
                (
                    ClarityName::from_literal("unlock-burn-height"),
                    Value::UInt(unlock_burn_height as u128),
                ),
                (ClarityName::from_literal("unlock-cycle"), Value::UInt(14)),
            ])
            .unwrap(),
        ))
        .unwrap()
    }

    /// Helper: build a pox-5 `unstake` ok response tuple
    fn make_unstake_ok_response(
        staker: &PrincipalData,
        amount_ustx: u128,
        unlock_burn_height: u64,
    ) -> Value {
        Value::okay(Value::Tuple(
            TupleData::from_data(vec![
                (
                    ClarityName::from_literal("staker"),
                    Value::Principal(staker.clone()),
                ),
                (
                    ClarityName::from_literal("amount-ustx"),
                    Value::UInt(amount_ustx),
                ),
                (
                    ClarityName::from_literal("first-reward-cycle"),
                    Value::UInt(2),
                ),
                (ClarityName::from_literal("unlock-cycle"), Value::UInt(3)),
                (
                    ClarityName::from_literal("unlock-burn-height"),
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
        staker: &PrincipalData,
        total_amount: u128,
    ) -> GlobalContext<'a, 'a> {
        let db = store.as_clarity_db();
        let mut global_context = GlobalContext::new(
            false,
            CHAIN_ID_TESTNET,
            db,
            LimitedCostTracker::new_free(),
            StacksEpochId::Epoch40,
        );
        global_context.begin();
        {
            let mut snapshot = global_context
                .database
                .get_stx_balance_snapshot(staker)
                .unwrap();
            snapshot.credit(total_amount).expect("Failed to credit");
            snapshot.save().expect("Failed to save");
        }
        global_context
    }

    // ── Parser tests ──

    #[test]
    fn parse_pox_stake_result_ok() {
        let staker: PrincipalData = StandardPrincipalData::transient().into();
        let response = make_stake_ok_response(&staker, 500_000, 10_000);
        let (parsed_staker, amount, height) = parse_pox_stake_result(&response).unwrap();
        assert_eq!(parsed_staker, staker);
        assert_eq!(amount, 500_000);
        assert_eq!(height, 10_000);
    }

    #[test]
    fn parse_pox_stake_result_err() {
        let response = Value::error(Value::UInt(1)).unwrap();
        let err = parse_pox_stake_result(&response).unwrap_err();
        assert_eq!(err, 1);
    }

    // ── Handler tests ──

    #[test]
    fn handle_stake_lockup_applies_lock() {
        let staker: PrincipalData = StandardPrincipalData::transient().into();
        let total_amount = 1_000_000;
        let lock_amount = 500_000u128;
        let unlock_height = 10_000u64;

        let mut store = MemoryBackingStore::new();
        let mut global_context = setup_global_context(&mut store, &staker, total_amount);

        let response = make_stake_ok_response(&staker, lock_amount, unlock_height);
        let event = handle_stake_lockup_pox_v5(&mut global_context, "stake", &response)
            .expect("handler should succeed");

        // Should produce an STXLockEvent
        assert!(event.is_some());
        let event = event.unwrap();
        match event {
            StacksTransactionEvent::STXEvent(STXEventType::STXLockEvent(data)) => {
                assert_eq!(data.locked_amount, lock_amount);
                assert_eq!(data.unlock_height, unlock_height);
                assert_eq!(data.locked_address, staker);
            }
            other => panic!("Expected STXLockEvent, got: {other:?}"),
        }

        // Verify the lock was actually applied to the account
        let balance = global_context
            .database
            .get_account_stx_balance(&staker)
            .expect("Failed to get balance");
        assert_eq!(balance.amount_locked(), lock_amount);
        assert_eq!(balance.amount_unlocked(), total_amount - lock_amount);
    }

    #[test]
    fn handle_stake_lockup_on_error_response_is_noop() {
        let staker: PrincipalData = StandardPrincipalData::transient().into();
        let mut store = MemoryBackingStore::new();
        let mut global_context = setup_global_context(&mut store, &staker, 1_000_000);

        let err_response = Value::error(Value::UInt(1)).unwrap();
        let event = handle_stake_lockup_pox_v5(&mut global_context, "stake", &err_response)
            .expect("handler should succeed");

        assert!(event.is_none());

        // Account should be unchanged
        let balance = global_context
            .database
            .get_account_stx_balance(&staker)
            .expect("Failed to get balance");
        assert_eq!(balance.amount_locked(), 0);
    }

    #[test]
    fn handle_stake_update_applies_extension() {
        let staker: PrincipalData = StandardPrincipalData::transient().into();
        let total_amount = 1_000_000;
        let lock_amount = 500_000u128;
        let initial_unlock = 10_000u64;
        let extended_unlock = 15_000u64;

        let mut store = MemoryBackingStore::new();
        let mut global_context = setup_global_context(&mut store, &staker, total_amount);

        // First, lock the tokens
        pox_lock_v5(
            &mut global_context.database,
            &staker,
            lock_amount,
            initial_unlock,
        )
        .expect("initial lock should succeed");

        // Now extend (same amount, later unlock height)
        let response = make_stake_update_ok_response(&staker, lock_amount, extended_unlock);
        let event =
            handle_stake_lockup_update_pox_v5(&mut global_context, "stake-update", &response)
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
        let staker: PrincipalData = StandardPrincipalData::transient().into();
        let total_amount = 1_000_000;
        let initial_lock = 300_000u128;
        let new_total_locked = 500_000u128;
        let unlock_height = 10_000u64;

        let mut store = MemoryBackingStore::new();
        let mut global_context = setup_global_context(&mut store, &staker, total_amount);

        // First, lock some tokens
        pox_lock_v5(
            &mut global_context.database,
            &staker,
            initial_lock,
            unlock_height,
        )
        .expect("initial lock should succeed");

        // Now increase via stake-update (same unlock height, larger amount).
        // The update result returns the new total amount-ustx.
        let response = make_stake_update_ok_response(&staker, new_total_locked, unlock_height);
        let event =
            handle_stake_lockup_update_pox_v5(&mut global_context, "stake-update", &response)
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
            .get_account_stx_balance(&staker)
            .expect("Failed to get balance");
        assert_eq!(balance.amount_locked(), new_total_locked);
        assert_eq!(balance.amount_unlocked(), total_amount - new_total_locked);
    }

    // ── Error / edge-case tests ──

    #[test]
    #[should_panic(expected = "FATAL")]
    fn handle_stake_lockup_insufficient_balance_panics() {
        let staker: PrincipalData = StandardPrincipalData::transient().into();
        let total_amount = 100_000;
        let lock_amount = 500_000u128; // more than the account has

        let mut store = MemoryBackingStore::new();
        let mut global_context = setup_global_context(&mut store, &staker, total_amount);

        let response = make_stake_ok_response(&staker, lock_amount, 10_000);
        // The contract would prevent this, so hitting this path is a FATAL panic
        let _ = handle_stake_lockup_pox_v5(&mut global_context, "stake", &response);
    }

    #[test]
    fn handle_stake_update_extends_and_increases_together() {
        let staker: PrincipalData = StandardPrincipalData::transient().into();
        let total_amount = 1_000_000;
        let initial_lock = 300_000u128;
        let new_total_locked = 600_000u128;
        let initial_unlock = 10_000u64;
        let extended_unlock = 15_000u64;

        let mut store = MemoryBackingStore::new();
        let mut global_context = setup_global_context(&mut store, &staker, total_amount);

        pox_lock_v5(
            &mut global_context.database,
            &staker,
            initial_lock,
            initial_unlock,
        )
        .expect("initial lock should succeed");

        // Extend the unlock height AND increase the locked amount in one update
        let response = make_stake_update_ok_response(&staker, new_total_locked, extended_unlock);
        let event =
            handle_stake_lockup_update_pox_v5(&mut global_context, "stake-update", &response)
                .expect("handler should succeed");

        assert!(event.is_some());
        match event.unwrap() {
            StacksTransactionEvent::STXEvent(STXEventType::STXLockEvent(data)) => {
                assert_eq!(data.locked_amount, new_total_locked);
                assert_eq!(data.unlock_height, extended_unlock);
            }
            other => panic!("Expected STXLockEvent, got: {other:?}"),
        }

        let balance = global_context
            .database
            .get_account_stx_balance(&staker)
            .expect("Failed to get balance");
        assert_eq!(balance.amount_locked(), new_total_locked);
        assert_eq!(balance.amount_unlocked(), total_amount - new_total_locked);
    }

    #[test]
    fn handle_stake_update_on_error_response_is_noop() {
        let staker: PrincipalData = StandardPrincipalData::transient().into();
        let mut store = MemoryBackingStore::new();
        let mut global_context = setup_global_context(&mut store, &staker, 1_000_000);

        let err_response = Value::error(Value::UInt(7)).unwrap();
        let event =
            handle_stake_lockup_update_pox_v5(&mut global_context, "stake-update", &err_response)
                .expect("handler should succeed");

        assert!(event.is_none());
    }

    #[test]
    #[should_panic(expected = "FATAL")]
    fn handle_stake_update_on_unlocked_account_panics() {
        let staker: PrincipalData = StandardPrincipalData::transient().into();
        let mut store = MemoryBackingStore::new();
        let mut global_context = setup_global_context(&mut store, &staker, 1_000_000);

        // No tokens locked — update should panic
        let response = make_stake_update_ok_response(&staker, 500_000, 10_000);
        let _ = handle_stake_lockup_update_pox_v5(&mut global_context, "stake-update", &response);
    }

    #[test]
    fn handle_stake_lockup_already_locked_returns_runtime_error() {
        let staker: PrincipalData = StandardPrincipalData::transient().into();
        let total_amount = 1_000_000;
        let lock_amount = 300_000u128;
        let unlock_height = 10_000u64;

        let mut store = MemoryBackingStore::new();
        let mut global_context = setup_global_context(&mut store, &staker, total_amount);

        // Lock once directly so the account already has locked tokens.
        pox_lock_v5(
            &mut global_context.database,
            &staker,
            lock_amount,
            unlock_height,
        )
        .expect("initial lock should succeed");

        // A second lockup attempt must surface as a graceful runtime error,
        // not a FATAL panic.
        let response = make_stake_ok_response(&staker, lock_amount, unlock_height);
        let err = handle_stake_lockup_pox_v5(&mut global_context, "stake", &response)
            .expect_err("expected PoxAlreadyLocked runtime error");
        match err {
            VmExecutionError::Runtime(RuntimeError::PoxAlreadyLocked, None) => {}
            other => panic!("expected PoxAlreadyLocked runtime error, got: {other:?}"),
        }
    }

    // ── Dispatcher tests (handle_contract_call) ──

    #[test]
    fn handle_contract_call_routes_stake_and_appends_event() {
        let staker: PrincipalData = StandardPrincipalData::transient().into();
        let total_amount = 1_000_000;
        let lock_amount = 500_000u128;
        let unlock_height = 10_000u64;

        let mut store = MemoryBackingStore::new();
        let mut global_context = setup_global_context(&mut store, &staker, total_amount);
        let contract_id = boot_code_id(POX_5_NAME, global_context.mainnet);

        let response = make_stake_ok_response(&staker, lock_amount, unlock_height);
        handle_contract_call(
            &mut global_context,
            None,
            &contract_id,
            "stake",
            &[],
            &response,
        )
        .expect("dispatch should succeed");

        // The lockup must have been applied to the account.
        let balance = global_context
            .database
            .get_account_stx_balance(&staker)
            .expect("Failed to get balance");
        assert_eq!(balance.amount_locked(), lock_amount);

        // And an STXLockEvent must have been appended to the current batch.
        let (batch, _) = global_context
            .event_batches
            .last()
            .expect("event batch should exist");
        assert_eq!(batch.events.len(), 1);
        match &batch.events[0] {
            StacksTransactionEvent::STXEvent(STXEventType::STXLockEvent(data)) => {
                assert_eq!(data.locked_amount, lock_amount);
                assert_eq!(data.unlock_height, unlock_height);
                assert_eq!(data.locked_address, staker);
            }
            other => panic!("Expected STXLockEvent, got: {other:?}"),
        }
    }

    #[test]
    fn handle_contract_call_routes_stake_update_and_appends_event() {
        let staker: PrincipalData = StandardPrincipalData::transient().into();
        let total_amount = 1_000_000;
        let initial_lock = 300_000u128;
        let new_total_locked = 600_000u128;
        let initial_unlock = 10_000u64;
        let extended_unlock = 15_000u64;

        let mut store = MemoryBackingStore::new();
        let mut global_context = setup_global_context(&mut store, &staker, total_amount);
        let contract_id = boot_code_id(POX_5_NAME, global_context.mainnet);

        pox_lock_v5(
            &mut global_context.database,
            &staker,
            initial_lock,
            initial_unlock,
        )
        .expect("initial lock should succeed");

        let response = make_stake_update_ok_response(&staker, new_total_locked, extended_unlock);
        handle_contract_call(
            &mut global_context,
            None,
            &contract_id,
            "stake-update",
            &[],
            &response,
        )
        .expect("dispatch should succeed");

        let balance = global_context
            .database
            .get_account_stx_balance(&staker)
            .expect("Failed to get balance");
        assert_eq!(balance.amount_locked(), new_total_locked);

        let (batch, _) = global_context
            .event_batches
            .last()
            .expect("event batch should exist");
        assert_eq!(batch.events.len(), 1);
        match &batch.events[0] {
            StacksTransactionEvent::STXEvent(STXEventType::STXLockEvent(data)) => {
                assert_eq!(data.locked_amount, new_total_locked);
                assert_eq!(data.unlock_height, extended_unlock);
            }
            other => panic!("Expected STXLockEvent, got: {other:?}"),
        }
    }

    #[test]
    fn handle_contract_call_unknown_function_is_noop() {
        let staker: PrincipalData = StandardPrincipalData::transient().into();
        let mut store = MemoryBackingStore::new();
        let mut global_context = setup_global_context(&mut store, &staker, 1_000_000);
        let contract_id = boot_code_id(POX_5_NAME, global_context.mainnet);

        let response = make_stake_ok_response(&staker, 500_000, 10_000);
        handle_contract_call(
            &mut global_context,
            None,
            &contract_id,
            "some-unrelated-function",
            &[],
            &response,
        )
        .expect("dispatch should succeed");

        // No lockup applied, no event emitted.
        let balance = global_context
            .database
            .get_account_stx_balance(&staker)
            .expect("Failed to get balance");
        assert_eq!(balance.amount_locked(), 0);

        let (batch, _) = global_context
            .event_batches
            .last()
            .expect("event batch should exist");
        assert!(batch.events.is_empty());
    }

    // ── register-for-bond tests ──

    #[test]
    fn parse_pox_stake_result_ok_register_for_bond() {
        let staker: PrincipalData = StandardPrincipalData::transient().into();
        let response = make_register_for_bond_ok_response(&staker, 750_000, 12_000);
        let (parsed_staker, amount, height) = parse_pox_stake_result(&response).unwrap();
        assert_eq!(parsed_staker, staker);
        assert_eq!(amount, 750_000);
        assert_eq!(height, 12_000);
    }

    #[test]
    fn handle_register_for_bond_applies_lock() {
        let staker: PrincipalData = StandardPrincipalData::transient().into();
        let total_amount = 1_000_000;
        let lock_amount = 750_000u128;
        let unlock_height = 12_000u64;

        let mut store = MemoryBackingStore::new();
        let mut global_context = setup_global_context(&mut store, &staker, total_amount);

        let response = make_register_for_bond_ok_response(&staker, lock_amount, unlock_height);
        let event = handle_stake_lockup_pox_v5(&mut global_context, "register-for-bond", &response)
            .expect("handler should succeed");

        let event = event.expect("expected an STXLockEvent");
        match event {
            StacksTransactionEvent::STXEvent(STXEventType::STXLockEvent(data)) => {
                assert_eq!(data.locked_amount, lock_amount);
                assert_eq!(data.unlock_height, unlock_height);
                assert_eq!(data.locked_address, staker);
            }
            other => panic!("Expected STXLockEvent, got: {other:?}"),
        }

        let balance = global_context
            .database
            .get_account_stx_balance(&staker)
            .expect("Failed to get balance");
        assert_eq!(balance.amount_locked(), lock_amount);
        assert_eq!(balance.amount_unlocked(), total_amount - lock_amount);
    }

    #[test]
    fn handle_register_for_bond_on_error_response_is_noop() {
        let staker: PrincipalData = StandardPrincipalData::transient().into();
        let mut store = MemoryBackingStore::new();
        let mut global_context = setup_global_context(&mut store, &staker, 1_000_000);

        let err_response = Value::error(Value::UInt(11)).unwrap();
        let event =
            handle_stake_lockup_pox_v5(&mut global_context, "register-for-bond", &err_response)
                .expect("handler should succeed");

        assert!(event.is_none());

        let balance = global_context
            .database
            .get_account_stx_balance(&staker)
            .expect("Failed to get balance");
        assert_eq!(balance.amount_locked(), 0);
    }

    #[test]
    fn handle_register_for_bond_already_locked_returns_runtime_error() {
        let staker: PrincipalData = StandardPrincipalData::transient().into();
        let total_amount = 1_000_000;
        let lock_amount = 400_000u128;
        let unlock_height = 12_000u64;

        let mut store = MemoryBackingStore::new();
        let mut global_context = setup_global_context(&mut store, &staker, total_amount);

        // Pre-existing lock (e.g. user already called `stake`) must surface as a
        // graceful runtime error, not a FATAL panic, when register-for-bond runs.
        pox_lock_v5(
            &mut global_context.database,
            &staker,
            lock_amount,
            unlock_height,
        )
        .expect("initial lock should succeed");

        let response = make_register_for_bond_ok_response(&staker, lock_amount, unlock_height);
        let err = handle_stake_lockup_pox_v5(&mut global_context, "register-for-bond", &response)
            .expect_err("expected PoxAlreadyLocked runtime error");
        match err {
            VmExecutionError::Runtime(RuntimeError::PoxAlreadyLocked, None) => {}
            other => panic!("expected PoxAlreadyLocked runtime error, got: {other:?}"),
        }
    }

    #[test]
    fn handle_contract_call_routes_register_for_bond_and_appends_event() {
        let staker: PrincipalData = StandardPrincipalData::transient().into();
        let total_amount = 1_000_000;
        let lock_amount = 750_000u128;
        let unlock_height = 12_000u64;

        let mut store = MemoryBackingStore::new();
        let mut global_context = setup_global_context(&mut store, &staker, total_amount);
        let contract_id = boot_code_id(POX_5_NAME, global_context.mainnet);

        let response = make_register_for_bond_ok_response(&staker, lock_amount, unlock_height);
        handle_contract_call(
            &mut global_context,
            None,
            &contract_id,
            "register-for-bond",
            &[],
            &response,
        )
        .expect("dispatch should succeed");

        let balance = global_context
            .database
            .get_account_stx_balance(&staker)
            .expect("Failed to get balance");
        assert_eq!(balance.amount_locked(), lock_amount);

        let (batch, _) = global_context
            .event_batches
            .last()
            .expect("event batch should exist");
        assert_eq!(batch.events.len(), 1);
        match &batch.events[0] {
            StacksTransactionEvent::STXEvent(STXEventType::STXLockEvent(data)) => {
                assert_eq!(data.locked_amount, lock_amount);
                assert_eq!(data.unlock_height, unlock_height);
                assert_eq!(data.locked_address, staker);
            }
            other => panic!("Expected STXLockEvent, got: {other:?}"),
        }
    }

    // ── Direct error-path tests for pox_lock_update_v5 ──

    #[test]
    fn pox_lock_update_v5_insufficient_balance_returns_err() {
        let staker: PrincipalData = StandardPrincipalData::transient().into();
        let total_amount = 1_000_000;
        let initial_lock = 300_000u128;
        let unlock_height = 10_000u64;

        let mut store = MemoryBackingStore::new();
        let mut global_context = setup_global_context(&mut store, &staker, total_amount);

        pox_lock_v5(
            &mut global_context.database,
            &staker,
            initial_lock,
            unlock_height,
        )
        .expect("initial lock should succeed");

        // Asking to lock more than the account holds must surface as
        // PoxInsufficientBalance.
        let err = pox_lock_update_v5(
            &mut global_context.database,
            &staker,
            unlock_height,
            total_amount + 1,
        )
        .expect_err("expected PoxInsufficientBalance");
        assert!(matches!(err, LockingError::PoxInsufficientBalance));
    }

    #[test]
    fn pox_lock_update_v5_invalid_increase_returns_err() {
        let staker: PrincipalData = StandardPrincipalData::transient().into();
        let total_amount = 1_000_000;
        let initial_lock = 500_000u128;
        let unlock_height = 10_000u64;

        let mut store = MemoryBackingStore::new();
        let mut global_context = setup_global_context(&mut store, &staker, total_amount);

        pox_lock_v5(
            &mut global_context.database,
            &staker,
            initial_lock,
            unlock_height,
        )
        .expect("initial lock should succeed");

        // A "new total" smaller than the current lock is not a valid increase.
        let err = pox_lock_update_v5(
            &mut global_context.database,
            &staker,
            unlock_height,
            initial_lock - 1,
        )
        .expect_err("expected PoxInvalidIncrease");
        assert!(matches!(err, LockingError::PoxInvalidIncrease));
    }

    // ── unstake tests ──

    #[test]
    fn handle_unstake_reschedules_unlock_height() {
        let staker: PrincipalData = StandardPrincipalData::transient().into();
        let total_amount = 1_000_000;
        let lock_amount = 600_000u128;
        let initial_unlock = 12_000u64;
        let early_unlock = 5_000u64;

        let mut store = MemoryBackingStore::new();
        let mut global_context = setup_global_context(&mut store, &staker, total_amount);

        pox_lock_v5(
            &mut global_context.database,
            &staker,
            lock_amount,
            initial_unlock,
        )
        .expect("initial lock should succeed");

        let response = make_unstake_ok_response(&staker, lock_amount, early_unlock);
        let event = handle_unstake_pox_v5(&mut global_context, "unstake", &response)
            .expect("handler should succeed")
            .expect("expected an STXLockEvent");

        match event {
            StacksTransactionEvent::STXEvent(STXEventType::STXLockEvent(data)) => {
                assert_eq!(data.locked_amount, lock_amount);
                assert_eq!(data.unlock_height, early_unlock);
                assert_eq!(data.locked_address, staker);
            }
            other => panic!("Expected STXLockEvent, got: {other:?}"),
        }

        // The locked amount is unchanged; only the unlock-height moves.
        let snapshot = global_context
            .database
            .get_stx_balance_snapshot(&staker)
            .expect("Failed to get balance");
        let bal = snapshot.balance();
        assert_eq!(bal.amount_locked(), lock_amount);
        assert_eq!(bal.amount_unlocked(), total_amount - lock_amount);
        assert_eq!(bal.unlock_height(), early_unlock);
    }

    #[test]
    fn handle_unstake_on_error_response_is_noop() {
        let staker: PrincipalData = StandardPrincipalData::transient().into();
        let lock_amount = 600_000u128;
        let initial_unlock = 12_000u64;

        let mut store = MemoryBackingStore::new();
        let mut global_context = setup_global_context(&mut store, &staker, 1_000_000);

        pox_lock_v5(
            &mut global_context.database,
            &staker,
            lock_amount,
            initial_unlock,
        )
        .expect("initial lock should succeed");

        let err_response = Value::error(Value::UInt(13)).unwrap();
        let event = handle_unstake_pox_v5(&mut global_context, "unstake", &err_response)
            .expect("handler should succeed");
        assert!(event.is_none());

        // Lock state unchanged.
        let snapshot = global_context
            .database
            .get_stx_balance_snapshot(&staker)
            .expect("Failed to get balance");
        assert_eq!(snapshot.balance().unlock_height(), initial_unlock);
    }

    #[test]
    #[should_panic(expected = "FATAL")]
    fn handle_unstake_on_unlocked_account_panics() {
        let staker: PrincipalData = StandardPrincipalData::transient().into();
        let mut store = MemoryBackingStore::new();
        let mut global_context = setup_global_context(&mut store, &staker, 1_000_000);

        // No tokens locked — pox-5 should never have produced an unstake `ok`
        // for this account, so the handler must panic.
        let response = make_unstake_ok_response(&staker, 500_000, 5_000);
        let _ = handle_unstake_pox_v5(&mut global_context, "unstake", &response);
    }

    #[test]
    fn handle_contract_call_routes_unstake_and_appends_event() {
        let staker: PrincipalData = StandardPrincipalData::transient().into();
        let total_amount = 1_000_000;
        let lock_amount = 600_000u128;
        let initial_unlock = 12_000u64;
        let early_unlock = 5_000u64;

        let mut store = MemoryBackingStore::new();
        let mut global_context = setup_global_context(&mut store, &staker, total_amount);
        let contract_id = boot_code_id(POX_5_NAME, global_context.mainnet);

        pox_lock_v5(
            &mut global_context.database,
            &staker,
            lock_amount,
            initial_unlock,
        )
        .expect("initial lock should succeed");

        let response = make_unstake_ok_response(&staker, lock_amount, early_unlock);
        handle_contract_call(
            &mut global_context,
            None,
            &contract_id,
            "unstake",
            &[],
            &response,
        )
        .expect("dispatch should succeed");

        let snapshot = global_context
            .database
            .get_stx_balance_snapshot(&staker)
            .expect("Failed to get balance");
        assert_eq!(snapshot.balance().amount_locked(), lock_amount);
        assert_eq!(snapshot.balance().unlock_height(), early_unlock);

        let (batch, _) = global_context
            .event_batches
            .last()
            .expect("event batch should exist");
        assert_eq!(batch.events.len(), 1);
        match &batch.events[0] {
            StacksTransactionEvent::STXEvent(STXEventType::STXLockEvent(data)) => {
                assert_eq!(data.locked_amount, lock_amount);
                assert_eq!(data.unlock_height, early_unlock);
                assert_eq!(data.locked_address, staker);
            }
            other => panic!("Expected STXLockEvent, got: {other:?}"),
        }
    }
}
