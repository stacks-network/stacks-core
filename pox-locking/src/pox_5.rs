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
use clarity::vm::errors::{RuntimeError, VmExecutionError, VmInternalError};
use clarity::vm::events::{STXEventType, STXLockEventData, StacksTransactionEvent};
use clarity::vm::types::{PrincipalData, QualifiedContractIdentifier};
use clarity::vm::Value;
use stacks_common::debug;

use crate::{LockingError, POX_5_NAME};

/// Outcome of parsing a pox-5 stake / register-for-bond / stake-update /
/// unstake response. `Ok` means the contract returned a well-formed
/// `(ok { staker, amount-ustx, unlock-burn-height, ... })` tuple;
/// `ContractErr` means the contract returned `(err <uint>)` —
/// a normal user-visible failure that the locking handler must skip.
#[derive(Debug)]
enum ParsedStakeResult {
    Ok {
        staker: PrincipalData,
        amount_ustx: u128,
        unlock_burn_height: u64,
    },
    ContractErr,
}

/// Parse the returned value from PoX-5 `stake`, `stake-update`,
/// `register-for-bond`, and `unstake`. These functions return
/// `(ok { staker, amount-ustx, unlock-burn-height, ... })` on success and
/// `(err <code>)` on failure.
///
/// Returns `Err(LockingError::PoxMalformedResponse(...))` if the response
/// shape doesn't match the expected pox-5 contract — that's an invariant
/// violation, not a user-level failure, so callers should propagate it
/// rather than silently no-op.
fn parse_pox_stake_result(result: &Value) -> Result<ParsedStakeResult, LockingError> {
    let response = result
        .clone()
        .expect_result()
        .map_err(|e| LockingError::PoxMalformedResponse(format!("not a response: {e:?}")))?;
    match response {
        Ok(res) => {
            let tuple_data = res.expect_tuple().map_err(|e| {
                LockingError::PoxMalformedResponse(format!("ok payload not a tuple: {e:?}"))
            })?;
            let staker = tuple_data
                .get("staker")
                .map_err(|_| LockingError::PoxMalformedResponse("missing 'staker'".into()))?
                .to_owned()
                .expect_principal()
                .map_err(|e| {
                    LockingError::PoxMalformedResponse(format!(
                        "'staker' is not a principal: {e:?}"
                    ))
                })?;

            let amount_ustx = tuple_data
                .get("amount-ustx")
                .map_err(|_| LockingError::PoxMalformedResponse("missing 'amount-ustx'".into()))?
                .to_owned()
                .expect_u128()
                .map_err(|e| {
                    LockingError::PoxMalformedResponse(format!(
                        "'amount-ustx' is not a uint: {e:?}"
                    ))
                })?;

            let unlock_burn_height_u128 = tuple_data
                .get("unlock-burn-height")
                .map_err(|_| {
                    LockingError::PoxMalformedResponse("missing 'unlock-burn-height'".into())
                })?
                .to_owned()
                .expect_u128()
                .map_err(|e| {
                    LockingError::PoxMalformedResponse(format!(
                        "'unlock-burn-height' is not a uint: {e:?}"
                    ))
                })?;
            let unlock_burn_height: u64 = unlock_burn_height_u128.try_into().map_err(|_| {
                LockingError::PoxMalformedResponse(format!(
                    "'unlock-burn-height' overflows u64: {unlock_burn_height_u128}"
                ))
            })?;

            Ok(ParsedStakeResult::Ok {
                staker,
                amount_ustx,
                unlock_burn_height,
            })
        }
        Err(e) => {
            // Validate the err payload shape — pox-5 is typed
            // `(response ... uint)`, so a non-uint here means the response
            // is malformed and should surface as such.
            e.expect_u128().map_err(|err| {
                LockingError::PoxMalformedResponse(format!("err payload not a uint: {err:?}"))
            })?;
            Ok(ParsedStakeResult::ContractErr)
        }
    }
}

/// Lift a `LockingError` produced by an unexpected pox-locking failure into
/// a graceful `VmExecutionError`. Used by the handlers to surface
/// invariant violations as transaction-aborting runtime errors instead of
/// panicking the node.
///
/// `DefunctPoxContract` and `PoxAlreadyLocked` are user-visible and have
/// dedicated `RuntimeError` variants; the rest are internal invariants
/// the pox-5 contract is supposed to uphold and surface as
/// `VmInternalError::Expect`.
fn locking_error_to_vm_error(e: LockingError, ctx: &str) -> VmExecutionError {
    match e {
        LockingError::DefunctPoxContract => {
            VmExecutionError::Runtime(RuntimeError::DefunctPoxContract, None)
        }
        LockingError::PoxAlreadyLocked => {
            VmExecutionError::Runtime(RuntimeError::PoxAlreadyLocked, None)
        }
        LockingError::Clarity(err) => err,
        // Exhaustively match the remaining variants so adding a new one
        // forces a decision here instead of silently falling through to
        // `VmInternalError::Expect`. If a future variant is user-visible,
        // give it its own arm above; if it really is an invariant
        // violation, add it to this list.
        e @ (LockingError::PoxInsufficientBalance
        | LockingError::PoxExtendNotLocked
        | LockingError::PoxIncreaseOnV1
        | LockingError::PoxInvalidIncrease
        | LockingError::PoxUnstakeNotLocked
        | LockingError::PoxInvalidLockAmount
        | LockingError::PoxInvalidUnlockHeight
        | LockingError::PoxBalanceOverflow
        | LockingError::PoxMalformedResponse(_)) => VmExecutionError::Internal(
            VmInternalError::Expect(format!("{ctx}: pox-5 invariant violated: {e:?}")),
        ),
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
    if unlock_burn_height == 0 {
        return Err(LockingError::PoxInvalidUnlockHeight);
    }
    if lock_amount == 0 {
        return Err(LockingError::PoxInvalidLockAmount);
    }

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
    if unlock_burn_height == 0 {
        return Err(LockingError::PoxInvalidUnlockHeight);
    }

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
    if unlock_burn_height == 0 {
        return Err(LockingError::PoxInvalidUnlockHeight);
    }
    if new_total_locked == 0 {
        return Err(LockingError::PoxInvalidLockAmount);
    }

    let mut snapshot = db.get_stx_balance_snapshot(principal)?;

    if !snapshot.has_locked_tokens()? {
        return Err(LockingError::PoxExtendNotLocked);
    }

    snapshot.update_unlock_v5(unlock_burn_height)?;

    let bal = snapshot.canonical_balance_repr()?;
    let total_amount = bal
        .amount_unlocked()
        .checked_add(bal.amount_locked())
        .ok_or(LockingError::PoxBalanceOverflow)?;
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

/// Roll an existing pox-5 lock forward into a new position: reschedule the
/// unlock to `unlock_burn_height` and reset the locked amount to
/// `new_total_locked`, which may be higher OR lower than the current lock
/// (any freed STX returns to the unlocked balance). Does NOT touch the
/// account nonce. Returns the resulting balance.
///
/// Used for any cross-mode roll-over the pox-5 contract permits: bond →
/// bond (`register-for-bond` from a previous bond), stake → bond
/// (`register-for-bond` from an STX-only stake), and bond → stake (`stake`
/// from a previous bond). The contract gates which transitions are legal;
/// at the node level we trust the call. In every case the STX lock is
/// carried over rather than released and re-acquired, so there is no gap.
///
/// # Errors
/// - Returns `PoxInvalidUnlockHeight` if the `unlock_burn_height` is not
///   strictly greater than the current unlock height (a roll-over must move
///   the unlock forward).
/// - Returns `PoxInvalidLockAmount` if the `new_total_locked` is zero.
/// - Returns `PoxExtendNotLocked` if the account isn't currently locked.
///   The pox-5 contract only reaches this path with an active prior lock
///   (existing bond membership or stx-only stake), so this should surface
///   as an invariant violation.
/// - Returns `PoxInsufficientBalance` if the account can't cover
///   `new_total_locked`.
pub fn pox_rollover_v5(
    db: &mut ClarityDatabase,
    principal: &PrincipalData,
    unlock_burn_height: u64,
    new_total_locked: u128,
) -> Result<STXBalance, LockingError> {
    if new_total_locked == 0 {
        return Err(LockingError::PoxInvalidLockAmount);
    }

    let mut snapshot = db.get_stx_balance_snapshot(principal)?;

    if !snapshot.has_locked_tokens()? {
        return Err(LockingError::PoxExtendNotLocked);
    }

    let bal = snapshot.canonical_balance_repr()?;
    let total_amount = bal
        .amount_unlocked()
        .checked_add(bal.amount_locked())
        .ok_or(LockingError::PoxBalanceOverflow)?;
    if total_amount < new_total_locked {
        return Err(LockingError::PoxInsufficientBalance);
    }

    if unlock_burn_height <= bal.unlock_height() {
        return Err(LockingError::PoxInvalidUnlockHeight);
    }

    snapshot.set_lock_v5(new_total_locked, unlock_burn_height)?;

    let out_balance = snapshot.canonical_balance_repr()?;

    debug!(
        "PoX v5 lock rolled forward";
        "pox_locked_ustx" => out_balance.amount_locked(),
        "available_ustx" => out_balance.amount_unlocked(),
        "unlock_burn_height" => unlock_burn_height,
        "account" => %principal,
    );

    snapshot.save()?;
    Ok(out_balance)
}

/// Handle responses from pox-5 entry points that lock STX for a staker:
/// `stake` (STX-only) and `register-for-bond` (protocol bond). A first-time
/// call (no existing pox-5 lock) acquires a fresh lock via
/// [`pox_lock_v5`]; a roll-over (the account is already locked from an
/// ending bond or stake) carries the lock forward via
/// [`pox_rollover_v5`] -- the amount may go up or down and the
/// unlock height is rescheduled, so the lock never releases. The contract
/// is responsible for gating the roll-over (non-overlap + L1 unlock window
/// for bond sources); if the contract returns ok, this handler trusts the
/// call is legitimate.
fn handle_lockup_pox_v5(
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

    let parsed = parse_pox_stake_result(value).map_err(|e| {
        locking_error_to_vm_error(e, &format!("pox-5 {function_name}: bad response"))
    })?;
    let (staker, locked_amount, unlock_height) = match parsed {
        ParsedStakeResult::Ok {
            staker,
            amount_ustx,
            unlock_burn_height,
        } => (staker, amount_ustx, unlock_burn_height),
        ParsedStakeResult::ContractErr => return Ok(None),
    };

    // A staker rolling from one bond/stake position into another is already
    // locked; carry the lock forward instead of acquiring a fresh one (which
    // would fail with `PoxAlreadyLocked`). A first-time call locks fresh.
    let already_locked = {
        let mut snapshot = global_context.database.get_stx_balance_snapshot(&staker)?;
        snapshot.has_locked_tokens()?
    };

    let lock_result = if already_locked {
        pox_rollover_v5(
            &mut global_context.database,
            &staker,
            unlock_height,
            locked_amount,
        )
        .map(|_| ())
    } else {
        pox_lock_v5(
            &mut global_context.database,
            &staker,
            locked_amount,
            unlock_height,
        )
    };

    match lock_result {
        Ok(()) => {
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
        Err(e) => Err(locking_error_to_vm_error(
            e,
            &format!("pox-5 {function_name}: failed to lock {locked_amount} from {staker} until {unlock_height}"),
        )),
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

    let parsed = parse_pox_stake_result(value).map_err(|e| {
        locking_error_to_vm_error(e, &format!("pox-5 {function_name}: bad response"))
    })?;
    let (staker, amount_ustx, unlock_height) = match parsed {
        ParsedStakeResult::Ok {
            staker,
            amount_ustx,
            unlock_burn_height,
        } => (staker, amount_ustx, unlock_burn_height),
        ParsedStakeResult::ContractErr => return Ok(None),
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
        Err(e) => Err(locking_error_to_vm_error(
            e,
            &format!(
                "pox-5 {function_name}: failed to extend lock from {staker} until {unlock_height}"
            ),
        )),
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

    let parsed = parse_pox_stake_result(value).map_err(|e| {
        locking_error_to_vm_error(e, &format!("pox-5 {function_name}: bad response"))
    })?;
    let (staker, locked_amount, unlock_height) = match parsed {
        ParsedStakeResult::Ok {
            staker,
            amount_ustx,
            unlock_burn_height,
        } => (staker, amount_ustx, unlock_burn_height),
        ParsedStakeResult::ContractErr => return Ok(None),
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
        Err(e) => Err(locking_error_to_vm_error(
            e,
            &format!("pox-5 {function_name}: failed to unstake {staker} until {unlock_height}"),
        )),
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
            handle_lockup_pox_v5(global_context, function_name, value)?
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
        match parse_pox_stake_result(&response).expect("parse should succeed") {
            ParsedStakeResult::Ok {
                staker: parsed_staker,
                amount_ustx,
                unlock_burn_height,
            } => {
                assert_eq!(parsed_staker, staker);
                assert_eq!(amount_ustx, 500_000);
                assert_eq!(unlock_burn_height, 10_000);
            }
            ParsedStakeResult::ContractErr => panic!("expected Ok, got ContractErr"),
        }
    }

    #[test]
    fn parse_pox_stake_result_err() {
        let response = Value::error(Value::UInt(1)).unwrap();
        match parse_pox_stake_result(&response).expect("parse should succeed") {
            ParsedStakeResult::ContractErr => {}
            ParsedStakeResult::Ok { .. } => panic!("expected ContractErr"),
        }
    }

    #[test]
    fn parse_pox_stake_result_malformed_response_returns_error() {
        // Not a `(response ...)` value at all — just a plain uint.
        let bogus = Value::UInt(0);
        let err =
            parse_pox_stake_result(&bogus).expect_err("non-response value must surface as error");
        assert!(
            matches!(err, LockingError::PoxMalformedResponse(_)),
            "unexpected error: {err:?}"
        );

        // `(ok 1)` — ok payload isn't a tuple.
        let ok_not_tuple = Value::okay(Value::UInt(1)).unwrap();
        let err = parse_pox_stake_result(&ok_not_tuple)
            .expect_err("non-tuple ok payload must surface as error");
        assert!(
            matches!(err, LockingError::PoxMalformedResponse(_)),
            "unexpected error: {err:?}"
        );
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
        let event = handle_lockup_pox_v5(&mut global_context, "stake", &response)
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
        let event = handle_lockup_pox_v5(&mut global_context, "stake", &err_response)
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
    fn handle_stake_lockup_insufficient_balance_returns_internal_error() {
        let staker: PrincipalData = StandardPrincipalData::transient().into();
        let total_amount = 100_000;
        let lock_amount = 500_000u128; // more than the account has

        let mut store = MemoryBackingStore::new();
        let mut global_context = setup_global_context(&mut store, &staker, total_amount);

        let response = make_stake_ok_response(&staker, lock_amount, 10_000);
        // The contract is supposed to prevent this; hitting this path used
        // to panic but now surfaces as a graceful Internal/Expect error.
        let err = handle_lockup_pox_v5(&mut global_context, "stake", &response)
            .expect_err("expected an Internal error");
        match err {
            VmExecutionError::Internal(VmInternalError::Expect(_)) => {}
            other => panic!("expected Internal/Expect, got: {other:?}"),
        }
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
    fn handle_stake_update_on_unlocked_account_returns_internal_error() {
        let staker: PrincipalData = StandardPrincipalData::transient().into();
        let mut store = MemoryBackingStore::new();
        let mut global_context = setup_global_context(&mut store, &staker, 1_000_000);

        // No tokens locked — pox-5 should never have produced a stake-update
        // ok for this account.
        let response = make_stake_update_ok_response(&staker, 500_000, 10_000);
        let err = handle_stake_lockup_update_pox_v5(&mut global_context, "stake-update", &response)
            .expect_err("expected an Internal error");
        match err {
            VmExecutionError::Internal(VmInternalError::Expect(_)) => {}
            other => panic!("expected Internal/Expect, got: {other:?}"),
        }
    }

    // `stake` on an already-locked account rolls the existing lock forward
    // (bond → STX-only stake rollover). At the node level the function name
    // is the only difference vs `register-for-bond` — the lock-state path is
    // `handle_lockup_pox_v5` → `pox_rollover_v5`, identical to the bond →
    // bond rollover tests above. We cover same/higher/lower at the dispatch
    // boundary to anchor the cross-mode hand-off and the
    // [`handle_lockup_pox_v5`] routing.

    /// Bond → stake, new amount equal to current locked.
    #[test]
    fn handle_stake_on_locked_account_rolls_forward_same_amount() {
        let staker: PrincipalData = StandardPrincipalData::transient().into();
        let total_amount = 1_000_000;
        let lock_amount = 400_000u128;
        let bond_unlock = 10_000u64;
        let stake_unlock = 24_000u64;

        let mut store = MemoryBackingStore::new();
        let mut global_context = setup_global_context(&mut store, &staker, total_amount);

        pox_lock_v5(
            &mut global_context.database,
            &staker,
            lock_amount,
            bond_unlock,
        )
        .expect("initial lock should succeed");

        let response = make_stake_ok_response(&staker, lock_amount, stake_unlock);
        let event = handle_lockup_pox_v5(&mut global_context, "stake", &response)
            .expect("handler should succeed")
            .expect("expected an STXLockEvent");
        match event {
            StacksTransactionEvent::STXEvent(STXEventType::STXLockEvent(data)) => {
                assert_eq!(data.locked_amount, lock_amount);
                assert_eq!(data.unlock_height, stake_unlock);
            }
            other => panic!("Expected STXLockEvent, got: {other:?}"),
        }

        let snapshot = global_context
            .database
            .get_stx_balance_snapshot(&staker)
            .expect("Failed to get balance");
        let bal = snapshot.balance();
        assert_eq!(bal.amount_locked(), lock_amount);
        assert_eq!(bal.unlock_height(), stake_unlock);
    }

    /// Bond → stake, new amount higher than current locked.
    #[test]
    fn handle_stake_on_locked_account_rolls_forward_higher_amount() {
        let staker: PrincipalData = StandardPrincipalData::transient().into();
        let total_amount = 1_000_000;
        let bond_lock = 300_000u128;
        let stake_amount = 600_000u128;
        let bond_unlock = 10_000u64;
        let stake_unlock = 24_000u64;

        let mut store = MemoryBackingStore::new();
        let mut global_context = setup_global_context(&mut store, &staker, total_amount);

        pox_lock_v5(
            &mut global_context.database,
            &staker,
            bond_lock,
            bond_unlock,
        )
        .expect("initial lock should succeed");

        let response = make_stake_ok_response(&staker, stake_amount, stake_unlock);
        handle_lockup_pox_v5(&mut global_context, "stake", &response)
            .expect("handler should succeed")
            .expect("expected an STXLockEvent");

        let snapshot = global_context
            .database
            .get_stx_balance_snapshot(&staker)
            .expect("Failed to get balance");
        let bal = snapshot.balance();
        assert_eq!(bal.amount_locked(), stake_amount);
        assert_eq!(bal.unlock_height(), stake_unlock);
        assert_eq!(bal.amount_unlocked(), total_amount - stake_amount);
    }

    /// Bond → stake, new amount lower than current locked. The freed STX
    /// returns to the unlocked balance.
    #[test]
    fn handle_stake_on_locked_account_rolls_forward_lower_amount() {
        let staker: PrincipalData = StandardPrincipalData::transient().into();
        let total_amount = 1_000_000;
        let bond_lock = 600_000u128;
        let stake_amount = 250_000u128;
        let bond_unlock = 10_000u64;
        let stake_unlock = 24_000u64;

        let mut store = MemoryBackingStore::new();
        let mut global_context = setup_global_context(&mut store, &staker, total_amount);

        pox_lock_v5(
            &mut global_context.database,
            &staker,
            bond_lock,
            bond_unlock,
        )
        .expect("initial lock should succeed");

        let response = make_stake_ok_response(&staker, stake_amount, stake_unlock);
        handle_lockup_pox_v5(&mut global_context, "stake", &response)
            .expect("handler should succeed")
            .expect("expected an STXLockEvent");

        let snapshot = global_context
            .database
            .get_stx_balance_snapshot(&staker)
            .expect("Failed to get balance");
        let bal = snapshot.balance();
        assert_eq!(bal.amount_locked(), stake_amount);
        assert_eq!(bal.unlock_height(), stake_unlock);
        assert_eq!(bal.amount_unlocked(), total_amount - stake_amount);
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
        match parse_pox_stake_result(&response).expect("parse should succeed") {
            ParsedStakeResult::Ok {
                staker: parsed_staker,
                amount_ustx,
                unlock_burn_height,
            } => {
                assert_eq!(parsed_staker, staker);
                assert_eq!(amount_ustx, 750_000);
                assert_eq!(unlock_burn_height, 12_000);
            }
            ParsedStakeResult::ContractErr => panic!("expected Ok, got ContractErr"),
        }
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
        let event = handle_lockup_pox_v5(&mut global_context, "register-for-bond", &response)
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
        let event = handle_lockup_pox_v5(&mut global_context, "register-for-bond", &err_response)
            .expect("handler should succeed");

        assert!(event.is_none());

        let balance = global_context
            .database
            .get_account_stx_balance(&staker)
            .expect("Failed to get balance");
        assert_eq!(balance.amount_locked(), 0);
    }

    /// Rolling a bond forward keeps the lock and reschedules it to the new
    /// bond's unlock height, with the locked amount unchanged.
    #[test]
    fn handle_register_for_bond_rolls_forward_same_amount() {
        let staker: PrincipalData = StandardPrincipalData::transient().into();
        let total_amount = 1_000_000;
        let lock_amount = 400_000u128;
        let first_unlock = 12_000u64;
        let next_unlock = 24_000u64;

        let mut store = MemoryBackingStore::new();
        let mut global_context = setup_global_context(&mut store, &staker, total_amount);

        // Bond 0 lock already in place.
        pox_lock_v5(
            &mut global_context.database,
            &staker,
            lock_amount,
            first_unlock,
        )
        .expect("initial lock should succeed");

        // Registering for the next bond rolls the lock forward (no PoxAlreadyLocked).
        let response = make_register_for_bond_ok_response(&staker, lock_amount, next_unlock);
        let event = handle_lockup_pox_v5(&mut global_context, "register-for-bond", &response)
            .expect("handler should succeed")
            .expect("expected an STXLockEvent");
        match event {
            StacksTransactionEvent::STXEvent(STXEventType::STXLockEvent(data)) => {
                assert_eq!(data.locked_amount, lock_amount);
                assert_eq!(data.unlock_height, next_unlock);
            }
            other => panic!("Expected STXLockEvent, got: {other:?}"),
        }

        let snapshot = global_context
            .database
            .get_stx_balance_snapshot(&staker)
            .expect("Failed to get balance");
        let bal = snapshot.balance();
        assert_eq!(bal.amount_locked(), lock_amount);
        assert_eq!(bal.unlock_height(), next_unlock);
        assert_eq!(bal.amount_unlocked(), total_amount - lock_amount);
    }

    /// Rolling forward may lock *more* in the new bond; the extra is taken from
    /// the unlocked balance.
    #[test]
    fn handle_register_for_bond_rolls_forward_higher_amount() {
        let staker: PrincipalData = StandardPrincipalData::transient().into();
        let total_amount = 1_000_000;
        let initial_lock = 400_000u128;
        let new_total = 600_000u128;
        let first_unlock = 12_000u64;
        let next_unlock = 24_000u64;

        let mut store = MemoryBackingStore::new();
        let mut global_context = setup_global_context(&mut store, &staker, total_amount);

        pox_lock_v5(
            &mut global_context.database,
            &staker,
            initial_lock,
            first_unlock,
        )
        .expect("initial lock should succeed");

        let response = make_register_for_bond_ok_response(&staker, new_total, next_unlock);
        handle_lockup_pox_v5(&mut global_context, "register-for-bond", &response)
            .expect("handler should succeed")
            .expect("expected an STXLockEvent");

        let snapshot = global_context
            .database
            .get_stx_balance_snapshot(&staker)
            .expect("Failed to get balance");
        let bal = snapshot.balance();
        assert_eq!(bal.amount_locked(), new_total);
        assert_eq!(bal.unlock_height(), next_unlock);
        assert_eq!(bal.amount_unlocked(), total_amount - new_total);
    }

    /// Rolling forward may lock *less* in the new bond; the difference returns
    /// to the unlocked balance.
    #[test]
    fn handle_register_for_bond_rolls_forward_lower_amount() {
        let staker: PrincipalData = StandardPrincipalData::transient().into();
        let total_amount = 1_000_000;
        let initial_lock = 600_000u128;
        let new_total = 400_000u128;
        let first_unlock = 12_000u64;
        let next_unlock = 24_000u64;

        let mut store = MemoryBackingStore::new();
        let mut global_context = setup_global_context(&mut store, &staker, total_amount);

        pox_lock_v5(
            &mut global_context.database,
            &staker,
            initial_lock,
            first_unlock,
        )
        .expect("initial lock should succeed");

        let response = make_register_for_bond_ok_response(&staker, new_total, next_unlock);
        handle_lockup_pox_v5(&mut global_context, "register-for-bond", &response)
            .expect("handler should succeed")
            .expect("expected an STXLockEvent");

        let snapshot = global_context
            .database
            .get_stx_balance_snapshot(&staker)
            .expect("Failed to get balance");
        let bal = snapshot.balance();
        assert_eq!(bal.amount_locked(), new_total);
        assert_eq!(bal.unlock_height(), next_unlock);
        assert_eq!(bal.amount_unlocked(), total_amount - new_total);
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

    // ── Direct tests for pox_rollover_v5 ──
    //
    // `pox_rollover_v5` is the lock-state primitive backing every cross-mode
    // roll-over (bond → bond, stake → bond, bond → stake). Happy-path and
    // error-path coverage here pins down the invariants the higher-level
    // [`handle_lockup_pox_v5`] dispatcher relies on.

    /// Roll-over with the same locked amount: the lock is rescheduled to the
    /// new unlock height; `amount_locked` and `amount_unlocked` are unchanged.
    #[test]
    fn pox_rollover_v5_same_amount() {
        let staker: PrincipalData = StandardPrincipalData::transient().into();
        let total_amount = 1_000_000;
        let lock_amount = 400_000u128;
        let initial_unlock = 10_000u64;
        let next_unlock = 24_000u64;

        let mut store = MemoryBackingStore::new();
        let mut global_context = setup_global_context(&mut store, &staker, total_amount);

        pox_lock_v5(
            &mut global_context.database,
            &staker,
            lock_amount,
            initial_unlock,
        )
        .expect("initial lock should succeed");

        let new_balance = pox_rollover_v5(
            &mut global_context.database,
            &staker,
            next_unlock,
            lock_amount,
        )
        .expect("rollover should succeed");
        assert_eq!(new_balance.amount_locked(), lock_amount);
        assert_eq!(new_balance.unlock_height(), next_unlock);
        assert_eq!(new_balance.amount_unlocked(), total_amount - lock_amount);
    }

    /// Roll-over to a higher amount: the additional STX is pulled from the
    /// unlocked balance into the lock.
    #[test]
    fn pox_rollover_v5_higher_amount() {
        let staker: PrincipalData = StandardPrincipalData::transient().into();
        let total_amount = 1_000_000;
        let initial_lock = 300_000u128;
        let new_total = 600_000u128;
        let initial_unlock = 10_000u64;
        let next_unlock = 24_000u64;

        let mut store = MemoryBackingStore::new();
        let mut global_context = setup_global_context(&mut store, &staker, total_amount);

        pox_lock_v5(
            &mut global_context.database,
            &staker,
            initial_lock,
            initial_unlock,
        )
        .expect("initial lock should succeed");

        let new_balance = pox_rollover_v5(
            &mut global_context.database,
            &staker,
            next_unlock,
            new_total,
        )
        .expect("rollover should succeed");
        assert_eq!(new_balance.amount_locked(), new_total);
        assert_eq!(new_balance.unlock_height(), next_unlock);
        assert_eq!(new_balance.amount_unlocked(), total_amount - new_total);
    }

    /// Roll-over to a lower amount: the freed STX returns to the unlocked
    /// balance. (This is the case `pox_lock_update_v5` does not allow.)
    #[test]
    fn pox_rollover_v5_lower_amount() {
        let staker: PrincipalData = StandardPrincipalData::transient().into();
        let total_amount = 1_000_000;
        let initial_lock = 600_000u128;
        let new_total = 250_000u128;
        let initial_unlock = 10_000u64;
        let next_unlock = 24_000u64;

        let mut store = MemoryBackingStore::new();
        let mut global_context = setup_global_context(&mut store, &staker, total_amount);

        pox_lock_v5(
            &mut global_context.database,
            &staker,
            initial_lock,
            initial_unlock,
        )
        .expect("initial lock should succeed");

        let new_balance = pox_rollover_v5(
            &mut global_context.database,
            &staker,
            next_unlock,
            new_total,
        )
        .expect("rollover should succeed");
        assert_eq!(new_balance.amount_locked(), new_total);
        assert_eq!(new_balance.unlock_height(), next_unlock);
        assert_eq!(new_balance.amount_unlocked(), total_amount - new_total);
    }

    /// A roll-over must move the unlock height forward: an `unlock_burn_height`
    /// equal to the current unlock height is rejected.
    #[test]
    fn pox_rollover_v5_same_unlock_height_returns_err() {
        let staker: PrincipalData = StandardPrincipalData::transient().into();
        let initial_unlock = 10_000u64;
        let mut store = MemoryBackingStore::new();
        let mut global_context = setup_global_context(&mut store, &staker, 1_000_000);

        pox_lock_v5(
            &mut global_context.database,
            &staker,
            400_000,
            initial_unlock,
        )
        .expect("initial lock should succeed");

        let err = pox_rollover_v5(
            &mut global_context.database,
            &staker,
            initial_unlock,
            500_000,
        )
        .expect_err("expected PoxInvalidUnlockHeight");
        assert!(matches!(err, LockingError::PoxInvalidUnlockHeight));
    }

    /// A roll-over to an earlier unlock height (before the current one) is
    /// rejected — the lock can only be carried forward, never pulled back.
    #[test]
    fn pox_rollover_v5_earlier_unlock_height_returns_err() {
        let staker: PrincipalData = StandardPrincipalData::transient().into();
        let initial_unlock = 10_000u64;
        let mut store = MemoryBackingStore::new();
        let mut global_context = setup_global_context(&mut store, &staker, 1_000_000);

        pox_lock_v5(
            &mut global_context.database,
            &staker,
            400_000,
            initial_unlock,
        )
        .expect("initial lock should succeed");

        let err = pox_rollover_v5(
            &mut global_context.database,
            &staker,
            initial_unlock - 1,
            500_000,
        )
        .expect_err("expected PoxInvalidUnlockHeight");
        assert!(matches!(err, LockingError::PoxInvalidUnlockHeight));
    }

    /// A zero `new_total_locked` is an invalid request (pre-snapshot check).
    #[test]
    fn pox_rollover_v5_zero_amount_returns_err() {
        let staker: PrincipalData = StandardPrincipalData::transient().into();
        let mut store = MemoryBackingStore::new();
        let mut global_context = setup_global_context(&mut store, &staker, 1_000_000);

        let err = pox_rollover_v5(&mut global_context.database, &staker, 10_000, 0)
            .expect_err("expected PoxInvalidLockAmount");
        assert!(matches!(err, LockingError::PoxInvalidLockAmount));
    }

    /// Calling `pox_rollover_v5` on an account that isn't currently locked
    /// is an invariant violation — the contract should never reach this path
    /// without a prior bond membership or stx-only stake.
    #[test]
    fn pox_rollover_v5_not_locked_returns_err() {
        let staker: PrincipalData = StandardPrincipalData::transient().into();
        let mut store = MemoryBackingStore::new();
        let mut global_context = setup_global_context(&mut store, &staker, 1_000_000);

        // No prior lock — has_locked_tokens is false.
        let err = pox_rollover_v5(&mut global_context.database, &staker, 10_000, 500_000)
            .expect_err("expected PoxExtendNotLocked");
        assert!(matches!(err, LockingError::PoxExtendNotLocked));
    }

    /// A rollover that asks to lock more than the account holds (unlocked +
    /// locked) must surface as `PoxInsufficientBalance`.
    #[test]
    fn pox_rollover_v5_insufficient_balance_returns_err() {
        let staker: PrincipalData = StandardPrincipalData::transient().into();
        let total_amount = 500_000;
        let initial_lock = 300_000u128;
        let initial_unlock = 10_000u64;

        let mut store = MemoryBackingStore::new();
        let mut global_context = setup_global_context(&mut store, &staker, total_amount);

        pox_lock_v5(
            &mut global_context.database,
            &staker,
            initial_lock,
            initial_unlock,
        )
        .expect("initial lock should succeed");

        // Ask for more than the account's total balance.
        let err = pox_rollover_v5(
            &mut global_context.database,
            &staker,
            24_000,
            total_amount + 1,
        )
        .expect_err("expected PoxInsufficientBalance");
        assert!(matches!(err, LockingError::PoxInsufficientBalance));
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
    fn handle_unstake_on_unlocked_account_returns_internal_error() {
        let staker: PrincipalData = StandardPrincipalData::transient().into();
        let mut store = MemoryBackingStore::new();
        let mut global_context = setup_global_context(&mut store, &staker, 1_000_000);

        // No tokens locked — pox-5 should never have produced an unstake `ok`
        // for this account.
        let response = make_unstake_ok_response(&staker, 500_000, 5_000);
        let err = handle_unstake_pox_v5(&mut global_context, "unstake", &response)
            .expect_err("expected an Internal error");
        match err {
            VmExecutionError::Internal(VmInternalError::Expect(_)) => {}
            other => panic!("expected Internal/Expect, got: {other:?}"),
        }
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
    use proptest::prelude::*;

    proptest! {
        /// Rule: `lock_amount == 0` is rejected before any DB work.
        #[test]
        #[cfg_attr(test, pinny::tag(t_prop))]
        fn prop_pox_lock_v5_zero_amount_rejected(
            unlock_height in 1u64..=1_000_000,
            total_amount in 1u128..=1_000_000_000,
        ) {
            let staker: PrincipalData = StandardPrincipalData::transient().into();
            let mut store = MemoryBackingStore::new();
            let mut gc = setup_global_context(&mut store, &staker, total_amount);

            let err = pox_lock_v5(&mut gc.database, &staker, 0, unlock_height)
                .expect_err("zero amount must be rejected");
            prop_assert!(
                matches!(err, LockingError::PoxInvalidLockAmount),
                "expected PoxInvalidLockAmount, got {err:?}"
            );
        }

        /// Rule: `unlock_burn_height == 0` is rejected before any DB work.
        #[test]
        #[cfg_attr(test, pinny::tag(t_prop))]
        fn prop_pox_lock_v5_zero_height_rejected(
            amount in 1u128..=1_000_000,
            total_amount in 1u128..=1_000_000_000,
        ) {
            let staker: PrincipalData = StandardPrincipalData::transient().into();
            let mut store = MemoryBackingStore::new();
            let mut gc = setup_global_context(&mut store, &staker, total_amount);

            let err = pox_lock_v5(&mut gc.database, &staker, amount, 0)
                .expect_err("zero unlock_height must be rejected");
            prop_assert!(
                matches!(err, LockingError::PoxInvalidUnlockHeight),
                "expected PoxInvalidUnlockHeight, got {err:?}"
            );
        }

        /// Rule: a second `pox_lock_v5` on an already-locked account must surface
        /// `PoxAlreadyLocked` no matter what the second amount/height are.
        /// `has_locked_tokens` is checked before `can_transfer`, so the rejection
        /// applies even when the second amount would otherwise exceed the
        /// available balance.
        #[test]
        #[cfg_attr(test, pinny::tag(t_prop))]
        fn prop_pox_lock_v5_double_lock_rejected(
            first_amount in 1u128..=500_000,
            first_unlock in 1_000u64..=1_000_000,
            second_amount in 1u128..=10_000_000,
            second_unlock in 1u64..=1_000_000,
        ) {
            let staker: PrincipalData = StandardPrincipalData::transient().into();
            let total_amount: u128 = 10_000_000;
            let mut store = MemoryBackingStore::new();
            let mut gc = setup_global_context(&mut store, &staker, total_amount);

            pox_lock_v5(&mut gc.database, &staker, first_amount, first_unlock)
                .expect("first lock should succeed");
            let err = pox_lock_v5(&mut gc.database, &staker, second_amount, second_unlock)
                .expect_err("second lock must be rejected");
            prop_assert!(
                matches!(err, LockingError::PoxAlreadyLocked),
                "expected PoxAlreadyLocked, got {err:?}"
            );
        }

        /// Rule: locking more than the available balance is rejected with
        /// `PoxInsufficientBalance` (after the zero-amount/zero-height gates).
        #[test]
        #[cfg_attr(test, pinny::tag(t_prop))]
        fn prop_pox_lock_v5_exceeds_balance(
            balance in 1u128..=1_000_000,
            extra in 1u128..=1_000_000,
            unlock_height in 1u64..=1_000_000,
        ) {
            let lock_amount = balance.checked_add(extra).unwrap();
            let staker: PrincipalData = StandardPrincipalData::transient().into();
            let mut store = MemoryBackingStore::new();
            let mut gc = setup_global_context(&mut store, &staker, balance);

            let err = pox_lock_v5(&mut gc.database, &staker, lock_amount, unlock_height)
                .expect_err("over-balance lock must be rejected");
            prop_assert!(
                matches!(err, LockingError::PoxInsufficientBalance),
                "expected PoxInsufficientBalance, got {err:?}"
            );
        }

        /// Rule: `pox_lock_update_v5` cannot reduce `amount_locked`. Any
        /// `new_total_locked < current_amount_locked` must return
        /// `PoxInvalidIncrease` — there is no "decrease via stake-update" path.
        #[test]
        #[cfg_attr(test, pinny::tag(t_prop))]
        fn prop_pox_lock_update_v5_no_decrease(
            initial_lock in 100u128..=1_000_000,
            decrease in 1u128..=99,
            initial_unlock in 1_000u64..=1_000_000,
            new_unlock in 1_000u64..=1_000_000,
        ) {
            let new_total = initial_lock - decrease;
            let total_amount: u128 = 10_000_000;
            let staker: PrincipalData = StandardPrincipalData::transient().into();
            let mut store = MemoryBackingStore::new();
            let mut gc = setup_global_context(&mut store, &staker, total_amount);

            pox_lock_v5(&mut gc.database, &staker, initial_lock, initial_unlock)
                .expect("first lock should succeed");
            let err = pox_lock_update_v5(&mut gc.database, &staker, new_unlock, new_total)
                .expect_err("decrease must be rejected");
            prop_assert!(
                matches!(err, LockingError::PoxInvalidIncrease),
                "expected PoxInvalidIncrease, got {err:?}"
            );
        }

        /// Rule: `pox_unstake_v5` with `unlock_burn_height == 0` is the FIRST
        /// gate and produces `PoxInvalidUnlockHeight`, regardless of whether
        /// the account is locked. Pins the gate ordering inside
        /// `pox_unstake_v5`.
        #[test]
        #[cfg_attr(test, pinny::tag(t_prop))]
        fn prop_pox_unstake_v5_zero_height_rejected(
            total_amount in 1u128..=1_000_000_000,
        ) {
            let staker: PrincipalData = StandardPrincipalData::transient().into();
            let mut store = MemoryBackingStore::new();
            let mut gc = setup_global_context(&mut store, &staker, total_amount);

            let err = pox_unstake_v5(&mut gc.database, &staker, 0)
                .expect_err("zero unlock_burn_height must be rejected");
            prop_assert!(
                matches!(err, LockingError::PoxInvalidUnlockHeight),
                "expected PoxInvalidUnlockHeight, got {err:?}"
            );
        }

        /// Rule: `pox_lock_update_v5` with `new_total_locked == 0` fails with
        /// `PoxInvalidLockAmount`. Mirrors the `pox_lock_v5` zero-amount
        /// gate but on the update path.
        #[test]
        #[cfg_attr(test, pinny::tag(t_prop))]
        fn prop_pox_lock_update_v5_zero_total_rejected(
            unlock_height in 1u64..=1_000_000,
            total_amount in 1u128..=1_000_000_000,
        ) {
            let staker: PrincipalData = StandardPrincipalData::transient().into();
            let mut store = MemoryBackingStore::new();
            let mut gc = setup_global_context(&mut store, &staker, total_amount);

            let err = pox_lock_update_v5(&mut gc.database, &staker, unlock_height, 0)
                .expect_err("zero new_total must be rejected");
            prop_assert!(
                matches!(err, LockingError::PoxInvalidLockAmount),
                "expected PoxInvalidLockAmount, got {err:?}"
            );
        }

        /// Rule: `pox_lock_update_v5` on an UNLOCKED account produces
        /// `PoxExtendNotLocked` — you can't extend something you haven't
        /// started.
        #[test]
        #[cfg_attr(test, pinny::tag(t_prop))]
        fn prop_pox_lock_update_v5_not_locked(
            unlock_height in 1u64..=1_000_000,
            new_total in 1u128..=1_000_000,
            total_amount in 1_000_000u128..=1_000_000_000,
        ) {
            let staker: PrincipalData = StandardPrincipalData::transient().into();
            let mut store = MemoryBackingStore::new();
            let mut gc = setup_global_context(&mut store, &staker, total_amount);

            let err = pox_lock_update_v5(&mut gc.database, &staker, unlock_height, new_total)
                .expect_err("update on unlocked must be rejected");
            prop_assert!(
                matches!(err, LockingError::PoxExtendNotLocked),
                "expected PoxExtendNotLocked, got {err:?}"
            );
        }

        /// Rule: `pox_lock_update_v5` with `new_total > total_balance` fails
        /// with `PoxInsufficientBalance`. The check is strict `<` (not `<=`)
        /// — `new_total == total_balance` is accepted (full-balance lock).
        /// Pins the comparator direction.
        #[test]
        #[cfg_attr(test, pinny::tag(t_prop))]
        fn prop_pox_lock_update_v5_exceeds_balance(
            initial_lock in 100u128..=1_000,
            initial_unlock in 1_000u64..=1_000_000,
            new_unlock in 1_000u64..=1_000_000,
            extra in 1u128..=1_000_000,
        ) {
            let total_amount: u128 = 100_000;
            let new_total = total_amount.checked_add(extra).unwrap();
            let staker: PrincipalData = StandardPrincipalData::transient().into();
            let mut store = MemoryBackingStore::new();
            let mut gc = setup_global_context(&mut store, &staker, total_amount);

            pox_lock_v5(&mut gc.database, &staker, initial_lock, initial_unlock)
                .expect("initial lock should succeed");
            let err = pox_lock_update_v5(&mut gc.database, &staker, new_unlock, new_total)
                .expect_err("new_total > total_balance must be rejected");
            prop_assert!(
                matches!(err, LockingError::PoxInsufficientBalance),
                "expected PoxInsufficientBalance, got {err:?}"
            );
        }

        /// Locking exactly `total_balance` (not more) must be accepted.
        /// The comparator in `pox_lock_update_v5` is strict `<`, so
        /// `new_total == total_amount` is the legal full-balance lock —
        /// pins the comparator direction at the boundary.
        #[test]
        #[cfg_attr(test, pinny::tag(t_prop))]
        fn prop_pox_lock_update_v5_exact_balance_accepted(
            initial_lock in 100u128..=10_000,
            initial_unlock in 1_000u64..=1_000_000,
            new_unlock in 1_000u64..=1_000_000,
        ) {
            let total_amount: u128 = 100_000;
            let staker: PrincipalData = StandardPrincipalData::transient().into();
            let mut store = MemoryBackingStore::new();
            let mut gc = setup_global_context(&mut store, &staker, total_amount);

            pox_lock_v5(&mut gc.database, &staker, initial_lock, initial_unlock)
                .expect("initial lock should succeed");

            // Lock every available ustx (new_total == total). Must be
            // accepted — comparator is strict `<`, not `<=`.
            let result = pox_lock_update_v5(
                &mut gc.database, &staker, new_unlock, total_amount,
            );
            prop_assert!(
                result.is_ok(),
                "exact-balance lock should be accepted, got {result:?}"
            );
        }

        /// Symmetric pin for `pox_lock_v5`: locking exactly the full balance
        /// from scratch (no prior lock) must succeed. The check is delegated
        /// to `can_transfer`, so cargo-mutants can't surface a comparator
        /// mutant directly, but the boundary test pins the documented contract.
        #[test]
        #[cfg_attr(test, pinny::tag(t_prop))]
        fn prop_pox_lock_v5_exact_balance_accepted(
            balance in 1u128..=1_000_000,
            unlock_height in 1u64..=1_000_000,
        ) {
            let staker: PrincipalData = StandardPrincipalData::transient().into();
            let mut store = MemoryBackingStore::new();
            let mut gc = setup_global_context(&mut store, &staker, balance);

            // Lock the entire available balance. Must succeed.
            let result = pox_lock_v5(&mut gc.database, &staker, balance, unlock_height);
            prop_assert!(
                result.is_ok(),
                "full-balance lock should be accepted, got {result:?}"
            );
        }

        /// Rule: `pox_unstake_v5` on an account that holds no lock fails with
        /// `PoxUnstakeNotLocked` regardless of the requested unlock height.
        #[test]
        #[cfg_attr(test, pinny::tag(t_prop))]
        fn prop_pox_unstake_v5_not_locked(
            unlock_height in 1u64..=1_000_000,
            total_amount in 1u128..=1_000_000_000,
        ) {
            let staker: PrincipalData = StandardPrincipalData::transient().into();
            let mut store = MemoryBackingStore::new();
            let mut gc = setup_global_context(&mut store, &staker, total_amount);

            let err = pox_unstake_v5(&mut gc.database, &staker, unlock_height)
                .expect_err("unstake on unlocked must be rejected");
            prop_assert!(
                matches!(err, LockingError::PoxUnstakeNotLocked),
                "expected PoxUnstakeNotLocked, got {err:?}"
            );
        }

        /// Rule: a Clarity tuple missing any of `staker`, `amount-ustx`, or
        /// `unlock-burn-height` is rejected as `PoxMalformedResponse`. Pins the
        /// contract <-> handler shape contract against future field renames.
        #[test]
        #[cfg_attr(test, pinny::tag(t_prop))]
        fn prop_parse_pox_stake_result_malformed_missing_field(
            which_field in 0u8..=2,
            amount in any::<u128>(),
            unlock_u64 in any::<u64>(),
        ) {
            let staker: PrincipalData = StandardPrincipalData::transient().into();
            let mut fields: Vec<(ClarityName, Value)> = vec![
                (ClarityName::from_literal("staker"), Value::Principal(staker)),
                (ClarityName::from_literal("amount-ustx"), Value::UInt(amount)),
                (
                    ClarityName::from_literal("unlock-burn-height"),
                    Value::UInt(u128::from(unlock_u64)),
                ),
            ];
            fields.remove(which_field as usize);
            let tuple = TupleData::from_data(fields).unwrap();
            let bad = Value::okay(Value::Tuple(tuple)).unwrap();
            let err = parse_pox_stake_result(&bad)
                .expect_err("missing field must surface as PoxMalformedResponse");
            prop_assert!(
                matches!(err, LockingError::PoxMalformedResponse(_)),
                "expected PoxMalformedResponse, got {err:?}"
            );
        }

        /// Rule: an `unlock-burn-height` u128 value above `u64::MAX` must surface
        /// as `PoxMalformedResponse`. This is the only place the u128 -> u64
        /// cast can overflow silently.
        #[test]
        #[cfg_attr(test, pinny::tag(t_prop))]
        fn prop_parse_pox_stake_result_unlock_height_overflow(
            unlock_overflow in ((u64::MAX as u128) + 1)..=u128::MAX,
            amount in any::<u128>(),
        ) {
            let staker: PrincipalData = StandardPrincipalData::transient().into();
            let fields: Vec<(ClarityName, Value)> = vec![
                (ClarityName::from_literal("staker"), Value::Principal(staker)),
                (ClarityName::from_literal("amount-ustx"), Value::UInt(amount)),
                (
                    ClarityName::from_literal("unlock-burn-height"),
                    Value::UInt(unlock_overflow),
                ),
            ];
            let tuple = TupleData::from_data(fields).unwrap();
            let bad = Value::okay(Value::Tuple(tuple)).unwrap();
            let err = parse_pox_stake_result(&bad)
                .expect_err("u128 > u64::MAX must surface as PoxMalformedResponse");
            prop_assert!(
                matches!(err, LockingError::PoxMalformedResponse(_)),
                "expected PoxMalformedResponse, got {err:?}"
            );
        }

        /// Rule: a pox-5 `(err ...)` payload is typed `uint`; any non-uint err
        /// payload must surface as `PoxMalformedResponse` (the `expect_u128`
        /// gate on the err arm). Complements the ok-shape malformed properties.
        #[test]
        #[cfg_attr(test, pinny::tag(t_prop))]
        fn prop_parse_pox_stake_result_err_non_uint(
            b in any::<bool>(),
            n in any::<i128>(),
            which in 0u8..=1,
        ) {
            let payload = if which == 0 { Value::Bool(b) } else { Value::Int(n) };
            let bad = Value::error(payload).unwrap();
            let err = parse_pox_stake_result(&bad)
                .expect_err("non-uint err payload must surface as PoxMalformedResponse");
            prop_assert!(
                matches!(err, LockingError::PoxMalformedResponse(_)),
                "expected PoxMalformedResponse, got {err:?}"
            );
        }
    }
}
