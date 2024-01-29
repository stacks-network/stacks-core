// Copyright (C) 2013-2020 Blockstack PBC, a public benefit corporation
// Copyright (C) 2020-2023 Stacks Open Internet Foundation
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
use clarity::vm::database::ClarityDatabase;
use clarity::vm::errors::{Error as ClarityError, RuntimeErrorType};
use clarity::vm::events::{STXEventType, STXLockEventData, StacksTransactionEvent};
use clarity::vm::types::PrincipalData;
use clarity::vm::Value;
use slog::slog_debug;
use stacks_common::debug;

use crate::LockingError;

/// Parse the returned value from PoX `stack-stx` and `delegate-stack-stx` functions
///  from pox.clar into a format more readily digestible in rust.
/// Panics if the supplied value doesn't match the expected tuple structure
fn parse_pox_stacking_result_v1(
    result: &Value,
) -> std::result::Result<(PrincipalData, u128, u64), i128> {
    match result
        .clone()
        .expect_result()
        .expect("FATAL: unexpected clarity value")
    {
        Ok(res) => {
            // should have gotten back (ok (tuple (stacker principal) (lock-amount uint) (unlock-burn-height uint)))
            let tuple_data = res.expect_tuple().expect("FATAL: unexpected clarity value");
            let stacker = tuple_data
                .get("stacker")
                .expect("FATAL: no 'stacker'")
                .to_owned()
                .expect_principal()
                .expect("FATAL: unexpected clarity value");

            let lock_amount = tuple_data
                .get("lock-amount")
                .expect("FATAL: no 'lock-amount'")
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

            Ok((stacker, lock_amount, unlock_burn_height))
        }
        Err(e) => Err(e.expect_i128().expect("FATAL: unexpected clarity value")),
    }
}

/// Is a PoX-1 function read-only?
/// i.e. can we call it without incurring an error?
pub fn is_read_only(func_name: &str) -> bool {
    func_name == "get-pox-rejection"
        || func_name == "is-pox-active"
        || func_name == "get-stacker-info"
        || func_name == "get-reward-set-size"
        || func_name == "get-total-ustx-stacked"
        || func_name == "get-reward-set-pox-address"
        || func_name == "get-stacking-minimum"
        || func_name == "can-stack-stx"
        || func_name == "minimal-can-stack-stx"
        || func_name == "get-pox-info"
}

/////////////////////// PoX (first version) /////////////////////////////////

/// Lock up STX for PoX for a time.  Does NOT touch the account nonce.
pub fn pox_lock_v1(
    db: &mut ClarityDatabase,
    principal: &PrincipalData,
    lock_amount: u128,
    unlock_burn_height: u64,
) -> Result<(), LockingError> {
    assert!(unlock_burn_height > 0);
    assert!(lock_amount > 0);

    let mut snapshot = db.get_stx_balance_snapshot(principal)?;

    if snapshot.balance().was_locked_by_v2() {
        debug!("PoX Lock attempted on an account locked by v2");
        return Err(LockingError::DefunctPoxContract);
    }

    if snapshot.has_locked_tokens()? {
        return Err(LockingError::PoxAlreadyLocked);
    }
    if !snapshot.can_transfer(lock_amount)? {
        return Err(LockingError::PoxInsufficientBalance);
    }
    snapshot.lock_tokens_v1(lock_amount, unlock_burn_height)?;

    debug!(
        "PoX v1 lock applied";
        "pox_locked_ustx" => snapshot.balance().amount_locked(),
        "available_ustx" => snapshot.balance().amount_unlocked(),
        "unlock_burn_height" => unlock_burn_height,
        "account" => %principal,
    );

    snapshot.save()?;
    Ok(())
}

/// Handle special cases when calling into the PoX v1 contract
#[allow(clippy::needless_return)]
pub fn handle_contract_call(
    global_context: &mut GlobalContext,
    _sender_opt: Option<&PrincipalData>,
    function_name: &str,
    value: &Value,
) -> Result<(), ClarityError> {
    if !(function_name == "stack-stx" || function_name == "delegate-stack-stx") {
        // only have work to do if the function is `stack-stx` or `delegate-stack-stx`
        return Ok(());
    }

    debug!(
        "Handle special-case contract-call to {:?} {} (which returned {:?})",
        "pox-1", function_name, value
    );

    // applying a pox lock at this point is equivalent to evaluating a transfer
    runtime_cost(
        ClarityCostFunction::StxTransfer,
        &mut global_context.cost_track,
        1,
    )?;

    let (stacker, locked_amount, unlock_height) = match parse_pox_stacking_result_v1(value) {
        Ok(x) => x,
        Err(_) => {
            // the pox method failed: do not apply a lock.
            return Ok(());
        }
    };

    // in most cases, if this fails, then there's a bug in the contract (since it already does
    // the necessary checks), but with v2 introduction, that's no longer true -- if someone
    // locks on PoX v2, and then tries to lock again in PoX v1, that's not captured by the v1
    // contract.
    match pox_lock_v1(
        &mut global_context.database,
        &stacker,
        locked_amount,
        unlock_height,
    ) {
        Ok(_) => {
            if let Some(batch) = global_context.event_batches.last_mut() {
                batch.events.push(StacksTransactionEvent::STXEvent(
                    STXEventType::STXLockEvent(STXLockEventData {
                        locked_amount,
                        unlock_height,
                        locked_address: stacker,
                        contract_identifier: boot_code_id("pox", global_context.mainnet),
                    }),
                ));
            }
            return Ok(());
        }
        Err(LockingError::DefunctPoxContract) => {
            return Err(ClarityError::Runtime(
                RuntimeErrorType::DefunctPoxContract,
                None,
            ));
        }
        Err(LockingError::PoxAlreadyLocked) => {
            // the caller tried to lock tokens into both pox-1 and pox-2
            return Err(ClarityError::Runtime(
                RuntimeErrorType::PoxAlreadyLocked,
                None,
            ));
        }
        Err(e) => {
            panic!(
                "FATAL: failed to lock {} from {} until {}: '{:?}'",
                locked_amount, stacker, unlock_height, &e
            );
        }
    }
}
