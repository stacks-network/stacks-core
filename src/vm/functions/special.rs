// Copyright (C) 2013-2020 Blocstack PBC, a public benefit corporation
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

use std::cmp;
use std::convert::{TryFrom, TryInto};
use vm::costs::{cost_functions, CostTracker, MemoryConsumer};

use vm::contexts::{GlobalContext, Environment};
use vm::errors::Error;
use vm::errors::{CheckErrors, InterpreterError, InterpreterResult as Result, RuntimeErrorType};
use vm::representations::{SymbolicExpression, SymbolicExpressionType, ClarityName};
use vm::types::{PrincipalData, QualifiedContractIdentifier, Value, BuffData, TupleData, SequenceData, TypeSignature};

use chainstate::stacks::boot::boot_code_id;
use chainstate::stacks::db::StacksChainState;
use chainstate::stacks::events::{STXEventType, STXLockEventData, StacksTransactionEvent};
use chainstate::stacks::db::MINER_REWARD_MATURITY;
use chainstate::stacks::StacksMicroblockHeader;
use vm::clarity::ClarityTransactionConnection;

use util::hash::Hash160;

fn parse_pox_stacking_result(
    result: &Value,
) -> std::result::Result<(PrincipalData, u128, u64), i128> {
    match result.clone().expect_result() {
        Ok(res) => {
            // should have gotten back (ok (tuple (stacker principal) (lock-amount uint) (unlock-burn-height uint)))
            let tuple_data = res.expect_tuple();
            let stacker = tuple_data
                .get("stacker")
                .expect(&format!("FATAL: no 'stacker'"))
                .to_owned()
                .expect_principal();

            let lock_amount = tuple_data
                .get("lock-amount")
                .expect(&format!("FATAL: no 'lock-amount'"))
                .to_owned()
                .expect_u128();

            let unlock_burn_height = tuple_data
                .get("unlock-burn-height")
                .expect(&format!("FATAL: no 'unlock-burn-height'"))
                .to_owned()
                .expect_u128()
                .try_into()
                .expect("FATAL: 'unlock-burn-height' overflow");

            Ok((stacker, lock_amount, unlock_burn_height))
        }
        Err(e) => Err(e.expect_i128()),
    }
}

/// Handle special cases when calling into the PoX API contract
fn handle_pox_api_contract_call(
    global_context: &mut GlobalContext,
    _sender_opt: Option<&PrincipalData>,
    function_name: &str,
    value: &Value,
) -> Result<()> {
    if function_name == "stack-stx" || function_name == "delegate-stack-stx" {
        debug!(
            "Handle special-case contract-call to {:?} {} (which returned {:?})",
            boot_code_id("pox"),
            function_name,
            value
        );

        match parse_pox_stacking_result(value) {
            Ok((stacker, locked_amount, unlock_height)) => {
                // if this fails, then there's a bug in the contract (since it already does
                // the necessary checks)
                match StacksChainState::pox_lock(
                    &mut global_context.database,
                    &stacker,
                    locked_amount,
                    unlock_height as u64,
                ) {
                    Ok(_) => {
                        if let Some(batch) = global_context.event_batches.last_mut() {
                            batch.events.push(StacksTransactionEvent::STXEvent(
                                STXEventType::STXLockEvent(STXLockEventData {
                                    locked_amount,
                                    unlock_height,
                                    locked_address: stacker,
                                }),
                            ));
                        }
                    }
                    Err(e) => {
                        panic!(
                            "FATAL: failed to lock {} from {} until {}: '{:?}'",
                            locked_amount, stacker, unlock_height, &e
                        );
                    }
                }

                return Ok(());
            }
            Err(_) => {
                // nothing to do -- the function failed
                return Ok(());
            }
        }
    }
    // nothing to do
    Ok(())
}

/// Handle special cases of contract-calls -- namely, those into PoX that should lock up STX
pub fn handle_contract_call_special_cases(
    global_context: &mut GlobalContext,
    sender: Option<&PrincipalData>,
    contract_id: &QualifiedContractIdentifier,
    function_name: &str,
    result: &Value,
) -> Result<()> {
    if *contract_id == boot_code_id("pox") {
        return handle_pox_api_contract_call(global_context, sender, function_name, result);
    }
    // TODO: insert more special cases here, as needed
    Ok(())
}


/// Given two microblock headers, were they signed by the same key?
/// Return the pubkey hash if so; return Err otherwise
fn check_microblock_header_signer(mblock_hdr_1: &StacksMicroblockHeader, mblock_hdr_2: &StacksMicroblockHeader) -> Result<Hash160> {
    let pkh1 = mblock_hdr_1.check_recover_pubkey()
        .map_err(|e| InterpreterError::InvalidPoisonMicroblockTransaction(format!("Failed to recover public key: {:?}", &e)))?;

    let pkh2 = mblock_hdr_2.check_recover_pubkey()
        .map_err(|e| InterpreterError::InvalidPoisonMicroblockTransaction(format!("Failed to recover public key: {:?}", &e)))?;

    if pkh1 != pkh2 {
        let msg = format!("Invalid PoisonMicroblock transaction -- signature pubkey hash {} != {}", &pkh1, &pkh2);
        warn!("{}", &msg);
        return Err(InterpreterError::InvalidPoisonMicroblockTransaction(msg).into());
    }
    Ok(pkh1)
}

/// Process a poison-microblock transaction.  This isn't something that can happen from a Clarity
/// program, but it's "special" because it does a non-trivial amount of VM work that needs to be
/// accounted for in the encapsulating Environment.
/// Returns a Value that represents the miner slashed:
/// * contains the block height of the block with the slashed microblock public key hash
/// * contains the microblock public key hash
/// * contains the sender that reported the poison-microblock
/// * contains the sequence number at which the fork occured
pub fn handle_poison_microblock(
    env: &mut Environment,
    mblock_header_1: &StacksMicroblockHeader,
    mblock_header_2: &StacksMicroblockHeader,
) -> Result<Value> {
    
    // encodes MARF reads for loading microblock height and current height, and loading and storing a
    // poison-microblock report
    runtime_cost!(cost_functions::POISON_MICROBLOCK, env, 0)?;

    let sender_principal = match &env.sender {
        Some(ref sender) => {
            let sender_principal = sender.clone().expect_principal();
            if let PrincipalData::Standard(sender_principal) = sender_principal {
                sender_principal
            }
            else {
                panic!("BUG: tried to handle poison microblock without a standard principal sender");
            }
        },
        None => {
            panic!("BUG: tried to handle poison microblock without a sender");
        }
    };

    // is this valid -- were both headers signed by the same key?
    let pubkh = check_microblock_header_signer(mblock_header_1, mblock_header_2)?;

    let microblock_height_opt = env.global_context.database.get_microblock_pubkey_hash_height(&pubkh);
    let current_height = env.global_context.database.get_current_block_height();

    env.add_memory(20)?;      // for the microblock public key hash we had to process
    env.add_memory(4)?;       // for the block height we had to load

    // was the referenced public key hash used anytime in the past
    // MINER_REWARD_MATURITY blocks?
    let mblock_pubk_height = match microblock_height_opt {
        None => {
            // public key has never been seen before
            let msg = format!("Invalid Stacks transaction: microblock public key hash {} never seen in this fork", &pubkh);
            warn!("{}", &msg);

            return Err(InterpreterError::InvalidPoisonMicroblockTransaction(msg).into());
        }
        Some(height) => {
            if height.checked_add(MINER_REWARD_MATURITY as u32).expect("BUG: too many blocks") < current_height {
                let msg = format!("Invalid Stacks transaction: microblock public key hash from height {} has matured relative to current height {}", height, current_height);
                warn!("{}", &msg);

                return Err(InterpreterError::InvalidPoisonMicroblockTransaction(msg).into());
            }
            height
        }
    };

    // add punishment / commission record, if one does not already exist at lower sequence
    let (reporter_principal, reported_seq) = 
        if let Some((reporter, seq)) = env.global_context.database.get_microblock_poison_report(mblock_pubk_height) {
            // account for report loaded
            env.add_memory(TypeSignature::PrincipalType.size() as u64)?;
            env.add_memory(16)?;        // u128 sequence

            if mblock_header_1.sequence < seq {
                // this sender reports a point lower in the stream where a fork occurred, and is now
                // entitled to a commission of the punished miner's coinbase
                debug!("Sender {} reports a better poison-miroblock record (at {}) for key {} at height {} than {} (at {})", &sender_principal, mblock_header_1.sequence, &pubkh, mblock_pubk_height, &reporter, seq);
                env.global_context.database.insert_microblock_poison(mblock_pubk_height, &sender_principal, mblock_header_1.sequence)?;
                (sender_principal.clone(), mblock_header_1.sequence)
            }
            else {
                // someone else beat the sender to this report
                debug!("Sender {} reports an equal or worse poison-microblock record (at {}, but already have one for {}); dropping...", &sender_principal, mblock_header_1.sequence, seq);
                (reporter, seq)
            }
        }
        else {
            // first-ever report of a fork
            debug!("Sender {} reports a poison-microblock record at seq {} for key {} at height {}", &sender_principal, mblock_header_1.sequence, &pubkh, &mblock_pubk_height);
            env.global_context.database.insert_microblock_poison(mblock_pubk_height, &sender_principal, mblock_header_1.sequence)?;
            (sender_principal.clone(), mblock_header_1.sequence)
        };

    let hash_data = BuffData { data: pubkh.as_bytes().to_vec() };
    let tuple_data = TupleData::from_data(
        vec![
            (ClarityName::try_from("block_height").expect("BUG: valid string representation"), Value::UInt(mblock_pubk_height as u128)),
            (ClarityName::try_from("microblock_pubkey_hash").expect("BUG: valid string representation"), Value::Sequence(SequenceData::Buffer(hash_data))),
            (ClarityName::try_from("reporter").expect("BUG: valid string representation"), Value::Principal(PrincipalData::Standard(reporter_principal))),
            (ClarityName::try_from("sequence").expect("BUG: valid string representation"), Value::UInt(reported_seq as u128)),
        ]
    ).expect("BUG: valid tuple representation");

    Ok(Value::Tuple(tuple_data))
}
