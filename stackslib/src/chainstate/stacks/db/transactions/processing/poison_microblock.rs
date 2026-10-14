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

//! Poison-microblock transaction execution.

use clarity::vm::contexts::{ExecutionState, InvocationContext};
use clarity::vm::costs::cost_functions::ClarityCostFunction;
use clarity::vm::costs::{runtime_cost, CostTracker as _};
use clarity::vm::representations::ClarityName;
use clarity::vm::types::{BuffData, PrincipalData, SequenceData, TupleData, TypeSignature, Value};

use crate::chainstate::stacks::db::MINER_REWARD_MATURITY;
use crate::chainstate::stacks::{Error, MicroblockSignerMatch, StacksMicroblockHeader};

/// Processes a poison-microblock transaction within a Clarity environment.
///
/// Returns a value identifying the slashed miner and successful reporter.
pub fn handle(
    env: &mut ExecutionState,
    invoke_ctx: &InvocationContext,
    first_header: &StacksMicroblockHeader,
    second_header: &StacksMicroblockHeader,
) -> Result<Value, Error> {
    let cost_before = env.global_context.cost_track.get_total();

    // encodes MARF reads for loading microblock height and current height, and loading and storing a
    // poison-microblock report
    runtime_cost(ClarityCostFunction::PoisonMicroblock, env, 0)
        .map_err(|e| Error::from_cost_error(e, cost_before.clone(), env.global_context))?;

    let sender_principal = match &invoke_ctx.sender {
        Some(ref sender) => {
            if let PrincipalData::Standard(sender) = sender.clone() {
                sender
            } else {
                panic!(
                    "BUG: tried to handle poison microblock without a standard principal sender"
                );
            }
        }
        None => {
            panic!("BUG: tried to handle poison microblock without a sender");
        }
    };

    let pubkh = match first_header.recover_signer_match(second_header) {
        Err(e) => {
            return Err(Error::InvalidStacksTransaction(
                format!("Failed to recover public key: {e:?}"),
                false,
            ));
        }
        Ok(MicroblockSignerMatch::Common(signer)) => signer,
        Ok(MicroblockSignerMatch::Different { first, second }) => {
            let msg = format!(
                "Invalid PoisonMicroblock transaction -- signature pubkey hash {first} != {second}"
            );
            warn!("{msg}");
            return Err(Error::InvalidStacksTransaction(msg, false));
        }
    };

    let microblock_height_opt = env
        .global_context
        .database
        .get_microblock_pubkey_hash_height(&pubkh)?;
    let current_height = env.global_context.database.get_current_block_height();

    // for the microblock public key hash we had to process
    env.add_memory(20)
        .map_err(|e| Error::from_cost_error(e, cost_before.clone(), env.global_context))?;

    // for the block height we had to load
    env.add_memory(4)
        .map_err(|e| Error::from_cost_error(e, cost_before.clone(), env.global_context))?;

    // was the referenced public key hash used anytime in the past
    // MINER_REWARD_MATURITY blocks?
    let mblock_pubk_height = match microblock_height_opt {
        None => {
            // public key has never been seen before
            let msg = format!(
                "Invalid Stacks transaction: microblock public key hash {} never seen in this fork",
                &pubkh
            );
            warn!("{}", &msg;
                  "microblock_pubkey_hash" => %pubkh
            );

            return Err(Error::InvalidStacksTransaction(msg, false));
        }
        Some(height) => {
            if height
                .checked_add(u32::try_from(MINER_REWARD_MATURITY).expect("FATAL: maturity > 2^32"))
                .expect("BUG: too many blocks")
                < current_height
            {
                let msg = format!(
                    "Invalid Stacks transaction: microblock public key hash from height {} has matured relative to current height {}",
                    height, current_height
                );
                warn!("{}", &msg;
                      "microblock_pubkey_hash" => %pubkh
                );

                return Err(Error::InvalidStacksTransaction(msg, false));
            }
            height
        }
    };

    // add punishment / commission record, if one does not already exist at lower sequence
    let (reporter_principal, reported_seq) = if let Some((reporter, seq)) = env
        .global_context
        .database
        .get_microblock_poison_report(mblock_pubk_height)?
    {
        // account for report loaded
        env.add_memory(u64::from(TypeSignature::PrincipalType.size().map_err(
            |_| Error::Expects("Failed to get size of PrincipalType".into()),
        )?))
        .map_err(|e| Error::from_cost_error(e, cost_before.clone(), env.global_context))?;

        // u128 sequence
        env.add_memory(16)
            .map_err(|e| Error::from_cost_error(e, cost_before.clone(), env.global_context))?;

        if first_header.sequence < seq {
            // this sender reports a point lower in the stream where a fork occurred, and is now
            // entitled to a commission of the punished miner's coinbase
            debug!("Sender {} reports a better poison-miroblock record (at {}) for key {} at height {} than {} (at {})", &sender_principal, first_header.sequence, &pubkh, mblock_pubk_height, &reporter, seq;
                "sender" => %sender_principal,
                "microblock_pubkey_hash" => %pubkh
            );
            env.global_context.database.insert_microblock_poison(
                mblock_pubk_height,
                &sender_principal,
                first_header.sequence,
            )?;
            (sender_principal, first_header.sequence)
        } else {
            // someone else beat the sender to this report
            debug!("Sender {} reports an equal or worse poison-microblock record (at {}, but already have one for {}); dropping...", &sender_principal, first_header.sequence, seq;
                "sender" => %sender_principal,
                "microblock_pubkey_hash" => %pubkh
            );
            (reporter, seq)
        }
    } else {
        // first-ever report of a fork
        debug!(
            "Sender {} reports a poison-microblock record at seq {} for key {} at height {}",
            &sender_principal, first_header.sequence, &pubkh, &mblock_pubk_height;
            "sender" => %sender_principal,
            "microblock_pubkey_hash" => %pubkh
        );
        env.global_context.database.insert_microblock_poison(
            mblock_pubk_height,
            &sender_principal,
            first_header.sequence,
        )?;
        (sender_principal, first_header.sequence)
    };

    let hash_data = BuffData {
        data: pubkh.as_bytes().to_vec(),
    };
    let tuple_data = TupleData::from_data(vec![
        (
            ClarityName::try_from("block_height").expect("BUG: valid string representation"),
            Value::UInt(u128::from(mblock_pubk_height)),
        ),
        (
            ClarityName::try_from("microblock_pubkey_hash")
                .expect("BUG: valid string representation"),
            Value::Sequence(SequenceData::Buffer(hash_data)),
        ),
        (
            ClarityName::try_from("reporter").expect("BUG: valid string representation"),
            Value::Principal(PrincipalData::Standard(reporter_principal)),
        ),
        (
            ClarityName::try_from("sequence").expect("BUG: valid string representation"),
            Value::UInt(u128::from(reported_seq)),
        ),
    ])
    .expect("BUG: valid tuple representation");

    Ok(Value::Tuple(tuple_data))
}
