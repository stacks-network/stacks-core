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

//! Which special-case entry point handles which PoX contract.
//!
//! There are two entry points because they need different capabilities.
//! [`handle_contract_call_special_cases`] is typed over a specific engine's
//! `GlobalContext` because PoX 1-4 synthesize print events, which means
//! *evaluating Clarity*. [`handle_kernel_contract_call_special_cases`] is typed
//! over kernel state alone, so any engine can invoke it, which is what `.pox-5`
//! needs: `.pox-5` is a Clarity 6 contract, so the Clarity 6 engine executes it
//! and there is no dispatcher hop into the legacy engine to apply its lock-ups.
//!
//! Getting that split wrong is silent -- the contract call still succeeds, the
//! lock just never happens -- so it is pinned here.

use clarity::boot_util::boot_code_id;
use clarity::consts::CHAIN_ID_TESTNET;
use clarity::vm::contexts::GlobalContext;
use clarity::vm::costs::LimitedCostTracker;
use clarity::vm::database::MemoryBackingStore;
use clarity::vm::errors::{RuntimeError, VmExecutionError};
use clarity::vm::types::{PrincipalData, StandardPrincipalData};
use clarity::vm::Value;
use stacks_common::types::StacksEpochId;

use crate::{
    handle_contract_call_special_cases, handle_kernel_contract_call_special_cases, POX_4_NAME,
    POX_5_NAME,
};

fn global_context_at<'a>(
    store: &'a mut MemoryBackingStore,
    epoch: StacksEpochId,
) -> GlobalContext<'a, 'a> {
    let db = store.as_clarity_db();
    let mut global_context = GlobalContext::new(
        false,
        CHAIN_ID_TESTNET,
        db,
        LimitedCostTracker::new_free(),
        epoch,
    );
    global_context.begin();
    global_context
}

fn sender() -> PrincipalData {
    PrincipalData::Standard(StandardPrincipalData::transient())
}

/// A `.pox-4` state-changing call must be rejected outright from Epoch 4.0 on,
/// where `.pox-5` takes over. `.pox-4` stays on the legacy engine (its language
/// version predates Clarity 6), so the engine-typed entry point is the one that
/// has to raise this.
#[test]
fn pox_4_state_change_is_defunct_in_epoch_40() {
    let mut store = MemoryBackingStore::new();
    let mut global_context = global_context_at(&mut store, StacksEpochId::Epoch40);
    let pox_4 = boot_code_id(POX_4_NAME, false);
    let sender = sender();

    let result = handle_contract_call_special_cases(
        &mut global_context,
        Some(&sender),
        None,
        &pox_4,
        "stack-stx",
        &[],
        &Value::okay(Value::Bool(true)).unwrap(),
    );

    assert!(
        matches!(
            result,
            Err(VmExecutionError::Runtime(
                RuntimeError::DefunctPoxContract,
                _
            ))
        ),
        "pox-4 stack-stx must be defunct in Epoch 4.0, got {result:?}"
    );
}

/// A read-only `.pox-4` call stays callable in Epoch 4.0 -- only state changes
/// are defunct.
#[test]
fn pox_4_read_only_still_allowed_in_epoch_40() {
    let mut store = MemoryBackingStore::new();
    let mut global_context = global_context_at(&mut store, StacksEpochId::Epoch40);
    let pox_4 = boot_code_id(POX_4_NAME, false);
    let sender = sender();

    handle_contract_call_special_cases(
        &mut global_context,
        Some(&sender),
        None,
        &pox_4,
        "get-pox-info",
        &[],
        &Value::okay(Value::Bool(true)).unwrap(),
    )
    .expect("read-only pox-4 calls must remain callable in Epoch 4.0");
}

/// The kernel-typed entry point deliberately handles only `.pox-5`. PoX 1-4 are
/// legacy-engine contracts whose handling needs Clarity evaluation, so they must
/// *not* be silently half-handled here.
#[test]
fn kernel_entry_point_handles_pox_5_only() {
    let mut store = MemoryBackingStore::new();
    let mut global_context = global_context_at(&mut store, StacksEpochId::Epoch40);
    let sender = sender();

    // `.pox-4` through the kernel entry point is a no-op rather than an error:
    // it is not this entry point's contract, and the legacy engine that does
    // execute `.pox-4` raises `DefunctPoxContract` itself.
    let pox_4 = boot_code_id(POX_4_NAME, false);
    handle_kernel_contract_call_special_cases(
        &mut global_context.special_case_context(),
        Some(&sender),
        None,
        &pox_4,
        "stack-stx",
        &[],
        &Value::okay(Value::Bool(true)).unwrap(),
    )
    .expect("kernel entry point must not claim pox-4");

    // `.pox-5` is claimed: an unrecognized function name is accepted (no
    // lock-up side effect), which proves dispatch reached pox-5's handler
    // rather than falling through.
    let pox_5 = boot_code_id(POX_5_NAME, false);
    handle_kernel_contract_call_special_cases(
        &mut global_context.special_case_context(),
        Some(&sender),
        None,
        &pox_5,
        "get-stacker-info",
        &[],
        &Value::okay(Value::Bool(true)).unwrap(),
    )
    .expect("kernel entry point must claim pox-5");
}
