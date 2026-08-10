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

//! Host hooks for special-cased contract calls.
//!
//! Some boot contracts have consensus effects the interpreter cannot express:
//! a PoX contract call returns normally, and then the *host* locks the
//! caller's STX. The host supplies a hook, the backing store hands it to
//! whichever engine is executing the call, and the engine invokes it after the
//! call returns.
//!
//! This hook is typed over kernel state alone — database, cost tracker,
//! transaction frame, and the epoch and network the call runs in — so a single
//! hook serves every engine, present and future. That matters because the
//! contract needing the hook is not necessarily written in the same language
//! version as the engine reached through a dispatcher: `.pox-5` is a Clarity 6
//! contract, so its lock-up is applied by the Clarity 6 engine, not by the
//! legacy engine.
//!
//! An engine that additionally needs to *evaluate* Clarity while handling a
//! special case cannot use this hook, because evaluation requires the engine's
//! own interpreter state. The legacy engine synthesizes print events for PoX 1
//! through 4 that way, so it carries a second, engine-typed hook alongside
//! this one (see `ClarityBackingStore::get_cc_special_cases_handler`).

use clarity_types::Value;
use clarity_types::types::{PrincipalData, QualifiedContractIdentifier};
use stacks_common::types::StacksEpochId;

use crate::assets::AssetMap;
use crate::costs::CostTrackerHandle;
use crate::database::ClarityDatabase;
use crate::errors::VmExecutionError;
use crate::transaction::{EventBatch, TransactionFrame};

/// The kernel state a special-case hook may touch, borrowed from the engine
/// that is executing the call.
pub struct SpecialCaseContext<'a, 'db> {
    pub database: &'a mut ClarityDatabase<'db>,
    pub cost_track: &'a mut CostTrackerHandle,
    pub transaction: &'a mut TransactionFrame,
    /// Epoch of the block this call is executing in.
    pub epoch_id: StacksEpochId,
    pub mainnet: bool,
}

impl SpecialCaseContext<'_, '_> {
    /// The innermost open event batch, if the caller opened one. Hooks append
    /// their events here so they appear after the events the contract itself
    /// emitted.
    pub fn current_event_batch_mut(&mut self) -> Option<&mut (EventBatch, u64)> {
        self.transaction.current_event_batch_mut()
    }

    fn asset_map(&mut self) -> Result<&mut AssetMap, VmExecutionError> {
        self.transaction.current_asset_map()
    }

    /// Record a stacking movement, so transaction post-conditions see the STX
    /// the hook locked.
    pub fn log_stacking(
        &mut self,
        sender: &PrincipalData,
        amount: u128,
    ) -> Result<(), VmExecutionError> {
        let epoch = self.epoch_id;
        self.asset_map()?.add_stacking(sender, amount, epoch)
    }

    /// Record a position-altering PoX action, so post-conditions and
    /// allowances can constrain it.
    pub fn log_pox_action(&mut self, sender: &PrincipalData) -> Result<(), VmExecutionError> {
        self.asset_map()?.add_pox_action(sender);
        Ok(())
    }
}

/// Signature of the kernel-typed special-case hook: the state it may touch,
/// then the identity of the call that just returned and its result.
pub type KernelSpecialCaseHandlerSig = fn(
    &mut SpecialCaseContext,
    // the sender of the transaction
    Option<&PrincipalData>,
    // the sponsor of the transaction, if any
    Option<&PrincipalData>,
    // the invoked contract
    &QualifiedContractIdentifier,
    // the invoked function name
    &str,
    // the function arguments
    &[Value],
    // the value the function returned
    &Value,
) -> Result<(), VmExecutionError>;

/// A host-provided special-case hook.
///
/// Hosts hold one in a `static` and return a reference to it from
/// [`ClarityBackingStore::get_kernel_cc_special_cases_handler`](crate::database::ClarityBackingStore::get_kernel_cc_special_cases_handler).
/// Unlike the engine-typed hook, this needs no downcast: the type is
/// kernel-owned, so every engine names the same one.
pub struct KernelSpecialCaseHandlerFn(pub KernelSpecialCaseHandlerSig);
