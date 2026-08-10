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

//! Engine-neutral transaction framing shared by nested Clarity calls.
//!
//! The database owns the rollback log itself. This module owns the parallel
//! in-memory frame stacks that must advance and unwind with it: asset
//! movements, events, read-only status, and function-call identity.

use std::collections::HashSet;

use clarity_types::types::FunctionIdentifier;
use stacks_common::types::StacksEpochId;

use crate::assets::AssetMap;
use crate::errors::{StackTrace, VmExecutionError, VmInternalError};
use crate::events::StacksTransactionEvent;

pub const MAX_EVENTS_BATCH: u64 = 50 * 1024 * 1024;

#[derive(Debug, Clone, Default)]
pub struct EventBatch {
    pub events: Vec<StacksTransactionEvent>,
}

impl EventBatch {
    pub fn new() -> Self {
        Self::default()
    }
}

/// The in-memory half of the shared transaction's rollback frame.
#[derive(Default)]
pub struct TransactionFrame {
    asset_maps: Vec<AssetMap>,
    event_batches: Vec<(EventBatch, u64)>,
    read_only: Vec<bool>,
}

impl TransactionFrame {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn is_top_level(&self) -> bool {
        self.asset_maps.is_empty()
    }

    pub fn depth(&self) -> usize {
        self.asset_maps.len()
    }

    pub fn is_read_only(&self) -> bool {
        self.read_only.last().copied().unwrap_or(false)
    }

    pub fn begin(&mut self) {
        let read_only = self.is_read_only();
        self.begin_with_read_only(read_only);
    }

    pub fn begin_read_only(&mut self) {
        self.begin_with_read_only(true);
    }

    fn begin_with_read_only(&mut self, read_only: bool) {
        self.asset_maps.push(AssetMap::new());
        let total_size = self
            .event_batches
            .last()
            .map(|(_, total_size)| *total_size)
            .unwrap_or(0);
        self.event_batches.push((EventBatch::new(), total_size));
        self.read_only.push(read_only);
    }

    pub fn current_asset_map(&mut self) -> Result<&mut AssetMap, VmExecutionError> {
        self.asset_maps
            .last_mut()
            .ok_or_else(|| VmInternalError::Expect("Failed to obtain asset map".into()).into())
    }

    pub fn current_asset_map_readonly(&self) -> Result<&AssetMap, VmExecutionError> {
        self.asset_maps
            .last()
            .ok_or_else(|| VmInternalError::Expect("Failed to obtain asset map".into()).into())
    }

    pub fn current_event_batch(&self) -> Option<&(EventBatch, u64)> {
        self.event_batches.last()
    }

    pub fn current_event_batch_mut(&mut self) -> Option<&mut (EventBatch, u64)> {
        self.event_batches.last_mut()
    }

    pub fn push_event(
        &mut self,
        event: StacksTransactionEvent,
        size: u64,
    ) -> Result<(), VmExecutionError> {
        if let Some((batch, total_size)) = self.event_batches.last_mut() {
            batch.events.push(event);
            *total_size = total_size.saturating_add(size);
            if *total_size >= MAX_EVENTS_BATCH {
                return Err(VmInternalError::Expect(
                    "Event batch grew too large during execution".into(),
                )
                .into());
            }
        }
        Ok(())
    }

    /// Merge the current in-memory frame into its parent. The database layer
    /// must commit its matching savepoint only after this succeeds.
    pub fn commit(
        &mut self,
        epoch: StacksEpochId,
    ) -> Result<(Option<AssetMap>, Option<EventBatch>), VmExecutionError> {
        self.read_only.pop();
        let asset_map = self.asset_maps.pop().ok_or_else(|| {
            VmInternalError::Expect("ERROR: Committed non-nested context.".into())
        })?;
        let (mut event_batch, new_total_size) = self.event_batches.pop().ok_or_else(|| {
            VmInternalError::Expect("ERROR: Committed non-nested context.".into())
        })?;

        let out_map = match self.asset_maps.last_mut() {
            Some(parent) => {
                parent.commit_other(asset_map, epoch)?;
                None
            }
            None => Some(asset_map),
        };

        let out_batch = match self.event_batches.last_mut() {
            Some((parent, total_size)) => {
                parent.events.append(&mut event_batch.events);
                *total_size = new_total_size;
                None
            }
            None => Some(event_batch),
        };

        Ok((out_map, out_batch))
    }

    /// Discard the current in-memory frame. The database layer rolls back its
    /// matching savepoint after this succeeds.
    pub fn roll_back(&mut self) -> Result<(), VmExecutionError> {
        if self.asset_maps.pop().is_none() {
            return Err(VmInternalError::Expect("Expected entry to rollback".into()).into());
        }
        if self.read_only.pop().is_none() {
            return Err(VmInternalError::Expect("Expected entry to rollback".into()).into());
        }
        if self.event_batches.pop().is_none() {
            return Err(VmInternalError::Expect("Expected entry to rollback".into()).into());
        }
        Ok(())
    }
}

/// Function and expression depth shared across engine call boundaries.
pub struct CallStack {
    stack: Vec<FunctionIdentifier>,
    set: HashSet<FunctionIdentifier>,
    apply_depth: u64,
}

impl Default for CallStack {
    fn default() -> Self {
        Self::new()
    }
}

impl CallStack {
    pub fn new() -> Self {
        Self {
            stack: Vec::new(),
            set: HashSet::new(),
            apply_depth: 0,
        }
    }

    pub fn depth(&self) -> u64 {
        let stack_len = u64::try_from(self.stack.len()).unwrap_or(u64::MAX);
        stack_len.saturating_add(self.apply_depth)
    }

    pub fn contains(&self, function: &FunctionIdentifier) -> bool {
        self.set.contains(function)
    }

    pub fn insert(&mut self, function: &FunctionIdentifier, track: bool) {
        self.stack.push(function.clone());
        if track {
            self.set.insert(function.clone());
        }
    }

    pub fn incr_apply_depth(&mut self) {
        self.apply_depth += 1;
    }

    pub fn decr_apply_depth(&mut self) {
        self.apply_depth -= 1;
    }

    pub fn remove(
        &mut self,
        function: &FunctionIdentifier,
        tracked: bool,
    ) -> Result<(), VmExecutionError> {
        if let Some(removed) = self.stack.pop() {
            if removed != *function {
                return Err(VmInternalError::InvariantViolation(
                    "Tried to remove item from empty call stack.".into(),
                )
                .into());
            }
            if tracked && !self.set.remove(function) {
                return Err(VmInternalError::InvariantViolation(
                    "Tried to remove tracked function from call stack, but could not find in current context.".into()
                )
                .into());
            }
            Ok(())
        } else {
            Err(VmInternalError::InvariantViolation(
                "Tried to remove item from empty call stack.".into(),
            )
            .into())
        }
    }

    #[cfg(feature = "developer-mode")]
    pub fn make_stack_trace(&self) -> StackTrace {
        self.stack.clone()
    }

    #[cfg(not(feature = "developer-mode"))]
    pub fn make_stack_trace(&self) -> StackTrace {
        Vec::new()
    }
}

#[cfg(test)]
mod tests {
    use clarity_types::types::{FunctionIdentifier, QualifiedContractIdentifier};

    use super::*;

    fn function(name: &str) -> FunctionIdentifier {
        FunctionIdentifier::new_user_function(name, "frame-test")
    }

    #[test]
    fn nested_frames_inherit_read_only_and_merge_events() {
        let mut frame = TransactionFrame::new();
        frame.begin_read_only();
        frame.begin();
        assert!(frame.is_read_only());

        frame
            .push_event(
                StacksTransactionEvent::SmartContractEvent(crate::events::SmartContractEventData {
                    key: (QualifiedContractIdentifier::transient(), "event".into()),
                    value: clarity_types::Value::UInt(1),
                }),
                1,
            )
            .unwrap();

        let (assets, events) = frame.commit(StacksEpochId::latest()).unwrap();
        assert!(assets.is_none());
        assert!(events.is_none());
        assert_eq!(frame.current_event_batch().unwrap().0.events.len(), 1);

        frame.roll_back().unwrap();
        assert!(frame.is_top_level());
    }

    #[test]
    fn call_stack_preserves_reentrancy_and_depth_state() {
        let mut stack = CallStack::new();
        let function = function("run");
        stack.insert(&function, true);
        stack.incr_apply_depth();

        assert!(stack.contains(&function));
        assert_eq!(stack.depth(), 2);

        stack.decr_apply_depth();
        stack.remove(&function, true).unwrap();
        assert_eq!(stack.depth(), 0);
        assert!(!stack.contains(&function));
    }
}
