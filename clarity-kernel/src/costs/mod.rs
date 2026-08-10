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

//! Execution-cost accounting shared by every Clarity engine: the
//! [`CostTracker`] interface, [`ExecutionCost`] arithmetic, and the pure
//! cost functions for each cost-contract version.
//!
//! The interpreter-coupled cost tracker (`LimitedCostTracker`, which
//! evaluates user-defined cost contracts) lives with the VM, not here.

use std::any::Any;
use std::cmp;

use clarity_types::types::{QualifiedContractIdentifier, TypeSignature};
use clarity_types::{ClarityName, Value};

pub mod constants;
pub mod cost_functions;
#[allow(unused_variables)]
pub mod costs_1;
#[allow(unused_variables)]
pub mod costs_2;
#[allow(unused_variables)]
pub mod costs_2_testnet;
#[allow(unused_variables)]
pub mod costs_3;
#[allow(unused_variables)]
pub mod costs_4;
pub mod costs_5;
pub mod errors;
pub mod execution_cost;

pub use crate::costs::cost_functions::ClarityCostFunction;
pub use crate::costs::errors::{CostErrors, CostFunctionError};
pub use crate::costs::execution_cost::{CostOverflowingMath, ExecutionCost};

pub const CLARITY_MEMORY_LIMIT: u64 = 100 * 1000 * 1000;

pub fn runtime_cost<T: TryInto<u64>, C: CostTracker>(
    cost_function: ClarityCostFunction,
    tracker: &mut C,
    input: T,
) -> Result<(), CostErrors> {
    let size: u64 = input.try_into().map_err(|_| CostErrors::CostOverflow)?;
    let cost = tracker.compute_cost(cost_function, &[size])?;

    tracker.add_cost(cost)
}

pub fn analysis_typecheck_cost<T: CostTracker>(
    track: &mut T,
    t1: &TypeSignature,
    t2: &TypeSignature,
) -> Result<(), CostErrors> {
    let t1_size = t1.type_size().map_err(|_| CostErrors::CostOverflow)?;
    let t2_size = t2.type_size().map_err(|_| CostErrors::CostOverflow)?;
    let cost = track.compute_cost(
        ClarityCostFunction::AnalysisTypeCheck,
        &[cmp::max(t1_size, t2_size) as u64],
    )?;
    track.add_cost(cost)
}

pub trait MemoryConsumer {
    fn get_memory_use(&self) -> Result<u64, CostErrors>;
}

impl MemoryConsumer for Value {
    fn get_memory_use(&self) -> Result<u64, CostErrors> {
        Ok(self
            .size()
            .map_err(|_| CostErrors::InterpreterFailure)?
            .into())
    }
}

pub trait CostTracker {
    fn compute_cost(
        &mut self,
        cost_function: ClarityCostFunction,
        input: &[u64],
    ) -> Result<ExecutionCost, CostErrors>;
    fn add_cost(&mut self, cost: ExecutionCost) -> Result<(), CostErrors>;
    fn add_memory(&mut self, memory: u64) -> Result<(), CostErrors>;
    fn drop_memory(&mut self, memory: u64) -> Result<(), CostErrors>;
    fn reset_memory(&mut self);
    /// Check if the given contract-call should be short-circuited.
    ///  If so: this charges the cost to the CostTracker, and return true
    ///  If not: return false
    fn short_circuit_contract_call(
        &mut self,
        contract: &QualifiedContractIdentifier,
        function: &ClarityName,
        input: &[u64],
    ) -> Result<bool, CostErrors>;
}

/// Observable cumulative state required of a transaction-wide cost tracker.
pub trait CostTrackerMetrics {
    /// Cumulative execution cost charged by this tracker.
    fn get_total(&self) -> ExecutionCost;

    /// Maximum execution cost accepted by this tracker.
    fn get_limit(&self) -> ExecutionCost;

    /// Memory currently charged to this tracker.
    fn get_memory(&self) -> u64;

    /// Maximum memory accepted by this tracker.
    fn get_memory_limit(&self) -> u64;
}

/// Type-erased, kernel-owned access to one transaction's cumulative cost
/// tracker.
///
/// Cost schedules may remain engine- or host-specific (the legacy tracker,
/// for example, can contain interpreted historical cost contracts), but the
/// handle itself is shared transaction state. Moving this handle between
/// engines preserves one cumulative budget without making the kernel depend
/// on a concrete engine's tracker type.
pub struct CostTrackerHandle {
    inner: Box<dyn ErasedCostTracker>,
}

trait ErasedCostTracker: CostTracker + CostTrackerMetrics {
    fn as_any(&self) -> &dyn Any;
    fn as_any_mut(&mut self) -> &mut dyn Any;
    fn into_any(self: Box<Self>) -> Box<dyn Any>;
}

impl<T> ErasedCostTracker for T
where
    T: CostTracker + CostTrackerMetrics + 'static,
{
    fn as_any(&self) -> &dyn Any {
        self
    }

    fn as_any_mut(&mut self) -> &mut dyn Any {
        self
    }

    fn into_any(self: Box<Self>) -> Box<dyn Any> {
        self
    }
}

impl CostTrackerHandle {
    pub fn new<T>(tracker: T) -> Self
    where
        T: CostTracker + CostTrackerMetrics + 'static,
    {
        Self {
            inner: Box::new(tracker),
        }
    }

    pub fn free() -> Self {
        Self::new(())
    }

    pub fn is<T: 'static>(&self) -> bool {
        self.inner.as_any().is::<T>()
    }

    pub fn downcast_ref<T: 'static>(&self) -> Option<&T> {
        self.inner.as_any().downcast_ref()
    }

    pub fn downcast_mut<T: 'static>(&mut self) -> Option<&mut T> {
        self.inner.as_any_mut().downcast_mut()
    }

    pub fn into_inner<T: 'static>(self) -> Result<Box<T>, Self> {
        if !self.is::<T>() {
            return Err(self);
        }
        Ok(self
            .inner
            .into_any()
            .downcast()
            .expect("cost tracker type changed after successful type check"))
    }

    pub fn get_total(&self) -> ExecutionCost {
        CostTrackerMetrics::get_total(self)
    }

    pub fn get_limit(&self) -> ExecutionCost {
        CostTrackerMetrics::get_limit(self)
    }

    pub fn get_memory(&self) -> u64 {
        CostTrackerMetrics::get_memory(self)
    }

    pub fn get_memory_limit(&self) -> u64 {
        CostTrackerMetrics::get_memory_limit(self)
    }
}

impl std::fmt::Debug for CostTrackerHandle {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("CostTrackerHandle")
            .field("total", &self.get_total())
            .field("limit", &self.get_limit())
            .field("memory", &self.get_memory())
            .field("memory_limit", &self.get_memory_limit())
            .finish()
    }
}

impl CostTracker for CostTrackerHandle {
    fn compute_cost(
        &mut self,
        cost_function: ClarityCostFunction,
        input: &[u64],
    ) -> Result<ExecutionCost, CostErrors> {
        self.inner.compute_cost(cost_function, input)
    }

    fn add_cost(&mut self, cost: ExecutionCost) -> Result<(), CostErrors> {
        self.inner.add_cost(cost)
    }

    fn add_memory(&mut self, memory: u64) -> Result<(), CostErrors> {
        self.inner.add_memory(memory)
    }

    fn drop_memory(&mut self, memory: u64) -> Result<(), CostErrors> {
        self.inner.drop_memory(memory)
    }

    fn reset_memory(&mut self) {
        self.inner.reset_memory()
    }

    fn short_circuit_contract_call(
        &mut self,
        contract: &QualifiedContractIdentifier,
        function: &ClarityName,
        input: &[u64],
    ) -> Result<bool, CostErrors> {
        self.inner
            .short_circuit_contract_call(contract, function, input)
    }
}

impl CostTrackerMetrics for CostTrackerHandle {
    fn get_total(&self) -> ExecutionCost {
        self.inner.get_total()
    }

    fn get_limit(&self) -> ExecutionCost {
        self.inner.get_limit()
    }

    fn get_memory(&self) -> u64 {
        self.inner.get_memory()
    }

    fn get_memory_limit(&self) -> u64 {
        self.inner.get_memory_limit()
    }
}

// Don't track!
impl CostTracker for () {
    fn compute_cost(
        &mut self,
        _cost_function: ClarityCostFunction,
        _input: &[u64],
    ) -> Result<ExecutionCost, CostErrors> {
        Ok(ExecutionCost::ZERO)
    }
    fn add_cost(&mut self, _cost: ExecutionCost) -> Result<(), CostErrors> {
        Ok(())
    }
    fn add_memory(&mut self, _memory: u64) -> Result<(), CostErrors> {
        Ok(())
    }
    fn drop_memory(&mut self, _memory: u64) -> Result<(), CostErrors> {
        Ok(())
    }
    fn reset_memory(&mut self) {}
    fn short_circuit_contract_call(
        &mut self,
        _contract: &QualifiedContractIdentifier,
        _function: &ClarityName,
        _input: &[u64],
    ) -> Result<bool, CostErrors> {
        Ok(false)
    }
}

impl CostTrackerMetrics for () {
    fn get_total(&self) -> ExecutionCost {
        ExecutionCost::ZERO
    }

    fn get_limit(&self) -> ExecutionCost {
        ExecutionCost::max_value()
    }

    fn get_memory(&self) -> u64 {
        0
    }

    fn get_memory_limit(&self) -> u64 {
        u64::MAX
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    struct TestTracker {
        total: ExecutionCost,
        memory: u64,
    }

    impl Default for TestTracker {
        fn default() -> Self {
            Self {
                total: ExecutionCost::ZERO,
                memory: 0,
            }
        }
    }

    impl CostTracker for TestTracker {
        fn compute_cost(
            &mut self,
            _cost_function: ClarityCostFunction,
            input: &[u64],
        ) -> Result<ExecutionCost, CostErrors> {
            Ok(ExecutionCost {
                runtime: input.iter().copied().sum(),
                ..ExecutionCost::ZERO
            })
        }

        fn add_cost(&mut self, cost: ExecutionCost) -> Result<(), CostErrors> {
            self.total.runtime += cost.runtime;
            Ok(())
        }

        fn add_memory(&mut self, memory: u64) -> Result<(), CostErrors> {
            self.memory += memory;
            Ok(())
        }

        fn drop_memory(&mut self, memory: u64) -> Result<(), CostErrors> {
            self.memory -= memory;
            Ok(())
        }

        fn reset_memory(&mut self) {
            self.memory = 0;
        }

        fn short_circuit_contract_call(
            &mut self,
            _contract: &QualifiedContractIdentifier,
            _function: &ClarityName,
            _input: &[u64],
        ) -> Result<bool, CostErrors> {
            Ok(false)
        }
    }

    impl CostTrackerMetrics for TestTracker {
        fn get_total(&self) -> ExecutionCost {
            self.total.clone()
        }

        fn get_limit(&self) -> ExecutionCost {
            ExecutionCost::max_value()
        }

        fn get_memory(&self) -> u64 {
            self.memory
        }

        fn get_memory_limit(&self) -> u64 {
            u64::MAX
        }
    }

    #[test]
    fn erased_tracker_preserves_meter_and_concrete_state() {
        let mut tracker = CostTrackerHandle::new(TestTracker::default());
        runtime_cost(ClarityCostFunction::Add, &mut tracker, 7_u64).unwrap();
        tracker.add_memory(11).unwrap();

        assert_eq!(tracker.get_total().runtime, 7);
        assert_eq!(tracker.get_memory(), 11);
        assert!(tracker.is::<TestTracker>());
        assert!(!tracker.is::<()>());

        let tracker = tracker.into_inner::<TestTracker>().unwrap();
        assert_eq!(tracker.total.runtime, 7);
        assert_eq!(tracker.memory, 11);
    }
}
