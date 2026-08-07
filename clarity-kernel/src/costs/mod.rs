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
