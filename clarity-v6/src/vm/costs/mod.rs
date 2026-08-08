// Copyright (C) 2013-2020 Blockstack PBC, a public benefit corporation
// Copyright (C) 2020-2026 Stacks Open Internet Foundation
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

use std::collections::HashMap;
use std::fmt;

use clarity_kernel::costs::costs_5::Costs5;
// The pure cost layer (cost functions, execution-cost arithmetic, the
// `CostTracker` interface) lives in `clarity-kernel`; it is re-exported here
// so all pre-existing `crate::vm::costs::...` paths keep working.
pub use clarity_kernel::costs::{
    CLARITY_MEMORY_LIMIT, CostTracker, CostTrackerHandle, CostTrackerMetrics, MemoryConsumer,
    analysis_typecheck_cost, constants, cost_functions, costs_1, costs_2, costs_2_testnet, costs_3,
    costs_4, costs_5, errors, execution_cost, runtime_cost,
};

use super::errors::{RuntimeCheckErrorKind, RuntimeError};
use crate::boot_util::boot_code_id;
use crate::vm::ClarityName;
use crate::vm::costs::cost_functions::ClarityCostFunction;
pub use crate::vm::costs::errors::CostErrors;
pub use crate::vm::costs::execution_cost::{CostOverflowingMath, ExecutionCost};
use crate::vm::errors::VmExecutionError;
use crate::vm::types::QualifiedContractIdentifier;

// TODO: factor out into a boot lib?
pub const COSTS_5_NAME: &str = "costs-5";

macro_rules! finally_drop_memory {
    ( $gc: expr, $used_mem:expr; $exec:expr ) => {{
        let result = (|| $exec)();
        $gc.drop_memory($used_mem)?;
        result
    }};
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct ClarityCostFunctionReference {
    contract_id: QualifiedContractIdentifier,
    function_name: String,
}

impl ::std::fmt::Display for ClarityCostFunctionReference {
    fn fmt(&self, f: &mut ::std::fmt::Formatter<'_>) -> ::std::fmt::Result {
        write!(f, "{}.{}", &self.contract_id, &self.function_name)
    }
}

impl ClarityCostFunctionReference {
    fn evaluate(
        &self,
        f: &ClarityCostFunction,
        input: &[u64],
    ) -> Result<ExecutionCost, CostErrors> {
        let n = input.first().ok_or_else(|| {
            CostErrors::Expect("Default cost function supplied with 0 args".into())
        })?;
        let r = f.eval::<Costs5>(*n);
        // Convert the kernel's cost-function error back into the exact
        // legacy error values, so the mapping below (and the resulting
        // error strings) are unchanged.
        let r = r.map_err(VmExecutionError::from);
        r.map_err(|e| {
            let e = match e {
                VmExecutionError::Runtime(RuntimeError::NotImplemented, _) => {
                    RuntimeCheckErrorKind::UndefinedFunction(self.function_name.clone()).into()
                }
                other => other,
            };

            CostErrors::CostComputationFailed(format!(
                "Error evaluating result of cost function {self}: {e}",
            ))
        })
    }
}

#[derive(Clone)]
/// This struct holds all of the data required for non-free LimitedCostTracker instances
pub struct TrackerData {
    cost_function_references: HashMap<&'static ClarityCostFunction, ClarityCostFunctionReference>,
    total: ExecutionCost,
    limit: ExecutionCost,
    memory: u64,
    memory_limit: u64,
}

#[derive(Clone)]
#[allow(clippy::large_enum_variant)]
pub enum LimitedCostTracker {
    Limited(TrackerData),
    Free,
}

impl fmt::Debug for LimitedCostTracker {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Free => f.debug_struct("LimitedCostTracker::Free").finish(),
            Self::Limited(TrackerData {
                total,
                limit,
                memory,
                memory_limit,
                ..
            }) => f
                .debug_struct("LimitedCostTracker")
                .field("total", total)
                .field("limit", limit)
                .field("memory", memory)
                .field("memory_limit", memory_limit)
                .finish(),
        }
    }
}

impl PartialEq for LimitedCostTracker {
    fn eq(&self, other: &Self) -> bool {
        match (self, other) {
            (Self::Free, Self::Free) => true,
            (Self::Limited(self_data), Self::Limited(other_data)) => {
                self_data.total == other_data.total
                    && other_data.limit == self_data.limit
                    && self_data.memory == other_data.memory
                    && self_data.memory_limit == other_data.memory_limit
            }
            (_, _) => false,
        }
    }
}

impl LimitedCostTracker {
    pub fn new(mainnet: bool, limit: ExecutionCost) -> LimitedCostTracker {
        Self::limited(mainnet, limit)
    }

    #[cfg(any(test, feature = "testing"))]
    pub fn new_max_limit(use_mainnet: bool) -> LimitedCostTracker {
        LimitedCostTracker::new(use_mainnet, ExecutionCost::max_value())
    }

    pub fn new_free() -> LimitedCostTracker {
        Self::Free
    }

    /// Create a Costs-5 tracker without a database for parser tests.
    #[cfg(any(test, feature = "testing"))]
    pub fn new_with_limit(limit: ExecutionCost) -> LimitedCostTracker {
        Self::limited(false, limit)
    }

    fn limited(mainnet: bool, limit: ExecutionCost) -> LimitedCostTracker {
        let boot_costs_id = boot_code_id(COSTS_5_NAME, mainnet);
        let mut cost_functions = HashMap::new();
        for each in ClarityCostFunction::ALL {
            cost_functions.insert(
                each,
                ClarityCostFunctionReference {
                    contract_id: boot_costs_id.clone(),
                    function_name: each.get_name(),
                },
            );
        }

        Self::Limited(TrackerData {
            cost_function_references: cost_functions,
            limit,
            memory_limit: CLARITY_MEMORY_LIMIT,
            total: ExecutionCost::ZERO,
            memory: 0,
        })
    }
}

impl LimitedCostTracker {
    pub fn get_total(&self) -> ExecutionCost {
        match self {
            Self::Limited(TrackerData { total, .. }) => total.clone(),
            Self::Free => ExecutionCost::ZERO,
        }
    }
    #[allow(clippy::panic)]
    pub fn set_total(&mut self, total: ExecutionCost) {
        // used by the miner to "undo" the cost of a transaction when trying to pack a block.
        match self {
            Self::Limited(data) => data.total = total,
            Self::Free => panic!("Cannot set total on free tracker"),
        }
    }
    pub fn get_limit(&self) -> ExecutionCost {
        match self {
            Self::Limited(TrackerData { limit, .. }) => limit.clone(),
            Self::Free => ExecutionCost::max_value(),
        }
    }

    pub fn get_memory(&self) -> u64 {
        match self {
            Self::Limited(TrackerData { memory, .. }) => *memory,
            Self::Free => 0,
        }
    }
    pub fn get_memory_limit(&self) -> u64 {
        match self {
            Self::Limited(TrackerData { memory_limit, .. }) => *memory_limit,
            Self::Free => u64::MAX,
        }
    }
}

fn add_cost(s: &mut TrackerData, cost: ExecutionCost) -> Result<(), CostErrors> {
    s.total.add(&cost)?;
    if cfg!(feature = "disable-costs") {
        // Disable check for exceeding the cost limit to allow mining large blocks for profiling purposes.
        return Ok(());
    }
    if s.total.exceeds(&s.limit) {
        Err(CostErrors::CostBalanceExceeded(
            s.total.clone(),
            s.limit.clone(),
        ))
    } else {
        Ok(())
    }
}

fn add_memory(s: &mut TrackerData, memory: u64) -> Result<(), CostErrors> {
    s.memory = s.memory.cost_overflow_add(memory)?;
    if s.memory > s.memory_limit {
        Err(CostErrors::MemoryBalanceExceeded(s.memory, s.memory_limit))
    } else {
        Ok(())
    }
}

fn drop_memory(s: &mut TrackerData, memory: u64) -> Result<(), CostErrors> {
    s.memory = s
        .memory
        .checked_sub(memory)
        .ok_or_else(|| CostErrors::Expect("Underflowed dropped memory".into()))?;
    Ok(())
}

impl CostTracker for LimitedCostTracker {
    fn compute_cost(
        &mut self,
        cost_function: ClarityCostFunction,
        input: &[u64],
    ) -> Result<ExecutionCost, CostErrors> {
        match self {
            Self::Free => {
                // tracker is free, return zero!
                Ok(ExecutionCost::ZERO)
            }
            Self::Limited(data) => {
                if cost_function == ClarityCostFunction::Unimplemented {
                    return Err(CostErrors::Expect(
                        "Used unimplemented cost function".into(),
                    ));
                }
                let cost_function_ref = data.cost_function_references.get(&cost_function).ok_or(
                    CostErrors::CostComputationFailed(format!(
                        "CostFunction not defined: {cost_function}"
                    )),
                )?;

                cost_function_ref.evaluate(&cost_function, input)
            }
        }
    }
    fn add_cost(&mut self, cost: ExecutionCost) -> Result<(), CostErrors> {
        match self {
            Self::Free => Ok(()),
            Self::Limited(data) => add_cost(data, cost),
        }
    }
    fn add_memory(&mut self, memory: u64) -> Result<(), CostErrors> {
        match self {
            Self::Free => Ok(()),
            Self::Limited(data) => add_memory(data, memory),
        }
    }
    fn drop_memory(&mut self, memory: u64) -> Result<(), CostErrors> {
        match self {
            Self::Free => Ok(()),
            Self::Limited(data) => drop_memory(data, memory),
        }
    }
    fn reset_memory(&mut self) {
        match self {
            Self::Free => {}
            Self::Limited(data) => {
                data.memory = 0;
            }
        }
    }
    fn short_circuit_contract_call(
        &mut self,
        _contract: &QualifiedContractIdentifier,
        _function: &ClarityName,
        _input: &[u64],
    ) -> Result<bool, CostErrors> {
        // Cost voting is retired in Clarity 6, so contract calls never have
        // host-voted replacement cost functions.
        Ok(false)
    }
}

impl CostTrackerMetrics for LimitedCostTracker {
    fn get_total(&self) -> ExecutionCost {
        LimitedCostTracker::get_total(self)
    }

    fn get_limit(&self) -> ExecutionCost {
        LimitedCostTracker::get_limit(self)
    }

    fn get_memory(&self) -> u64 {
        LimitedCostTracker::get_memory(self)
    }

    fn get_memory_limit(&self) -> u64 {
        LimitedCostTracker::get_memory_limit(self)
    }
}

impl CostTracker for &mut LimitedCostTracker {
    fn compute_cost(
        &mut self,
        cost_function: ClarityCostFunction,
        input: &[u64],
    ) -> Result<ExecutionCost, CostErrors> {
        LimitedCostTracker::compute_cost(self, cost_function, input)
    }
    fn add_cost(&mut self, cost: ExecutionCost) -> Result<(), CostErrors> {
        LimitedCostTracker::add_cost(self, cost)
    }
    fn add_memory(&mut self, memory: u64) -> Result<(), CostErrors> {
        LimitedCostTracker::add_memory(self, memory)
    }
    fn drop_memory(&mut self, memory: u64) -> Result<(), CostErrors> {
        LimitedCostTracker::drop_memory(self, memory)
    }
    fn reset_memory(&mut self) {
        LimitedCostTracker::reset_memory(self)
    }
    fn short_circuit_contract_call(
        &mut self,
        contract: &QualifiedContractIdentifier,
        function: &ClarityName,
        input: &[u64],
    ) -> Result<bool, CostErrors> {
        LimitedCostTracker::short_circuit_contract_call(self, contract, function, input)
    }
}

// ONLY WORKS IF INPUT IS u64
fn int_log2(input: u64) -> Option<u64> {
    63_u32.checked_sub(input.leading_zeros()).map(|floor_log| {
        if input.trailing_zeros() == floor_log {
            u64::from(floor_log)
        } else {
            u64::from(floor_log + 1)
        }
    })
}

#[cfg(all(test, any()))]
mod unit_tests {
    use super::*;

    #[test]
    fn test_simple_overflows() {
        assert_eq!(u64::MAX.cost_overflow_add(1), Err(CostErrors::CostOverflow));
        assert_eq!(u64::MAX.cost_overflow_mul(2), Err(CostErrors::CostOverflow));
    }

    #[test]
    fn test_simple_sub() {
        assert_eq!(0u64.cost_overflow_sub(1), Err(CostErrors::CostOverflow));
    }

    #[test]
    fn test_simple_log2s() {
        let inputs = [
            1,
            2,
            4,
            8,
            16,
            31,
            32,
            33,
            39,
            64,
            128,
            2_u64.pow(63),
            u64::MAX,
        ];
        let expected = [0, 1, 2, 3, 4, 5, 5, 6, 6, 6, 7, 63, 64];
        for (input, expected) in inputs.iter().zip(expected.iter()) {
            assert_eq!(int_log2(*input).unwrap(), *expected);
        }
    }
}
