// Copyright (C) 2025 Stacks Open Internet Foundation
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
use std::fmt;

use crate::execution_cost::ExecutionCost;

/// Errors related to cost tracking and resource accounting in the Clarity VM.
///
/// Each error variant is annotated with "Invalidates Block" status, indicating
/// whether the inclusion of the transaction that caused the error should cause
/// an entire block to be rejected.
#[derive(Debug, PartialEq, Eq)]
pub enum CostErrors {
    /// Arithmetic overflow in cost computation during type-checking, exceeding the maximum threshold.
    /// Invalidates Block: true.
    CostOverflow,
    /// Cumulative type-checking cost exceeds the allocated budget, indicating budget depletion.
    /// The first `ExecutionCost` represents the total consumed cost, and the second represents the budget limit.
    /// Invalidates Block: true.
    CostBalanceExceeded(ExecutionCost, ExecutionCost),
    /// Memory usage during type-checking exceeds the allocated budget.
    /// The first `u64` represents the total consumed memory, and the second represents the memory limit.
    /// Invalidates Block:
    ///  - true if happens during contract analysis
    ///  - false if happens during contract intitialization or contract call.
    MemoryBalanceExceeded(u64, u64),
    /// Failure to access or load cost-related contracts or their state during runtime operations.
    /// Invalidates Block: false.
    CostContractLoadFailure,
    /// Failure in cost-tracking due to an unexpected condition or invalid state.
    /// The `String` wraps the specific reason for the failure.
    /// Invalidates Block: false.
    CostComputationFailed(String),
    // Time checker errors
    /// Type-checking time exceeds the allowed budget, halting analysis to ensure responsiveness.
    /// Invalidates Block: true.
    ExecutionTimeExpired,
    /// Unexpected condition or failure, indicating a bug or invalid state.
    /// Invalidates Block: true.
    InterpreterFailure,
    /// Unexpected condition or failure, indicating a bug or invalid state.
    /// Invalidates Block: true.
    Expect(String),
}

impl fmt::Display for CostErrors {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match self {
            CostErrors::CostComputationFailed(s) => write!(f, "Cost computation failed: {s}"),
            CostErrors::CostOverflow => write!(f, "Cost overflow"),
            CostErrors::CostBalanceExceeded(total, limit) => {
                write!(f, "Cost balance exceeded: total {total}, limit {limit}")
            }
            CostErrors::MemoryBalanceExceeded(used, limit) => {
                write!(f, "Memory balance exceeded: used {used}, limit {limit}")
            }
            CostErrors::CostContractLoadFailure => write!(f, "Failed to load cost contract"),
            CostErrors::InterpreterFailure => write!(f, "Interpreter failure"),
            CostErrors::Expect(s) => write!(f, "Expectation failed: {s}"),
            CostErrors::ExecutionTimeExpired => write!(f, "Execution time expired"),
        }
    }
}

impl CostErrors {
    pub fn rejectable(&self) -> bool {
        matches!(self, CostErrors::InterpreterFailure | CostErrors::Expect(_))
    }
}
