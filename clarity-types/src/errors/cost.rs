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

#[derive(Debug, PartialEq, Eq)]
pub enum CostErrors {
    CostComputationFailed(String),
    CostOverflow,
    CostBalanceExceeded(ExecutionCost, ExecutionCost),
    MemoryBalanceExceeded(u64, u64),
    CostContractLoadFailure,
    InterpreterFailure,
    Expect(String),
    ExecutionTimeExpired,
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

impl std::error::Error for CostErrors {}
