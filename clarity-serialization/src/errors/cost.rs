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
