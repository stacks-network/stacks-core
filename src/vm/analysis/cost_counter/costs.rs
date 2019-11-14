use vm::analysis::errors::{CheckResult, CheckError, CheckErrors};

use super::SpecialCostType;

pub enum CostSpecification {
    Simple(SimpleCostSpecification),
    Special(SpecialCostType),
}

#[derive(Debug, Deserialize, Serialize, Clone, PartialEq, Eq)]
pub enum CostFunctions {
    Constant(u64),
    Linear(u64, u64),
    NLogN(u64, u64),
}

#[derive(Debug, Deserialize, Serialize, Clone, PartialEq, Eq)]
pub struct SimpleCostSpecification {
    pub write_count: CostFunctions,
    pub write_length: CostFunctions,
    pub read_count: CostFunctions,
    pub read_length: CostFunctions,
    pub runtime: CostFunctions,
}

#[derive(Debug, Deserialize, Serialize, PartialEq, Eq)]
pub struct ExecutionCost {
    pub write_length: u64,
    pub write_count: u64,
    pub read_length: u64,
    pub read_count: u64,
    pub runtime: u64
}

pub trait CostOverflowingMath <T> {
    fn cost_overflow_mul(self, other: T) -> CheckResult<T>;
    fn cost_overflow_add(self, other: T) -> CheckResult<T>;
}

impl CostOverflowingMath <u64> for u64 {
    fn cost_overflow_mul(self, other: u64) -> CheckResult<u64> {
        self.checked_mul(other)
            .ok_or_else(|| CheckErrors::CostOverflow.into())
    }
    fn cost_overflow_add(self, other: u64) -> CheckResult<u64> {
        self.checked_add(other)
            .ok_or_else(|| CheckErrors::CostOverflow.into())
    }
}

impl ExecutionCost {
    pub fn zero() -> ExecutionCost {
        Self { runtime: 0, write_length: 0, read_count: 0, write_count: 0, read_length: 0 }
    }

    pub fn runtime(runtime: u64) -> ExecutionCost {
        Self { runtime, write_length: 0, read_count: 0, write_count: 0, read_length: 0 }
    }

    pub fn add_runtime(&mut self, runtime: u64) -> CheckResult<()> {
        self.runtime = self.runtime.cost_overflow_add(runtime)?;
        Ok(())
    }

    pub fn add(&mut self, other: &ExecutionCost) -> CheckResult<()> {
        self.runtime = self.runtime.cost_overflow_add(other.runtime)?;
        self.read_count   = self.read_count.cost_overflow_add(other.read_count)?;
        self.read_length  = self.read_length.cost_overflow_add(other.read_length)?;
        self.write_length = self.write_length.cost_overflow_add(other.write_length)?;
        self.write_count  = self.write_count.cost_overflow_add(other.write_count)?;
        Ok(())
    }

    pub fn multiply(&mut self, times: u64) -> CheckResult<()> {
        self.runtime = self.runtime.cost_overflow_mul(times)?;
        self.read_count   = self.read_count.cost_overflow_mul(times)?;
        self.read_length  = self.read_length.cost_overflow_mul(times)?;
        self.write_length = self.write_length.cost_overflow_mul(times)?;
        self.write_count  = self.write_count.cost_overflow_mul(times)?;
        Ok(())
    }

    pub fn max_cost(first: ExecutionCost, second: ExecutionCost) -> ExecutionCost {
        Self {
            runtime: first.runtime.max(second.runtime),
            write_length: first.write_length.max(second.write_length),
            write_count:  first.write_count.max(second.write_count),
            read_count:   first.read_count.max(second.read_count),
            read_length:  first.read_length.max(second.read_length)
        }
    }
}

// ONLY WORKS IF INPUT IS u64
fn int_log2(input: u64) -> Option<u64> {
    63_u32.checked_sub(input.leading_zeros())
        .map(|floor_log| {
            if input.trailing_zeros() == floor_log {
                u64::from(floor_log)
            } else {
                u64::from(floor_log + 1)
            }
        })
}

impl CostFunctions {
    pub fn compute_cost(&self, input: u64) -> CheckResult<u64> {
        match self {
            CostFunctions::Constant(val) => Ok(*val),
            CostFunctions::Linear(a, b) => { a.cost_overflow_mul(input)?
                                             .cost_overflow_add(*b) }
            CostFunctions::NLogN(a, b) => {
                // a*input*log(input)) + b
                int_log2(input)
                    .ok_or_else(|| CheckErrors::CostOverflow)?
                    .cost_overflow_mul(input)?
                    .cost_overflow_mul(*a)?
                    .cost_overflow_add(*b)
            }
        }
    }
}

impl SimpleCostSpecification {
    pub fn new_diskless(runtime: CostFunctions) -> SimpleCostSpecification {
        SimpleCostSpecification {
            write_length: CostFunctions::Constant(0),
            write_count: CostFunctions::Constant(0),
            read_count: CostFunctions::Constant(0),
            read_length: CostFunctions::Constant(0),
            runtime
        }
    }

    pub fn compute_cost(&self, input: u64) -> CheckResult<ExecutionCost> {
        Ok(ExecutionCost {
            write_length: self.write_length.compute_cost(input)?,
            write_count:  self.write_count.compute_cost(input)?,
            read_count:   self.read_count.compute_cost(input)?,
            read_length:  self.read_length.compute_cost(input)?,
            runtime:      self.runtime.compute_cost(input)?
        })
    }
}

impl From<ExecutionCost> for SimpleCostSpecification {
    fn from(value: ExecutionCost) -> SimpleCostSpecification {
        let ExecutionCost {
            write_length, write_count, read_count, read_length, runtime } = value; 
        SimpleCostSpecification {
            write_length: CostFunctions::Constant(write_length),
            write_count:  CostFunctions::Constant(write_count),
            read_length: CostFunctions::Constant(read_length),
            read_count:  CostFunctions::Constant(read_count),
            runtime: CostFunctions::Constant(runtime),
        }
    }
}

#[cfg(test)]
mod unit_tests {
    use super::*;

    #[test]
    fn test_simple_overflows() {
        assert_eq!(
            u64::max_value().cost_overflow_add(1),
            Err(CheckErrors::CostOverflow.into()));
        assert_eq!(
            u64::max_value().cost_overflow_mul(2),
            Err(CheckErrors::CostOverflow.into()));
        assert_eq!(
            CostFunctions::NLogN(1, 1).compute_cost(0),
            Err(CheckErrors::CostOverflow.into()));
    }

    #[test]
    fn test_simple_log2s() {
        let inputs = [
            1, 2, 4, 8, 16, 31, 32, 33, 39, 64, 128, 2_u64.pow(63), u64::max_value() ];
        let expected = [
            0, 1, 2, 3, 4, 5, 5, 6, 6, 6, 7, 63, 64 ];
        for (input, expected) in inputs.iter().zip(expected.iter()) {
            assert_eq!(
                int_log2(*input).unwrap(),
                *expected);
        }
    }

}
