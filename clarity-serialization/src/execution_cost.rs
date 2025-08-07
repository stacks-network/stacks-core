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
use std::{cmp, fmt};

#[cfg(feature = "rusqlite")]
use rusqlite::{
    ToSql,
    types::{FromSql, FromSqlResult, ToSqlOutput, ValueRef},
};

use crate::errors::CostErrors;

#[derive(Debug, Deserialize, Serialize, Clone, PartialEq, Eq, Hash)]
pub struct ExecutionCost {
    pub write_length: u64,
    pub write_count: u64,
    pub read_length: u64,
    pub read_count: u64,
    pub runtime: u64,
}

impl fmt::Display for ExecutionCost {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(
            f,
            "{{\"runtime\": {}, \"write_len\": {}, \"write_cnt\": {}, \"read_len\": {}, \"read_cnt\": {}}}",
            self.runtime, self.write_length, self.write_count, self.read_length, self.read_count
        )
    }
}

impl ExecutionCost {
    pub const ZERO: Self = Self {
        runtime: 0,
        write_length: 0,
        read_count: 0,
        write_count: 0,
        read_length: 0,
    };

    /// Returns the percentage of self consumed in `numerator`'s largest proportion dimension.
    pub fn proportion_largest_dimension(&self, numerator: &ExecutionCost) -> u64 {
        // max() should always return because there are > 0 elements
        #[allow(clippy::expect_used)]
        *[
            numerator.runtime / cmp::max(1, self.runtime / 100),
            numerator.write_length / cmp::max(1, self.write_length / 100),
            numerator.write_count / cmp::max(1, self.write_count / 100),
            numerator.read_length / cmp::max(1, self.read_length / 100),
            numerator.read_count / cmp::max(1, self.read_count / 100),
        ]
        .iter()
        .max()
        .expect("BUG: should find maximum")
    }

    /// Returns the dot product of this execution cost with `resolution`/block_limit
    /// This provides a scalar value representing the cumulative consumption
    /// of `self` in the provided block_limit.
    pub fn proportion_dot_product(&self, block_limit: &ExecutionCost, resolution: u64) -> u64 {
        [
            // each field here is calculating `r * self / limit`, using f64
            //  use MAX(1, block_limit) to guard against divide by zero
            //  use MIN(1, self/block_limit) to guard against self > block_limit
            resolution as f64
                * 1_f64.min(self.runtime as f64 / 1_f64.max(block_limit.runtime as f64)),
            resolution as f64
                * 1_f64.min(self.read_count as f64 / 1_f64.max(block_limit.read_count as f64)),
            resolution as f64
                * 1_f64.min(self.write_count as f64 / 1_f64.max(block_limit.write_count as f64)),
            resolution as f64
                * 1_f64.min(self.read_length as f64 / 1_f64.max(block_limit.read_length as f64)),
            resolution as f64
                * 1_f64.min(self.write_length as f64 / 1_f64.max(block_limit.write_length as f64)),
        ]
        .iter()
        .fold(0, |acc, dim| acc.saturating_add(cmp::max(*dim as u64, 1)))
    }

    pub fn max_value() -> ExecutionCost {
        Self {
            runtime: u64::MAX,
            write_length: u64::MAX,
            read_count: u64::MAX,
            write_count: u64::MAX,
            read_length: u64::MAX,
        }
    }

    pub fn runtime(runtime: u64) -> ExecutionCost {
        Self {
            runtime,
            write_length: 0,
            read_count: 0,
            write_count: 0,
            read_length: 0,
        }
    }

    pub fn add_runtime(&mut self, runtime: u64) -> Result<(), CostErrors> {
        self.runtime = self.runtime.cost_overflow_add(runtime)?;
        Ok(())
    }

    pub fn add(&mut self, other: &ExecutionCost) -> Result<(), CostErrors> {
        self.runtime = self.runtime.cost_overflow_add(other.runtime)?;
        self.read_count = self.read_count.cost_overflow_add(other.read_count)?;
        self.read_length = self.read_length.cost_overflow_add(other.read_length)?;
        self.write_length = self.write_length.cost_overflow_add(other.write_length)?;
        self.write_count = self.write_count.cost_overflow_add(other.write_count)?;
        Ok(())
    }

    pub fn sub(&mut self, other: &ExecutionCost) -> Result<(), CostErrors> {
        self.runtime = self.runtime.cost_overflow_sub(other.runtime)?;
        self.read_count = self.read_count.cost_overflow_sub(other.read_count)?;
        self.read_length = self.read_length.cost_overflow_sub(other.read_length)?;
        self.write_length = self.write_length.cost_overflow_sub(other.write_length)?;
        self.write_count = self.write_count.cost_overflow_sub(other.write_count)?;
        Ok(())
    }

    pub fn multiply(&mut self, times: u64) -> Result<(), CostErrors> {
        self.runtime = self.runtime.cost_overflow_mul(times)?;
        self.read_count = self.read_count.cost_overflow_mul(times)?;
        self.read_length = self.read_length.cost_overflow_mul(times)?;
        self.write_length = self.write_length.cost_overflow_mul(times)?;
        self.write_count = self.write_count.cost_overflow_mul(times)?;
        Ok(())
    }

    pub fn divide(&mut self, divisor: u64) -> Result<(), CostErrors> {
        self.runtime = self.runtime.cost_overflow_div(divisor)?;
        self.read_count = self.read_count.cost_overflow_div(divisor)?;
        self.read_length = self.read_length.cost_overflow_div(divisor)?;
        self.write_length = self.write_length.cost_overflow_div(divisor)?;
        self.write_count = self.write_count.cost_overflow_div(divisor)?;
        Ok(())
    }

    /// Returns whether or not this cost exceeds any dimension of the
    ///  other cost.
    pub fn exceeds(&self, other: &ExecutionCost) -> bool {
        self.runtime > other.runtime
            || self.write_length > other.write_length
            || self.write_count > other.write_count
            || self.read_count > other.read_count
            || self.read_length > other.read_length
    }

    pub fn max_cost(first: ExecutionCost, second: ExecutionCost) -> ExecutionCost {
        Self {
            runtime: first.runtime.max(second.runtime),
            write_length: first.write_length.max(second.write_length),
            write_count: first.write_count.max(second.write_count),
            read_count: first.read_count.max(second.read_count),
            read_length: first.read_length.max(second.read_length),
        }
    }

    pub fn is_zero(&self) -> bool {
        *self == Self::ZERO
    }
}

pub trait CostOverflowingMath<T> {
    fn cost_overflow_mul(self, other: T) -> Result<T, CostErrors>;
    fn cost_overflow_add(self, other: T) -> Result<T, CostErrors>;
    fn cost_overflow_sub(self, other: T) -> Result<T, CostErrors>;
    fn cost_overflow_div(self, other: T) -> Result<T, CostErrors>;
}

impl CostOverflowingMath<u64> for u64 {
    fn cost_overflow_mul(self, other: u64) -> Result<u64, CostErrors> {
        self.checked_mul(other).ok_or(CostErrors::CostOverflow)
    }
    fn cost_overflow_add(self, other: u64) -> Result<u64, CostErrors> {
        self.checked_add(other).ok_or(CostErrors::CostOverflow)
    }
    fn cost_overflow_sub(self, other: u64) -> Result<u64, CostErrors> {
        self.checked_sub(other).ok_or(CostErrors::CostOverflow)
    }
    fn cost_overflow_div(self, other: u64) -> Result<u64, CostErrors> {
        self.checked_div(other).ok_or(CostErrors::CostOverflow)
    }
}

#[cfg(feature = "rusqlite")]
impl ToSql for ExecutionCost {
    fn to_sql(&self) -> rusqlite::Result<ToSqlOutput<'_>> {
        let val = serde_json::to_string(self)
            .map_err(|e| rusqlite::Error::ToSqlConversionFailure(Box::new(e)))?;
        Ok(ToSqlOutput::from(val))
    }
}

#[cfg(feature = "rusqlite")]
impl FromSql for ExecutionCost {
    fn column_result(value: ValueRef) -> FromSqlResult<ExecutionCost> {
        let str_val = String::column_result(value)?;
        let parsed = serde_json::from_str(&str_val)
            .map_err(|e| rusqlite::types::FromSqlError::Other(Box::new(e)))?;
        Ok(parsed)
    }
}
