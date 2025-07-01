// Copyright (C) 2013-2020 Blockstack PBC, a public benefit corporation
// Copyright (C) 2020 Stacks Open Internet Foundation
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

use serde::{Deserialize, Serialize};

#[cfg(feature = "vm")]
pub mod constants;
pub mod cost_functions;
#[cfg(feature = "vm")]
#[allow(unused_variables)]
pub mod costs_1;
#[cfg(feature = "vm")]
#[allow(unused_variables)]
pub mod costs_2;
#[cfg(feature = "vm")]
#[allow(unused_variables)]
pub mod costs_2_testnet;
#[cfg(feature = "vm")]
#[allow(unused_variables)]
pub mod costs_3;

#[cfg(feature = "vm")]
#[macro_use]
pub mod tracker;
#[cfg(feature = "vm")]
pub use tracker::*;

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

impl CostErrors {
    fn rejectable(&self) -> bool {
        matches!(self, CostErrors::InterpreterFailure | CostErrors::Expect(_))
    }
}

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
        write!(f, "{{\"runtime\": {}, \"write_len\": {}, \"write_cnt\": {}, \"read_len\": {}, \"read_cnt\": {}}}",
               self.runtime, self.write_length, self.write_count, self.read_length, self.read_count)
    }
}

type Result<T> = std::result::Result<T, CostErrors>;
