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

pub use weight_limited_fifo::WeightLimitedFifo;

use crate::vm::contracts::Contract;
use crate::vm::types::QualifiedContractIdentifier;

mod weight_limited_fifo;

/// Default aggregate `load_cost_size` budget for the contract cache: 5 MiB.
///
/// ## Background
///
/// Estimated for a resident memory size inflation of roughly 3-5× source, so this caps worst-case
/// parsed resident memory at ~15-25 MB per tx, which is well below the counting-allocator
/// threshold, and above most known, realistic tx working sets.
///
/// The vector this limit aims to mitigate is where a malicious or buggy contract calls
/// `contract-call?` on a large number of large, unique contracts, allowing the cache to grow
/// without clear bounds. A transaction OOM'ing a node is largely mitigated by the counting
/// allocator abort callback, however, and this mechanism serves as a conservative & deterministic
/// policy for if/when costs are optimized to account for cached reads.
pub const DEFAULT_CONTRACT_CACHE_BYTE_LIMIT: u64 = 5 * 1024 * 1024;
/// A parsed contract and its load-cost size.
#[derive(Clone)]
pub struct CachedContract {
    pub contract: Contract,
    /// `contract_size + data_size`, the consensus-bearing [`LoadContract`][lc] cost value, also
    /// used as the cache eviction weight.
    ///
    /// [lc]: crate::vm::costs::cost_functions::ClarityCostFunction::LoadContract
    pub load_cost_size: u64,
}

/// Container for per-transaction cached data consulted during Clarity execution.
pub struct ClarityExecutionCache {
    /// Memoization cache for parsed contracts loaded during the transaction.
    ///
    /// Bounded by aggregate `load_cost_size`; entries are evicted in FIFO order when the budget
    /// is exceeded. See the `weight_limited_fifo` module for cache mechanics and counter
    /// semantics.
    pub contracts: WeightLimitedFifo<QualifiedContractIdentifier, CachedContract>,
}

impl Default for ClarityExecutionCache {
    fn default() -> Self {
        Self {
            contracts: WeightLimitedFifo::new(DEFAULT_CONTRACT_CACHE_BYTE_LIMIT),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::vm::contexts::ContractContext;
    use crate::vm::version::ClarityVersion;

    #[test]
    fn cached_contract_clone_shares_arc_payload() {
        // Cloning a `CachedContract` should result in a shallow clone. Verified by deref'ing both
        // clones through `Contract`'s `Deref` and checking pointer equality on the underlying
        // `ContractContext`.
        let id = QualifiedContractIdentifier::local("shared").unwrap();
        let entry = CachedContract {
            contract: ContractContext::new(id, ClarityVersion::Clarity4).into(),
            load_cost_size: 0,
        };
        let clone = entry.clone();
        assert!(std::ptr::eq(&*entry.contract, &*clone.contract));
    }
}
