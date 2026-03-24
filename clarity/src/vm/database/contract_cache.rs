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

//! TinyUFO-based in-memory cache for parsed Clarity contracts.
//!
//! Contracts are keyed by [`QualifiedContractIdentifier`] and weighted by their
//! [`ResidentBytes`] heap footprint so the cache respects a configurable byte budget.
//!
//! The cache is owned by [`ClarityInstance`](crate::vm::clarity::ClarityInstance) and
//! lives across blocks. [`ContractCache::check_and_advance`] must be called at the start
//! of each block to detect reorgs or epoch transitions; either condition invalidates the
//! entire cache.

use std::mem::size_of;
use std::ops::Deref;
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};

use clarity_types::resident_bytes::ResidentBytes;
use stacks_common::types::StacksEpochId;
use stacks_common::types::chainstate::StacksBlockId;
use tinyufo::TinyUfo;

use crate::vm::contracts::Contract;
use crate::vm::types::QualifiedContractIdentifier;

/// Per-entry overhead beyond what `contract.resident_bytes()` and `key.resident_bytes()` report.
///
/// - `CachedContractInner` minus `Contract`: the wrapper's own fields (`load_cost_size`,
///   `resident_bytes`) that sit outside the `Contract`'s `resident_bytes()` measurement.
/// - Arc allocation header (strong + weak counts on the heap): 16 bytes.
/// - TinyUFO per-entry metadata (frequency counters, node pointers): ~64 bytes.
const ENTRY_OVERHEAD: u64 =
    (size_of::<CachedContractInner>() - size_of::<Contract>()) as u64 + 16 + 64;

/// Bytes per TinyUFO weight unit. Smaller values give finer eviction granularity but reduce the
/// maximum representable entry size (`u16::MAX * CACHE_WEIGHT_UNIT`).
///
/// At 256 bytes per unit:
/// - Max per-entry weight: `u16::MAX * 256` ≈ 16 MiB (sufficient headroom for a parsed AST from a
///   max-size 2 MiB contract source — `MAX_TRANSACTION_LEN` in stackslib)
/// - A 64 MiB cache budget yields `262,144` capacity units
const CACHE_WEIGHT_UNIT: u64 = 256;

/// Inner data for a cached contract. Not used directly by callers.
pub struct CachedContractInner {
    pub contract: Contract,
    /// `contract_size` + `data_size` (for load-contract runtime cost)
    pub load_cost_size: u64,
    /// Actual heap footprint (for cache eviction weight)
    pub resident_bytes: u64,
}

/// Shared handle to a cached contract. Cheap to clone (Arc internally).
/// Derefs to [`CachedContractInner`] so callers access fields directly.
#[derive(Clone)]
pub struct CachedContract(Arc<CachedContractInner>);

impl CachedContract {
    /// Create a new cached contract entry.
    pub fn new(contract: Contract, load_cost_size: u64, resident_bytes: u64) -> Self {
        CachedContract(Arc::new(CachedContractInner {
            contract,
            load_cost_size,
            resident_bytes,
        }))
    }
}

impl Deref for CachedContract {
    type Target = CachedContractInner;

    fn deref(&self) -> &CachedContractInner {
        &self.0
    }
}

/// Parsed-contract cache backed by TinyUFO (an O(1), lock-free, approximate LFU).
///
/// Entries are weighted by their in-memory footprint so the total resident size stays within
/// `byte_limit`.
///
/// The cache is invalidated in its entirety when a reorg or epoch transition is detected by
/// [`check_and_advance()`](Self::check_and_advance), which *must* be called at the start of each
/// new block to ensure cache correctness.
pub struct ContractCache {
    cache: TinyUfo<QualifiedContractIdentifier, CachedContract>,
    byte_limit: usize,
    last_epoch: Option<StacksEpochId>,
    last_block: Option<StacksBlockId>,
    hits: AtomicU64,
    misses: AtomicU64,
}

impl ContractCache {
    /// Create a new cache with the given byte budget.
    ///
    /// Cache capacity is derived by dividing `byte_limit` by [`CACHE_WEIGHT_UNIT`].
    pub fn new(byte_limit: usize) -> Self {
        Self {
            cache: TinyUfo::new(byte_limit / CACHE_WEIGHT_UNIT as usize, 256),
            byte_limit,
            last_epoch: None,
            last_block: None,
            hits: AtomicU64::new(0),
            misses: AtomicU64::new(0),
        }
    }

    /// Look up a cached contract. Returns `None` on miss.
    ///
    /// Increments the `hits` or `misses` counter accordingly.
    pub fn get(&self, key: &QualifiedContractIdentifier) -> Option<CachedContract> {
        let result = self.cache.get(key);
        if result.is_some() {
            self.hits.fetch_add(1, Ordering::Relaxed);
        } else {
            self.misses.fetch_add(1, Ordering::Relaxed);
        }
        result
    }

    /// Gets the total number of cache hits since creation.
    pub fn hits(&self) -> u64 {
        self.hits.load(Ordering::Relaxed)
    }

    /// Gets the total number of cache misses since creation.
    pub fn misses(&self) -> u64 {
        self.misses.load(Ordering::Relaxed)
    }

    /// Insert a contract into the cache.
    ///
    /// The entry is silently dropped if its weight (resident size of the key + contract /
    /// [`CACHE_WEIGHT_UNIT`]) exceeds `u16::MAX`.
    pub fn insert(&self, key: QualifiedContractIdentifier, entry: CachedContract) {
        let total = key.resident_bytes() as u64 + entry.resident_bytes + ENTRY_OVERHEAD;
        let units = total.div_ceil(CACHE_WEIGHT_UNIT);

        // Don't cache entries that exceed the maximum representable weight. This _shouldn't_ happen
        // in practice, but we guard against it because deploy-time contract size != resident
        // runtime size.
        let Some(weight) = u16::try_from(units.max(1)).ok() else {
            return;
        };

        self.cache.put(key, entry, weight);
    }

    /// Validate cache against the current block and epoch.
    ///
    /// If the parent block doesn't match the last seen block, or if the epoch has changed, we
    /// assume a reorg or epoch transition has occurred and clear the cache to maintain correctness.
    /// Otherwise, the cache is updated to reflect the new `current_block` and preserved for
    /// continued use.
    pub fn check_and_advance(
        &mut self,
        parent_block: &StacksBlockId,
        current_block: &StacksBlockId,
        epoch: StacksEpochId,
    ) {
        if self.last_block.as_ref() != Some(parent_block) || self.last_epoch != Some(epoch) {
            self.cache = TinyUfo::new(self.byte_limit / CACHE_WEIGHT_UNIT as usize, 256);
            self.last_epoch = Some(epoch);
        }
        self.last_block = Some(current_block.clone());
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::vm::contexts::ContractContext;
    use crate::vm::version::ClarityVersion;

    fn make_contract_id(name: &str) -> QualifiedContractIdentifier {
        QualifiedContractIdentifier::local(name).unwrap()
    }

    fn make_cached(load_cost_size: u64) -> CachedContract {
        make_cached_with_size(load_cost_size, None)
    }

    /// Create a [`CachedContract`] with an explicit `resident_bytes` override for eviction tests.
    fn make_cached_with_size(
        load_cost_size: u64,
        resident_override: Option<u64>,
    ) -> CachedContract {
        let id = make_contract_id("test");
        let contract = Contract {
            contract_context: ContractContext::new(id, ClarityVersion::Clarity4),
        };
        let resident = resident_override.unwrap_or_else(|| contract.resident_bytes() as u64);
        CachedContract::new(contract, load_cost_size, resident)
    }

    #[test]
    fn cache_hit_and_miss() {
        let cache = ContractCache::new(64 * 1024 * 1024);
        let id = make_contract_id("my-contract");
        assert!(cache.get(&id).is_none());

        let entry = make_cached(1000);
        cache.insert(id.clone(), entry.clone());
        let hit = cache.get(&id).unwrap();
        assert_eq!(hit.load_cost_size, 1000);
    }

    #[test]
    fn check_and_advance_clears_on_epoch_change() {
        let mut cache = ContractCache::new(64 * 1024 * 1024);
        let block_a = StacksBlockId([0x01; 32]);
        let block_b = StacksBlockId([0x02; 32]);

        cache.check_and_advance(&block_a, &block_b, StacksEpochId::Epoch21);

        let id = make_contract_id("cached");
        cache.insert(id.clone(), make_cached(500));
        assert!(cache.get(&id).is_some());

        // Same parent, new block, different epoch → clear
        cache.check_and_advance(&block_b, &StacksBlockId([0x03; 32]), StacksEpochId::Epoch25);
        assert!(cache.get(&id).is_none());
    }

    #[test]
    fn check_and_advance_clears_on_reorg() {
        let mut cache = ContractCache::new(64 * 1024 * 1024);
        let block_a = StacksBlockId([0x01; 32]);
        let block_b = StacksBlockId([0x02; 32]);

        cache.check_and_advance(&block_a, &block_b, StacksEpochId::Epoch21);

        let id = make_contract_id("cached");
        cache.insert(id.clone(), make_cached(500));
        assert!(cache.get(&id).is_some());

        // Parent doesn't match last block (block_b) → reorg → clear
        let fork_parent = StacksBlockId([0xAA; 32]);
        cache.check_and_advance(
            &fork_parent,
            &StacksBlockId([0xBB; 32]),
            StacksEpochId::Epoch21,
        );
        assert!(cache.get(&id).is_none());
    }

    #[test]
    fn check_and_advance_preserves_on_linear_chain() {
        let mut cache = ContractCache::new(64 * 1024 * 1024);
        let block_a = StacksBlockId([0x01; 32]);
        let block_b = StacksBlockId([0x02; 32]);
        let block_c = StacksBlockId([0x03; 32]);

        cache.check_and_advance(&block_a, &block_b, StacksEpochId::Epoch21);

        let id = make_contract_id("cached");
        cache.insert(id.clone(), make_cached(500));

        // Linear progression: parent = last block → preserve
        cache.check_and_advance(&block_b, &block_c, StacksEpochId::Epoch21);
        assert!(cache.get(&id).is_some());
    }

    #[test]
    fn cached_contract_deref() {
        let entry = make_cached(42);
        assert_eq!(entry.load_cost_size, 42);
        assert!(entry.resident_bytes > 0);
        assert_eq!(
            entry.contract.contract_context.contract_identifier,
            make_contract_id("test")
        );
    }

    #[test]
    fn eviction_under_pressure() {
        // Budget: 2 KiB = 2048 bytes. Each entry claims ~900 bytes of resident data.
        // With ENTRY_OVERHEAD (96) + key overhead, each entry weighs roughly 1 KiB in weight units
        // (≥4 × 256-byte units). Two entries should fit; a third should trigger eviction of an
        // earlier one.
        let cache = ContractCache::new(2048);

        let id_a = make_contract_id("contract-a");
        let id_b = make_contract_id("contract-b");
        let id_c = make_contract_id("contract-c");

        cache.insert(id_a.clone(), make_cached_with_size(1, Some(900)));
        cache.insert(id_b.clone(), make_cached_with_size(2, Some(900)));
        cache.insert(id_c.clone(), make_cached_with_size(3, Some(900)));

        // At least one of the earlier entries should have been evicted
        let hits: usize = [&id_a, &id_b, &id_c]
            .iter()
            .filter(|id| cache.get(id).is_some())
            .count();
        assert!(
            hits < 3,
            "expected eviction under a 2 KiB budget, but all 3 entries survived"
        );

        // The most recently inserted entry should still be present
        assert!(
            cache.get(&id_c).is_some(),
            "most recent entry should survive eviction"
        );
    }

    #[test]
    fn oversized_entry_silently_dropped() {
        let cache = ContractCache::new(64 * 1024 * 1024);
        let id = make_contract_id("huge");

        // resident_bytes large enough that weight > u16::MAX:
        // u16::MAX * CACHE_WEIGHT_UNIT = 65535 * 256 = 16,776,960
        let huge_resident = u16::MAX as u64 * CACHE_WEIGHT_UNIT + 1;
        let entry = make_cached_with_size(1, Some(huge_resident));
        cache.insert(id.clone(), entry);

        assert!(
            cache.get(&id).is_none(),
            "entry exceeding u16::MAX weight units should not be cached"
        );
    }

    #[test]
    fn weight_reflects_resident_bytes() {
        // Verify that a larger contract gets a proportionally larger weight by checking that
        // inserting two 8 KiB contracts fills a 16 KiB cache (leaving no room for a third), while
        // two 1 KiB contracts would leave room.
        let cache = ContractCache::new(16 * 1024);

        let id_a = make_contract_id("large-a");
        let id_b = make_contract_id("large-b");
        let id_c = make_contract_id("large-c");

        // Each entry: ~8 KiB resident → weight ≈ 32 units (8192/256).
        // Two entries ≈ 64 units; cache capacity = 16384/256 = 64 units → full.
        cache.insert(id_a.clone(), make_cached_with_size(1, Some(8 * 1024)));
        cache.insert(id_b.clone(), make_cached_with_size(2, Some(8 * 1024)));
        cache.insert(id_c.clone(), make_cached_with_size(3, Some(8 * 1024)));

        // Third insert should have caused eviction
        let hits: usize = [&id_a, &id_b, &id_c]
            .iter()
            .filter(|id| cache.get(id).is_some())
            .count();
        assert!(
            hits < 3,
            "cache should evict when filled with entries matching its capacity"
        );
    }
}
