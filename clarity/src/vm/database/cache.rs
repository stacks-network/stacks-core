use std::{cell::RefCell, collections::HashMap, num::NonZeroUsize};

use lazy_static::lazy_static;
use lru::LruCache;
use stacks_common::types::StacksEpochId;

use crate::vm::{
    analysis::ContractAnalysis, 
    database::structures::StoredContract, 
    types::QualifiedContractIdentifier
};

// Initialize a thread-local static variable to store the cache
thread_local!(
    /// A thread-local cache for the Clarity VM. Since the VM is single-threaded, 
    /// this is safe.
    static CLARITY_CACHE: RefCell<ClarityCache> = RefCell::new(ClarityCache::new());
);

pub fn disable_clarity_cache() {
    CLARITY_CACHE.with_borrow_mut(|cache| *cache.is_enabled.borrow_mut() = false);
}

pub fn enable_clarity_cache() {
    CLARITY_CACHE.with_borrow_mut(|cache| *cache.is_enabled.borrow_mut() = true);
}

/// Executes the given closure with the Clarity cache.
pub fn with_clarity_cache<T, F: FnOnce(&ClarityCache) -> T>(f: F) -> T {
    CLARITY_CACHE.with_borrow(|cache| f(&cache))
}

#[cfg(test)]
pub fn clear_clarity_cache() {
    CLARITY_CACHE.with_borrow(|cache| cache.clear());
}

pub struct ClarityCache {
    is_enabled: RefCell<bool>,
    contract_cache: RefCell<LruCache<ContractKey, StoredContract>>,
    analysis_cache: RefCell<LruCache<ContractKey, ContractAnalysis>>,
    contract_id_lookup_cache: RefCell<HashMap<QualifiedContractIdentifier, u32>>,
}

impl ClarityCache {
    pub fn new() -> Self {
        ClarityCache {
            #[cfg(not(any(test, feature = "testing")))]
            is_enabled: RefCell::new(true),
            #[cfg(any(test, feature = "testing"))]
            is_enabled: RefCell::new(false),
            contract_cache: RefCell::new(LruCache::new(NonZeroUsize::new(100).unwrap())),
            analysis_cache: RefCell::new(LruCache::new(NonZeroUsize::new(100).unwrap())),
            contract_id_lookup_cache: RefCell::new(HashMap::new()),
        }
    }

    pub fn try_get_contract(&self, id: &QualifiedContractIdentifier, epoch: Option<StacksEpochId>) -> Option<StoredContract> {
        if self.is_enabled.borrow().eq(&false) {
            return None;
        }

        self.contract_cache.borrow_mut().get(&ContractKey(id.clone(), epoch)).cloned()
    }

    pub fn push_contract(&self, id: QualifiedContractIdentifier, epoch: Option<StacksEpochId>, contract: StoredContract) {
        if self.is_enabled.borrow().eq(&false) {
            return;
        }

        self.contract_id_lookup_cache.borrow_mut()
            .insert(id.clone(), contract.id);

        self.contract_cache.borrow_mut()
            .push(ContractKey(id, epoch), contract);
    }

    pub fn has_contract(&self, id: &QualifiedContractIdentifier) -> bool {
        if self.is_enabled.borrow().eq(&false) {
            return false;
        }

        self.contract_cache.borrow().contains(&ContractKey(id.clone(), None))
    }

    pub fn try_get_contract_analysis(&self, id: &QualifiedContractIdentifier, epoch: Option<StacksEpochId>) -> Option<ContractAnalysis> {
        if self.is_enabled.borrow().eq(&false) {
            return None;
        }

        self.analysis_cache.borrow_mut().get(&ContractKey(id.clone(), epoch)).cloned()
    }

    pub fn push_contract_analysis(&self, id: QualifiedContractIdentifier, epoch: Option<StacksEpochId>, analysis: ContractAnalysis) {
        if self.is_enabled.borrow().eq(&false) {
            return;
        }

        self.analysis_cache.borrow_mut().push(ContractKey(id, epoch), analysis);
    }

    pub fn try_get_contract_id(&self, id: &QualifiedContractIdentifier) -> Option<u32> {
        if self.is_enabled.borrow().eq(&false) {
            return None;
        }

        self.contract_id_lookup_cache.borrow().get(&id).cloned()
    }

    pub fn push_contract_id(&self, id: QualifiedContractIdentifier, contract_id: u32) {
        if self.is_enabled.borrow().eq(&false) {
            return;
        }

        self.contract_id_lookup_cache.borrow_mut()
            .insert(id, contract_id);
    }

    #[cfg(test)]
    pub fn clear(&self) {
        self.contract_cache.borrow_mut().clear();
        self.analysis_cache.borrow_mut().clear();
        self.contract_id_lookup_cache.borrow_mut().clear();
    }
}

#[derive(Debug, Clone, Eq, PartialEq, Hash)]
struct ContractKey(QualifiedContractIdentifier, Option<StacksEpochId>);