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

//! The rollback-aware database layer lives in `clarity-kernel` and is
//! re-exported here so all pre-existing `crate::vm::database::...` paths keep
//! working. This module holds the *engine-side* pieces that the kernel must
//! not know about: the interpreter-shaped contract object model
//! ([`Contract`]/[`ContractContext`]) stored through [`ClarityDatabaseExt`],
//! the engine-owned execution cache, and the concrete special-case handler
//! type.

pub use clarity_kernel::database::*;

use self::caching::CachedContract;
pub use self::caching::ClarityExecutionCache;
use crate::vm::analysis::{AnalysisDatabase, ContractAnalysis};
use crate::vm::contexts::{ContractContext, GlobalContext};
use crate::vm::contracts::Contract;
use crate::vm::database::structures::deserialize_json;
use crate::vm::errors::{VmExecutionError, VmInternalError};
use crate::vm::types::{PrincipalData, QualifiedContractIdentifier, Value};

mod caching;

/// Signature of the engine-side special-case contract-call hook (see
/// [`SpecialCaseHandlerFn`]).
pub type SpecialCaseHandlerSig = fn(
    // the current Clarity global context
    &mut GlobalContext,
    // the current sender
    Option<&PrincipalData>,
    // the current sponsor
    Option<&PrincipalData>,
    // the invoked contract
    &QualifiedContractIdentifier,
    // the invoked function name
    &str,
    // the function parameters
    &[Value],
    // the result of the function call
    &Value,
) -> Result<(), VmExecutionError>;

/// The concrete type behind the kernel's opaque [`SpecialCaseHandler`] token
/// for this engine: a host-provided hook invoked after specific contract
/// calls (e.g. PoX lock handling in stacks-core).
///
/// Hosts wrap their handler function in this struct (in a `static`) and
/// return a reference to it from
/// [`ClarityBackingStore::get_cc_special_cases_handler`]; the interpreter
/// downcasts the token back to this type at the invocation site.
pub struct SpecialCaseHandlerFn(pub SpecialCaseHandlerSig);

/// Serialization of [`ContractContext`] behind a wrapper struct with a single
/// `contract_context` field, for compatibility with the on-disk format where
/// the `ContractContext` was previously serialized via the `Contract` type.
#[derive(Serialize, Deserialize)]
struct ContractContextWrapper<T> {
    pub contract_context: T,
}

impl ClaritySerializable for ContractContext {
    fn serialize(&self) -> String {
        serde_json::to_string(&ContractContextWrapper {
            contract_context: self,
        })
        .expect("Failed to serialize vm.Value")
    }
}

impl ClarityDeserializable<ContractContext> for ContractContext {
    fn deserialize(json: &str) -> Result<Self, VmExecutionError> {
        deserialize_json::<ContractContextWrapper<ContractContext>>(json)
            .map(|w| w.contract_context)
    }
}

// Contract analyses are persisted in the kernel-owned stored-interface
// format ([`clarity_kernel::analysis::StoredContractAnalysis`], a serde-exact
// mirror of this engine's serialized subset), so the stored bytes are
// unchanged and other engines can read them without this engine's types.
impl ClaritySerializable for ContractAnalysis {
    fn serialize(&self) -> String {
        self.to_stored().serialize()
    }
}

impl ClarityDeserializable<ContractAnalysis> for ContractAnalysis {
    fn deserialize(json: &str) -> Result<Self, VmExecutionError> {
        clarity_kernel::analysis::StoredContractAnalysis::deserialize(json)
            .map(ContractAnalysis::from_stored)
    }
}

/// Constructor sugar for building an [`AnalysisDatabase`] view over any
/// backing store, replacing the inherent `as_analysis_db` methods that lived
/// on the store types before they moved to `clarity-kernel`.
pub trait AsAnalysisDb: ClarityBackingStore + Sized {
    fn as_analysis_db(&mut self) -> AnalysisDatabase<'_> {
        AnalysisDatabase::new(self)
    }
}

impl<T: ClarityBackingStore + Sized> AsAnalysisDb for T {}

/// Borrow the cached contract entry, updating hit/miss counters but not FIFO
/// ordering. Returns [`None`] if no cache is attached or the entry is absent.
fn cached_contract<'a>(
    db: &'a mut ClarityDatabase,
    id: &QualifiedContractIdentifier,
) -> Option<&'a CachedContract> {
    db.execution_cache_mut()?
        .downcast_mut::<ClarityExecutionCache>()?
        .contracts
        .get(id)
}

/// Borrow the cached contract entry without altering FIFO counters.
fn peek_cached_contract<'a>(
    db: &'a ClarityDatabase,
    id: &QualifiedContractIdentifier,
) -> Option<&'a CachedContract> {
    db.execution_cache()?
        .downcast_ref::<ClarityExecutionCache>()?
        .contracts
        .peek(id)
}

/// Insert an entry into the cache if one is attached; otherwise a no-op.
fn cache_contract(
    db: &mut ClarityDatabase,
    id: QualifiedContractIdentifier,
    entry: CachedContract,
) {
    let weight = entry.load_cost_size;
    if let Some(cache) = db
        .execution_cache_mut()
        .and_then(|c| c.downcast_mut::<ClarityExecutionCache>())
    {
        cache.contracts.insert(id, entry, weight);
    }
}

/// Engine-side contract and analysis storage over the kernel's
/// [`ClarityDatabase`]: these methods traffic in the interpreter's contract
/// object model ([`Contract`]/[`ContractContext`]/[`ContractAnalysis`]),
/// which the kernel deliberately does not know about.
pub trait ClarityDatabaseExt {
    fn load_contract_analysis(
        &mut self,
        contract_identifier: &QualifiedContractIdentifier,
    ) -> Result<Option<ContractAnalysis>, VmExecutionError>;

    fn get_contract_size(
        &mut self,
        contract_identifier: &QualifiedContractIdentifier,
    ) -> Result<u64, VmExecutionError>;

    fn insert_contract(
        &mut self,
        contract_identifier: &QualifiedContractIdentifier,
        contract: Contract,
    ) -> Result<(), VmExecutionError>;

    fn get_contract(
        &mut self,
        contract_identifier: &QualifiedContractIdentifier,
    ) -> Result<Contract, VmExecutionError>;

    fn is_in_regtest(&self) -> bool;
}

impl ClarityDatabaseExt for ClarityDatabase<'_> {
    // load contract analysis stored by an analysis_db instance.
    //   in unit testing, where the interpreter is invoked without
    //   an analysis pass, this function will fail to find contract
    //   analysis data
    fn load_contract_analysis(
        &mut self,
        contract_identifier: &QualifiedContractIdentifier,
    ) -> Result<Option<ContractAnalysis>, VmExecutionError> {
        self.store
            .get_metadata(contract_identifier, AnalysisDatabase::storage_key())
            // treat NoSuchContract error thrown by get_metadata as an Option::None --
            //    the analysis will propagate that as a StaticCheckError anyways.
            .ok()
            .flatten()
            .map(|x| ContractAnalysis::deserialize(&x))
            .transpose()
    }

    /// `LoadContract` cost size (`contract_size + data_size`).
    ///
    /// When a cache is attached to this instance and the store isn't retargeted by e.g. `at-block`,
    /// this method attempts to serve values via a passive cache lookup. Cache hits do not update
    /// FIFO counters, and misses fall through to reading from the backing store.
    fn get_contract_size(
        &mut self,
        contract_identifier: &QualifiedContractIdentifier,
    ) -> Result<u64, VmExecutionError> {
        if !self.store.is_retargeted()
            && let Some(cached) = peek_cached_contract(self, contract_identifier)
        {
            return Ok(cached.load_cost_size);
        }

        self.read_contract_size(contract_identifier)
    }

    fn insert_contract(
        &mut self,
        contract_identifier: &QualifiedContractIdentifier,
        contract: Contract,
    ) -> Result<(), VmExecutionError> {
        let artifact = ContractArtifact::new((*contract).serialize());
        self.insert_contract_artifact(contract_identifier, &artifact)
    }

    /// Load a parsed contract, returning a canonicalized [`Contract`].
    ///
    /// Consults the attached cache when attached and the store is not retargeted; on a miss the
    /// contract is read from the backing store and inserted into the cache before being returned.
    ///
    /// The cache is bypassed entirely during `(at-block ...)` retargeting; those reads hit the
    /// backing store and are not cached, since they reflect a different chainstate view.
    ///
    /// Reads served from uncommitted pending metadata (e.g. a contract deployed earlier in the same
    /// rollback layer but not yet committed to the backing store) are not cached.
    fn get_contract(
        &mut self,
        contract_identifier: &QualifiedContractIdentifier,
    ) -> Result<Contract, VmExecutionError> {
        let retargeted = self.store.is_retargeted();

        // Attempt to serve from cache ONLY if we are reading at chain tip (not retargeted).
        if !retargeted && let Some(entry) = cached_contract(self, contract_identifier) {
            return Ok(entry.contract.clone());
        }

        // Miss path: read from store, then (when applicable) populate the cache.
        let contract = read_contract(self, contract_identifier)?;

        // Defensive check: this is not expected on the ordinary contract-call path, but we include
        // it conservatively as this is a lower-level DB API which can be reached while a rollback
        // layer contains pending metadata (e.g., if the cache were ever reused across transaction
        // boundaries).
        let is_pending = self.has_pending_metadata_for_contract(contract_identifier);

        // Only populate the cache on reads at tip and when there are no pending writes to relevant
        // metadata keys.
        if !retargeted && !is_pending {
            let load_cost_size = self.read_contract_size(contract_identifier)?;

            cache_contract(
                self,
                contract_identifier.clone(),
                CachedContract {
                    contract: contract.clone(),
                    load_cost_size,
                },
            );
        }

        Ok(contract)
    }

    /// Lives on the extension trait (not the kernel) so that `cfg!(test)` is
    /// evaluated in this crate, preserving the historical behavior: `true`
    /// exactly when the `clarity` crate itself is compiled with `cfg(test)`.
    fn is_in_regtest(&self) -> bool {
        cfg!(test)
    }
}

/// Read and deserialize the contract blob from the backing store, canonicalizing its types to
/// the current epoch.
///
/// Reads through the rollback-aware metadata layer; does not consult or populate the contract
/// cache.
fn read_contract(
    db: &mut ClarityDatabase,
    contract_identifier: &QualifiedContractIdentifier,
) -> Result<Contract, VmExecutionError> {
    let artifact = db
        .get_contract_artifact(contract_identifier)?
        .ok_or_else(|| {
            VmInternalError::Expect(
                "Failed to read non-consensus contract metadata, even though contract exists in MARF."
                    .into(),
            )
        })?;
    let mut contract_context = ContractContext::deserialize(artifact.as_str())?;

    let epoch = db.get_clarity_epoch_version()?;
    contract_context.canonicalize_types(&epoch)?;

    Ok(contract_context.into())
}

#[cfg(all(test, any()))]
mod tests {
    use clarity_types::{ClarityName, ClarityVersion};
    use stacks_common::types::StacksEpochId;

    use super::*;
    use crate::vm::contexts::ContractContext;
    use crate::vm::database::{MemoryBackingStore, StoreType};
    use crate::vm::types::{QualifiedContractIdentifier, TupleData, TypeSignature, Value};

    /// Deploy a minimal stub contract under `id` in its own committed db transaction.
    #[track_caller]
    fn deploy_stub_contract(db: &mut ClarityDatabase, id: &QualifiedContractIdentifier) {
        db.begin();
        let contract = ContractContext::new(id.clone(), ClarityVersion::Clarity2).into();
        db.insert_contract_hash(id, "(define-public (noop) (ok true))")
            .expect("insert_contract_hash");
        db.set_contract_data_size(id, 0)
            .expect("set_contract_data_size");
        db.insert_contract(id, contract).expect("insert_contract");
        db.commit().expect("commit stub contract");
    }

    #[test]
    fn legacy_contract_adapter_preserves_stored_bytes() {
        let mut store = MemoryBackingStore::new();
        let id = QualifiedContractIdentifier::local("legacy-artifact").unwrap();
        let context = ContractContext::new(id.clone(), ClarityVersion::Clarity2);
        let expected = context.serialize();

        let mut db = store.as_clarity_db();
        db.begin();
        db.insert_contract_hash(&id, "(define-public (noop) (ok true))")
            .expect("insert_contract_hash");
        db.insert_contract(&id, context.into())
            .expect("insert legacy contract");

        let artifact = db
            .get_contract_artifact(&id)
            .expect("load stored artifact")
            .expect("stored artifact should exist");
        assert_eq!(artifact.as_str().as_bytes(), expected.as_bytes());

        let loaded = db.get_contract(&id).expect("decode legacy artifact");
        assert_eq!(loaded.contract_identifier, id);
        assert_eq!(*loaded.get_clarity_version(), ClarityVersion::Clarity2);
        db.roll_back().unwrap();
    }

    #[test]
    fn get_contract_populates_cache_on_miss() {
        let mut cache = ClarityExecutionCache::default();
        let mut store = MemoryBackingStore::new();
        let id = QualifiedContractIdentifier::local("cached").unwrap();

        // Deploy outside the cache attachment so the cache starts empty.
        deploy_stub_contract(&mut store.as_clarity_db(), &id);

        // Each `db` block scopes the exclusive borrow on `cache` so we can inspect counters
        // between calls.
        let first = {
            let mut db = store.as_clarity_db().with_cache(&mut cache);
            db.begin();
            let entry = db.get_contract(&id).expect("load contract");
            db.roll_back().unwrap();
            entry
        };
        assert_eq!(first.contract_identifier, id);
        assert_eq!(cache.contracts.misses(), 1);
        assert_eq!(cache.contracts.hits(), 0);

        let second = {
            let mut db = store.as_clarity_db().with_cache(&mut cache);
            db.begin();
            let entry = db.get_contract(&id).expect("cached load");
            db.roll_back().unwrap();
            entry
        };
        // Both `Contract`s should deref to the same underlying `ContractContext`, confirming the
        // cached entry's Arc was shared rather than deserialized fresh.
        assert!(
            std::ptr::eq(&*first, &*second),
            "second call should share the cached Arc, not a fresh deserialization",
        );
        assert_eq!(cache.contracts.hits(), 1);
        assert_eq!(cache.contracts.misses(), 1);
    }

    #[test]
    fn get_contract_load_cost_size_serves_from_cache() {
        let mut cache = ClarityExecutionCache::default();
        let mut store = MemoryBackingStore::new();
        let id = QualifiedContractIdentifier::local("size-cached").unwrap();
        deploy_stub_contract(&mut store.as_clarity_db(), &id);

        // Prime the cache via `get_contract`, then capture the expected size separately.
        let expected_size = {
            let mut db = store.as_clarity_db().with_cache(&mut cache);
            db.begin();
            let _contract = db.get_contract(&id).expect("prime cache");
            let s = db.read_contract_size(&id).unwrap();
            db.roll_back().unwrap();
            s
        };
        let counters_after_prime = (cache.contracts.hits(), cache.contracts.misses());

        // Subsequent `get_contract_size` must come from the cache, and being a passive `peek` it
        // must not bump hit/miss counters.
        let size = {
            let mut db = store.as_clarity_db().with_cache(&mut cache);
            db.begin();
            let s = db.get_contract_size(&id).expect("load_cost_size");
            db.roll_back().unwrap();
            s
        };
        assert_eq!(size, expected_size);
        assert_eq!(
            (cache.contracts.hits(), cache.contracts.misses()),
            counters_after_prime,
            "passive size lookup must not alter hit/miss counters",
        );
    }

    #[test]
    fn get_contract_load_cost_size_falls_back_without_cache() {
        let mut store = MemoryBackingStore::new();
        let id = QualifiedContractIdentifier::local("no-cache").unwrap();
        deploy_stub_contract(&mut store.as_clarity_db(), &id);

        let mut db = store.as_clarity_db();
        db.begin();
        let size = db.get_contract_size(&id).expect("load_cost_size");
        let expected = db.read_contract_size(&id).unwrap();
        assert_eq!(size, expected);
        db.roll_back().unwrap();
    }

    /// A contract deployed in an uncommitted rollback layer is visible via `get_contract` (pending
    /// metadata is served), but it must not be cached: if the surrounding context rolls back, a
    /// cached entry would point at a contract that no longer exists on the backing store, and the
    /// next lookup in the same tx would falsely succeed.
    #[test]
    fn get_contract_does_not_cache_pending_writes() {
        let mut cache = ClarityExecutionCache::default();
        let mut store = MemoryBackingStore::new();
        let id = QualifiedContractIdentifier::local("pending").unwrap();

        // Deploy + load inside a rollback layer, then discard the layer.
        {
            let mut db = store.as_clarity_db().with_cache(&mut cache);
            db.begin();
            let contract = ContractContext::new(id.clone(), ClarityVersion::Clarity2).into();
            db.insert_contract_hash(&id, "(define-public (noop) (ok true))")
                .expect("insert_contract_hash");
            db.set_contract_data_size(&id, 0)
                .expect("set_contract_data_size");
            db.insert_contract(&id, contract).expect("insert_contract");
            let _ = db
                .get_contract(&id)
                .expect("pending-state load should succeed via uncommitted metadata");
            db.roll_back().unwrap();
        }

        // The rolled-back contract must not be served from cache on a subsequent lookup. The
        // backing store also doesn't have it (the deploy was never committed), so the lookup must
        // error.
        {
            let mut db = store.as_clarity_db().with_cache(&mut cache);
            db.begin();
            let result = db.get_contract(&id);
            assert!(
                result.is_err(),
                "rolled-back contract must not be served from cache after rollback",
            );
            db.roll_back().unwrap();
        }
    }

    /// Guards that the DB read path applies the epoch gate, never returning a
    /// type-unsound tuple from Epoch 4.1.
    #[test]
    fn get_value_epoch_gates_typed_tuple_fields() {
        // `{a:int,b:int}` buffer with a duplicate `a` field; collapses to `{a: 2}`.
        const DUPLICATE_FIELDS: &str = "0c000000020161000000000000000000000000000000000101610000000000000000000000000000000002";
        const REDUCED_TUPLE: &str = "0c0000000101610000000000000000000000000000000002";

        let mut store = MemoryBackingStore::new();
        let mut db = store.as_clarity_db();
        db.begin();

        let contract = QualifiedContractIdentifier::transient();
        let key = ClarityDatabase::make_key_for_trip(&contract, StoreType::Variable, "corrupt");
        // Store raw bytes to bypass write-path sanitization and isolate the read path.
        db.put_data(&key, &DUPLICATE_FIELDS.to_string())
            .expect("failed to store raw value");

        let expected_type = TypeSignature::type_of(&Value::from(
            TupleData::from_data(vec![
                (ClarityName::from_literal("a"), Value::Int(1)),
                (ClarityName::from_literal("b"), Value::Int(2)),
            ])
            .unwrap(),
        ))
        .unwrap();

        // Pre-Epoch 4.1: historical handling reduces the duplicate to one field.
        // Epoch40 pins the activation boundary.
        for epoch in [StacksEpochId::Epoch34, StacksEpochId::Epoch40] {
            let legacy = db
                .get_value(&key, &expected_type, &epoch)
                .expect("legacy read should not error")
                .expect("value should be present");
            assert_eq!(legacy.value.serialize_to_hex().unwrap(), REDUCED_TUPLE);
        }

        // Epoch 4.1+: the read is rejected instead of returning a type-unsound tuple.
        let strict = db.get_value(&key, &expected_type, &StacksEpochId::Epoch41);
        assert!(
            strict.is_err(),
            "strict read should reject the malformed tuple, got {strict:?}"
        );

        db.commit().unwrap();
    }
}
