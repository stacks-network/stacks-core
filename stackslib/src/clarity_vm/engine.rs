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

//! Host-owned selection of Clarity engine revisions.
//!
//! A contract stores its [`ClarityVersion`], not the concrete engine build
//! that executes it. For each block, the current protocol epoch selects a
//! manifest, and that manifest maps every supported language version to an
//! engine revision:
//!
//! ```text
//! (current epoch, contract Clarity version) -> engine revision
//! ```
//!
//! Selecting by the current epoch is consensus-critical. An old contract can
//! acquire epoch-gated behavior changes when called later (`at-block` is the
//! historical example), while replay of its earlier calls must retain the old
//! behavior. Engine revisions are reused across epochs that do not change
//! their semantics; this is not one engine crate per epoch/version cell. The
//! transitional legacy engine remains one revision because it intentionally
//! carries all historical epoch gates internally. Gate-free engines use new
//! linked revisions when an epoch changes their existing contracts.

use std::fmt;

use clarity::vm::analysis::StoredContractAnalysis;
use clarity::vm::engine::{ContractDispatcher, Engine, EngineError, LegacyEngine, RuntimeContext};
use clarity::vm::types::QualifiedContractIdentifier;
use clarity::vm::ClarityVersion;
use clarity_v6::Clarity6Engine;
use stacks_common::types::StacksEpochId;

static LEGACY_V1: LegacyEngine = LegacyEngine;
static CLARITY6_V1: Clarity6Engine = Clarity6Engine;

/// A concrete, linkable consensus revision of a Clarity engine.
///
/// Future variants will distinguish side-by-side major releases such as
/// `Clarity6V1` and `Clarity6V2`. Multiple epochs may select the same variant.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EngineRevision {
    LegacyV1,
    Clarity6V1,
}

/// One engine selected from the manifest for an interaction.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SelectedEngine {
    revision: EngineRevision,
}

impl SelectedEngine {
    pub fn revision(self) -> EngineRevision {
        self.revision
    }

    pub fn engine(self) -> &'static dyn Engine {
        match self.revision {
            EngineRevision::LegacyV1 => &LEGACY_V1,
            EngineRevision::Clarity6V1 => &CLARITY6_V1,
        }
    }
}

/// The engine set active in one Stacks protocol epoch.
#[derive(Debug, Clone, Copy)]
pub struct ClarityEngineManifest {
    epoch: StacksEpochId,
}

/// Nested-call router installed in every production transaction context.
/// It reads the callee's stored language version from the shared database and
/// applies the same epoch manifest used for top-level calls.
pub struct ClarityEngineDispatcher {
    manifest: ClarityEngineManifest,
}

impl ClarityEngineDispatcher {
    pub fn for_epoch(epoch: StacksEpochId) -> Self {
        Self {
            manifest: ClarityEngineManifest::for_epoch(epoch),
        }
    }
}

impl ContractDispatcher for ClarityEngineDispatcher {
    fn select_engine(
        &mut self,
        runtime: &mut RuntimeContext,
        contract: &QualifiedContractIdentifier,
    ) -> Result<&'static dyn Engine, EngineError> {
        let Some(analysis) = StoredContractAnalysis::load(&mut runtime.db, contract)
            .map_err(EngineError::Execution)?
        else {
            // Legacy deployment helpers, and potentially historical contracts,
            // can persist an executable contract without its analysis. Only the
            // legacy engine supports that representation; future engines must
            // persist analysis so their version can be selected explicitly.
            return Ok(&LEGACY_V1);
        };
        self.manifest
            .select(analysis.clarity_version)
            .map(SelectedEngine::engine)
            .map_err(|e| EngineError::Internal(e.to_string()))
    }
}

impl ClarityEngineManifest {
    pub fn for_epoch(epoch: StacksEpochId) -> Self {
        Self { epoch }
    }

    pub fn epoch(self) -> StacksEpochId {
        self.epoch
    }

    /// The newest contract language version deployable in this epoch.
    pub fn default_version(self) -> Option<ClarityVersion> {
        if self.epoch == StacksEpochId::Epoch10 {
            None
        } else {
            Some(ClarityVersion::default_for_epoch(self.epoch))
        }
    }

    /// Map a language version to its independently linkable engine revision.
    /// Epoch availability is validated separately by [`Self::select`].
    fn revision_for_version(version: ClarityVersion) -> EngineRevision {
        match version {
            ClarityVersion::Clarity1
            | ClarityVersion::Clarity2
            | ClarityVersion::Clarity3
            | ClarityVersion::Clarity4
            | ClarityVersion::Clarity5 => EngineRevision::LegacyV1,
            ClarityVersion::Clarity6 => EngineRevision::Clarity6V1,
        }
    }

    /// Select the engine revision for a contract language version at this
    /// manifest's current execution epoch.
    pub fn select(self, version: ClarityVersion) -> Result<SelectedEngine, EngineSelectionError> {
        let Some(maximum) = self.default_version() else {
            return Err(EngineSelectionError::ClarityUnavailable { epoch: self.epoch });
        };
        if version > maximum {
            return Err(EngineSelectionError::UnsupportedVersion {
                epoch: self.epoch,
                requested: version,
                maximum,
            });
        }

        Ok(SelectedEngine {
            revision: Self::revision_for_version(version),
        })
    }
}

#[derive(Debug, Clone, Copy)]
pub enum EngineSelectionError {
    ClarityUnavailable {
        epoch: StacksEpochId,
    },
    UnsupportedVersion {
        epoch: StacksEpochId,
        requested: ClarityVersion,
        maximum: ClarityVersion,
    },
}

impl fmt::Display for EngineSelectionError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::ClarityUnavailable { epoch } => {
                write!(f, "Clarity is unavailable in epoch {epoch}")
            }
            Self::UnsupportedVersion {
                epoch,
                requested,
                maximum,
            } => write!(
                f,
                "{requested} is unavailable in epoch {epoch}; maximum is {maximum}"
            ),
        }
    }
}

#[cfg(test)]
mod tests {
    use clarity::vm::costs::{ExecutionCost, LimitedCostTracker};
    use clarity::vm::database::MemoryBackingStore;
    use clarity::vm::engine::{CostBudget, TransactionContext};
    use clarity::vm::resource_limiter::ResourceBudget;
    use clarity::vm::types::{PrincipalData, StandardPrincipalData, Value};
    use stacks_common::consts::CHAIN_ID_TESTNET;

    use super::*;

    const CALLEE: &str = "
        (define-data-var calls uint u0)
        (define-read-only (get-calls) (var-get calls))
        (define-public (record)
          (begin
            (var-set calls (+ (var-get calls) u1))
            (print contract-caller)
            (ok contract-caller)))";

    const CALLER: &str = "
        (define-public (run)
          (contract-call? .callee record))";

    const FAILING_CALLER: &str = "
        (define-public (run)
          (begin
            (unwrap-panic (contract-call? .callee record))
            (/ u1 u0)
            (ok true)))";

    fn setup_store() -> MemoryBackingStore {
        let mut store = MemoryBackingStore::new();
        let mut db = store.as_clarity_db();
        db.begin();
        db.set_clarity_epoch_version(StacksEpochId::Epoch40)
            .unwrap();
        db.commit().unwrap();
        store
    }

    fn contract_id(name: &str) -> QualifiedContractIdentifier {
        QualifiedContractIdentifier::new(
            StandardPrincipalData::transient(),
            name.to_string().try_into().unwrap(),
        )
    }

    fn deploy(
        manifest: ClarityEngineManifest,
        context: &mut TransactionContext,
        id: &QualifiedContractIdentifier,
        source: &str,
        version: ClarityVersion,
    ) {
        manifest
            .select(version)
            .unwrap()
            .engine()
            .deploy_contract(context, id, source, version, None)
            .unwrap();
    }

    fn run_mixed_call(
        caller_version: ClarityVersion,
        callee_version: ClarityVersion,
        caller_source: &str,
        install_host_tracker: bool,
    ) -> (Result<Value, EngineError>, Value, usize) {
        let manifest = ClarityEngineManifest::for_epoch(StacksEpochId::Epoch40);
        let mut store = setup_store();
        let mut context = TransactionContext::new(
            store.as_clarity_db(),
            false,
            CHAIN_ID_TESTNET,
            StacksEpochId::Epoch40,
        )
        .with_budget(CostBudget::Limited(ExecutionCost::max_value()));
        if install_host_tracker {
            context.install_cost_tracker(LimitedCostTracker::new_free());
        }
        let callee = contract_id("callee");
        let caller = contract_id("caller");
        deploy(manifest, &mut context, &callee, CALLEE, callee_version);
        deploy(
            manifest,
            &mut context,
            &caller,
            caller_source,
            caller_version,
        );

        context.install_dispatcher(ClarityEngineDispatcher::for_epoch(StacksEpochId::Epoch40));
        let sender: PrincipalData = StandardPrincipalData::transient().into();
        let call = manifest
            .select(caller_version)
            .unwrap()
            .engine()
            .execute_call(
                &mut context,
                sender,
                None,
                &caller,
                "run",
                &[],
                None,
                &ResourceBudget::unlimited(),
            );
        let event_count = call
            .as_ref()
            .map(|outcome| outcome.events.len())
            .unwrap_or(0);
        let value = call.map(|outcome| outcome.value);
        let calls = manifest
            .select(callee_version)
            .unwrap()
            .engine()
            .eval_read_only(&mut context, &callee, "(get-calls)")
            .unwrap();
        (value, calls, event_count)
    }

    #[test]
    fn manifest_selects_every_historically_available_version() {
        for &epoch in StacksEpochId::ALL {
            let manifest = ClarityEngineManifest::for_epoch(epoch);
            let Some(maximum) = manifest.default_version() else {
                assert_eq!(epoch, StacksEpochId::Epoch10);
                for &version in ClarityVersion::ALL {
                    assert!(manifest.select(version).is_err());
                }
                continue;
            };

            for &version in ClarityVersion::ALL {
                let selected = manifest.select(version);
                if version <= maximum {
                    let selected = selected.unwrap();
                    let expected = if version == ClarityVersion::Clarity6 {
                        EngineRevision::Clarity6V1
                    } else {
                        EngineRevision::LegacyV1
                    };
                    assert_eq!(selected.revision(), expected);
                    assert!(selected.engine().supported_versions().contains(&version));
                } else {
                    assert!(selected.is_err());
                }
            }
        }
    }

    #[test]
    fn clarity6_revision_spans_epoch40_and_epoch41_kernel_rules() {
        let epoch_40 = ClarityEngineManifest::for_epoch(StacksEpochId::Epoch40)
            .select(ClarityVersion::Clarity6)
            .unwrap();
        let epoch_41 = ClarityEngineManifest::for_epoch(StacksEpochId::Epoch41)
            .select(ClarityVersion::Clarity6)
            .unwrap();

        assert_eq!(epoch_40.revision(), epoch_41.revision());
        assert_eq!(epoch_40.revision(), EngineRevision::Clarity6V1);
        let selected = epoch_40;
        assert_eq!(selected.engine().name(), "clarity-v6-revision-1");
        assert_eq!(
            selected.engine().supported_versions(),
            &[ClarityVersion::Clarity6]
        );
    }

    #[test]
    fn nested_calls_cross_the_legacy_clarity6_boundary_both_ways() {
        for (caller_version, callee_version) in [
            (ClarityVersion::Clarity5, ClarityVersion::Clarity6),
            (ClarityVersion::Clarity6, ClarityVersion::Clarity5),
        ] {
            let (value, calls, event_count) =
                run_mixed_call(caller_version, callee_version, CALLER, true);
            assert_eq!(
                value.unwrap(),
                Value::okay(Value::Principal(PrincipalData::Contract(contract_id(
                    "caller"
                ))))
                .unwrap()
            );
            assert_eq!(calls, Value::UInt(1));
            assert_eq!(event_count, 1);
        }
    }

    #[test]
    fn either_engine_can_establish_the_shared_cost_tracker() {
        for (caller_version, callee_version) in [
            // Deployment order is callee then caller, so these two cases make
            // each concrete engine tracker the transaction's initial meter.
            (ClarityVersion::Clarity5, ClarityVersion::Clarity6),
            (ClarityVersion::Clarity6, ClarityVersion::Clarity5),
        ] {
            let (value, calls, event_count) =
                run_mixed_call(caller_version, callee_version, CALLER, false);
            assert!(value.is_ok());
            assert_eq!(calls, Value::UInt(1));
            assert_eq!(event_count, 1);
        }
    }

    #[test]
    fn mixed_engine_nested_writes_roll_back_with_the_outer_call() {
        for (caller_version, callee_version) in [
            (ClarityVersion::Clarity5, ClarityVersion::Clarity6),
            (ClarityVersion::Clarity6, ClarityVersion::Clarity5),
        ] {
            let (value, calls, event_count) =
                run_mixed_call(caller_version, callee_version, FAILING_CALLER, true);
            assert!(matches!(value, Err(EngineError::Execution(_))));
            assert_eq!(calls, Value::UInt(0));
            assert_eq!(event_count, 0);
        }
    }
}
