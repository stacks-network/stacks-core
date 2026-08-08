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

//! The pinned Clarity 6 engine, introduced with Stacks epoch 4.0.
//!
//! Revision 1 establishes Clarity 6 as a separately linkable engine behind
//! the kernel ABI. It initially delegates evaluation to the frozen legacy
//! interpreter for byte-for-byte behavior parity while Clarity 6 semantics
//! are extracted and their historical gates are replaced with fixed choices.
//! Real epoch-4.0 and epoch-4.1 contracts route through this engine, making
//! every extraction step testable against mainnet history.

use clarity::vm::analysis::ContractAnalysis;
use clarity::vm::ast::ContractAST;
use clarity::vm::engine::LegacyEngine;
use clarity_kernel::engine::{
    AbortCallback, AnalyzedContract, ContractDispatcher, DeployOutcome, Engine, EngineError,
    ExecutionOutcome, TransactionContext,
};
use clarity_kernel::resource_limiter::ResourceBudget;
use clarity_types::types::{PrincipalData, QualifiedContractIdentifier};
use clarity_types::{ClarityVersion, Value};

static LEGACY_EXECUTOR: LegacyEngine = LegacyEngine;
const SUPPORTED_VERSIONS: &[ClarityVersion] = &[ClarityVersion::Clarity6];

/// The first separately linkable Clarity 6 consensus revision.
pub struct Clarity6Engine;

/// Clarity 6's private analyzed representation.
///
/// Revision 1 carries the behavior-parity legacy representation internally;
/// the host and other engines only see the kernel's stored interface.
struct Clarity6Analysis {
    legacy: AnalyzedContract,
}

impl Clarity6Engine {
    fn wrap_legacy_analysis(legacy: AnalyzedContract) -> AnalyzedContract {
        let source = legacy.source().to_owned();
        let interface = legacy.interface().clone();
        AnalyzedContract::new(source, interface, Clarity6Analysis { legacy })
    }

    fn analysis(analyzed: &AnalyzedContract) -> Result<&AnalyzedContract, EngineError> {
        analyzed
            .engine_data::<Clarity6Analysis>()
            .map(|analysis| &analysis.legacy)
            .ok_or_else(|| {
                EngineError::Internal(
                    "AnalyzedContract was not produced by clarity-v6 revision 1".into(),
                )
            })
    }

    /// Wrap analysis performed through the legacy transaction API in a
    /// Clarity-6-owned engine handle.
    ///
    /// This preserves the node's historical parser/static-error taxonomy
    /// while its production analysis entry point is migrated to the ABI.
    pub fn from_legacy_parts(
        source: String,
        ast: ContractAST,
        analysis: ContractAnalysis,
    ) -> AnalyzedContract {
        Self::wrap_legacy_analysis(LegacyEngine::from_legacy_parts(source, ast, analysis))
    }

    /// Recover the legacy working analysis needed by the transaction receipt
    /// while the node still exposes that concrete type.
    pub fn into_legacy_parts(
        analyzed: AnalyzedContract,
    ) -> Option<(ContractAST, ContractAnalysis)> {
        let analysis = analyzed.into_engine_data::<Clarity6Analysis>()?;
        LegacyEngine::into_legacy_parts(analysis.legacy)
    }
}

impl Engine for Clarity6Engine {
    fn name(&self) -> &'static str {
        "clarity-v6-revision-1"
    }

    fn supported_versions(&self) -> &'static [ClarityVersion] {
        SUPPORTED_VERSIONS
    }

    fn analyze_contract(
        &self,
        ctx: &mut TransactionContext,
        contract: &QualifiedContractIdentifier,
        source: &str,
        version: ClarityVersion,
        analysis_budget: &ResourceBudget,
    ) -> Result<AnalyzedContract, EngineError> {
        if version != ClarityVersion::Clarity6 {
            return Err(EngineError::Internal(format!(
                "{} cannot analyze {version}",
                self.name()
            )));
        }

        let legacy = LEGACY_EXECUTOR.analyze_contract(
            ctx,
            contract,
            source,
            ClarityVersion::Clarity6,
            analysis_budget,
        )?;
        Ok(Self::wrap_legacy_analysis(legacy))
    }

    fn initialize_contract(
        &self,
        ctx: &mut TransactionContext,
        analyzed: &AnalyzedContract,
        sponsor: Option<PrincipalData>,
        abort: Option<AbortCallback>,
        execution_budget: &ResourceBudget,
    ) -> Result<DeployOutcome, EngineError> {
        LEGACY_EXECUTOR.initialize_contract(
            ctx,
            Self::analysis(analyzed)?,
            sponsor,
            abort,
            execution_budget,
        )
    }

    fn save_analysis(
        &self,
        ctx: &mut TransactionContext,
        analyzed: &AnalyzedContract,
    ) -> Result<(), EngineError> {
        LEGACY_EXECUTOR.save_analysis(ctx, Self::analysis(analyzed)?)
    }

    fn execute_call(
        &self,
        ctx: &mut TransactionContext,
        sender: PrincipalData,
        sponsor: Option<PrincipalData>,
        contract: &QualifiedContractIdentifier,
        function: &str,
        args: &[Value],
        abort: Option<AbortCallback>,
        execution_budget: &ResourceBudget,
    ) -> Result<ExecutionOutcome, EngineError> {
        LEGACY_EXECUTOR.execute_call(
            ctx,
            sender,
            sponsor,
            contract,
            function,
            args,
            abort,
            execution_budget,
        )
    }

    fn execute_nested_call(
        &self,
        ctx: &mut TransactionContext,
        dispatcher: &mut dyn ContractDispatcher,
        sender: Option<PrincipalData>,
        caller: Option<PrincipalData>,
        sponsor: Option<PrincipalData>,
        contract: &QualifiedContractIdentifier,
        function: &str,
        args: &[Value],
    ) -> Result<Value, EngineError> {
        LEGACY_EXECUTOR.execute_nested_call(
            ctx, dispatcher, sender, caller, sponsor, contract, function, args,
        )
    }

    fn eval_read_only(
        &self,
        ctx: &mut TransactionContext,
        contract: &QualifiedContractIdentifier,
        program: &str,
    ) -> Result<Value, EngineError> {
        LEGACY_EXECUTOR.eval_read_only(ctx, contract, program)
    }
}

#[cfg(test)]
mod tests {
    use clarity::vm::database::MemoryBackingStore;
    use clarity_kernel::costs::ExecutionCost;
    use clarity_kernel::engine::CostBudget;
    use clarity_types::types::StandardPrincipalData;
    use stacks_common::consts::CHAIN_ID_TESTNET;
    use stacks_common::types::StacksEpochId;

    use super::*;

    const COUNTER: &str = "(define-data-var count uint u0)
        (define-read-only (get-count) (var-get count))
        (define-public (increment)
          (begin
            (print (var-get count))
            (ok (var-set count (+ (var-get count) u1)))))";

    fn setup_store(epoch: StacksEpochId) -> MemoryBackingStore {
        let mut store = MemoryBackingStore::new();
        let mut db = store.as_clarity_db();
        db.begin();
        db.set_clarity_epoch_version(epoch).unwrap();
        db.commit().unwrap();
        store
    }

    #[test]
    fn owns_clarity6_analysis_handles() {
        let mut store = setup_store(StacksEpochId::Epoch40);
        let id = QualifiedContractIdentifier::local("clarity6-owned").unwrap();
        let engine = Clarity6Engine;
        let mut ctx = TransactionContext::new(
            store.as_clarity_db(),
            false,
            CHAIN_ID_TESTNET,
            StacksEpochId::Epoch40,
        )
        .with_budget(CostBudget::Free);

        let wrong_version = engine.analyze_contract(
            &mut ctx,
            &id,
            COUNTER,
            ClarityVersion::Clarity5,
            &ResourceBudget::unlimited(),
        );
        assert!(matches!(wrong_version, Err(EngineError::Internal(_))));

        let analyzed = engine
            .analyze_contract(
                &mut ctx,
                &id,
                COUNTER,
                ClarityVersion::Clarity6,
                &ResourceBudget::unlimited(),
            )
            .unwrap();
        assert_eq!(analyzed.version(), ClarityVersion::Clarity6);

        let foreign_result = LEGACY_EXECUTOR.initialize_contract(
            &mut ctx,
            &analyzed,
            None,
            None,
            &ResourceBudget::unlimited(),
        );
        assert!(matches!(foreign_result, Err(EngineError::Internal(_))));

        engine
            .initialize_contract(
                &mut ctx,
                &analyzed,
                None,
                None,
                &ResourceBudget::unlimited(),
            )
            .unwrap();
        engine.save_analysis(&mut ctx, &analyzed).unwrap();
    }

    #[test]
    fn revision_one_matches_legacy_clarity6_in_epoch40_and_epoch41() {
        for epoch in [StacksEpochId::Epoch40, StacksEpochId::Epoch41] {
            let id = QualifiedContractIdentifier::local("behavior-parity").unwrap();
            let sender: PrincipalData = StandardPrincipalData::transient().into();

            let mut legacy_store = setup_store(epoch);
            let mut legacy_ctx = TransactionContext::new(
                legacy_store.as_clarity_db(),
                false,
                CHAIN_ID_TESTNET,
                epoch,
            )
            .with_budget(CostBudget::Limited(ExecutionCost::max_value()));
            let legacy_deploy = LEGACY_EXECUTOR
                .deploy_contract(
                    &mut legacy_ctx,
                    &id,
                    COUNTER,
                    ClarityVersion::Clarity6,
                    None,
                )
                .unwrap();
            let legacy_call = LEGACY_EXECUTOR
                .execute_call(
                    &mut legacy_ctx,
                    sender.clone(),
                    None,
                    &id,
                    "increment",
                    &[],
                    None,
                    &ResourceBudget::unlimited(),
                )
                .unwrap();

            let mut clarity6_store = setup_store(epoch);
            let mut clarity6_ctx = TransactionContext::new(
                clarity6_store.as_clarity_db(),
                false,
                CHAIN_ID_TESTNET,
                epoch,
            )
            .with_budget(CostBudget::Limited(ExecutionCost::max_value()));
            let clarity6 = Clarity6Engine;
            let clarity6_deploy = clarity6
                .deploy_contract(
                    &mut clarity6_ctx,
                    &id,
                    COUNTER,
                    ClarityVersion::Clarity6,
                    None,
                )
                .unwrap();
            let clarity6_call = clarity6
                .execute_call(
                    &mut clarity6_ctx,
                    sender.clone(),
                    None,
                    &id,
                    "increment",
                    &[],
                    None,
                    &ResourceBudget::unlimited(),
                )
                .unwrap();

            assert_eq!(clarity6_call.value, legacy_call.value);
            assert_eq!(clarity6_call.assets, legacy_call.assets);
            assert_eq!(clarity6_call.events, legacy_call.events);
            assert_eq!(clarity6_deploy.cost, legacy_deploy.cost);
            assert_eq!(clarity6_call.cost, legacy_call.cost);

            let legacy_read = LEGACY_EXECUTOR
                .eval_read_only(&mut legacy_ctx, &id, "(get-count)")
                .unwrap();
            let clarity6_read = clarity6
                .eval_read_only(&mut clarity6_ctx, &id, "(get-count)")
                .unwrap();
            assert_eq!(clarity6_read, legacy_read);
        }
    }
}
