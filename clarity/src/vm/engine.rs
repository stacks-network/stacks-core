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

//! The legacy engine: this crate's interpreter (Clarity 1 through
//! [`ClarityVersion::latest`]) wrapped behind the kernel's [`Engine`] ABI.
//!
//! Deployment runs the full pipeline — parse, static analysis (persisted to
//! the metadata store), then evaluation of the top-level forms — charging
//! all three phases against the context's [`CostBudget`]. The cost tracker
//! is kept in the context's engine-state slot between interactions, so the
//! budget is enforced cumulatively across a whole transaction.
//!
//! v0 caveats, tracked in the extraction plan:
//! - A [`CostBudget::Limited`] tracker resolves cost functions from the
//!   database at first use, exactly like the node does; on a fresh store
//!   this requires the stored Clarity epoch to be 4.0 or later (where cost
//!   functions are Rust-implemented boot defaults rather than deployed
//!   contracts).
//! - `contract-call?` between contracts stays inside this engine; routing
//!   through [`ContractDispatcher`] is the mixed-engine milestone.

pub use clarity_kernel::engine::{
    ContractDispatcher, CostBudget, DeployOutcome, Engine, EngineError, ExecutionOutcome,
    TransactionContext,
};
use clarity_types::types::{PrincipalData, QualifiedContractIdentifier};
use clarity_types::{ClarityName, ClarityVersion, Value};

use crate::vm::SymbolicExpression;
use crate::vm::analysis::{AnalysisDatabase, run_analysis};
use crate::vm::ast::build_ast;
use crate::vm::contexts::OwnedEnvironment;
use crate::vm::costs::LimitedCostTracker;
use crate::vm::database::ClarityDatabase;
use crate::vm::errors::ClarityEvalError;
use crate::vm::resource_limiter::ResourceLimiter;

/// The interpreter-backed engine for all legacy Clarity versions.
pub struct LegacyEngine;

fn engine_error(err: ClarityEvalError) -> EngineError {
    match err {
        ClarityEvalError::Vm(e) => EngineError::Execution(e),
        ClarityEvalError::Parse(e) => EngineError::Parse(vec![e.diagnostic]),
    }
}

impl LegacyEngine {
    /// Recover the transaction's cost tracker from the context, or build a
    /// fresh one from its budget on the first interaction.
    fn take_tracker(
        &self,
        ctx: &mut TransactionContext,
        db: &mut ClarityDatabase,
    ) -> Result<LimitedCostTracker, EngineError> {
        if let Some(tracker) = ctx.take_engine_state::<LimitedCostTracker>() {
            return Ok(*tracker);
        }
        match &ctx.budget {
            CostBudget::Free => Ok(LimitedCostTracker::new_free()),
            CostBudget::Limited(limit) => {
                LimitedCostTracker::new(ctx.mainnet, ctx.chain_id, limit.clone(), db, ctx.epoch)
                    .map_err(|e| {
                        EngineError::Internal(format!("Failed to initialize cost tracker: {e}"))
                    })
            }
        }
    }

    /// Park the tracker back in the context for the next interaction, and
    /// report the cumulative cost consumed so far.
    fn park_tracker(
        &self,
        ctx: &mut TransactionContext,
        tracker: LimitedCostTracker,
    ) -> clarity_kernel::costs::ExecutionCost {
        let cost = tracker.get_total();
        ctx.set_engine_state(tracker);
        cost
    }

    /// Run `interact` inside an [`OwnedEnvironment`] assembled from the
    /// transaction context's parts, restoring the database and cost tracker
    /// afterwards — including on error paths. Returns the interaction result
    /// together with the cumulative cost consumed in this context.
    fn with_env<F, R>(
        &self,
        ctx: &mut TransactionContext,
        interact: F,
    ) -> Result<(R, clarity_kernel::costs::ExecutionCost), EngineError>
    where
        F: FnOnce(&mut OwnedEnvironment) -> Result<R, EngineError>,
    {
        let mut db = ctx.take_db()?;
        let tracker = match self.take_tracker(ctx, &mut db) {
            Ok(tracker) => tracker,
            Err(e) => {
                ctx.restore_db(db);
                return Err(e);
            }
        };
        let mut env =
            OwnedEnvironment::new_cost_limited(ctx.mainnet, ctx.chain_id, db, tracker, ctx.epoch);
        let result = interact(&mut env);
        let (db, tracker) = env
            .destruct()
            .ok_or_else(|| EngineError::Internal("OwnedEnvironment failed to destruct".into()))?;
        ctx.restore_db(db);
        let cost = self.park_tracker(ctx, tracker);
        result.map(|r| (r, cost))
    }
}

impl Engine for LegacyEngine {
    fn name(&self) -> &'static str {
        "clarity-legacy-interpreter"
    }

    fn supported_versions(&self) -> &'static [ClarityVersion] {
        ClarityVersion::ALL
    }

    fn deploy_contract(
        &self,
        ctx: &mut TransactionContext,
        contract: &QualifiedContractIdentifier,
        source: &str,
        version: ClarityVersion,
        sponsor: Option<PrincipalData>,
    ) -> Result<DeployOutcome, EngineError> {
        let mut db = ctx.take_db()?;
        let mut tracker = match self.take_tracker(ctx, &mut db) {
            Ok(tracker) => tracker,
            Err(e) => {
                ctx.restore_db(db);
                return Err(e);
            }
        };

        // 1) Parse, charging the tracker.
        let ast = match build_ast(contract, source, &mut tracker, version, ctx.epoch) {
            Ok(ast) => ast,
            Err(e) => {
                ctx.restore_db(db);
                self.park_tracker(ctx, tracker);
                return Err(EngineError::Parse(vec![e.diagnostic]));
            }
        };

        // 2) Static analysis, persisted to the metadata store. The analysis
        // database wraps the bare backing store, so take the database apart
        // and reassemble it afterwards.
        let headers_db = db.get_headers_db();
        let burn_state_db = db.get_burn_state_db();
        let store = db.destroy().into_store();
        let analysis_result = {
            let mut analysis_db = AnalysisDatabase::new(&mut *store);
            run_analysis(
                contract,
                &ast.expressions,
                &mut analysis_db,
                true,
                tracker,
                ctx.epoch,
                version,
                false,
                ResourceLimiter::unlimited(),
            )
        };
        ctx.restore_db(ClarityDatabase::new(&mut *store, headers_db, burn_state_db));
        match analysis_result {
            Ok(mut analysis) => {
                let tracker = analysis.take_contract_cost_tracker();
                self.park_tracker(ctx, tracker);
            }
            Err(boxed) => {
                let (check_error, tracker) = *boxed;
                self.park_tracker(ctx, tracker);
                return Err(EngineError::Static(Box::new(check_error)));
            }
        }

        // 3) Evaluate the top-level forms and persist the contract.
        let (((), assets, events), cost) = self.with_env(ctx, |env| {
            env.initialize_contract_from_ast(contract.clone(), version, &ast, source, sponsor)
                .map_err(EngineError::Execution)
        })?;
        Ok(DeployOutcome {
            assets,
            events,
            cost,
        })
    }

    fn execute_call(
        &self,
        ctx: &mut TransactionContext,
        sender: PrincipalData,
        sponsor: Option<PrincipalData>,
        contract: &QualifiedContractIdentifier,
        function: &ClarityName,
        args: &[Value],
    ) -> Result<ExecutionOutcome, EngineError> {
        let ((value, assets, events), cost) = self.with_env(ctx, |env| {
            let args: Vec<_> = args
                .iter()
                .map(|arg| SymbolicExpression::atom_value(arg.clone()))
                .collect();
            env.execute_transaction(sender, sponsor, contract.clone(), function, &args)
                .map_err(EngineError::Execution)
        })?;
        Ok(ExecutionOutcome {
            value,
            assets,
            events,
            cost,
        })
    }

    fn eval_read_only(
        &self,
        ctx: &mut TransactionContext,
        contract: &QualifiedContractIdentifier,
        program: &str,
    ) -> Result<Value, EngineError> {
        let ((value, _assets, _events), _cost) = self.with_env(ctx, |env| {
            env.eval_read_only(contract, program).map_err(engine_error)
        })?;
        Ok(value)
    }
}

#[cfg(test)]
mod tests {
    use clarity_kernel::costs::ExecutionCost;
    use stacks_common::consts::CHAIN_ID_TESTNET;
    use stacks_common::types::StacksEpochId;

    use super::*;
    use crate::vm::database::{ClarityDatabaseExt, MemoryBackingStore};
    use crate::vm::types::StandardPrincipalData;

    const COUNTER: &str = "(define-data-var count uint u0)
         (define-read-only (get-count) (var-get count))
         (define-public (increment)
           (ok (var-set count (+ (var-get count) u1))))";

    fn setup_store(epoch: StacksEpochId) -> MemoryBackingStore {
        let mut store = MemoryBackingStore::new();
        {
            let mut db = store.as_clarity_db();
            db.begin();
            db.set_clarity_epoch_version(epoch).unwrap();
            db.commit().unwrap();
        }
        store
    }

    fn contract_id(name: &str) -> QualifiedContractIdentifier {
        QualifiedContractIdentifier::new(
            StandardPrincipalData::transient(),
            name.to_string().try_into().unwrap(),
        )
    }

    #[test]
    fn deploy_call_and_read_through_abi_with_metered_costs() {
        let epoch = StacksEpochId::latest();
        let mut store = setup_store(epoch);
        let engine = LegacyEngine;
        let id = contract_id("counter");
        let sender: PrincipalData = StandardPrincipalData::transient().into();

        let mut ctx =
            TransactionContext::new(store.as_clarity_db(), false, CHAIN_ID_TESTNET, epoch)
                .with_budget(CostBudget::Limited(ExecutionCost::max_value()));

        let deploy = engine
            .deploy_contract(&mut ctx, &id, COUNTER, ClarityVersion::latest(), None)
            .unwrap();
        assert!(deploy.cost.runtime > 0, "deploy must consume budget");

        let call = engine
            .execute_call(
                &mut ctx,
                sender,
                None,
                &id,
                &ClarityName::from_literal("increment"),
                &[],
            )
            .unwrap();
        assert_eq!(call.value, Value::okay(Value::Bool(true)).unwrap());
        assert!(
            call.cost.runtime > deploy.cost.runtime,
            "cost must accumulate across interactions in one context"
        );

        let count = engine.eval_read_only(&mut ctx, &id, "(get-count)").unwrap();
        assert_eq!(count, Value::UInt(1));
    }

    #[test]
    fn deploy_persists_contract_analysis() {
        let epoch = StacksEpochId::latest();
        let mut store = setup_store(epoch);
        let engine = LegacyEngine;
        let id = contract_id("analyzed");

        let mut ctx =
            TransactionContext::new(store.as_clarity_db(), false, CHAIN_ID_TESTNET, epoch);
        engine
            .deploy_contract(&mut ctx, &id, COUNTER, ClarityVersion::latest(), None)
            .unwrap();

        let mut db = ctx.into_db().unwrap();
        db.begin();
        let analysis = db.load_contract_analysis(&id).unwrap();
        db.roll_back().unwrap();
        let analysis = analysis.expect("deploy must persist the contract analysis");
        assert!(analysis.read_only_function_types.contains_key("get-count"));
        assert!(analysis.public_function_types.contains_key("increment"));
    }

    #[test]
    fn exhausted_budget_fails_and_context_stays_usable() {
        let epoch = StacksEpochId::latest();
        let mut store = setup_store(epoch);
        let engine = LegacyEngine;
        let id = contract_id("broke");

        // A one-runtime-unit budget cannot even parse the contract.
        let mut ctx =
            TransactionContext::new(store.as_clarity_db(), false, CHAIN_ID_TESTNET, epoch)
                .with_budget(CostBudget::Limited(ExecutionCost {
                    runtime: 1,
                    ..ExecutionCost::ZERO
                }));

        let err = engine
            .deploy_contract(&mut ctx, &id, COUNTER, ClarityVersion::latest(), None)
            .unwrap_err();
        // Budget exhaustion during parsing surfaces as a parse failure; the
        // important property is that it fails rather than executing free.
        assert!(
            matches!(err, EngineError::Parse(_) | EngineError::Execution(_)),
            "unexpected error variant: {err:?}"
        );

        // The context must have its database (and tracker) restored.
        assert!(ctx.into_db().is_some());
    }

    #[test]
    fn static_check_failure_is_reported_and_not_deployed() {
        let epoch = StacksEpochId::latest();
        let mut store = setup_store(epoch);
        let engine = LegacyEngine;
        let id = contract_id("illtyped");

        let mut ctx =
            TransactionContext::new(store.as_clarity_db(), false, CHAIN_ID_TESTNET, epoch);
        let err = engine
            .deploy_contract(
                &mut ctx,
                &id,
                "(define-public (bad) (ok (+ u1 1)))",
                ClarityVersion::latest(),
                None,
            )
            .unwrap_err();
        assert!(
            matches!(err, EngineError::Static(_)),
            "unexpected error variant: {err:?}"
        );

        let mut db = ctx.into_db().unwrap();
        db.begin();
        assert!(!db.has_contract(&id), "failed deploy must not persist");
        db.roll_back().unwrap();
    }

    #[test]
    fn parse_failure_carries_diagnostics() {
        let epoch = StacksEpochId::latest();
        let mut store = setup_store(epoch);
        let engine = LegacyEngine;

        let mut ctx =
            TransactionContext::new(store.as_clarity_db(), false, CHAIN_ID_TESTNET, epoch);
        let err = engine
            .deploy_contract(
                &mut ctx,
                &contract_id("unparsable"),
                "(define-public (broken",
                ClarityVersion::latest(),
                None,
            )
            .unwrap_err();
        match err {
            EngineError::Parse(diagnostics) => assert!(!diagnostics.is_empty()),
            other => panic!("unexpected error variant: {other:?}"),
        }
    }
}
