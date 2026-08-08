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

#![allow(dead_code)]
#![allow(non_camel_case_types)]
#![allow(non_snake_case)]
#![allow(non_upper_case_globals)]
#![cfg_attr(test, allow(unused_variables, unused_assignments))]

//! The pinned Clarity 6 engine, introduced with Stacks epoch 4.0.
//!
//! Revision 1 establishes Clarity 6 as a separately linkable engine behind
//! the kernel ABI. The engine owns its interpreter sources, ABI orchestration,
//! parsed/analyzed contract representation, rollback lifecycle, and entry
//! points. Real epoch-4.0 and epoch-4.1 contracts route through this engine,
//! making every extraction step testable against mainnet history.

#[allow(unused_imports)]
#[macro_use(o, slog_log, slog_trace, slog_debug, slog_info, slog_warn, slog_error)]
extern crate slog;

#[macro_use]
extern crate serde_derive;

extern crate serde_json;

#[macro_use]
extern crate stacks_common;

pub use stacks_common::{
    codec, consts, impl_array_hexstring_fmt, impl_array_newtype, impl_byte_array_message_codec,
    impl_byte_array_serde, types, util,
};

#[macro_use]
pub mod vm;

pub mod boot_util {
    use stacks_common::types::chainstate::StacksAddress;

    use crate::vm::representations::ContractName;
    use crate::vm::types::QualifiedContractIdentifier;

    #[allow(clippy::expect_used)]
    pub fn boot_code_id(name: &str, mainnet: bool) -> QualifiedContractIdentifier {
        let addr = boot_code_addr(mainnet);
        QualifiedContractIdentifier::new(
            addr.into(),
            ContractName::try_from(name.to_string())
                .expect("FATAL: boot contract name is not a legal ContractName"),
        )
    }

    pub fn boot_code_addr(mainnet: bool) -> StacksAddress {
        StacksAddress::burn_address(mainnet)
    }
}

use clarity_kernel::assets::AssetMap;
use clarity_kernel::costs::{CostTrackerHandle, ExecutionCost};
use clarity_kernel::engine::{
    AbortCallback, AnalyzedContract, ContractDispatcher, CostBudget, DeployOutcome, Engine,
    EngineError, ExecutionOutcome, TransactionContext,
};
use clarity_kernel::events::StacksTransactionEvent;
use clarity_kernel::resource_limiter::ResourceBudget;
use clarity_kernel::transaction::{CallStack, TransactionFrame};
use clarity_types::types::{PrincipalData, QualifiedContractIdentifier};
use clarity_types::{ClarityVersion, Value};
use stacks_common::types::StacksEpochId;

use crate::vm::SymbolicExpression;
use crate::vm::analysis::{AnalysisDatabase, ContractAnalysis, run_analysis};
use crate::vm::ast::errors::{ParseError, ParseErrorKind};
use crate::vm::ast::{ContractAST, build_ast};
use crate::vm::contexts::OwnedEnvironment;
use crate::vm::costs::LimitedCostTracker;
use crate::vm::database::ClarityDatabase;
use crate::vm::errors::ClarityEvalError;

const SUPPORTED_VERSIONS: &[ClarityVersion] = &[ClarityVersion::Clarity6];

/// The first separately linkable Clarity 6 consensus revision.
pub struct Clarity6Engine;

/// Clarity 6's private analyzed representation.
///
/// The host and other engines only see the kernel's stored interface.
struct Clarity6Analysis {
    ast: ContractAST,
    analysis: ContractAnalysis,
}

/// The engine's working parts, taken out of a transaction context for one
/// interaction and returned on every success and error path.
struct TakenParts<'a> {
    tracker: CostTrackerHandle,
    db: ClarityDatabase<'a>,
}

struct ExecutionParts<'a> {
    core: TakenParts<'a>,
    transaction: TransactionFrame,
    call_stack: CallStack,
    dispatcher: Option<Box<dyn ContractDispatcher>>,
}

type Produced<R> = (R, AssetMap, Vec<StacksTransactionEvent>);
type InteractionOutcome<R> = Result<(Produced<R>, ExecutionCost), EngineError>;

fn parse_engine_error(err: ParseError, epoch: StacksEpochId) -> EngineError {
    match &*err.err {
        ParseErrorKind::CostOverflow | ParseErrorKind::MemoryBalanceExceeded(..) => {
            EngineError::Cost(ExecutionCost::max_value(), ExecutionCost::max_value())
        }
        ParseErrorKind::CostBalanceExceeded(total, limit) => {
            EngineError::Cost(total.clone(), limit.clone())
        }
        _ => EngineError::Parse {
            rejectable: err.rejectable_in_epoch(epoch),
            diagnostics: vec![err.diagnostic],
        },
    }
}

fn engine_error(err: ClarityEvalError, epoch: StacksEpochId) -> EngineError {
    match err {
        ClarityEvalError::Vm(e) => EngineError::Execution(e),
        ClarityEvalError::Parse(e) => parse_engine_error(e, epoch),
    }
}

impl Clarity6Engine {
    fn analysis(analyzed: &AnalyzedContract) -> Result<&Clarity6Analysis, EngineError> {
        analyzed.engine_data::<Clarity6Analysis>().ok_or_else(|| {
            EngineError::Internal(
                "AnalyzedContract was not produced by clarity-v6 revision 1".into(),
            )
        })
    }

    fn take_or_create_tracker(
        &self,
        ctx: &mut TransactionContext,
        db: &mut ClarityDatabase,
    ) -> Result<CostTrackerHandle, EngineError> {
        if let Some(tracker) = ctx.take_cost_tracker() {
            return Ok(tracker);
        }
        let tracker = match &ctx.budget {
            CostBudget::Free => LimitedCostTracker::new_free(),
            CostBudget::Limited(limit) => {
                LimitedCostTracker::new(ctx.mainnet, ctx.chain_id, limit.clone(), db, ctx.epoch)
                    .map_err(|e| {
                        EngineError::Internal(format!("Failed to initialize cost tracker: {e}"))
                    })?
            }
        };
        Ok(CostTrackerHandle::new(tracker))
    }

    fn take_parts<'a>(
        &self,
        ctx: &mut TransactionContext<'a>,
    ) -> Result<TakenParts<'a>, EngineError> {
        let mut db = ctx.take_db()?;
        match self.take_or_create_tracker(ctx, &mut db) {
            Ok(tracker) => Ok(TakenParts { tracker, db }),
            Err(e) => {
                ctx.restore_db(db);
                Err(e)
            }
        }
    }

    fn take_execution_parts<'a>(
        &self,
        ctx: &mut TransactionContext<'a>,
    ) -> Result<ExecutionParts<'a>, EngineError> {
        let core = self.take_parts(ctx)?;
        let transaction = match ctx.take_transaction_frame() {
            Ok(transaction) => transaction,
            Err(e) => {
                ctx.restore_db(core.db);
                self.park_tracker(ctx, core.tracker);
                return Err(e);
            }
        };
        let call_stack = match ctx.take_call_stack() {
            Ok(call_stack) => call_stack,
            Err(e) => {
                ctx.restore_transaction_frame(transaction);
                ctx.restore_db(core.db);
                self.park_tracker(ctx, core.tracker);
                return Err(e);
            }
        };
        Ok(ExecutionParts {
            core,
            transaction,
            call_stack,
            dispatcher: ctx.take_dispatcher(),
        })
    }

    fn park_tracker(
        &self,
        ctx: &mut TransactionContext,
        tracker: CostTrackerHandle,
    ) -> ExecutionCost {
        let cost = tracker.get_total();
        ctx.restore_cost_tracker(tracker);
        cost
    }

    fn park_runtime(
        &self,
        ctx: &mut TransactionContext,
        tracker: CostTrackerHandle,
        transaction: TransactionFrame,
        call_stack: CallStack,
        dispatcher: Option<Box<dyn ContractDispatcher>>,
    ) -> ExecutionCost {
        ctx.restore_transaction_frame(transaction);
        ctx.restore_call_stack(call_stack);
        if let Some(dispatcher) = dispatcher {
            ctx.restore_dispatcher(dispatcher);
        }
        self.park_tracker(ctx, tracker)
    }

    fn with_abortable_env<'a, F, R>(
        &self,
        ctx: &mut TransactionContext<'a>,
        parts: ExecutionParts<'a>,
        execution_budget: &ResourceBudget,
        abort: Option<AbortCallback>,
        output_for_abort: fn(&R) -> Option<Box<Value>>,
        interact: F,
    ) -> InteractionOutcome<R>
    where
        F: FnOnce(&mut OwnedEnvironment) -> Result<Produced<R>, EngineError>,
    {
        let ExecutionParts {
            core: TakenParts { tracker, mut db },
            transaction,
            call_stack,
            mut dispatcher,
        } = parts;
        db.begin();
        let dispatcher_ref = dispatcher
            .as_mut()
            .map(|dispatcher| &mut **dispatcher as &mut (dyn ContractDispatcher + '_));
        let mut env = OwnedEnvironment::new_with_dispatcher(
            ctx.mainnet,
            ctx.chain_id,
            db,
            tracker,
            transaction,
            call_stack,
            ctx.epoch,
            dispatcher_ref,
        );
        env.set_execution_resource_limiter(execution_budget.start_tracking());
        let result = interact(&mut env);
        let (mut db, tracker, transaction, call_stack) = env
            .destruct_with_shared_transaction()
            .ok_or_else(|| EngineError::Internal("OwnedEnvironment failed to destruct".into()))?;

        match result {
            Ok((value, assets, events)) => {
                let abort_reason = match abort {
                    Some(callback) => callback(&assets, &mut db),
                    None => None,
                };
                match abort_reason {
                    Some(reason) => {
                        let rolled_back = db.roll_back().map_err(EngineError::Execution);
                        ctx.restore_db(db);
                        self.park_runtime(ctx, tracker, transaction, call_stack, dispatcher);
                        rolled_back?;
                        Err(EngineError::AbortedByCallback {
                            output: output_for_abort(&value),
                            assets: Box::new(assets),
                            events,
                            reason,
                        })
                    }
                    None => {
                        let committed = db.commit().map_err(EngineError::Execution);
                        ctx.restore_db(db);
                        let cost =
                            self.park_runtime(ctx, tracker, transaction, call_stack, dispatcher);
                        committed?;
                        Ok(((value, assets, events), cost))
                    }
                }
            }
            Err(e) => {
                let rolled_back = db.roll_back().map_err(EngineError::Execution);
                ctx.restore_db(db);
                self.park_runtime(ctx, tracker, transaction, call_stack, dispatcher);
                rolled_back?;
                Err(e)
            }
        }
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

        let TakenParts { mut tracker, db } = self.take_parts(ctx)?;
        let resource_limiter = analysis_budget.start_tracking();

        let ast = match build_ast(
            contract,
            source,
            &mut tracker,
            ClarityVersion::Clarity6,
            ctx.epoch,
        ) {
            Ok(ast) => ast,
            Err(e) => {
                ctx.restore_db(db);
                self.park_tracker(ctx, tracker);
                return Err(parse_engine_error(e, ctx.epoch));
            }
        };

        let headers_db = db.get_headers_db();
        let burn_state_db = db.get_burn_state_db();
        let mut analysis_db = AnalysisDatabase::new_with_rollback_wrapper(db.destroy());
        let analysis_result = run_analysis(
            contract,
            &ast.expressions,
            &mut analysis_db,
            false,
            tracker,
            ctx.epoch,
            ClarityVersion::Clarity6,
            false,
            resource_limiter,
        );
        ctx.restore_db(ClarityDatabase::new_with_rollback_wrapper(
            analysis_db.destroy(),
            headers_db,
            burn_state_db,
        ));

        match analysis_result {
            Ok(mut analysis) => {
                let tracker = analysis.take_contract_cost_tracker();
                let interface = analysis.to_stored();
                self.park_tracker(ctx, tracker);
                debug_assert_eq!(interface.contract_identifier, *contract);
                debug_assert_eq!(interface.clarity_version, ClarityVersion::Clarity6);
                Ok(AnalyzedContract::new(
                    source.to_owned(),
                    interface,
                    Clarity6Analysis { ast, analysis },
                ))
            }
            Err(boxed) => {
                let (check_error, tracker) = *boxed;
                self.park_tracker(ctx, tracker);
                Err(EngineError::Static(Box::new(check_error)))
            }
        }
    }

    fn initialize_contract(
        &self,
        ctx: &mut TransactionContext,
        analyzed: &AnalyzedContract,
        sponsor: Option<PrincipalData>,
        abort: Option<AbortCallback>,
        execution_budget: &ResourceBudget,
    ) -> Result<DeployOutcome, EngineError> {
        let parts = self.take_execution_parts(ctx)?;
        let analysis = match Self::analysis(analyzed) {
            Ok(analysis) => analysis,
            Err(e) => {
                ctx.restore_db(parts.core.db);
                self.park_runtime(
                    ctx,
                    parts.core.tracker,
                    parts.transaction,
                    parts.call_stack,
                    parts.dispatcher,
                );
                return Err(e);
            }
        };

        let (((), assets, events), cost) = self.with_abortable_env(
            ctx,
            parts,
            execution_budget,
            abort,
            |_: &()| None,
            |env| {
                env.initialize_contract_from_ast(
                    analyzed.contract().clone(),
                    ClarityVersion::Clarity6,
                    &analysis.ast,
                    analyzed.source(),
                    sponsor,
                )
                .map_err(EngineError::Execution)
            },
        )?;
        Ok(DeployOutcome {
            assets,
            events,
            cost,
        })
    }

    fn save_analysis(
        &self,
        ctx: &mut TransactionContext,
        analyzed: &AnalyzedContract,
    ) -> Result<(), EngineError> {
        let TakenParts { tracker, db } = self.take_parts(ctx)?;
        let analysis = match Self::analysis(analyzed) {
            Ok(analysis) => analysis,
            Err(e) => {
                ctx.restore_db(db);
                self.park_tracker(ctx, tracker);
                return Err(e);
            }
        };

        let headers_db = db.get_headers_db();
        let burn_state_db = db.get_burn_state_db();
        let mut analysis_db = AnalysisDatabase::new_with_rollback_wrapper(db.destroy());
        analysis_db.begin();
        let result = match analysis_db.insert_contract(analyzed.contract(), &analysis.analysis) {
            Ok(()) => analysis_db
                .commit()
                .map_err(|e| EngineError::Static(Box::new(e))),
            Err(e) => {
                let rolled_back = analysis_db
                    .roll_back()
                    .map_err(|e| EngineError::Static(Box::new(e)));
                rolled_back.and(Err(EngineError::Static(Box::new(e))))
            }
        };
        ctx.restore_db(ClarityDatabase::new_with_rollback_wrapper(
            analysis_db.destroy(),
            headers_db,
            burn_state_db,
        ));
        self.park_tracker(ctx, tracker);
        result
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
        let parts = self.take_execution_parts(ctx)?;
        let expr_args: Vec<_> = args
            .iter()
            .map(|arg| SymbolicExpression::atom_value(arg.clone()))
            .collect();
        let ((value, assets, events), cost) = self.with_abortable_env(
            ctx,
            parts,
            execution_budget,
            abort,
            |value: &Value| Some(Box::new(value.clone())),
            |env| {
                env.execute_transaction(sender, sponsor, contract.clone(), function, &expr_args)
                    .map_err(EngineError::Execution)
            },
        )?;
        Ok(ExecutionOutcome {
            value,
            assets,
            events,
            cost,
        })
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
        let ExecutionParts {
            core: TakenParts { tracker, db },
            transaction,
            call_stack,
            dispatcher: parked_dispatcher,
        } = self.take_execution_parts(ctx)?;
        let mut env = OwnedEnvironment::new_with_dispatcher(
            ctx.mainnet,
            ctx.chain_id,
            db,
            tracker,
            transaction,
            call_stack,
            ctx.epoch,
            Some(dispatcher),
        );
        env.set_execution_resource_limiter(ctx.execution_resource_limiter());
        let expr_args: Vec<_> = args
            .iter()
            .map(|arg| SymbolicExpression::atom_value(arg.clone()))
            .collect();
        let result = env
            .execute_nested_transaction(sender, caller, sponsor, contract, function, &expr_args)
            .map_err(EngineError::Execution);
        let (db, tracker, transaction, call_stack) = env
            .destruct_nested_with_shared_transaction()
            .ok_or_else(|| EngineError::Internal("OwnedEnvironment failed to destruct".into()))?;
        ctx.restore_db(db);
        self.park_runtime(ctx, tracker, transaction, call_stack, parked_dispatcher);
        result
    }

    fn eval_read_only(
        &self,
        ctx: &mut TransactionContext,
        contract: &QualifiedContractIdentifier,
        program: &str,
    ) -> Result<Value, EngineError> {
        let ExecutionParts {
            core: TakenParts { tracker, db },
            transaction,
            call_stack,
            mut dispatcher,
        } = self.take_execution_parts(ctx)?;
        let dispatcher_ref = dispatcher
            .as_mut()
            .map(|dispatcher| &mut **dispatcher as &mut (dyn ContractDispatcher + '_));
        let mut env = OwnedEnvironment::new_with_dispatcher(
            ctx.mainnet,
            ctx.chain_id,
            db,
            tracker,
            transaction,
            call_stack,
            ctx.epoch,
            dispatcher_ref,
        );
        let result = env
            .eval_read_only(contract, program)
            .map_err(|err| engine_error(err, ctx.epoch));
        let (db, tracker, transaction, call_stack) = env
            .destruct_with_shared_transaction()
            .ok_or_else(|| EngineError::Internal("OwnedEnvironment failed to destruct".into()))?;
        ctx.restore_db(db);
        self.park_runtime(ctx, tracker, transaction, call_stack, dispatcher);
        result.map(|(value, _assets, _events)| value)
    }
}

#[cfg(test)]
mod tests {
    use clarity::vm::database::MemoryBackingStore;
    use clarity::vm::engine::LegacyEngine;
    use clarity_kernel::costs::ExecutionCost;
    use clarity_kernel::engine::CostBudget;
    use clarity_types::types::StandardPrincipalData;
    use stacks_common::consts::CHAIN_ID_TESTNET;
    use stacks_common::types::StacksEpochId;

    use super::*;

    static LEGACY_EXECUTOR: LegacyEngine = LegacyEngine;

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
    fn parser_cost_exhaustion_crosses_the_engine_abi() {
        let mut store = setup_store(StacksEpochId::Epoch40);
        let id = QualifiedContractIdentifier::local("clarity6-parser-cost").unwrap();
        let mut ctx = TransactionContext::new(
            store.as_clarity_db(),
            false,
            CHAIN_ID_TESTNET,
            StacksEpochId::Epoch40,
        )
        .with_budget(CostBudget::Limited(ExecutionCost::ZERO));

        let error = match Clarity6Engine.analyze_contract(
            &mut ctx,
            &id,
            COUNTER,
            ClarityVersion::Clarity6,
            &ResourceBudget::unlimited(),
        ) {
            Err(error) => error,
            Ok(_) => panic!("zero parser budget unexpectedly succeeded"),
        };
        assert!(matches!(error, EngineError::Cost(..)));
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
