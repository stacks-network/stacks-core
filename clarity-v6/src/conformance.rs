// Copyright (C) 2026 Stacks Open Internet Foundation
//
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.

//! Differential conformance scenarios for the independently owned Clarity 6
//! interpreter. These exercise only the engine ABI, so the same scenario
//! shape can be reused for future engine revisions.

use clarity::vm::database::MemoryBackingStore;
use clarity::vm::engine::LegacyEngine;
use clarity_kernel::analysis::StoredContractAnalysis;
use clarity_kernel::assets::AssetMap;
use clarity_kernel::costs::ExecutionCost;
use clarity_kernel::database::ClarityDatabase;
use clarity_kernel::engine::{
    CostBudget, Engine, EngineError, ExecutionOutcome, TransactionContext,
};
use clarity_kernel::events::StacksTransactionEvent;
use clarity_kernel::resource_limiter::ResourceBudget;
use clarity_types::types::{PrincipalData, QualifiedContractIdentifier, StandardPrincipalData};
use clarity_types::{ClarityVersion, Value};
use stacks_common::consts::CHAIN_ID_TESTNET;
use stacks_common::types::StacksEpochId;

use crate::Clarity6Engine;

static LEGACY: LegacyEngine = LegacyEngine;
static CLARITY6: Clarity6Engine = Clarity6Engine;
const GOLDEN_VECTORS: &str = include_str!("../tests/vectors/clarity6-v1.json");

const ANALYSIS_SURFACE: &str = "
    (define-trait balance-trait
      ((balance-of (principal) (response uint uint))))
    (define-data-var owner principal tx-sender)
    (define-map balances principal uint)
    (define-fungible-token coin)
    (define-non-fungible-token collectible uint)
    (define-private (next (amount uint)) (+ amount u1))
    (define-read-only (read (who principal))
      (default-to u0 (map-get? balances who)))
    (define-public (write (amount uint))
      (begin
        (map-set balances tx-sender amount)
        (ok (next amount))))";

const RUNTIME_SURFACE: &str = "
    (define-data-var count uint u0)
    (define-fungible-token coin)
    (define-read-only (get-count) (var-get count))
    (define-read-only (get-balance (who principal)) (ft-get-balance coin who))
    (define-public (transfer (amount uint) (recipient principal))
      (ft-transfer? coin amount tx-sender recipient))
    (define-public (exercise (amount uint))
      (begin
        (print amount)
        (var-set count (+ (var-get count) amount))
        (try! (ft-mint? coin amount tx-sender))
        (ok {
          count: (var-get count),
          values: (concat (list u1) (list u2 u3) (list u4))
        })))";

const RUNTIME_ROLLBACK: &str = "
    (define-data-var count uint u0)
    (define-read-only (get-count) (var-get count))
    (define-public (fail-after-write)
      (begin
        (var-set count u1)
        (/ u1 u0)
        (ok true)))";

#[derive(Debug, PartialEq)]
enum ErrorFingerprint {
    Parse {
        rejectable: bool,
        messages: Vec<String>,
    },
    Static(String),
    Cost(ExecutionCost, ExecutionCost),
    Execution(String),
    Aborted {
        output: Option<Value>,
        assets: Box<AssetMap>,
        events: Vec<StacksTransactionEvent>,
        reason: String,
    },
    Internal(String),
}

fn fingerprint(error: EngineError) -> ErrorFingerprint {
    match error {
        EngineError::Parse {
            diagnostics,
            rejectable,
        } => ErrorFingerprint::Parse {
            rejectable,
            messages: diagnostics
                .into_iter()
                .map(|diagnostic| diagnostic.message.to_string())
                .collect(),
        },
        EngineError::Static(error) => {
            ErrorFingerprint::Static(error.diagnostic.message.to_string())
        }
        EngineError::Cost(total, limit) => ErrorFingerprint::Cost(total, limit),
        EngineError::Execution(error) => ErrorFingerprint::Execution(error.to_string()),
        EngineError::AbortedByCallback {
            output,
            assets,
            events,
            reason,
        } => ErrorFingerprint::Aborted {
            output: output.map(|value| *value),
            assets,
            events,
            reason,
        },
        EngineError::Internal(message) => ErrorFingerprint::Internal(message),
    }
}

fn setup_store(epoch: StacksEpochId) -> MemoryBackingStore {
    let mut store = MemoryBackingStore::new();
    let mut db = store.as_clarity_db();
    db.begin();
    db.set_clarity_epoch_version(epoch).unwrap();
    db.commit().unwrap();
    store
}

fn contract_id(name: &str) -> QualifiedContractIdentifier {
    QualifiedContractIdentifier::new(
        StandardPrincipalData::transient(),
        name.to_string().try_into().unwrap(),
    )
}

fn test_ruleset(epoch: StacksEpochId) -> clarity_kernel::rules::KernelRuleset {
    if epoch >= StacksEpochId::Epoch41 {
        clarity_kernel::rules::KernelRuleset::V4
    } else {
        clarity_kernel::rules::KernelRuleset::V3
    }
}

fn analysis_result(
    engine: &dyn Engine,
    source: &str,
    epoch: StacksEpochId,
) -> (
    Result<StoredContractAnalysis, ErrorFingerprint>,
    ExecutionCost,
) {
    let mut store = setup_store(epoch);
    let mut context = TransactionContext::new(
        store.as_clarity_db(),
        false,
        CHAIN_ID_TESTNET,
        epoch,
        test_ruleset(epoch),
    )
    .with_budget(CostBudget::Limited(ExecutionCost::max_value()));
    let result = engine
        .analyze_contract(
            &mut context,
            &contract_id("analysis-conformance"),
            source,
            ClarityVersion::Clarity6,
            &ResourceBudget::unlimited(),
        )
        .map(|analyzed| analyzed.interface().clone())
        .map_err(fingerprint);
    let tracker = context
        .take_cost_tracker()
        .expect("analysis must restore the cumulative cost tracker");
    (result, tracker.get_total())
}

fn deployed_context<'a>(
    engine: &dyn Engine,
    store: &'a mut MemoryBackingStore,
    epoch: StacksEpochId,
    source: &str,
    name: &str,
) -> (
    TransactionContext<'a>,
    QualifiedContractIdentifier,
    ExecutionCost,
) {
    let id = contract_id(name);
    let mut context = TransactionContext::new(
        store.as_clarity_db(),
        false,
        CHAIN_ID_TESTNET,
        epoch,
        test_ruleset(epoch),
    )
    .with_budget(CostBudget::Limited(ExecutionCost::max_value()));
    let deployment = engine
        .deploy_contract(&mut context, &id, source, ClarityVersion::Clarity6, None)
        .unwrap();
    (context, id, deployment.cost)
}

fn run_exercise(
    engine: &dyn Engine,
    epoch: StacksEpochId,
) -> (ExecutionCost, ExecutionOutcome, Value, Value) {
    let mut store = setup_store(epoch);
    let (mut context, id, deploy_cost) =
        deployed_context(engine, &mut store, epoch, RUNTIME_SURFACE, "runtime");
    let sender: PrincipalData = StandardPrincipalData::transient().into();
    let outcome = engine
        .execute_call(
            &mut context,
            sender.clone(),
            None,
            &id,
            "exercise",
            &[Value::UInt(7)],
            None,
            &ResourceBudget::unlimited(),
        )
        .unwrap();
    let count = engine
        .eval_read_only(&mut context, &id, "(get-count)")
        .unwrap();
    let balance = engine
        .eval_read_only(&mut context, &id, &format!("(get-balance '{sender})"))
        .unwrap();
    (deploy_cost, outcome, count, balance)
}

#[test]
fn analysis_interfaces_errors_and_costs_match_legacy_clarity6() {
    for epoch in [StacksEpochId::Epoch40, StacksEpochId::Epoch41] {
        for source in [
            ANALYSIS_SURFACE,
            "(define-public (broken) (ok (+ true u1)))",
            "(define-public (unterminated) (ok true)",
        ] {
            let legacy = analysis_result(&LEGACY, source, epoch);
            let clarity6 = analysis_result(&CLARITY6, source, epoch);
            assert_eq!(clarity6, legacy, "analysis diverged for {source}");
        }
    }
}

#[test]
fn values_state_assets_events_and_costs_match_legacy_clarity6() {
    for epoch in [StacksEpochId::Epoch40, StacksEpochId::Epoch41] {
        let (legacy_deploy, legacy, legacy_count, legacy_balance) = run_exercise(&LEGACY, epoch);
        let (clarity6_deploy, clarity6, clarity6_count, clarity6_balance) =
            run_exercise(&CLARITY6, epoch);

        assert_eq!(clarity6_deploy, legacy_deploy);
        assert_eq!(clarity6.value, legacy.value);
        assert_eq!(clarity6.assets, legacy.assets);
        assert_eq!(clarity6.events, legacy.events);
        assert_eq!(clarity6.cost, legacy.cost);
        assert_eq!(clarity6_count, legacy_count);
        assert_eq!(clarity6_balance, legacy_balance);
        assert_eq!(clarity6_count, Value::UInt(7));
        assert_eq!(clarity6_balance, Value::UInt(7));
    }
}

fn run_runtime_failure(
    engine: &dyn Engine,
    epoch: StacksEpochId,
) -> (ErrorFingerprint, Value, ExecutionCost) {
    let mut store = setup_store(epoch);
    let (mut context, id, _) =
        deployed_context(engine, &mut store, epoch, RUNTIME_ROLLBACK, "rollback");
    let sender: PrincipalData = StandardPrincipalData::transient().into();
    let error = engine
        .execute_call(
            &mut context,
            sender,
            None,
            &id,
            "fail-after-write",
            &[],
            None,
            &ResourceBudget::unlimited(),
        )
        .map_err(fingerprint)
        .expect_err("the conformance call must fail");
    let count = engine
        .eval_read_only(&mut context, &id, "(get-count)")
        .unwrap();
    let tracker = context
        .take_cost_tracker()
        .expect("execution must restore the cumulative cost tracker");
    (error, count, tracker.get_total())
}

#[test]
fn runtime_errors_and_rollback_match_legacy_clarity6() {
    for epoch in [StacksEpochId::Epoch40, StacksEpochId::Epoch41] {
        let legacy = run_runtime_failure(&LEGACY, epoch);
        let clarity6 = run_runtime_failure(&CLARITY6, epoch);
        assert_eq!(clarity6, legacy);
        assert_eq!(clarity6.1, Value::UInt(0));
    }
}

fn run_host_abort(
    engine: &dyn Engine,
    epoch: StacksEpochId,
) -> (ErrorFingerprint, Value, Value, ExecutionCost) {
    let mut store = setup_store(epoch);
    let (mut context, id, _) =
        deployed_context(engine, &mut store, epoch, RUNTIME_SURFACE, "abort");
    let sender: PrincipalData = StandardPrincipalData::transient().into();
    engine
        .execute_call(
            &mut context,
            sender.clone(),
            None,
            &id,
            "exercise",
            &[Value::UInt(7)],
            None,
            &ResourceBudget::unlimited(),
        )
        .unwrap();
    let recipient = PrincipalData::Contract(contract_id("recipient"));
    fn abort(_assets: &AssetMap, _db: &mut ClarityDatabase<'_>) -> Option<String> {
        Some("conformance abort".to_string())
    }
    let mut abort = abort;
    let error = engine
        .execute_call(
            &mut context,
            sender.clone(),
            None,
            &id,
            "transfer",
            &[Value::UInt(3), Value::Principal(recipient.clone())],
            Some(&mut abort),
            &ResourceBudget::unlimited(),
        )
        .map_err(fingerprint)
        .expect_err("the host callback must abort the call");
    let sender_balance = engine
        .eval_read_only(&mut context, &id, &format!("(get-balance '{sender})"))
        .unwrap();
    let recipient_balance = engine
        .eval_read_only(&mut context, &id, &format!("(get-balance '{recipient})"))
        .unwrap();
    let tracker = context
        .take_cost_tracker()
        .expect("aborted execution must restore the cumulative cost tracker");
    (
        error,
        sender_balance,
        recipient_balance,
        tracker.get_total(),
    )
}

#[test]
fn host_aborts_assets_events_and_rollback_match_legacy_clarity6() {
    for epoch in [StacksEpochId::Epoch40, StacksEpochId::Epoch41] {
        let legacy = run_host_abort(&LEGACY, epoch);
        let clarity6 = run_host_abort(&CLARITY6, epoch);
        assert_eq!(clarity6, legacy);
        assert!(matches!(
            &clarity6.0,
            ErrorFingerprint::Aborted {
                assets,
                events,
                reason,
                ..
            } if assets.as_ref() != &AssetMap::new()
                && !events.is_empty()
                && reason == "conformance abort"
        ));
        assert_eq!(clarity6.1, Value::UInt(7));
        assert_eq!(clarity6.2, Value::UInt(0));
    }
}

#[test]
fn checked_in_vectors_match_the_frozen_legacy_oracle() {
    let suite = clarity_conformance::parse_suite(GOLDEN_VECTORS).unwrap();
    clarity_conformance::verify_suite(&LEGACY, &suite).unwrap();
}

/// Maintainer utility: run this ignored test with `--nocapture` to inspect a
/// recording. Set `CLARITY_V6_UPDATE_VECTORS` to a path to update a fixture.
#[test]
#[ignore = "prints regenerated conformance vectors"]
fn print_vectors_recorded_from_the_legacy_oracle() {
    let suite = clarity_conformance::parse_suite(GOLDEN_VECTORS).unwrap();
    let recorded = clarity_conformance::record_suite(&LEGACY, &suite).unwrap();
    let json = format!("{}\n", serde_json::to_string_pretty(&recorded).unwrap());
    if let Ok(path) = std::env::var("CLARITY_V6_UPDATE_VECTORS") {
        std::fs::write(path, &json).unwrap();
    }
    println!("{json}");
}

#[test]
fn generated_state_machine_cases_match_the_rust_model() {
    use clarity_conformance::{ObservationResult, VectorCase, VectorStep};
    use proptest::test_runner::{Config, TestRng, TestRunner};

    let config = Config {
        cases: 64,
        failure_persistence: None,
        ..Config::default()
    };
    let algorithm = config.rng_algorithm;
    let mut runner = TestRunner::new_with_rng(config, TestRng::deterministic_rng(algorithm));
    let strategy = (0u64..10_000, 0u64..10_000, 0usize..=6, proptest::bool::ANY);

    runner
        .run(&strategy, |(initial, delta, repetitions, epoch_41)| {
            let epoch = if epoch_41 {
                StacksEpochId::Epoch41
            } else {
                StacksEpochId::Epoch40
            };
            let source = format!(
                "(define-data-var total uint u{initial})\n\
             (define-read-only (get-total) (var-get total))\n\
             (define-public (add-to-total (amount uint)) \n\
               (begin \n\
                 (var-set total (+ (var-get total) amount)) \n\
                 (ok (var-get total))))"
            );
            let mut steps = vec![
                VectorStep::Analyze,
                VectorStep::Initialize,
                VectorStep::SaveAnalysis,
            ];
            steps.extend((0..repetitions).map(|_| VectorStep::Call {
                function: "add-to-total".into(),
                args: vec![clarity_conformance::encode_value(&Value::UInt(
                    delta.into(),
                ))],
                sender: None,
                sponsor: None,
                abort_reason: None,
            }));
            steps.push(VectorStep::ReadOnly {
                expression: "(get-total)".into(),
            });
            let case = VectorCase {
                name: "generated state machine".into(),
                epoch,
                language_version: ClarityVersion::Clarity6,
                contract_name: "generated-state".into(),
                source,
                steps,
                expected: vec![],
            };

            // Generated inputs exercise the same serialized format consumed by
            // checked-in vectors, not a privileged in-memory-only path.
            let serialized = serde_json::to_string(&case).unwrap();
            let case: VectorCase = serde_json::from_str(&serialized).unwrap();
            let observations = clarity_conformance::run_case(&CLARITY6, &case).unwrap();

            for (index, observation) in observations[3..3 + repetitions].iter().enumerate() {
                let expected = u128::from(initial) + u128::from(delta) * (index as u128 + 1);
                assert!(matches!(
                    &observation.result,
                    ObservationResult::Execution { value, assets, events }
                        if value == &format!("(ok u{expected})")
                            && assets == &AssetMap::new().to_json()
                            && events.is_empty()
                ));
            }
            let expected = u128::from(initial) + u128::from(delta) * repetitions as u128;
            assert!(matches!(
                &observations.last().unwrap().result,
                ObservationResult::ReadOnly { value } if value == &format!("u{expected}")
            ));
            assert!(
                observations
                    .windows(2)
                    .all(|pair| pair[0].cumulative_cost.runtime <= pair[1].cumulative_cost.runtime)
            );
            Ok(())
        })
        .unwrap();
}
