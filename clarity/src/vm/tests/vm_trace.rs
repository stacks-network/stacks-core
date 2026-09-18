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

#[cfg(any(test, feature = "testing"))]
use rstest::rstest;
use stacks_common::types::StacksEpochId;

use crate::vm::contexts::{ContractContext, MAX_EVENTS_BATCH, OwnedEnvironment};
use crate::vm::database::MemoryBackingStore;
use crate::vm::events::{StorageEvent, VmTraceEvent};
use crate::vm::tests::{
    TopLevelMemoryEnvironmentGenerator, is_committed, is_err_code, symbols_from_values,
    test_epochs, tl_env_factory,
};
use crate::vm::types::{PrincipalData, QualifiedContractIdentifier, Value};
use crate::vm::version::ClarityVersion;

const STORE: &str = r#"
(define-data-var n uint u0)
(define-map kv uint uint)
(define-public (set-n (x uint))
  (ok (var-set n x)))
(define-public (get-n)
  (ok (var-get n)))
(define-public (write-map (k uint) (v uint))
  (begin
    (map-set kv k v)
    (ok true)))
(define-public (insert-map (k uint) (v uint))
  (ok (map-insert kv k v)))
(define-public (delete-map (k uint))
  (ok (map-delete kv k)))
(define-public (print-and-set (x uint))
  (begin
    (print x)
    (ok (var-set n x))))
(define-public (fail-after-set)
  (begin
    (var-set n u9)
    (err u1)))
"#;

const CALLEE: &str = r#"
(define-data-var n uint u0)
(define-public (inc)
  (ok (var-set n (+ (var-get n) u1))))
(define-public (fail-after-set)
  (begin
    (var-set n u9)
    (err u1)))
"#;

const CALLER: &str = r#"
(define-public (go)
  (contract-call? .callee inc))
(define-public (observe-fail)
  (ok (contract-call? .callee fail-after-set)))
"#;

fn issuer() -> PrincipalData {
    QualifiedContractIdentifier::local("store")
        .unwrap()
        .issuer
        .into()
}

fn exec(
    env: &mut OwnedEnvironment,
    contract: &QualifiedContractIdentifier,
    name: &str,
    args: Vec<Value>,
) -> (Value, Vec<crate::vm::events::StacksTransactionEvent>) {
    let (value, _assets, events) = env
        .execute_transaction(
            issuer(),
            None,
            contract.clone(),
            name,
            &symbols_from_values(args),
        )
        .unwrap();
    (value, events)
}

fn store_id() -> QualifiedContractIdentifier {
    QualifiedContractIdentifier::local("store").unwrap()
}

fn init_store(env: &mut OwnedEnvironment, version: ClarityVersion) {
    env.initialize_versioned_contract(store_id(), version, STORE, None)
        .unwrap();
}

fn placeholder_ctx() -> ContractContext {
    ContractContext::new(
        QualifiedContractIdentifier::transient(),
        ClarityVersion::Clarity2,
    )
}

/// Invoke a public function on an already-`begin()`'d environment so the
/// caller can inspect the live event batch (classic `total_size`).
fn exec_on_batch(
    env: &mut OwnedEnvironment,
    contract: &QualifiedContractIdentifier,
    name: &str,
    args: Vec<Value>,
) -> Value {
    let ctx = placeholder_ctx();
    let (mut exec, invoke) = env.get_exec_environment(Some(issuer()), None, &ctx);
    exec.execute_contract(&invoke, contract, name, &symbols_from_values(args), false)
        .unwrap()
}

fn clarity_for_epoch(epoch: StacksEpochId) -> ClarityVersion {
    ClarityVersion::default_for_epoch(epoch)
}

#[apply(test_epochs)]
fn vm_trace_off_emits_nothing(
    epoch: StacksEpochId,
    mut tl_env_factory: TopLevelMemoryEnvironmentGenerator,
) {
    let mut env = tl_env_factory.get_env(epoch);
    init_store(&mut env, clarity_for_epoch(epoch));
    let (value, events) = exec(&mut env, &store_id(), "set-n", vec![Value::UInt(3)]);
    assert!(is_committed(&value));
    assert!(env.vm_trace_events().is_empty());
    assert!(events.is_empty());
}

#[apply(test_epochs)]
fn vm_trace_var_set_isolated_from_classic_events(
    epoch: StacksEpochId,
    mut tl_env_factory: TopLevelMemoryEnvironmentGenerator,
) {
    let mut env = tl_env_factory.get_env(epoch);
    init_store(&mut env, clarity_for_epoch(epoch));
    env.set_emit_vm_trace(true);

    let (value, events) = exec(&mut env, &store_id(), "print-and-set", vec![Value::UInt(4)]);
    assert!(is_committed(&value));
    assert_eq!(events.len(), 1, "print stays in classic events[]");
    assert_eq!(env.vm_trace_events().len(), 1);
    match &env.vm_trace_events()[0] {
        VmTraceEvent::Storage(StorageEvent::VarSet(data)) => {
            assert_eq!(data.var_name, "n");
            assert_eq!(data.raw_value, "0x0100000000000000000000000000000004");
        }
        other => panic!("expected var_set, got {other:?}"),
    }
}

#[apply(test_epochs)]
fn vm_trace_map_insert_delete_only_on_change(
    epoch: StacksEpochId,
    mut tl_env_factory: TopLevelMemoryEnvironmentGenerator,
) {
    let mut env = tl_env_factory.get_env(epoch);
    init_store(&mut env, clarity_for_epoch(epoch));
    env.set_emit_vm_trace(true);

    let (value, _) = exec(
        &mut env,
        &store_id(),
        "insert-map",
        vec![Value::UInt(1), Value::UInt(2)],
    );
    assert!(is_committed(&value));
    assert_eq!(env.vm_trace_events().len(), 1);
    assert!(matches!(
        env.vm_trace_events()[0],
        VmTraceEvent::Storage(StorageEvent::MapInsert(_))
    ));

    let (value, _) = exec(
        &mut env,
        &store_id(),
        "insert-map",
        vec![Value::UInt(1), Value::UInt(3)],
    );
    assert!(is_committed(&value));
    assert!(
        env.vm_trace_events().is_empty(),
        "no-op insert must not emit"
    );

    let (value, _) = exec(&mut env, &store_id(), "delete-map", vec![Value::UInt(1)]);
    assert!(is_committed(&value));
    assert_eq!(env.vm_trace_events().len(), 1);
    assert!(matches!(
        env.vm_trace_events()[0],
        VmTraceEvent::Storage(StorageEvent::MapDelete(_))
    ));

    let (value, _) = exec(&mut env, &store_id(), "delete-map", vec![Value::UInt(1)]);
    assert!(is_committed(&value));
    assert!(
        env.vm_trace_events().is_empty(),
        "no-op delete must not emit"
    );

    let (value, _) = exec(
        &mut env,
        &store_id(),
        "write-map",
        vec![Value::UInt(5), Value::UInt(6)],
    );
    assert!(is_committed(&value));
    assert_eq!(env.vm_trace_events().len(), 1);
    assert!(matches!(
        env.vm_trace_events()[0],
        VmTraceEvent::Storage(StorageEvent::MapSet(_))
    ));
}

#[apply(test_epochs)]
fn vm_trace_err_rollback_drops_storage(
    epoch: StacksEpochId,
    mut tl_env_factory: TopLevelMemoryEnvironmentGenerator,
) {
    let mut env = tl_env_factory.get_env(epoch);
    init_store(&mut env, clarity_for_epoch(epoch));
    env.set_emit_vm_trace(true);

    let (value, events) = exec(&mut env, &store_id(), "fail-after-set", vec![]);
    assert!(is_err_code(&value, 1));
    assert!(events.is_empty());
    assert!(
        env.vm_trace_events().is_empty(),
        "(err …) must drop the var-set with the batch"
    );

    let (got, _, _) = env.eval_read_only(&store_id(), "(var-get n)").unwrap();
    assert_eq!(got, Value::UInt(0));
}

#[apply(test_epochs)]
fn vm_trace_nested_call_after_inner_return(
    epoch: StacksEpochId,
    mut tl_env_factory: TopLevelMemoryEnvironmentGenerator,
) {
    let mut env = tl_env_factory.get_env(epoch);
    let callee = QualifiedContractIdentifier::local("callee").unwrap();
    let caller = QualifiedContractIdentifier::local("caller").unwrap();
    let version = clarity_for_epoch(epoch);
    env.initialize_versioned_contract(callee.clone(), version, CALLEE, None)
        .unwrap();
    env.initialize_versioned_contract(caller.clone(), version, CALLER, None)
        .unwrap();
    env.set_emit_vm_trace(true);

    let (value, events) = exec(&mut env, &caller, "go", vec![]);
    assert!(is_committed(&value));
    assert!(events.is_empty());
    assert_eq!(env.vm_trace_events().len(), 2);
    assert!(
        matches!(
            env.vm_trace_events()[0],
            VmTraceEvent::Storage(StorageEvent::VarSet(_))
        ),
        "inner write commits first"
    );
    match &env.vm_trace_events()[1] {
        VmTraceEvent::ContractCall(data) => {
            assert_eq!(data.contract_identifier, callee);
            assert_eq!(data.function_name, "inc");
            assert!(data.function_args.is_empty());
            assert_eq!(data.caller, PrincipalData::Contract(caller.clone()));
        }
        other => panic!("expected contract_call, got {other:?}"),
    }

    let (value, _) = exec(&mut env, &caller, "observe-fail", vec![]);
    assert!(
        is_committed(&value),
        "caller commits (ok (err u1)); inner err is the payload"
    );
    assert_eq!(
        env.vm_trace_events().len(),
        1,
        "inner var-set rolled back; call event kept because caller committed"
    );
    match &env.vm_trace_events()[0] {
        VmTraceEvent::ContractCall(data) => {
            assert_eq!(data.function_name, "fail-after-set");
            let result = Value::try_deserialize_hex_untyped(&data.raw_result).unwrap();
            assert!(!is_committed(&result));
            assert!(is_err_code(&result, 1));
        }
        other => panic!("expected contract_call, got {other:?}"),
    }

    let (got, _, _) = env.eval_read_only(&callee, "(var-get n)").unwrap();
    assert_eq!(got, Value::UInt(1), "failed inner call did not keep u9");
}

#[apply(test_epochs)]
fn vm_trace_same_result_flag_on_or_off(
    epoch: StacksEpochId,
    mut tl_env_factory: TopLevelMemoryEnvironmentGenerator,
) {
    let mut env = tl_env_factory.get_env(epoch);
    init_store(&mut env, clarity_for_epoch(epoch));

    let (off_value, off_events) = exec(&mut env, &store_id(), "set-n", vec![Value::UInt(8)]);
    let off_cost = env.get_cost_total();

    env.set_emit_vm_trace(true);
    let (on_value, on_events) = exec(&mut env, &store_id(), "set-n", vec![Value::UInt(8)]);
    let on_cost = env.get_cost_total();

    assert_eq!(off_value, on_value);
    assert_eq!(off_events, on_events);
    assert_eq!(
        off_cost, on_cost,
        "free tracker: both ZERO. Metered identity: vm_trace_limited_tracker_cost_identity"
    );
    assert_eq!(env.vm_trace_events().len(), 1);
}

#[test]
fn vm_trace_does_not_charge_event_batch_size() {
    let mut marf = MemoryBackingStore::new();
    let mut env = OwnedEnvironment::new(marf.as_clarity_db(), StacksEpochId::latest());
    let version = ClarityVersion::Clarity2;
    init_store(&mut env, version);
    let callee = QualifiedContractIdentifier::local("callee").unwrap();
    let caller = QualifiedContractIdentifier::local("caller").unwrap();
    env.initialize_versioned_contract(callee, version, CALLEE, None)
        .unwrap();
    env.initialize_versioned_contract(caller.clone(), version, CALLER, None)
        .unwrap();
    env.set_emit_vm_trace(true);
    env.begin();
    let before = env.context.event_batches.last().unwrap().1;

    let set = exec_on_batch(&mut env, &store_id(), "set-n", vec![Value::UInt(1)]);
    assert!(is_committed(&set));
    let map = exec_on_batch(
        &mut env,
        &store_id(),
        "write-map",
        vec![Value::UInt(1), Value::UInt(2)],
    );
    assert!(is_committed(&map));
    let call = exec_on_batch(&mut env, &caller, "go", vec![]);
    assert!(is_committed(&call));

    let after = env.context.event_batches.last().unwrap().1;
    assert_eq!(
        before, after,
        "vm_events must not count toward MAX_EVENTS_BATCH"
    );
    let vm_events = &env.context.event_batches.last().unwrap().0.vm_events;
    assert!(
        vm_events
            .iter()
            .any(|e| matches!(e, VmTraceEvent::Storage(StorageEvent::VarSet(_)))),
        "set-n must emit var_set: {vm_events:?}"
    );
    assert!(
        vm_events
            .iter()
            .any(|e| matches!(e, VmTraceEvent::Storage(StorageEvent::MapSet(_)))),
        "write-map must emit map_set: {vm_events:?}"
    );
    assert!(
        vm_events
            .iter()
            .any(|e| matches!(e, VmTraceEvent::ContractCall(_))),
        "nested contract-call? must emit contract_call: {vm_events:?}"
    );
}

#[test]
fn vm_trace_on_print_still_charges_and_cap_still_fires() {
    let mut marf = MemoryBackingStore::new();
    let mut env = OwnedEnvironment::new(marf.as_clarity_db(), StacksEpochId::latest());
    init_store(&mut env, ClarityVersion::Clarity2);
    env.set_emit_vm_trace(true);
    env.begin();
    let ctx = placeholder_ctx();
    {
        let (mut exec, invoke) = env.get_exec_environment(None, None, &ctx);
        exec.register_print_event(&invoke, Value::UInt(1)).unwrap();
    }
    let print_size = env.context.event_batches.last().unwrap().1;
    assert!(print_size > 0, "prints still charge with emit_vm_trace on");

    env.context.event_batches.last_mut().unwrap().1 = MAX_EVENTS_BATCH - 1;
    {
        let (mut exec, invoke) = env.get_exec_environment(None, None, &ctx);
        let err = exec
            .register_print_event(&invoke, Value::UInt(1))
            .expect_err("print at cap must fail");
        let msg = format!("{err}");
        assert!(
            msg.contains("too large") || msg.contains("Event batch"),
            "unexpected cap error: {msg}"
        );
    }

    env.context.event_batches.last_mut().unwrap().1 = MAX_EVENTS_BATCH;
    let set = exec_on_batch(&mut env, &store_id(), "set-n", vec![Value::UInt(9)]);
    assert!(is_committed(&set));
    assert_eq!(
        env.context.event_batches.last().unwrap().1,
        MAX_EVENTS_BATCH,
        "var-set at cap must not bump total_size or fail"
    );
    assert!(
        env.context
            .event_batches
            .last()
            .unwrap()
            .0
            .vm_events
            .iter()
            .any(|e| matches!(e, VmTraceEvent::Storage(StorageEvent::VarSet(_)))),
        "var-set at classic cap must still be collected"
    );
}

#[apply(test_epochs)]
fn vm_trace_contract_call_arg_hex_matches_principal_trait_cast(
    epoch: StacksEpochId,
    mut tl_env_factory: TopLevelMemoryEnvironmentGenerator,
) {
    if epoch < StacksEpochId::Epoch21 {
        return;
    }
    let mut env = tl_env_factory.get_env(epoch);
    let version = clarity_for_epoch(epoch);
    let trait_c = QualifiedContractIdentifier::local("iface").unwrap();
    let impl_c = QualifiedContractIdentifier::local("impl").unwrap();
    let callee = QualifiedContractIdentifier::local("callee").unwrap();
    let caller = QualifiedContractIdentifier::local("caller").unwrap();
    env.initialize_versioned_contract(
        trait_c.clone(),
        version,
        "(define-trait t ((noop () (response bool uint))))",
        None,
    )
    .unwrap();
    env.initialize_versioned_contract(
        impl_c.clone(),
        version,
        "(impl-trait .iface.t)\n(define-public (noop) (ok true))",
        None,
    )
    .unwrap();
    env.initialize_versioned_contract(
        callee.clone(),
        version,
        "(use-trait t .iface.t)\n(define-public (takes (x <t>)) (ok true))",
        None,
    )
    .unwrap();
    env.initialize_versioned_contract(
        caller.clone(),
        version,
        "(define-public (go) (contract-call? .callee takes .impl))",
        None,
    )
    .unwrap();
    env.set_emit_vm_trace(true);

    let impl_principal = Value::Principal(PrincipalData::Contract(impl_c.clone()));
    let (value, _) = exec(&mut env, &caller, "go", vec![]);
    assert!(is_committed(&value));
    let call = env
        .vm_trace_events()
        .iter()
        .find_map(|e| match e {
            VmTraceEvent::ContractCall(data) if data.function_name == "takes" => Some(data),
            _ => None,
        })
        .expect("expected takes contract_call");
    assert_eq!(call.function_args.len(), 1);
    let expected = crate::vm::events::VarSetEventData::try_from_value(
        impl_c.clone(),
        "unused".into(),
        &impl_principal,
    )
    .unwrap()
    .raw_value;
    assert_eq!(
        call.function_args[0], expected,
        "principal→trait binding must not change emitted argument hex"
    );
}

#[apply(test_epochs)]
fn vm_trace_extra_tuple_fields_do_not_bind(
    epoch: StacksEpochId,
    mut tl_env_factory: TopLevelMemoryEnvironmentGenerator,
) {
    let mut env = tl_env_factory.get_env(epoch);
    let version = clarity_for_epoch(epoch);
    let callee = QualifiedContractIdentifier::local("callee").unwrap();
    env.initialize_versioned_contract(
        callee.clone(),
        version,
        "(define-public (takes (x {a: uint})) (ok x))",
        None,
    )
    .unwrap();
    env.set_emit_vm_trace(true);

    let extra = crate::vm::types::TupleData::from_data(vec![
        (crate::vm::ClarityName::from_literal("a"), Value::UInt(1)),
        (crate::vm::ClarityName::from_literal("b"), Value::UInt(2)),
    ])
    .unwrap();
    let result = env.execute_transaction(
        issuer(),
        None,
        callee,
        "takes",
        &symbols_from_values(vec![Value::Tuple(extra)]),
    );
    assert!(
        result.is_err(),
        "extra tuple fields must not bind; got {result:?}"
    );
    assert!(
        env.vm_trace_events().is_empty(),
        "failed invocation must not emit function_args"
    );
}

#[test]
fn vm_trace_hex_encodes_large_buffer() {
    let mut marf = MemoryBackingStore::new();
    let mut env = OwnedEnvironment::new(marf.as_clarity_db(), StacksEpochId::latest());
    env.initialize_versioned_contract(
        store_id(),
        ClarityVersion::Clarity2,
        r#"
(define-data-var n (buff 2048) 0x)
(define-public (set-n (x (buff 2048)))
  (ok (var-set n x)))
"#,
        None,
    )
    .unwrap();
    env.set_emit_vm_trace(true);
    let val = Value::buff_from(vec![0u8; 2048]).unwrap();
    env.begin();
    let first = exec_on_batch(&mut env, &store_id(), "set-n", vec![val.clone()]);
    assert!(is_committed(&first));
    let second = exec_on_batch(&mut env, &store_id(), "set-n", vec![val]);
    assert!(is_committed(&second));
    let batch = &env.context.event_batches.last().unwrap().0;
    assert_eq!(batch.vm_events.len(), 2);
    for event in &batch.vm_events {
        match event {
            VmTraceEvent::Storage(StorageEvent::VarSet(data)) => {
                assert!(data.raw_value.starts_with("0x"));
                assert!(data.raw_value.len() > 4000);
            }
            other => panic!("expected var_set, got {other:?}"),
        }
    }
}

#[apply(test_epochs)]
fn vm_trace_nested_read_only_calls_are_kept(
    epoch: StacksEpochId,
    mut tl_env_factory: TopLevelMemoryEnvironmentGenerator,
) {
    let mut env = tl_env_factory.get_env(epoch);
    let version = clarity_for_epoch(epoch);
    let c = QualifiedContractIdentifier::local("c").unwrap();
    let b = QualifiedContractIdentifier::local("b").unwrap();
    let a = QualifiedContractIdentifier::local("a").unwrap();
    env.initialize_versioned_contract(c.clone(), version, "(define-read-only (c) (ok u3))", None)
        .unwrap();
    env.initialize_versioned_contract(
        b.clone(),
        version,
        "(define-read-only (b) (contract-call? .c c))",
        None,
    )
    .unwrap();
    env.initialize_versioned_contract(
        a.clone(),
        version,
        "(define-public (a) (ok (contract-call? .b b)))",
        None,
    )
    .unwrap();
    env.set_emit_vm_trace(true);

    let (value, _) = exec(&mut env, &a, "a", vec![]);
    assert!(is_committed(&value));
    let names: Vec<&str> = env
        .vm_trace_events()
        .iter()
        .filter_map(|e| match e {
            VmTraceEvent::ContractCall(data) => Some(data.function_name.as_str()),
            _ => None,
        })
        .collect();
    assert_eq!(
        names,
        vec!["c", "b"],
        "A → read-only B → read-only C must report C then B: {names:?}"
    );
}
