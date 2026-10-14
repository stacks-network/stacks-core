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

//! Measures function lookup and a call that skips the bulk of its body, as that bulk grows.
//! Both timings should stay flat across `body_size`: any per-call copy of the body would
//! show up as cost growing with it. Parsing, definition evaluation, and database setup
//! happen outside the timed loops.

use std::hint::black_box;

use clarity::vm::contexts::{ExecutionState, GlobalContext, InvocationContext};
use clarity::vm::costs::LimitedCostTracker;
use clarity::vm::database::MemoryBackingStore;
use clarity::vm::types::QualifiedContractIdentifier;
use clarity::vm::{
    CallStack, ClarityVersion, ContractContext, LocalContext, SymbolicExpression, Value, ast, eval,
    eval_all,
};
use criterion::{BenchmarkId, Criterion, criterion_group, criterion_main};
use stacks_common::consts::CHAIN_ID_TESTNET;
use stacks_common::types::StacksEpochId;

const VERSION: ClarityVersion = ClarityVersion::Clarity7;
const EPOCH: StacksEpochId = StacksEpochId::Epoch41;

/// Parses fixtures before any timing starts.
fn parse(source: &str) -> Vec<SymbolicExpression> {
    ast::build_ast(
        &QualifiedContractIdentifier::transient(),
        source,
        &mut LimitedCostTracker::new_free(),
        VERSION,
        EPOCH,
    )
    .expect("failed to parse function lookup benchmark")
    .expressions
}

/// Grows the skipped branch while keeping the executed path constant.
fn bench_function_lookup(c: &mut Criterion) {
    let mut group = c.benchmark_group("function_lookup");
    for body_size in [0, 128, 1024] {
        let padding = "(+ u1 u1) ".repeat(body_size);
        let definitions = parse(&format!(
            "(define-private (short-path (quick bool)) (if quick u1 (begin {padding}u2)))"
        ));
        let calls = parse("(short-path true)");
        let call = calls.first().expect("missing benchmark call");
        let mut store = MemoryBackingStore::new();
        let mut global = GlobalContext::new(
            false,
            CHAIN_ID_TESTNET,
            store.as_clarity_db(),
            LimitedCostTracker::new_free(),
            EPOCH,
        );
        let mut contract = ContractContext::new(QualifiedContractIdentifier::transient(), VERSION);
        global
            .execute(|global| eval_all(&definitions, &mut contract, global, None))
            .expect("failed to initialize benchmark functions");

        group.bench_function(BenchmarkId::new("lookup", body_size), |b| {
            b.iter(|| black_box(contract.lookup_function(black_box("short-path"))));
        });

        global
            .execute(|global| {
                let mut stack = CallStack::new();
                let mut state = ExecutionState {
                    global_context: global,
                    call_stack: &mut stack,
                };
                let invocation = InvocationContext {
                    contract_context: &contract,
                    sender: None,
                    caller: None,
                    sponsor: None,
                };
                let locals = LocalContext::new();
                assert_eq!(
                    eval(call, &mut state, &invocation, &locals)?.as_ref(),
                    &Value::UInt(1)
                );
                group.bench_function(BenchmarkId::new("short_path_call", body_size), |b| {
                    b.iter(|| {
                        black_box(
                            eval(black_box(call), &mut state, &invocation, &locals)
                                .expect("benchmark call failed"),
                        )
                    });
                });
                Ok(())
            })
            .expect("benchmark transaction failed");
    }
    group.finish();
}

criterion_group!(benches, bench_function_lookup);
criterion_main!(benches);
