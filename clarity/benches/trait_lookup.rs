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

//! Benchmarks trait lookup and dynamic dispatch as the trait's method count grows.
//! Both timings should stay flat across `method_count`: any per-call copy of the method
//! map would show up as cost growing with it. The target implements every method but
//! omits `impl-trait`, so every call goes through the runtime compliance check. Parsing,
//! deployment, and cache warm-up happen outside the timed loops.

use std::hint::black_box;

use clarity::vm::contexts::OwnedEnvironment;
use clarity::vm::database::{ClarityExecutionCache, MemoryBackingStore};
use clarity::vm::types::{PrincipalData, QualifiedContractIdentifier};
use clarity::vm::{ClarityVersion, SymbolicExpression, Value};
use criterion::{BenchmarkId, Criterion, criterion_group, criterion_main};
use stacks_common::consts::CHAIN_ID_TESTNET;
use stacks_common::types::StacksEpochId;

const VERSION: ClarityVersion = ClarityVersion::Clarity7;
const EPOCH: StacksEpochId = StacksEpochId::Epoch41;

/// Records `EPOCH` in the store, so loaded contracts are canonicalized for the epoch they
/// execute under.
fn setup_store(store: &mut MemoryBackingStore) {
    let mut db = store.as_clarity_db();
    db.begin();
    db.set_clarity_epoch_version(EPOCH).unwrap();
    db.commit().unwrap();
}

/// Measures both the isolated map lookup and the full cached contract-call path.
fn bench_trait_lookup(c: &mut Criterion) {
    let mut group = c.benchmark_group("trait_lookup");
    for method_count in [1, 16, 128] {
        let mut methods = String::new();
        let mut target_source = String::new();
        for method in 0..method_count {
            methods.push_str(&format!("(method{method} (uint) (response uint uint))\n"));
            target_source.push_str(&format!(
                "(define-public (method{method} (x uint)) (ok x))\n"
            ));
        }
        let source = format!(
            "(define-trait interface ({methods}))
             (define-public (call (target <interface>))
               (contract-call? target method0 u1))"
        );
        let caller = QualifiedContractIdentifier::local("caller").unwrap();
        let target = QualifiedContractIdentifier::local("target").unwrap();
        let sender: PrincipalData = caller.issuer.clone().into();
        let args = [SymbolicExpression::atom_value(Value::from(target.clone()))];
        let mut store = MemoryBackingStore::new();
        setup_store(&mut store);
        let mut cache = ClarityExecutionCache::default();
        let mut env = OwnedEnvironment::new_free(
            false,
            CHAIN_ID_TESTNET,
            store.as_clarity_db().with_cache(&mut cache),
            EPOCH,
        );
        env.initialize_versioned_contract(caller.clone(), VERSION, &source, None)
            .unwrap();
        env.initialize_versioned_contract(target, VERSION, &target_source, None)
            .unwrap();

        // The warm-up also verifies that runtime trait dispatch returns the expected value.
        let result = env
            .execute_transaction(sender.clone(), None, caller.clone(), "call", &args)
            .unwrap();
        assert_eq!(result.0, Value::okay(Value::UInt(1)).unwrap());

        let (contract, _, _) = env
            .execute_in_env(sender.clone(), None, None, |state, _| {
                state.global_context.database.get_contract(&caller)
            })
            .unwrap();
        group.bench_function(BenchmarkId::new("lookup", method_count), |b| {
            b.iter(|| black_box(contract.lookup_trait_definition(black_box("interface"))));
        });
        group.bench_function(BenchmarkId::new("dynamic_call", method_count), |b| {
            b.iter(|| {
                black_box(
                    env.execute_transaction(
                        sender.clone(),
                        None,
                        caller.clone(),
                        "call",
                        black_box(&args),
                    )
                    .expect("benchmark trait call failed"),
                )
            });
        });
    }
    group.finish();
}

criterion_group!(benches, bench_trait_lookup);
criterion_main!(benches);
