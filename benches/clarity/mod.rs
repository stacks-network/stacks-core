extern crate criterion;
extern crate blockstack_lib;
extern crate rand;

use std::time;
use criterion::{criterion_group, criterion_main, Criterion, BenchmarkId};
use rand::Rng;
use std::convert::TryFrom;

use blockstack_lib::vm::{ast, eval_all, eval};
use blockstack_lib::vm::representations::{SymbolicExpression, ClarityName};
use blockstack_lib::vm::types::QualifiedContractIdentifier;
use blockstack_lib::vm::database::{MemoryBackingStore};
use blockstack_lib::vm::contexts::{GlobalContext, LocalContext, ContractContext, CallStack, Environment};
use blockstack_lib::vm::costs::{LimitedCostTracker};



fn generate_contract(func_type: &str, scale: u64, input_size: u64) -> String {
    // Generate the arg list passed to the function
    let mut rng = rand::thread_rng();
    let func_args: Vec<String> = (0..input_size).map(|_| { format!("{}", rng.gen::<u64>()) }).collect();
    let func_call = format!("({} {})", func_type, func_args.join(" "));

    // Generate the body of the method
    let body: Vec<String> = (0..scale).map(|_| { func_call.clone() }).collect();
    
    // Envelop the body and return the contract
    format!("(begin {})", body.join(" "))
}

pub fn criterion_benchmark(c: &mut Criterion) {
    let contract_id = QualifiedContractIdentifier::transient();
    let contract_src = generate_contract("+", 10, 2);
    let contract_ast = ast::build_ast(&contract_id, &contract_src).unwrap();
    let mut contract_context = ContractContext::new(contract_id.clone());
    let mut marf = MemoryBackingStore::new();    
    let conn = marf.as_clarity_db();
    let mut global_context = GlobalContext::new(conn, LimitedCostTracker::new_max_limit());

    let mut group = c.benchmark_group("Native functions");
    group.measurement_time(time::Duration::from_secs(20));
    group.bench_function("+", |b| b.iter(|| {
        global_context.execute(|g| {
            eval_all(&contract_ast.expressions, &mut contract_context, g)
        }).unwrap();    
    }));
    group.finish();
}

criterion_group!(benches, criterion_benchmark);
criterion_main!(benches);
