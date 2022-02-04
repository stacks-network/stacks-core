#[macro_use]
extern crate criterion;
extern crate blockstack_lib;
extern crate rand;

use blockstack_lib::clarity_vm::clarity::ClarityInstance;
use blockstack_lib::clarity_vm::database::marf::MarfedKV;
use blockstack_lib::types::chainstate::StacksBlockId;
use blockstack_lib::types::proof::ClarityMarfTrieId;
use blockstack_lib::vm::database::NULL_BURN_STATE_DB;
use blockstack_lib::{vm::database::NULL_HEADER_DB, vm::types::QualifiedContractIdentifier};
use criterion::Criterion;

pub fn rollback_log_memory_test() {
    let marf = MarfedKV::temporary();
    let mut clarity_instance = ClarityInstance::new(false, marf);
    let EXPLODE_N = 100;

    let contract_identifier = QualifiedContractIdentifier::local("foo").unwrap();

    {
        let mut conn = clarity_instance.begin_block(
            &StacksBlockId::sentinel(),
            &StacksBlockId::from_bytes(&[0 as u8; 32]).unwrap(),
            &NULL_HEADER_DB,
            &NULL_BURN_STATE_DB,
        );

        let define_data_var = "(define-data-var XZ (buff 1048576) \"a\")";

        let mut contract = define_data_var.to_string();
        for i in 0..20 {
            let cur_size = format!("{}", 2u32.pow(i));
            contract.push_str("\n");
            contract.push_str(&format!(
                "(var-set XZ (concat (unwrap-panic (as-max-len? (var-get XZ) u{}))
                                             (unwrap-panic (as-max-len? (var-get XZ) u{}))))",
                cur_size, cur_size
            ));
        }
        for i in 0..EXPLODE_N {
            let exploder = format!("(define-data-var var-{} (buff 1048576) (var-get XZ))", i);
            contract.push_str("\n");
            contract.push_str(&exploder);
        }

        conn.as_transaction(|conn| {
            let (ct_ast, _ct_analysis) = conn
                .analyze_smart_contract(&contract_identifier, &contract)
                .unwrap();

            assert!(format!(
                "{:?}",
                conn.initialize_smart_contract(&contract_identifier, &ct_ast, &contract, |_, _| {
                    false
                })
                .unwrap_err()
            )
            .contains("MemoryBalanceExceeded"));
        });
    }
}

pub fn ccall_memory_test() {
    let marf = MarfedKV::temporary();
    let mut clarity_instance = ClarityInstance::new(false, marf);
    let COUNT_PER_CONTRACT = 20;
    let CONTRACTS = 5;

    {
        let mut conn = clarity_instance.begin_block(
            &StacksBlockId::sentinel(),
            &StacksBlockId::from_bytes(&[0 as u8; 32]).unwrap(),
            &NULL_HEADER_DB,
            &NULL_BURN_STATE_DB,
        );

        let define_data_var = "(define-constant buff-0 \"a\")\n";

        let mut contract = define_data_var.to_string();
        for i in 0..20 {
            contract.push_str(&format!(
                "(define-constant buff-{} (concat buff-{} buff-{}))\n",
                i + 1,
                i,
                i
            ));
        }

        for i in 0..COUNT_PER_CONTRACT {
            contract.push_str(&format!("(define-constant var-{} buff-20)\n", i));
        }

        contract.push_str("(define-public (call)\n");

        let mut contracts = vec![];

        for i in 0..CONTRACTS {
            let mut my_contract = contract.clone();
            if i == 0 {
                my_contract.push_str("(ok 1))\n");
            } else {
                my_contract.push_str(&format!("(contract-call? .contract-{} call))\n", i - 1));
            }
            my_contract.push_str("(call)\n");
            contracts.push(my_contract);
        }

        for (i, contract) in contracts.into_iter().enumerate() {
            let contract_name = format!("contract-{}", i);
            let contract_identifier = QualifiedContractIdentifier::local(&contract_name).unwrap();

            if i < (CONTRACTS - 1) {
                conn.as_transaction(|conn| {
                    let (ct_ast, ct_analysis) = conn
                        .analyze_smart_contract(&contract_identifier, &contract)
                        .unwrap();
                    conn.initialize_smart_contract(
                        &contract_identifier,
                        &ct_ast,
                        &contract,
                        |_, _| false,
                    )
                    .unwrap();
                    conn.save_analysis(&contract_identifier, &ct_analysis)
                        .unwrap();
                })
            } else {
                conn.as_transaction(|conn| {
                    let (ct_ast, _ct_analysis) = conn
                        .analyze_smart_contract(&contract_identifier, &contract)
                        .unwrap();
                    assert!(format!(
                        "{:?}",
                        conn.initialize_smart_contract(
                            &contract_identifier,
                            &ct_ast,
                            &contract,
                            |_, _| false
                        )
                        .unwrap_err()
                    )
                    .contains("MemoryBalanceExceeded"));
                })
            }
        }
    }
}

pub fn basic_usage_benchmark(c: &mut Criterion) {
    c.bench_function("rollback_log_memory_test", |b| {
        b.iter(|| rollback_log_memory_test())
    });
    c.bench_function("ccall_memory_test", |b| b.iter(|| ccall_memory_test()));
}

criterion_group!(benches, basic_usage_benchmark);
criterion_main!(benches);
