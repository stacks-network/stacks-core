extern crate blockstack_lib;
extern crate serde_json;

use blockstack_lib::{
    chainstate::stacks::index::storage::{TrieFileStorage},
    chainstate::burn::BlockHeaderHash,
    vm::types::{QualifiedContractIdentifier},
    vm::database::{MarfedKV, NULL_HEADER_DB}, 
    vm::clarity::ClarityInstance, 
    vm::costs::ExecutionCost,
};

use std::env;
use std::process;
use std::fmt::Write;


fn test_via_tx(scaling: u32, inner_loop: &str, other_decl: &str) -> ExecutionCost {
    let marf = MarfedKV::temporary();
    let mut clarity_instance = ClarityInstance::new(marf, ExecutionCost::max_value());

    let contract_identifier = QualifiedContractIdentifier::local("foo").unwrap();

    let blocks = [TrieFileStorage::block_sentinel(),
                  BlockHeaderHash::from_bytes(&[1 as u8; 32]).unwrap(),
                  BlockHeaderHash::from_bytes(&[2 as u8; 32]).unwrap()];

    {
        let mut conn = clarity_instance.begin_block(&blocks[0],
                                                    &blocks[1],
                                                    &NULL_HEADER_DB);

        let mut contract = "(define-constant list-0 (list 0))".to_string();

        for i in 0..15 {
            contract.push_str("\n");
            contract.push_str(
                &format!("(define-constant list-{} (concat list-{} list-{}))",
                         i+1, i, i));
        }

        contract.push_str("\n");
        contract.push_str(other_decl);
        contract.push_str("\n");
        contract.push_str(inner_loop);

        write!(contract, "\n(define-private (outer-loop) (map inner-loop list-10))\n").unwrap();
        write!(contract, "(define-public (do-it) (begin \n").unwrap();
        for _i in 0..scaling {
            write!(contract, "(outer-loop)\n").unwrap();
        }
        write!(contract, " (ok 1)))\n").unwrap();


        let (ct_ast, _ct_analysis) = conn.analyze_smart_contract(&contract_identifier, &contract).unwrap();
        conn.initialize_smart_contract(
            // initialize the ok contract without errs, but still abort.
            &contract_identifier, &ct_ast, &contract, |_,_| false).unwrap();

        conn.commit_to_block(&blocks[1]);
    }

    {
        let mut conn = clarity_instance.begin_block(&blocks[1], &blocks[2], &NULL_HEADER_DB);
        conn.run_contract_call(&contract_identifier.clone().into(),
                               &contract_identifier, "do-it", &[], |_, _| false).unwrap();
        conn.commit_to_block(&blocks[2]).get_total()
    }

}

// on a fairly underpowered laptop:
// read-length of ~1e9 corresponds to 10 seconds. (scaling => 2)
fn read_length_test(scaling: u32) -> ExecutionCost {
    let other_decl = "(define-data-var var-to-read (list 33000 int) list-15)";
    let inner_loop = "(define-private (inner-loop (x int)) (len (var-get var-to-read)))";
    test_via_tx(scaling, inner_loop, other_decl)
}

// on a fairly underpowered laptop:
// read-count of ~50k corresponds to 10 seconds. (scaling => 50)
fn read_count_test(scaling: u32) -> ExecutionCost {
    let other_decl = "(define-data-var var-to-read int 0)";
    let inner_loop = "(define-private (inner-loop (x int)) (var-get var-to-read))";
    test_via_tx(scaling, inner_loop, other_decl)
}

// on a fairly underpowered laptop:
// write-length of ~1e8 corresponds to 10 seconds. (scaling => 10)
//   at scaling = 5, the tx takes about 5 seconds => write-length of ~8e7,
//   so for ~10s, max write-len should be 1.5e8
fn write_length_test(scaling: u32) -> ExecutionCost {
    let other_decl = "(define-data-var var-to-read (list 1024 int) list-10)";
    let inner_loop = "(define-private (inner-loop (x int)) (var-set var-to-read list-10))";
    test_via_tx(scaling, inner_loop, other_decl)
}

// on a fairly underpowered laptop:
// write-count of ~50k corresponds to 10 seconds. (scaling => 50)
fn write_count_test(scaling: u32) -> ExecutionCost {
    let other_decl = "(define-data-var var-to-read int 0)";
    let inner_loop = "(define-private (inner-loop (x int)) (var-set var-to-read 0))";
    test_via_tx(scaling, inner_loop, other_decl)
}

// on a fairly underpowered laptop:
// runtime count of ~1e8 corresponds to 10 seconds. (scaling => 6)
fn runtime_hash_test(scaling: u32) -> ExecutionCost {
    let other_decl = "";
    let inner_loop = "(define-private (inner-loop (x int)) (begin (map sha512 list-10) 0))";
    test_via_tx(scaling, inner_loop, other_decl)
}

fn main() {
    let argv: Vec<_> = env::args().collect();

    if argv.len() < 3 {
        eprintln!("Usage: {} [test-name] [scalar]", argv[0]);
        process::exit(1);
    }

    let scalar = argv[2].parse().expect("Invalid scalar");

    let result = match argv[1].as_str() {
        "runtime" => {
            runtime_hash_test(scalar)
        },
        "read-length" => {
            read_length_test(scalar)
        },
        "read-count" => {
            read_count_test(scalar)
        },
        "write-count" => {
            write_count_test(scalar)
        },
        "write-length" => {
            write_length_test(scalar)
        },
        _ => {
            eprintln!("bad test name");
            process::exit(1);
        },
    };

    println!("{}", serde_json::to_string(&result).unwrap());
}
