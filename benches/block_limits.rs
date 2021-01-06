extern crate blockstack_lib;
extern crate rand;
extern crate serde_json;

use blockstack_lib::{
    burnchains::BurnchainHeaderHash,
    chainstate::{
        self,
        burn::BlockHeaderHash,
        stacks::{index::MarfTrieId, StacksBlockId},
    },
    vm::clarity::ClarityInstance,
    vm::costs::ExecutionCost,
    vm::database::{MarfedKV, NULL_HEADER_DB},
    vm::{
        database::{HeadersDB, NULL_BURN_STATE_DB},
        types::{PrincipalData, QualifiedContractIdentifier, StandardPrincipalData},
    },
};
use chainstate::{burn::VRFSeed, stacks::StacksAddress};

use std::fmt::Write;
use std::process;
use std::{env, time::Instant};

use rand::Rng;

struct TestHeadersDB;

impl HeadersDB for TestHeadersDB {
    fn get_stacks_block_header_hash_for_block(
        &self,
        id_bhh: &StacksBlockId,
    ) -> Option<BlockHeaderHash> {
        Some(BlockHeaderHash(id_bhh.0.clone()))
    }

    fn get_burn_header_hash_for_block(
        &self,
        id_bhh: &StacksBlockId,
    ) -> Option<BurnchainHeaderHash> {
        Some(BurnchainHeaderHash(id_bhh.0.clone()))
    }

    fn get_vrf_seed_for_block(&self, _id_bhh: &StacksBlockId) -> Option<VRFSeed> {
        Some(VRFSeed([0; 32]))
    }

    fn get_burn_block_time_for_block(&self, _id_bhh: &StacksBlockId) -> Option<u64> {
        Some(1)
    }

    fn get_burn_block_height_for_block(&self, id_bhh: &StacksBlockId) -> Option<u32> {
        if id_bhh == &StacksBlockId::sentinel() {
            Some(0)
        } else {
            let height = id_bhh.0[0];
            Some(height as u32)
        }
    }

    fn get_miner_address(&self, _id_bhh: &StacksBlockId) -> Option<StacksAddress> {
        None
    }

    fn get_total_liquid_ustx(&self, _id_bhh: &StacksBlockId) -> u128 {
        u128::max_value()
    }
}

fn test_via_tx(scaling: u32, inner_loop: &str, other_decl: &str) -> ExecutionCost {
    let marf = MarfedKV::temporary();
    let mut clarity_instance = ClarityInstance::new(marf, ExecutionCost::max_value());

    let contract_identifier = QualifiedContractIdentifier::local("foo").unwrap();

    let blocks = [
        StacksBlockId::sentinel(),
        StacksBlockId([1; 32]),
        StacksBlockId([2; 32]),
    ];

    {
        let mut conn = clarity_instance.begin_block(
            &blocks[0],
            &blocks[1],
            &NULL_HEADER_DB,
            &NULL_BURN_STATE_DB,
        );

        let mut contract = "(define-constant list-0 (list 0))".to_string();

        for i in 0..15 {
            contract.push_str("\n");
            contract.push_str(&format!(
                "(define-constant list-{} (concat list-{} list-{}))",
                i + 1,
                i,
                i
            ));
        }

        contract.push_str("\n");
        contract.push_str(other_decl);
        contract.push_str("\n");
        contract.push_str(inner_loop);

        write!(
            contract,
            "\n(define-private (outer-loop) (map inner-loop list-10))\n"
        )
        .unwrap();
        write!(contract, "(define-public (do-it) (begin \n").unwrap();
        for _i in 0..scaling {
            write!(contract, "(outer-loop)\n").unwrap();
        }
        write!(contract, " (ok 1)))\n").unwrap();

        conn.as_transaction(|tx| {
            let (ct_ast, _ct_analysis) = tx
                .analyze_smart_contract(&contract_identifier, &contract)
                .unwrap();
            tx.initialize_smart_contract(
                // initialize the ok contract without errs, but still abort.
                &contract_identifier,
                &ct_ast,
                &contract,
                |_, _| false,
            )
            .unwrap();
        });
        conn.commit_to_block(&blocks[1]);
    }

    {
        let mut conn = clarity_instance.begin_block(
            &blocks[1],
            &blocks[2],
            &NULL_HEADER_DB,
            &NULL_BURN_STATE_DB,
        );
        conn.as_transaction(|tx| {
            tx.run_contract_call(
                &contract_identifier.clone().into(),
                &contract_identifier,
                "do-it",
                &[],
                |_, _| false,
            )
            .unwrap()
        });
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

fn as_hash160(inp: u32) -> [u8; 20] {
    let mut out = [0; 20];
    out[0..4].copy_from_slice(&inp.to_le_bytes());
    out
}

fn as_hash(inp: u32) -> [u8; 32] {
    let mut out = [0; 32];
    out[0..4].copy_from_slice(&inp.to_le_bytes());
    out
}

fn transfer_test(buildup_count: u32, scaling: u32) -> ExecutionCost {
    let marf = MarfedKV::temporary();
    let mut clarity_instance = ClarityInstance::new(marf, ExecutionCost::max_value());
    let mut blocks = vec![StacksBlockId::sentinel()];
    blocks.extend(
        (0..buildup_count)
            .into_iter()
            .map(|i| StacksBlockId(as_hash(i))),
    );

    let principals: Vec<PrincipalData> = (0..(buildup_count - 1))
        .into_iter()
        .map(|i| StandardPrincipalData(0, as_hash160(i)).into())
        .collect();

    eprintln!("Blocks to produce: {}", blocks.len() - 1);
    eprintln!("Principals to credit: {}", principals.len());

    let mut exec_cost = None;

    for ix in 0..(blocks.len() - 1) {
        let parent_block = &blocks[ix];
        let current_block = &blocks[ix + 1];

        let mut conn = if ix == 0 {
            clarity_instance.begin_test_genesis_block(
                parent_block,
                current_block,
                &TestHeadersDB,
                &NULL_BURN_STATE_DB,
            )
        } else {
            clarity_instance.begin_block(
                parent_block,
                current_block,
                &TestHeadersDB,
                &NULL_BURN_STATE_DB,
            )
        };

        let begin = Instant::now();

        if ix < principals.len() {
            // minting phase
            conn.as_transaction(|tx| {
                tx.with_clarity_db(|db| {
                    let mut stx_account_0 = db.get_stx_balance_snapshot_genesis(&principals[ix]);
                    stx_account_0.credit(1_000_000);
                    stx_account_0.save();
                    Ok(())
                })
                .unwrap()
            });
        } else {
            // transfer phase
            let mut rng = rand::thread_rng();
            for _i in 0..scaling {
                let from = rng.gen_range(0, principals.len());
                let to = (from + rng.gen_range(1, principals.len())) % principals.len();

                conn.as_transaction(|tx| {
                    tx.run_stx_transfer(&principals[from], &principals[to], 10)
                        .unwrap()
                });
            }
        }

        let this_cost = conn.commit_to_block(current_block).get_total();
        let elapsed = begin.elapsed();

        if ix >= principals.len() {
            println!(
                "Elapsed time during transfer block: {} transfers in {} ms, after {} block buildup",
                scaling,
                elapsed.as_millis(),
                buildup_count
            );
            exec_cost = Some(this_cost);
        }
    }

    exec_cost.expect("Failed to calculate the exec cost during the transfer block")
}

fn main() {
    let argv: Vec<_> = env::args().collect();

    if argv.len() < 3 {
        eprintln!("Usage: {} [test-name] [scalar-0] ... [scalar-n]", argv[0]);
        process::exit(1);
    }

    let scalar_0 = argv[2].parse().expect("Invalid scalar");
    let scalar_1 = argv[3].parse().expect("Invalid scalar");

    let result = match argv[1].as_str() {
        "transfer" => transfer_test(scalar_0, scalar_1),
        "runtime" => runtime_hash_test(scalar_0),
        "read-length" => read_length_test(scalar_0),
        "read-count" => read_count_test(scalar_0),
        "write-count" => write_count_test(scalar_0),
        "write-length" => write_length_test(scalar_0),
        _ => {
            eprintln!("bad test name");
            process::exit(1);
        }
    };

    println!("{}", serde_json::to_string(&result).unwrap());
}
