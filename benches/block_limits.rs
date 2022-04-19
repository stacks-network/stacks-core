extern crate blockstack_lib;
extern crate rand;
extern crate serde_json;

use std::fs;
use std::path::PathBuf;
use std::process;
use std::{env, time::Instant};

use blockstack_lib::clarity_vm::clarity::ClarityInstance;
use blockstack_lib::clarity_vm::database::MemoryBackingStore;
use blockstack_lib::core::StacksEpochId;
use blockstack_lib::types::chainstate::BlockHeaderHash;
use blockstack_lib::types::chainstate::BurnchainHeaderHash;
use blockstack_lib::types::chainstate::VRFSeed;
use blockstack_lib::types::proof::ClarityMarfTrieId;
use blockstack_lib::vm::ast::build_ast;
use blockstack_lib::vm::contexts::GlobalContext;
use blockstack_lib::vm::costs::LimitedCostTracker;
use blockstack_lib::vm::errors::InterpreterResult;
use blockstack_lib::vm::{eval_all, ContractContext};
use rand::Rng;

use blockstack_lib::clarity_vm::database::marf::MarfedKV;
use blockstack_lib::types::chainstate::{StacksAddress, StacksBlockId};
use blockstack_lib::util::boot::boot_code_id;
use blockstack_lib::{
    vm::costs::ExecutionCost,
    vm::{
        database::{HeadersDB, NULL_BURN_STATE_DB},
        types::{PrincipalData, QualifiedContractIdentifier, StandardPrincipalData},
        Value,
    },
};

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
            let mut bytes = [0; 4];
            bytes.copy_from_slice(&id_bhh.0[0..4]);
            let height = u32::from_le_bytes(bytes);
            Some(height)
        }
    }

    fn get_miner_address(&self, _id_bhh: &StacksBlockId) -> Option<StacksAddress> {
        None
    }
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

fn transfer_test(buildup_count: u32, scaling: u32, genesis_size: u32) -> ExecutionCost {
    let start = Instant::now();

    let marf = setup_chain_state(genesis_size);
    let mut clarity_instance = ClarityInstance::new(false, marf);
    let blocks: Vec<_> = (0..(buildup_count + 1))
        .into_iter()
        .map(|i| StacksBlockId(as_hash(i)))
        .collect();

    let principals: Vec<PrincipalData> = (0..(buildup_count - 1))
        .into_iter()
        .map(|i| StandardPrincipalData(0, as_hash160(i)).into())
        .collect();

    let last_mint_block = blocks.len() - 2;
    let last_block = blocks.len() - 1;

    for ix in 1..(last_mint_block + 1) {
        let parent_block = &blocks[ix - 1];
        let current_block = &blocks[ix];

        let mut conn = clarity_instance.begin_block(
            parent_block,
            current_block,
            &TestHeadersDB,
            &NULL_BURN_STATE_DB,
        );

        // minting phase
        conn.as_transaction(|tx| {
            tx.with_clarity_db(|db| {
                let mut stx_account_0 = db.get_stx_balance_snapshot_genesis(&principals[ix - 1]);
                stx_account_0.credit(1_000_000);
                stx_account_0.save();
                Ok(())
            })
            .unwrap()
        });

        conn.commit_to_block(current_block);
    }

    eprintln!("Finished buildup in {}ms", start.elapsed().as_millis());

    // transfer phase
    let mut conn = clarity_instance.begin_block(
        &blocks[last_mint_block],
        &blocks[last_block],
        &TestHeadersDB,
        &NULL_BURN_STATE_DB,
    );

    let begin = Instant::now();

    let mut rng = rand::thread_rng();
    for _i in 0..scaling {
        let from = rng.gen_range(0, principals.len());
        let to = (from + rng.gen_range(1, principals.len())) % principals.len();

        conn.as_transaction(|tx| {
            tx.run_stx_transfer(&principals[from], &principals[to], 10, &BuffData::empty())
                .unwrap()
        });
    }

    let this_cost = conn.commit_to_block(&blocks[last_block]).get_total();
    let elapsed = begin.elapsed();

    println!(
        "{} transfers in {} ms, after {} block buildup with a {} account genesis",
        scaling,
        elapsed.as_millis(),
        buildup_count,
        genesis_size,
    );

    this_cost
}

fn setup_chain_state(scaling: u32) -> MarfedKV {
    let pre_initialized_path = format!("/tmp/block_limit_bench_{}.marf", scaling);
    let out_path = "/tmp/block_limit_bench_last.marf";

    if fs::metadata(&pre_initialized_path).is_err() {
        let marf = MarfedKV::open(&pre_initialized_path, None).unwrap();
        let mut clarity_instance = ClarityInstance::new(false, marf);
        let mut conn = clarity_instance.begin_test_genesis_block(
            &StacksBlockId::sentinel(),
            &StacksBlockId(as_hash(0)),
            &TestHeadersDB,
            &NULL_BURN_STATE_DB,
        );

        conn.as_transaction(|tx| {
            for j in 0..scaling {
                tx.with_clarity_db(|db| {
                    let addr = StandardPrincipalData(0, as_hash160(j + 1)).into();
                    let mut stx_account_0 = db.get_stx_balance_snapshot_genesis(&addr);
                    stx_account_0.credit(1);
                    stx_account_0.save();
                    db.increment_ustx_liquid_supply(1).unwrap();
                    Ok(())
                })
                .unwrap();
            }
        });

        conn.commit_to_block(&StacksBlockId(as_hash(0)));
    };

    if fs::metadata(&out_path).is_err() {
        let path = PathBuf::from(out_path);
        fs::create_dir_all(&path).expect("Error creating directory");
    }

    fs::copy(
        &format!("{}/marf.sqlite", pre_initialized_path),
        &format!("{}/marf.sqlite", out_path),
    )
    .unwrap();
    return MarfedKV::open(out_path, None).unwrap();
}

fn test_via_raw_contract(
    eval: &str,
    scaling: u32,
    buildup_count: u32,
    genesis_size: u32,
) -> ExecutionCost {
    let start = Instant::now();

    let marf = setup_chain_state(genesis_size);

    let mut clarity_instance = ClarityInstance::new(false, marf);
    let blocks: Vec<_> = (0..(buildup_count + 1))
        .into_iter()
        .map(|i| StacksBlockId(as_hash(i)))
        .collect();

    let stacker: PrincipalData = StandardPrincipalData(0, as_hash160(0)).into();

    let contract_id =
        QualifiedContractIdentifier::new(StandardPrincipalData(0, as_hash160(0)), "test".into());

    let mut smart_contract = "".to_string();
    for _i in 0..scaling {
        smart_contract.push_str(&format!("{}\n", eval));
    }

    let last_mint_block = blocks.len() - 2;
    let last_block = blocks.len() - 1;

    for ix in 1..(last_mint_block + 1) {
        let parent_block = &blocks[ix - 1];
        let current_block = &blocks[ix];

        let mut conn = clarity_instance.begin_block(
            parent_block,
            current_block,
            &TestHeadersDB,
            &NULL_BURN_STATE_DB,
        );

        // minting phase
        conn.as_transaction(|tx| {
            tx.with_clarity_db(|db| {
                let mut stx_account_0 = db.get_stx_balance_snapshot_genesis(&stacker);
                stx_account_0.credit(1_000_000);
                stx_account_0.save();
                db.increment_ustx_liquid_supply(1_000_000).unwrap();
                Ok(())
            })
            .unwrap();
        });

        conn.commit_to_block(current_block);
    }

    eprintln!("Finished buildup in {}ms", start.elapsed().as_millis());

    // execute the block
    let mut conn = clarity_instance.begin_block(
        &blocks[last_mint_block],
        &blocks[last_block],
        &TestHeadersDB,
        &NULL_BURN_STATE_DB,
    );

    let begin = Instant::now();

    let exec_cost = conn.as_transaction(|tx| {
        let analysis_cost = tx.cost_so_far();
        let (contract_ast, contract_analysis) = tx
            .analyze_smart_contract(&contract_id, &smart_contract)
            .unwrap();
        tx.initialize_smart_contract(
            &contract_id,
            &contract_ast,
            &smart_contract,
            None,
            |_, _| false,
        )
        .unwrap();

        let mut initialize_cost = tx.cost_so_far();
        initialize_cost.sub(&analysis_cost).unwrap();

        tx.save_analysis(&contract_id, &contract_analysis)
            .expect("FATAL: failed to store contract analysis");

        initialize_cost
    });

    let _this_cost = conn.commit_to_block(&blocks[last_block]).get_total();
    let elapsed = begin.elapsed();

    println!(
        "Completed raw execution scaled at {} in {} ms, after {} block buildup with a {} account genesis",
        scaling,
        elapsed.as_millis(),
        buildup_count,
        genesis_size,
    );

    exec_cost
}

fn smart_contract_test(scaling: u32, buildup_count: u32, genesis_size: u32) -> ExecutionCost {
    let start = Instant::now();

    let marf = setup_chain_state(genesis_size);

    let mut clarity_instance = ClarityInstance::new(false, marf);
    let blocks: Vec<_> = (0..(buildup_count + 1))
        .into_iter()
        .map(|i| StacksBlockId(as_hash(i)))
        .collect();

    let stacker: PrincipalData = StandardPrincipalData(0, as_hash160(0)).into();

    let contract_id =
        QualifiedContractIdentifier::new(StandardPrincipalData(0, as_hash160(0)), "test".into());

    let mut smart_contract = "".to_string();
    for i in 0..scaling {
        smart_contract.push_str(&format!("(define-public (foo-{}) (ok (+ u2 u3)))\n", i));
    }

    let last_mint_block = blocks.len() - 2;
    let last_block = blocks.len() - 1;

    for ix in 1..(last_mint_block + 1) {
        let parent_block = &blocks[ix - 1];
        let current_block = &blocks[ix];

        let mut conn = clarity_instance.begin_block(
            parent_block,
            current_block,
            &TestHeadersDB,
            &NULL_BURN_STATE_DB,
        );

        // minting phase
        conn.as_transaction(|tx| {
            tx.with_clarity_db(|db| {
                let mut stx_account_0 = db.get_stx_balance_snapshot_genesis(&stacker);
                stx_account_0.credit(1_000_000);
                stx_account_0.save();
                db.increment_ustx_liquid_supply(1_000_000).unwrap();
                Ok(())
            })
            .unwrap();
        });

        conn.commit_to_block(current_block);
    }

    eprintln!("Finished buildup in {}ms", start.elapsed().as_millis());

    // execute the block
    let mut conn = clarity_instance.begin_block(
        &blocks[last_mint_block],
        &blocks[last_block],
        &TestHeadersDB,
        &NULL_BURN_STATE_DB,
    );

    let begin = Instant::now();

    conn.as_transaction(|tx| {
        let (contract_ast, contract_analysis) = tx
            .analyze_smart_contract(&contract_id, &smart_contract)
            .unwrap();
        tx.initialize_smart_contract(
            &contract_id,
            &contract_ast,
            &smart_contract,
            None,
            |_, _| false,
        )
        .unwrap();

        tx.save_analysis(&contract_id, &contract_analysis)
            .expect("FATAL: failed to store contract analysis");
    });

    let this_cost = conn.commit_to_block(&blocks[last_block]).get_total();
    let elapsed = begin.elapsed();

    println!(
        "Completed smart-contract scaled at {} in {} ms, after {} block buildup with a {} account genesis",
        scaling,
        elapsed.as_millis(),
        buildup_count,
        genesis_size,
    );

    this_cost
}

fn expensive_contract_test(scaling: u32, buildup_count: u32, genesis_size: u32) -> ExecutionCost {
    let start = Instant::now();

    let marf = setup_chain_state(genesis_size);

    let mut clarity_instance = ClarityInstance::new(false, marf);
    let blocks: Vec<_> = (0..(buildup_count + 1))
        .into_iter()
        .map(|i| StacksBlockId(as_hash(i)))
        .collect();

    let stacker: PrincipalData = StandardPrincipalData(0, as_hash160(0)).into();

    let contract_id =
        QualifiedContractIdentifier::new(StandardPrincipalData(0, as_hash160(0)), "test".into());

    let smart_contract = format!(
        "(define-public (f) (begin {} (ok 1))) (begin (f))",
        (0..scaling)
            .map(|_| format!(
                "(unwrap! (contract-call? '{} submit-proposal '{} \"cost-old\" '{} \"cost-new\") (err 1))",
                boot_code_id("cost-voting", false),
                contract_id.clone(),
                contract_id.clone()
            ))
            .collect::<Vec<String>>()
            .join(" ")
    );

    let last_mint_block = blocks.len() - 2;
    let last_block = blocks.len() - 1;

    for ix in 1..(last_mint_block + 1) {
        let parent_block = &blocks[ix - 1];
        let current_block = &blocks[ix];

        let mut conn = clarity_instance.begin_block(
            parent_block,
            current_block,
            &TestHeadersDB,
            &NULL_BURN_STATE_DB,
        );

        // minting phase
        conn.as_transaction(|tx| {
            tx.with_clarity_db(|db| {
                let mut stx_account_0 = db.get_stx_balance_snapshot_genesis(&stacker);
                stx_account_0.credit(1_000_000);
                stx_account_0.save();
                db.increment_ustx_liquid_supply(1_000_000).unwrap();
                Ok(())
            })
            .unwrap();
        });

        conn.commit_to_block(current_block);
    }

    eprintln!("Finished buildup in {}ms", start.elapsed().as_millis());

    // execute the block
    let mut conn = clarity_instance.begin_block(
        &blocks[last_mint_block],
        &blocks[last_block],
        &TestHeadersDB,
        &NULL_BURN_STATE_DB,
    );

    let begin = Instant::now();

    conn.as_transaction(|tx| {
        let (contract_ast, contract_analysis) = tx
            .analyze_smart_contract(&contract_id, &smart_contract)
            .unwrap();
        tx.initialize_smart_contract(&contract_id, &contract_ast, &smart_contract, |_, _| false)
            .unwrap();

        tx.save_analysis(&contract_id, &contract_analysis)
            .expect("FATAL: failed to store contract analysis");
    });

    let this_cost = conn.commit_to_block(&blocks[last_block]).get_total();
    let elapsed = begin.elapsed();

    println!(
        "Completed smart-contract scaled at {} in {} ms, after {} block buildup with a {} account genesis",
        scaling,
        elapsed.as_millis(),
        buildup_count,
        genesis_size,
    );

    this_cost
}

pub fn execute_in_epoch(program: &str, epoch: StacksEpochId) -> InterpreterResult<Option<Value>> {
    let contract_id = QualifiedContractIdentifier::transient();
    let mut contract_context = ContractContext::new(contract_id.clone());
    let mut marf = MemoryBackingStore::new();
    let conn = marf.as_clarity_db();
    let mut global_context = GlobalContext::new(false, conn, LimitedCostTracker::new_free(), epoch);
    global_context.execute(|g| {
        let parsed = build_ast(&contract_id, program, &mut ())?.expressions;
        eval_all(&parsed, &mut contract_context, g)
    })
}

fn execute(program: &str) -> InterpreterResult<Option<Value>> {
    let epoch_200_result = execute_in_epoch(program, StacksEpochId::Epoch20);
    let epoch_205_result = execute_in_epoch(program, StacksEpochId::Epoch2_05);
    assert_eq!(
        epoch_200_result, epoch_205_result,
        "Epoch 2.0 and 2.05 should have same execution result, but did not for program `{}`",
        program
    );
    epoch_205_result
}

fn stack_stx_test(buildup_count: u32, genesis_size: u32, scaling: u32) -> ExecutionCost {
    let start = Instant::now();
    let marf = setup_chain_state(genesis_size);

    let mut clarity_instance = ClarityInstance::new(false, marf);
    let blocks: Vec<_> = (0..(buildup_count + 1))
        .into_iter()
        .map(|i| StacksBlockId(as_hash(i)))
        .collect();

    let stackers: Vec<PrincipalData> = (0..scaling)
        .into_iter()
        .map(|i| StandardPrincipalData(0, as_hash160(i)).into())
        .collect();

    let stacker_balance = (buildup_count as u128 - 1) * 1_000_000;

    let pox_addrs: Vec<Value> = (0..50u64)
        .map(|ix| {
            execute(&format!(
                "{{ version: 0x00, hashbytes: 0x000000000000000000000000{} }}",
                &blockstack_lib::util::hash::to_hex(&ix.to_le_bytes())
            ))
            .unwrap()
            .unwrap()
        })
        .collect();

    let last_mint_block = blocks.len() - 2;
    let last_block = blocks.len() - 1;

    for ix in 1..(last_mint_block + 1) {
        let parent_block = &blocks[ix - 1];
        let current_block = &blocks[ix];

        let mut conn = clarity_instance.begin_block(
            parent_block,
            current_block,
            &TestHeadersDB,
            &NULL_BURN_STATE_DB,
        );

        // minting phase
        conn.as_transaction(|tx| {
            tx.with_clarity_db(|db| {
                for stacker in stackers.iter() {
                    let mut stx_account_0 = db.get_stx_balance_snapshot_genesis(stacker);
                    stx_account_0.credit(1_000_000);
                    stx_account_0.save();
                    db.increment_ustx_liquid_supply(1_000_000).unwrap();
                }
                Ok(())
            })
            .unwrap();
        });

        conn.commit_to_block(current_block);
    }

    eprintln!("Finished buildup in {}ms", start.elapsed().as_millis());

    // do the stack-stx block
    let mut conn = clarity_instance.begin_block(
        &blocks[last_mint_block],
        &blocks[last_block],
        &TestHeadersDB,
        &NULL_BURN_STATE_DB,
    );

    let begin = Instant::now();

    conn.as_transaction(|tx| {
        for stacker in stackers.iter() {
            let result = tx
                .run_contract_call(
                    stacker,
                    None,
                    &boot_code_id("pox", false),
                    "stack-stx",
                    &[
                        Value::UInt(stacker_balance),
                        pox_addrs[0].clone(),
                        Value::UInt(buildup_count as u128 + 2),
                        Value::UInt(12),
                    ],
                    |_, _| false,
                )
                .unwrap()
                .0;
            if let Err(v) = result.expect_result() {
                panic!("Stacking failed: {}", v);
            }
        }
    });

    let this_cost = conn.commit_to_block(&blocks[last_block]).get_total();
    let elapsed = begin.elapsed();

    println!(
        "Completed {} stack-stx ops in {} ms, after {} block buildup with a {} account genesis",
        scaling,
        elapsed.as_millis(),
        buildup_count,
        genesis_size,
    );

    this_cost
}

fn main() {
    let argv: Vec<_> = env::args().collect();

    if argv.len() < 3 {
        eprintln!(
            "Usage: {} [test-name] [scalar-0] ... [scalar-n]

transfer <block_build_up> <genesis_size> <number_of_ops>
smart-contract <block_build_up> <genesis_size> <number_of_ops>
stack-stx <block_build_up> <genesis_size> <number_of_ops>
clarity-transfer <block_build_up> <genesis_size> <number_of_ops>
clarity-verify <block_build_up> <genesis_size> <number_of_ops>
clarity-raw  <block_build_up> <genesis_size> <number_of_ops> <eval-block>
",
            argv[0]
        );
        process::exit(1);
    }

    let block_build_up = argv[2].parse().expect("Invalid scalar");
    let genesis_size = argv[3].parse().expect("Invalid scalar");
    let scaling = argv[4].parse().expect("Invalid scalar");

    let result = match argv[1].as_str() {
        "transfer" => transfer_test(block_build_up, scaling, genesis_size),
        "smart-contract" => smart_contract_test(scaling, block_build_up, genesis_size),
        "clarity-transfer" => test_via_raw_contract(r#"(stx-transfer? u1 tx-sender 'SZ2J6ZY48GV1EZ5V2V5RB9MP66SW86PYKKQ9H6DPR)"#,
                                                    scaling, block_build_up, genesis_size),
        "expensive-contract" => expensive_contract_test(scaling, block_build_up, genesis_size),
        "clarity-verify" => test_via_raw_contract("(secp256k1-verify 0xde5b9eb9e7c5592930eb2e30a01369c36586d872082ed8181ee83d2a0ec20f04
 0x8738487ebe69b93d8e51583be8eee50bb4213fc49c767d329632730cc193b873554428fc936ca3569afc15f1c9365f6591d6251a89fee9c9ac661116824d3a1301
 0x03adb8de4bfb65db2cfd6120d55c6526ae9c52e675db7e47308636534ba7786110)",
                                                  scaling, block_build_up, genesis_size),
        "stack-stx" => stack_stx_test(block_build_up, genesis_size, scaling),
        _ => {
            eprintln!("bad test name");
            process::exit(1);
        }
    };

    println!("{}", serde_json::to_string(&result).unwrap());
}
