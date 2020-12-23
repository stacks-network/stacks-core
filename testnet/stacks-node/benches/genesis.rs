extern crate serde_json;
extern crate stacks;

use dhat::{Dhat, DhatAlloc};

#[global_allocator]
static ALLOCATOR: DhatAlloc = DhatAlloc;

use stacks::{
    burnchains::BurnchainHeaderHash,
    chainstate::stacks::db::{
        ChainStateBootData, ChainstateAccountBalance, ChainstateAccountLockup, StacksChainState,
    },
    chainstate::{
        burn::BlockHeaderHash,
        stacks::{index::MarfTrieId, StacksBlockId},
    },
    vm::costs::ExecutionCost,
};
use std::env;

pub fn get_account_lockups(
    use_test_chainstate_data: bool,
) -> Box<dyn Iterator<Item = ChainstateAccountLockup>> {
    Box::new(
        stx_genesis::GenesisData::new(use_test_chainstate_data)
            .read_lockups()
            .map(|item| ChainstateAccountLockup {
                address: item.address,
                amount: item.amount,
                block_height: item.block_height,
            }),
    )
}

pub fn get_account_balances(
    use_test_chainstate_data: bool,
) -> Box<dyn Iterator<Item = ChainstateAccountBalance>> {
    Box::new(
        stx_genesis::GenesisData::new(use_test_chainstate_data)
            .read_balances()
            .map(|item| ChainstateAccountBalance {
                address: item.address,
                amount: item.amount,
            }),
    )
}

fn main() {
    let _dhat = Dhat::start_heap_profiling();
    let argv: Vec<_> = env::args().collect();

    match std::fs::remove_dir_all("/tmp/test-bench-genesis-boot") {
        Ok(_) => eprintln!("Removed prior test data"),
        Err(_) => {}
    }

    let mut boot_data = ChainStateBootData {
        initial_balances: vec![],
        post_flight_callback: None,
        first_burnchain_block_hash: BurnchainHeaderHash::sentinel(),
        first_burnchain_block_height: 0,
        first_burnchain_block_timestamp: 1,
        get_bulk_initial_lockups: Some(Box::new(|| get_account_lockups(false))),
        get_bulk_initial_balances: Some(Box::new(|| get_account_balances(false))),
    };

    let (chain_state_db, receipts) = StacksChainState::open_and_exec(
        false,
        0x80000000,
        "/tmp/test-bench-genesis-boot",
        Some(&mut boot_data),
        ExecutionCost::max_value(),
    )
    .unwrap();

    println!("Finished!");
}
