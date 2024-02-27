use fake::{Fake, Faker};
use stacks_common::types::StacksEpochId;

use super::{random_contract_and_analysis, random_contract_id, CONTRACT_SRC};
use crate::vm::analysis::ContractAnalysis;
use crate::vm::ast::build_ast;
use crate::vm::contracts::Contract;
use crate::vm::costs::LimitedCostTracker;
use crate::vm::database::structures::GetContractResult;
use crate::vm::database::{
    ClarityBackingStore, MemoryBackingStore, RollbackWrapper, SqliteConnection,
};
use crate::vm::types::QualifiedContractIdentifier;
use crate::vm::{ClarityVersion, ContractContext};

/// Generic test which tests that both a contract and its analysis can be
/// put into the [RollbackWrapper] and then retrieved. Validates that
/// the contract and analysis do not get persisted to the underlying store.
#[test]
fn can_put_contract_and_analysis_in_nested_context() {
    let mut store = MemoryBackingStore::new();
    let mut kv = RollbackWrapper::new(&mut store);

    let (contract_context, analysis) = random_contract_and_analysis();

    kv.nest();

    kv.put_contract(CONTRACT_SRC, contract_context)
        .expect("failed to put contract");

    kv.put_contract_analysis(&analysis);

    assert_eq!(SqliteConnection::contract_count(store.get_side_store()), 0);
    assert_eq!(SqliteConnection::analysis_count(store.get_side_store()), 0);
}

#[test]
fn can_get_analysis_nested_1() {
    let mut store = MemoryBackingStore::new();
    let mut kv = RollbackWrapper::new(&mut store);

    let (contract_context, analysis) = random_contract_and_analysis();
    let contract_id = contract_context.contract_identifier.clone();

    kv.nest();

    kv.put_contract(CONTRACT_SRC, contract_context.clone())
        .expect("failed to put contract");

    kv.put_contract_analysis(&analysis);

    let result = kv
        .get_contract_analysis(&contract_id)
        .expect("failed to get contract analysis")
        .expect("contract analysis not found");
}

#[test]
fn can_get_nested_analyses() {
    let mut store = MemoryBackingStore::new();
    let mut kv = RollbackWrapper::new(&mut store);

    let mut contract_ids = Vec::<QualifiedContractIdentifier>::with_capacity(10);

    for _ in 0..10 {
        kv.nest();

        let (contract_context, analysis) = random_contract_and_analysis();
        let contract_id = contract_context.contract_identifier.clone();

        kv.put_contract(CONTRACT_SRC, contract_context)
            .expect("failed to put contract");

        kv.put_contract_analysis(&analysis);

        contract_ids.push(contract_id);

        for id in &contract_ids {
            let result = kv
                .get_contract_analysis(id)
                .expect("failed to get contract analysis")
                .expect("contract analysis not found");
        }
    }
}

/// Tests putting a single contract into the [RollbackWrapper] with
/// a single level of nesting and ensures that the contract can be retrieved.
#[test]
fn can_get_contract_nested_1() {
    let mut store = MemoryBackingStore::new();
    let mut kv = RollbackWrapper::new(&mut store);

    let (contract_context, analysis) = random_contract_and_analysis();
    let contract_id = contract_context.contract_identifier.clone();

    kv.nest();

    kv.put_contract(CONTRACT_SRC, contract_context.clone())
        .expect("failed to put contract");

    let result = kv
        .get_contract(&contract_id)
        .expect("failed to get contract");

    match result {
        GetContractResult::NotFound => panic!("contract not found"),
        GetContractResult::Stored(_) => panic!("contract should not be stored"),
        GetContractResult::Pending(c) => {
            assert_eq!(c.source, CONTRACT_SRC);
            assert_eq!(c.contract, contract_context);
        }
    }
}

/// Tests putting a number of contracts into the [RollbackWrapper] with multiple
/// levels of nesting and ensures that the contracts for all levels and be
/// retrieved from any other level. This test only tests un-committed data.
#[test]
fn can_get_nested_contracts_multilevel() {
    let mut store = MemoryBackingStore::new();
    let mut kv = RollbackWrapper::new(&mut store);

    let mut contract_ids = Vec::<QualifiedContractIdentifier>::with_capacity(10);

    for _ in 0..10 {
        kv.nest();

        let (contract_context, analysis) = random_contract_and_analysis();
        let contract_id = contract_context.contract_identifier.clone();

        kv.put_contract(CONTRACT_SRC, contract_context)
            .expect("failed to put contract");

        contract_ids.push(contract_id);

        for id in &contract_ids {
            let result = kv.get_contract(id).expect("failed to get contract");

            match result {
                GetContractResult::NotFound => panic!("contract not found"),
                GetContractResult::Stored(_) => panic!("contract should not be stored"),
                GetContractResult::Pending(c) => {
                    assert_eq!(c.source, CONTRACT_SRC);
                    assert_eq!(c.contract.contract_identifier, *id);
                }
            }
        }
    }
}

#[test]
fn contract_put_rollback() {
    let mut store = MemoryBackingStore::new();

    let mut kv = RollbackWrapper::new(&mut store);

    let (contract_context, analysis) = random_contract_and_analysis();
    let contract_id = contract_context.contract_identifier.clone();

    kv.nest();
    assert_eq!(kv.depth(), 1);

    kv.put_contract(CONTRACT_SRC, contract_context.clone())
        .expect("failed to put contract");

    kv.rollback().expect("failed to roll-back");

    let result = kv
        .get_contract(&contract_id)
        .expect("failed to get contract");

    match result {
        GetContractResult::NotFound => {}
        GetContractResult::Stored(_) => panic!("contract should not be stored"),
        GetContractResult::Pending(_) => panic!("contract should not be pending"),
    }
}

#[test]
fn contract_put_commit() {
    let mut store = MemoryBackingStore::new();
    let mut kv = RollbackWrapper::new(&mut store);

    let (contract_context, analysis) = random_contract_and_analysis();
    let contract_id = contract_context.contract_identifier.clone();

    kv.nest();
    assert_eq!(kv.depth(), 1);

    kv.put_contract(CONTRACT_SRC, contract_context.clone())
        .expect("failed to put contract");

    kv.commit().expect("failed to commit");

    let result = kv
        .get_contract(&contract_id)
        .expect("failed to get contract");

    match result {
        GetContractResult::NotFound => panic!("contract not found"),
        GetContractResult::Stored(c) => {
            assert_eq!(c.source, CONTRACT_SRC);
            assert_eq!(c.contract.contract_identifier, contract_id);
        }
        GetContractResult::Pending(_) => panic!("contract should not be pending"),
    }
}

#[test]
fn analysis_put_commit() {
    let mut store = MemoryBackingStore::new();
    let mut kv = RollbackWrapper::new(&mut store);

    let (contract_context, analysis) = random_contract_and_analysis();
    let contract_id = contract_context.contract_identifier.clone();

    kv.nest();
    assert_eq!(kv.depth(), 1);

    kv.put_contract(CONTRACT_SRC, contract_context.clone())
        .expect("failed to put contract");

    kv.put_contract_analysis(&analysis);

    kv.commit().expect("failed to commit");

    let result = kv
        .get_contract_analysis(&contract_id)
        .expect("failed to get contract analysis")
        .expect("contract analysis not found");
}

#[test]
fn contract_put_commit_nest_put_nest_put_rollback() {
    let mut store = MemoryBackingStore::new();
    let mut kv = RollbackWrapper::new(&mut store);

    let (contract_1_context, _) = random_contract_and_analysis();
    let contract_1_id = contract_1_context.contract_identifier.clone();

    let (contract_2_context, _) = random_contract_and_analysis();
    let contract_2_id = contract_2_context.contract_identifier.clone();

    let (contract_3_context, _) = random_contract_and_analysis();
    let contract_3_id = contract_3_context.contract_identifier.clone();

    kv.nest();
    assert_eq!(kv.depth(), 1);

    kv.put_contract(CONTRACT_SRC, contract_1_context.clone())
        .expect("failed to put contract");

    kv.commit().expect("failed to commit");
    assert_eq!(kv.depth(), 0);

    kv.nest();
    assert_eq!(kv.depth(), 1);
    kv.put_contract(CONTRACT_SRC, contract_2_context.clone())
        .expect("failed to put contract");

    kv.nest();
    assert_eq!(kv.depth(), 2);
    kv.put_contract(CONTRACT_SRC, contract_3_context.clone())
        .expect("failed to put contract");

    kv.rollback().expect("failed to rollback");
    assert_eq!(kv.depth(), 1);

    let result_1 = kv
        .get_contract(&contract_1_id)
        .expect("failed to get contract");
    assert!(matches!(result_1, GetContractResult::Stored(_)));

    let result_2 = kv
        .get_contract(&contract_2_id)
        .expect("failed to get contract");
    assert!(matches!(result_2, GetContractResult::Pending(_)));

    let result_3 = kv
        .get_contract(&contract_3_id)
        .expect("failed to get contract");
    assert!(matches!(result_3, GetContractResult::NotFound));
}

#[test]
fn contract_put_nest_put_commit() {
    let mut store = MemoryBackingStore::new();
    let mut kv = RollbackWrapper::new(&mut store);

    let (contract_1_context, _) = random_contract_and_analysis();
    let contract_1_id = contract_1_context.contract_identifier.clone();

    let (contract_2_context, _) = random_contract_and_analysis();
    let contract_2_id = contract_2_context.contract_identifier.clone();

    kv.nest();
    assert_eq!(kv.depth(), 1);

    kv.put_contract(CONTRACT_SRC, contract_1_context.clone())
        .expect("failed to put contract");

    kv.nest();
    assert_eq!(kv.depth(), 2);

    kv.put_contract(CONTRACT_SRC, contract_2_context.clone())
        .expect("failed to put contract");

    kv.commit().expect("failed to commit");
    assert_eq!(kv.depth(), 1);

    let result_1 = kv
        .get_contract(&contract_1_id)
        .expect("failed to get contract");
    assert!(matches!(result_1, GetContractResult::Pending(_)));
    let result_2 = kv
        .get_contract(&contract_2_id)
        .expect("failed to get contract");
    assert!(matches!(result_2, GetContractResult::Pending(_)));

    kv.commit().expect("failed to commit");
    assert_eq!(kv.depth(), 0);

    let result_1 = kv
        .get_contract(&contract_1_id)
        .expect("failed to get contract");
    assert!(matches!(result_1, GetContractResult::Stored(_)));

    let result_2 = kv
        .get_contract(&contract_2_id)
        .expect("failed to get contract");
    assert!(matches!(result_2, GetContractResult::Stored(_)));
}
