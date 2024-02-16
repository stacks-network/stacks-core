
use rand::RngCore;
use stacks_common::types::chainstate::StacksBlockId;

use crate::vm::database::{tests::{assert_contract_eq, random_contract_data}, *};

use self::structures::{ContractData, ContractAnalysisData};

use super::{random_bhh, random_bytes_random_len, random_height, random_stacks_block_id, random_string, random_u32};

#[test]
fn can_create_and_initialize_database() {
    let conn = SqliteConnection::memory()
        .expect("failed to create in-memory SQLite database");

    // The first call runs this, but let's make sure it's idempotent, and
    // just in-case someone changes that...
    SqliteConnection::initialize_conn(&conn)
        .expect("failed to initialize connection");

    // The first call runs this, but just in-case someone changes that...
    SqliteConnection::check_schema(&conn)
        .expect("failed to check schema");
}

#[test]
fn insert_contract() {
    let conn = SqliteConnection::memory()
        .unwrap();

    let bhh = random_stacks_block_id();
    let height = random_height();

    let mut contract = random_contract_data();

    SqliteConnection::insert_contract(&conn, &bhh, height, &mut contract)
        .expect("failed to insert contract");

    assert_eq!(contract.id, 1);
}

#[test]
fn get_contract() {
    let conn = SqliteConnection::memory()
        .unwrap();

    let bhh = random_stacks_block_id();
    let height = random_height();

    let mut contract1 = random_contract_data();
    let mut contract2 = random_contract_data();

    let contract1_id = SqliteConnection::insert_contract(&conn, &bhh, height, &mut contract1)
        .expect("failed to insert contract1");
    let contract2_id = SqliteConnection::insert_contract(&conn, &bhh, height, &mut contract2)
        .expect("failed to insert contract2");

    assert_eq!(contract1.id, 1);
    assert_eq!(contract2.id, 2);

    // Retrieve first contract
    let contract1_retrieved = SqliteConnection::get_contract(
            &conn,
            &contract1.issuer,
            &contract1.name, 
            &bhh
        )
        .expect("failed to retrieve contract1")
        .expect("contract1 was not found");

    assert_eq!(contract1_retrieved.id, contract1.id);
    assert_contract_eq(contract1, contract1_retrieved);

    // Retrieve second contract
    let contract2_retrieved = SqliteConnection::get_contract(
            &conn, 
            &contract2.issuer, 
            &contract2.name, 
            &bhh
        )
        .expect("failed to retrieve contract2")
        .expect("contract2 was not found");

    assert_eq!(contract2_retrieved.id, contract2.id);
    assert_contract_eq(contract2, contract2_retrieved);

    // Retrieve non-existent contract
    let contract3_retrieved = SqliteConnection::get_contract(
            &conn,
            &random_string(20),
            &random_string(20),
            &bhh
        )
        .expect("failed to retrieve contract3");

    assert!(contract3_retrieved.is_none());
}

#[test]
fn insert_contract_analysis() {
    let conn = SqliteConnection::memory()
        .unwrap();

    // Random block/height
    let bhh = random_stacks_block_id();
    let height = random_height();

    // Create a random contract
    let mut contract = random_contract_data();
    SqliteConnection::insert_contract(&conn, &bhh, height, &mut contract)
        .expect("failed to insert contract");
    assert_eq!(contract.id, 1);

    let analysis = random_bytes_random_len(100, 1000);

    SqliteConnection::insert_contract_analysis(&conn, contract.id, &analysis)
        .expect("failed to insert contract analysis");
}

#[test]
#[should_panic]
fn insert_contract_analysis_with_bad_contract_id() {
    let conn = SqliteConnection::memory()
        .unwrap();

    // Random block/height
    let bhh = random_stacks_block_id();
    let height = random_height();

    let analysis = random_bytes_random_len(100, 1000);

    SqliteConnection::insert_contract_analysis(&conn, 999, &analysis)
        .expect("inserted contract analysis with bad contract id");
}