
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

    let data = random_contract_data();

    let contract_id = SqliteConnection::insert_contract(&conn, &bhh, height, &data);

    assert_eq!(contract_id, 1);
}

#[test]
fn get_contract() {
    let conn = SqliteConnection::memory()
        .unwrap();

    let bhh = random_stacks_block_id();
    let height = random_height();

    let contract1 = random_contract_data();
    let contract2 = random_contract_data();

    let contract1_id = SqliteConnection::insert_contract(&conn, &bhh, height, &contract1);
    let contract2_id = SqliteConnection::insert_contract(&conn, &bhh, height, &contract2);

    assert_eq!(contract1_id, 1);
    assert_eq!(contract2_id, 2);

    // Retrieve first contract
    let contract1_retrieved = SqliteConnection::get_contract(
            &conn,
            &contract1.contract_issuer,
            &contract1.contract_name, 
            &bhh
        ).expect("failed to retrieve contract1");

    assert_eq!(contract1_retrieved.id, Some(contract1_id));
    assert_contract_eq(contract1, contract1_retrieved);

    // Retrieve second contract
    let contract2_retrieved = SqliteConnection::get_contract(
            &conn, 
            &contract2.contract_issuer, 
            &contract2.contract_name, 
            &bhh
        ).expect("failed to retrieve contract2");

    assert_eq!(contract2_retrieved.id, Some(contract2_id));
    assert_contract_eq(contract2, contract2_retrieved);

    // Retrieve non-existent contract
    let contract3_retrieved = SqliteConnection::get_contract(
            &conn,
            &random_string(20),
            &random_string(20),
            &bhh
        );

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
    let data = random_contract_data();
    let contract_id = SqliteConnection::insert_contract(&conn, &bhh, height, &data);
    assert_eq!(contract_id, 1);

    let analysis = random_bytes_random_len(100, 1000);
    let analysis_size = analysis.len() as u32;

    let data = ContractAnalysisData {
        contract_id,
        analysis,
        analysis_size,
    };

    SqliteConnection::insert_contract_analysis(&conn, &data);
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
    let analysis_size = analysis.len() as u32;

    let data = ContractAnalysisData {
        contract_id: 5,
        analysis,
        analysis_size,
    };

    SqliteConnection::insert_contract_analysis(&conn, &data);
}