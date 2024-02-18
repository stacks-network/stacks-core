use fake::{Fake, Faker};

use super::*;
use crate::vm::analysis::CheckErrors;
use crate::vm::contracts::Contract;
use crate::vm::database::{
    ClarityDatabase, MemoryBackingStore, RollbackWrapper, SqliteConnection, NULL_BURN_STATE_DB,
    NULL_HEADER_DB,
};
use crate::vm::types::QualifiedContractIdentifier;
use crate::vm::ContractContext;

#[test]
fn contract_exists_using_pending_data() {
    let conn = SqliteConnection::memory().unwrap();

    let mut store = MemoryBackingStore::new();
    let mut wrapper = RollbackWrapper::new(&mut store);

    let bhh = random_stacks_block_id();
    let height = random_height();

    let src: String = Faker.fake();
    let context: ContractContext = Faker.fake();

    wrapper.nest();

    wrapper
        .put_contract(src, context.clone())
        .expect("failed to put contract");

    let exists = wrapper
        .has_contract(&context.contract_identifier)
        .expect("failed to check if contract exists");
    assert!(exists);

    let nonexistent_contract_id = QualifiedContractIdentifier::local(&random_string(20)).unwrap();
    let exists = wrapper
        .has_contract(&nonexistent_contract_id)
        .expect("failed to check if contract exists");
    assert!(!exists);
}

#[test]
fn contract_exists_using_committed_data() {
    let conn = SqliteConnection::memory().unwrap();

    let mut store = MemoryBackingStore::new();
    let mut wrapper = RollbackWrapper::new(&mut store);
    // let mut db = ClarityDatabase::new_with_rollback_wrapper(
    //     wrapper,
    //     &NULL_HEADER_DB,
    //     &NULL_BURN_STATE_DB
    // );
    // db.begin();

    let bhh = random_stacks_block_id();
    let height = random_height();

    let src: String = Faker.fake();
    let context: ContractContext = Faker.fake();

    wrapper.nest();

    wrapper
        .put_contract(src, context.clone())
        .expect("failed to put contract");

    wrapper.commit();

    // db.insert_contract2(
    //         Contract {
    //             contract_context: context.clone()
    //         },
    //         &src
    //     ).expect("failed to put contract");

    // db.commit();

    // db.begin();

    let exists = wrapper
        .has_contract(&context.contract_identifier)
        .expect("failed to check if contract exists");
    assert!(exists);

    let nonexistent_contract_id = QualifiedContractIdentifier::local(&random_string(20)).unwrap();
    let exists = wrapper
        .has_contract(&nonexistent_contract_id)
        .expect("failed to check if contract exists");
    assert!(!exists);
}
