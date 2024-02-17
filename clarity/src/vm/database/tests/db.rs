use fake::{Fake, Faker};

use crate::vm::{database::{ClarityDatabase, MemoryBackingStore, RollbackWrapper, SqliteConnection, NULL_BURN_STATE_DB, NULL_HEADER_DB}, types::QualifiedContractIdentifier, ContractContext};

use super::*;

#[test]
fn contract_exists() {
    let conn = SqliteConnection::memory()
        .unwrap();

    let bhh = random_stacks_block_id();
    let height = random_height();

    let (identifier, mut contract) = random_contract_data();

    let context: ContractContext = Faker.fake();
    dbg!(context);
    return;

    SqliteConnection::insert_contract(&conn, &bhh, height, &mut contract)
        .expect("failed to insert contract");

    // We're missing the marf/data entry

    let mut store = MemoryBackingStore::new();
    let wrapper= RollbackWrapper::new(&mut store);
    let mut db = ClarityDatabase::new_with_rollback_wrapper(
        wrapper, 
        &NULL_HEADER_DB, 
        &NULL_BURN_STATE_DB
    );
    db.begin();

    let exists = db.has_contract2(&identifier)
        .expect("failed to check if contract exists [1]");
    assert!(exists);

    let exists = db.has_contract2(&QualifiedContractIdentifier::local(&random_string(20)).unwrap())
        .expect("failed to check if contract exists [2]");
    assert!(!exists);
}