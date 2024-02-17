use fake::{Fake, Faker};

use crate::vm::{analysis::CheckErrors, contracts::Contract, database::{ClarityDatabase, MemoryBackingStore, RollbackWrapper, SqliteConnection, NULL_BURN_STATE_DB, NULL_HEADER_DB}, types::QualifiedContractIdentifier, ContractContext};

use super::*;

#[test]
fn contract_exists() {
    let conn = SqliteConnection::memory()
        .unwrap();

    let mut store = MemoryBackingStore::new();
    let mut wrapper= RollbackWrapper::new(&mut store);
    let mut db = ClarityDatabase::new_with_rollback_wrapper(
        wrapper, 
        &NULL_HEADER_DB, 
        &NULL_BURN_STATE_DB
    );
    db.begin();

    let bhh = random_stacks_block_id();
    let height = random_height();

    let src: String = Faker.fake();
    let context: ContractContext = Faker.fake();

    db.insert_contract2(
            Contract { 
                contract_context: context.clone() 
            }, 
            &src
        ).expect("failed to put contract");

    db.commit();

    db.begin();

    let exists = db.has_contract2(&context.contract_identifier)
        .expect("failed to check if contract exists");
    assert!(exists);

    let nonexistent_contract_id = QualifiedContractIdentifier::local(&random_string(20)).unwrap();
    let exists = db.has_contract2(&nonexistent_contract_id);
    let err = exists.err().expect("an error should have been thrown");
    
    assert_eq!(err, crate::vm::errors::Error::Unchecked(CheckErrors::NoSuchContract(nonexistent_contract_id.to_string())));
}