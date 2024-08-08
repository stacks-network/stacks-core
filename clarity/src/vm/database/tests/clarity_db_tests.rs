// Copyright (C) 2013-2020 Blockstack PBC, a public benefit corporation
// Copyright (C) 2020 Stacks Open Internet Foundation
//
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.
//
// This program is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
// GNU General Public License for more details.
//
// You should have received a copy of the GNU General Public License
// along with this program.  If not, see <http://www.gnu.org/licenses/>.

use proptest::prelude::*;
use stacks_common::proptesting::sha_512_trunc_256_sum;
use stacks_common::util::hash::Sha512Trunc256Sum;

use crate::proptesting::*;
use crate::vm::contracts::Contract;
use crate::vm::database::clarity_store::ContractCommitment;
use crate::vm::database::{
    ClarityBackingStore, ClarityDatabase, ClaritySerializable, MemoryBackingStore,
    NULL_BURN_STATE_DB, NULL_HEADER_DB,
};
use crate::vm::Value;

proptest! {
    #[test]
    fn insert_contract(contract in contract()) {
        let mut store = MemoryBackingStore::new();
        let mut db = ClarityDatabase::new(&mut store, &NULL_HEADER_DB, &NULL_BURN_STATE_DB);

        db.begin();

        let contract_id = contract.contract_context.contract_identifier.clone();

        db.insert_contract(&contract_id, contract)
            .expect("failed to insert contract into backing store");

        let exists = sql_metadata_table_key_count(&mut store, &contract_id.to_string()) > 0;
        assert!(!exists);
    }

    #[test]
    fn get_contract(contract in contract()) {
        let mut store = MemoryBackingStore::new();
        let mut db = ClarityDatabase::new(&mut store, &NULL_HEADER_DB, &NULL_BURN_STATE_DB);

        db.begin();

        let contract_id = contract.contract_context.contract_identifier.clone();

        db.insert_contract(&contract_id, contract.clone())
            .expect("failed to insert contract into backing store");

        let retrieved_contract = db
            .get_contract(&contract_id)
            .expect("failed to retrieve contract from backing store");

        assert_eq!(contract, retrieved_contract);
    }

    #[test]
    fn insert_contract_without_begin_should_fail(contract in contract()) {
        let mut store = MemoryBackingStore::new();
        let mut db = ClarityDatabase::new(&mut store, &NULL_HEADER_DB, &NULL_BURN_STATE_DB);

        let contract_id = contract.contract_context.contract_identifier.clone();

        db.insert_contract(&contract_id, contract)
            .expect_err("inserting contract without a begin should fail");
    }

    #[test]
    fn insert_contract_with_commit_should_exist_in_backing_store(contract in contract()) {
        let mut store = MemoryBackingStore::new();
        let mut db = ClarityDatabase::new(&mut store, &NULL_HEADER_DB, &NULL_BURN_STATE_DB);

        db.begin();

        let contract_id = contract.contract_context.contract_identifier.clone();

        db.insert_contract(&contract_id, contract.clone())
            .expect("failed to insert contract into backing store");

        db.commit().expect("failed to commit to backing store");

        let contract_key = format!(
            "clr-meta::{}::vm-metadata::9::contract",
            contract_id.to_string()
        );

        let count = sql_metadata_table_key_count(&mut store, &contract_key);

        assert_eq!(1, count);
    }

    #[test]
    fn put_data_no_commit(
        key in any::<String>(),
        block_height in any::<u32>(),
        hash in sha_512_trunc_256_sum()
    ) {
        let mut store = MemoryBackingStore::new();
        let mut db = ClarityDatabase::new(&mut store, &NULL_HEADER_DB, &NULL_BURN_STATE_DB);

        db.begin();

        db.put_data(
            &key,
            &ContractCommitment {
                block_height,
                hash,
            },
        )
        .expect("failed to put data");

        let count = sql_data_table_key_count(&mut store, &key.to_string());
        assert_eq!(0, count);
    }

    #[test]
    fn put_data_with_commit_should_exist_in_backing_store(
        key in any::<String>(),
        block_height in any::<u32>(),
        hash in sha_512_trunc_256_sum()
    ) {
        let mut store = MemoryBackingStore::new();
        let mut db = ClarityDatabase::new(&mut store, &NULL_HEADER_DB, &NULL_BURN_STATE_DB);

        db.begin();

        db.put_data(
            &key,
            &ContractCommitment {
                block_height,
                hash,
            },
        )
        .expect("failed to put data");

        db.commit().expect("failed to commit to backing store");

        let count = sql_data_table_key_count(&mut store, &key.to_string());
        assert_eq!(1, count);
    }

    #[test]
    fn put_data_without_begin_fails(
        key in any::<String>(),
        block_height in any::<u32>(),
        hash in sha_512_trunc_256_sum()
    ) {
        let mut store = MemoryBackingStore::new();
        let mut db = ClarityDatabase::new(&mut store, &NULL_HEADER_DB, &NULL_BURN_STATE_DB);

        db.put_data(
            &key,
            &ContractCommitment {
                block_height,
                hash,
            },
        )
        .expect_err("expected not-nested error");
    }
}

/// Returns the number of rows in the metadata table for the provided key.
fn sql_metadata_table_key_count<S: ClarityBackingStore>(store: &mut S, key: &str) -> u32 {
    let sqlite = store.get_side_store();
    let count = sqlite
        .query_row(
            "SELECT COUNT(*) FROM metadata_table WHERE key = ?1;",
            &[key],
            |row| {
                let i: u32 = row.get(0)?;
                Ok(i)
            },
        )
        .expect("failed to verify results in sqlite");
    count
}

/// Returns the number of rows in the `data_table` with the given key.
fn sql_data_table_key_count<S: ClarityBackingStore>(store: &mut S, key: &str) -> u32 {
    let sqlite = store.get_side_store();
    let count = sqlite
        .query_row(
            "SELECT COUNT(*) FROM data_table WHERE key = ?1;",
            &[key],
            |row| {
                let i: u32 = row.get(0)?;
                Ok(i)
            },
        )
        .expect("failed to verify results in sqlite");
    count
}
