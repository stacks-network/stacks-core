// Copyright (C) 2013-2020 Blockstack PBC, a public benefit corporation
// Copyright (C) 2020-2022 Stacks Open Internet Foundation
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

use super::*;
use crate::chainstate::stacks::index::marf::*;
use crate::chainstate::stacks::index::test::*;
use crate::chainstate::stacks::index::*;

#[test]
fn verifier_catches_stale_proof() {
    use std::env;
    env::set_var("BLOCKSTACK_TEST_PROOF_ALLOW_INVALID", "1");

    let marf_opts = MARFOpenOpts::default();
    let mut m = MARF::from_path(":memory:", marf_opts).unwrap();

    let sentinel_block = BlockHeaderHash::sentinel();
    let block_0 = BlockHeaderHash([0u8; 32]);
    let block_1 = BlockHeaderHash([1u8; 32]);
    let block_2 = BlockHeaderHash([2u8; 32]);

    let k1 = "K1".to_string();
    let old_v = "OLD".to_string();
    let new_v = "NEW".to_string();

    m.begin(&sentinel_block, &block_0).unwrap();
    m.commit().unwrap();

    // Block #1
    m.begin(&block_0, &block_1).unwrap();
    let r = m.insert(&k1, MARFValue::from_value(&old_v));
    m.seal().unwrap();
    let (_, root_hash_1) = Trie::read_root(&mut m.borrow_storage_backend()).unwrap();
    m.commit().unwrap();

    // Block #2
    m.begin(&block_1, &block_2).unwrap();
    let r = m.insert(&k1, MARFValue::from_value(&new_v));
    m.seal().unwrap();
    let (_, root_hash_2) = Trie::read_root(&mut m.borrow_storage_backend()).unwrap();
    m.commit().unwrap();

    let old_value = m.get(&block_1, &k1);
    test_debug!("OLD: {:?}", old_value);

    let new_value = m.get(&block_2, &k1).unwrap().unwrap();
    test_debug!("NEW: {:?}", new_value);

    let path = TriePath::from_key(&k1);

    merkle_test_marf_key_value(&mut m.borrow_storage_backend(), &block_2, &k1, &new_v, None);

    let root_to_block = m
        .borrow_storage_backend()
        .read_root_to_block_table()
        .unwrap();

    // create a proof from the current block to the old value.
    // It should succeed
    let proof_2 =
        TrieMerkleProof::from_entry(&mut m.borrow_storage_backend(), &k1, &old_v, &block_2)
            .unwrap();

    // the verifier should not allow a proof from k1 to old_v from block_2
    let triepath_2 = TriePath::from_key(&k1);
    let marf_value_2 = MARFValue::from_value(&old_v);
    assert!(!proof_2.verify(&triepath_2, &marf_value_2, &root_hash_2, &root_to_block));

    // create a proof from the previous block to the old value.
    // It should succeed
    let proof_1 =
        TrieMerkleProof::from_entry(&mut m.borrow_storage_backend(), &k1, &old_v, &block_1)
            .unwrap();

    // the verifier should allow a proof from k1 to old_v from block_1
    let triepath_1 = TriePath::from_key(&k1);
    let marf_value_1 = MARFValue::from_value(&old_v);
    assert!(proof_1.verify(&triepath_1, &marf_value_1, &root_hash_1, &root_to_block));
}

#[test]
fn ncc_verifier_catches_stale_proof() {
    let marf_opts = MARFOpenOpts::default();
    let mut m = MARF::from_path(":memory:", marf_opts).unwrap();

    let sentinel_block = BlockHeaderHash::sentinel();
    let block_0 = BlockHeaderHash([0u8; 32]);
    let block_1 = BlockHeaderHash([1u8; 32]);
    let block_2 = BlockHeaderHash([2u8; 32]);
    let block_3 = BlockHeaderHash([3u8; 32]);
    let block_4 = BlockHeaderHash([4u8; 32]);
    let block_5 = BlockHeaderHash([5u8; 32]);

    let k1 = "K1".to_string();
    let old_v = "OLD".to_string();
    let new_v = "NEW".to_string();
    let new_new_v = "NEWNEW".to_string();
    let new_new_new_v = "NEWNEWNEW".to_string();
    let another_v = "ANOTHERV".to_string();

    m.begin(&sentinel_block, &block_0).unwrap();
    m.commit().unwrap();

    // Block #1
    m.begin(&block_0, &block_1).unwrap();
    let r = m.insert(&k1, MARFValue::from_value(&new_v));
    m.seal().unwrap();
    let (_, root_hash_1) = Trie::read_root(&mut m.borrow_storage_backend()).unwrap();
    m.commit().unwrap();

    // Block #2
    m.begin(&block_1, &block_2).unwrap();
    let r = m.insert(&k1, MARFValue::from_value(&old_v));
    m.seal().unwrap();
    let (_, root_hash_2) = Trie::read_root(&mut m.borrow_storage_backend()).unwrap();
    m.commit().unwrap();

    // Block #3
    m.begin(&block_2, &block_3).unwrap();
    let r = m.insert(&k1, MARFValue::from_value(&new_new_v));
    m.seal().unwrap();
    let (_, root_hash_3) = Trie::read_root(&mut m.borrow_storage_backend()).unwrap();
    m.commit().unwrap();

    // Block #4
    m.begin(&block_3, &block_4).unwrap();
    let r = m.insert(&k1, MARFValue::from_value(&new_v));
    m.seal().unwrap();
    let (_, root_hash_4) = Trie::read_root(&mut m.borrow_storage_backend()).unwrap();
    m.commit().unwrap();

    // Block #5
    m.begin(&block_4, &block_5).unwrap();
    let r = m.insert(&k1, MARFValue::from_value(&another_v));
    m.seal().unwrap();
    let (_, root_hash_5) = Trie::read_root(&mut m.borrow_storage_backend()).unwrap();
    m.commit().unwrap();

    merkle_test_marf_key_value(
        &mut m.borrow_storage_backend(),
        &block_5,
        &k1,
        &another_v,
        None,
    );
    merkle_test_marf_key_value(&mut m.borrow_storage_backend(), &block_2, &k1, &old_v, None);

    let root_to_block = {
        m.borrow_storage_backend()
            .read_root_to_block_table()
            .unwrap()
    };

    // prove for latest k/v pair succeeds
    let proof_5 =
        TrieMerkleProof::from_entry(&mut m.borrow_storage_backend(), &k1, &another_v, &block_5)
            .unwrap();

    let triepath_4 = TriePath::from_key(&k1);
    let marf_value_4 = MARFValue::from_value(&another_v);
    let root_to_block = {
        m.borrow_storage_backend()
            .read_root_to_block_table()
            .unwrap()
    };

    println!("DEBUG: verify(another_v)");
    assert!(proof_5.verify(&triepath_4, &marf_value_4, &root_hash_5, &root_to_block));

    // prepare a proof for the wrong root hash i.e. block2 instead of block5.
    // Should fail
    let proof_5 =
        TrieMerkleProof::from_entry(&mut m.borrow_storage_backend(), &k1, &old_v, &block_2)
            .unwrap();

    let triepath_4 = TriePath::from_key(&k1);
    let marf_value_4 = MARFValue::from_value(&old_v);
    let root_to_block = {
        m.borrow_storage_backend()
            .read_root_to_block_table()
            .unwrap()
    };

    println!("DEBUG: verify(old_v)");
    assert!(!proof_5.verify(&triepath_4, &marf_value_4, &root_hash_5, &root_to_block));
}
