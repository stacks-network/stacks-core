// Copyright (C) 2026 Stacks Open Internet Foundation
//
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.
//
// This program is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
// GNU General Public License for more details.
//
// You should have received a copy of the GNU General Public License
// along with this program. If not, see <http://www.gnu.org/licenses/>.

//! Contracts for serializing extensions and installing their bytes.

use std::io::Read;
use std::{assert_matches, fs, io};

use stacks_common::types::chainstate::{BlockHeaderHash, TrieHash};

use crate::blob_layout::{BlobHeader, READER_PREFIX_LEN};
use crate::marf::{MARFOpenOpts, MarfConnection, MARF};
use crate::test::opts;
use crate::trie::Trie;
use crate::{trie_sql, ClarityMarfTrieId, Error, MARFValue};

/// Provisional identity reused after serialization and rollback.
const PLACEHOLDER: BlockHeaderHash = BlockHeaderHash([0; 32]);
/// Committed parent of each serialized extension.
const PARENT: BlockHeaderHash = BlockHeaderHash([1; 32]);
/// Destination identity assigned during promotion.
const TARGET: BlockHeaderHash = BlockHeaderHash([2; 32]);

/// Seed a parent; larger key counts allow compressed extensions to contain patches.
fn setup(path: &str, options: &MARFOpenOpts, key_count: usize) -> MARF<BlockHeaderHash> {
    let mut marf = MARF::from_path(path, options.clone()).unwrap();
    marf.begin(&BlockHeaderHash::sentinel(), &PARENT).unwrap();
    let keys: Vec<_> = (0..key_count).map(|i| format!("key-{i}")).collect();
    marf.insert_batch(&keys, vec![MARFValue::from_value("parent"); key_count])
        .unwrap();
    marf.commit().unwrap();
    marf
}

/// Serialize a one-key update without registering its provisional identity.
fn serialize_update(marf: &mut MARF<BlockHeaderHash>) -> (TrieHash, Vec<u8>) {
    marf.begin(&PARENT, &PLACEHOLDER).unwrap();
    marf.insert("key-0", MARFValue::from_value("updated"))
        .unwrap();
    let root = marf.seal().unwrap();
    let mut tx = marf.begin_tx().unwrap();
    let bytes = tx.serialize_and_discard().unwrap();
    tx.commit().unwrap();
    (root, bytes)
}

/// Read the installed bytes directly from either storage backend.
fn stored_bytes(marf: &mut MARF<BlockHeaderHash>, target: &BlockHeaderHash) -> Vec<u8> {
    let mut tx = marf.borrow_storage_transaction();
    let bytes = tx.with_trie_blobs(|db, blobs| {
        let id = trie_sql::get_block_identifier(db, target).unwrap();
        match blobs {
            Some(blobs) => blobs.read_trie_blob(db, id).unwrap(),
            None => {
                let mut bytes = Vec::new();
                trie_sql::open_trie_blob(db, id)
                    .unwrap()
                    .read_to_end(&mut bytes)
                    .unwrap();
                bytes
            }
        }
    });
    tx.rollback();
    bytes
}

/// Distinguish a missing block from a failed database query.
fn assert_absent(marf: &MARF<BlockHeaderHash>, target: &BlockHeaderHash) {
    assert_matches!(
        trie_sql::get_block_identifier(marf.sqlite_conn(), target),
        Err(Error::NotFoundError)
    );
}

/// Both sealing paths return the same header and bytes, consume the extension and register nothing.
#[rstest]
#[case::immediate(&opts::OPTS_IMM)]
#[case::deferred(&opts::OPTS_DEF)]
fn serialized_extension_contract(#[case] marf_opts: &MARFOpenOpts) {
    let mut marf = setup(":memory:", marf_opts, 1);
    let parent_root = marf.get_root_hash_at(&PARENT).unwrap();
    let mut previous = None;
    for sealed in [false, true] {
        marf.begin(&PARENT, &PLACEHOLDER).unwrap();
        marf.insert("key-0", MARFValue::from_value("updated"))
            .unwrap();
        let root = sealed.then(|| marf.seal().unwrap());
        let mut tx = marf.begin_tx().unwrap();
        let bytes = tx.serialize_and_discard().unwrap();
        let header =
            BlobHeader::<BlockHeaderHash>::parse(bytes[..READER_PREFIX_LEN].try_into().unwrap());
        assert_eq!(header.parent_hash, PARENT);
        if let Some(root) = root {
            assert_eq!(header.root_hash, root);
        }
        assert_matches!(tx.serialize_and_discard(), Err(Error::NotOpenedError));
        assert_eq!(tx.get_root_hash_at(&PARENT).unwrap(), parent_root);
        tx.commit().unwrap();
        assert_eq!(marf.get_root_hash_at(&PARENT).unwrap(), parent_root);
        assert_absent(&marf, &PLACEHOLDER);
        if let Some(previous) = previous {
            assert_eq!(bytes, previous);
        }
        previous = Some(bytes);
    }
}

/// Savepoint recovery releases a serialized extension's lock independently of the read cursor.
#[test]
fn serialized_extension_savepoint_recovery() {
    let mut marf = setup(":memory:", &opts::OPTS_IMM, 1);
    let parent_root = marf.get_root_hash_at(&PARENT).unwrap();
    let mut tx = marf.begin_tx().unwrap();
    tx.begin(&PARENT, &PLACEHOLDER).unwrap();
    tx.sqlite_tx().execute_batch("SAVEPOINT serialize").unwrap();
    tx.serialize_and_discard().unwrap();
    tx.with_conn(|conn| conn.open_block(&PARENT)).unwrap();
    tx.sqlite_tx()
        .execute_batch("ROLLBACK TO serialize; RELEASE serialize")
        .unwrap();
    assert_eq!(
        tx.sqlite_tx()
            .query_row("SELECT COUNT(*) FROM block_extension_locks", [], |row| row
                .get::<_, u32>(
                0
            ))
            .unwrap(),
        1
    );
    tx.discard_trie_and_commit().unwrap();
    assert_eq!(marf.get_root_hash_at(&PARENT).unwrap(), parent_root);
    marf.begin(&PARENT, &PLACEHOLDER).unwrap();
    marf.drop_current();
}

/// Promotion preserves bytes and ancestor references even when another fork takes the next row ID.
#[apply(opts::tpl_all_opts)]
fn serialized_promotion_round_trip(marf_opts: &MARFOpenOpts) {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("marf.sqlite");
    let mut marf = setup(path.to_str().unwrap(), marf_opts, 256);
    let (root, bytes) = serialize_update(&mut marf);
    let sibling = BlockHeaderHash([3; 32]);
    marf.begin(&PARENT, &PLACEHOLDER).unwrap();
    marf.insert("sibling-only", MARFValue::from_value("sibling"))
        .unwrap();
    marf.commit_to(&sibling).unwrap();

    let mut tx = marf.begin_tx().unwrap();
    tx.begin(&PARENT, &PLACEHOLDER).unwrap();
    tx.insert_batch(
        &["temporary".into()],
        vec![MARFValue::from_value("discard")],
    )
    .unwrap();
    tx.promote_from(&TARGET, bytes.len() as u64, |_, writer| {
        Ok(writer.write_all(&bytes)?)
    })
    .unwrap();
    tx.commit().unwrap();
    drop(marf);

    let mut marf = MARF::from_path(path.to_str().unwrap(), marf_opts.clone()).unwrap();
    assert_eq!(stored_bytes(&mut marf, &TARGET), bytes);
    assert_eq!(marf.get_root_hash_at(&TARGET).unwrap(), root);
    for (key, value) in [("key-0", "updated"), ("key-1", "parent")] {
        assert_eq!(
            marf.get(&TARGET, key).unwrap(),
            Some(MARFValue::from_value(value))
        );
    }
    assert_eq!(marf.get(&TARGET, "temporary").unwrap(), None);
    assert_eq!(marf.get(&TARGET, "sibling-only").unwrap(), None);
    if marf_opts.compress {
        marf.open_block(&TARGET).unwrap();
        let (root, _) = Trie::read_root(&mut marf.borrow_storage_backend()).unwrap();
        assert!(
            !root.get_patches().is_empty(),
            "exercise actual compressed patches"
        );
    }
}

/// Failed external registration preserves accepted bytes; reopening and retry reuse the orphan extent.
#[test]
fn serialized_promotion_registration_failure_reuses_extent() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("marf.sqlite");
    let blob_path = path.with_extension("sqlite.blobs");
    let mut marf = setup(path.to_str().unwrap(), &opts::OPTS_IMM_EXT, 1);
    let (_, bytes) = serialize_update(&mut marf);
    let mut expected = fs::read(&blob_path).unwrap();
    let offset = expected.len() as u64;
    marf.sqlite_conn()
        .execute_batch(
            "CREATE TEMP TRIGGER fail_registration BEFORE INSERT ON marf_data
         BEGIN SELECT RAISE(ABORT, 'injected registration failure'); END;",
        )
        .unwrap();
    let mut tx = marf.begin_tx().unwrap();
    tx.begin(&PARENT, &PLACEHOLDER).unwrap();
    assert_matches!(
        tx.promote_from(&TARGET, bytes.len() as u64, |_, writer| Ok(writer.write_all(&bytes)?)),
        Err(Error::SQLError(error)) if error.to_string().contains("injected registration failure")
    );
    drop(tx);
    assert_absent(&marf, &TARGET);
    assert_eq!(
        trie_sql::get_external_blobs_length(marf.sqlite_conn()).unwrap(),
        offset
    );
    expected.extend_from_slice(&bytes);
    assert_eq!(fs::read(&blob_path).unwrap(), expected);
    drop(marf);

    // Reopening removes the TEMP trigger but must retain the unregistered extent.
    let mut marf = MARF::from_path(path.to_str().unwrap(), opts::OPTS_IMM_EXT.clone()).unwrap();
    assert_absent(&marf, &TARGET);
    assert_eq!(fs::read(&blob_path).unwrap(), expected);
    let mut tx = marf.begin_tx().unwrap();
    tx.begin(&PARENT, &PLACEHOLDER).unwrap();
    tx.promote_from(&TARGET, bytes.len() as u64, |_, writer| {
        Ok(writer.write_all(&bytes)?)
    })
    .unwrap();
    tx.commit().unwrap();
    assert_eq!(
        trie_sql::get_external_trie_offset_length_by_bhh(marf.sqlite_conn(), &TARGET).unwrap(),
        (offset, bytes.len() as u64)
    );
    assert_eq!(fs::read(&blob_path).unwrap(), expected);
}

/// Copy errors and rollback leave no accepted row and permit another attempt on the same handle.
#[rstest::rstest]
#[case::sqlite(&opts::OPTS_IMM)]
#[case::external(&opts::OPTS_IMM_EXT)]
fn serialized_promotion_errors_and_rollback(#[case] marf_opts: &MARFOpenOpts) {
    let dir = tempfile::tempdir().unwrap();
    let mut marf = setup(
        dir.path().join("marf.sqlite").to_str().unwrap(),
        marf_opts,
        1,
    );
    let (root, bytes) = serialize_update(&mut marf);
    for case in 0..5 {
        let mut tx = marf.begin_tx().unwrap();
        tx.begin(&PARENT, &PLACEHOLDER).unwrap();
        let len = if case == 0 {
            READER_PREFIX_LEN - 1
        } else {
            bytes.len()
        };
        let error = tx
            .promote_from(&TARGET, len as u64, |_, writer| {
                match case {
                    0 => panic!("short-header rejection must precede callback"),
                    1 => writer.write_all(&bytes[..bytes.len() - 1])?,
                    2 => {
                        writer.write_all(&bytes)?;
                        writer.write_all(&[0])?;
                    }
                    3 => {
                        writer.write_all(&bytes[..32])?;
                        return Err(io::Error::other("injected source failure").into());
                    }
                    4 => {
                        writer.write_all(&bytes)?;
                        let _ = writer.write_all(&[0]);
                    }
                    _ => unreachable!(),
                }
                Ok(())
            })
            .unwrap_err();
        if case == 0 {
            assert_matches!(error, Error::CorruptionError(_));
            assert_eq!(tx.get_open_chain_tip(), Some(&PLACEHOLDER));
            tx.drop_current();
        } else {
            assert_matches!(error, Error::IOError(_));
            assert!(tx.get_open_chain_tip().is_none());
            drop(tx);
        }
        assert_absent(&marf, &TARGET);
    }
    // Successful installation must also be reversible until the caller commits.
    for commit in [false, true] {
        let mut tx = marf.begin_tx().unwrap();
        tx.begin(&PARENT, &PLACEHOLDER).unwrap();
        tx.promote_from(&TARGET, bytes.len() as u64, |_, writer| {
            Ok(writer.write_all(&bytes)?)
        })
        .unwrap();
        if commit {
            tx.commit().unwrap();
        } else {
            drop(tx);
            assert_absent(&marf, &TARGET);
        }
    }
    assert_eq!(marf.get_root_hash_at(&TARGET).unwrap(), root);
}
