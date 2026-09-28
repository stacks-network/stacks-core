// Copyright (C) 2013-2020 Blockstack PBC, a public benefit corporation
// Copyright (C) 2020-2026 Stacks Open Internet Foundation
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

use std::collections::BTreeMap;
use std::fs;
use std::io::{self, Read, Seek, SeekFrom};

use pinny::tag;
use proptest::prelude::*;
use rusqlite::{Connection, OpenFlags};
use stacks_common::codec::StacksMessageCodec;

use super::*;
use crate::chainstate::stacks::index::file::*;
use crate::chainstate::stacks::index::*;
use crate::util_lib::db::*;

fn db_path(test_name: &str) -> String {
    let path = format!("/tmp/{}.sqlite", test_name);
    path
}

fn setup_db(test_name: &str) -> Connection {
    let path = db_path(test_name);
    if fs::metadata(&path).is_ok() {
        fs::remove_file(&path).unwrap();
    }

    let mut db = sqlite_open(
        &path,
        OpenFlags::SQLITE_OPEN_READ_WRITE | OpenFlags::SQLITE_OPEN_CREATE,
        true,
    )
    .unwrap();
    trie_sql::create_tables_if_needed(&mut db).unwrap();
    db
}

#[test]
fn test_load_store_trie_blob() {
    let mut db = setup_db("test_load_store_trie_blob");
    let mut blobs = TrieFile::from_db_path(&db_path("test_load_store_trie_blob"), false).unwrap();
    trie_sql::migrate_tables_if_needed::<BlockHeaderHash>(&mut db).unwrap();

    blobs
        .store_trie_blob::<BlockHeaderHash>(&db, &BlockHeaderHash([0x01; 32]), &[1, 2, 3, 4, 5])
        .unwrap();
    blobs
        .store_trie_blob::<BlockHeaderHash>(
            &db,
            &BlockHeaderHash([0x02; 32]),
            &[10, 20, 30, 40, 50],
        )
        .unwrap();

    let block_id = trie_sql::get_block_identifier(&db, &BlockHeaderHash([0x01; 32])).unwrap();
    assert_eq!(blobs.get_trie_offset(&db, block_id).unwrap(), 0);

    let buf = blobs.read_trie_blob(&db, block_id).unwrap();
    assert_eq!(buf, vec![1, 2, 3, 4, 5]);

    let block_id = trie_sql::get_block_identifier(&db, &BlockHeaderHash([0x02; 32])).unwrap();
    assert_eq!(blobs.get_trie_offset(&db, block_id).unwrap(), 5);

    let buf = blobs.read_trie_blob(&db, block_id).unwrap();
    assert_eq!(buf, vec![10, 20, 30, 40, 50]);
}

#[test]
fn test_migrate_tables_readonly_succeeds_when_current() {
    let mut db = setup_db(function_name!());
    // First migrate in writable mode to bring schema to current version
    let previous_version = trie_sql::migrate_tables_if_needed::<BlockHeaderHash>(&mut db).unwrap();
    assert_eq!(previous_version, 1);
    // Now a read-only migration check should succeed
    trie_sql::ensure_no_migration_necessary::<BlockHeaderHash>(&mut db).unwrap();
}

#[test]
fn test_migrate_tables_readonly_fails_when_outdated() {
    let path = db_path("test_migrate_tables_readonly_fail");
    if fs::metadata(&path).is_ok() {
        fs::remove_file(&path).unwrap();
    }
    let mut db = sqlite_open(
        &path,
        OpenFlags::SQLITE_OPEN_READ_WRITE | OpenFlags::SQLITE_OPEN_CREATE,
        true,
    )
    .unwrap();
    trie_sql::create_tables_if_needed(&mut db).unwrap();
    // Don't migrate - schema is at version 1.
    // A read-only open should fail because the schema is outdated.
    let err = trie_sql::ensure_no_migration_necessary::<BlockHeaderHash>(&mut db).unwrap_err();
    assert!(
        matches!(&err, crate::chainstate::stacks::index::Error::CorruptionError(msg) if msg.contains("not compatible with read-only")),
        "instead got: {err}"
    );
}

#[test]
fn test_migrate_existing_trie_blobs() {
    let test_file = "/tmp/test_migrate_existing_trie_blobs.sqlite";
    let test_blobs_file = "/tmp/test_migrate_existing_trie_blobs.sqlite.blobs";
    if fs::metadata(&test_file).is_ok() {
        fs::remove_file(&test_file).unwrap();
    }
    if fs::metadata(&test_blobs_file).is_ok() {
        fs::remove_file(&test_blobs_file).unwrap();
    }

    let (data, last_block_header, root_header_map) = {
        let marf_opts = MARFOpenOpts::new(TrieHashCalculationMode::Deferred, false);

        let f = TrieFileStorage::open(test_file, marf_opts).unwrap();
        let mut marf = MARF::from_storage(f);

        // make data to insert
        let data = make_test_insert_data(128, 128);
        let mut last_block_header = BlockHeaderHash::sentinel();
        for (i, block_data) in data.iter().enumerate() {
            let mut block_hash_bytes = [0u8; 32];
            block_hash_bytes[0..8].copy_from_slice(&(i as u64).to_be_bytes());

            let block_header = BlockHeaderHash(block_hash_bytes);
            marf.begin(&last_block_header, &block_header).unwrap();

            for (key, value) in block_data.iter() {
                let path = TrieHash::from_key(key);
                let leaf = TrieLeaf::from_value(&[], value.clone());
                marf.insert_raw(path, leaf).unwrap();
            }
            marf.commit().unwrap();
            last_block_header = block_header;
        }

        let root_header_map =
            trie_sql::read_all_block_hashes_and_roots::<BlockHeaderHash>(marf.sqlite_conn())
                .unwrap();
        (data, last_block_header, root_header_map)
    };

    // migrate
    let mut marf_opts = MARFOpenOpts::new(TrieHashCalculationMode::Deferred, true);
    marf_opts.force_db_migrate = true;

    let f = TrieFileStorage::open(test_file, marf_opts).unwrap();
    let mut marf = MARF::from_storage(f);

    // blobs file exists
    assert!(fs::metadata(&test_blobs_file).is_ok());

    // verify that the new blob structure is well-formed
    let blob_root_header_map = {
        let mut blobs = TrieFile::from_db_path(test_file, false).unwrap();
        let blob_root_header_map = blobs
            .read_all_block_hashes_and_roots::<BlockHeaderHash>(marf.sqlite_conn())
            .unwrap();
        blob_root_header_map
    };

    assert_eq!(blob_root_header_map.len(), root_header_map.len());
    for (e1, e2) in blob_root_header_map.iter().zip(root_header_map.iter()) {
        assert_eq!(e1, e2);
    }

    // verify that we can read everything from the blobs
    for (i, block_data) in data.iter().enumerate() {
        for (key, value) in block_data.iter() {
            let path = TrieHash::from_key(key);
            let marf_leaf = TrieLeaf::from_value(&[], value.clone());

            let leaf = MARF::get_path(
                &mut marf.borrow_storage_backend(),
                &last_block_header,
                &path,
            )
            .unwrap()
            .unwrap();

            assert_eq!(leaf.data.to_vec(), marf_leaf.data.to_vec());
        }
    }
}

#[test]
fn test_bulk_read_block_entries_rejects_negative_external_offset() {
    let mut db = setup_db("test_bulk_read_block_entries_rejects_negative_external_offset");
    trie_sql::migrate_tables_if_needed::<BlockHeaderHash>(&mut db).unwrap();

    let block_hash = BlockHeaderHash([0x11; 32]);
    db.execute(
        "INSERT INTO marf_data (block_hash, data, unconfirmed, external_offset, external_length) \
         VALUES (?1, ?2, 0, ?3, ?4)",
        rusqlite::params![block_hash.to_string(), Vec::<u8>::new(), -1i64, 0i64],
    )
    .unwrap();

    let err = trie_sql::bulk_read_block_entries::<BlockHeaderHash>(&db).unwrap_err();
    assert!(
        matches!(err, crate::chainstate::stacks::index::Error::OverflowError),
        "instead got: {err:?}"
    );
}

#[test]
fn test_update_squash_root_node_hash_requires_existing_row() {
    let mut db = setup_db("test_update_squash_root_node_hash_requires_existing_row");
    trie_sql::migrate_tables_if_needed::<BlockHeaderHash>(&mut db).unwrap();
    let hash = TrieHash::from_data(b"squash-root");

    let err = trie_sql::update_squash_root_node_hash(&db, &hash).unwrap_err();
    assert!(
        matches!(
            err,
            crate::chainstate::stacks::index::Error::CorruptionError(ref msg)
                if msg.contains("no marf_squash_info row exists")
        ),
        "instead got: {err:?}"
    );
}

#[test]
fn test_migrate_schema_3_creates_squash_tables_on_v2_db() {
    let mut db = setup_db(function_name!());

    // Bring schema to current first, then rewrite the version and drop the
    // schema-3 tables to simulate a pre-squash schema-v2 DB.
    trie_sql::migrate_tables_if_needed::<BlockHeaderHash>(&mut db).unwrap();
    db.execute_batch(
        "DROP TABLE IF EXISTS marf_squash_info; \
         DROP TABLE IF EXISTS marf_squashed_blocks; \
         UPDATE schema_version SET version = 2; \
         UPDATE migrated_version SET version = 2;",
    )
    .unwrap();

    let count_squash_tables = |db: &rusqlite::Connection| -> i64 {
        db.query_row(
            "SELECT COUNT(*) FROM sqlite_master WHERE type='table' \
             AND name IN ('marf_squash_info', 'marf_squashed_blocks')",
            stacks_common::types::sqlite::NO_PARAMS,
            |row| row.get(0),
        )
        .unwrap()
    };
    assert_eq!(
        count_squash_tables(&db),
        0,
        "squash tables should be absent on simulated legacy v2 DB"
    );

    // Migrating from schema 2 to 3 must create the squash tables.
    let previous_version = trie_sql::migrate_tables_if_needed::<BlockHeaderHash>(&mut db).unwrap();
    assert_eq!(previous_version, 2);
    assert_eq!(
        count_squash_tables(&db),
        2,
        "migrate_tables_if_needed must add both squash tables to a v2 DB"
    );
    trie_sql::ensure_no_migration_necessary::<BlockHeaderHash>(&mut db).unwrap();

    // re-running again is a no-op.
    trie_sql::migrate_tables_if_needed::<BlockHeaderHash>(&mut db).unwrap();
    assert_eq!(count_squash_tables(&db), 2);
}

/// The parallel chunked reader must return exactly what per-block
/// `read_blob_header` reads, regardless of how the entries split
/// across worker threads.
#[test]
fn test_bulk_read_blob_headers_sorted_matches_sequential() {
    let dir = tempfile::tempdir().unwrap();
    let marf_path = dir.path().join("bulk_headers.sqlite");
    // 67 blocks: not a multiple of any plausible worker count, so the last
    // chunk is ragged.
    let (mut marf, _, _) = super::marf::setup_marf(marf_path.to_str().unwrap(), 67, 4);

    marf.with_conn(|conn| {
        let mut entries =
            trie_sql::bulk_read_block_entries::<StacksBlockId>(conn.sqlite_conn()).unwrap();
        conn.warm_trie_offsets_from_entries(&entries);
        entries.sort_unstable_by_key(|e| (e.external_offset, e.block_id));
        assert!(entries.len() >= 67);

        let bulk = conn.bulk_read_blob_headers_sorted(&entries).unwrap();
        assert_eq!(bulk.len(), entries.len());
        for entry in &entries {
            let expected = conn.read_blob_header(entry.block_id).unwrap();
            assert_eq!(
                bulk.get(&entry.block_hash),
                Some(&expected),
                "bulk header mismatch for block {}",
                entry.block_hash
            );
        }
    });
}

/// An empty entry list is a valid request: zero entries yield an
/// empty map.
#[test]
fn test_bulk_read_blob_headers_sorted_empty_returns_empty() {
    let dir = tempfile::tempdir().unwrap();
    let marf_path = dir.path().join("bulk_headers_empty.sqlite");
    let (mut marf, _, _) = super::marf::setup_marf(marf_path.to_str().unwrap(), 1, 4);

    marf.with_conn(|conn| {
        let entries =
            trie_sql::bulk_read_block_entries::<StacksBlockId>(conn.sqlite_conn()).unwrap();
        // Empty slice of the right element type, without naming the private entry struct.
        let empty = entries.get(..0).unwrap();
        let headers = conn.bulk_read_blob_headers_sorted(empty).unwrap();
        assert!(headers.is_empty());
    });
}

#[derive(Debug, Clone)]
enum ReaderOp {
    Read(usize),
    SeekStart(u64),
    SeekCurrent(i64),
    SeekEnd(i64),
    Position,
}

fn reader_op() -> impl Strategy<Value = ReaderOp> {
    prop_oneof![
        3 => (0..100usize).prop_map(ReaderOp::Read),
        1 => (0..400u64).prop_map(ReaderOp::SeekStart),
        1 => (-120..120i64).prop_map(ReaderOp::SeekCurrent),
        1 => (-120..40i64).prop_map(ReaderOp::SeekEnd),
        1 => Just(ReaderOp::Position),
    ]
}

/// Apply `op`, reading like the node parsers do: until `n` bytes or end of file.
fn apply_reader_op<R: Read + Seek>(r: &mut R, op: &ReaderOp) -> Result<Vec<u8>, io::ErrorKind> {
    let res = match op {
        ReaderOp::Read(n) => {
            let mut out = vec![];
            r.by_ref()
                .take(*n as u64)
                .read_to_end(&mut out)
                .map(|_| out)
        }
        ReaderOp::SeekStart(pos) => r
            .seek(SeekFrom::Start(*pos))
            .map(|p| p.to_be_bytes().to_vec()),
        ReaderOp::SeekCurrent(d) => r
            .seek(SeekFrom::Current(*d))
            .map(|p| p.to_be_bytes().to_vec()),
        ReaderOp::SeekEnd(d) => r.seek(SeekFrom::End(*d)).map(|p| p.to_be_bytes().to_vec()),
        ReaderOp::Position => r.stream_position().map(|p| p.to_be_bytes().to_vec()),
    };
    res.map_err(|e| e.kind())
}

/// Key space for [`MarfStep`]. Paths spread keys over 4 root children and up to 150
/// grandchildren, so every node type gets persisted.
const DIFF_KEYS: u16 = 600;

fn diff_path(key: u16) -> TrieHash {
    let mut path = [0x5au8; 32];
    path[0] = (key % 4) as u8;
    path[1] = (key / 4) as u8;
    TrieHash(path)
}

#[derive(Debug, Clone)]
enum MarfStep {
    /// Commit a block with these writes.
    Block(Vec<(u16, u8)>),
    /// Commit an unconfirmed trie with these writes atop the tip, read it, then drop it.
    Unconfirmed(Vec<(u16, u8)>),
}

fn marf_step() -> impl Strategy<Value = MarfStep> {
    let writes = prop::collection::vec((0..DIFF_KEYS, any::<u8>()), 1..48);
    prop_oneof![
        3 => writes.clone().prop_map(MarfStep::Block),
        1 => writes.prop_map(MarfStep::Unconfirmed),
    ]
}

/// One MARF under test, plus a read-only handle opened before later blocks were appended.
struct DiffSide {
    path: String,
    opts: MARFOpenOpts,
    marf: MARF<StacksBlockId>,
    ro: Option<MARF<StacksBlockId>>,
}

impl DiffSide {
    fn new(dir: &std::path::Path, external_blobs: bool, compress: bool) -> Self {
        let path = dir
            .join(format!("diff-{external_blobs}.sqlite"))
            .to_str()
            .unwrap()
            .to_string();
        let opts = MARFOpenOpts::new(TrieHashCalculationMode::Deferred, external_blobs)
            .with_compression(compress);
        let marf = MARF::from_path(&path, opts.clone()).unwrap();
        DiffSide {
            path,
            opts,
            marf,
            ro: None,
        }
    }
}

/// Value of `key` at `block`, which must exist; a missing key reads as `NotFoundError`.
fn read_leaf(marf: &mut MARF<StacksBlockId>, block: &StacksBlockId, key: u16) -> Option<MARFValue> {
    match MARF::get_path(&mut marf.borrow_storage_backend(), block, &diff_path(key)) {
        Ok(leaf) => leaf.map(|leaf| leaf.data),
        Err(crate::chainstate::stacks::index::Error::NotFoundError) => None,
        Err(e) => panic!("read of key {key} at {block} failed: {e:?}"),
    }
}

/// Value and serialized proof of `key` at `block`.
fn read_with_proof(
    marf: &mut MARF<StacksBlockId>,
    block: &StacksBlockId,
    key: u16,
) -> Option<(MARFValue, Vec<u8>)> {
    match marf.get_with_proof_from_hash(block, &diff_path(key)) {
        Ok(found) => found.map(|(value, proof)| (value, proof.serialize_to_vec())),
        Err(crate::chainstate::stacks::index::Error::NotFoundError) => None,
        Err(e) => panic!("proof of key {key} at {block} failed: {e:?}"),
    }
}

fn value_of(byte: u8) -> MARFValue {
    MARFValue([byte; 40])
}

/// Run `steps` against a MARF with external blobs and one with SQLite blobs, and check that
/// every value, root hash and proof agrees across the two and with a model.
fn check_blob_reads_match_sqlite_blobs(
    steps: &[MarfStep],
    compress: bool,
) -> Result<(), TestCaseError> {
    let dir = tempfile::tempdir().unwrap();
    let mut sides = [
        DiffSide::new(dir.path(), true, compress),
        DiffSide::new(dir.path(), false, compress),
    ];
    let mut tip = StacksBlockId::sentinel();
    let mut blocks: Vec<(StacksBlockId, BTreeMap<u16, u8>)> = vec![];
    let mut model: BTreeMap<u16, u8> = BTreeMap::new();

    for (step_num, step) in steps.iter().enumerate() {
        match step {
            MarfStep::Block(writes) => {
                let next = StacksBlockId([step_num as u8 + 1; 32]);
                let mut roots = vec![];
                for side in sides.iter_mut() {
                    side.marf.begin(&tip, &next).unwrap();
                    for (key, val) in writes {
                        side.marf
                            .insert_raw(diff_path(*key), TrieLeaf::new(&[], &[*val; 40]))
                            .unwrap();
                    }
                    side.marf.commit().unwrap();
                    roots.push(side.marf.get_root_hash_at(&next).unwrap());
                    if side.ro.is_none() {
                        side.ro = Some(side.marf.reopen_readonly().unwrap());
                    }
                }
                prop_assert_eq!(roots[0], roots[1]);
                model.extend(writes.iter().copied());
                blocks.push((next.clone(), model.clone()));
                tip = next;

                let absent = (0..DIFF_KEYS).filter(|k| !model.contains_key(k)).take(2);
                let checked: Vec<u16> = writes
                    .iter()
                    .map(|(k, _)| *k)
                    .chain(model.keys().copied().take(16))
                    .chain(absent)
                    .collect();
                for key in checked {
                    let expected = model.get(&key).copied().map(value_of);
                    let mut proofs = vec![];
                    for side in sides.iter_mut() {
                        prop_assert_eq!(read_leaf(&mut side.marf, &tip, key), expected.clone());
                        let ro = side.ro.as_mut().unwrap();
                        prop_assert_eq!(read_leaf(ro, &tip, key), expected.clone());
                        let proof = read_with_proof(&mut side.marf, &tip, key);
                        prop_assert_eq!(proof.as_ref().map(|(v, _)| v.clone()), expected.clone());
                        proofs.push(proof.map(|(_, p)| p));
                    }
                    prop_assert_eq!(&proofs[0], &proofs[1]);
                }
            }
            MarfStep::Unconfirmed(writes) => {
                if blocks.is_empty() {
                    continue;
                }
                let mut expected_model = model.clone();
                expected_model.extend(writes.iter().copied());
                let mut values = vec![];
                for side in sides.iter_mut() {
                    let storage =
                        TrieFileStorage::open_unconfirmed(&side.path, side.opts.clone()).unwrap();
                    let mut unconfirmed = MARF::from_storage(storage);
                    let unconfirmed_tip = unconfirmed.begin_unconfirmed(&tip).unwrap();
                    for (key, val) in writes {
                        unconfirmed
                            .insert_raw(diff_path(*key), TrieLeaf::new(&[], &[*val; 40]))
                            .unwrap();
                    }
                    unconfirmed.commit().unwrap();
                    let side_values: Vec<_> = expected_model
                        .keys()
                        .map(|key| read_leaf(&mut unconfirmed, &unconfirmed_tip, *key))
                        .collect();
                    unconfirmed.begin_unconfirmed(&tip).unwrap();
                    unconfirmed.drop_unconfirmed();
                    values.push(side_values);
                }
                let expected: Vec<_> = expected_model
                    .values()
                    .map(|val| Some(value_of(*val)))
                    .collect();
                prop_assert_eq!(&values[0], &expected);
                prop_assert_eq!(&values[1], &expected);
            }
        }
    }

    for side in sides.iter_mut() {
        let mut fresh = side.marf.reopen_readonly().unwrap();
        for (block, snapshot) in &blocks {
            for key in model.keys() {
                let expected = snapshot.get(key).copied().map(value_of);
                prop_assert_eq!(read_leaf(&mut fresh, block, *key), expected.clone());
                let ro = side.ro.as_mut().unwrap();
                prop_assert_eq!(read_leaf(ro, block, *key), expected);
            }
        }
    }
    Ok(())
}

proptest! {
    #![proptest_config(ProptestConfig::with_cases(32))]

    /// External-blob reads return the same values, root hashes and proofs as SQLite-blob reads,
    /// including through a read-only handle opened before later blocks were appended and after
    /// unconfirmed tries are committed and dropped.
    #[tag(t_prop)]
    #[test]
    fn blob_reads_match_sqlite_blobs(
        steps in prop::collection::vec(marf_step(), 1..8),
        compress in any::<bool>(),
    ) {
        check_blob_reads_match_sqlite_blobs(&steps, compress)?;
    }
}

proptest! {
    /// `WindowReader` reads and seeks like the file it wraps, for any window size, and never
    /// moves the file's cursor.
    #[tag(t_prop)]
    #[test]
    fn window_reader_matches_file(
        contents in prop::collection::vec(any::<u8>(), 0..300),
        window in 1..64usize,
        ops in prop::collection::vec(reader_op(), 1..40),
    ) {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("window.bin");
        fs::write(&path, &contents).unwrap();
        let mut plain = fs::File::open(&path).unwrap();
        let windowed = fs::File::open(&path).unwrap();
        let mut buf = vec![];
        let mut reader = WindowReader::new(&windowed, &mut buf, window, 0);
        for op in &ops {
            prop_assert_eq!(apply_reader_op(&mut plain, op), apply_reader_op(&mut reader, op), "op {:?}", op);
        }
        prop_assert_eq!((&windowed).stream_position().unwrap(), 0);
    }
}
