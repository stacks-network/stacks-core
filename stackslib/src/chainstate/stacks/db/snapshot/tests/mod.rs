// Copyright (C) 2026 Stacks Open Internet Foundation
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

use std::collections::HashSet;

use rstest::rstest;
use rusqlite::{params, Connection};
use stacks_common::types::chainstate::StacksBlockId;
use tempfile::tempdir;

use crate::chainstate::stacks::db::StacksChainState;
use crate::chainstate::stacks::index::marf::{MARFOpenOpts, MARF};
use crate::chainstate::stacks::index::{ClarityMarfTrieId, Error, MARFValue};

mod index;

/// Create a source `index.sqlite`
fn create_source_db(path: &std::path::Path) -> Connection {
    let _ = StacksChainState::instantiate_db(false, 1, path.to_str().unwrap(), true, None)
        .expect("chainstate DB init failed");
    Connection::open(path).unwrap()
}

/// A deterministic 32-byte [`StacksBlockId`] for a short test label: the
/// label's UTF-8 bytes, zero-padded. Tests use labels like `"ibh1"` for
/// readability; the canonical-set fixtures store these ids as BLOBs (as
/// the squash engine does) and the chainstate fixtures store [`hex_id`]
/// TEXT, so the two sides join.
fn label_block_id(label: &str) -> StacksBlockId {
    let mut bytes = [0u8; 32];
    let len = label.len().min(32);
    bytes[..len].copy_from_slice(&label.as_bytes()[..len]);
    StacksBlockId(bytes)
}

/// The lowercase-hex form of [`label_block_id`], for the chainstate
/// `index_block_hash` TEXT columns.
fn hex_id(label: &str) -> String {
    label_block_id(label).to_hex()
}

/// The single leaf value committed into every fixture MARF (see
/// [`create_dest_db_with_canonical_blocks`]): a src `__fork_storage` row
/// keyed by its hex is canonical and gets copied.
const FIXTURE_LEAF: MARFValue = MARFValue([0xff; 40]);

/// Create a destination DB that simulates a squashed MARF: a real (tiny)
/// MARF with one confirmed block and one [`FIXTURE_LEAF`] leaf, plus the
/// `marf_squashed_blocks` table holding the given canonical block labels
/// (stored as [`label_block_id`] BLOBs). Returns the connection for
/// [`append_canonical_block`].
fn create_dest_db_with_canonical_blocks(path: &std::path::Path, canonical: &[&str]) -> Connection {
    let mut marf =
        MARF::<StacksBlockId>::from_path(path.to_str().unwrap(), MARFOpenOpts::default())
            .expect("MARF init failed");
    marf.begin(&StacksBlockId::sentinel(), &label_block_id("marf_tip"))
        .unwrap();
    marf.insert("test::leaf", FIXTURE_LEAF).unwrap();
    marf.commit().unwrap();
    drop(marf);

    let conn = Connection::open(path).unwrap();
    conn.execute_batch(
        "CREATE TABLE IF NOT EXISTS marf_squashed_blocks (
            height INTEGER PRIMARY KEY,
            block_hash BLOB NOT NULL UNIQUE,
            marf_root_hash BLOB NOT NULL
        )",
    )
    .unwrap();
    for (h, bh) in canonical.iter().enumerate() {
        let id = label_block_id(bh);
        conn.execute(
            "INSERT INTO marf_squashed_blocks (height, block_hash, marf_root_hash) \
             VALUES (?1, ?2, ?3)",
            params![h as i64, id.0.as_slice(), [0u8; 32].as_slice()],
        )
        .unwrap();
    }
    conn
}

/// Append a canonical block above the existing ones. `block_hash` is the
/// raw BLOB content: a test label or a computed [`StacksBlockId`].
fn append_canonical_block(conn: &Connection, block_hash: &[u8]) {
    conn.execute(
        "INSERT INTO marf_squashed_blocks (height, block_hash, marf_root_hash) \
         VALUES ((SELECT COALESCE(MAX(height) + 1, 0) FROM marf_squashed_blocks), ?1, ?2)",
        params![block_hash, [0u8; 32].as_slice()],
    )
    .unwrap();
}

/// Insert an epoch-2 `block_headers` row at the given height.
fn insert_epoch2_block_header(conn: &Connection, height: u32, suffix: &str) {
    conn.execute(
            "INSERT INTO block_headers (version, total_burn, total_work, proof, parent_block, \
             parent_microblock, parent_microblock_sequence, tx_merkle_root, state_index_root, \
             microblock_pubkey_hash, block_hash, index_block_hash, block_height, index_root, \
             consensus_hash, burn_header_hash, burn_header_height, burn_header_timestamp, \
             parent_block_id, cost, block_size) \
             VALUES (1,'0','0','p','par','mb',0,'mr','sr','mph',?1,?2,?3,'ir',?4,'bhh',?3,0,'pid','0','0')",
            params![
                format!("bh{suffix}"),
                hex_id(&format!("ibh{suffix}")),
                height,
                format!("ch{suffix}"),
            ],
        )
        .unwrap();
}

/// Insert a payment row at the given height.
fn insert_payment(conn: &Connection, height: u32, suffix: &str) {
    conn.execute(
        "INSERT INTO payments (address, block_hash, consensus_hash, parent_block_hash, \
             parent_consensus_hash, coinbase, tx_fees_anchored, tx_fees_streamed, stx_burns, \
             burnchain_commit_burn, burnchain_sortition_burn, miner, stacks_block_height, \
             index_block_hash, vtxindex, recipient, schedule_type) \
             VALUES ('addr',?1,?2,'pbh','pch','100','0','0','0',0,0,1,?3,?4,0,NULL,'Epoch2')",
        params![
            format!("bh{suffix}"),
            format!("ch{suffix}"),
            height,
            hex_id(&format!("ibh{suffix}")),
        ],
    )
    .unwrap();
}

/// Insert a transaction row for the given index_block_hash label.
///
/// Callers pass a short label (e.g. `"ibh1"`); we store it as
/// [`hex_id`] so it joins against the squash side-table.
fn insert_transaction(conn: &Connection, id: i64, ibh_label: &str) {
    conn.execute(
        "INSERT INTO transactions (id, txid, index_block_hash, tx_hex, result) \
             VALUES (?1, ?2, ?3, '0x00', 'ok')",
        params![id, format!("tx{id}"), hex_id(ibh_label)],
    )
    .unwrap();
}
/// Assert `err` is a [`Error::CorruptionError`] whose message contains
/// `needle`, pinning which corruption guard fired.
fn assert_corruption_containing(err: Error, needle: &str) {
    match err {
        Error::CorruptionError(msg) => {
            assert!(msg.contains(needle), "wrong corruption message: {msg}")
        }
        other => panic!("expected CorruptionError, got {other:?}"),
    }
}

/// The `__fork_storage` copy keeps only rows whose `value_hash` is
/// referenced by a canonical MARF leaf and drops fork-only entries.
#[test]
fn test_copy_canonical_fork_storage_filters_by_leaf_hash() {
    let dir = tempdir().unwrap();
    let src_path = dir.path().join("src.sqlite");
    let dst_path = dir.path().join("dst.sqlite");

    // src.__fork_storage: two canonical entries (aa, cc) and one
    // non-canonical fork entry (bb) that must be excluded.
    let aa = MARFValue([0xaa; 40]);
    let bb = MARFValue([0xbb; 40]);
    let cc = MARFValue([0xcc; 40]);
    let src = Connection::open(&src_path).unwrap();
    src.execute_batch(
        "CREATE TABLE __fork_storage (\
             value_hash TEXT NOT NULL PRIMARY KEY, value TEXT NOT NULL);",
    )
    .unwrap();
    for (key, value) in [(&aa, "va"), (&bb, "vb"), (&cc, "vc")] {
        src.execute(
            "INSERT INTO __fork_storage VALUES (?1, ?2)",
            params![key.to_hex(), value],
        )
        .unwrap();
    }
    drop(src);

    // Empty dst with src attached; the copy filters by the canonical leaf set.
    let dst = Connection::open(&dst_path).unwrap();
    dst.execute(
        "ATTACH DATABASE ?1 AS src",
        params![src_path.to_str().unwrap()],
    )
    .unwrap();
    let leaf_hashes: HashSet<MARFValue> = [aa.clone(), cc.clone()].into_iter().collect();

    let copied = super::fork_storage::copy_canonical_fork_storage(&dst, &leaf_hashes).unwrap();
    assert_eq!(copied, 2, "only canonical value_hashes are copied");

    let present: i64 = dst
        .query_row(
            "SELECT COUNT(*) FROM __fork_storage WHERE value_hash IN (?1, ?2)",
            params![aa.to_hex(), cc.to_hex()],
            |row| row.get(0),
        )
        .unwrap();
    assert_eq!(present, 2);
    let forked: i64 = dst
        .query_row(
            "SELECT COUNT(*) FROM __fork_storage WHERE value_hash = ?1",
            params![bb.to_hex()],
            |row| row.get(0),
        )
        .unwrap();
    assert_eq!(forked, 0, "non-canonical fork row excluded");
}

/// Invalid `value_hash` encodings are corruption: `store_indexed` is the
/// only writer and always stores the full hash as lowercase hex, and the
/// runtime reads it back the same way (so a copied row with any other
/// encoding would be unreachable in dst).
#[rstest]
#[case::not_a_marf_value("aa".into(), "is not a hex MARFValue")]
#[case::uppercase(
    MARFValue([0xaa; 40]).to_hex().to_uppercase(),
    "is not canonical lowercase hex"
)]
fn test_fork_storage_invalid_value_hash_is_corruption(
    #[case] value_hash: String,
    #[case] needle: &str,
) {
    let dir = tempdir().unwrap();
    let src_path = dir.path().join("src.sqlite");
    let dst_path = dir.path().join("dst.sqlite");

    let src = Connection::open(&src_path).unwrap();
    src.execute_batch(
        "CREATE TABLE __fork_storage (\
             value_hash TEXT NOT NULL PRIMARY KEY, value TEXT NOT NULL);",
    )
    .unwrap();
    src.execute(
        "INSERT INTO __fork_storage VALUES (?1, 'va')",
        params![value_hash],
    )
    .unwrap();
    drop(src);

    let dst = Connection::open(&dst_path).unwrap();
    dst.execute(
        "ATTACH DATABASE ?1 AS src",
        params![src_path.to_str().unwrap()],
    )
    .unwrap();

    let err = super::fork_storage::copy_canonical_fork_storage(&dst, &HashSet::new()).unwrap_err();
    assert_corruption_containing(err, needle);
}
