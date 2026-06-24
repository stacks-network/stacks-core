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

//! Index side-table (`index.sqlite`) copy/validate tests.

use std::collections::HashSet;

use rusqlite::{params, Connection};
use tempfile::tempdir;

use super::super::index::{
    assert_source_tables_classified, copy_index_side_tables, index_copy_specs, COPIED_TABLES,
};
use super::{
    append_canonical_block, assert_corruption_containing, create_dest_db_with_canonical_blocks,
    create_source_db, hex_id, insert_epoch2_block_header, insert_nakamoto_header, label_block_id,
    FIXTURE_LEAF,
};
use crate::chainstate::nakamoto::{NakamotoBlockHeader, NakamotoChainState};
use crate::chainstate::stacks::db::{StacksHeaderInfo, CHAINSTATE_VERSION};
use crate::chainstate::stacks::index::{Error, MARFValue};

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

/// End-to-end copy of the index side-tables: only rows belonging to the
/// canonical set land in dst, and the schema-only tables exist but are empty.
#[test]
fn test_copy_index_side_tables_round_trip() {
    let dir = tempdir().unwrap();
    let src_path = dir.path().join("src_index.sqlite");
    let conn = create_source_db(&src_path);

    // Insert test data at heights 1, 2, 3.
    for (h, s) in [(1, "1"), (2, "2"), (3, "3")] {
        insert_epoch2_block_header(&conn, h, s);
        insert_payment(&conn, h, s);
        insert_transaction(&conn, h as i64, &format!("ibh{s}"));
    }
    // Canonical Nakamoto tip (squashing requires an epoch 3.4+ src).
    let tip_id = insert_nakamoto_header(&conn, "tip", 4);
    conn.execute(
            "INSERT INTO nakamoto_tenure_events (tenure_id_consensus_hash, prev_tenure_id_consensus_hash, \
             burn_view_consensus_hash, cause, block_hash, block_id, coinbase_height, num_blocks_confirmed) \
             VALUES ('ch1','ch0','bv1',0,'bh1',?1,1,0)",
            params![hex_id("ibh1")],
        )
        .unwrap();
    conn.execute(
        "INSERT INTO nakamoto_reward_sets (index_block_hash, reward_set) VALUES (?1,'{}')",
        params![hex_id("ibh1")],
    )
    .unwrap();
    // One canonical __fork_storage row (referenced by the fixture MARF's
    // leaf) and one fork-only row that must be excluded.
    conn.execute(
        "INSERT INTO __fork_storage (value_hash, value) VALUES (?1, 'vleaf'), (?2, 'vfork')",
        params![FIXTURE_LEAF.to_hex(), MARFValue([0xee; 40]).to_hex()],
    )
    .unwrap();
    drop(conn);

    // Destination: canonical blocks are ibh1, ibh2 and the Nakamoto tip -
    // ibh3 is NOT canonical.
    let dst_path = dir.path().join("dst_index.sqlite");
    let dst = create_dest_db_with_canonical_blocks(&dst_path, &["ibh1", "ibh2"]);
    append_canonical_block(&dst, &tip_id);
    drop(dst);

    // Copy: only canonical blocks ibh1 and ibh2 should be included.
    let stats =
        copy_index_side_tables(src_path.to_str().unwrap(), dst_path.to_str().unwrap(), 0, 1)
            .unwrap();

    assert_eq!(stats.block_headers_rows, 2, "2 canonical block_headers");
    assert_eq!(stats.nakamoto_block_headers_rows, 1, "the Nakamoto tip");
    assert_eq!(stats.payments_rows, 2, "2 canonical payments");
    assert_eq!(stats.transactions_rows, 2, "2 canonical transactions");
    assert_eq!(
        stats.fork_storage_rows, 1,
        "only the leaf-referenced __fork_storage row"
    );
    assert_eq!(
        stats.nakamoto_tenure_events_rows, 1,
        "1 tenure event for ibh1"
    );
    assert_eq!(stats.nakamoto_reward_sets_rows, 1);

    // Confirm the canonical rows actually landed in the destination DB
    // (querying dst directly rather than trusting the returned stats).
    let dst = Connection::open(&dst_path).unwrap();
    let count = |sql: &str| -> i64 { dst.query_row(sql, [], |r| r.get(0)).unwrap() };
    assert_eq!(count("SELECT COUNT(*) FROM block_headers"), 2);
    assert_eq!(count("SELECT COUNT(*) FROM payments"), 2);
    assert_eq!(count("SELECT COUNT(*) FROM transactions"), 2);
    assert_eq!(count("SELECT COUNT(*) FROM nakamoto_tenure_events"), 1);
    // The leaf-referenced __fork_storage row landed; the fork-only one didn't.
    let fork_storage_keys: i64 = dst
        .query_row(
            "SELECT COUNT(*) FROM __fork_storage WHERE value_hash = ?1",
            params![FIXTURE_LEAF.to_hex()],
            |r| r.get(0),
        )
        .unwrap();
    assert_eq!(fork_storage_keys, 1);
    assert_eq!(count("SELECT COUNT(*) FROM __fork_storage"), 1);
    // Schema-only compatibility table is present but empty.
    assert_eq!(
        count("SELECT COUNT(*) FROM invalidated_microblocks_data"),
        0
    );
    // db_config is copied verbatim (values set by `create_source_db`).
    let (version, mainnet, chain_id): (String, i64, i64) = dst
        .query_row(
            "SELECT version, mainnet, chain_id FROM db_config",
            [],
            |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?)),
        )
        .unwrap();
    assert_eq!(
        (version.as_str(), mainnet, chain_id),
        (CHAINSTATE_VERSION, 0, 1)
    );
}

/// Two blocks at the same height - one canonical, one fork: only the
/// canonical block's rows are copied.
#[test]
fn test_copy_excludes_fork_rows() {
    let dir = tempdir().unwrap();
    let src_path = dir.path().join("src_index.sqlite");
    let conn = create_source_db(&src_path);

    // Insert canonical block at height 1.
    insert_epoch2_block_header(&conn, 1, "1_canonical");
    insert_transaction(&conn, 1, "ibh1_canonical");
    // Insert fork block at same height 1 (different consensus hash).
    insert_epoch2_block_header(&conn, 1, "1_fork");
    insert_transaction(&conn, 2, "ibh1_fork");
    // Canonical Nakamoto tip (squashing requires an epoch 3.4+ src).
    let tip_id = insert_nakamoto_header(&conn, "tip", 2);
    drop(conn);

    // Only ibh1_canonical (and the tip) is in the canonical set.
    let dst_path = dir.path().join("dst_index.sqlite");
    let dst = create_dest_db_with_canonical_blocks(&dst_path, &["ibh1_canonical"]);
    append_canonical_block(&dst, &tip_id);
    drop(dst);

    let stats =
        copy_index_side_tables(src_path.to_str().unwrap(), dst_path.to_str().unwrap(), 0, 1)
            .unwrap();

    // Only canonical block should be copied, not the fork.
    assert_eq!(stats.block_headers_rows, 1, "only canonical block_headers");
    assert_eq!(stats.transactions_rows, 1, "only canonical transactions");

    // Confirm only the canonical row is present in the destination DB.
    let dst = Connection::open(&dst_path).unwrap();
    let bh: i64 = dst
        .query_row("SELECT COUNT(*) FROM block_headers", [], |r| r.get(0))
        .unwrap();
    let tx: i64 = dst
        .query_row("SELECT COUNT(*) FROM transactions", [], |r| r.get(0))
        .unwrap();
    assert_eq!(bh, 1, "only the canonical block_header is copied");
    assert_eq!(tx, 1, "only the canonical transaction is copied");
}

/// Insert an epoch-2 `staging_blocks` row with the given
/// `processed`/`orphaned` flags.
fn insert_epoch2_staging_block(
    conn: &Connection,
    suffix: &str,
    height: u32,
    processed: i64,
    orphaned: i64,
) {
    conn.execute(
        "INSERT INTO staging_blocks (\
                anchored_block_hash, parent_anchored_block_hash, \
                consensus_hash, parent_consensus_hash, \
                parent_microblock_hash, parent_microblock_seq, \
                microblock_pubkey_hash, height, attachable, orphaned, processed, \
                commit_burn, sortition_burn, index_block_hash, \
                download_time, arrival_time, processed_time) \
             VALUES (?1, ?2, ?3, ?4, ?5, 0, 'mph', ?6, 1, ?7, ?8, 0, 0, ?9, 100, 200, 300)",
        params![
            format!("bh{suffix}"),
            format!("parent_bh{suffix}"),
            format!("ch{suffix}"),
            format!("parent_ch{suffix}"),
            "0000000000000000000000000000000000000000000000000000000000000000",
            height,
            orphaned,
            processed,
            hex_id(&format!("ibh{suffix}")),
        ],
    )
    .unwrap();
}

/// The staging_blocks copy keeps canonical processed blocks with all
/// columns preserved, and drops non-canonical, unprocessed, and
/// orphaned ones.
#[test]
fn test_staging_blocks_populated_for_canonical() {
    let dir = tempdir().unwrap();
    let src_path = dir.path().join("src.sqlite");
    let conn = create_source_db(&src_path);

    // Insert block headers and staging blocks at heights 1, 2, 3.
    for (h, s) in [(1, "1"), (2, "2"), (3, "3")] {
        insert_epoch2_block_header(&conn, h, s);
        insert_epoch2_staging_block(&conn, s, h, 1, 0);
    }
    // Canonical blocks excluded by the semantic predicate:
    // ibh4 is unprocessed, ibh5 is orphaned.
    insert_epoch2_block_header(&conn, 4, "4");
    insert_epoch2_staging_block(&conn, "4", 4, 0, 0);
    insert_epoch2_block_header(&conn, 5, "5");
    insert_epoch2_staging_block(&conn, "5", 5, 1, 1);
    // Canonical Nakamoto tip (squashing requires an epoch 3.4+ src).
    let tip_id = insert_nakamoto_header(&conn, "tip", 6);
    drop(conn);

    // Canonical set includes ibh1, ibh2, ibh4, ibh5, but NOT ibh3.
    let dst_path = dir.path().join("dst.sqlite");
    let dst = create_dest_db_with_canonical_blocks(&dst_path, &["ibh1", "ibh2", "ibh4", "ibh5"]);
    append_canonical_block(&dst, &tip_id);
    drop(dst);

    let stats =
        copy_index_side_tables(src_path.to_str().unwrap(), dst_path.to_str().unwrap(), 0, 1)
            .unwrap();

    // Only the 2 canonical processed rows survive.
    assert_eq!(stats.staging_blocks_rows, 2);

    // Verify all columns preserved verbatim.
    let dst_conn = Connection::open(&dst_path).unwrap();
    let (download_time, arrival_time, processed_time): (i64, i64, i64) = dst_conn
        .query_row(
            "SELECT download_time, arrival_time, processed_time \
                 FROM staging_blocks WHERE index_block_hash = ?1",
            params![hex_id("ibh1")],
            |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)),
        )
        .unwrap();
    assert_eq!(download_time, 100);
    assert_eq!(arrival_time, 200);
    assert_eq!(processed_time, 300);

    // Non-canonical (ibh3), unprocessed (ibh4), and orphaned (ibh5)
    // rows are all excluded.
    for label in ["ibh3", "ibh4", "ibh5"] {
        let count: i64 = dst_conn
            .query_row(
                "SELECT COUNT(*) FROM staging_blocks WHERE index_block_hash = ?1",
                params![hex_id(label)],
                |row| row.get(0),
            )
            .unwrap();
        assert_eq!(count, 0, "{label} must not be copied");
    }
}

/// `signer_stats` is copied through the reward cycle of the canonical
/// Nakamoto tip and later cycles are excluded.
#[test]
fn test_signer_stats_copied_through_tip_reward_cycle() {
    let dir = tempdir().unwrap();
    let src_path = dir.path().join("src.sqlite");
    let conn = create_source_db(&src_path);

    // Canonical chain: epoch2 block ibh1, Nakamoto tip at burn height 10.
    insert_epoch2_block_header(&conn, 1, "1");
    let tip_id = insert_nakamoto_header(&conn, "tip", 10);
    conn.execute(
        "INSERT INTO signer_stats (public_key, reward_cycle, blocks_signed) \
         VALUES ('pk1', 1, 5), ('pk2', 2, 3), ('pk3', 3, 7)",
        [],
    )
    .unwrap();
    drop(conn);

    let dst_path = dir.path().join("dst.sqlite");
    let dst = create_dest_db_with_canonical_blocks(&dst_path, &["ibh1"]);
    append_canonical_block(&dst, &tip_id);
    drop(dst);

    // first_burn_height=0, reward_cycle_len=5 → tip cycle = 10 / 5 = 2.
    let stats =
        copy_index_side_tables(src_path.to_str().unwrap(), dst_path.to_str().unwrap(), 0, 5)
            .unwrap();

    assert_eq!(stats.nakamoto_block_headers_rows, 1);
    assert_eq!(
        stats.signer_stats_rows, 2,
        "cycles 1 and 2 copied, cycle 3 excluded"
    );
    let dst = Connection::open(&dst_path).unwrap();
    let max_cycle: i64 = dst
        .query_row("SELECT MAX(reward_cycle) FROM signer_stats", [], |r| {
            r.get(0)
        })
        .unwrap();
    assert_eq!(max_cycle, 2);
}

/// A source with no Nakamoto blocks at all violates the epoch 3.4+
/// squash precondition and is rejected.
#[test]
fn test_src_without_nakamoto_blocks_is_corruption() {
    let dir = tempdir().unwrap();
    let src_path = dir.path().join("src.sqlite");
    let conn = create_source_db(&src_path);

    insert_epoch2_block_header(&conn, 1, "1");
    drop(conn);

    let dst_path = dir.path().join("dst.sqlite");
    create_dest_db_with_canonical_blocks(&dst_path, &["ibh1"]);

    let err = copy_index_side_tables(src_path.to_str().unwrap(), dst_path.to_str().unwrap(), 0, 5)
        .unwrap_err();
    assert_corruption_containing(err, "canonical tip is not a Nakamoto block");
}

/// A canonical set whose tip is an epoch-2 block sitting above a Nakamoto
/// block is corrupt: epochs are monotonic, so the canonical tip itself
/// must be Nakamoto - a lower Nakamoto block must not satisfy the check.
#[test]
fn test_epoch2_tip_above_nakamoto_block_is_corruption() {
    let dir = tempdir().unwrap();
    let src_path = dir.path().join("src.sqlite");
    let conn = create_source_db(&src_path);

    let nak_id = insert_nakamoto_header(&conn, "nak", 10);
    insert_epoch2_block_header(&conn, 2, "2");
    drop(conn);

    // ibh2 (epoch-2) sits above the Nakamoto block in the canonical set.
    let dst_path = dir.path().join("dst.sqlite");
    let dst = create_dest_db_with_canonical_blocks(&dst_path, &[]);
    append_canonical_block(&dst, &nak_id);
    append_canonical_block(&dst, &label_block_id("ibh2"));
    drop(dst);

    let err = copy_index_side_tables(src_path.to_str().unwrap(), dst_path.to_str().unwrap(), 0, 5)
        .unwrap_err();
    assert_corruption_containing(err, "canonical tip is not a Nakamoto block");
}

/// An empty `marf_squashed_blocks` (the squash recorded no canonical
/// blocks) must fail loudly instead of producing an empty copy.
#[test]
fn test_empty_canonical_set_is_corruption() {
    let dir = tempdir().unwrap();
    let src_path = dir.path().join("src.sqlite");
    let conn = create_source_db(&src_path);
    insert_epoch2_block_header(&conn, 1, "1");
    drop(conn);

    let dst_path = dir.path().join("dst.sqlite");
    create_dest_db_with_canonical_blocks(&dst_path, &[]);

    let err = copy_index_side_tables(src_path.to_str().unwrap(), dst_path.to_str().unwrap(), 0, 1)
        .unwrap_err();
    assert_corruption_containing(err, "marf_squashed_blocks is empty");
}

/// A canonical block recorded by the squash but absent from the source
/// headers (epoch2 and Nakamoto) is corruption: src is incomplete.
#[test]
fn test_canonical_block_missing_from_src_is_corruption() {
    let dir = tempdir().unwrap();
    let src_path = dir.path().join("src.sqlite");
    let conn = create_source_db(&src_path);
    insert_epoch2_block_header(&conn, 1, "1");
    drop(conn);

    let dst_path = dir.path().join("dst.sqlite");
    create_dest_db_with_canonical_blocks(&dst_path, &["ibh1", "ibh_missing"]);

    let err = copy_index_side_tables(src_path.to_str().unwrap(), dst_path.to_str().unwrap(), 0, 1)
        .unwrap_err();
    assert_corruption_containing(
        err,
        "absent from src.block_headers and src.nakamoto_block_headers",
    );
}

/// Copy-spec coverage guard: every table in [`COPIED_TABLES`] has exactly
/// one copy spec, so a table can't be classified as copied yet receive no
/// rows - or two specs' worth of duplicates.
#[test]
fn test_copy_specs_match_copied_tables() {
    let copied: HashSet<&str> = COPIED_TABLES.iter().copied().collect();

    let specs: Vec<&str> = index_copy_specs(0).iter().map(|s| s.table).collect();
    let spec_set: HashSet<&str> = specs.iter().copied().collect();
    assert_eq!(specs.len(), spec_set.len(), "duplicate spec tables");
    assert_eq!(spec_set, copied);
}

/// Drift guard: every table the chainstate migrations create must be
/// classified, so a future migration can't silently drop one from the copy.
/// Runs the exact production guard against a freshly-migrated schema, so the
/// test and the runtime check cannot drift apart.
#[test]
fn test_no_unclassified_source_tables() {
    let dir = tempdir().unwrap();
    let conn = create_source_db(&dir.path().join("src.sqlite"));
    assert_source_tables_classified(&conn)
        .expect("fresh production index schema must be fully classified");
}

/// A source table the copy lists don't classify is rejected before any
/// destination is produced — the runtime complement to the drift test.
#[test]
fn test_unclassified_source_table_is_rejected() {
    let dir = tempdir().unwrap();
    let src_path = dir.path().join("src.sqlite");
    let conn = create_source_db(&src_path);
    conn.execute_batch("CREATE TABLE surprise_table (x INTEGER)")
        .unwrap();
    drop(conn);

    let dst_path = dir.path().join("dst_index.sqlite");
    let err = copy_index_side_tables(src_path.to_str().unwrap(), dst_path.to_str().unwrap(), 0, 1)
        .expect_err("unclassified source table must be rejected");
    match err {
        Error::CorruptionError(msg) => assert!(
            msg.contains("surprise_table"),
            "error should name the offending table, got: {msg}"
        ),
        other => panic!("expected CorruptionError, got {other:?}"),
    }
    assert!(
        !dst_path.exists(),
        "no destination should be produced when the source is rejected"
    );
}
