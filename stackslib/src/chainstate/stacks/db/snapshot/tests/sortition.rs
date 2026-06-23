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

//! Sortition side-table copy tests.

use std::collections::HashSet;
use std::path::{Path, PathBuf};

use rstest::rstest;
use rusqlite::{params, Connection, OptionalExtension};
use stacks_common::types::chainstate::{
    BlockHeaderHash, BurnchainHeaderHash, ConsensusHash, SortitionId, TrieHash,
};
use tempfile::tempdir;

use super::super::sortition::{
    assert_source_tables_classified, copy_sortition_side_tables,
    copy_sortition_side_tables_with_boundary, sortition_copy_specs, SortitionTipCopyBoundary,
    REQUIRED_TABLES,
};
use super::{hex_id, label_block_id};
use crate::burnchains::PoxConstants;
use crate::chainstate::burn::db::sortdb::tests::{
    make_fork_run, test_append_snapshot, test_insert_block_commit_parent_row,
    test_insert_block_commit_row, test_insert_delegate_stx_row, test_insert_leader_key_row,
    test_insert_missed_commit_row, test_insert_preprocessed_reward_set_row,
    test_insert_snapshot_row, test_insert_snapshot_transition_ops_row, test_insert_stack_stx_row,
    test_insert_stacks_chain_tip_by_burn_view_row, test_insert_stacks_chain_tip_row,
    test_insert_transfer_stx_row, test_insert_vote_for_aggregate_key_row,
    test_set_snapshot_consensus_hash,
};
use crate::chainstate::burn::db::sortdb::SortitionDB;
use crate::chainstate::stacks::index::marf::{MARFOpenOpts, MARF};
use crate::chainstate::stacks::index::{trie_sql, ClarityMarfTrieId, Error, MARFValue};
use crate::core::{StacksEpoch, StacksEpochExtension};

/// Create a sortition source DB. `connect` also seeds the genesis
/// snapshot and the epoch rows. Returns a connection to the sqlite
/// file along with its path.
fn create_sortition_source_db(dir: &Path) -> (Connection, PathBuf) {
    let db_dir = dir.join("src_sort");
    let _db = SortitionDB::connect(
        db_dir.to_str().unwrap(),
        0,
        &BurnchainHeaderHash([0u8; 32]),
        0,
        &StacksEpoch::unit_test_3_4(0),
        PoxConstants::test_default(),
        None,
        true,
        None,
    )
    .expect("sortition DB init failed");
    let db_path = db_dir.join("marf.sqlite");
    let conn = Connection::open(&db_path).unwrap();
    (conn, db_path)
}

/// Insert a snapshot row for the given sortition_id and burn_header_hash labels.
///
/// `sortition_id` is stored as its [`hex_id`] form so it joins against the
/// canonical-sortitions temp table, which `populate_canonical_sortitions`
/// fills with the lowercase-hex ids read via `trie_sql::bulk_read_squashed_blocks`.
fn insert_snapshot(
    conn: &Connection,
    sortition_id_label: &str,
    burn_header_hash: &str,
    block_height: u32,
) {
    test_insert_snapshot_row(
        conn,
        block_height,
        burn_header_hash,
        &hex_id(sortition_id_label),
        &format!("ch_{sortition_id_label}"),
        &format!("ir_{sortition_id_label}"),
    )
    .unwrap();
}

/// Insert a leader_keys row for the given sortition_id label.
fn insert_leader_key(conn: &Connection, sortition_id_label: &str) {
    test_insert_leader_key_row(
        conn,
        &format!("lk_tx_{sortition_id_label}"),
        &hex_id(sortition_id_label),
    )
    .unwrap();
}

/// Insert a block_commits row for the given sortition_id label.
fn insert_block_commit(conn: &Connection, sortition_id_label: &str) {
    test_insert_block_commit_row(
        conn,
        &format!("bc_tx_{sortition_id_label}"),
        &hex_id(sortition_id_label),
    )
    .unwrap();
}

/// Insert a block_commit_parents row.
fn insert_block_commit_parent(conn: &Connection, sortition_id_label: &str) {
    test_insert_block_commit_parent_row(
        conn,
        &format!("bc_tx_{sortition_id_label}"),
        &hex_id(sortition_id_label),
    )
    .unwrap();
}

/// Insert a stack_stx row for the given burn_header_hash.
fn insert_stack_stx(conn: &Connection, burn_header_hash: &str, txid: &str) {
    test_insert_stack_stx_row(conn, txid, burn_header_hash).unwrap();
}

/// Create a sortition dest DB simulating a squashed MARF with the given
/// canonical sortition IDs.
fn create_sortition_dest_db_with_ids(path: &Path, canonical_ids: &[SortitionId]) {
    // A real (tiny) MARF so the leaf walk in `collect_canonical_leaf_hashes`
    // succeeds; its single leaf is irrelevant to the sortition assertions
    // (src `__fork_storage` holds no matching value hash, so nothing is
    // copied from it).
    let mut marf = MARF::<SortitionId>::from_path(path.to_str().unwrap(), MARFOpenOpts::default())
        .expect("MARF init failed");
    marf.begin(&SortitionId::sentinel(), &SortitionId([0x99; 32]))
        .unwrap();
    marf.insert("test::leaf", MARFValue([0xff; 40])).unwrap();
    marf.commit().unwrap();
    drop(marf);

    let conn = Connection::open(path).unwrap();
    for (h, sid) in canonical_ids.iter().enumerate() {
        trie_sql::test_insert_squashed_block(&conn, h as u32, sid, &TrieHash([0u8; 32])).unwrap();
    }
}

/// [`create_sortition_dest_db_with_ids`] for canonical sortition-ID labels.
///
/// Each label is stored as a 32-byte zero-padded id so its hex form matches
/// the `hex_id`-encoded sortition_id that test chainstate inserts use
/// (sortition IDs in `snapshots` are TEXT).
fn create_sortition_dest_db(path: &Path, canonical_sortition_ids: &[&str]) {
    let ids: Vec<SortitionId> = canonical_sortition_ids
        .iter()
        .map(|sid| SortitionId(label_block_id(sid).0))
        .collect();
    create_sortition_dest_db_with_ids(path, &ids);
}

fn sortition_test_tip_boundary(max_stacks_height: u64) -> SortitionTipCopyBoundary {
    SortitionTipCopyBoundary {
        max_stacks_height,
        anchor_consensus_hash: ConsensusHash([0x11; 20]),
        anchor_burn_view_consensus_hash: ConsensusHash([0x11; 20]),
        anchor_block_hash: BlockHeaderHash([0x22; 32]),
        anchor_block_height: max_stacks_height,
    }
}

/// Canonical and fork rows across every sortition_id-filtered table:
/// only the canonical sortitions' rows are copied.
#[test]
fn test_sortition_copy_excludes_fork_data() {
    let dir = tempdir().unwrap();
    let (conn, src_path) = create_sortition_source_db(dir.path());

    // Canonical chain: sort_0 at height 0, sort_1 at height 1.
    insert_snapshot(&conn, "sort_0", "bhh_0", 0);
    insert_snapshot(&conn, "sort_1", "bhh_1", 1);
    // Fork at height 1: sort_1_fork with different burn hash.
    insert_snapshot(&conn, "sort_1_fork", "bhh_1_fork", 1);

    // Insert related data for canonical and fork.
    insert_leader_key(&conn, "sort_1");
    insert_leader_key(&conn, "sort_1_fork");
    insert_block_commit(&conn, "sort_1");
    insert_block_commit(&conn, "sort_1_fork");
    insert_block_commit_parent(&conn, "sort_1");
    insert_block_commit_parent(&conn, "sort_1_fork");
    insert_stack_stx(&conn, "bhh_1", "stx_tx_canon");
    insert_stack_stx(&conn, "bhh_1_fork", "stx_tx_fork");

    // Transition ops.
    test_insert_snapshot_transition_ops_row(&conn, &hex_id("sort_1")).unwrap();
    test_insert_snapshot_transition_ops_row(&conn, &hex_id("sort_1_fork")).unwrap();

    // Stacks chain tips.
    test_insert_stacks_chain_tip_row(&conn, &hex_id("sort_1"), "ch", "bh", 1).unwrap();
    test_insert_stacks_chain_tip_row(&conn, &hex_id("sort_1_fork"), "ch2", "bh2", 1).unwrap();

    // Missed commits.
    test_insert_missed_commit_row(&conn, "mc_tx", &hex_id("sort_1")).unwrap();
    test_insert_missed_commit_row(&conn, "mc_tx_fork", &hex_id("sort_1_fork")).unwrap();

    // Preprocessed reward sets.
    test_insert_preprocessed_reward_set_row(&conn, &hex_id("sort_1")).unwrap();
    test_insert_preprocessed_reward_set_row(&conn, &hex_id("sort_1_fork")).unwrap();

    // src __fork_storage: the dest fixture's single MARF leaf ([0xff; 40])
    // is canonical; an unreferenced entry must be dropped.
    conn.execute(
        "INSERT INTO __fork_storage (value_hash, value) VALUES (?1, 'canon')",
        params![MARFValue([0xff; 40]).to_hex()],
    )
    .unwrap();
    conn.execute(
        "INSERT INTO __fork_storage (value_hash, value) VALUES (?1, 'fork')",
        params![MARFValue([0xee; 40]).to_hex()],
    )
    .unwrap();
    // `connect` seeds the epochs and one db_config row per migration, so
    // the full-copy expectations come from the source itself.
    let (src_epochs, src_db_config): (u64, u64) = conn
        .query_row(
            "SELECT (SELECT COUNT(*) FROM epochs), (SELECT COUNT(*) FROM db_config)",
            [],
            |row| Ok((row.get(0)?, row.get(1)?)),
        )
        .unwrap();
    drop(conn);

    // Only sort_0 and sort_1 are canonical.
    let dst_path = dir.path().join("dst_sort.sqlite");
    create_sortition_dest_db(&dst_path, &["sort_0", "sort_1"]);

    let stats =
        copy_sortition_side_tables(src_path.to_str().unwrap(), dst_path.to_str().unwrap()).unwrap();

    // Only canonical rows should be copied.
    assert_eq!(stats.snapshots_rows, 2, "2 canonical snapshots");
    assert_eq!(stats.leader_keys_rows, 1, "only sort_1 leader key");
    assert_eq!(stats.block_commits_rows, 1, "only sort_1 block commit");
    assert_eq!(
        stats.block_commit_parents_rows, 1,
        "only sort_1 block commit parent"
    );
    assert_eq!(
        stats.snapshot_transition_ops_rows, 1,
        "only sort_1 transition ops"
    );
    assert_eq!(stats.stacks_chain_tips_rows, 1, "only sort_1 chain tip");
    assert_eq!(stats.missed_commits_rows, 1, "only sort_1 missed commit");
    assert_eq!(
        stats.preprocessed_reward_sets_rows, 1,
        "only sort_1 reward set"
    );
    assert_eq!(stats.stack_stx_rows, 1, "only bhh_1 stack_stx");
    assert_eq!(stats.epochs_rows, src_epochs, "epochs full copy");
    assert_eq!(stats.db_config_rows, src_db_config, "db_config full copy");
    assert_eq!(stats.fork_storage_rows, 1, "only the canonical leaf row");

    // Copied rows carry their source content; fork rows are absent by key.
    let dst_conn = Connection::open(&dst_path).unwrap();
    let burn_hash: String = dst_conn
        .query_row(
            "SELECT burn_header_hash FROM snapshots WHERE sortition_id = ?1",
            params![hex_id("sort_1")],
            |row| row.get(0),
        )
        .unwrap();
    assert_eq!(burn_hash, "bhh_1");
    let fork_rows: i64 = dst_conn
        .query_row(
            "SELECT (SELECT COUNT(*) FROM snapshots WHERE sortition_id = ?1) \
             + (SELECT COUNT(*) FROM leader_keys WHERE txid = 'lk_tx_sort_1_fork') \
             + (SELECT COUNT(*) FROM stack_stx WHERE txid = 'stx_tx_fork') \
             + (SELECT COUNT(*) FROM __fork_storage WHERE value_hash = ?2)",
            params![hex_id("sort_1_fork"), MARFValue([0xee; 40]).to_hex()],
            |row| row.get(0),
        )
        .unwrap();
    assert_eq!(fork_rows, 0, "fork rows must be absent by key");
}

/// burn_header_hash-keyed tables (`stack_stx`, `transfer_stx`, ...) must
/// exclude rows associated with non-canonical burn hashes.
#[test]
fn test_sortition_burn_header_hash_filtering() {
    let dir = tempdir().unwrap();
    let (conn, src_path) = create_sortition_source_db(dir.path());

    insert_snapshot(&conn, "sort_0", "bhh_canon", 0);
    insert_snapshot(&conn, "sort_0_fork", "bhh_fork", 0);

    // stack_stx at canonical and fork burn hashes.
    insert_stack_stx(&conn, "bhh_canon", "stx_canon");
    insert_stack_stx(&conn, "bhh_fork", "stx_fork");

    // transfer_stx at canonical and fork.
    test_insert_transfer_stx_row(&conn, "xfer_canon", "bhh_canon").unwrap();
    test_insert_transfer_stx_row(&conn, "xfer_fork", "bhh_fork").unwrap();

    // delegate_stx and vote_for_aggregate_key at canonical and fork.
    for (txid, bhh) in [("del_canon", "bhh_canon"), ("del_fork", "bhh_fork")] {
        test_insert_delegate_stx_row(&conn, txid, bhh).unwrap();
    }
    for (txid, bhh) in [("vote_canon", "bhh_canon"), ("vote_fork", "bhh_fork")] {
        test_insert_vote_for_aggregate_key_row(&conn, txid, bhh).unwrap();
    }

    drop(conn);

    // Only sort_0 is canonical -> bhh_canon is the only canonical burn hash.
    let dst_path = dir.path().join("dst_sort.sqlite");
    create_sortition_dest_db(&dst_path, &["sort_0"]);

    let stats =
        copy_sortition_side_tables(src_path.to_str().unwrap(), dst_path.to_str().unwrap()).unwrap();

    assert_eq!(stats.stack_stx_rows, 1, "only bhh_canon stack_stx");
    assert_eq!(stats.transfer_stx_rows, 1, "only bhh_canon transfer_stx");
    assert_eq!(stats.delegate_stx_rows, 1, "only bhh_canon delegate_stx");
    assert_eq!(
        stats.vote_for_aggregate_key_rows, 1,
        "only bhh_canon vote_for_aggregate_key"
    );

    // The canonical row of each table survives by key; the fork row is absent.
    let dst_conn = Connection::open(&dst_path).unwrap();
    for (table, canon, fork) in [
        ("stack_stx", "stx_canon", "stx_fork"),
        ("transfer_stx", "xfer_canon", "xfer_fork"),
        ("delegate_stx", "del_canon", "del_fork"),
        ("vote_for_aggregate_key", "vote_canon", "vote_fork"),
    ] {
        let (canon_rows, fork_rows): (i64, i64) = dst_conn
            .query_row(
                &format!(
                    "SELECT (SELECT COUNT(*) FROM {table} WHERE txid = ?1), \
                            (SELECT COUNT(*) FROM {table} WHERE txid = ?2)"
                ),
                params![canon, fork],
                |row| Ok((row.get(0)?, row.get(1)?)),
            )
            .unwrap();
        assert_eq!((canon_rows, fork_rows), (1, 0), "{table}");
    }
}

/// A destination claiming a canonical sortition_id absent from
/// `src.snapshots` is corruption: the copy must abort.
#[test]
fn test_sortition_copy_rejects_fabricated_canonical_set() {
    let dir = tempdir().unwrap();
    let (conn, src_path) = create_sortition_source_db(dir.path());

    insert_snapshot(&conn, "sort_0", "bhh_0", 0);
    drop(conn);

    // Destination claims sort_0 AND sort_fake as canonical.
    let dst_path = dir.path().join("dst_sort.sqlite");
    create_sortition_dest_db(&dst_path, &["sort_0", "sort_fake"]);

    let err = copy_sortition_side_tables(src_path.to_str().unwrap(), dst_path.to_str().unwrap())
        .expect_err("copy must reject fabricated canonical sortition");
    match err {
        Error::CorruptionError(msg) => assert!(
            msg.contains("canonical sortition") && msg.contains("absent from src.snapshots"),
            "unexpected corruption message: {msg}"
        ),
        other => panic!("expected CorruptionError, got {other:?}"),
    }
}

/// `stacks_chain_tips_by_burn_view` (schema 11) rows for canonical
/// sortitions are copied and reported in the stats.
#[test]
fn test_sortition_stacks_chain_tips_by_burn_view_copied() {
    let dir = tempdir().unwrap();
    let (conn, src_path) = create_sortition_source_db(dir.path());

    // Insert canonical snapshots.
    insert_snapshot(&conn, "sort_0", "bhh_0", 0);
    insert_snapshot(&conn, "sort_1", "bhh_1", 1);

    // Insert stacks_chain_tips_by_burn_view rows.
    // consensus_hash and burn_view_consensus_hash must reference
    // existing snapshots(consensus_hash) due to FK constraints.
    test_insert_stacks_chain_tip_by_burn_view_row(
        &conn,
        &hex_id("sort_0"),
        "ch_sort_0",
        "ch_sort_0",
        "bh_0",
        0,
    )
    .unwrap();
    test_insert_stacks_chain_tip_by_burn_view_row(
        &conn,
        &hex_id("sort_1"),
        "ch_sort_1",
        "ch_sort_1",
        "bh_1",
        1,
    )
    .unwrap();
    drop(conn);

    let dst_path = dir.path().join("dst_sort.sqlite");
    create_sortition_dest_db(&dst_path, &["sort_0", "sort_1"]);

    let stats =
        copy_sortition_side_tables(src_path.to_str().unwrap(), dst_path.to_str().unwrap()).unwrap();

    // The stats struct should reflect the copied rows.
    assert_eq!(
        stats.stacks_chain_tips_by_burn_view_rows, 2,
        "stats should report 2 stacks_chain_tips_by_burn_view rows"
    );

    // Verify the exact rows landed in the destination.
    let dst_conn = Connection::open(&dst_path).unwrap();
    let rows: Vec<(String, String, String, i64)> = dst_conn
        .prepare(
            "SELECT consensus_hash, burn_view_consensus_hash, block_hash, block_height \
             FROM stacks_chain_tips_by_burn_view ORDER BY block_height",
        )
        .unwrap()
        .query_map([], |row| {
            Ok((row.get(0)?, row.get(1)?, row.get(2)?, row.get(3)?))
        })
        .unwrap()
        .collect::<Result<_, _>>()
        .unwrap();
    assert_eq!(
        rows,
        vec![
            ("ch_sort_0".into(), "ch_sort_0".into(), "bh_0".into(), 0),
            ("ch_sort_1".into(), "ch_sort_1".into(), "bh_1".into(), 1),
        ]
    );
}

/// Expected outcome of a single Stacks-tip memo row under the boundary copy.
enum Expect {
    /// Copied unchanged (row at or below the boundary).
    Verbatim,
    /// Kept but clamped down to the anchor (above-boundary anchor row).
    RewrittenToAnchor,
    /// Excluded entirely (above-boundary, not the anchor).
    Dropped,
}

/// `stacks_chain_tips` boundary handling (the relaxed-match memo table): a row
/// at/below the boundary is copied verbatim, an above-boundary anchor row is
/// rewritten down to the anchor, and an above-boundary non-anchor row is
/// dropped.
#[rstest]
#[case::pass_through(5, false, Expect::Verbatim)]
#[case::rewrite_anchor(20, true, Expect::RewrittenToAnchor)]
#[case::drop_non_anchor(20, false, Expect::Dropped)]
fn test_sortition_stacks_chain_tip_boundary(
    #[case] input_height: u64,
    #[case] input_is_anchor: bool,
    #[case] expect: Expect,
) {
    let dir = tempdir().unwrap();
    let (conn, src_path) = create_sortition_source_db(dir.path());
    insert_snapshot(&conn, "sort_0", "bhh_0", 0);
    insert_snapshot(&conn, "sort_1", "bhh_1", 1);

    let boundary = sortition_test_tip_boundary(10);
    let anchor_ch = boundary.anchor_consensus_hash.to_string();
    let anchor_bhh = boundary.anchor_block_hash.to_string();
    // stacks_chain_tips has no consensus_hash FK, so the input hash is free.
    let input_ch = if input_is_anchor {
        anchor_ch.clone()
    } else {
        "ch_other".to_string()
    };
    test_insert_stacks_chain_tip_row(&conn, &hex_id("sort_1"), &input_ch, "bh_in", input_height)
        .unwrap();
    drop(conn);

    let dst_path = dir.path().join("dst_sort.sqlite");
    create_sortition_dest_db(&dst_path, &["sort_0", "sort_1"]);

    copy_sortition_side_tables_with_boundary(
        src_path.to_str().unwrap(),
        dst_path.to_str().unwrap(),
        Some(&boundary),
    )
    .unwrap();

    let dst_conn = Connection::open(&dst_path).unwrap();
    let row: Option<(String, String, i64)> = dst_conn
        .query_row(
            "SELECT consensus_hash, block_hash, block_height FROM stacks_chain_tips \
             WHERE sortition_id = ?1",
            params![hex_id("sort_1")],
            |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?)),
        )
        .optional()
        .unwrap();

    let expected = match expect {
        Expect::Verbatim => Some((input_ch, "bh_in".to_string(), input_height as i64)),
        Expect::RewrittenToAnchor => {
            Some((anchor_ch, anchor_bhh, boundary.anchor_block_height as i64))
        }
        Expect::Dropped => None,
    };
    assert_eq!(row, expected);
}

/// `stacks_chain_tips_by_burn_view` boundary handling (the strict-match memo
/// table): its anchor match requires BOTH `consensus_hash` AND
/// `burn_view_consensus_hash` to equal the anchor. An above-boundary row with
/// the anchor consensus hash is kept+rewritten only when its burn-view hash
/// also matches; a mismatching burn view is dropped (whereas
/// `stacks_chain_tips` would keep it -- see
/// [`test_sortition_stacks_chain_tip_boundary`]).
#[rstest]
#[case::rewrite_when_burn_view_matches(true)]
#[case::drop_when_burn_view_differs(false)]
fn test_sortition_by_burn_view_boundary(#[case] burn_view_is_anchor: bool) {
    let dir = tempdir().unwrap();
    let (conn, src_path) = create_sortition_source_db(dir.path());
    insert_snapshot(&conn, "sort_0", "bhh_0", 0);
    insert_snapshot(&conn, "sort_1", "bhh_1", 1);

    let boundary = sortition_test_tip_boundary(10);
    let anchor_ch = boundary.anchor_consensus_hash.to_string();
    let anchor_burn_view_ch = boundary.anchor_burn_view_consensus_hash.to_string();
    let anchor_bhh = boundary.anchor_block_hash.to_string();

    // Both by_burn_view columns FK to snapshots(consensus_hash): the row's
    // consensus_hash is always the anchor; its burn_view_consensus_hash is the
    // anchor (rewrite) or a different, snapshot-backed value (drop).
    test_set_snapshot_consensus_hash(&conn, &hex_id("sort_0"), &anchor_ch).unwrap();
    let burn_view_ch = if burn_view_is_anchor {
        anchor_burn_view_ch.clone()
    } else {
        let wrong_ch = ConsensusHash([0x22; 20]).to_string();
        test_set_snapshot_consensus_hash(&conn, &hex_id("sort_1"), &wrong_ch).unwrap();
        wrong_ch
    };
    // Above the boundary (20 > 10) so the height branch fires.
    test_insert_stacks_chain_tip_by_burn_view_row(
        &conn,
        &hex_id("sort_1"),
        &anchor_ch,
        &burn_view_ch,
        "bh_bv",
        20,
    )
    .unwrap();
    drop(conn);

    let dst_path = dir.path().join("dst_sort.sqlite");
    create_sortition_dest_db(&dst_path, &["sort_0", "sort_1"]);

    copy_sortition_side_tables_with_boundary(
        src_path.to_str().unwrap(),
        dst_path.to_str().unwrap(),
        Some(&boundary),
    )
    .unwrap();

    let dst_conn = Connection::open(&dst_path).unwrap();
    let row: Option<(String, String, String, i64)> = dst_conn
        .query_row(
            "SELECT consensus_hash, burn_view_consensus_hash, block_hash, block_height \
             FROM stacks_chain_tips_by_burn_view WHERE sortition_id = ?1",
            params![hex_id("sort_1")],
            |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?, r.get(3)?)),
        )
        .optional()
        .unwrap();

    let expected = if burn_view_is_anchor {
        // Strict anchor match -> kept and clamped to the anchor.
        Some((
            anchor_ch,
            anchor_burn_view_ch,
            anchor_bhh,
            boundary.anchor_block_height as i64,
        ))
    } else {
        // Burn view != anchor -> dropped (stacks_chain_tips would keep it).
        None
    };
    assert_eq!(row, expected);
}

/// Production-path integration. The copy keeps the canonical chain's
/// rows and drops the fork's.
#[test]
fn test_sortition_copy_with_production_seeded_source() {
    let dir = tempdir().unwrap();
    let db_dir = dir.path().join("src_sort");
    let mut db = SortitionDB::connect(
        db_dir.to_str().unwrap(),
        0,
        &BurnchainHeaderHash([0u8; 32]),
        0,
        &StacksEpoch::unit_test_3_4(0),
        PoxConstants::test_default(),
        None,
        true,
        None,
    )
    .expect("sortition DB init failed");

    let genesis = SortitionDB::get_first_block_snapshot(db.conn()).unwrap();
    // Canonical chain: two snapshots appended at the tip.
    let sn1 = test_append_snapshot(&mut db, BurnchainHeaderHash([0x11; 32]), &[]);
    let sn2 = test_append_snapshot(&mut db, BurnchainHeaderHash([0x12; 32]), &[]);
    // A two-block fork branching off sn1.
    let fork = make_fork_run(&mut db, &sn1, 2, 0x80);
    assert_eq!(fork.len(), 2);
    drop(db);
    let src_path = db_dir.join("marf.sqlite");

    let dst_path = dir.path().join("dst_sort.sqlite");
    create_sortition_dest_db_with_ids(
        &dst_path,
        &[
            genesis.sortition_id.clone(),
            sn1.sortition_id.clone(),
            sn2.sortition_id.clone(),
        ],
    );

    let stats =
        copy_sortition_side_tables(src_path.to_str().unwrap(), dst_path.to_str().unwrap()).unwrap();
    assert_eq!(stats.snapshots_rows, 3, "genesis + two canonical snapshots");

    let dst_conn = Connection::open(&dst_path).unwrap();
    for fork_sn in &fork {
        let count: i64 = dst_conn
            .query_row(
                "SELECT COUNT(*) FROM snapshots WHERE sortition_id = ?1",
                params![fork_sn.sortition_id.to_string()],
                |row| row.get(0),
            )
            .unwrap();
        assert_eq!(count, 0, "fork snapshot must not be copied");
    }
}

/// Drift guard: every table the sortition migrations create must be
/// classified, so a future migration can't silently drop one from the copy.
/// Runs the exact production guard against a freshly-migrated schema, so the
/// test and the runtime check cannot drift apart.
#[test]
fn test_no_unclassified_sortition_tables() {
    let dir = tempdir().unwrap();
    let (conn, _src_path) = create_sortition_source_db(dir.path());
    assert_source_tables_classified(&conn)
        .expect("fresh production sortition schema must be fully classified");
}

/// Every table whose schema is cloned ([`REQUIRED_TABLES`]) must also have a
/// row-copy spec, and vice versa. Without this, a table could pass the
/// classification guard and be cloned into the dst yet never populated —
/// recreated-empty inconsistency one level below the unclassified-table check.
#[test]
fn test_sortition_copy_specs_match_required_tables() {
    let spec_tables: Vec<&str> = sortition_copy_specs(None).iter().map(|s| s.table).collect();
    let spec_set: HashSet<&str> = spec_tables.iter().copied().collect();
    assert_eq!(
        spec_tables.len(),
        spec_set.len(),
        "duplicate table in sortition_copy_specs"
    );
    let required_set: HashSet<&str> = REQUIRED_TABLES.iter().copied().collect();
    assert_eq!(
        spec_set, required_set,
        "every REQUIRED_TABLES entry must have exactly one copy spec (and vice versa); \
         a cloned-but-uncopied table would be present-but-empty in the squash"
    );
}

/// Runtime guard: a source DB carrying a table the copy lists don't classify
/// is rejected up front, naming the offending table, before any destination is
/// produced. This is the defense-in-depth complement to the compile-time
/// `test_no_unclassified_sortition_tables` guard.
#[test]
fn test_unclassified_source_table_is_rejected() {
    let dir = tempdir().unwrap();
    let (conn, src_path) = create_sortition_source_db(dir.path());
    conn.execute_batch("CREATE TABLE surprise_table (x INTEGER)")
        .unwrap();
    drop(conn);

    let dst_path = dir.path().join("dst_sort.sqlite");
    let err = copy_sortition_side_tables(src_path.to_str().unwrap(), dst_path.to_str().unwrap())
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
