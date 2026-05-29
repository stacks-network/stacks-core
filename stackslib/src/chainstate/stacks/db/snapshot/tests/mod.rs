use rusqlite::{params, Connection};
use tempfile::tempdir;

use super::common::{unclassified_tables, MARF_INFRA_TABLES};
use super::index::copy_index_side_tables;
use crate::chainstate::nakamoto::{
    NAKAMOTO_CHAINSTATE_SCHEMA_1, NAKAMOTO_CHAINSTATE_SCHEMA_2, NAKAMOTO_CHAINSTATE_SCHEMA_3,
    NAKAMOTO_CHAINSTATE_SCHEMA_4, NAKAMOTO_CHAINSTATE_SCHEMA_5, NAKAMOTO_CHAINSTATE_SCHEMA_6,
    NAKAMOTO_CHAINSTATE_SCHEMA_7, NAKAMOTO_CHAINSTATE_SCHEMA_8,
};
use crate::chainstate::stacks::db::{
    CHAINSTATE_INDEXES, CHAINSTATE_INITIAL_SCHEMA, CHAINSTATE_SCHEMA_2, CHAINSTATE_SCHEMA_3,
    CHAINSTATE_SCHEMA_4, CHAINSTATE_SCHEMA_5,
};

/// Create a source `index.sqlite` with the full chainstate schema by replaying
/// the real migration pipeline. Returns the connection for inserting test data.
fn create_source_db(path: &std::path::Path) -> Connection {
    let conn = Connection::open(path).unwrap();

    for cmd in CHAINSTATE_INITIAL_SCHEMA {
        conn.execute_batch(cmd).unwrap();
    }
    conn.execute(
        "INSERT INTO db_config (version, mainnet, chain_id) VALUES (?1, ?2, ?3)",
        params!["1", 1i64, 1i64],
    )
    .unwrap();

    // Apply all migrations in order (same as StacksChainState::apply_schema_migrations).
    for cmd in CHAINSTATE_SCHEMA_2 {
        conn.execute_batch(cmd).unwrap();
    }
    for cmd in CHAINSTATE_SCHEMA_3 {
        conn.execute_batch(cmd).unwrap();
    }
    for cmd in NAKAMOTO_CHAINSTATE_SCHEMA_1.iter() {
        conn.execute_batch(cmd).unwrap();
    }
    for cmd in NAKAMOTO_CHAINSTATE_SCHEMA_2 {
        conn.execute_batch(cmd).unwrap();
    }
    for cmd in NAKAMOTO_CHAINSTATE_SCHEMA_3 {
        conn.execute_batch(cmd).unwrap();
    }
    for cmd in NAKAMOTO_CHAINSTATE_SCHEMA_4 {
        conn.execute_batch(cmd).unwrap();
    }
    for cmd in NAKAMOTO_CHAINSTATE_SCHEMA_5 {
        conn.execute_batch(cmd).unwrap();
    }
    for cmd in CHAINSTATE_SCHEMA_4 {
        conn.execute_batch(cmd).unwrap();
    }
    for cmd in NAKAMOTO_CHAINSTATE_SCHEMA_6 {
        conn.execute_batch(cmd).unwrap();
    }
    for cmd in CHAINSTATE_SCHEMA_5 {
        conn.execute_batch(cmd).unwrap();
    }
    for cmd in NAKAMOTO_CHAINSTATE_SCHEMA_7 {
        conn.execute_batch(cmd).unwrap();
    }
    for cmd in NAKAMOTO_CHAINSTATE_SCHEMA_8 {
        conn.execute_batch(cmd).unwrap();
    }
    for cmd in CHAINSTATE_INDEXES {
        conn.execute_batch(cmd).unwrap();
    }

    // Tests skip the MARF migration; create `__fork_storage` empty so
    // `copy_canonical_fork_storage`'s strict src-has-table check passes.
    conn.execute_batch(
        "CREATE TABLE IF NOT EXISTS __fork_storage (
            value_hash TEXT NOT NULL,
            value TEXT NOT NULL,
            PRIMARY KEY(value_hash)
        );",
    )
    .unwrap();

    conn
}

/// Render a short test identifier as the lowercase-hex form of its UTF-8 bytes.
///
/// The production squash code stores 32-byte `index_block_hash` values as
/// BLOB in `marf_squashed_blocks.block_hash` and joins them against the
/// chainstate `index_block_hash` TEXT columns via `lower(hex(block_hash))`.
/// Tests use short labels like `"ibh1"` for readability; this helper converts
/// such a label to the matching lower-hex TEXT so a label-based fixture is
/// consistent with what production code expects to see in the chainstate
/// tables.
fn hex_id(label: &str) -> String {
    use std::fmt::Write;
    let mut out = String::with_capacity(label.len() * 2);
    for b in label.as_bytes() {
        write!(out, "{:02x}", b).unwrap();
    }
    out
}

/// Create a destination DB that simulates a squashed MARF by adding the
/// `marf_squashed_blocks` table with the given canonical block-hash labels.
///
/// Each label is stored as raw UTF-8 bytes in the BLOB column, so
/// `lower(hex(block_hash))` returns the same TEXT that test chainstate
/// inserts write via [`hex_id`].
fn create_dest_db_with_canonical_blocks(path: &std::path::Path, canonical: &[&str]) {
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
        conn.execute(
            "INSERT INTO marf_squashed_blocks (height, block_hash, marf_root_hash) \
             VALUES (?1, ?2, X'00')",
            params![h as i64, bh.as_bytes()],
        )
        .unwrap();
    }
}

/// Insert a block_headers row at the given height.
fn insert_block_header(conn: &Connection, height: u32, suffix: &str) {
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

#[test]
fn test_copy_index_side_tables_round_trip() {
    let dir = tempdir().unwrap();
    let src_path = dir.path().join("src_index.sqlite");
    let conn = create_source_db(&src_path);

    // Insert test data at heights 1, 2, 3.
    for (h, s) in [(1, "1"), (2, "2"), (3, "3")] {
        insert_block_header(&conn, h, s);
        insert_payment(&conn, h, s);
        insert_transaction(&conn, h as i64, &format!("ibh{s}"));
    }
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
    drop(conn);

    // Destination: canonical blocks are ibh1, ibh2 (height 0, 1) - ibh3 is NOT canonical.
    let dst_path = dir.path().join("dst_index.sqlite");
    create_dest_db_with_canonical_blocks(&dst_path, &["ibh1", "ibh2"]);

    // Copy: only canonical blocks ibh1 and ibh2 should be included.
    let stats =
        copy_index_side_tables(src_path.to_str().unwrap(), dst_path.to_str().unwrap(), 0, 1)
            .unwrap();

    assert_eq!(stats.block_headers_rows, 2, "2 canonical block_headers");
    assert_eq!(stats.payments_rows, 2, "2 canonical payments");
    assert_eq!(stats.transactions_rows, 2, "2 canonical transactions");
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
    // Schema-only compatibility table is present but empty.
    assert_eq!(
        count("SELECT COUNT(*) FROM invalidated_microblocks_data"),
        0
    );
}

#[test]
fn test_copy_excludes_fork_rows() {
    let dir = tempdir().unwrap();
    let src_path = dir.path().join("src_index.sqlite");
    let conn = create_source_db(&src_path);

    // Insert canonical block at height 1.
    insert_block_header(&conn, 1, "1_canonical");
    insert_transaction(&conn, 1, "ibh1_canonical");
    // Insert fork block at same height 1 (different consensus hash).
    insert_block_header(&conn, 1, "1_fork");
    insert_transaction(&conn, 2, "ibh1_fork");
    drop(conn);

    // Only ibh1_canonical is in the canonical set.
    let dst_path = dir.path().join("dst_index.sqlite");
    create_dest_db_with_canonical_blocks(&dst_path, &["ibh1_canonical"]);

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

#[test]
fn test_copy_canonical_fork_storage_filters_by_leaf_hash() {
    let dir = tempdir().unwrap();
    let src_path = dir.path().join("src.sqlite");
    let dst_path = dir.path().join("dst.sqlite");

    // src.__fork_storage: two canonical entries (aa, cc) and one
    // non-canonical fork entry (bb) that must be excluded.
    let src = Connection::open(&src_path).unwrap();
    src.execute_batch(
        "CREATE TABLE __fork_storage (\
             value_hash TEXT NOT NULL PRIMARY KEY, value TEXT NOT NULL);\
         INSERT INTO __fork_storage VALUES ('aa','va'),('bb','vb'),('cc','vc');",
    )
    .unwrap();
    drop(src);

    // Empty dst with src attached; the copy filters by the canonical leaf set.
    let dst = Connection::open(&dst_path).unwrap();
    dst.execute(
        "ATTACH DATABASE ?1 AS src",
        params![src_path.to_str().unwrap()],
    )
    .unwrap();
    let leaf_hashes: std::collections::HashSet<String> =
        ["aa".to_string(), "cc".to_string()].into_iter().collect();

    let copied = super::fork_storage::copy_canonical_fork_storage(&dst, &leaf_hashes).unwrap();
    assert_eq!(copied, 2, "only canonical value_hashes are copied");

    let present: i64 = dst
        .query_row(
            "SELECT COUNT(*) FROM __fork_storage WHERE value_hash IN ('aa','cc')",
            [],
            |row| row.get(0),
        )
        .unwrap();
    assert_eq!(present, 2);
    let forked: i64 = dst
        .query_row(
            "SELECT COUNT(*) FROM __fork_storage WHERE value_hash = 'bb'",
            [],
            |row| row.get(0),
        )
        .unwrap();
    assert_eq!(forked, 0, "non-canonical fork row excluded");
}
/// Insert a staging_blocks row for a canonical processed block.
fn insert_staging_block(conn: &Connection, suffix: &str, height: u32) {
    conn.execute(
        "INSERT INTO staging_blocks (\
                anchored_block_hash, parent_anchored_block_hash, \
                consensus_hash, parent_consensus_hash, \
                parent_microblock_hash, parent_microblock_seq, \
                microblock_pubkey_hash, height, attachable, orphaned, processed, \
                commit_burn, sortition_burn, index_block_hash, \
                download_time, arrival_time, processed_time) \
             VALUES (?1, ?2, ?3, ?4, ?5, 0, 'mph', ?6, 1, 0, 1, 0, 0, ?7, 100, 200, 300)",
        params![
            format!("bh{suffix}"),
            format!("parent_bh{suffix}"),
            format!("ch{suffix}"),
            format!("parent_ch{suffix}"),
            "0000000000000000000000000000000000000000000000000000000000000000",
            height,
            hex_id(&format!("ibh{suffix}")),
        ],
    )
    .unwrap();
}

#[test]
fn test_staging_blocks_populated_for_canonical() {
    let dir = tempdir().unwrap();
    let src_path = dir.path().join("src.sqlite");
    let conn = create_source_db(&src_path);

    // Insert block headers and staging blocks at heights 1, 2, 3.
    for (h, s) in [(1, "1"), (2, "2"), (3, "3")] {
        insert_block_header(&conn, h, s);
        insert_staging_block(&conn, s, h);
    }
    drop(conn);

    // Canonical set includes ibh1 and ibh2, but NOT ibh3.
    let dst_path = dir.path().join("dst.sqlite");
    create_dest_db_with_canonical_blocks(&dst_path, &["ibh1", "ibh2"]);

    let stats =
        copy_index_side_tables(src_path.to_str().unwrap(), dst_path.to_str().unwrap(), 0, 1)
            .unwrap();

    // Only 2 staging_blocks rows for canonical blocks.
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

    // ibh3 should NOT be present.
    let count: i64 = dst_conn
        .query_row(
            "SELECT COUNT(*) FROM staging_blocks WHERE index_block_hash = ?1",
            params![hex_id("ibh3")],
            |row| row.get(0),
        )
        .unwrap();
    assert_eq!(count, 0);
}

#[test]
fn test_no_unclassified_source_tables() {
    // Drift guard: every table the chainstate migrations create must be
    // classified, so a future migration can't silently drop one from the copy.
    let dir = tempdir().unwrap();
    let conn = create_source_db(&dir.path().join("src.sqlite"));
    let known: Vec<&str> = super::index::COPIED_TABLES
        .iter()
        .chain(super::index::SCHEMA_ONLY_TABLES)
        .chain(MARF_INFRA_TABLES.iter())
        .copied()
        .collect();
    let extra = unclassified_tables(&conn, &known);
    assert!(
        extra.is_empty(),
        "unclassified index table(s) {extra:?}: classify each in COPIED_TABLES or \
         SCHEMA_ONLY_TABLES (snapshot/index.rs)"
    );
}
