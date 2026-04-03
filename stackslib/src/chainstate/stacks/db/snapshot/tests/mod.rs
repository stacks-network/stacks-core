use rusqlite::{params, Connection};
use tempfile::tempdir;

use super::index::{copy_index_side_tables, validate_index_side_tables};
use crate::burnchains::bitcoin::spv::{
    SPV_DB_VERSION, SPV_INITIAL_SCHEMA, SPV_SCHEMA_2, SPV_SCHEMA_3,
};
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

    conn
}

/// Create a destination DB that simulates a squashed MARF by adding the
/// `marf_squash_block_heights` table with the given canonical block hashes.
fn create_dest_db_with_canonical_blocks(path: &std::path::Path, canonical: &[&str]) {
    let conn = Connection::open(path).unwrap();
    conn.execute_batch(
            "CREATE TABLE IF NOT EXISTS marf_squash_block_heights (block_hash TEXT NOT NULL, height INTEGER NOT NULL)",
        )
        .unwrap();
    for (h, bh) in canonical.iter().enumerate() {
        conn.execute(
            "INSERT INTO marf_squash_block_heights (block_hash, height) VALUES (?1, ?2)",
            params![bh, h as i64],
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
                format!("ibh{suffix}"),
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
            format!("ibh{suffix}"),
        ],
    )
    .unwrap();
}

/// Insert a transaction row for the given index_block_hash.
fn insert_transaction(conn: &Connection, id: i64, ibh: &str) {
    conn.execute(
        "INSERT INTO transactions (id, txid, index_block_hash, tx_hex, result) \
             VALUES (?1, ?2, ?3, '0x00', 'ok')",
        params![id, format!("tx{id}"), ibh],
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
             VALUES ('ch1','ch0','bv1',0,'bh1','ibh1',1,0)",
            [],
        )
        .unwrap();
    conn.execute(
        "INSERT INTO nakamoto_reward_sets (index_block_hash, reward_set) VALUES ('ibh1','{}')",
        [],
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

    // Validate.
    let validation =
        validate_index_side_tables(src_path.to_str().unwrap(), dst_path.to_str().unwrap(), 0, 1)
            .unwrap();

    assert!(
        validation.is_valid(),
        "validation should pass: {validation:?}"
    );
    assert!(validation.tables_present);
    assert!(validation.db_config_matches);
    assert!(validation.block_headers_count_match);
    assert!(validation.payments_count_match);
    assert!(validation.transactions_count_match);
    assert!(validation.nakamoto_tenure_events_count_match);
    assert!(validation.transactions_no_extra_blocks);
    assert!(validation.tenure_events_no_extra_blocks);
    assert!(validation.staging_blocks_match);
    assert!(validation.invalidated_microblocks_data_empty);
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

    // Validate passes - fork rows excluded.
    let validation =
        validate_index_side_tables(src_path.to_str().unwrap(), dst_path.to_str().unwrap(), 0, 1)
            .unwrap();
    assert!(
        validation.is_valid(),
        "validation should pass without fork rows: {validation:?}"
    );
}

#[test]
fn test_validate_index_side_tables_detects_extra_rows() {
    let dir = tempdir().unwrap();
    let src_path = dir.path().join("src_index.sqlite");
    let conn = create_source_db(&src_path);

    // Insert one block + transaction.
    insert_block_header(&conn, 1, "1");
    insert_transaction(&conn, 1, "ibh1");
    drop(conn);

    let dst_path = dir.path().join("dst_index.sqlite");
    create_dest_db_with_canonical_blocks(&dst_path, &["ibh1"]);

    let _stats =
        copy_index_side_tables(src_path.to_str().unwrap(), dst_path.to_str().unwrap(), 0, 1)
            .unwrap();

    // Inject a transaction for a block NOT in the canonical set.
    {
        let conn = Connection::open(&dst_path).unwrap();
        conn.execute(
            "INSERT INTO transactions VALUES (99, 'tx_bad', 'ibh_UNKNOWN', '0x00', 'ok')",
            [],
        )
        .unwrap();
    }

    let validation =
        validate_index_side_tables(src_path.to_str().unwrap(), dst_path.to_str().unwrap(), 0, 1)
            .unwrap();

    assert!(
        !validation.transactions_no_extra_blocks,
        "should detect extra block"
    );
    assert!(
        !validation.transactions_count_match,
        "count should mismatch"
    );
    assert!(!validation.is_valid(), "validation must fail");
}

#[test]
fn test_all_required_tables_exist() {
    let dir = tempdir().unwrap();
    let src_path = dir.path().join("src.sqlite");
    let _conn = create_source_db(&src_path);
    drop(_conn);

    let dst_path = dir.path().join("dst.sqlite");
    create_dest_db_with_canonical_blocks(&dst_path, &[]);

    copy_index_side_tables(src_path.to_str().unwrap(), dst_path.to_str().unwrap(), 0, 1).unwrap();

    let dst_conn = Connection::open(&dst_path).unwrap();

    // Verify all required tables exist including the newly added ones.
    for table in &[
        "staging_blocks",
        "staging_microblocks",
        "staging_microblocks_data",
        "invalidated_microblocks_data",
        "user_supporters",
    ] {
        let count: i64 = dst_conn
            .query_row(
                "SELECT COUNT(*) FROM sqlite_master WHERE type='table' AND name=?1",
                params![table],
                |row| row.get(0),
            )
            .unwrap();
        assert_eq!(count, 1, "table '{table}' should exist");
    }

    // invalidated_microblocks_data should be empty.
    let count: i64 = dst_conn
        .query_row(
            "SELECT COUNT(*) FROM invalidated_microblocks_data",
            [],
            |row| row.get(0),
        )
        .unwrap();
    assert_eq!(count, 0, "invalidated_microblocks_data should be empty");
}

/// Create a source headers.sqlite (SPV v3 schema with chain_work).
/// Replays the real SPV migration pipeline: INITIAL -> SCHEMA_2 -> SCHEMA_3.
fn create_spv_headers_db(path: &std::path::Path) -> Connection {
    let conn = Connection::open(path).unwrap();
    for cmd in SPV_INITIAL_SCHEMA {
        conn.execute_batch(cmd).unwrap();
    }
    for cmd in SPV_SCHEMA_2 {
        conn.execute_batch(cmd).unwrap();
    }
    for cmd in SPV_SCHEMA_3 {
        conn.execute_batch(cmd).unwrap();
    }
    conn.execute(
        &format!("INSERT INTO db_config (version) VALUES ('{SPV_DB_VERSION}')"),
        [],
    )
    .unwrap();
    conn
}

#[test]
fn test_spv_headers_copy_and_validate() {
    let dir = tempdir().unwrap();
    let src_path = dir.path().join("src_headers.sqlite");
    let dst_path = dir.path().join("dst_headers.sqlite");

    let src = create_spv_headers_db(&src_path);
    // Insert headers at heights 0..=5000.
    for h in 0..=5000u32 {
        src.execute(
            "INSERT INTO headers VALUES (1, 'prev', 'merkle', 0, 0, 0, ?1, ?2)",
            params![h, format!("hash_{h}")],
        )
        .unwrap();
    }
    // Insert chain_work for intervals 0, 1, 2.
    src.execute("INSERT INTO chain_work VALUES (0, 'work_0')", [])
        .unwrap();
    src.execute("INSERT INTO chain_work VALUES (1, 'work_1')", [])
        .unwrap();
    src.execute("INSERT INTO chain_work VALUES (2, 'work_2')", [])
        .unwrap();
    drop(src);

    let stats =
        super::spv::copy_spv_headers(src_path.to_str().unwrap(), dst_path.to_str().unwrap(), 4500)
            .unwrap()
            .unwrap();

    // Headers 0..=4500 = 4501 rows.
    assert_eq!(stats.headers_rows, 4501);
    // Interval 0: (0+1)*2016-1=2015 <= 4500 ✓
    // Interval 1: (1+1)*2016-1=4031 <= 4500 ✓
    // Interval 2: (2+1)*2016-1=6047 <= 4500 ✗
    assert_eq!(stats.chain_work_rows, 2);

    let v = super::spv::validate_spv_headers(
        src_path.to_str().unwrap(),
        dst_path.to_str().unwrap(),
        4500,
    )
    .unwrap()
    .unwrap();
    assert!(v.is_valid(), "validation failed: {v:?}");
}

#[test]
fn test_spv_headers_chain_work_boundary_0() {
    let dir = tempdir().unwrap();
    let src_path = dir.path().join("src.sqlite");
    let dst_path = dir.path().join("dst.sqlite");

    let src = create_spv_headers_db(&src_path);
    src.execute(
        "INSERT INTO headers VALUES (1, 'p', 'm', 0, 0, 0, 0, 'h0')",
        [],
    )
    .unwrap();
    src.execute("INSERT INTO chain_work VALUES (0, 'w0')", [])
        .unwrap();
    drop(src);

    let stats =
        super::spv::copy_spv_headers(src_path.to_str().unwrap(), dst_path.to_str().unwrap(), 0)
            .unwrap()
            .unwrap();

    assert_eq!(stats.headers_rows, 1);
    // (0+1)*2016-1 = 2015 > 0 -> no intervals included.
    assert_eq!(stats.chain_work_rows, 0);
}

#[test]
fn test_spv_headers_chain_work_boundary_2015() {
    let dir = tempdir().unwrap();
    let src_path = dir.path().join("src.sqlite");
    let dst_path = dir.path().join("dst.sqlite");

    let src = create_spv_headers_db(&src_path);
    for h in 0..=2015u32 {
        src.execute(
            "INSERT INTO headers VALUES (1, 'p', 'm', 0, 0, 0, ?1, ?2)",
            params![h, format!("h{h}")],
        )
        .unwrap();
    }
    src.execute("INSERT INTO chain_work VALUES (0, 'w0')", [])
        .unwrap();
    src.execute("INSERT INTO chain_work VALUES (1, 'w1')", [])
        .unwrap();
    drop(src);

    let stats =
        super::spv::copy_spv_headers(src_path.to_str().unwrap(), dst_path.to_str().unwrap(), 2015)
            .unwrap()
            .unwrap();

    assert_eq!(stats.headers_rows, 2016);
    // (0+1)*2016-1 = 2015 <= 2015 ✓ -> 1 interval.
    assert_eq!(stats.chain_work_rows, 1);
}

#[test]
fn test_spv_headers_chain_work_boundary_2016() {
    let dir = tempdir().unwrap();
    let src_path = dir.path().join("src.sqlite");
    let dst_path = dir.path().join("dst.sqlite");

    let src = create_spv_headers_db(&src_path);
    for h in 0..=2016u32 {
        src.execute(
            "INSERT INTO headers VALUES (1, 'p', 'm', 0, 0, 0, ?1, ?2)",
            params![h, format!("h{h}")],
        )
        .unwrap();
    }
    src.execute("INSERT INTO chain_work VALUES (0, 'w0')", [])
        .unwrap();
    src.execute("INSERT INTO chain_work VALUES (1, 'w1')", [])
        .unwrap();
    drop(src);

    let stats =
        super::spv::copy_spv_headers(src_path.to_str().unwrap(), dst_path.to_str().unwrap(), 2016)
            .unwrap()
            .unwrap();

    assert_eq!(stats.headers_rows, 2017);
    // (0+1)*2016-1 = 2015 <= 2016 ✓
    // (1+1)*2016-1 = 4031 <= 2016 ✗
    assert_eq!(stats.chain_work_rows, 1);
}

#[test]
fn test_spv_headers_chain_work_boundary_4031() {
    let dir = tempdir().unwrap();
    let src_path = dir.path().join("src.sqlite");
    let dst_path = dir.path().join("dst.sqlite");

    let src = create_spv_headers_db(&src_path);
    for h in 0..=4031u32 {
        src.execute(
            "INSERT INTO headers VALUES (1, 'p', 'm', 0, 0, 0, ?1, ?2)",
            params![h, format!("h{h}")],
        )
        .unwrap();
    }
    src.execute("INSERT INTO chain_work VALUES (0, 'w0')", [])
        .unwrap();
    src.execute("INSERT INTO chain_work VALUES (1, 'w1')", [])
        .unwrap();
    src.execute("INSERT INTO chain_work VALUES (2, 'w2')", [])
        .unwrap();
    drop(src);

    let stats =
        super::spv::copy_spv_headers(src_path.to_str().unwrap(), dst_path.to_str().unwrap(), 4031)
            .unwrap()
            .unwrap();

    assert_eq!(stats.headers_rows, 4032);
    // (0+1)*2016-1 = 2015 <= 4031 ✓
    // (1+1)*2016-1 = 4031 <= 4031 ✓
    // (2+1)*2016-1 = 6047 <= 4031 ✗
    assert_eq!(stats.chain_work_rows, 2);
}

#[test]
fn test_spv_headers_chain_work_boundary_4032() {
    let dir = tempdir().unwrap();
    let src_path = dir.path().join("src.sqlite");
    let dst_path = dir.path().join("dst.sqlite");

    let src = create_spv_headers_db(&src_path);
    for h in 0..=4032u32 {
        src.execute(
            "INSERT INTO headers VALUES (1, 'p', 'm', 0, 0, 0, ?1, ?2)",
            params![h, format!("h{h}")],
        )
        .unwrap();
    }
    src.execute("INSERT INTO chain_work VALUES (0, 'w0')", [])
        .unwrap();
    src.execute("INSERT INTO chain_work VALUES (1, 'w1')", [])
        .unwrap();
    src.execute("INSERT INTO chain_work VALUES (2, 'w2')", [])
        .unwrap();
    drop(src);

    let stats =
        super::spv::copy_spv_headers(src_path.to_str().unwrap(), dst_path.to_str().unwrap(), 4032)
            .unwrap()
            .unwrap();

    assert_eq!(stats.headers_rows, 4033);
    // (2+1)*2016-1 = 6047 <= 4032 ✗ -> still only 2 intervals.
    assert_eq!(stats.chain_work_rows, 2);
}

#[test]
fn test_spv_headers_missing_source_returns_none() {
    let dir = tempdir().unwrap();
    let src_path = dir.path().join("nonexistent.sqlite");
    let dst_path = dir.path().join("dst.sqlite");

    let result =
        super::spv::copy_spv_headers(src_path.to_str().unwrap(), dst_path.to_str().unwrap(), 100)
            .unwrap();
    assert!(result.is_none());
}

#[test]
fn test_spv_headers_validate_source_present_dest_missing_fails() {
    let dir = tempdir().unwrap();
    let src_path = dir.path().join("src.sqlite");
    let dst_path = dir.path().join("nonexistent.sqlite");

    create_spv_headers_db(&src_path);

    let result = super::spv::validate_spv_headers(
        src_path.to_str().unwrap(),
        dst_path.to_str().unwrap(),
        100,
    );
    assert!(result.is_err());
}

#[test]
fn test_spv_headers_validate_both_absent_passes() {
    let dir = tempdir().unwrap();
    let src_path = dir.path().join("no_src.sqlite");
    let dst_path = dir.path().join("no_dst.sqlite");

    let result = super::spv::validate_spv_headers(
        src_path.to_str().unwrap(),
        dst_path.to_str().unwrap(),
        100,
    )
    .unwrap();
    assert!(result.is_none());
}

#[test]
fn test_spv_headers_stale_destination_removed_when_source_absent() {
    let dir = tempdir().unwrap();
    let src_path = dir.path().join("nonexistent.sqlite");
    let dst_path = dir.path().join("stale_headers.sqlite");

    // Create a stale destination file (simulates reused output dir).
    std::fs::write(&dst_path, b"stale data").unwrap();
    assert!(dst_path.exists());

    let result =
        super::spv::copy_spv_headers(src_path.to_str().unwrap(), dst_path.to_str().unwrap(), 100)
            .unwrap();

    assert!(result.is_none());
    assert!(
        !dst_path.exists(),
        "stale destination should be removed when source is absent"
    );
}

#[test]
fn test_spv_headers_reused_output_dir() {
    let dir = tempdir().unwrap();
    let src_path = dir.path().join("src.sqlite");
    let dst_path = dir.path().join("dst.sqlite");

    let src = create_spv_headers_db(&src_path);
    for h in 0..=10u32 {
        src.execute(
            "INSERT INTO headers VALUES (1, 'p', 'm', 0, 0, 0, ?1, ?2)",
            params![h, format!("h{h}")],
        )
        .unwrap();
    }
    drop(src);

    // First copy.
    super::spv::copy_spv_headers(src_path.to_str().unwrap(), dst_path.to_str().unwrap(), 10)
        .unwrap()
        .unwrap();

    // Second copy into the same destination (reused output dir).
    let stats =
        super::spv::copy_spv_headers(src_path.to_str().unwrap(), dst_path.to_str().unwrap(), 10)
            .unwrap()
            .unwrap();

    assert_eq!(stats.headers_rows, 11);

    // Validate to confirm no duplicate rows.
    let v = super::spv::validate_spv_headers(
        src_path.to_str().unwrap(),
        dst_path.to_str().unwrap(),
        10,
    )
    .unwrap()
    .unwrap();
    assert!(
        v.is_valid(),
        "reused output dir should produce valid copy: {v:?}"
    );
}

// ---------------------------------------------------------------
// Sortition side-table tests
// ---------------------------------------------------------------

use super::sortition::{copy_sortition_side_tables, validate_sortition_side_tables};
use crate::chainstate::burn::db::sortdb::{
    SORTITION_DB_INITIAL_SCHEMA, SORTITION_DB_SCHEMA_10, SORTITION_DB_SCHEMA_11,
    SORTITION_DB_SCHEMA_2, SORTITION_DB_SCHEMA_3, SORTITION_DB_SCHEMA_4, SORTITION_DB_SCHEMA_5,
    SORTITION_DB_SCHEMA_6, SORTITION_DB_SCHEMA_7, SORTITION_DB_SCHEMA_8, SORTITION_DB_SCHEMA_9,
};

/// Create a sortition source DB with the real schema (all migrations
/// through schema 11). Applies only the DDL; epoch data inserts are
/// skipped since tests only need the table structure.
fn create_sortition_source_db(path: &std::path::Path) -> Connection {
    let conn = Connection::open(path).unwrap();
    for cmd in SORTITION_DB_INITIAL_SCHEMA {
        conn.execute_batch(cmd).unwrap();
    }
    for cmd in SORTITION_DB_SCHEMA_2 {
        conn.execute_batch(cmd).unwrap();
    }
    for cmd in SORTITION_DB_SCHEMA_3 {
        conn.execute_batch(cmd).unwrap();
    }
    for cmd in SORTITION_DB_SCHEMA_4 {
        conn.execute_batch(cmd).unwrap();
    }
    for cmd in SORTITION_DB_SCHEMA_5 {
        conn.execute_batch(cmd).unwrap();
    }
    for cmd in SORTITION_DB_SCHEMA_6 {
        conn.execute_batch(cmd).unwrap();
    }
    for cmd in SORTITION_DB_SCHEMA_7 {
        conn.execute_batch(cmd).unwrap();
    }
    for cmd in SORTITION_DB_SCHEMA_8 {
        conn.execute_batch(cmd).unwrap();
    }
    for cmd in SORTITION_DB_SCHEMA_9 {
        conn.execute_batch(cmd).unwrap();
    }
    for cmd in SORTITION_DB_SCHEMA_10 {
        conn.execute_batch(cmd).unwrap();
    }
    for cmd in SORTITION_DB_SCHEMA_11 {
        conn.execute_batch(cmd).unwrap();
    }
    conn.execute(
        "INSERT OR REPLACE INTO db_config (version) VALUES ('11')",
        [],
    )
    .unwrap();
    conn
}

/// Insert a snapshot row for the given sortition_id and burn_header_hash.
fn insert_snapshot(
    conn: &Connection,
    sortition_id: &str,
    burn_header_hash: &str,
    block_height: u32,
) {
    conn.execute(
        "INSERT INTO snapshots (
                block_height, burn_header_hash, sortition_id, parent_sortition_id,
                burn_header_timestamp, parent_burn_header_hash, consensus_hash,
                ops_hash, total_burn, sortition, sortition_hash,
                winning_block_txid, winning_stacks_block_hash, index_root,
                num_sortitions, stacks_block_accepted, stacks_block_height,
                arrival_index, canonical_stacks_tip_height, canonical_stacks_tip_hash,
                canonical_stacks_tip_consensus_hash, pox_valid,
                accumulated_coinbase_ustx, pox_payouts, miner_pk_hash
            ) VALUES (
                ?1, ?2, ?3, 'parent_sort', 1000, 'parent_bhh', ?4,
                'ops', '0', 1, 'shash', 'wbtxid', 'wsbh', ?5,
                ?1, 0, 0, ?1, 0, 'csth', 'cstch', 1, '0', '[]', NULL
            )",
        params![
            block_height,
            burn_header_hash,
            sortition_id,
            format!("ch_{sortition_id}"),
            format!("ir_{sortition_id}"),
        ],
    )
    .unwrap();
}

/// Insert a leader_keys row for the given sortition_id.
fn insert_leader_key(conn: &Connection, sortition_id: &str) {
    conn.execute(
        "INSERT INTO leader_keys (txid, vtxindex, block_height, burn_header_hash, \
             sortition_id, consensus_hash, public_key, memo) \
             VALUES (?1, 0, 1, 'bhh', ?2, 'ch', 'pk', 'memo')",
        params![format!("lk_tx_{sortition_id}"), sortition_id],
    )
    .unwrap();
}

/// Insert a block_commits row for the given sortition_id.
fn insert_block_commit(conn: &Connection, sortition_id: &str) {
    conn.execute(
        "INSERT INTO block_commits (txid, vtxindex, block_height, burn_header_hash, \
             sortition_id, block_header_hash, new_seed, parent_block_ptr, parent_vtxindex, \
             key_block_ptr, key_vtxindex, memo, commit_outs, burn_fee, sunset_burn, \
             input, apparent_sender, burn_parent_modulus, punished) \
             VALUES (?1, 0, 1, 'bhh', ?2, 'bhh', 'seed', 0, 0, 0, 0, '', '', '0', '0', \
             'input', 'sender', 0, NULL)",
        params![format!("bc_tx_{sortition_id}"), sortition_id],
    )
    .unwrap();
}

/// Insert a block_commit_parents row.
fn insert_block_commit_parent(conn: &Connection, sortition_id: &str) {
    conn.execute(
        "INSERT INTO block_commit_parents (block_commit_txid, block_commit_sortition_id, \
             parent_sortition_id) VALUES (?1, ?2, 'parent_sort')",
        params![format!("bc_tx_{sortition_id}"), sortition_id],
    )
    .unwrap();
}

/// Insert a stack_stx row for the given burn_header_hash.
fn insert_stack_stx(conn: &Connection, burn_header_hash: &str, txid: &str) {
    conn.execute(
        "INSERT INTO stack_stx (txid, vtxindex, block_height, burn_header_hash, \
             sender_addr, reward_addr, stacked_ustx, num_cycles, signer_key, max_amount, auth_id) \
             VALUES (?1, 0, 1, ?2, 'sender', 'reward', '1000', 1, NULL, NULL, NULL)",
        params![txid, burn_header_hash],
    )
    .unwrap();
}

/// Insert an epochs row.
fn insert_epoch(conn: &Connection, start: u32, epoch_id: u32) {
    conn.execute(
        "INSERT INTO epochs (start_block_height, end_block_height, epoch_id, \
             block_limit, network_epoch) VALUES (?1, ?2, ?3, '{}', 1)",
        params![start, start + 100, epoch_id],
    )
    .unwrap();
}

/// Create a sortition dest DB simulating a squashed MARF with the given
/// canonical sortition IDs.
fn create_sortition_dest_db(path: &std::path::Path, canonical_sortition_ids: &[&str]) {
    let conn = Connection::open(path).unwrap();
    conn.execute_batch(
        "CREATE TABLE IF NOT EXISTS marf_squash_block_heights \
             (block_hash TEXT NOT NULL, height INTEGER NOT NULL)",
    )
    .unwrap();
    for (h, sid) in canonical_sortition_ids.iter().enumerate() {
        conn.execute(
            "INSERT INTO marf_squash_block_heights (block_hash, height) VALUES (?1, ?2)",
            params![sid, h as i64],
        )
        .unwrap();
    }
}

#[test]
fn test_sortition_copy_excludes_fork_data() {
    let dir = tempdir().unwrap();
    let src_path = dir.path().join("src_sort.sqlite");
    let conn = create_sortition_source_db(&src_path);

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
    insert_epoch(&conn, 0, 1);

    // Transition ops.
    conn.execute(
        "INSERT INTO snapshot_transition_ops (sortition_id, accepted_ops, consumed_keys) \
             VALUES ('sort_1', '[]', '[]')",
        [],
    )
    .unwrap();
    conn.execute(
        "INSERT INTO snapshot_transition_ops (sortition_id, accepted_ops, consumed_keys) \
             VALUES ('sort_1_fork', '[]', '[]')",
        [],
    )
    .unwrap();

    // Stacks chain tips.
    conn.execute(
        "INSERT INTO stacks_chain_tips (sortition_id, consensus_hash, block_hash, block_height) \
             VALUES ('sort_1', 'ch', 'bh', 1)",
        [],
    )
    .unwrap();
    conn.execute(
        "INSERT INTO stacks_chain_tips (sortition_id, consensus_hash, block_hash, block_height) \
             VALUES ('sort_1_fork', 'ch2', 'bh2', 1)",
        [],
    )
    .unwrap();

    // Missed commits.
    conn.execute(
        "INSERT INTO missed_commits (txid, input, intended_sortition_id) \
             VALUES ('mc_tx', 'input', 'sort_1')",
        [],
    )
    .unwrap();
    conn.execute(
        "INSERT INTO missed_commits (txid, input, intended_sortition_id) \
             VALUES ('mc_tx_fork', 'input', 'sort_1_fork')",
        [],
    )
    .unwrap();

    // Preprocessed reward sets.
    conn.execute(
        "INSERT INTO preprocessed_reward_sets (sortition_id, reward_set) \
             VALUES ('sort_1', '{}')",
        [],
    )
    .unwrap();
    conn.execute(
        "INSERT INTO preprocessed_reward_sets (sortition_id, reward_set) \
             VALUES ('sort_1_fork', '{}')",
        [],
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
    assert_eq!(stats.epochs_rows, 1, "epochs full copy");
    assert_eq!(stats.db_config_rows, 1, "db_config full copy");

    // Validate passes.
    let validation =
        validate_sortition_side_tables(src_path.to_str().unwrap(), dst_path.to_str().unwrap())
            .unwrap();
    assert!(
        validation.is_valid(),
        "validation should pass: {validation:?}"
    );
}

#[test]
fn test_sortition_validate_detects_payload_corruption() {
    let dir = tempdir().unwrap();
    let src_path = dir.path().join("src_sort.sqlite");
    let conn = create_sortition_source_db(&src_path);

    insert_snapshot(&conn, "sort_0", "bhh_0", 0);
    insert_epoch(&conn, 0, 1);
    drop(conn);

    let dst_path = dir.path().join("dst_sort.sqlite");
    create_sortition_dest_db(&dst_path, &["sort_0"]);

    let _stats =
        copy_sortition_side_tables(src_path.to_str().unwrap(), dst_path.to_str().unwrap()).unwrap();

    // Corrupt a non-key column in the destination snapshots table.
    {
        let conn = Connection::open(&dst_path).unwrap();
        conn.execute(
            "UPDATE snapshots SET burn_header_timestamp = 9999 WHERE sortition_id = 'sort_0'",
            [],
        )
        .unwrap();
    }

    let validation =
        validate_sortition_side_tables(src_path.to_str().unwrap(), dst_path.to_str().unwrap())
            .unwrap();

    assert!(
        !validation.snapshots_match,
        "payload corruption should be detected"
    );
    assert!(!validation.is_valid(), "validation must fail");
}

#[test]
fn test_sortition_validate_detects_extra_rows() {
    let dir = tempdir().unwrap();
    let src_path = dir.path().join("src_sort.sqlite");
    let conn = create_sortition_source_db(&src_path);

    insert_snapshot(&conn, "sort_0", "bhh_0", 0);
    insert_epoch(&conn, 0, 1);
    drop(conn);

    let dst_path = dir.path().join("dst_sort.sqlite");
    create_sortition_dest_db(&dst_path, &["sort_0"]);

    let _stats =
        copy_sortition_side_tables(src_path.to_str().unwrap(), dst_path.to_str().unwrap()).unwrap();

    // Inject an extra leader_keys row in destination that doesn't exist in source.
    {
        let conn = Connection::open(&dst_path).unwrap();
        conn.execute(
            "INSERT INTO leader_keys (txid, vtxindex, block_height, burn_header_hash, \
                 sortition_id, consensus_hash, public_key, memo) \
                 VALUES ('extra_tx', 0, 1, 'bhh', 'sort_0', 'ch', 'pk', 'memo')",
            [],
        )
        .unwrap();
    }

    let validation =
        validate_sortition_side_tables(src_path.to_str().unwrap(), dst_path.to_str().unwrap())
            .unwrap();

    assert!(
        !validation.leader_keys_match,
        "extra rows should be detected"
    );
    assert!(!validation.is_valid(), "validation must fail");
}

#[test]
fn test_sortition_burn_header_hash_filtering() {
    // Verify that burn_header_hash-keyed tables (stack_stx, transfer_stx, etc.)
    // correctly exclude rows associated with non-canonical burn hashes.
    let dir = tempdir().unwrap();
    let src_path = dir.path().join("src_sort.sqlite");
    let conn = create_sortition_source_db(&src_path);

    insert_snapshot(&conn, "sort_0", "bhh_canon", 0);
    insert_snapshot(&conn, "sort_0_fork", "bhh_fork", 0);

    // stack_stx at canonical and fork burn hashes.
    insert_stack_stx(&conn, "bhh_canon", "stx_canon");
    insert_stack_stx(&conn, "bhh_fork", "stx_fork");

    // transfer_stx at canonical and fork.
    conn.execute(
        "INSERT INTO transfer_stx (txid, vtxindex, block_height, burn_header_hash, \
             sender_addr, recipient_addr, transfered_ustx, memo) \
             VALUES ('xfer_canon', 0, 0, 'bhh_canon', 's', 'r', '100', 'x')",
        [],
    )
    .unwrap();
    conn.execute(
        "INSERT INTO transfer_stx (txid, vtxindex, block_height, burn_header_hash, \
             sender_addr, recipient_addr, transfered_ustx, memo) \
             VALUES ('xfer_fork', 0, 0, 'bhh_fork', 's', 'r', '100', 'x')",
        [],
    )
    .unwrap();

    insert_epoch(&conn, 0, 1);
    drop(conn);

    // Only sort_0 is canonical -> bhh_canon is the only canonical burn hash.
    let dst_path = dir.path().join("dst_sort.sqlite");
    create_sortition_dest_db(&dst_path, &["sort_0"]);

    let stats =
        copy_sortition_side_tables(src_path.to_str().unwrap(), dst_path.to_str().unwrap()).unwrap();

    assert_eq!(stats.stack_stx_rows, 1, "only bhh_canon stack_stx");
    assert_eq!(stats.transfer_stx_rows, 1, "only bhh_canon transfer_stx");

    let validation =
        validate_sortition_side_tables(src_path.to_str().unwrap(), dst_path.to_str().unwrap())
            .unwrap();
    assert!(
        validation.is_valid(),
        "should pass with canonical-only data: {validation:?}"
    );
}

#[test]
fn test_sortition_validate_detects_fabricated_canonical_set() {
    // Destination claims a sortition_id that doesn't exist in source snapshots.
    let dir = tempdir().unwrap();
    let src_path = dir.path().join("src_sort.sqlite");
    let conn = create_sortition_source_db(&src_path);

    insert_snapshot(&conn, "sort_0", "bhh_0", 0);
    insert_epoch(&conn, 0, 1);
    drop(conn);

    // Destination claims sort_0 AND sort_fake as canonical.
    let dst_path = dir.path().join("dst_sort.sqlite");
    create_sortition_dest_db(&dst_path, &["sort_0", "sort_fake"]);

    let _stats =
        copy_sortition_side_tables(src_path.to_str().unwrap(), dst_path.to_str().unwrap()).unwrap();

    let validation =
        validate_sortition_side_tables(src_path.to_str().unwrap(), dst_path.to_str().unwrap())
            .unwrap();

    assert!(
        !validation.canonical_set_in_source,
        "fabricated sortition_id should be detected"
    );
    assert!(!validation.is_valid(), "validation must fail");
}

#[test]
fn test_sortition_optional_table_asymmetry() {
    // Source has snapshot_burn_distributions but destination doesn't
    // (e.g., table was created in source but clone_optional_schemas
    // somehow didn't create it in destination). Validation should
    // report Some(false).
    let dir = tempdir().unwrap();
    let src_path = dir.path().join("src_sort.sqlite");
    let conn = create_sortition_source_db(&src_path);

    // Add the optional table to source.
    conn.execute_batch(
        "CREATE TABLE snapshot_burn_distributions (
                sortition_id TEXT PRIMARY KEY,
                data TEXT NOT NULL
            )",
    )
    .unwrap();
    conn.execute(
        "INSERT INTO snapshot_burn_distributions (sortition_id, data) \
             VALUES ('sort_0', 'dist_data')",
        [],
    )
    .unwrap();

    insert_snapshot(&conn, "sort_0", "bhh_0", 0);
    insert_epoch(&conn, 0, 1);
    drop(conn);

    let dst_path = dir.path().join("dst_sort.sqlite");
    create_sortition_dest_db(&dst_path, &["sort_0"]);

    // Do the copy - this should copy snapshot_burn_distributions.
    let _stats =
        copy_sortition_side_tables(src_path.to_str().unwrap(), dst_path.to_str().unwrap()).unwrap();

    // Validation should pass with the table present in both.
    let validation =
        validate_sortition_side_tables(src_path.to_str().unwrap(), dst_path.to_str().unwrap())
            .unwrap();
    assert_eq!(
        validation.snapshot_burn_distributions_match,
        Some(true),
        "should match when present in both"
    );
    assert!(validation.is_valid(), "should pass: {validation:?}");

    // Now drop the table from destination to simulate asymmetry.
    {
        let conn = Connection::open(&dst_path).unwrap();
        conn.execute_batch("DROP TABLE snapshot_burn_distributions")
            .unwrap();
    }

    let validation =
        validate_sortition_side_tables(src_path.to_str().unwrap(), dst_path.to_str().unwrap())
            .unwrap();
    assert_eq!(
        validation.snapshot_burn_distributions_match,
        Some(false),
        "should detect table present in source but not dest"
    );
    assert!(
        !validation.is_valid(),
        "asymmetric optional table must fail"
    );
}

#[test]
fn test_sortition_stacks_chain_tips_by_burn_view_copied() {
    let dir = tempdir().unwrap();
    let src_path = dir.path().join("src_sort.sqlite");
    let conn = create_sortition_source_db(&src_path);

    // Insert canonical snapshots.
    insert_snapshot(&conn, "sort_0", "bhh_0", 0);
    insert_snapshot(&conn, "sort_1", "bhh_1", 1);
    insert_epoch(&conn, 0, 2);

    // Insert stacks_chain_tips_by_burn_view rows (schema 11 table).
    // consensus_hash and burn_view_consensus_hash must reference
    // existing snapshots(consensus_hash) due to FK constraints.
    conn.execute(
        "INSERT INTO stacks_chain_tips_by_burn_view \
         (sortition_id, consensus_hash, burn_view_consensus_hash, block_hash, block_height) \
         VALUES ('sort_0', 'ch_sort_0', 'ch_sort_0', 'bh_0', 0)",
        [],
    )
    .unwrap();
    conn.execute(
        "INSERT INTO stacks_chain_tips_by_burn_view \
         (sortition_id, consensus_hash, burn_view_consensus_hash, block_hash, block_height) \
         VALUES ('sort_1', 'ch_sort_1', 'ch_sort_1', 'bh_1', 1)",
        [],
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

    // Verify the rows actually exist in the destination.
    let dst_conn = Connection::open(&dst_path).unwrap();
    let count: i64 = dst_conn
        .query_row(
            "SELECT COUNT(*) FROM stacks_chain_tips_by_burn_view",
            [],
            |row| row.get(0),
        )
        .unwrap();
    assert_eq!(count, 2);

    // Validation should pass.
    let validation =
        validate_sortition_side_tables(src_path.to_str().unwrap(), dst_path.to_str().unwrap())
            .unwrap();
    assert!(
        validation.is_valid(),
        "validation should pass: {validation:?}"
    );
}

#[test]
fn test_sortition_stacks_chain_tips_by_burn_view_detects_extra_row() {
    let dir = tempdir().unwrap();
    let src_path = dir.path().join("src_sort.sqlite");
    let conn = create_sortition_source_db(&src_path);

    insert_snapshot(&conn, "sort_0", "bhh_0", 0);
    insert_epoch(&conn, 0, 1);

    conn.execute(
        "INSERT INTO stacks_chain_tips_by_burn_view \
         (sortition_id, consensus_hash, burn_view_consensus_hash, block_hash, block_height) \
         VALUES ('sort_0', 'ch_sort_0', 'ch_sort_0', 'bh_0', 0)",
        [],
    )
    .unwrap();
    drop(conn);

    let dst_path = dir.path().join("dst_sort.sqlite");
    create_sortition_dest_db(&dst_path, &["sort_0"]);

    copy_sortition_side_tables(src_path.to_str().unwrap(), dst_path.to_str().unwrap()).unwrap();

    // Inject a non-canonical row directly into the destination.
    {
        let dst_conn = Connection::open(&dst_path).unwrap();
        dst_conn.execute_batch("PRAGMA foreign_keys = OFF").unwrap();
        dst_conn
            .execute(
                "INSERT INTO stacks_chain_tips_by_burn_view \
                 (sortition_id, consensus_hash, burn_view_consensus_hash, block_hash, block_height) \
                 VALUES ('rogue_sort', 'rogue_ch', 'rogue_bv', 'rogue_bh', 999)",
                [],
            )
            .unwrap();
    }

    let validation =
        validate_sortition_side_tables(src_path.to_str().unwrap(), dst_path.to_str().unwrap())
            .unwrap();
    assert!(
        !validation.stacks_chain_tips_by_burn_view_match,
        "extra non-canonical row should fail validation"
    );
    assert!(!validation.is_valid());
}

// -----------------------------------------------------------------------
// Block preservation tests
// -----------------------------------------------------------------------
