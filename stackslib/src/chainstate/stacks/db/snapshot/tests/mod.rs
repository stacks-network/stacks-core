use rusqlite::{params, Connection};
use tempfile::tempdir;

use super::index::{copy_index_side_tables, validate_index_side_tables};
use crate::burnchains::bitcoin::spv::{
    SPV_DB_VERSION, SPV_INITIAL_SCHEMA, SPV_SCHEMA_2, SPV_SCHEMA_3,
};
use crate::burnchains::db::{
    BURNCHAIN_DB_INDEXES, BURNCHAIN_DB_MIGRATION_V2_TO_V3, BURNCHAIN_DB_SCHEMA_2,
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

// -----------------------------------------------------------------------
// Burnchain auxiliary: burnchain.sqlite tests
// -----------------------------------------------------------------------

/// Create a v3 burnchain.sqlite source (no affirmation_maps).
/// Replays the real schema: SCHEMA_2 then MIGRATION_V2_TO_V3, plus indexes.
fn create_burnchain_db_v3(path: &std::path::Path) -> Connection {
    let conn = Connection::open(path).unwrap();
    conn.execute_batch(BURNCHAIN_DB_SCHEMA_2).unwrap();
    conn.execute("INSERT INTO db_config (version) VALUES ('2')", [])
        .unwrap();
    for idx in BURNCHAIN_DB_INDEXES {
        conn.execute_batch(idx).unwrap();
    }
    conn.execute_batch(BURNCHAIN_DB_MIGRATION_V2_TO_V3).unwrap();
    conn.execute("UPDATE db_config SET version = '3'", [])
        .unwrap();
    conn
}

/// Create a v2 burnchain.sqlite source (with affirmation_maps).
/// Uses the real v2 schema plus indexes; does NOT apply the v3 migration.
fn create_burnchain_db_v2(path: &std::path::Path) -> Connection {
    let conn = Connection::open(path).unwrap();
    conn.execute_batch(BURNCHAIN_DB_SCHEMA_2).unwrap();
    conn.execute("INSERT INTO db_config (version) VALUES ('2')", [])
        .unwrap();
    for idx in BURNCHAIN_DB_INDEXES {
        conn.execute_batch(idx).unwrap();
    }
    conn
}

/// Create a squashed sortition DB with canonical burn hashes in a
/// `snapshots` table.
fn create_squashed_sortition(
    path: &std::path::Path,
    canonical_hashes: &[(u32, &str)], // (block_height, burn_header_hash)
) -> Connection {
    let conn = Connection::open(path).unwrap();
    conn.execute_batch(
        "CREATE TABLE snapshots (
                block_height INTEGER NOT NULL,
                burn_header_hash TEXT NOT NULL
            )",
    )
    .unwrap();
    for (height, hash) in canonical_hashes {
        conn.execute(
            "INSERT INTO snapshots (block_height, burn_header_hash) VALUES (?1, ?2)",
            params![height, hash],
        )
        .unwrap();
    }
    conn
}

#[test]
fn test_burnchain_db_copy_and_validate() {
    let dir = tempdir().unwrap();
    let src_path = dir.path().join("src_burnchain.sqlite");
    let dst_path = dir.path().join("dst_burnchain.sqlite");
    let sort_path = dir.path().join("sortition.sqlite");

    // Canonical hashes at heights 0, 1, 2.
    let canonical = vec![(0, "hash_0"), (1, "hash_1"), (2, "hash_2")];
    create_squashed_sortition(&sort_path, &canonical);

    let src = create_burnchain_db_v3(&src_path);
    // Insert canonical block headers.
    for (h, hash) in &canonical {
        src.execute(
            "INSERT INTO burnchain_db_block_headers VALUES (?1, ?2, ?3, 0, 0)",
            params![h, hash, format!("parent_{hash}")],
        )
        .unwrap();
    }
    // Insert a non-canonical block at height 1.
    src.execute(
        "INSERT INTO burnchain_db_block_headers VALUES (1, 'fork_hash_1', 'parent_fork', 0, 0)",
        [],
    )
    .unwrap();
    // Ops for canonical and non-canonical.
    src.execute(
        "INSERT INTO burnchain_db_block_ops VALUES ('hash_1', 'op1', 'tx1')",
        [],
    )
    .unwrap();
    src.execute(
        "INSERT INTO burnchain_db_block_ops VALUES ('fork_hash_1', 'op_fork', 'tx_fork')",
        [],
    )
    .unwrap();
    // block_commit_metadata for canonical.
    src.execute(
            "INSERT INTO block_commit_metadata (burn_block_hash, txid, block_height, vtxindex, anchor_block, anchor_block_descendant) \
             VALUES ('hash_1', 'tx1', 1, 0, NULL, NULL)",
            [],
        )
        .unwrap();
    // block_commit_metadata for non-canonical.
    src.execute(
            "INSERT INTO block_commit_metadata (burn_block_hash, txid, block_height, vtxindex, anchor_block, anchor_block_descendant) \
             VALUES ('fork_hash_1', 'tx_fork', 1, 0, NULL, NULL)",
            [],
        )
        .unwrap();
    drop(src);

    let stats = super::burnchain::copy_burnchain_db(
        src_path.to_str().unwrap(),
        dst_path.to_str().unwrap(),
        sort_path.to_str().unwrap(),
        2,
    )
    .unwrap();

    assert_eq!(stats.block_headers_rows, 3); // 3 canonical
    assert_eq!(stats.block_ops_rows, 1); // only hash_1's op
    assert_eq!(stats.block_commit_metadata_rows, 1); // only canonical
    assert_eq!(stats.affirmation_maps_rows, 0); // v3

    let v = super::burnchain::validate_burnchain_db(
        src_path.to_str().unwrap(),
        dst_path.to_str().unwrap(),
        sort_path.to_str().unwrap(),
        2,
    )
    .unwrap();
    assert!(v.is_valid(), "validation failed: {v:?}");
}

#[test]
fn test_burnchain_db_excludes_non_canonical_fork() {
    let dir = tempdir().unwrap();
    let src_path = dir.path().join("src.sqlite");
    let dst_path = dir.path().join("dst.sqlite");
    let sort_path = dir.path().join("sort.sqlite");

    // Only hash_a is canonical at height 1.
    create_squashed_sortition(&sort_path, &[(0, "genesis"), (1, "hash_a")]);

    let src = create_burnchain_db_v3(&src_path);
    src.execute(
        "INSERT INTO burnchain_db_block_headers VALUES (0, 'genesis', 'none', 0, 0)",
        [],
    )
    .unwrap();
    src.execute(
        "INSERT INTO burnchain_db_block_headers VALUES (1, 'hash_a', 'genesis', 0, 0)",
        [],
    )
    .unwrap();
    src.execute(
        "INSERT INTO burnchain_db_block_headers VALUES (1, 'hash_b', 'genesis', 0, 0)",
        [],
    )
    .unwrap();
    drop(src);

    let stats = super::burnchain::copy_burnchain_db(
        src_path.to_str().unwrap(),
        dst_path.to_str().unwrap(),
        sort_path.to_str().unwrap(),
        1,
    )
    .unwrap();

    assert_eq!(stats.block_headers_rows, 2); // genesis + hash_a, not hash_b

    // Verify hash_b is not in destination.
    let dst = Connection::open(&dst_path).unwrap();
    let count: i64 = dst
        .query_row(
            "SELECT COUNT(*) FROM burnchain_db_block_headers WHERE block_hash = 'hash_b'",
            [],
            |r| r.get(0),
        )
        .unwrap();
    assert_eq!(count, 0);
}

#[test]
fn test_burnchain_db_block_ops_follow_canonical_headers() {
    let dir = tempdir().unwrap();
    let src_path = dir.path().join("src.sqlite");
    let dst_path = dir.path().join("dst.sqlite");
    let sort_path = dir.path().join("sort.sqlite");

    create_squashed_sortition(&sort_path, &[(0, "canon")]);

    let src = create_burnchain_db_v3(&src_path);
    src.execute(
        "INSERT INTO burnchain_db_block_headers VALUES (0, 'canon', 'none', 0, 0)",
        [],
    )
    .unwrap();
    src.execute(
        "INSERT INTO burnchain_db_block_headers VALUES (0, 'fork', 'none', 0, 0)",
        [],
    )
    .unwrap();
    src.execute(
        "INSERT INTO burnchain_db_block_ops VALUES ('canon', 'op_c', 'tx_c')",
        [],
    )
    .unwrap();
    src.execute(
        "INSERT INTO burnchain_db_block_ops VALUES ('fork', 'op_f', 'tx_f')",
        [],
    )
    .unwrap();
    drop(src);

    let stats = super::burnchain::copy_burnchain_db(
        src_path.to_str().unwrap(),
        dst_path.to_str().unwrap(),
        sort_path.to_str().unwrap(),
        0,
    )
    .unwrap();

    assert_eq!(stats.block_ops_rows, 1);

    let dst = Connection::open(&dst_path).unwrap();
    let op: String = dst
        .query_row("SELECT op FROM burnchain_db_block_ops", [], |r| r.get(0))
        .unwrap();
    assert_eq!(op, "op_c");
}

#[test]
fn test_burnchain_db_anchor_blocks_filtered() {
    let dir = tempdir().unwrap();
    let src_path = dir.path().join("src.sqlite");
    let dst_path = dir.path().join("dst.sqlite");
    let sort_path = dir.path().join("sort.sqlite");

    create_squashed_sortition(&sort_path, &[(0, "h0"), (1, "h1")]);

    let src = create_burnchain_db_v3(&src_path);
    src.execute(
        "INSERT INTO burnchain_db_block_headers VALUES (0, 'h0', 'none', 0, 0)",
        [],
    )
    .unwrap();
    src.execute(
        "INSERT INTO burnchain_db_block_headers VALUES (1, 'h1', 'h0', 0, 0)",
        [],
    )
    .unwrap();
    // Anchor block for cycle 1 (referenced by canonical commit).
    src.execute("INSERT INTO anchor_blocks VALUES (1)", [])
        .unwrap();
    // Anchor block for cycle 99 (not referenced by any canonical commit).
    src.execute("INSERT INTO anchor_blocks VALUES (99)", [])
        .unwrap();
    // Canonical commit referencing anchor block cycle 1.
    src.execute(
            "INSERT INTO block_commit_metadata (burn_block_hash, txid, block_height, vtxindex, anchor_block, anchor_block_descendant) \
             VALUES ('h1', 'tx_a', 1, 0, 1, NULL)",
            [],
        )
        .unwrap();
    // Override for cycle 1 (should be copied) and cycle 99 (should not).
    src.execute("INSERT INTO overrides VALUES (1, 'map_1')", [])
        .unwrap();
    src.execute("INSERT INTO overrides VALUES (99, 'map_99')", [])
        .unwrap();
    drop(src);

    let stats = super::burnchain::copy_burnchain_db(
        src_path.to_str().unwrap(),
        dst_path.to_str().unwrap(),
        sort_path.to_str().unwrap(),
        1,
    )
    .unwrap();

    assert_eq!(stats.anchor_blocks_rows, 1);
    assert_eq!(stats.overrides_rows, 1);

    let dst = Connection::open(&dst_path).unwrap();
    let cycle: i64 = dst
        .query_row("SELECT reward_cycle FROM anchor_blocks", [], |r| r.get(0))
        .unwrap();
    assert_eq!(cycle, 1);
    let override_map: String = dst
        .query_row("SELECT affirmation_map FROM overrides", [], |r| r.get(0))
        .unwrap();
    assert_eq!(override_map, "map_1");
}

#[test]
fn test_burnchain_db_validate_detects_non_canonical_leak() {
    let dir = tempdir().unwrap();
    let src_path = dir.path().join("src.sqlite");
    let dst_path = dir.path().join("dst.sqlite");
    let sort_path = dir.path().join("sort.sqlite");

    create_squashed_sortition(&sort_path, &[(0, "h0")]);

    let src = create_burnchain_db_v3(&src_path);
    src.execute(
        "INSERT INTO burnchain_db_block_headers VALUES (0, 'h0', 'none', 0, 0)",
        [],
    )
    .unwrap();
    drop(src);

    // Copy normally first.
    super::burnchain::copy_burnchain_db(
        src_path.to_str().unwrap(),
        dst_path.to_str().unwrap(),
        sort_path.to_str().unwrap(),
        0,
    )
    .unwrap();

    // Inject a non-canonical row into the destination.
    let dst = Connection::open(&dst_path).unwrap();
    dst.execute(
        "INSERT INTO burnchain_db_block_headers VALUES (0, 'rogue', 'none', 0, 0)",
        [],
    )
    .unwrap();
    drop(dst);

    let v = super::burnchain::validate_burnchain_db(
        src_path.to_str().unwrap(),
        dst_path.to_str().unwrap(),
        sort_path.to_str().unwrap(),
        0,
    )
    .unwrap();
    assert!(!v.is_valid(), "should detect non-canonical leak");
    assert!(!v.no_extra_headers);
}

#[test]
fn test_burnchain_db_missing_source_is_error() {
    let dir = tempdir().unwrap();
    let src_path = dir.path().join("nonexistent.sqlite");
    let dst_path = dir.path().join("dst.sqlite");
    let sort_path = dir.path().join("sort.sqlite");

    create_squashed_sortition(&sort_path, &[(0, "h0")]);

    let result = super::burnchain::copy_burnchain_db(
        src_path.to_str().unwrap(),
        dst_path.to_str().unwrap(),
        sort_path.to_str().unwrap(),
        0,
    );
    // Should error because the source file does not exist.
    assert!(result.is_err());
}

#[test]
fn test_burnchain_db_affirmation_maps_preserved_v2() {
    let dir = tempdir().unwrap();
    let src_path = dir.path().join("src.sqlite");
    let dst_path = dir.path().join("dst.sqlite");
    let sort_path = dir.path().join("sort.sqlite");

    create_squashed_sortition(&sort_path, &[(0, "h0"), (1, "h1")]);

    let src = create_burnchain_db_v2(&src_path);
    src.execute(
        "INSERT INTO burnchain_db_block_headers VALUES (0, 'h0', 'none', 0, 0)",
        [],
    )
    .unwrap();
    src.execute(
        "INSERT INTO burnchain_db_block_headers VALUES (1, 'h1', 'h0', 0, 0)",
        [],
    )
    .unwrap();
    // Affirmation map id=1 (id=0 already inserted by schema).
    src.execute(
        "INSERT INTO affirmation_maps (affirmation_id, weight, affirmation_map) VALUES (1, 1, 'p')",
        [],
    )
    .unwrap();
    // Affirmation map id=2 (not referenced by any canonical commit).
    src.execute(
            "INSERT INTO affirmation_maps (affirmation_id, weight, affirmation_map) VALUES (2, 2, 'pp')",
            [],
        )
        .unwrap();
    // Canonical commit referencing affirmation_id=1.
    src.execute(
            "INSERT INTO block_commit_metadata (burn_block_hash, txid, block_height, vtxindex, affirmation_id, anchor_block, anchor_block_descendant) \
             VALUES ('h1', 'tx1', 1, 0, 1, NULL, NULL)",
            [],
        )
        .unwrap();
    drop(src);

    let stats = super::burnchain::copy_burnchain_db(
        src_path.to_str().unwrap(),
        dst_path.to_str().unwrap(),
        sort_path.to_str().unwrap(),
        1,
    )
    .unwrap();

    // Only affirmation_id=1 referenced by canonical commit.
    assert_eq!(stats.affirmation_maps_rows, 1);

    let v = super::burnchain::validate_burnchain_db(
        src_path.to_str().unwrap(),
        dst_path.to_str().unwrap(),
        sort_path.to_str().unwrap(),
        1,
    )
    .unwrap();
    assert!(v.is_valid(), "v2 validation failed: {v:?}");
    assert!(v.affirmation_maps_match);
}

#[test]
fn test_burnchain_db_v3_no_affirmation_maps() {
    let dir = tempdir().unwrap();
    let src_path = dir.path().join("src.sqlite");
    let dst_path = dir.path().join("dst.sqlite");
    let sort_path = dir.path().join("sort.sqlite");

    create_squashed_sortition(&sort_path, &[(0, "h0")]);

    let src = create_burnchain_db_v3(&src_path);
    src.execute(
        "INSERT INTO burnchain_db_block_headers VALUES (0, 'h0', 'none', 0, 0)",
        [],
    )
    .unwrap();
    drop(src);

    let stats = super::burnchain::copy_burnchain_db(
        src_path.to_str().unwrap(),
        dst_path.to_str().unwrap(),
        sort_path.to_str().unwrap(),
        0,
    )
    .unwrap();

    assert_eq!(stats.affirmation_maps_rows, 0);

    let v = super::burnchain::validate_burnchain_db(
        src_path.to_str().unwrap(),
        dst_path.to_str().unwrap(),
        sort_path.to_str().unwrap(),
        0,
    )
    .unwrap();
    assert!(v.is_valid(), "v3 validation failed: {v:?}");
    assert!(v.affirmation_maps_match); // both absent = true
}

#[test]
fn test_burnchain_db_sortition_tip_mismatch_is_error() {
    let dir = tempdir().unwrap();
    let src_path = dir.path().join("src.sqlite");
    let dst_path = dir.path().join("dst.sqlite");
    let sort_path = dir.path().join("sort.sqlite");

    // Sortition tip is at height 5.
    create_squashed_sortition(&sort_path, &[(0, "h0"), (5, "h5")]);

    let src = create_burnchain_db_v3(&src_path);
    src.execute(
        "INSERT INTO burnchain_db_block_headers VALUES (0, 'h0', 'none', 0, 0)",
        [],
    )
    .unwrap();
    drop(src);

    // Pass expected_burn_height=10, but sortition tip is 5.
    let result = super::burnchain::copy_burnchain_db(
        src_path.to_str().unwrap(),
        dst_path.to_str().unwrap(),
        sort_path.to_str().unwrap(),
        10,
    );
    assert!(result.is_err(), "should fail on sortition tip mismatch");
}

#[test]
fn test_burnchain_db_fresh_output_dir() {
    let dir = tempdir().unwrap();
    let src_path = dir.path().join("src.sqlite");
    let sort_path = dir.path().join("sort.sqlite");
    // Nested non-existent directory.
    let dst_path = dir
        .path()
        .join("deep")
        .join("nested")
        .join("burnchain.sqlite");

    create_squashed_sortition(&sort_path, &[(0, "h0")]);

    let src = create_burnchain_db_v3(&src_path);
    src.execute(
        "INSERT INTO burnchain_db_block_headers VALUES (0, 'h0', 'none', 0, 0)",
        [],
    )
    .unwrap();
    drop(src);

    let stats = super::burnchain::copy_burnchain_db(
        src_path.to_str().unwrap(),
        dst_path.to_str().unwrap(),
        sort_path.to_str().unwrap(),
        0,
    )
    .unwrap();

    assert_eq!(stats.block_headers_rows, 1);
    assert!(dst_path.exists());
}

#[test]
fn test_burnchain_db_copy_fails_when_source_missing_canonical_hash() {
    let dir = tempdir().unwrap();
    let src_path = dir.path().join("src.sqlite");
    let dst_path = dir.path().join("dst.sqlite");
    let sort_path = dir.path().join("sort.sqlite");

    // Sortition says heights 0, 1, 2 are canonical.
    create_squashed_sortition(&sort_path, &[(0, "h0"), (1, "h1"), (2, "h2")]);

    // But source burnchain.sqlite only has h0 and h1 - h2 is missing.
    let src = create_burnchain_db_v3(&src_path);
    src.execute(
        "INSERT INTO burnchain_db_block_headers VALUES (0, 'h0', 'none', 0, 0)",
        [],
    )
    .unwrap();
    src.execute(
        "INSERT INTO burnchain_db_block_headers VALUES (1, 'h1', 'h0', 0, 0)",
        [],
    )
    .unwrap();
    drop(src);

    let result = super::burnchain::copy_burnchain_db(
        src_path.to_str().unwrap(),
        dst_path.to_str().unwrap(),
        sort_path.to_str().unwrap(),
        2,
    );
    assert!(
        result.is_err(),
        "should fail when source is missing a canonical burn hash"
    );
}

#[test]
fn test_burnchain_db_validate_detects_missing_canonical_hash() {
    let dir = tempdir().unwrap();
    let src_path = dir.path().join("src.sqlite");
    let dst_path = dir.path().join("dst.sqlite");
    let sort_path = dir.path().join("sort.sqlite");

    create_squashed_sortition(&sort_path, &[(0, "h0"), (1, "h1")]);

    let src = create_burnchain_db_v3(&src_path);
    src.execute(
        "INSERT INTO burnchain_db_block_headers VALUES (0, 'h0', 'none', 0, 0)",
        [],
    )
    .unwrap();
    src.execute(
        "INSERT INTO burnchain_db_block_headers VALUES (1, 'h1', 'h0', 0, 0)",
        [],
    )
    .unwrap();
    drop(src);

    // Copy normally (source has all canonical hashes).
    super::burnchain::copy_burnchain_db(
        src_path.to_str().unwrap(),
        dst_path.to_str().unwrap(),
        sort_path.to_str().unwrap(),
        1,
    )
    .unwrap();

    // Now delete h1 from the destination to simulate incomplete copy.
    let dst = Connection::open(&dst_path).unwrap();
    dst.execute(
        "DELETE FROM burnchain_db_block_headers WHERE block_hash = 'h1'",
        [],
    )
    .unwrap();
    drop(dst);

    let v = super::burnchain::validate_burnchain_db(
        src_path.to_str().unwrap(),
        dst_path.to_str().unwrap(),
        sort_path.to_str().unwrap(),
        1,
    )
    .unwrap();
    assert!(!v.is_valid(), "should detect missing canonical hash: {v:?}");
    assert!(!v.canonical_complete);
}

#[test]
fn test_burnchain_db_missing_source_does_not_create_file() {
    let dir = tempdir().unwrap();
    let src_path = dir.path().join("nonexistent_burnchain.sqlite");
    let dst_path = dir.path().join("dst.sqlite");
    let sort_path = dir.path().join("sort.sqlite");

    create_squashed_sortition(&sort_path, &[(0, "h0")]);

    assert!(!src_path.exists());

    let result = super::burnchain::copy_burnchain_db(
        src_path.to_str().unwrap(),
        dst_path.to_str().unwrap(),
        sort_path.to_str().unwrap(),
        0,
    );
    assert!(result.is_err());
    // Source path must not have been created by ATTACH.
    assert!(
        !src_path.exists(),
        "missing source must not be created by ATTACH"
    );
}

#[test]
fn test_burnchain_db_reused_output_dir() {
    let dir = tempdir().unwrap();
    let src_path = dir.path().join("src.sqlite");
    let dst_path = dir.path().join("dst.sqlite");
    let sort_path = dir.path().join("sort.sqlite");

    create_squashed_sortition(&sort_path, &[(0, "h0"), (1, "h1")]);

    let src = create_burnchain_db_v3(&src_path);
    src.execute(
        "INSERT INTO burnchain_db_block_headers VALUES (0, 'h0', 'none', 0, 0)",
        [],
    )
    .unwrap();
    src.execute(
        "INSERT INTO burnchain_db_block_headers VALUES (1, 'h1', 'h0', 0, 0)",
        [],
    )
    .unwrap();
    drop(src);

    // First copy.
    super::burnchain::copy_burnchain_db(
        src_path.to_str().unwrap(),
        dst_path.to_str().unwrap(),
        sort_path.to_str().unwrap(),
        1,
    )
    .unwrap();

    // Second copy into the same destination (reused output dir).
    let stats = super::burnchain::copy_burnchain_db(
        src_path.to_str().unwrap(),
        dst_path.to_str().unwrap(),
        sort_path.to_str().unwrap(),
        1,
    )
    .unwrap();

    assert_eq!(stats.block_headers_rows, 2);

    // Validate to confirm no duplicate rows.
    let v = super::burnchain::validate_burnchain_db(
        src_path.to_str().unwrap(),
        dst_path.to_str().unwrap(),
        sort_path.to_str().unwrap(),
        1,
    )
    .unwrap();
    assert!(
        v.is_valid(),
        "reused output dir should produce valid copy: {v:?}"
    );
}
