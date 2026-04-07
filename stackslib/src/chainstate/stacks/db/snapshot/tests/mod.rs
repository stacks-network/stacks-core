use rusqlite::{params, Connection};
use stacks_common::codec::StacksMessageCodec;
use stacks_common::types::chainstate::{BlockHeaderHash, ConsensusHash, StacksBlockId};
use stacks_common::util::hash::Sha512Trunc256Sum;
use stacks_common::util::secp256k1::MessageSignature;
use tempfile::tempdir;

use super::index::{copy_index_side_tables, validate_index_side_tables};
use crate::burnchains::bitcoin::spv::{
    SPV_DB_VERSION, SPV_INITIAL_SCHEMA, SPV_SCHEMA_2, SPV_SCHEMA_3,
};
use crate::chainstate::nakamoto::staging_blocks::{
    NAKAMOTO_STAGING_DB_SCHEMA_1, NAKAMOTO_STAGING_DB_SCHEMA_2, NAKAMOTO_STAGING_DB_SCHEMA_3,
    NAKAMOTO_STAGING_DB_SCHEMA_4, NAKAMOTO_STAGING_DB_SCHEMA_5,
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
use crate::chainstate::stacks::index::Error;
use crate::chainstate::stacks::{
    StacksMicroblock, StacksMicroblockHeader, StacksTransaction, TokenTransferMemo,
    TransactionAuth, TransactionPayload, TransactionSpendingCondition, TransactionVersion,
};
use crate::core::EMPTY_MICROBLOCK_PARENT_HASH;

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
            .unwrap();

    assert_eq!(stats.headers_rows, 4033);
    // (2+1)*2016-1 = 6047 <= 4032 ✗ -> still only 2 intervals.
    assert_eq!(stats.chain_work_rows, 2);
}

#[test]
fn test_spv_headers_missing_source_is_error() {
    let dir = tempdir().unwrap();
    let src_path = dir.path().join("nonexistent.sqlite");
    let dst_path = dir.path().join("dst.sqlite");

    let result =
        super::spv::copy_spv_headers(src_path.to_str().unwrap(), dst_path.to_str().unwrap(), 100);
    assert!(result.is_err(), "missing source should error");
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
fn test_spv_headers_validate_both_absent_is_error() {
    let dir = tempdir().unwrap();
    let src_path = dir.path().join("no_src.sqlite");
    let dst_path = dir.path().join("no_dst.sqlite");

    let result = super::spv::validate_spv_headers(
        src_path.to_str().unwrap(),
        dst_path.to_str().unwrap(),
        100,
    );
    assert!(result.is_err(), "both absent should error");
}



#[test]
fn test_spv_headers_stale_destination_errors_when_source_absent() {
    let dir = tempdir().unwrap();
    let src_path = dir.path().join("nonexistent.sqlite");
    let dst_path = dir.path().join("stale_headers.sqlite");

    // Create a stale destination file (simulates reused output dir).
    std::fs::write(&dst_path, b"stale data").unwrap();
    assert!(dst_path.exists());

    let result =
        super::spv::copy_spv_headers(src_path.to_str().unwrap(), dst_path.to_str().unwrap(), 100);
    assert!(
        result.is_err(),
        "missing source should error even with stale destination"
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
        .unwrap();

    // Second copy into the same destination (reused output dir).
    let stats =
        super::spv::copy_spv_headers(src_path.to_str().unwrap(), dst_path.to_str().unwrap(), 10)
            .unwrap();

    assert_eq!(stats.headers_rows, 11);

    // Validate to confirm no duplicate rows.
    let v = super::spv::validate_spv_headers(
        src_path.to_str().unwrap(),
        dst_path.to_str().unwrap(),
        10,
    )
    .unwrap();
    assert!(
        v.is_valid(),
        "reused output dir should produce valid copy: {v:?}"
    );
}

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
            format!("ibh{suffix}"),
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
                "SELECT download_time, arrival_time, processed_time FROM staging_blocks WHERE index_block_hash = 'ibh1'",
                [],
                |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)),
            )
            .unwrap();
    assert_eq!(download_time, 100);
    assert_eq!(arrival_time, 200);
    assert_eq!(processed_time, 300);

    // ibh3 should NOT be present.
    let count: i64 = dst_conn
        .query_row(
            "SELECT COUNT(*) FROM staging_blocks WHERE index_block_hash = 'ibh3'",
            [],
            |row| row.get(0),
        )
        .unwrap();
    assert_eq!(count, 0);
}

#[test]
fn test_staging_blocks_validation_detects_drift() {
    let dir = tempdir().unwrap();
    let src_path = dir.path().join("src.sqlite");
    let conn = create_source_db(&src_path);

    insert_block_header(&conn, 1, "1");
    insert_staging_block(&conn, "1", 1);
    drop(conn);

    let dst_path = dir.path().join("dst.sqlite");
    create_dest_db_with_canonical_blocks(&dst_path, &["ibh1"]);

    copy_index_side_tables(src_path.to_str().unwrap(), dst_path.to_str().unwrap(), 0, 1).unwrap();

    // Validation should pass initially.
    let v =
        validate_index_side_tables(src_path.to_str().unwrap(), dst_path.to_str().unwrap(), 0, 1)
            .unwrap();
    assert!(v.staging_blocks_match);

    // Now corrupt a column in destination staging_blocks.
    let dst_conn = Connection::open(&dst_path).unwrap();
    dst_conn
            .execute(
                "UPDATE staging_blocks SET parent_consensus_hash = 'corrupted' WHERE index_block_hash = 'ibh1'",
                [],
            )
            .unwrap();
    drop(dst_conn);

    // Validation should now fail.
    let v =
        validate_index_side_tables(src_path.to_str().unwrap(), dst_path.to_str().unwrap(), 0, 1)
            .unwrap();
    assert!(!v.staging_blocks_match, "should detect column drift: {v:?}");
}

#[test]
fn test_epoch2_block_file_copy_and_validate() {
    let dir = tempdir().unwrap();
    let src_blocks_dir = dir.path().join("src_blocks");
    let dst_blocks_dir = dir.path().join("dst_blocks");

    // Create a squashed index.sqlite with 2 block headers (height 0 = genesis, height 1).
    let idx_path = dir.path().join("squashed_index.sqlite");
    let conn = Connection::open(&idx_path).unwrap();
    conn.execute_batch(
            "CREATE TABLE block_headers (index_block_hash TEXT NOT NULL, block_height INTEGER NOT NULL)",
        )
        .unwrap();
    conn.execute(
            "INSERT INTO block_headers VALUES ('0000000000000000000000000000000000000000000000000000000000000000', 0)",
            [],
        )
        .unwrap();
    // Height 1 block: hex hash that maps to a known path.
    let hash_hex = "aabbccdd00000000000000000000000000000000000000000000000000000001";
    conn.execute(
        "INSERT INTO block_headers VALUES (?1, 1)",
        params![hash_hex],
    )
    .unwrap();
    drop(conn);

    // Create source block file for height 1.
    // index_block_hash_to_rel_path uses 2-byte (4 hex char) directory segments.
    let rel = format!("aabb/ccdd/{hash_hex}");
    let src_file = src_blocks_dir.join(&rel);
    std::fs::create_dir_all(src_file.parent().unwrap()).unwrap();
    std::fs::write(&src_file, b"block data here").unwrap();

    // Copy.
    let stats = super::blocks::copy_epoch2_block_files(
        idx_path.to_str().unwrap(),
        src_blocks_dir.to_str().unwrap(),
        dst_blocks_dir.to_str().unwrap(),
    )
    .unwrap();

    assert_eq!(stats.files_copied, 1);
    assert_eq!(stats.genesis_skipped, 1);
    assert_eq!(stats.total_bytes, 15); // "block data here".len()

    // Destination file exists and matches.
    let dst_file = dst_blocks_dir.join(&rel);
    assert!(dst_file.exists());
    assert_eq!(std::fs::read(&dst_file).unwrap(), b"block data here");

    // Validate.
    let v = super::blocks::validate_epoch2_block_files(
        idx_path.to_str().unwrap(),
        src_blocks_dir.to_str().unwrap(),
        dst_blocks_dir.to_str().unwrap(),
    )
    .unwrap();
    assert!(v.is_valid(), "validation should pass: {v:?}");
}

#[test]
fn test_epoch2_block_file_missing_source_is_error() {
    let dir = tempdir().unwrap();
    let src_blocks_dir = dir.path().join("src_blocks");
    let dst_blocks_dir = dir.path().join("dst_blocks");

    // Index with height-1 block but NO source file.
    let idx_path = dir.path().join("squashed_index.sqlite");
    let conn = Connection::open(&idx_path).unwrap();
    conn.execute_batch(
            "CREATE TABLE block_headers (index_block_hash TEXT NOT NULL, block_height INTEGER NOT NULL)",
        )
        .unwrap();
    let hash_hex = "aabbccdd00000000000000000000000000000000000000000000000000000001";
    conn.execute(
        "INSERT INTO block_headers VALUES (?1, 1)",
        params![hash_hex],
    )
    .unwrap();
    drop(conn);

    std::fs::create_dir_all(&src_blocks_dir).unwrap();

    let err = super::blocks::copy_epoch2_block_files(
        idx_path.to_str().unwrap(),
        src_blocks_dir.to_str().unwrap(),
        dst_blocks_dir.to_str().unwrap(),
    )
    .expect_err("copy should fail when a required source epoch-2 block file is missing");

    match err {
        Error::CorruptionError(msg) => {
            assert!(
                msg.contains("Missing source epoch-2 block file"),
                "unexpected error message: {msg}"
            );
        }
        other => panic!("unexpected error type: {other:?}"),
    }
}

/// Build a minimal serializable StacksMicroblock with the given sequence
/// and prev_block, returning (block_hash, serialized_bytes).
fn make_test_microblock(sequence: u16, prev_block: &BlockHeaderHash) -> (BlockHeaderHash, Vec<u8>) {
    use stacks_common::types::chainstate::StacksAddress;
    use stacks_common::util::hash::Hash160;
    use stacks_common::util::secp256k1::{Secp256k1PrivateKey, Secp256k1PublicKey};

    // Create a minimal STX transfer transaction.
    let privk = Secp256k1PrivateKey::from_hex(
        "6d430bb91222408e7706c9001cfaeb91b08c2be6d5ac95779ab52c6b431950e001",
    )
    .unwrap();
    let auth = TransactionAuth::Standard(
        TransactionSpendingCondition::new_singlesig_p2pkh(Secp256k1PublicKey::from_private(&privk))
            .unwrap(),
    );
    let recipient = StacksAddress::new(1, Hash160([0xAA; 20])).unwrap().into();
    let tx = StacksTransaction::new(
        TransactionVersion::Testnet,
        auth,
        TransactionPayload::TokenTransfer(recipient, 1, TokenTransferMemo([0u8; 34])),
    );

    // Use StacksMicroblock::first_unsigned for sequence 0,
    // or build with from_parent_unsigned for others.
    let txid_bytes = tx.txid().as_bytes().to_vec();
    let merkle_tree =
        stacks_common::util::hash::MerkleTree::<Sha512Trunc256Sum>::new(&[txid_bytes]);
    let tx_merkle_root = merkle_tree.root();

    let header = StacksMicroblockHeader {
        version: 0,
        sequence,
        prev_block: prev_block.clone(),
        tx_merkle_root,
        signature: MessageSignature::empty(),
    };

    let mblock = StacksMicroblock {
        header,
        txs: vec![tx],
    };
    let hash = mblock.block_hash();
    let mut bytes = vec![];
    mblock.consensus_serialize(&mut bytes).unwrap();
    (hash, bytes)
}

/// Insert a staging_microblocks row into the given connection.
fn insert_staging_microblock(
    conn: &Connection,
    anchored_block_hash: &str,
    consensus_hash: &ConsensusHash,
    index_block_hash: &StacksBlockId,
    microblock_hash: &BlockHeaderHash,
    parent_hash: &BlockHeaderHash,
    index_microblock_hash: &StacksBlockId,
    sequence: u16,
    processed: i32,
    orphaned: i32,
) {
    conn.execute(
        "INSERT INTO staging_microblocks \
             (anchored_block_hash, consensus_hash, index_block_hash, microblock_hash, \
              parent_hash, index_microblock_hash, sequence, processed, orphaned) \
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9)",
        params![
            anchored_block_hash,
            consensus_hash,
            index_block_hash,
            microblock_hash,
            parent_hash,
            index_microblock_hash,
            sequence as i32,
            processed,
            orphaned,
        ],
    )
    .unwrap();
}

/// Insert a staging_microblocks_data row.
fn insert_staging_microblock_data(
    conn: &Connection,
    block_hash: &BlockHeaderHash,
    block_data: &[u8],
) {
    conn.execute(
        "INSERT INTO staging_microblocks_data (block_hash, block_data) VALUES (?1, ?2)",
        params![block_hash, block_data],
    )
    .unwrap();
}

/// Insert a staging_blocks row with microblock parent linkage.
fn insert_staging_block_with_microblock_parent(
    conn: &Connection,
    anchored_block_hash: &str,
    consensus_hash: &str,
    parent_consensus_hash: &str,
    parent_anchored_block_hash: &str,
    parent_microblock_hash: &str,
    parent_microblock_seq: i32,
    index_block_hash: &str,
    height: i32,
) {
    conn.execute(
        "INSERT INTO staging_blocks \
             (anchored_block_hash, parent_anchored_block_hash, consensus_hash, \
              parent_consensus_hash, parent_microblock_hash, parent_microblock_seq, \
              microblock_pubkey_hash, height, attachable, orphaned, processed, \
              commit_burn, sortition_burn, index_block_hash, \
              download_time, arrival_time, processed_time) \
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, 'mph', ?7, 1, 0, 1, 0, 0, ?8, 0, 0, 0)",
        params![
            anchored_block_hash,
            parent_anchored_block_hash,
            consensus_hash,
            parent_consensus_hash,
            parent_microblock_hash,
            parent_microblock_seq,
            height,
            index_block_hash,
        ],
    )
    .unwrap();
}

/// Create a source nakamoto.sqlite with the full schema (v1 through v5).
fn create_source_nakamoto_db(path: &std::path::Path) -> Connection {
    let conn = Connection::open(path).unwrap();
    for cmd in NAKAMOTO_STAGING_DB_SCHEMA_1 {
        conn.execute_batch(cmd).unwrap();
    }
    for cmd in NAKAMOTO_STAGING_DB_SCHEMA_2 {
        conn.execute_batch(cmd).unwrap();
    }
    for cmd in NAKAMOTO_STAGING_DB_SCHEMA_3 {
        conn.execute_batch(cmd).unwrap();
    }
    for cmd in NAKAMOTO_STAGING_DB_SCHEMA_4 {
        conn.execute_batch(cmd).unwrap();
    }
    for cmd in NAKAMOTO_STAGING_DB_SCHEMA_5 {
        conn.execute_batch(cmd).unwrap();
    }
    conn
}

/// Insert a nakamoto_staging_blocks row.
fn insert_nakamoto_staging_block(
    conn: &Connection,
    block_hash: &str,
    consensus_hash: &str,
    parent_block_id: &str,
    height: i64,
    index_block_hash: &str,
    obtain_method: &str,
    data: &[u8],
) {
    conn.execute(
        "INSERT INTO nakamoto_staging_blocks \
             (block_hash, consensus_hash, parent_block_id, is_tenure_start, \
              burn_attachable, processed, orphaned, height, index_block_hash, \
              processed_time, obtain_method, signing_weight, data) \
             VALUES (?1, ?2, ?3, 1, 1, 1, 0, ?4, ?5, 0, ?6, 100, ?7)",
        params![
            block_hash,
            consensus_hash,
            parent_block_id,
            height,
            index_block_hash,
            obtain_method,
            data,
        ],
    )
    .unwrap();
}

#[test]
fn test_microblock_stream_copy_and_validate() {
    let dir = tempdir().unwrap();
    let src_path = dir.path().join("src_index.sqlite");
    let dst_path = dir.path().join("dst_index.sqlite");

    // Create source DB with full schema.
    let src_conn = create_source_db(&src_path);

    // Set up a parent anchored block "parent_bh" with consensus_hash "parent_ch".
    let parent_ch = ConsensusHash([0xAA; 20]);
    let parent_bh = BlockHeaderHash([0xBB; 32]);
    let parent_ibh = StacksBlockId::new(&parent_ch, &parent_bh);

    // Build a 2-microblock stream: mblock0 (seq=0, prev=parent_bh) -> mblock1 (seq=1, prev=mblock0_hash).
    let (mblock0_hash, mblock0_data) = make_test_microblock(0, &parent_bh);
    let (mblock1_hash, mblock1_data) = make_test_microblock(1, &mblock0_hash);

    // Insert microblock metadata and data into source.
    let imh0 = StacksBlockId::new(&parent_ch, &mblock0_hash);
    let imh1 = StacksBlockId::new(&parent_ch, &mblock1_hash);

    insert_staging_microblock(
        &src_conn,
        &format!("{parent_bh}"),
        &parent_ch,
        &parent_ibh,
        &mblock0_hash,
        &parent_bh,
        &imh0,
        0,
        1,
        0,
    );
    insert_staging_microblock(
        &src_conn,
        &format!("{parent_bh}"),
        &parent_ch,
        &parent_ibh,
        &mblock1_hash,
        &mblock0_hash,
        &imh1,
        1,
        1,
        0,
    );
    insert_staging_microblock_data(&src_conn, &mblock0_hash, &mblock0_data);
    insert_staging_microblock_data(&src_conn, &mblock1_hash, &mblock1_data);

    // Also insert an orphaned fork microblock that should NOT be copied.
    let (fork_hash, fork_data) = make_test_microblock(0, &BlockHeaderHash([0xCC; 32]));
    let fork_imh = StacksBlockId::new(&parent_ch, &fork_hash);
    insert_staging_microblock(
        &src_conn,
        &format!("{parent_bh}"),
        &parent_ch,
        &parent_ibh,
        &fork_hash,
        &BlockHeaderHash([0xCC; 32]),
        &fork_imh,
        0,
        1,
        1, // orphaned = 1: this fork microblock should be excluded by the copy query
    );
    insert_staging_microblock_data(&src_conn, &fork_hash, &fork_data);
    drop(src_conn);

    // Create dest DB with schema, canonical blocks, and staging_blocks populated.
    create_dest_db_with_canonical_blocks(&dst_path, &[]);
    let dst_conn = Connection::open(&dst_path).unwrap();

    // Clone schemas from source for staging tables.
    dst_conn
        .execute_batch(&format!(
            "ATTACH DATABASE '{}' AS src",
            src_path.to_str().unwrap()
        ))
        .unwrap();
    super::common::clone_schemas_from_source(
        &dst_conn,
        &[
            "staging_blocks",
            "staging_microblocks",
            "staging_microblocks_data",
        ],
    )
    .unwrap();
    dst_conn.execute_batch("DETACH DATABASE src").unwrap();

    // Insert a canonical child block that references mblock1_hash as its parent_microblock_hash.
    // All values must be valid hex for ConsensusHash (40 hex chars) / BlockHeaderHash (64 hex chars).
    let child_ch = ConsensusHash([0x11; 20]);
    let child_bh = BlockHeaderHash([0x22; 32]);
    let child_ibh = StacksBlockId::new(&child_ch, &child_bh);
    insert_staging_block_with_microblock_parent(
        &dst_conn,
        &format!("{child_bh}"),
        &format!("{child_ch}"),
        &format!("{parent_ch}"),
        &format!("{parent_bh}"),
        &format!("{mblock1_hash}"),
        1,
        &format!("{child_ibh}"),
        2,
    );

    // Also insert a child with no microblock stream (empty parent).
    let nostream_ch = ConsensusHash([0x33; 20]);
    let nostream_bh = BlockHeaderHash([0x44; 32]);
    let nostream_ibh = StacksBlockId::new(&nostream_ch, &nostream_bh);
    let nostream_pch = ConsensusHash([0x55; 20]);
    let nostream_pbh = BlockHeaderHash([0x66; 32]);
    insert_staging_block_with_microblock_parent(
        &dst_conn,
        &format!("{nostream_bh}"),
        &format!("{nostream_ch}"),
        &format!("{nostream_pch}"),
        &format!("{nostream_pbh}"),
        &format!("{EMPTY_MICROBLOCK_PARENT_HASH}"),
        0,
        &format!("{nostream_ibh}"),
        3,
    );
    drop(dst_conn);

    // Copy microblocks.
    let stats = super::blocks::copy_confirmed_epoch2_microblocks(
        src_path.to_str().unwrap(),
        dst_path.to_str().unwrap(),
    )
    .unwrap();

    assert_eq!(stats.streams_copied, 1);
    assert_eq!(stats.microblock_rows_copied, 2);
    assert!(stats.microblock_bytes_copied > 0);

    // The fork microblock should NOT be in destination.
    let dst_conn = Connection::open(&dst_path).unwrap();
    let fork_count: i64 = dst_conn
        .query_row(
            "SELECT COUNT(*) FROM staging_microblocks_data WHERE block_hash = ?1",
            params![fork_hash],
            |row| row.get(0),
        )
        .unwrap();
    assert_eq!(fork_count, 0, "fork microblock should not be copied");

    // Validate.
    let v = super::blocks::validate_microblock_streams(
        src_path.to_str().unwrap(),
        dst_path.to_str().unwrap(),
    )
    .unwrap();
    assert!(v.is_valid(), "microblock validation should pass: {v:?}");
}

#[test]
fn test_microblock_stream_unprocessed_skipped() {
    let dir = tempdir().unwrap();
    let src_path = dir.path().join("src_index.sqlite");
    let dst_path = dir.path().join("dst_index.sqlite");

    let src_conn = create_source_db(&src_path);

    let parent_ch = ConsensusHash([0xDD; 20]);
    let parent_bh = BlockHeaderHash([0xEE; 32]);
    let parent_ibh = StacksBlockId::new(&parent_ch, &parent_bh);

    // Build a 1-microblock stream where the microblock is NOT processed.
    let (mblock0_hash, mblock0_data) = make_test_microblock(0, &parent_bh);
    let imh0 = StacksBlockId::new(&parent_ch, &mblock0_hash);
    insert_staging_microblock(
        &src_conn,
        &format!("{parent_bh}"),
        &parent_ch,
        &parent_ibh,
        &mblock0_hash,
        &parent_bh,
        &imh0,
        0,
        0,
        0, // processed=0
    );
    insert_staging_microblock_data(&src_conn, &mblock0_hash, &mblock0_data);
    drop(src_conn);

    // Create dest with staging_blocks referencing the stream.
    create_dest_db_with_canonical_blocks(&dst_path, &[]);
    let dst_conn = Connection::open(&dst_path).unwrap();
    dst_conn
        .execute_batch(&format!(
            "ATTACH DATABASE '{}' AS src",
            src_path.to_str().unwrap()
        ))
        .unwrap();
    super::common::clone_schemas_from_source(
        &dst_conn,
        &[
            "staging_blocks",
            "staging_microblocks",
            "staging_microblocks_data",
        ],
    )
    .unwrap();
    dst_conn.execute_batch("DETACH DATABASE src").unwrap();

    let child_ch = ConsensusHash([0x11; 20]);
    let child_bh = BlockHeaderHash([0x22; 32]);
    let child_ibh = StacksBlockId::new(&child_ch, &child_bh);
    insert_staging_block_with_microblock_parent(
        &dst_conn,
        &format!("{child_bh}"),
        &format!("{child_ch}"),
        &format!("{parent_ch}"),
        &format!("{parent_bh}"),
        &format!("{mblock0_hash}"),
        0,
        &format!("{child_ibh}"),
        2,
    );
    drop(dst_conn);

    // Copy - stream should be skipped (not error).
    let stats = super::blocks::copy_confirmed_epoch2_microblocks(
        src_path.to_str().unwrap(),
        dst_path.to_str().unwrap(),
    )
    .unwrap();

    assert_eq!(stats.streams_copied, 0);
    assert_eq!(stats.streams_skipped, 1);
    assert_eq!(stats.microblock_rows_copied, 0);
}

#[test]
fn test_nakamoto_copy_and_validate() {
    let dir = tempdir().unwrap();
    let src_nak_path = dir.path().join("src_nakamoto.sqlite");
    let dst_nak_path = dir.path().join("dst_nakamoto.sqlite");
    let idx_path = dir.path().join("squashed_index.sqlite");

    // Create source nakamoto.sqlite with canonical + non-canonical rows.
    let src_conn = create_source_nakamoto_db(&src_nak_path);
    insert_nakamoto_staging_block(
        &src_conn,
        "canonical_bh_1",
        "canonical_ch_1",
        "parent_1",
        100,
        "canonical_ibh_1",
        "Fetched",
        b"block_data_1",
    );
    insert_nakamoto_staging_block(
        &src_conn,
        "canonical_bh_2",
        "canonical_ch_2",
        "parent_2",
        101,
        "canonical_ibh_2",
        "Shadow",
        b"block_data_2",
    );
    // Non-canonical block (not in index).
    insert_nakamoto_staging_block(
        &src_conn,
        "orphan_bh",
        "orphan_ch",
        "parent_x",
        100,
        "orphan_ibh",
        "Fetched",
        b"orphan_data",
    );
    drop(src_conn);

    // Create squashed index with nakamoto_block_headers for canonical blocks only.
    let idx_conn = Connection::open(&idx_path).unwrap();
    idx_conn
        .execute_batch(
            "CREATE TABLE nakamoto_block_headers (index_block_hash TEXT NOT NULL PRIMARY KEY)",
        )
        .unwrap();
    idx_conn
        .execute(
            "INSERT INTO nakamoto_block_headers VALUES ('canonical_ibh_1')",
            [],
        )
        .unwrap();
    idx_conn
        .execute(
            "INSERT INTO nakamoto_block_headers VALUES ('canonical_ibh_2')",
            [],
        )
        .unwrap();
    drop(idx_conn);

    // Copy.
    let stats = super::blocks::copy_nakamoto_staging_blocks(
        src_nak_path.to_str().unwrap(),
        dst_nak_path.to_str().unwrap(),
        idx_path.to_str().unwrap(),
    )
    .unwrap();

    assert_eq!(stats.rows_copied, 2);

    // Verify orphan not copied.
    let dst_conn = Connection::open(&dst_nak_path).unwrap();
    let orphan_count: i64 = dst_conn
        .query_row(
            "SELECT COUNT(*) FROM nakamoto_staging_blocks WHERE block_hash = 'orphan_bh'",
            [],
            |row| row.get(0),
        )
        .unwrap();
    assert_eq!(orphan_count, 0, "orphan should not be copied");

    // Verify obtain_method preserved.
    let method: String = dst_conn
        .query_row(
            "SELECT obtain_method FROM nakamoto_staging_blocks WHERE block_hash = 'canonical_bh_2'",
            [],
            |row| row.get(0),
        )
        .unwrap();
    assert_eq!(method, "Shadow", "obtain_method must be preserved");

    // Verify db_version matches source.
    let dst_ver: i64 = dst_conn
        .query_row("SELECT version FROM db_version", [], |row| row.get(0))
        .unwrap();
    assert_eq!(dst_ver, 5, "db_version should be 5 (latest migration)");
    drop(dst_conn);

    // Validate.
    let v = super::blocks::validate_nakamoto_staging_blocks(
        src_nak_path.to_str().unwrap(),
        dst_nak_path.to_str().unwrap(),
        idx_path.to_str().unwrap(),
    )
    .unwrap();
    assert!(v.is_valid(), "nakamoto validation should pass: {v:?}");
    assert!(v.db_version_match, "db_version should match");
    assert!(v.schema_match, "schema should match");
}

#[test]
fn test_nakamoto_validate_detects_db_version_drift() {
    let dir = tempdir().unwrap();
    let src_nak_path = dir.path().join("src_nakamoto.sqlite");
    let dst_nak_path = dir.path().join("dst_nakamoto.sqlite");
    let idx_path = dir.path().join("squashed_index.sqlite");

    // Create matching source and destination with one canonical row.
    let src_conn = create_source_nakamoto_db(&src_nak_path);
    insert_nakamoto_staging_block(
        &src_conn, "bh1", "ch1", "p1", 100, "ibh1", "Fetched", b"data1",
    );
    drop(src_conn);

    let idx_conn = Connection::open(&idx_path).unwrap();
    idx_conn
        .execute_batch(
            "CREATE TABLE nakamoto_block_headers (index_block_hash TEXT NOT NULL PRIMARY KEY)",
        )
        .unwrap();
    idx_conn
        .execute("INSERT INTO nakamoto_block_headers VALUES ('ibh1')", [])
        .unwrap();
    drop(idx_conn);

    // Copy first.
    super::blocks::copy_nakamoto_staging_blocks(
        src_nak_path.to_str().unwrap(),
        dst_nak_path.to_str().unwrap(),
        idx_path.to_str().unwrap(),
    )
    .unwrap();

    // Tamper with destination db_version.
    let dst_conn = Connection::open(&dst_nak_path).unwrap();
    dst_conn
        .execute("UPDATE db_version SET version = 99", [])
        .unwrap();
    drop(dst_conn);

    // Validate - should detect drift.
    let v = super::blocks::validate_nakamoto_staging_blocks(
        src_nak_path.to_str().unwrap(),
        dst_nak_path.to_str().unwrap(),
        idx_path.to_str().unwrap(),
    )
    .unwrap();
    assert!(!v.db_version_match, "should detect db_version drift");
    assert!(!v.is_valid(), "overall validation should fail");
}

#[test]
fn test_nakamoto_validate_detects_schema_drift() {
    let dir = tempdir().unwrap();
    let src_nak_path = dir.path().join("src_nakamoto.sqlite");
    let dst_nak_path = dir.path().join("dst_nakamoto.sqlite");
    let idx_path = dir.path().join("squashed_index.sqlite");

    let src_conn = create_source_nakamoto_db(&src_nak_path);
    insert_nakamoto_staging_block(
        &src_conn, "bh1", "ch1", "p1", 100, "ibh1", "Fetched", b"data1",
    );
    drop(src_conn);

    let idx_conn = Connection::open(&idx_path).unwrap();
    idx_conn
        .execute_batch(
            "CREATE TABLE nakamoto_block_headers (index_block_hash TEXT NOT NULL PRIMARY KEY)",
        )
        .unwrap();
    idx_conn
        .execute("INSERT INTO nakamoto_block_headers VALUES ('ibh1')", [])
        .unwrap();
    drop(idx_conn);

    super::blocks::copy_nakamoto_staging_blocks(
        src_nak_path.to_str().unwrap(),
        dst_nak_path.to_str().unwrap(),
        idx_path.to_str().unwrap(),
    )
    .unwrap();

    // Add an extra index to destination to cause schema drift.
    let dst_conn = Connection::open(&dst_nak_path).unwrap();
    dst_conn
        .execute_batch("CREATE INDEX extra_idx ON nakamoto_staging_blocks(height)")
        .unwrap();
    drop(dst_conn);

    let v = super::blocks::validate_nakamoto_staging_blocks(
        src_nak_path.to_str().unwrap(),
        dst_nak_path.to_str().unwrap(),
        idx_path.to_str().unwrap(),
    )
    .unwrap();
    assert!(
        !v.schema_match,
        "should detect schema drift from extra index"
    );
    assert!(!v.is_valid());
}

#[test]
fn test_epoch2_file_validation_ignores_nakamoto_sqlite() {
    let dir = tempdir().unwrap();
    let src_blocks_dir = dir.path().join("src_blocks");
    let dst_blocks_dir = dir.path().join("dst_blocks");

    // Create a squashed index with one block at height 1.
    let idx_path = dir.path().join("squashed_index.sqlite");
    let conn = Connection::open(&idx_path).unwrap();
    conn.execute_batch(
            "CREATE TABLE block_headers (index_block_hash TEXT NOT NULL, block_height INTEGER NOT NULL)",
        ).unwrap();
    conn.execute(
            "INSERT INTO block_headers VALUES ('0000000000000000000000000000000000000000000000000000000000000000', 0)",
            [],
        ).unwrap();
    let hash_hex = "aabbccdd00000000000000000000000000000000000000000000000000000001";
    conn.execute(
        "INSERT INTO block_headers VALUES (?1, 1)",
        params![hash_hex],
    )
    .unwrap();
    drop(conn);

    // Create source + dest block files.
    // index_block_hash_to_rel_path uses 2-byte (4 hex char) directory segments.
    let rel = format!("aabb/ccdd/{hash_hex}");
    let src_file = src_blocks_dir.join(&rel);
    std::fs::create_dir_all(src_file.parent().unwrap()).unwrap();
    std::fs::write(&src_file, b"block data").unwrap();

    super::blocks::copy_epoch2_block_files(
        idx_path.to_str().unwrap(),
        src_blocks_dir.to_str().unwrap(),
        dst_blocks_dir.to_str().unwrap(),
    )
    .unwrap();

    // Plant nakamoto.sqlite and sidecar files in destination blocks dir.
    std::fs::write(dst_blocks_dir.join("nakamoto.sqlite"), b"fake db").unwrap();
    std::fs::write(dst_blocks_dir.join("nakamoto.sqlite-journal"), b"journal").unwrap();
    std::fs::write(dst_blocks_dir.join("nakamoto.sqlite-wal"), b"wal").unwrap();

    // Validate should still pass - nakamoto files are not "extra" epoch-2 files.
    let v = super::blocks::validate_epoch2_block_files(
        idx_path.to_str().unwrap(),
        src_blocks_dir.to_str().unwrap(),
        dst_blocks_dir.to_str().unwrap(),
    )
    .unwrap();
    assert!(
        v.is_valid(),
        "nakamoto.sqlite sidecars should not cause validation failure: {v:?}"
    );
    assert!(v.no_extra_files, "no_extra_files should be true");
}

// -----------------------------------------------------------------------
// Burnchain auxiliary: burnchain.sqlite tests
// -----------------------------------------------------------------------
