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

/// Insert a minimal nakamoto_block_headers row into the source DB.
fn insert_nakamoto_header(conn: &Connection, ibh: &str, burn_height: u32) {
    conn.execute(
        "INSERT INTO nakamoto_block_headers ( \
             block_height, index_root, burn_header_hash, burn_header_height, \
             burn_header_timestamp, block_size, version, chain_length, burn_spent, \
             consensus_hash, parent_block_id, tx_merkle_root, state_index_root, \
             miner_signature, signer_signature, signer_bitvec, header_type, \
             block_hash, index_block_hash, cost, total_tenure_cost, tenure_changed, \
             tenure_tx_fees, vrf_proof, timestamp, burn_view, height_in_tenure, \
             total_tenure_size) \
         VALUES (?1,'ir','bhh',?2,0,'0',1,?1,0,'ch','pid','mr','sr','ms','ss','bv', \
                 'nakamoto','bh',?3,'0','0',0,'0',NULL,0,NULL,0,0)",
        params![burn_height, burn_height, ibh],
    )
    .unwrap();
}

#[test]
fn test_signer_stats_validates_with_source_drift() {
    // signer_stats is a non-consensus counter table. After the squash, the
    // source node continues running and increments blocks_signed for existing
    // (public_key, reward_cycle) pairs. Validation should still pass because
    // we only check that the destination keys are a subset of the source keys.
    let dir = tempdir().unwrap();
    let src_path = dir.path().join("src_index.sqlite");
    let conn = create_source_db(&src_path);

    insert_block_header(&conn, 1, "1");
    // Nakamoto header so derive_max_reward_cycle can compute a cycle.
    insert_nakamoto_header(&conn, "ibh1", 10);
    conn.execute(
        "INSERT INTO signer_stats (public_key, reward_cycle, blocks_signed) \
         VALUES ('pk1', 1, 5), ('pk2', 1, 3)",
        [],
    )
    .unwrap();
    drop(conn);

    let dst_path = dir.path().join("dst_index.sqlite");
    create_dest_db_with_canonical_blocks(&dst_path, &["ibh1"]);

    // Copy with first_burn_height=0, reward_cycle_len=1 so max_cycle = 10/1 = 10,
    // which covers the test row at reward_cycle=1.
    let _stats =
        copy_index_side_tables(src_path.to_str().unwrap(), dst_path.to_str().unwrap(), 0, 1)
            .unwrap();

    // Simulate source drift: increment blocks_signed counters.
    {
        let src_conn = Connection::open(&src_path).unwrap();
        src_conn
            .execute("UPDATE signer_stats SET blocks_signed = 100", [])
            .unwrap();
    }

    let validation =
        validate_index_side_tables(src_path.to_str().unwrap(), dst_path.to_str().unwrap(), 0, 1)
            .unwrap();

    assert!(
        validation.signer_stats_match,
        "signer_stats should pass with drifted counter values"
    );
    assert!(
        validation.is_valid(),
        "overall validation should pass: {validation:?}"
    );
}

#[test]
fn test_signer_stats_detects_fabricated_keys() {
    // If the destination has a (public_key, reward_cycle) pair that doesn't
    // exist in the source at all, validation must fail.
    let dir = tempdir().unwrap();
    let src_path = dir.path().join("src_index.sqlite");
    let conn = create_source_db(&src_path);

    insert_block_header(&conn, 1, "1");
    insert_nakamoto_header(&conn, "ibh1", 10);
    conn.execute(
        "INSERT INTO signer_stats (public_key, reward_cycle, blocks_signed) \
         VALUES ('pk1', 1, 5)",
        [],
    )
    .unwrap();
    drop(conn);

    let dst_path = dir.path().join("dst_index.sqlite");
    create_dest_db_with_canonical_blocks(&dst_path, &["ibh1"]);

    let _stats =
        copy_index_side_tables(src_path.to_str().unwrap(), dst_path.to_str().unwrap(), 0, 1)
            .unwrap();

    // Inject a fabricated signer key into the destination.
    {
        let dst_conn = Connection::open(&dst_path).unwrap();
        dst_conn
            .execute(
                "INSERT INTO signer_stats (public_key, reward_cycle, blocks_signed) \
                 VALUES ('pk_FAKE', 1, 99)",
                [],
            )
            .unwrap();
    }

    let validation =
        validate_index_side_tables(src_path.to_str().unwrap(), dst_path.to_str().unwrap(), 0, 1)
            .unwrap();

    assert!(
        !validation.signer_stats_match,
        "signer_stats should fail with fabricated key"
    );
    assert!(!validation.is_valid());
}

#[test]
fn test_signer_stats_detects_inflated_counters() {
    // If the destination has blocks_signed > source for an existing key,
    // validation must fail (the counter is monotonically increasing).
    let dir = tempdir().unwrap();
    let src_path = dir.path().join("src_index.sqlite");
    let conn = create_source_db(&src_path);

    insert_block_header(&conn, 1, "1");
    insert_nakamoto_header(&conn, "ibh1", 10);
    conn.execute(
        "INSERT INTO signer_stats (public_key, reward_cycle, blocks_signed) \
         VALUES ('pk1', 1, 5)",
        [],
    )
    .unwrap();
    drop(conn);

    let dst_path = dir.path().join("dst_index.sqlite");
    create_dest_db_with_canonical_blocks(&dst_path, &["ibh1"]);

    let _stats =
        copy_index_side_tables(src_path.to_str().unwrap(), dst_path.to_str().unwrap(), 0, 1)
            .unwrap();

    // Inflate the counter in the destination beyond the source value.
    {
        let dst_conn = Connection::open(&dst_path).unwrap();
        dst_conn
            .execute(
                "UPDATE signer_stats SET blocks_signed = 999 WHERE public_key = 'pk1'",
                [],
            )
            .unwrap();
    }

    let validation =
        validate_index_side_tables(src_path.to_str().unwrap(), dst_path.to_str().unwrap(), 0, 1)
            .unwrap();

    assert!(
        !validation.signer_stats_match,
        "signer_stats should fail with inflated counter"
    );
    assert!(!validation.is_valid());
}

#[test]
fn test_matured_rewards_validates_with_source_growth() {
    // matured_rewards is a non-consensus cache. After the squash, new blocks
    // on the source trigger maturation of rewards for older canonical blocks,
    // adding rows that match the canonical filter. Validation should still
    // pass because we only check dst ⊆ filtered-src.
    let dir = tempdir().unwrap();
    let src_path = dir.path().join("src_index.sqlite");
    let conn = create_source_db(&src_path);

    insert_block_header(&conn, 1, "1");
    insert_nakamoto_header(&conn, "ibh1", 10);
    conn.execute(
        "INSERT INTO matured_rewards (address, recipient, vtxindex, coinbase, \
             tx_fees_anchored, tx_fees_streamed_confirmed, tx_fees_streamed_produced, \
             child_index_block_hash, parent_index_block_hash) \
         VALUES ('addr1', NULL, 0, '100', '0', '0', '0', 'ibh1', 'pibh0')",
        [],
    )
    .unwrap();
    drop(conn);

    let dst_path = dir.path().join("dst_index.sqlite");
    create_dest_db_with_canonical_blocks(&dst_path, &["ibh1"]);

    let _stats =
        copy_index_side_tables(src_path.to_str().unwrap(), dst_path.to_str().unwrap(), 0, 1)
            .unwrap();

    // Simulate source growth: add a new matured_rewards row for a canonical block.
    {
        let src_conn = Connection::open(&src_path).unwrap();
        src_conn
            .execute(
                "INSERT INTO matured_rewards (address, recipient, vtxindex, coinbase, \
                     tx_fees_anchored, tx_fees_streamed_confirmed, tx_fees_streamed_produced, \
                     child_index_block_hash, parent_index_block_hash) \
                 VALUES ('addr2', NULL, 0, '0', '0', '0', '0', 'ibh1', 'pibh0')",
                [],
            )
            .unwrap();
    }

    let validation =
        validate_index_side_tables(src_path.to_str().unwrap(), dst_path.to_str().unwrap(), 0, 1)
            .unwrap();

    assert!(
        validation.matured_rewards_match,
        "matured_rewards should pass when source has grown"
    );
    assert!(
        validation.is_valid(),
        "overall validation should pass: {validation:?}"
    );
}

#[test]
fn test_matured_rewards_detects_fabricated_rows() {
    // If the destination has a matured_rewards row not in the filtered source,
    // validation must fail.
    let dir = tempdir().unwrap();
    let src_path = dir.path().join("src_index.sqlite");
    let conn = create_source_db(&src_path);

    insert_block_header(&conn, 1, "1");
    insert_nakamoto_header(&conn, "ibh1", 10);
    drop(conn);

    let dst_path = dir.path().join("dst_index.sqlite");
    create_dest_db_with_canonical_blocks(&dst_path, &["ibh1"]);

    let _stats =
        copy_index_side_tables(src_path.to_str().unwrap(), dst_path.to_str().unwrap(), 0, 1)
            .unwrap();

    // Inject a fabricated matured_rewards row.
    {
        let dst_conn = Connection::open(&dst_path).unwrap();
        dst_conn
            .execute(
                "INSERT INTO matured_rewards (address, recipient, vtxindex, coinbase, \
                     tx_fees_anchored, tx_fees_streamed_confirmed, tx_fees_streamed_produced, \
                     child_index_block_hash, parent_index_block_hash) \
                 VALUES ('addr_FAKE', NULL, 0, '999', '0', '0', '0', 'ibh1', 'pibh0')",
                [],
            )
            .unwrap();
    }

    let validation =
        validate_index_side_tables(src_path.to_str().unwrap(), dst_path.to_str().unwrap(), 0, 1)
            .unwrap();

    assert!(
        !validation.matured_rewards_match,
        "matured_rewards should fail with fabricated row"
    );
    assert!(!validation.is_valid());
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
