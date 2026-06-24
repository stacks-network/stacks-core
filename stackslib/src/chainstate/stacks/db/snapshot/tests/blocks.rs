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

//! Block-preservation copy tests: epoch-2 block files, confirmed microblock
//! streams, and the Nakamoto staging-blocks DB.

use std::collections::HashSet;
use std::path::Path;

use rusqlite::{params, Connection};
use stacks_common::codec::StacksMessageCodec;
use stacks_common::types::chainstate::{
    BlockHeaderHash, ConsensusHash, StacksAddress, StacksBlockId,
};
use stacks_common::util::hash::{Hash160, MerkleTree, Sha512Trunc256Sum};
use stacks_common::util::secp256k1::{MessageSignature, Secp256k1PrivateKey, Secp256k1PublicKey};
use tempfile::tempdir;

use super::super::blocks::{
    assert_source_tables_classified, copy_confirmed_epoch2_microblocks, copy_epoch2_block_files,
    copy_nakamoto_staging_blocks, nakamoto_copy_specs, NAKAMOTO_STAGING_TABLES,
};
use super::super::common::clone_schemas_from_source;
use super::{
    create_dest_db_with_canonical_blocks, create_source_db, insert_epoch2_block_header_with_ibh,
    insert_nakamoto_header,
};
use crate::chainstate::nakamoto::staging_blocks::NAKAMOTO_STAGING_DB_SCHEMA_LATEST;
use crate::chainstate::stacks::db::StacksChainState;
use crate::chainstate::stacks::index::Error;
use crate::chainstate::stacks::{
    StacksMicroblock, StacksMicroblockHeader, StacksTransaction, TokenTransferMemo,
    TransactionAuth, TransactionPayload, TransactionSpendingCondition, TransactionVersion,
};
use crate::core::EMPTY_MICROBLOCK_PARENT_HASH;

/// Create a squashed index DB whose `block_headers` rows are the given
/// `(index_block_hash, block_height)` pairs.
fn create_block_headers_index(path: &Path, rows: &[(&str, u32)]) {
    let conn = create_source_db(path);
    for (i, (ibh, height)) in rows.iter().enumerate() {
        insert_epoch2_block_header_with_ibh(&conn, *height, ibh, &format!("_{i}"));
    }
}

/// Create a squashed index DB whose `nakamoto_block_headers` rows are
/// headers seeded from the given labels, via the production writer.
/// Returns each label's computed `index_block_hash` hex, for the staging
/// fixtures that must join against it.
fn create_nakamoto_headers_index(path: &Path, labels: &[&str]) -> Vec<String> {
    let conn = create_source_db(path);
    labels
        .iter()
        .enumerate()
        .map(|(i, label)| insert_nakamoto_header(&conn, label, 100 + i as u32).to_hex())
        .collect()
}

/// End-to-end epoch-2 block file copy: genesis is skipped, the height-1
/// file lands byte-identical at its hashed relative path.
#[test]
fn test_epoch2_block_file_copy() {
    let dir = tempdir().unwrap();
    let src_blocks_dir = dir.path().join("src_blocks");
    let dst_blocks_dir = dir.path().join("dst_blocks");

    // A squashed index with 2 block headers (height 0 = genesis; height 1 is
    // a hex hash that maps to a known relative path).
    let idx_path = dir.path().join("squashed_index.sqlite");
    let hash_hex = "aabbccdd00000000000000000000000000000000000000000000000000000001";
    create_block_headers_index(
        &idx_path,
        &[
            (
                "0000000000000000000000000000000000000000000000000000000000000000",
                0,
            ),
            (hash_hex, 1),
        ],
    );

    // Create source block file for height 1.
    // StacksChainState::index_block_hash_to_rel_path uses 2-byte (4 hex char) directory segments.
    let rel = format!("aabb/ccdd/{hash_hex}");
    let src_file = src_blocks_dir.join(&rel);
    std::fs::create_dir_all(src_file.parent().unwrap()).unwrap();
    std::fs::write(&src_file, b"block data here").unwrap();

    // Copy.
    let stats = copy_epoch2_block_files(
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
}

/// A canonical block whose flat file is missing from the source archive
/// is corruption: the copy must abort.
#[test]
fn test_epoch2_block_file_missing_source_is_error() {
    let dir = tempdir().unwrap();
    let src_blocks_dir = dir.path().join("src_blocks");
    let dst_blocks_dir = dir.path().join("dst_blocks");

    // Index with height-1 block but NO source file.
    let idx_path = dir.path().join("squashed_index.sqlite");
    let hash_hex = "aabbccdd00000000000000000000000000000000000000000000000000000001";
    create_block_headers_index(&idx_path, &[(hash_hex, 1)]);

    std::fs::create_dir_all(&src_blocks_dir).unwrap();

    let err = copy_epoch2_block_files(
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

/// Drift guard: every table the Nakamoto staging migrations create must
/// be classified, so a future migration can't silently drop one from the
/// copy. Runs the exact production guard against a freshly-migrated schema,
/// so the test and the runtime check cannot drift apart.
#[test]
fn test_no_unclassified_nakamoto_staging_tables() {
    let dir = tempdir().unwrap();
    let conn = create_source_nakamoto_db(&dir.path().join("src.sqlite"));
    assert_source_tables_classified(&conn)
        .expect("fresh production Nakamoto staging schema must be fully classified");
}

/// Every cloned table (NAKAMOTO_STAGING_TABLES) must have a row-copy spec and vice versa,
/// else it would be cloned but never populated (present-but-empty).
#[test]
fn test_nakamoto_copy_specs_match_staging_tables() {
    let spec_tables: Vec<&str> = nakamoto_copy_specs().iter().map(|s| s.table).collect();
    let spec_set: HashSet<&str> = spec_tables.iter().copied().collect();
    assert_eq!(
        spec_tables.len(),
        spec_set.len(),
        "duplicate table in nakamoto_copy_specs"
    );
    let staging_set: HashSet<&str> = NAKAMOTO_STAGING_TABLES.iter().copied().collect();
    assert_eq!(
        spec_set, staging_set,
        "every NAKAMOTO_STAGING_TABLES entry must have exactly one copy spec (and vice versa); \
         a cloned-but-uncopied table would be present-but-empty in the squash"
    );
}

/// A source table the copy lists don't classify is rejected before any
/// destination is produced — the runtime complement to the drift test.
#[test]
fn test_unclassified_source_table_is_rejected() {
    let dir = tempdir().unwrap();
    let src_nak_path = dir.path().join("src_nakamoto.sqlite");
    let conn = create_source_nakamoto_db(&src_nak_path);
    conn.execute_batch("CREATE TABLE surprise_table (x INTEGER)")
        .unwrap();
    drop(conn);

    let dst_nak_path = dir.path().join("dst_nakamoto.sqlite");
    let idx_path = dir.path().join("squashed_index.sqlite");
    create_nakamoto_headers_index(&idx_path, &["canonical_ibh_1"]);

    let err = copy_nakamoto_staging_blocks(
        src_nak_path.to_str().unwrap(),
        dst_nak_path.to_str().unwrap(),
        idx_path.to_str().unwrap(),
    )
    .expect_err("unclassified source table must be rejected");
    match err {
        Error::CorruptionError(msg) => assert!(
            msg.contains("surprise_table"),
            "error should name the offending table, got: {msg}"
        ),
        other => panic!("expected CorruptionError, got {other:?}"),
    }
    assert!(
        !dst_nak_path.exists(),
        "no destination should be produced when the source is rejected"
    );
}

/// Build a minimal serializable StacksMicroblock with the given sequence
/// and prev_block, returning (block_hash, serialized_bytes).
fn make_microblock(sequence: u16, prev_block: &BlockHeaderHash) -> (BlockHeaderHash, Vec<u8>) {
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
    let merkle_tree = MerkleTree::<Sha512Trunc256Sum>::new(&[txid_bytes]);
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

/// Create a source nakamoto.sqlite via the production initializer
/// ([`StacksChainState::open_nakamoto_staging_blocks`]), so the fixture
/// always carries the current schema instead of replaying migrations by
/// hand.
fn create_source_nakamoto_db(path: &Path) -> Connection {
    // The first open instantiates the base schema only; migrations run on
    // subsequent opens, so a second open brings the DB to the current
    // version - exactly as node restarts do in production.
    StacksChainState::open_nakamoto_staging_blocks(path.to_str().unwrap(), true)
        .expect("nakamoto staging DB init failed");
    StacksChainState::open_nakamoto_staging_blocks(path.to_str().unwrap(), true)
        .expect("nakamoto staging DB migration failed");
    Connection::open(path).unwrap()
}

/// Insert a nakamoto_staging_blocks row
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

/// A confirmed 2-microblock stream referenced by a canonical child block
/// is copied in full; an orphaned microblock of the same parent is left
/// behind.
#[test]
fn test_microblock_stream_copy() {
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
    let (mblock0_hash, mblock0_data) = make_microblock(0, &parent_bh);
    let (mblock1_hash, mblock1_data) = make_microblock(1, &mblock0_hash);

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
    let (fork_hash, fork_data) = make_microblock(0, &BlockHeaderHash([0xCC; 32]));
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
        .execute(
            "ATTACH DATABASE ?1 AS src",
            params![src_path.to_str().unwrap()],
        )
        .unwrap();
    clone_schemas_from_source(
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
    let stats =
        copy_confirmed_epoch2_microblocks(src_path.to_str().unwrap(), dst_path.to_str().unwrap())
            .unwrap();

    assert_eq!(stats.streams_copied, 1);
    assert_eq!(stats.microblock_rows_copied, 2);
    assert!(stats.microblock_bytes_copied > 0);

    // The copied stream survives intact: ordered metadata and byte-identical
    // data blobs.
    let dst_conn = Connection::open(&dst_path).unwrap();
    let rows: Vec<(u32, BlockHeaderHash)> = dst_conn
        .prepare("SELECT sequence, microblock_hash FROM staging_microblocks ORDER BY sequence")
        .unwrap()
        .query_map([], |row| Ok((row.get(0)?, row.get(1)?)))
        .unwrap()
        .collect::<Result<_, _>>()
        .unwrap();
    assert_eq!(rows, vec![(0, mblock0_hash.clone()), (1, mblock1_hash)]);
    let blob: Vec<u8> = dst_conn
        .query_row(
            "SELECT block_data FROM staging_microblocks_data WHERE block_hash = ?1",
            params![mblock0_hash],
            |row| row.get(0),
        )
        .unwrap();
    assert_eq!(
        blob, mblock0_data,
        "copied data blob must be byte-identical"
    );

    // Neither the fork microblock's metadata nor its data may be copied.
    let (fork_meta, fork_data): (i64, i64) = dst_conn
        .query_row(
            "SELECT (SELECT COUNT(*) FROM staging_microblocks WHERE microblock_hash = ?1), \
                    (SELECT COUNT(*) FROM staging_microblocks_data WHERE block_hash = ?1)",
            params![fork_hash],
            |row| Ok((row.get(0)?, row.get(1)?)),
        )
        .unwrap();
    assert_eq!(
        (fork_meta, fork_data),
        (0, 0),
        "fork microblock should not be copied"
    );
}

/// A stream whose microblocks are unprocessed cannot be confirmed: it is
/// skipped with a warning, not an error.
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
    let (mblock0_hash, mblock0_data) = make_microblock(0, &parent_bh);
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
        .execute(
            "ATTACH DATABASE ?1 AS src",
            params![src_path.to_str().unwrap()],
        )
        .unwrap();
    clone_schemas_from_source(
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
    let stats =
        copy_confirmed_epoch2_microblocks(src_path.to_str().unwrap(), dst_path.to_str().unwrap())
            .unwrap();

    assert_eq!(stats.streams_copied, 0);
    assert_eq!(stats.streams_skipped, 1);
    assert_eq!(stats.microblock_rows_copied, 0);
}

/// A stream whose referenced tip is absent (only seq 0 exists, the child
/// confirms a tip at seq 1) is incomplete: it must be skipped, not
/// partially copied.
#[test]
fn test_microblock_stream_missing_tip_skipped() {
    let dir = tempdir().unwrap();
    let src_path = dir.path().join("src_index.sqlite");
    let dst_path = dir.path().join("dst_index.sqlite");

    let src_conn = create_source_db(&src_path);

    let parent_ch = ConsensusHash([0xDD; 20]);
    let parent_bh = BlockHeaderHash([0xEE; 32]);
    let parent_ibh = StacksBlockId::new(&parent_ch, &parent_bh);

    // Only the seq-0 microblock exists; the seq-1 tip the child references
    // was never stored.
    let (mblock0_hash, mblock0_data) = make_microblock(0, &parent_bh);
    let (mblock1_hash, _) = make_microblock(1, &mblock0_hash);
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
        1,
        0,
    );
    insert_staging_microblock_data(&src_conn, &mblock0_hash, &mblock0_data);
    drop(src_conn);

    create_dest_db_with_canonical_blocks(&dst_path, &[]);
    let dst_conn = Connection::open(&dst_path).unwrap();
    dst_conn
        .execute(
            "ATTACH DATABASE ?1 AS src",
            params![src_path.to_str().unwrap()],
        )
        .unwrap();
    clone_schemas_from_source(
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
        &format!("{mblock1_hash}"),
        1,
        &format!("{child_ibh}"),
        2,
    );
    drop(dst_conn);

    let stats =
        copy_confirmed_epoch2_microblocks(src_path.to_str().unwrap(), dst_path.to_str().unwrap())
            .unwrap();

    assert_eq!(stats.streams_copied, 0, "incomplete stream must be skipped");
    assert_eq!(stats.streams_skipped, 1);
    assert_eq!(
        stats.microblock_rows_copied, 0,
        "no partial stream may be copied"
    );
}

/// Canonical staging rows are copied with data blobs, `obtain_method`,
/// and `db_version` preserved; a row not in the squashed index headers is
/// dropped.
#[test]
fn test_nakamoto_copy() {
    let dir = tempdir().unwrap();
    let src_nak_path = dir.path().join("src_nakamoto.sqlite");
    let dst_nak_path = dir.path().join("dst_nakamoto.sqlite");
    let idx_path = dir.path().join("squashed_index.sqlite");

    // Squashed index with nakamoto_block_headers for canonical blocks only.
    let ibhs = create_nakamoto_headers_index(&idx_path, &["canonical_ibh_1", "canonical_ibh_2"]);

    // Create source nakamoto.sqlite with canonical + non-canonical rows.
    let src_conn: Connection = create_source_nakamoto_db(&src_nak_path);
    insert_nakamoto_staging_block(
        &src_conn,
        "canonical_bh_1",
        "canonical_ch_1",
        "parent_1",
        100,
        &ibhs[0],
        "Fetched",
        b"block_data_1",
    );
    insert_nakamoto_staging_block(
        &src_conn,
        "canonical_bh_2",
        "canonical_ch_2",
        "parent_2",
        101,
        &ibhs[1],
        "Shadow",
        b"block_data_2",
    );
    // Non-canonical block (not in the squashed index headers).
    insert_nakamoto_staging_block(
        &src_conn,
        "noncanon_bh",
        "noncanon_ch",
        "parent_x",
        100,
        "noncanon_ibh",
        "Fetched",
        b"noncanon_data",
    );
    drop(src_conn);

    // Copy.
    let stats = copy_nakamoto_staging_blocks(
        src_nak_path.to_str().unwrap(),
        dst_nak_path.to_str().unwrap(),
        idx_path.to_str().unwrap(),
    )
    .unwrap();

    assert_eq!(stats.rows_copied, 2);
    assert_eq!(
        stats.total_blob_bytes,
        (b"block_data_1".len() + b"block_data_2".len()) as u64
    );

    // Verify the non-canonical row is not copied.
    let dst_conn = Connection::open(&dst_nak_path).unwrap();
    let noncanon_count: i64 = dst_conn
        .query_row(
            "SELECT COUNT(*) FROM nakamoto_staging_blocks WHERE block_hash = 'noncanon_bh'",
            [],
            |row| row.get(0),
        )
        .unwrap();
    assert_eq!(noncanon_count, 0, "non-canonical row should not be copied");

    // Verify the data blob is byte-identical.
    let data: Vec<u8> = dst_conn
        .query_row(
            "SELECT data FROM nakamoto_staging_blocks WHERE block_hash = 'canonical_bh_1'",
            [],
            |row| row.get(0),
        )
        .unwrap();
    assert_eq!(data, b"block_data_1");

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
        .query_row("SELECT MAX(version) FROM db_version", [], |row| row.get(0))
        .unwrap();
    assert_eq!(
        dst_ver,
        i64::from(NAKAMOTO_STAGING_DB_SCHEMA_LATEST),
        "db_version should be the latest migration"
    );
    drop(dst_conn);
}

/// The copy writes into a NEW destination only: a pre-existing
/// `nakamoto.sqlite` (e.g. left over from a prior failed squash) is an
/// error, never appended to or overwritten.
#[test]
fn test_nakamoto_copy_existing_destination_is_error() {
    let dir = tempdir().unwrap();
    let src_nak_path = dir.path().join("src_nakamoto.sqlite");
    let dst_nak_path = dir.path().join("dst_nakamoto.sqlite");
    let idx_path = dir.path().join("squashed_index.sqlite");

    let ibhs = create_nakamoto_headers_index(&idx_path, &["canonical_ibh_1"]);
    let src_conn = create_source_nakamoto_db(&src_nak_path);
    insert_nakamoto_staging_block(
        &src_conn,
        "canonical_bh_1",
        "canonical_ch_1",
        "parent_1",
        100,
        &ibhs[0],
        "Fetched",
        b"block_data_1",
    );
    drop(src_conn);

    // A stale destination left over from a prior run must not be touched.
    std::fs::write(&dst_nak_path, b"stale data").unwrap();

    let err = copy_nakamoto_staging_blocks(
        src_nak_path.to_str().unwrap(),
        dst_nak_path.to_str().unwrap(),
        idx_path.to_str().unwrap(),
    )
    .expect_err("existing destination should error");
    assert!(
        matches!(err, Error::DestinationExists(_)),
        "expected DestinationExists, got {err:?}"
    );
    assert_eq!(
        std::fs::read(&dst_nak_path).unwrap(),
        b"stale data",
        "existing destination must be left untouched"
    );
}

/// The squash boundary lives entirely in the squashed index: a staging
/// row is retained iff its index_block_hash is in
/// idx.nakamoto_block_headers (<=H). A block above H, or an in-index but
/// orphaned block, must not be copied.
#[test]
fn test_nakamoto_copy_excludes_post_boundary_blocks() {
    let dir = tempdir().unwrap();
    let src_nak_path = dir.path().join("src_nakamoto.sqlite");
    let dst_nak_path = dir.path().join("dst_nakamoto.sqlite");
    let idx_path = dir.path().join("squashed_index.sqlite");

    // Squashed index stops at H: ibh_a, ibh_h, and the in-index orphan --
    // NOT the post-boundary block.
    let ibhs = create_nakamoto_headers_index(&idx_path, &["ibh_a", "ibh_h", "ibh_orphan"]);
    let (ibh_a, ibh_h, ibh_orphan) = (&ibhs[0], &ibhs[1], &ibhs[2]);

    // Source: two <=H canonical blocks plus one post-boundary (H+1) child of H.
    let src_conn = create_source_nakamoto_db(&src_nak_path);
    insert_nakamoto_staging_block(
        &src_conn, "bh_a", "ch_a", "parent_a", 100, ibh_a, "Fetched", b"data_a",
    );
    insert_nakamoto_staging_block(
        &src_conn, "bh_h", "ch_h", ibh_a, 101, ibh_h, "Fetched", b"data_h",
    );
    insert_nakamoto_staging_block(
        &src_conn,
        "bh_post",
        "ch_post",
        ibh_h,
        102,
        "ibh_post",
        "Fetched",
        b"data_post",
    );
    // A block that IS in the index but is orphaned must still be excluded -- this
    // isolates the `orphaned = 0` half of the predicate (set_block_orphaned can
    // mark a block's children orphaned via parent_block_id).
    insert_nakamoto_staging_block(
        &src_conn,
        "bh_orphan",
        "ch_orphan",
        ibh_a,
        101,
        ibh_orphan,
        "Fetched",
        b"data_orphan",
    );
    src_conn
        .execute(
            "UPDATE nakamoto_staging_blocks SET orphaned = 1 WHERE block_hash = 'bh_orphan'",
            [],
        )
        .unwrap();
    drop(src_conn);

    // Copy: only the two <=H blocks are retained.
    let stats = copy_nakamoto_staging_blocks(
        src_nak_path.to_str().unwrap(),
        dst_nak_path.to_str().unwrap(),
        idx_path.to_str().unwrap(),
    )
    .unwrap();
    assert_eq!(stats.rows_copied, 2, "only <=H blocks should be copied");

    let dst_conn = Connection::open(&dst_nak_path).unwrap();
    let post_count: i64 = dst_conn
        .query_row(
            "SELECT COUNT(*) FROM nakamoto_staging_blocks WHERE block_hash = 'bh_post'",
            [],
            |row| row.get(0),
        )
        .unwrap();
    assert_eq!(post_count, 0, "post-boundary block must not be copied");
    let orphan_count: i64 = dst_conn
        .query_row(
            "SELECT COUNT(*) FROM nakamoto_staging_blocks WHERE block_hash = 'bh_orphan'",
            [],
            |row| row.get(0),
        )
        .unwrap();
    assert_eq!(
        orphan_count, 0,
        "in-index but orphaned block must not be copied"
    );
    drop(dst_conn);
}
