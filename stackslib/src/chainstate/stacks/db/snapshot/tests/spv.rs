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

//! SPV headers DB (headers.sqlite) copy tests.

use std::collections::HashSet;

use rstest::rstest;
use rusqlite::Connection;
use stacks_common::deps_common::bitcoin::blockdata::block::{BlockHeader, LoneBlockHeader};
use stacks_common::deps_common::bitcoin::network::encodable::VarInt;
use stacks_common::deps_common::bitcoin::util::hash::Sha256dHash;
use tempfile::tempdir;

use super::super::spv::{
    assert_source_tables_classified, copy_spv_headers, spv_copy_specs, REQUIRED_TABLES,
};
use crate::burnchains::bitcoin::spv::{SpvClient, BLOCK_DIFFICULTY_CHUNK_SIZE, SPV_DB_VERSION};
use crate::burnchains::bitcoin::BitcoinNetworkType;
use crate::chainstate::stacks::index::Error;

/// Drift guard: every table the SPV migrations create must be classified, so a
/// future migration can't silently drop one from the copy. Runs the exact
/// production guard against a freshly-migrated schema, so the test and the
/// runtime check cannot drift apart.
#[test]
fn test_no_unclassified_spv_tables() {
    let dir = tempdir().unwrap();
    let src_path = dir.path().join("src.sqlite");
    let _client = create_spv_headers_db(&src_path);
    let conn = Connection::open(&src_path).unwrap();
    assert_source_tables_classified(&conn)
        .expect("fresh production SPV schema must be fully classified");
}

/// Every cloned table ([`REQUIRED_TABLES`]) must have a row-copy spec and vice versa,
/// else it would be cloned but never populated (present-but-empty).
#[test]
fn test_spv_copy_specs_match_required_tables() {
    let spec_tables: Vec<&str> = spv_copy_specs(100).iter().map(|s| s.table).collect();
    let spec_set: HashSet<&str> = spec_tables.iter().copied().collect();
    assert_eq!(
        spec_tables.len(),
        spec_set.len(),
        "duplicate table in spv_copy_specs"
    );
    let required_set: HashSet<&str> = REQUIRED_TABLES.iter().copied().collect();
    assert_eq!(
        spec_set, required_set,
        "every REQUIRED_TABLES entry must have exactly one copy spec (and vice versa); \
         a cloned-but-uncopied table would be present-but-empty in the squash"
    );
}

/// A source table the copy lists don't classify is rejected before any
/// destination is produced — the runtime complement to the drift test.
#[test]
fn test_unclassified_source_table_is_rejected() {
    let dir = tempdir().unwrap();
    let src_path = dir.path().join("src.sqlite");
    let dst_path = dir.path().join("dst.sqlite");

    let _client = create_spv_headers_db(&src_path);
    let conn = Connection::open(&src_path).unwrap();
    conn.execute_batch("CREATE TABLE surprise_table (x INTEGER)")
        .unwrap();
    drop(conn);

    let err = copy_spv_headers(src_path.to_str().unwrap(), dst_path.to_str().unwrap(), 100)
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

/// Create a source headers.sqlite. Initialization seeds the
/// regtest genesis header at height 0, so tests seed from height 1.
/// Returns the client so headers go through the production write path.
fn create_spv_headers_db(path: &std::path::Path) -> SpvClient {
    SpvClient::new(
        path.to_str().unwrap(),
        0,
        None,
        BitcoinNetworkType::Regtest,
        true,
        false,
    )
    .expect("SPV headers DB init failed")
}

/// Open an existing headers.sqlite read-only.
fn open_spv_headers_db_readonly(path: &std::path::Path) -> SpvClient {
    SpvClient::new(
        path.to_str().unwrap(),
        0,
        None,
        BitcoinNetworkType::Regtest,
        false,
        false,
    )
    .expect("opening copied headers.sqlite as SpvClient failed")
}

/// A synthetic-but-real header for height `h`, with deterministic fields.
fn fixture_header(h: u32) -> LoneBlockHeader {
    LoneBlockHeader {
        header: BlockHeader {
            version: 1,
            prev_blockhash: Sha256dHash::from_data(&h.wrapping_sub(1).to_le_bytes()),
            merkle_root: Sha256dHash::from_data(&h.to_le_bytes()),
            time: h,
            bits: 545259519,
            nonce: h,
        },
        tx_count: VarInt(0),
    }
}

/// Seed headers at heights 1..=`count` through the SPV client's storage
/// writer ([`SpvClient::test_write_block_headers`]; storage only, no
/// contiguity validation).
fn seed_headers(client: &mut SpvClient, count: u32) {
    let headers = (1..=count).map(fixture_header).collect();
    client.test_write_block_headers(1, headers).unwrap();
}

/// Seed `chain_work` interval rows.
fn seed_chain_work(src_path: &std::path::Path, intervals: u32) {
    let conn = Connection::open(src_path).unwrap();
    for interval in 0..intervals {
        SpvClient::test_insert_chain_work(&conn, u64::from(interval), &format!("work_{interval}"))
            .unwrap();
    }
}

/// Headers are copied up to the burn height and `chain_work` only for
/// complete 2016-block intervals.
#[test]
fn test_spv_headers_copy() {
    let dir = tempdir().unwrap();
    let src_path = dir.path().join("src_headers.sqlite");
    let dst_path = dir.path().join("dst_headers.sqlite");

    let mut client = create_spv_headers_db(&src_path);
    // Headers at heights 0 (genesis) ..=5000.
    seed_headers(&mut client, 5000);
    drop(client);
    // chain_work for intervals 0, 1, 2.
    seed_chain_work(&src_path, 3);

    let stats =
        copy_spv_headers(src_path.to_str().unwrap(), dst_path.to_str().unwrap(), 4500).unwrap();

    // Headers 0..=4500 = 4501 rows.
    assert_eq!(stats.headers_rows, 4501);
    // Interval 0: (0+1)*2016-1=2015 <= 4500 ✓
    // Interval 1: (1+1)*2016-1=4031 <= 4500 ✓
    // Interval 2: (2+1)*2016-1=6047 <= 4500 ✗
    assert_eq!(stats.chain_work_rows, 2);

    // The destination holds exactly the boundary content: the last header is
    // height 4500 with its source hash, nothing above it, the two complete
    // chain_work intervals, and the source db_config version.
    let src = Connection::open(&src_path).unwrap();
    let src_tip_hash: String = src
        .query_row("SELECT hash FROM headers WHERE height = 4500", [], |row| {
            row.get(0)
        })
        .unwrap();
    let dst = Connection::open(&dst_path).unwrap();
    let (count, max_height, tip_hash): (i64, u32, String) = dst
        .query_row(
            "SELECT COUNT(*), MAX(height), \
                    (SELECT hash FROM headers ORDER BY height DESC LIMIT 1) \
             FROM headers",
            [],
            |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)),
        )
        .unwrap();
    assert_eq!((count, max_height, tip_hash), (4501, 4500, src_tip_hash));
    let work: Vec<(u32, String)> = dst
        .prepare("SELECT interval, work FROM chain_work ORDER BY interval")
        .unwrap()
        .query_map([], |row| Ok((row.get(0)?, row.get(1)?)))
        .unwrap()
        .collect::<Result<_, _>>()
        .unwrap();
    assert_eq!(work, vec![(0, "work_0".into()), (1, "work_1".into())]);
    let version: String = dst
        .query_row("SELECT version FROM db_config", [], |row| row.get(0))
        .unwrap();
    assert_eq!(version, SPV_DB_VERSION);
}

/// End-to-end round trip: a copied headers.sqlite must be consumable through
/// the production [`SpvClient`] reader - the same headers and `chain_work` as
/// the source within the boundary, nothing beyond it.
#[test]
fn test_spv_headers_copy_round_trip() {
    let dir = tempdir().unwrap();
    let src_path = dir.path().join("src.sqlite");
    let dst_path = dir.path().join("dst.sqlite");

    // Copy at the end of the second complete interval: the copy keeps intervals
    // 0 and 1 plus the headers through interval 1's last block, so the aggregate
    // path has >1 stored interval and an empty partial tail. The source extends a
    // full interval further, so the boundary actually drops a header and an interval.
    let boundary = 2 * BLOCK_DIFFICULTY_CHUNK_SIZE - 1; // 4031: last block of interval 1
    let source_tip = 3 * BLOCK_DIFFICULTY_CHUNK_SIZE - 1; // 6047: source also stores interval 2

    let mut client = create_spv_headers_db(&src_path);
    seed_headers(&mut client, source_tip as u32);
    client.update_chain_work().unwrap();
    drop(client);

    let stats = copy_spv_headers(
        src_path.to_str().unwrap(),
        dst_path.to_str().unwrap(),
        boundary,
    )
    .unwrap();
    assert_eq!(stats.headers_rows, boundary + 1);
    assert_eq!(stats.chain_work_rows, 2);

    let src = open_spv_headers_db_readonly(&src_path);
    let dst = open_spv_headers_db_readonly(&dst_path);

    // Headers through the boundary round-trip identically through the reader,
    // and nothing above the boundary survives in the copy.
    assert_eq!(
        dst.read_block_headers(0, boundary + 1).unwrap(),
        src.read_block_headers(0, boundary + 1).unwrap()
    );
    assert!(
        dst.read_block_header(boundary + 1).unwrap().is_none(),
        "copy must not hold a header above the boundary"
    );

    // chain_work round-trips as real Uint256: both complete intervals match the
    // source; the interval past the boundary is dropped.
    for interval in [0, 1] {
        let work = dst.find_interval_work(interval).unwrap();
        assert!(work.is_some(), "interval {interval} work must be copied");
        assert_eq!(
            work,
            src.find_interval_work(interval).unwrap(),
            "interval {interval} work must round-trip through the reader"
        );
    }
    assert!(
        dst.find_interval_work(2).unwrap().is_none(),
        "interval 2 is past the boundary and must not be copied"
    );

    // The copy is consumable by the aggregate-work path, not just per-interval
    // reads. Its tip sits on interval 1's boundary (no partial tail), so the
    // total equals that interval's running work.
    assert_eq!(
        dst.get_chain_work().unwrap(),
        dst.find_interval_work(1)
            .unwrap()
            .expect("interval 1 work present"),
        "aggregate chain work over the copy must equal interval 1's running total"
    );

    // Setup invariants: confirm the boundary actually elided data, so the
    // truncation assertions above are not satisfied by an empty src.
    assert!(src.read_block_header(boundary + 1).unwrap().is_some());
    assert!(src.find_interval_work(2).unwrap().is_some());
}

/// Chain-work interval boundary cases: interval `k` is copied iff it is
/// complete at the squash height, i.e. `(k + 1) * 2016 - 1 <= burn_height`.
/// Headers are always copied through `burn_height` inclusive; the source
/// holds one more `chain_work` interval than the expected copy where
/// possible, so each case proves the cutoff.
#[rstest]
#[case::below_first_interval_end(0, 1, 0)]
#[case::exactly_first_interval_end(2015, 2, 1)]
#[case::one_past_first_interval_end(2016, 2, 1)]
#[case::exactly_second_interval_end(4031, 3, 2)]
#[case::one_past_second_interval_end(4032, 3, 2)]
fn test_spv_headers_chain_work_boundaries(
    #[case] burn_height: u64,
    #[case] src_chain_work_intervals: u32,
    #[case] expected_chain_work_rows: u64,
) {
    let dir = tempdir().unwrap();
    let src_path = dir.path().join("src.sqlite");
    let dst_path = dir.path().join("dst.sqlite");

    let mut client = create_spv_headers_db(&src_path);
    seed_headers(&mut client, burn_height as u32);
    drop(client);
    seed_chain_work(&src_path, src_chain_work_intervals);

    let stats = copy_spv_headers(
        src_path.to_str().unwrap(),
        dst_path.to_str().unwrap(),
        burn_height,
    )
    .unwrap();

    assert_eq!(stats.headers_rows, burn_height + 1);
    assert_eq!(stats.chain_work_rows, expected_chain_work_rows);
}

/// A missing source headers.sqlite is an error, whether or not a stale
/// destination file is already present (a reused output dir must not mask
/// the missing source), and the read-only ATTACH must not create the
/// source file as a side effect.
#[rstest]
#[case::fresh_destination(false)]
#[case::stale_destination(true)]
fn test_spv_headers_missing_source_is_error(#[case] stale_destination: bool) {
    let dir = tempdir().unwrap();
    let src_path = dir.path().join("nonexistent.sqlite");
    let dst_path = dir.path().join("dst.sqlite");
    if stale_destination {
        std::fs::write(&dst_path, b"stale data").unwrap();
    }

    let result = copy_spv_headers(src_path.to_str().unwrap(), dst_path.to_str().unwrap(), 100);
    assert!(result.is_err(), "missing source should error");
    assert!(
        !src_path.exists(),
        "missing source must not be created by ATTACH"
    );
}

/// The copy writes into a NEW destination only: a pre-existing
/// destination file (e.g. left over from a prior squash run) is an
/// error, never appended to or overwritten.
#[test]
fn test_spv_headers_existing_destination_is_error() {
    let dir = tempdir().unwrap();
    let src_path = dir.path().join("src.sqlite");
    let dst_path = dir.path().join("dst.sqlite");

    create_spv_headers_db(&src_path);
    std::fs::write(&dst_path, b"stale data").unwrap();

    let err = copy_spv_headers(src_path.to_str().unwrap(), dst_path.to_str().unwrap(), 100)
        .expect_err("existing destination should error");
    assert!(
        matches!(err, Error::DestinationExists(_)),
        "expected DestinationExists, got {err:?}"
    );
    assert_eq!(
        std::fs::read(&dst_path).unwrap(),
        b"stale data",
        "existing destination must be left untouched"
    );
}
