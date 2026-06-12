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

use rstest::rstest;
use rusqlite::Connection;
use stacks_common::deps_common::bitcoin::blockdata::block::{BlockHeader, LoneBlockHeader};
use stacks_common::deps_common::bitcoin::network::encodable::VarInt;
use stacks_common::deps_common::bitcoin::util::hash::Sha256dHash;
use tempfile::tempdir;

use super::super::common::unclassified_tables;
use crate::burnchains::bitcoin::spv::{SpvClient, SPV_DB_VERSION};
use crate::burnchains::bitcoin::BitcoinNetworkType;

/// Drift guard: every table the SPV migrations create must be
/// classified, so a future migration can't silently drop one from the copy.
#[test]
fn test_no_unclassified_spv_tables() {
    let dir = tempdir().unwrap();
    let src_path = dir.path().join("src.sqlite");
    let _client = create_spv_headers_db(&src_path);
    let conn = Connection::open(&src_path).unwrap();
    // headers.sqlite is not MARF-backed, so unlike the other drift guards
    // no MARF infra tables are exempted here.
    let extra = unclassified_tables(&conn, super::super::spv::REQUIRED_TABLES);
    assert!(
        extra.is_empty(),
        "unclassified SPV table(s) {extra:?}: classify each in REQUIRED_TABLES (snapshot/spv.rs)"
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

    let stats = super::super::spv::copy_spv_headers(
        src_path.to_str().unwrap(),
        dst_path.to_str().unwrap(),
        4500,
    )
    .unwrap();

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
    #[case] burn_height: u32,
    #[case] src_chain_work_intervals: u32,
    #[case] expected_chain_work_rows: u64,
) {
    let dir = tempdir().unwrap();
    let src_path = dir.path().join("src.sqlite");
    let dst_path = dir.path().join("dst.sqlite");

    let mut client = create_spv_headers_db(&src_path);
    seed_headers(&mut client, burn_height);
    drop(client);
    seed_chain_work(&src_path, src_chain_work_intervals);

    let stats = super::super::spv::copy_spv_headers(
        src_path.to_str().unwrap(),
        dst_path.to_str().unwrap(),
        burn_height,
    )
    .unwrap();

    assert_eq!(stats.headers_rows, u64::from(burn_height) + 1);
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

    let result = super::super::spv::copy_spv_headers(
        src_path.to_str().unwrap(),
        dst_path.to_str().unwrap(),
        100,
    );
    assert!(result.is_err(), "missing source should error");
    assert!(
        !src_path.exists(),
        "missing source must not be created by ATTACH"
    );
}
