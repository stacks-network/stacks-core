// Copyright (C) 2013-2020 Blockstack PBC, a public benefit corporation
// Copyright (C) 2020-2021 Stacks Open Internet Foundation
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

use stacks_common::types::chainstate::BurnchainHeaderHash;
use stacks_common::util::hash::hex_bytes;
use stacks_common::util::vrf::*;

use crate::burnchains::affirmation::*;
use crate::burnchains::db::*;
use crate::burnchains::tests::db::*;
use crate::burnchains::{BurnchainBlockHeader, *};
use crate::chainstate::burn::operations::leader_block_commit::*;
use crate::chainstate::burn::operations::*;
use crate::chainstate::coordinator::tests::*;

fn make_test_pox(
    cycle_len: u32,
    prepare_len: u32,
    anchor_thresh: u32,
    rejection_frac: u64,
) -> PoxConstants {
    PoxConstants::new(
        cycle_len,
        prepare_len,
        anchor_thresh,
        rejection_frac,
        0,
        u64::MAX - 1,
        u64::MAX,
        u32::MAX,
        u32::MAX,
        u32::MAX,
        u32::MAX,
    )
}

#[test]
fn affirmation_map_encode_decode() {
    assert_eq!(AffirmationMap::decode(""), Some(AffirmationMap::empty()));
    assert_eq!(
        AffirmationMap::decode("anp"),
        Some(AffirmationMap::new(vec![
            AffirmationMapEntry::PoxAnchorBlockAbsent,
            AffirmationMapEntry::Nothing,
            AffirmationMapEntry::PoxAnchorBlockPresent
        ]))
    );
    assert_eq!(AffirmationMap::decode("x"), None);
    assert_eq!(AffirmationMap::decode("\u{0101}"), None);

    assert_eq!(AffirmationMap::empty().encode(), "".to_string());
    assert_eq!(
        AffirmationMap::new(vec![
            AffirmationMapEntry::PoxAnchorBlockAbsent,
            AffirmationMapEntry::Nothing,
            AffirmationMapEntry::PoxAnchorBlockPresent
        ])
        .encode(),
        "anp".to_string()
    );
}

#[test]
fn affirmation_map_find_divergence() {
    assert_eq!(
        AffirmationMap::decode("aaa")
            .unwrap()
            .find_divergence(&AffirmationMap::decode("aaa").unwrap()),
        None
    );
    assert_eq!(
        AffirmationMap::decode("aaa")
            .unwrap()
            .find_divergence(&AffirmationMap::decode("aaaa").unwrap()),
        Some(3)
    );
    assert_eq!(
        AffirmationMap::decode("aaa")
            .unwrap()
            .find_divergence(&AffirmationMap::decode("aa").unwrap()),
        None
    );
    assert_eq!(
        AffirmationMap::decode("apa")
            .unwrap()
            .find_divergence(&AffirmationMap::decode("aaa").unwrap()),
        Some(1)
    );
    assert_eq!(
        AffirmationMap::decode("apa")
            .unwrap()
            .find_divergence(&AffirmationMap::decode("aaaa").unwrap()),
        Some(1)
    );
    assert_eq!(
        AffirmationMap::decode("naa")
            .unwrap()
            .find_divergence(&AffirmationMap::decode("aa").unwrap()),
        Some(0)
    );
    assert_eq!(
        AffirmationMap::decode("napn")
            .unwrap()
            .find_divergence(&AffirmationMap::decode("").unwrap()),
        None
    );
    assert_eq!(
        AffirmationMap::decode("pn")
            .unwrap()
            .find_divergence(&AffirmationMap::decode("n").unwrap()),
        Some(0)
    );
}

#[test]
fn affirmation_map_find_inv_search() {
    assert_eq!(
        AffirmationMap::decode("aaa")
            .unwrap()
            .find_inv_search(&AffirmationMap::decode("aaa").unwrap()),
        0
    );
    assert_eq!(
        AffirmationMap::decode("aaa")
            .unwrap()
            .find_inv_search(&AffirmationMap::decode("aaaa").unwrap()),
        0
    );
    assert_eq!(
        AffirmationMap::decode("aaa")
            .unwrap()
            .find_inv_search(&AffirmationMap::decode("aa").unwrap()),
        0
    );
    assert_eq!(
        AffirmationMap::decode("apa")
            .unwrap()
            .find_inv_search(&AffirmationMap::decode("aaa").unwrap()),
        0
    );
    assert_eq!(
        AffirmationMap::decode("apa")
            .unwrap()
            .find_inv_search(&AffirmationMap::decode("aaaa").unwrap()),
        0
    );
    assert_eq!(
        AffirmationMap::decode("naa")
            .unwrap()
            .find_inv_search(&AffirmationMap::decode("aa").unwrap()),
        0
    );
    assert_eq!(
        AffirmationMap::decode("napn")
            .unwrap()
            .find_inv_search(&AffirmationMap::decode("").unwrap()),
        0
    );
    assert_eq!(
        AffirmationMap::decode("pn")
            .unwrap()
            .find_inv_search(&AffirmationMap::decode("n").unwrap()),
        0
    );
    assert_eq!(
        AffirmationMap::decode("paap")
            .unwrap()
            .find_inv_search(&AffirmationMap::decode("pap").unwrap()),
        1
    );
    assert_eq!(
        AffirmationMap::decode("paap")
            .unwrap()
            .find_inv_search(&AffirmationMap::decode("paap").unwrap()),
        3
    );
    assert_eq!(
        AffirmationMap::decode("papa")
            .unwrap()
            .find_inv_search(&AffirmationMap::decode("apap").unwrap()),
        0
    );
    assert_eq!(
        AffirmationMap::decode("paapapap")
            .unwrap()
            .find_inv_search(&AffirmationMap::decode("paappapa").unwrap()),
        4
    );
    assert_eq!(
        AffirmationMap::decode("aaaaa")
            .unwrap()
            .find_inv_search(&AffirmationMap::decode("aaaaa").unwrap()),
        0
    );
}

pub fn make_simple_key_register(
    burn_header_hash: &BurnchainHeaderHash,
    block_height: u64,
    vtxindex: u32,
) -> LeaderKeyRegisterOp {
    LeaderKeyRegisterOp {
        consensus_hash: ConsensusHash::from_bytes(
            &hex_bytes("2222222222222222222222222222222222222222").unwrap(),
        )
        .unwrap(),
        public_key: VRFPublicKey::from_bytes(
            &hex_bytes("a366b51292bef4edd64063d9145c617fec373bceb0758e98cd72becd84d54c7a").unwrap(),
        )
        .unwrap(),
        memo: vec![1, 2, 3, 4, 5],

        txid: next_txid(),
        vtxindex,
        block_height,
        burn_header_hash: burn_header_hash.clone(),
    }
}

/// Create a mock reward cycle with a particular anchor block vote outcome -- it either confirms or
/// does not confirm an anchor block.  The method returns the data for all new mocked blocks
/// created -- it returns the list of new block headers, and for each new block, it returns the
/// list of block-commits created (if any).  In addition, the `headers` argument will be grown to
/// include the new block-headers (so that a succession of calls to this method will grow the given
/// headers argument).  The list of headers returned (first tuple item) is in 1-to-1 correspondence
/// with the list of lists of block-commits returned (second tuple item).  If the ith item in
/// parent_commits is None, then all the block-commits in the ith list of lists of block-commits
/// will be None.
///
/// The caller can control how many block-commits get produced per block with the `parent_commits`
/// argument.  If parent_commits[i] is Some(..), then a sequence of block-commits will be produced
/// that descend from it.
///
/// If `confirm_anchor_block` is true, then the prepare-phase of the reward cycle will confirm an
/// anchor block -- there will be sufficiently many confirmations placed on a block-commit in the
/// reward phase.  Otherwise, enough preapre-phase blocks will be missing block-commits that no
/// anchor block is selected.
///
/// All block-commits produced reference the given miner key (given in the `key` argument).  All
/// block-commits created, as well as all block headers, will be stored to the given burnchain
/// database (in addition to being returned).
pub fn make_reward_cycle_with_vote(
    burnchain_db: &mut BurnchainDB,
    burnchain: &Burnchain,
    key: &LeaderKeyRegisterOp,
    headers: &mut Vec<BurnchainBlockHeader>,
    mut parent_commits: Vec<Option<LeaderBlockCommitOp>>,
    confirm_anchor_block: bool,
) -> (
    Vec<BurnchainBlockHeader>,
    Vec<Vec<Option<LeaderBlockCommitOp>>>,
) {
    let mut new_headers = vec![];
    let mut new_commits = vec![];

    let first_block_header = burnchain_db.get_first_header().unwrap();
    let mut current_header = burnchain_db.get_canonical_chain_tip().unwrap();
    let mut height = current_header.block_height + 1;
    let mut parent_block_header: Option<BurnchainBlockHeader> =
        Some(headers.last().unwrap().to_owned());

    for i in 0..burnchain.pox_constants.reward_cycle_length {
        let block_header = BurnchainBlockHeader {
            block_height: height,
            block_hash: next_burn_header_hash(),
            parent_block_hash: parent_block_header
                .as_ref()
                .map(|blk| blk.block_hash.clone())
                .unwrap_or(first_block_header.block_hash.clone()),
            num_txs: parent_commits.len() as u64,
            timestamp: i as u64,
        };

        let ops = if current_header == first_block_header {
            // first-ever block -- add only the leader key
            let mut key_insert = key.clone();
            key_insert.burn_header_hash = block_header.block_hash.clone();

            test_debug!(
                "Insert key-register in {}: {},{},{} in block {}",
                &key_insert.burn_header_hash,
                &key_insert.txid,
                key_insert.block_height,
                key_insert.vtxindex,
                block_header.block_height
            );

            new_commits.push(vec![None; parent_commits.len()]);
            vec![BlockstackOperationType::LeaderKeyRegister(
                key_insert.clone(),
            )]
        } else {
            let mut commits = vec![];
            for i in 0..parent_commits.len() {
                let mut block_commit = make_simple_block_commit(
                    burnchain,
                    parent_commits[i].as_ref(),
                    &block_header,
                    next_block_hash(),
                );
                block_commit.key_block_ptr = key.block_height as u32;
                block_commit.key_vtxindex = key.vtxindex as u16;
                block_commit.vtxindex += i as u32;
                block_commit.burn_parent_modulus = if height > 0 {
                    ((height - 1) % BURN_BLOCK_MINED_AT_MODULUS) as u8
                } else {
                    BURN_BLOCK_MINED_AT_MODULUS as u8 - 1
                };

                assert_eq!(block_commit.burn_header_hash, block_header.block_hash);
                assert_eq!(block_commit.block_height, block_header.block_height);

                let append = if !burnchain.is_in_prepare_phase(block_commit.block_height) {
                    // non-prepare-phase commits always confirm their parent
                    true
                } else if confirm_anchor_block {
                    // all block-commits confirm anchor block
                    true
                } else {
                    // fewer than anchor_threshold commits confirm anchor block
                    let next_rc_start = burnchain.reward_cycle_to_block_height(
                        burnchain
                            .block_height_to_reward_cycle(block_commit.block_height)
                            .unwrap()
                            + 1,
                    );
                    if block_commit.block_height
                        + (burnchain.pox_constants.anchor_threshold as u64)
                        + 1
                        < next_rc_start
                    {
                        // in first half of prepare phase, so confirm
                        true
                    } else {
                        // in second half of prepare phase, so don't confirm
                        false
                    }
                };

                if append {
                    test_debug!(
                        "Insert block-commit in {}: {},{},{}, builds on {},{}",
                        &block_commit.burn_header_hash,
                        &block_commit.txid,
                        block_commit.block_height,
                        block_commit.vtxindex,
                        block_commit.parent_block_ptr,
                        block_commit.parent_vtxindex
                    );

                    if let Some(parent_commit) = parent_commits[i].as_ref() {
                        assert!(parent_commit.block_height != block_commit.block_height);
                        assert!(
                            parent_commit.block_height == u64::from(block_commit.parent_block_ptr)
                        );
                        assert!(parent_commit.vtxindex == u32::from(block_commit.parent_vtxindex));
                    }

                    parent_commits[i] = Some(block_commit.clone());
                    commits.push(Some(block_commit.clone()));
                } else {
                    test_debug!(
                        "Do NOT insert block-commit in {}: {},{},{}",
                        &block_commit.burn_header_hash,
                        &block_commit.txid,
                        block_commit.block_height,
                        block_commit.vtxindex
                    );

                    commits.push(None);
                }
            }
            new_commits.push(commits.clone());
            commits
                .into_iter()
                .flatten()
                .map(BlockstackOperationType::LeaderBlockCommit)
                .collect()
        };

        burnchain_db
            .store_new_burnchain_block_ops_unchecked(burnchain, headers, &block_header, &ops)
            .unwrap();

        headers.push(block_header.clone());
        new_headers.push(block_header.clone());
        parent_block_header = Some(block_header);

        current_header = burnchain_db.get_canonical_chain_tip().unwrap();
        height = current_header.block_height + 1;
    }

    (new_headers, new_commits)
}

/// Conveninece wrapper that produces a reward cycle with one sequence of block-commits.  Returns
/// the sequence of block headers in this reward cycle, and the list of block-commits created.  If
/// parent_commit is None, then the list of block-commits will contain all None's.
fn make_simple_reward_cycle(
    burnchain_db: &mut BurnchainDB,
    burnchain: &Burnchain,
    key: &LeaderKeyRegisterOp,
    headers: &mut Vec<BurnchainBlockHeader>,
    parent_commit: Option<LeaderBlockCommitOp>,
) -> (Vec<BurnchainBlockHeader>, Vec<Option<LeaderBlockCommitOp>>) {
    let (new_headers, commits) =
        make_reward_cycle(burnchain_db, burnchain, key, headers, vec![parent_commit]);
    (
        new_headers,
        commits
            .into_iter()
            .map(|mut cmts| cmts.pop().unwrap())
            .collect(),
    )
}

/// Convenience wrapper that produces a reward cycle with zero or more sequences of block-commits,
/// such that an anchor block-commit is chosen.
/// Returns the list of new block headers and each blocks' commits.
pub fn make_reward_cycle(
    burnchain_db: &mut BurnchainDB,
    burnchain: &Burnchain,
    key: &LeaderKeyRegisterOp,
    headers: &mut Vec<BurnchainBlockHeader>,
    parent_commits: Vec<Option<LeaderBlockCommitOp>>,
) -> (
    Vec<BurnchainBlockHeader>,
    Vec<Vec<Option<LeaderBlockCommitOp>>>,
) {
    make_reward_cycle_with_vote(burnchain_db, burnchain, key, headers, parent_commits, true)
}

/// Convenience wrapper that produces a reward cycle with zero or more sequences of block-commits,
/// such that no anchor block-commit is chosen.
/// Returns the list of new block headers and each blocks' commits.
pub fn make_reward_cycle_without_anchor(
    burnchain_db: &mut BurnchainDB,
    burnchain: &Burnchain,
    key: &LeaderKeyRegisterOp,
    headers: &mut Vec<BurnchainBlockHeader>,
    parent_commits: Vec<Option<LeaderBlockCommitOp>>,
) -> (
    Vec<BurnchainBlockHeader>,
    Vec<Vec<Option<LeaderBlockCommitOp>>>,
) {
    make_reward_cycle_with_vote(burnchain_db, burnchain, key, headers, parent_commits, false)
}

#[test]
fn test_read_prepare_phase_commits() {
    let first_bhh = BurnchainHeaderHash([0; 32]);
    let first_timestamp = 0;
    let first_height = 0;

    let mut burnchain = Burnchain::regtest(":memory:");
    burnchain.pox_constants = make_test_pox(10, 5, 3, 3);
    burnchain.first_block_height = first_height;
    burnchain.first_block_hash = first_bhh.clone();
    burnchain.first_block_timestamp = first_timestamp;

    let mut burnchain_db = BurnchainDB::connect(":memory:", &burnchain, true).unwrap();

    let first_block_header = burnchain_db.get_canonical_chain_tip().unwrap();
    assert_eq!(&first_block_header.block_hash, &first_bhh);
    assert_eq!(first_block_header.block_height, first_height);
    assert_eq!(first_block_header.timestamp, first_timestamp as u64);

    eprintln!(
        "First block parent is {}",
        &first_block_header.parent_block_hash
    );

    let mut headers = vec![first_block_header.clone()];
    let key_register = make_simple_key_register(&first_block_header.block_hash, 0, 1);
    let (next_headers, commits) = make_simple_reward_cycle(
        &mut burnchain_db,
        &burnchain,
        &key_register,
        &mut headers,
        None,
    );

    assert_eq!(
        commits.len() as u32,
        burnchain.pox_constants.reward_cycle_length
    );
    assert!(commits[0].is_none());
    for i in 1..burnchain.pox_constants.reward_cycle_length {
        assert!(commits[i as usize].is_some());
    }

    let all_ops = read_prepare_phase_commits(
        &burnchain_db.tx_begin().unwrap(),
        &headers,
        &burnchain.pox_constants,
        first_block_header.block_height,
        0,
    )
    .unwrap();
    assert_eq!(all_ops.len() as u32, burnchain.pox_constants.prepare_length);
    for i in 0..burnchain.pox_constants.prepare_length {
        assert_eq!(all_ops[i as usize].len(), 1);

        let opdata = &all_ops[i as usize][0];
        assert_eq!(
            opdata,
            commits[(i + burnchain.pox_constants.reward_cycle_length
                - burnchain.pox_constants.prepare_length) as usize]
                .as_ref()
                .unwrap()
        );
    }
}

#[test]
fn test_parent_block_commits() {
    let first_bhh = BurnchainHeaderHash([0; 32]);
    let first_timestamp = 0;
    let first_height = 0;

    let mut burnchain = Burnchain::regtest(":memory:");
    burnchain.pox_constants = make_test_pox(10, 5, 3, 3);
    burnchain.first_block_height = first_height;
    burnchain.first_block_hash = first_bhh.clone();
    burnchain.first_block_timestamp = first_timestamp;

    let mut burnchain_db = BurnchainDB::connect(":memory:", &burnchain, true).unwrap();

    let first_block_header = burnchain_db.get_canonical_chain_tip().unwrap();

    let mut headers = vec![first_block_header.clone()];
    let key_register = make_simple_key_register(&first_block_header.block_hash, 0, 1);

    // first reward cycle is all (linear) commits, so it must elect an anchor block
    let (next_headers, commits) = make_simple_reward_cycle(
        &mut burnchain_db,
        &burnchain,
        &key_register,
        &mut headers,
        None,
    );

    let all_ops = read_prepare_phase_commits(
        &burnchain_db.tx_begin().unwrap(),
        &headers,
        &burnchain.pox_constants,
        first_block_header.block_height,
        0,
    )
    .unwrap();
    let parent_commits =
        read_parent_block_commits(&burnchain_db.tx_begin().unwrap(), &headers, &all_ops).unwrap();

    // this is a simple reward cycle -- each block-commit has a unique parent
    assert_eq!(parent_commits.len(), all_ops.len());

    for op_list in all_ops.iter() {
        for opdata in op_list.iter() {
            let mut found_parent = false;
            for parent_commit in parent_commits.iter() {
                if parent_commit.block_height == (opdata.parent_block_ptr as u64)
                    && parent_commit.vtxindex == (opdata.parent_vtxindex as u32)
                {
                    found_parent = true;
                    break;
                }
            }
            assert!(found_parent, "did not find parent for {:?}", opdata);
        }
    }

    let mut all_ops_with_orphan = all_ops.clone();
    all_ops_with_orphan[1][0].parent_vtxindex += 1;

    let parent_commits = read_parent_block_commits(
        &burnchain_db.tx_begin().unwrap(),
        &headers,
        &all_ops_with_orphan,
    )
    .unwrap();

    // this is a simple reward cycle -- each block-commit has a unique parent, except for the
    // orphan
    assert_eq!(parent_commits.len(), all_ops_with_orphan.len() - 1);

    let mut all_ops_with_same_parent = all_ops;
    for ops in all_ops_with_same_parent.iter_mut() {
        for opdata in ops.iter_mut() {
            opdata.parent_block_ptr = 3;
            opdata.parent_vtxindex = 0;
        }
    }

    let parent_commits = read_parent_block_commits(
        &burnchain_db.tx_begin().unwrap(),
        &headers,
        &all_ops_with_same_parent,
    )
    .unwrap();

    assert_eq!(parent_commits.len(), 1);
    assert_eq!(parent_commits[0].block_height, 3);
    assert_eq!(parent_commits[0].vtxindex, 0);
}

#[test]
fn test_filter_orphan_block_commits() {
    let first_bhh = BurnchainHeaderHash([0; 32]);
    let first_timestamp = 0;
    let first_height = 0;

    let mut burnchain = Burnchain::regtest(":memory:");
    burnchain.pox_constants = make_test_pox(5, 3, 3, 3);
    burnchain.first_block_height = first_height;
    burnchain.first_block_hash = first_bhh.clone();
    burnchain.first_block_timestamp = first_timestamp;

    let mut burnchain_db = BurnchainDB::connect(":memory:", &burnchain, true).unwrap();

    let first_block_header = burnchain_db.get_canonical_chain_tip().unwrap();

    let mut headers = vec![first_block_header.clone()];
    let key_register = make_simple_key_register(&first_block_header.block_hash, 0, 1);

    // first reward cycle is all (linear) commits, so it must elect an anchor block
    let (next_headers, commits) = make_simple_reward_cycle(
        &mut burnchain_db,
        &burnchain,
        &key_register,
        &mut headers,
        None,
    );

    let all_ops = read_prepare_phase_commits(
        &burnchain_db.tx_begin().unwrap(),
        &headers,
        &burnchain.pox_constants,
        first_block_header.block_height,
        0,
    )
    .unwrap();
    let parent_commits =
        read_parent_block_commits(&burnchain_db.tx_begin().unwrap(), &headers, &all_ops).unwrap();

    let mut all_ops_with_orphan = all_ops.clone();
    all_ops_with_orphan[1][0].parent_vtxindex += 1;

    assert_eq!(all_ops_with_orphan[0].len(), 1);
    assert_eq!(all_ops_with_orphan[1].len(), 1);
    assert_eq!(all_ops_with_orphan[2].len(), 1);

    let parent_commits = read_parent_block_commits(
        &burnchain_db.tx_begin().unwrap(),
        &headers,
        &all_ops_with_orphan,
    )
    .unwrap();
    let filtered_ops = filter_orphan_block_commits(&parent_commits, all_ops_with_orphan);

    assert_eq!(filtered_ops.len(), all_ops.len());
    assert_eq!(filtered_ops[0].len(), 1);
    assert!(filtered_ops[1].is_empty());
    assert_eq!(filtered_ops[2].len(), 1);
}

#[test]
fn test_filter_missed_block_commits() {
    let first_bhh = BurnchainHeaderHash([0; 32]);
    let first_timestamp = 0;
    let first_height = 0;

    let mut burnchain = Burnchain::regtest(":memory:");
    burnchain.pox_constants = make_test_pox(5, 3, 3, 3);
    burnchain.first_block_height = first_height;
    burnchain.first_block_hash = first_bhh.clone();
    burnchain.first_block_timestamp = first_timestamp;

    let mut burnchain_db = BurnchainDB::connect(":memory:", &burnchain, true).unwrap();

    let first_block_header = burnchain_db.get_canonical_chain_tip().unwrap();

    let mut headers = vec![first_block_header.clone()];
    let key_register = make_simple_key_register(&first_block_header.block_hash, 0, 1);

    // first reward cycle is all (linear) commits, so it must elect an anchor block
    let (next_headers, commits) = make_simple_reward_cycle(
        &mut burnchain_db,
        &burnchain,
        &key_register,
        &mut headers,
        None,
    );

    let all_ops = read_prepare_phase_commits(
        &burnchain_db.tx_begin().unwrap(),
        &headers,
        &burnchain.pox_constants,
        first_block_header.block_height,
        0,
    )
    .unwrap();
    let parent_commits =
        read_parent_block_commits(&burnchain_db.tx_begin().unwrap(), &headers, &all_ops).unwrap();

    let mut all_ops_with_missed = all_ops.clone();
    all_ops_with_missed[1][0].burn_parent_modulus -= 1;

    assert_eq!(all_ops_with_missed[0].len(), 1);
    assert_eq!(all_ops_with_missed[1].len(), 1);
    assert_eq!(all_ops_with_missed[2].len(), 1);

    let parent_commits = read_parent_block_commits(
        &burnchain_db.tx_begin().unwrap(),
        &headers,
        &all_ops_with_missed,
    )
    .unwrap();
    let filtered_ops = filter_missed_block_commits(all_ops_with_missed);

    assert_eq!(filtered_ops.len(), all_ops.len());
    assert_eq!(filtered_ops[0].len(), 1);
    assert!(filtered_ops[1].is_empty());
    assert_eq!(filtered_ops[2].len(), 1);
}

#[test]
fn test_find_heaviest_block_commit() {
    let first_bhh = BurnchainHeaderHash([0; 32]);
    let first_timestamp = 0;
    let first_height = 0;

    let mut burnchain = Burnchain::regtest(":memory:");
    burnchain.pox_constants = make_test_pox(5, 3, 2, 3);
    burnchain.first_block_height = first_height;
    burnchain.first_block_hash = first_bhh.clone();
    burnchain.first_block_timestamp = first_timestamp;

    let mut burnchain_db = BurnchainDB::connect(":memory:", &burnchain, true).unwrap();

    let first_block_header = burnchain_db.get_canonical_chain_tip().unwrap();

    let mut headers = vec![first_block_header.clone()];
    let key_register = make_simple_key_register(&first_block_header.block_hash, 0, 1);

    // first reward cycle is all (linear) commits, so it must elect an anchor block
    let (next_headers, commits) = make_simple_reward_cycle(
        &mut burnchain_db,
        &burnchain,
        &key_register,
        &mut headers,
        None,
    );

    let all_ops = read_prepare_phase_commits(
        &burnchain_db.tx_begin().unwrap(),
        &headers,
        &burnchain.pox_constants,
        first_block_header.block_height,
        0,
    )
    .unwrap();
    let parent_commits =
        read_parent_block_commits(&burnchain_db.tx_begin().unwrap(), &headers, &all_ops).unwrap();
    let filtered_ops = filter_orphan_block_commits(&parent_commits, all_ops);

    let heaviest_parent_commit_opt = find_heaviest_block_commit(
        &burnchain_db.tx_begin().unwrap(),
        &headers,
        &filtered_ops,
        burnchain.pox_constants.anchor_threshold,
    )
    .unwrap();
    assert!(heaviest_parent_commit_opt.is_some());
    let (heaviest_parent_block_commit, descendancy, total_confs, total_burns) =
        heaviest_parent_commit_opt.unwrap();

    // since this is just a linear chain of block-commits, the heaviest parent is the parent of the
    // first block-commit in the prepare phase
    assert_eq!(commits[1].as_ref().unwrap(), &heaviest_parent_block_commit);
    assert_eq!(descendancy, vec![vec![true], vec![true], vec![true]]);
    assert_eq!(total_confs, 3);
    assert_eq!(total_burns, 3 * 10000);

    // make a forked history, but with a best-tip
    // 1,0 <-- 2,0 <-- 3,0 <-- 4,0
    //  \
    //   `---------------------------- 5,0
    let mut all_ops_forked_majority = filtered_ops.clone();
    all_ops_forked_majority[2][0].parent_block_ptr = 1;
    all_ops_forked_majority[2][0].parent_vtxindex = 0;

    // still commit 1
    let heaviest_parent_commit_opt = find_heaviest_block_commit(
        &burnchain_db.tx_begin().unwrap(),
        &headers,
        &all_ops_forked_majority,
        burnchain.pox_constants.anchor_threshold,
    )
    .unwrap();
    assert!(heaviest_parent_commit_opt.is_some());
    let (heaviest_parent_block_commit, descendancy, total_confs, total_burns) =
        heaviest_parent_commit_opt.unwrap();

    assert_eq!(commits[1].as_ref().unwrap(), &heaviest_parent_block_commit);
    assert_eq!(descendancy, vec![vec![true], vec![true], vec![false]]);
    assert_eq!(total_confs, 2);
    assert_eq!(total_burns, 2 * 10000);

    // make a forked history, with another best-tip winner, but with a deeper fork split
    // 1,0 <-- 2,0 <-- 3,0
    //           \
    //            `------- 4,0 <-- 5,0
    let mut all_ops_forked_majority = filtered_ops.clone();
    all_ops_forked_majority[1][0].parent_block_ptr = 2;
    all_ops_forked_majority[1][0].parent_vtxindex = 0;

    all_ops_forked_majority[2][0].parent_block_ptr = 2;
    all_ops_forked_majority[2][0].parent_vtxindex = 0;

    // still commit 1
    let heaviest_parent_commit_opt = find_heaviest_block_commit(
        &burnchain_db.tx_begin().unwrap(),
        &headers,
        &all_ops_forked_majority,
        burnchain.pox_constants.anchor_threshold,
    )
    .unwrap();
    assert!(heaviest_parent_commit_opt.is_some());
    let (heaviest_parent_block_commit, descendancy, total_confs, total_burns) =
        heaviest_parent_commit_opt.unwrap();

    assert_eq!(commits[1].as_ref().unwrap(), &heaviest_parent_block_commit);
    assert_eq!(descendancy, vec![vec![true], vec![true], vec![true]]);
    assert_eq!(total_confs, 3);
    assert_eq!(total_burns, 3 * 10000);

    // make a forked history where there is no best tip, but enough confirmations
    // 1,0 <-- 2,0 <-- 3,0
    //          |\
    //          | `------- 4,0
    //          \
    //           `------------- 5,0
    let mut all_ops_no_majority = filtered_ops.clone();
    all_ops_no_majority[0][0].parent_block_ptr = 2;
    all_ops_no_majority[0][0].parent_vtxindex = 0;
    all_ops_no_majority[0][0].burn_fee = 0;

    all_ops_no_majority[1][0].parent_block_ptr = 2;
    all_ops_no_majority[1][0].parent_vtxindex = 0;
    all_ops_no_majority[1][0].burn_fee = 1;

    all_ops_no_majority[2][0].parent_block_ptr = 2;
    all_ops_no_majority[2][0].parent_vtxindex = 0;
    all_ops_no_majority[2][0].burn_fee = 2;

    let heaviest_parent_commit_opt = find_heaviest_block_commit(
        &burnchain_db.tx_begin().unwrap(),
        &headers,
        &all_ops_no_majority,
        burnchain.pox_constants.anchor_threshold,
    )
    .unwrap();
    assert!(heaviest_parent_commit_opt.is_some());
    let (heaviest_parent_block_commit, descendancy, total_confs, total_burns) =
        heaviest_parent_commit_opt.unwrap();

    assert_eq!(commits[1].as_ref().unwrap(), &heaviest_parent_block_commit);
    assert_eq!(descendancy, vec![vec![true], vec![true], vec![true]]);
    assert_eq!(total_confs, 3);
    assert_eq!(total_burns, 1 + 2);

    // make a forked history where there is no best tip, but enough (majority) confirmations
    // 1,0 <-- 2,0 <-- 3,0
    //  |        \
    //  |         `-------- 4,0
    //  |
    //  `----------------------- 5,0
    let mut all_ops_no_majority = filtered_ops.clone();
    all_ops_no_majority[0][0].parent_block_ptr = 2;
    all_ops_no_majority[0][0].parent_vtxindex = 0;
    all_ops_no_majority[0][0].burn_fee = 0;

    all_ops_no_majority[1][0].parent_block_ptr = 2;
    all_ops_no_majority[1][0].parent_vtxindex = 0;
    all_ops_no_majority[1][0].burn_fee = 1;

    all_ops_no_majority[2][0].parent_block_ptr = 1;
    all_ops_no_majority[2][0].parent_vtxindex = 0;
    all_ops_no_majority[2][0].burn_fee = 20;

    let heaviest_parent_commit_opt = find_heaviest_block_commit(
        &burnchain_db.tx_begin().unwrap(),
        &headers,
        &all_ops_no_majority,
        burnchain.pox_constants.anchor_threshold,
    )
    .unwrap();
    assert!(heaviest_parent_commit_opt.is_some());
    let (heaviest_parent_block_commit, descendancy, total_confs, total_burns) =
        heaviest_parent_commit_opt.unwrap();

    assert_eq!(commits[1].as_ref().unwrap(), &heaviest_parent_block_commit);
    assert_eq!(descendancy, vec![vec![true], vec![true], vec![false]]);
    assert_eq!(total_confs, 2);
    assert_eq!(total_burns, 1);

    // make a history where there is no anchor block, period
    // 1,0 <-- 2,0 X-- 3,0
    //
    //             X------- 4,0
    //
    //             X------------ 5,0
    let mut all_ops_no_majority = filtered_ops;
    all_ops_no_majority[0][0].parent_block_ptr = 2;
    all_ops_no_majority[0][0].parent_vtxindex = 10;
    all_ops_no_majority[0][0].burn_fee = 0;

    all_ops_no_majority[1][0].parent_block_ptr = 2;
    all_ops_no_majority[1][0].parent_vtxindex = 10;
    all_ops_no_majority[1][0].burn_fee = 1;

    all_ops_no_majority[2][0].parent_block_ptr = 1;
    all_ops_no_majority[2][0].parent_vtxindex = 10;
    all_ops_no_majority[2][0].burn_fee = 20;

    let heaviest_parent_commit_opt = find_heaviest_block_commit(
        &burnchain_db.tx_begin().unwrap(),
        &headers,
        &all_ops_no_majority,
        burnchain.pox_constants.anchor_threshold,
    )
    .unwrap();
    assert!(heaviest_parent_commit_opt.is_none());
}

#[test]
fn test_find_heaviest_parent_commit_many_commits() {
    // Test finding parent block commits when there's multiple block-commit forks to choose from.
    // This tests the tie-breaking logic.
    let first_bhh = BurnchainHeaderHash([0; 32]);
    let first_timestamp = 0;
    let first_height = 0;

    let mut burnchain = Burnchain::regtest(":memory:");
    burnchain.pox_constants = make_test_pox(5, 3, 2, 3);
    burnchain.first_block_height = first_height;
    burnchain.first_block_hash = first_bhh.clone();
    burnchain.first_block_timestamp = first_timestamp;

    let mut burnchain_db = BurnchainDB::connect(":memory:", &burnchain, true).unwrap();

    let first_block_header = burnchain_db.get_canonical_chain_tip().unwrap();

    let mut headers = vec![first_block_header.clone()];
    let key_register = make_simple_key_register(&first_block_header.block_hash, 0, 1);

    let (next_headers, commits) = make_reward_cycle(
        &mut burnchain_db,
        &burnchain,
        &key_register,
        &mut headers,
        vec![None, None],
    );

    let all_ops = read_prepare_phase_commits(
        &burnchain_db.tx_begin().unwrap(),
        &headers,
        &burnchain.pox_constants,
        first_block_header.block_height,
        0,
    )
    .unwrap();
    let parent_commits =
        read_parent_block_commits(&burnchain_db.tx_begin().unwrap(), &headers, &all_ops).unwrap();
    let filtered_ops = filter_orphan_block_commits(&parent_commits, all_ops);

    // make a history with two miners' commits.
    // sortition winners in prepare phase were 3,0; 4,1; 5,0
    // 1,0 <-- 2,0 <--- 3,0 <--- 4,0 ,--- 5,0
    //           \         \        /
    //            `---- 3,1 `--- 4,1 <--- 5,1
    let mut all_ops_no_majority = filtered_ops.clone();

    // 3,0
    all_ops_no_majority[0][0].parent_block_ptr = 2;
    all_ops_no_majority[0][0].parent_vtxindex = 0;
    all_ops_no_majority[0][0].vtxindex = 0;
    all_ops_no_majority[0][0].burn_fee = 1;

    // 3,1
    all_ops_no_majority[0][1].parent_block_ptr = 2;
    all_ops_no_majority[0][1].parent_vtxindex = 0;
    all_ops_no_majority[0][1].vtxindex = 1;
    all_ops_no_majority[0][1].burn_fee = 1;

    // 4,0
    all_ops_no_majority[1][0].parent_block_ptr = 3;
    all_ops_no_majority[1][0].parent_vtxindex = 0;
    all_ops_no_majority[1][0].vtxindex = 0;
    all_ops_no_majority[1][0].burn_fee = 2;

    // 4,1
    all_ops_no_majority[1][1].parent_block_ptr = 3;
    all_ops_no_majority[1][1].parent_vtxindex = 0;
    all_ops_no_majority[1][1].vtxindex = 1;
    all_ops_no_majority[1][1].burn_fee = 2;

    // 5,0
    all_ops_no_majority[2][0].parent_block_ptr = 4;
    all_ops_no_majority[2][0].parent_vtxindex = 1;
    all_ops_no_majority[2][0].vtxindex = 0;
    all_ops_no_majority[2][0].burn_fee = 3;

    // 5,1
    all_ops_no_majority[2][1].parent_block_ptr = 4;
    all_ops_no_majority[2][1].parent_vtxindex = 1;
    all_ops_no_majority[2][1].vtxindex = 1;
    all_ops_no_majority[2][1].burn_fee = 3;

    let heaviest_parent_commit_opt = find_heaviest_block_commit(
        &burnchain_db.tx_begin().unwrap(),
        &headers,
        &all_ops_no_majority,
        burnchain.pox_constants.anchor_threshold,
    )
    .unwrap();
    assert!(heaviest_parent_commit_opt.is_some());
    let (heaviest_parent_block_commit, descendancy, total_confs, total_burns) =
        heaviest_parent_commit_opt.unwrap();

    assert_eq!(
        commits[1][0].as_ref().unwrap(),
        &heaviest_parent_block_commit
    );
    assert_eq!(
        descendancy,
        vec![vec![true, true], vec![true, true], vec![true, true]]
    );
    assert_eq!(total_confs, 3);
    assert_eq!(total_burns, 1 + 1 + 2 + 2 + 3 + 3);

    // make a history with two miners' commits
    // both histories have the same number of confirmations.
    // one history represents more BTC than the other.
    // 1,0 <-- 2,0 <--- 3,0 <--- 4,0 <--- 5,0 (winner)
    //  \
    //   `---- 2,1 <--- 3,1 <--- 4,1 <--- 5,1
    let mut all_ops_no_majority = filtered_ops.clone();

    // 3,0
    all_ops_no_majority[0][0].parent_block_ptr = 2;
    all_ops_no_majority[0][0].parent_vtxindex = 0;
    all_ops_no_majority[0][0].vtxindex = 0;
    all_ops_no_majority[0][0].burn_fee = 1;

    // 3,1
    all_ops_no_majority[0][1].parent_block_ptr = 2;
    all_ops_no_majority[0][1].parent_vtxindex = 1;
    all_ops_no_majority[0][1].vtxindex = 1;
    all_ops_no_majority[0][1].burn_fee = 1;

    // 4,0
    all_ops_no_majority[1][0].parent_block_ptr = 3;
    all_ops_no_majority[1][0].parent_vtxindex = 0;
    all_ops_no_majority[1][0].vtxindex = 0;
    all_ops_no_majority[1][0].burn_fee = 2;

    // 4,1
    all_ops_no_majority[1][1].parent_block_ptr = 3;
    all_ops_no_majority[1][1].parent_vtxindex = 1;
    all_ops_no_majority[1][1].vtxindex = 1;
    all_ops_no_majority[1][1].burn_fee = 2;

    // 5,0 -- slightly heavier than 5,1
    all_ops_no_majority[2][0].parent_block_ptr = 4;
    all_ops_no_majority[2][0].parent_vtxindex = 0;
    all_ops_no_majority[2][0].vtxindex = 0;
    all_ops_no_majority[2][0].burn_fee = 4;

    // 5,1
    all_ops_no_majority[2][1].parent_block_ptr = 4;
    all_ops_no_majority[2][1].parent_vtxindex = 1;
    all_ops_no_majority[2][1].vtxindex = 1;
    all_ops_no_majority[2][1].burn_fee = 3;

    let heaviest_parent_commit_opt = find_heaviest_block_commit(
        &burnchain_db.tx_begin().unwrap(),
        &headers,
        &all_ops_no_majority,
        burnchain.pox_constants.anchor_threshold,
    )
    .unwrap();
    assert!(heaviest_parent_commit_opt.is_some());
    let (heaviest_parent_block_commit, descendancy, total_confs, total_burns) =
        heaviest_parent_commit_opt.unwrap();

    // either 2,0 or 2,1 is the anchor block, but we break ties in part by weight.
    // 5,0 is heavier than 5,1, so 2,0 wins
    assert_eq!(
        commits[1][0].as_ref().unwrap(),
        &heaviest_parent_block_commit
    );
    // prepare-phase commits x,0 all descend from the anchor block.
    // prepare-phase commits x,1 do not.
    assert_eq!(
        descendancy,
        vec![vec![true, false], vec![true, false], vec![true, false]]
    );
    assert_eq!(total_confs, 3);
    assert_eq!(total_burns, 1 + 2 + 4);

    // make a history with two miners' commits
    // both histories have the same amount of confirmations and BTC burnt.
    // select the anchor block with the latest confirmation to break ties.
    // 1,0 <-- 2,0 <--- 3,0 <--- 4,0 <--- 5,0
    //  \
    //   `---- 2,1 <--- 3,1 <--- 4,1 <--- 5,1 (winner)
    let mut all_ops_no_majority = filtered_ops;

    // 3,0
    all_ops_no_majority[0][0].parent_block_ptr = 2;
    all_ops_no_majority[0][0].parent_vtxindex = 0;
    all_ops_no_majority[0][0].vtxindex = 0;
    all_ops_no_majority[0][0].burn_fee = 1;

    // 3,1
    all_ops_no_majority[0][1].parent_block_ptr = 2;
    all_ops_no_majority[0][1].parent_vtxindex = 1;
    all_ops_no_majority[0][1].vtxindex = 1;
    all_ops_no_majority[0][1].burn_fee = 1;

    // 4,0
    all_ops_no_majority[1][0].parent_block_ptr = 3;
    all_ops_no_majority[1][0].parent_vtxindex = 0;
    all_ops_no_majority[1][0].vtxindex = 0;
    all_ops_no_majority[1][0].burn_fee = 2;

    // 4,1
    all_ops_no_majority[1][1].parent_block_ptr = 3;
    all_ops_no_majority[1][1].parent_vtxindex = 1;
    all_ops_no_majority[1][1].vtxindex = 1;
    all_ops_no_majority[1][1].burn_fee = 2;

    // 5,0
    all_ops_no_majority[2][0].parent_block_ptr = 4;
    all_ops_no_majority[2][0].parent_vtxindex = 0;
    all_ops_no_majority[2][0].vtxindex = 0;
    all_ops_no_majority[2][0].burn_fee = 3;

    // 5,1 -- same BTC overall as the history ending at 5,0, but occurs later in the blockchain
    all_ops_no_majority[2][1].parent_block_ptr = 4;
    all_ops_no_majority[2][1].parent_vtxindex = 1;
    all_ops_no_majority[2][1].vtxindex = 1;
    all_ops_no_majority[2][1].burn_fee = 3;

    let heaviest_parent_commit_opt = find_heaviest_block_commit(
        &burnchain_db.tx_begin().unwrap(),
        &headers,
        &all_ops_no_majority,
        burnchain.pox_constants.anchor_threshold,
    )
    .unwrap();
    assert!(heaviest_parent_commit_opt.is_some());
    let (heaviest_parent_block_commit, descendancy, total_confs, total_burns) =
        heaviest_parent_commit_opt.unwrap();

    // number of confirmations and BTC amount are the same in the two fork histories, so break ties
    // by choosing the anchor block confirmed by the latest commit.
    assert_eq!(
        commits[1][1].as_ref().unwrap(),
        &heaviest_parent_block_commit
    );
    // prepare-phase commits x,0 do not descend from an anchor block
    // prepare-phase commits x,1 do
    assert_eq!(
        descendancy,
        vec![vec![false, true], vec![false, true], vec![false, true]]
    );
    assert_eq!(total_confs, 3);
    assert_eq!(total_burns, 1 + 2 + 3);
}
