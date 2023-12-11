use std::collections::HashMap;

use stacks_common::{types::{StacksEpochId, chainstate::{BlockHeaderHash, PoxId, BurnchainHeaderHash, SortitionId, ConsensusHash, StacksBlockId}}, util::hash::Sha512Trunc256Sum};

use crate::{burnchains::Txid, chainstate::{coordinator::RewardCycleInfo, burn::{db::sortdb::BlockHeaderCache, BlockSnapshot}}};

pub fn parse_last_anchor_block_hash(s: Option<String>) -> Option<BlockHeaderHash> {
    s.map(|s| {
        if s == "" {
            None
        } else {
            Some(BlockHeaderHash::from_hex(&s).expect("BUG: Bad BlockHeaderHash stored in DB"))
        }
    })
    .flatten()
}

pub fn parse_last_anchor_block_txid(s: Option<String>) -> Option<Txid> {
    s.map(|s| {
        if s == "" {
            None
        } else {
            Some(Txid::from_hex(&s).expect("BUG: Bad Txid stored in DB"))
        }
    })
    .flatten()
}

/// Compute the next PoX ID
pub fn make_next_pox_id(parent_pox: PoxId, next_pox_info: Option<&RewardCycleInfo>) -> PoxId {
    let mut next_pox = parent_pox;
    if let Some(ref next_pox_info) = next_pox_info {
        if next_pox_info.is_reward_info_known() {
            info!(
                "Begin reward-cycle sortition with present anchor block={:?}",
                &next_pox_info.selected_anchor_block(),
            );
            next_pox.extend_with_present_block();
        } else {
            info!(
                "Begin reward-cycle sortition with absent anchor block={:?}",
                &next_pox_info.selected_anchor_block(),
            );
            next_pox.extend_with_not_present_block();
        }
    };
    next_pox
}

/// Merge the result of get_stacks_header_hashes() into a BlockHeaderCache
pub fn merge_block_header_cache(
    cache: &mut BlockHeaderCache,
    header_data: &Vec<(ConsensusHash, Option<BlockHeaderHash>)>,
) -> () {
    if header_data.len() > 0 {
        let mut i = header_data.len() - 1;
        while i > 0 {
            let cur_consensus_hash = &header_data[i].0;
            let cur_block_opt = &header_data[i].1;

            if let Some((ref cached_block_opt, _)) = cache.get(cur_consensus_hash) {
                assert_eq!(cached_block_opt, cur_block_opt);
            } else {
                let prev_consensus_hash = header_data[i - 1].0.clone();
                cache.insert(
                    (*cur_consensus_hash).clone(),
                    ((*cur_block_opt).clone(), prev_consensus_hash.clone()),
                );
            }

            i -= 1;
        }
    }
    debug!("Block header cache has {} items", cache.len());
}

/// Resolve ties between blocks at the same height.
/// Hashes the given snapshot's sortition hash with the index block hash for each block
/// (calculated from `new_block_arrivals`' consensus hash and block header hash), and chooses
/// the block in `new_block_arrivals` whose resulting hash is lexographically the smallest.
/// Returns the index into `new_block_arrivals` for the block whose hash is the smallest.
pub fn break_canonical_stacks_tip_tie(
    tip: &BlockSnapshot,
    best_height: u64,
    new_block_arrivals: &[(ConsensusHash, BlockHeaderHash, u64)],
) -> Option<usize> {
    // if there's a tie, then randomly and deterministically pick one
    let mut tied = vec![];
    for (i, (consensus_hash, block_bhh, height)) in new_block_arrivals.iter().enumerate() {
        if best_height == *height {
            tied.push((StacksBlockId::new(consensus_hash, block_bhh), i));
        }
    }

    if tied.len() == 0 {
        return None;
    }
    if tied.len() == 1 {
        return Some(tied[0].1);
    }

    // break ties by hashing the index block hash with the snapshot's sortition hash, and
    // picking the lexicographically smallest one
    let mut hash_tied = vec![];
    let mut mapping = HashMap::new();
    for (block_id, arrival_idx) in tied.into_iter() {
        let mut buff = [0u8; 64];
        buff[0..32].copy_from_slice(&block_id.0);
        buff[32..64].copy_from_slice(&tip.sortition_hash.0);

        let hashed = Sha512Trunc256Sum::from_data(&buff);
        hash_tied.push(hashed.clone());
        mapping.insert(hashed, arrival_idx);
    }

    hash_tied.sort();
    let winner = hash_tied
        .first()
        .expect("FATAL: zero-length list of tied block IDs");

    let winner_index = *mapping
        .get(&winner)
        .expect("FATAL: winning block ID not mapped");

    Some(winner_index)
}

/// Calculate the next sortition ID, given the PoX ID so far and the reward info
pub fn make_next_sortition_id(
    parent_pox: PoxId,
    this_block_hash: &BurnchainHeaderHash,
    next_pox_info: Option<&RewardCycleInfo>,
) -> SortitionId {
    let next_pox = make_next_pox_id(parent_pox, next_pox_info);
    let next_sortition_id = SortitionId::new(this_block_hash, &next_pox);
    next_sortition_id
}

/// Is a particular database version supported by a given epoch?
pub fn is_db_version_supported_in_epoch(epoch: StacksEpochId, version: &str) -> bool {
    match epoch {
        StacksEpochId::Epoch10 => true,
        StacksEpochId::Epoch20 => {
            version == "1"
                || version == "2"
                || version == "3"
                || version == "4"
                || version == "5"
                || version == "6"
                || version == "7"
                || version == "8"
        }
        StacksEpochId::Epoch2_05 => {
            version == "2"
                || version == "3"
                || version == "4"
                || version == "5"
                || version == "6"
                || version == "7"
                || version == "8"
        }
        StacksEpochId::Epoch21 => {
            version == "3"
                || version == "4"
                || version == "5"
                || version == "6"
                || version == "7"
                || version == "8"
        }
        StacksEpochId::Epoch22 => {
            version == "3"
                || version == "4"
                || version == "5"
                || version == "6"
                || version == "7"
                || version == "8"
        }
        StacksEpochId::Epoch23 => {
            version == "3"
                || version == "4"
                || version == "5"
                || version == "6"
                || version == "7"
                || version == "8"
        }
        StacksEpochId::Epoch24 => {
            version == "3"
                || version == "4"
                || version == "5"
                || version == "6"
                || version == "7"
                || version == "8"
        }
        StacksEpochId::Epoch25 => {
            version == "3"
                || version == "4"
                || version == "5"
                || version == "6"
                || version == "7"
                // TODO: This should move to Epoch 30 once it is added
                || version == "8"
        }
        StacksEpochId::Epoch30 => {
            version == "3"
                || version == "4"
                || version == "5"
                || version == "6"
                || version == "7"
                || version == "8"
        }
    }
}