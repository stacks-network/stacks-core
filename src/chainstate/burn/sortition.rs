/*
 copyright: (c) 2013-2018 by Blockstack PBC, a public benefit corporation.

 This file is part of Blockstack.

 Blockstack is free software. You may redistribute or modify
 it under the terms of the GNU General Public License as published by
 the Free Software Foundation, either version 3 of the License or
 (at your option) any later version.

 Blockstack is distributed in the hope that it will be useful,
 but WITHOUT ANY WARRANTY, including without the implied warranty of
 MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
 GNU General Public License for more details.

 You should have received a copy of the GNU General Public License
 along with Blockstack. If not, see <http://www.gnu.org/licenses/>.
*/

use std::collections::BTreeMap;

use rusqlite::Transaction;
use rusqlite::Connection;

use chainstate::burn::{
    BurnchainBlock,
    OpsHash,
    ConsensusHash,
    SortitionHash,
    VRFSeed,
    Txid,
    BurnchainHeaderHash
};

use util::db::Error as db_error;

use chainstate::burn::db::burndb::BurnDB;
use chainstate::burn::operations::BlockstackOperationType;
use chainstate::burn::operations::leader_key_register::LeaderKeyRegisterOp;
use chainstate::burn::operations::leader_block_commit::LeaderBlockCommitOp;
use chainstate::burn::operations::user_burn_support::UserBurnSupportOp;
use chainstate::burn::BlockSnapshot;
use chainstate::burn::distribution::BurnSamplePoint;

use burnchains::Address;
use burnchains::PublicKey;
use burnchains::Burnchain;

use util::hash::Hash160;
use util::uint::Uint256;
use util::uint::Uint512;
use util::uint::BitArray;
use util::vrf::ECVRF_public_key_to_hex;

use util::log;

impl BlockSnapshot {
    /// Calculate a new burn quota by incrementing.
    /// Panic on numeric overflow.
    fn burn_quota_inc_checked(last_burn_quota: u64, burn_quota_inc: u64) -> u64 {
        if last_burn_quota.checked_add(burn_quota_inc).is_none() {
            panic!("FATAL ERROR burn quota overflow ({} + {})", last_burn_quota, burn_quota_inc);
        }

        if last_burn_quota + burn_quota_inc > ((1 as u64) << 63) - 1 {
            panic!("FATAL ERROR burn quota exceeds i64 ({})", last_burn_quota + burn_quota_inc);
        }

        last_burn_quota + burn_quota_inc
    }

    /// Calculate a new burn quota by multiplicatively decreasing
    /// Panic on numeric overflow
    fn burn_quota_dec_checked(last_burn_quota: u64, burn_quota_num: u64, burn_quota_den: u64) -> u64 {
        let mut last_burn_quota_u128 = last_burn_quota as u128;
        if last_burn_quota_u128.checked_mul(burn_quota_num.into()).is_none() {
            panic!("FATAL ERROR burn quota overflow ({} * {})", last_burn_quota, burn_quota_num);
        }
        last_burn_quota_u128 = last_burn_quota_u128 * (burn_quota_num as u128);

        if last_burn_quota_u128.checked_div(burn_quota_den as u128).is_none() {
            panic!("FATAL ERROR burn quota unsafe divide ({} * {} / {})", last_burn_quota, burn_quota_num, burn_quota_den);
        }
        last_burn_quota_u128 = last_burn_quota_u128 / (burn_quota_den as u128);

        last_burn_quota_u128 as u64
    }

    /// Calculate the total burn.
    /// Panic on numeric overflow.
    fn burn_total_checked(last_burn_total: u64, block_burn_total: u64) -> u64 {
        if block_burn_total.checked_add(last_burn_total).is_none() {
            panic!("FATAL ERROR burn total overflow ({} + {})", block_burn_total, last_burn_total);
        }

        block_burn_total + last_burn_total
    }
    
    /// Given the weighted burns, VRF seed of the last winner, and sortition hash, pick the next
    /// winner.  Return the index into the distribution *if there is a sample to take*.
    fn sample_burn_distribution<A, K>(dist: &Vec<BurnSamplePoint<A, K>>, VRF_seed: &VRFSeed, sortition_hash: &SortitionHash) -> Option<usize>
    where
        A: Address,
        K: PublicKey
    {
        if dist.len() == 0 {
            // no winners 
            return None;
        }
        if dist.len() == 1 {
            // only one winner 
            return Some(0);
        }

        let index = sortition_hash.mix_VRF_seed(VRF_seed).to_uint256();
        for i in 0..dist.len() {
            if (dist[i].range_start <= index) && (index < dist[i].range_end) {
                debug!("Sampled {}: {} <= HASH({},{}) < {}", dist[i].candidate.block_header_hash.to_hex(), dist[i].range_start, &sortition_hash.to_hex(), &VRF_seed.to_hex(), dist[i].range_end);
                return Some(i);
            }
        }

        // should never happen 
        panic!("FATAL ERROR: unable to map {} to a range", index);
    }

    /// Select the next Stacks block header hash using cryptographic sortition.
    /// Go through all block commits at this height, find out how any burn tokens
    /// were spent for them, and select one at random using the relative burn amounts
    /// to weight the sample.  Use HASH(sortition_hash ++ last_VRF_seed) to pick the 
    /// winning block commit, and by extension, the next VRF seed.
    ///
    /// If there are no block commits outstanding, then no winner is picked.
    ///
    /// Note that the VRF seed is not guaranteed to be the hash of a valid VRF
    /// proof.  Miners would only build off of leader block commits for which they
    /// (1) have the associated block data and (2) the proof in that block is valid.
    fn select_winning_block<'a, A, K>(tx: &mut Transaction<'a>, block_height: u64, sortition_hash: &SortitionHash, burn_dist: &Vec<BurnSamplePoint<A, K>>) -> Result<Option<LeaderBlockCommitOp<A, K>>, db_error>
    where
        A: Address,
        K: PublicKey
    {
        // get the last winner's VRF seed
        let last_sortition_snapshot = BurnDB::<A, K>::get_last_snapshot_with_sortition(tx, block_height)?;
        let VRF_seed;

        if last_sortition_snapshot.sortition_hash == SortitionHash::initial() {
            // this is the sentinal "first-sortition" block 
            VRF_seed = VRFSeed::initial();
        }
        else {
            // there was a prior winning block commit.  Use its VRF seed.
            let last_winning_block_commit_opt = BurnDB::<A, K>::get_block_commit(tx, &last_sortition_snapshot.winning_block_txid, &last_sortition_snapshot.winning_block_burn_hash)?;
            if last_winning_block_commit_opt.is_none() {
                // something is seriously wrong -- the canonical block snapshot doesn't point to a
                // canonical block commit.
                panic!("FATAL ERROR: no block commit for snapshot {:?}", last_sortition_snapshot);
            }
            let last_winning_block_commit = last_winning_block_commit_opt.unwrap();
            VRF_seed = last_winning_block_commit.new_seed.clone();
        }

        // pick the next winner
        let win_idx_opt = BlockSnapshot::sample_burn_distribution(burn_dist, &VRF_seed, sortition_hash);
        match win_idx_opt {
            None => {
                // no winner 
                Ok(None)
            },
            Some(win_idx) => {
                // winner!
                Ok(Some(burn_dist[win_idx].candidate.clone()))
            }
        }
    }
    

    /// Make a block snapshot from is block's data and the previous block.
    /// This process will:
    /// * calculate the new consensus hash
    /// * calculate the total burn so far
    /// * calculate the new burn quota
    /// * determine whether or not we can do a sortition, and if so,
    /// * carry out the sortition to select the next candidate block.
    ///
    /// All of this is rolled into the BlockSnapshot struct.
    /// 
    /// Call this *after* you store all of the block's transactions to the burn db.
    pub fn make_snapshot<'a, A, K>(tx: &mut Transaction<'a>, burnchain: &Burnchain, first_block_height: u64,
                                   block_height: u64, block_hash: &BurnchainHeaderHash, parent_block_hash: &BurnchainHeaderHash, burn_dist: &Vec<BurnSamplePoint<A, K>>) -> Result<BlockSnapshot, db_error>
    where
        A: Address, 
        K: PublicKey
    {
        // txids for operations stored in this block
        let txids = BurnDB::<A, K>::get_block_txids(tx, block_height, block_hash)?;

        // NOTE: this only counts burns from leader block commits and user burns that match them.
        // It ignores user burns that don't match any block.
        let block_burn_total_opt = BurnSamplePoint::get_total_burns(burn_dist);
        if block_burn_total_opt.is_none() {
            return Err(db_error::Overflow);
        }
        let block_burn_total = block_burn_total_opt.unwrap();

        let last_burn_quota;
        let last_sortition_hash;
        let last_burn_total;
        let last_sortition_burn_total;
        let last_sortition;

        let next_sortition;
        let next_sortition_burn_total;
        let next_burn_quota;
        let winning_block_txid;
        let winning_block_burn_hash;

        let last_block_snapshot_opt = BurnDB::<A, K>::get_block_snapshot(tx, block_height - 1)?;
        match last_block_snapshot_opt {
            Some(prev_snapshot) => {
                last_burn_total = prev_snapshot.total_burn;
                last_sortition_burn_total = prev_snapshot.sortition_burn;
                last_burn_quota = prev_snapshot.burn_quota;
                last_sortition_hash = prev_snapshot.sortition_hash;
                last_sortition = prev_snapshot.sortition;
            },
            None => {
                // initial block snapshot
                last_burn_total = 0;
                last_sortition_burn_total = 0;
                last_burn_quota = 0;
                last_sortition_hash = SortitionHash::initial();
                last_sortition = true;
            }
        };

        let sortition_burn_total = BlockSnapshot::burn_total_checked(block_burn_total, last_sortition_burn_total); 
        let next_sortition_hash = last_sortition_hash.mix_burn_header(block_hash);
       
        // did we burn enough?
        if sortition_burn_total >= last_burn_quota {
            // can do a sortition in this block
            // Try to pick a next block.
            let winning_block_opt : Option<LeaderBlockCommitOp<A, K>> = BlockSnapshot::select_winning_block(tx, block_height, &next_sortition_hash, burn_dist)?;
            match winning_block_opt {
                None => {
                    // we burned enough for a sortition, but no winner was picked.
                    // can happen if the burn quota is 0.
                    next_sortition = false;
                    winning_block_txid = Txid::from_bytes(&[0u8; 32]).unwrap();
                    winning_block_burn_hash = BurnchainHeaderHash::from_bytes(&[0u8; 32]).unwrap();

                    info!("SORTITION({}): Burn quota met ({}), but NO BLOCK CHOSEN", block_height, block_burn_total);
                },
                Some(winning_block) => {
                    // we burned enough for a sortition, and a winner was picked! 
                    next_sortition = true;
                    winning_block_txid = winning_block.txid.clone();
                    winning_block_burn_hash = winning_block.burn_header_hash.clone();

                    info!("SORTITION({}): Burn quota met ({}). WINNER BLOCK is {}", block_height, block_burn_total, &winning_block.block_header_hash.to_hex());
                }
            };

            // either way, we burned enough that we can alter the burn quota.
            // -- we INCREMENT if the burn quota was met in the _last_ block
            //      -- we either did a sortition last block, OR
            //      -- no blocks were committed (so no sortition) and the burn quota was 0
            // -- we DECREMENT otherwise
            if last_sortition || (last_sortition_burn_total == 0 && last_burn_quota == 0) {
                debug!("SORTITION({}): burned enough for sortition last block, so QUOTA INCREMENT", block_height);
                next_burn_quota = BlockSnapshot::burn_quota_inc_checked(last_burn_quota, burnchain.burn_quota.inc);
            }
            else {
                debug!("SORTITION({}): did no burn enough for sortition last block, so QUOTA DECREASE", block_height);
                next_burn_quota = BlockSnapshot::burn_quota_dec_checked(last_burn_quota, burnchain.burn_quota.dec_num, burnchain.burn_quota.dec_den);
            }

            // we will have burned 0 towards the next sortition.
            next_sortition_burn_total = 0;
        }
        else {
            // cannot do a sortition in this block, but don't change the burn quota -- it will only
            // be decremented once we meet it!  Instead, keep a running total of how much we burned
            // since the last sortition, and use that in the next epoch to see if we can adjust the
            // burn quota.
            next_sortition = false;
            next_burn_quota = last_burn_quota;
            next_sortition_burn_total = sortition_burn_total;

            winning_block_txid = Txid::from_bytes(&[0u8; 32]).unwrap();
            winning_block_burn_hash = BurnchainHeaderHash::from_bytes(&[0u8; 32]).unwrap();

            info!("SORTITION({}): Burn quota not met ({} < {}), so NO QUOTA CHANGE", block_height, block_burn_total, last_burn_quota);
        }

        let next_burn_total = BlockSnapshot::burn_total_checked(last_burn_total, block_burn_total);
        
        let next_ops_hash = OpsHash::from_txids(&txids);
        let next_ch = ConsensusHash::from_block_data::<A, K>(tx, &next_ops_hash, block_height, first_block_height, next_burn_total)?;

        Ok(BlockSnapshot {
            block_height: block_height,
            burn_header_hash: block_hash.clone(),
            parent_burn_header_hash: parent_block_hash.clone(), 
            consensus_hash: next_ch,
            ops_hash: next_ops_hash,
            total_burn: next_burn_total,
            sortition_burn: next_sortition_burn_total,
            burn_quota: next_burn_quota,
            sortition: next_sortition,
            sortition_hash: next_sortition_hash,
            winning_block_txid: winning_block_txid,
            winning_block_burn_hash: winning_block_burn_hash,
            canonical: true
        })
    }
}

