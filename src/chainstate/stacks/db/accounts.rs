/*
 copyright: (c) 2013-2019 by Blockstack PBC, a public benefit corporation.

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

use rusqlite::Row;
use rusqlite::types::ToSql;

use burnchains::Address;

use chainstate::stacks::Error;
use chainstate::stacks::*;
use chainstate::stacks::db::*;
use chainstate::stacks::db::blocks::*;
use vm::database::*;
use vm::database::marf::*;

use vm::types::*;

use util::db::*;
use util::db::Error as db_error;

#[derive(Debug, Clone, PartialEq)]
pub struct MinerReward {
    pub address: StacksAddress,
    pub coinbase: u128,
    pub tx_fees_anchored_shared: u128,
    pub tx_fees_anchored_exclusive: u128,
    pub tx_fees_streamed_produced: u128,
    pub tx_fees_streamed_confirmed: u128,
    pub vtxindex: u32       // will be 0 for the reward to the miner, and >0 for user burn supports
}

impl RowOrder for MinerPaymentSchedule {
    fn row_order() -> Vec<&'static str> {
        vec!["address","block_hash","burn_header_hash","parent_block_hash","parent_burn_header_hash","coinbase","tx_fees_anchored","tx_fees_streamed","stx_burns","burnchain_commit_burn","burnchain_sortition_burn","fill","miner","stacks_block_height","vtxindex"]
    }
}

impl FromRow<MinerPaymentSchedule> for MinerPaymentSchedule {
    fn from_row<'a>(row: &'a Row, index: usize) -> Result<MinerPaymentSchedule, db_error> {
        let address = StacksAddress::from_row(row, 0 + index)?;
        let block_hash = BlockHeaderHash::from_row(row, 1 + index)?;
        let burn_header_hash = BurnchainHeaderHash::from_row(row, 2 + index)?;
        let parent_block_hash = BlockHeaderHash::from_row(row, 3 + index)?;
        let parent_burn_header_hash = BurnchainHeaderHash::from_row(row, 4 + index)?;
        
        let coinbase_text : String = row.get(5 + index);
        let tx_fees_anchored_text : String = row.get(6 + index);
        let tx_fees_streamed_text : String = row.get(7 + index);
        let burns_text : String = row.get(8 + index);
        let burnchain_commit_burn_i64 : i64 = row.get(9 + index);
        let burnchain_sortition_burn_i64 : i64 = row.get(10 + index);
        let fill_text : String = row.get(11 + index);
        let miner : bool = row.get(12 + index);
        let block_height_i64 : i64 = row.get(13 + index);
        let vtxindex : u32 = row.get(14 + index);

        if burnchain_commit_burn_i64 < 0 || burnchain_sortition_burn_i64 < 0 {
            return Err(db_error::ParseError);
        }

        let coinbase = coinbase_text.parse::<u128>().map_err(|_e| db_error::ParseError)?;
        let tx_fees_anchored = tx_fees_anchored_text.parse::<u128>().map_err(|_e| db_error::ParseError)?;
        let tx_fees_streamed = tx_fees_streamed_text.parse::<u128>().map_err(|_e| db_error::ParseError)?;
        let stx_burns = burns_text.parse::<u128>().map_err(|_e| db_error::ParseError)?;
        let burnchain_commit_burn = burnchain_commit_burn_i64 as u64;
        let burnchain_sortition_burn = burnchain_sortition_burn_i64 as u64;
        let fill = fill_text.parse::<u64>().map_err(|_e| db_error::ParseError)?;
        let stacks_block_height = block_height_i64 as u64;

        let payment_data = MinerPaymentSchedule {
            address,
            block_hash,
            burn_header_hash,
            parent_block_hash,
            parent_burn_header_hash,
            coinbase,
            tx_fees_anchored,
            tx_fees_streamed,
            stx_burns,
            burnchain_commit_burn,
            burnchain_sortition_burn,
            fill,
            miner,
            stacks_block_height,
            vtxindex
        };
        Ok(payment_data)
    }
}

impl MinerReward {
    pub fn empty_miner(address: &StacksAddress) -> MinerReward {
        MinerReward {
            address: address.clone(),
            coinbase: 0,
            tx_fees_anchored_shared: 0,
            tx_fees_anchored_exclusive: 0,
            tx_fees_streamed_produced: 0,
            tx_fees_streamed_confirmed: 0,
            vtxindex: 0
        }
    }
    
    pub fn empty_user(address: &StacksAddress, vtxindex: u32) -> MinerReward {
        MinerReward {
            address: address.clone(),
            coinbase: 0,
            tx_fees_anchored_shared: 0,
            tx_fees_anchored_exclusive: 0,
            tx_fees_streamed_produced: 0,
            tx_fees_streamed_confirmed: 0,
            vtxindex: vtxindex
        }
    }

    pub fn total(&self) -> u128 {
        self.coinbase + self.tx_fees_anchored_shared + self.tx_fees_anchored_exclusive + self.tx_fees_streamed_produced + self.tx_fees_streamed_confirmed
    }
}

impl StacksChainState {
    pub fn get_account<'a>(clarity_tx: &mut ClarityTx<'a>, principal: &PrincipalData) -> StacksAccount {
        clarity_tx.connection().with_clarity_db_readonly(|ref mut db| {
            let stx_balance = db.get_account_stx_balance(principal);
            let nonce = db.get_account_nonce(principal);
            Ok(StacksAccount {
                principal: principal.clone(),
                stx_balance,
                nonce
            })
        }).expect("FATAL: failed to query account")
    }

    pub fn get_account_ft<'a>(clarity_tx: &mut ClarityTx<'a>, contract_id: &QualifiedContractIdentifier, token_name: &str, principal: &PrincipalData) -> Result<u128, Error> {
        clarity_tx.connection().with_clarity_db_readonly(|ref mut db| {
            let ft_balance = db.get_ft_balance(contract_id, token_name, principal)?;
            Ok(ft_balance)
        })
        .map_err(Error::ClarityError)
    }

    pub fn get_account_nft<'a>(clarity_tx: &mut ClarityTx<'a>, contract_id: &QualifiedContractIdentifier, token_name: &str, token_value: &Value) -> Result<PrincipalData, Error> {
        clarity_tx.connection().with_clarity_db_readonly(|ref mut db| {
            let nft_owner = db.get_nft_owner(contract_id, token_name, token_value)?;
            Ok(nft_owner)
        })
        .map_err(Error::ClarityError)
    }

    /// Called each time a transaction is invoked from this principal, to e.g.
    /// debit the STX-denominated tx fee or transfer/burn STX.
    /// DOES NOT UPDATE THE NONCE
    pub fn account_debit<'a>(clarity_tx: &mut ClarityTx<'a>, principal: &PrincipalData, amount: u64) {
        clarity_tx.connection().with_clarity_db(|ref mut db| {
            let cur_balance = db.get_account_stx_balance(principal);
            
            // last line of defense: if we don't have sufficient funds, panic.
            // This should be checked by the block validation logic.
            if cur_balance < (amount as u128) {
                panic!("Tried to debit {} from account {} (which only has {})", amount, principal, cur_balance);
            }

            let final_balance = cur_balance - (amount as u128);
            db.set_account_stx_balance(principal, final_balance);
            Ok(())
        }).expect("FATAL: failed to debit account")
    }

    /// Called each time a transaction sends STX to this principal.
    /// No nonce update is needed, since the transfer action is not taken by the principal.
    pub fn account_credit<'a>(clarity_tx: &mut ClarityTx<'a>, principal: &PrincipalData, amount: u64) {
        clarity_tx.connection().with_clarity_db(|ref mut db| {
            let cur_balance = db.get_account_stx_balance(principal);
            let final_balance = cur_balance.checked_add(amount as u128).expect("FATAL: account balance overflow");
            db.set_account_stx_balance(principal, amount as u128);
            Ok(())
        }).expect("FATAL: failed to credit account")
    }
    
    /// Verify that this transaction is not a replay, and update its nonce.
    pub fn update_account_nonce<'a>(clarity_tx: &mut ClarityTx<'a>, tx: &StacksTransaction, account: &StacksAccount) {
        clarity_tx.connection().with_clarity_db(|ref mut db| {
            let next_nonce = account.nonce.checked_add(1).expect("OUT OF NONCES");
            db.set_account_nonce(&account.principal, next_nonce);
            Ok(())
        }).expect("FATAL: failed to set account nonce")
    }

    /// Schedule a miner payment in the future.
    /// Schedules payments out to both miners and users that support them.
    pub fn insert_miner_payment_schedule<'a>(tx: &mut StacksDBTx<'a>, block_reward: &MinerPaymentSchedule, user_burns: &Vec<StagingUserBurnSupport>) -> Result<(), Error> {
        assert!(block_reward.burnchain_commit_burn < i64::max_value() as u64);
        assert!(block_reward.burnchain_sortition_burn < i64::max_value() as u64);

        tx.execute("INSERT INTO payments (address,block_hash,burn_header_hash,parent_block_hash,parent_burn_header_hash,coinbase,tx_fees_anchored,tx_fees_streamed,stx_burns,burnchain_commit_burn,burnchain_sortition_burn,fill,stacks_block_height,miner,vtxindex) \
                    VALUES (?1,?2,?3,?4,?5,?6,?7,?8,?9,?10,?11,?12,?13,?14,?15)",
                    &[&block_reward.address.to_string(), &block_reward.block_hash.to_hex(), &block_reward.burn_header_hash.to_hex(), &block_reward.parent_block_hash.to_hex(), &block_reward.parent_burn_header_hash.to_hex(),
                    &format!("{}", block_reward.coinbase), &format!("{}", block_reward.tx_fees_anchored), &format!("{}", block_reward.tx_fees_streamed), &format!("{}", block_reward.stx_burns), 
                    &(block_reward.burnchain_commit_burn as i64) as &dyn ToSql, &(block_reward.burnchain_sortition_burn as i64) as &dyn ToSql, &format!("{}", block_reward.fill), &(block_reward.stacks_block_height as i64) as &dyn ToSql, 
                    &true as &dyn ToSql, &0i64 as &dyn ToSql])
            .map_err(|e| Error::DBError(db_error::SqliteError(e)))?;

        for user_support in user_burns.iter() {
            tx.execute("INSERT INTO payments (address,block_hash,burn_header_hash,parent_block_hash,parent_burn_header_hash,coinbase,tx_fees_anchored,tx_fees_streamed,stx_burns,burnchain_commit_burn,burnchain_sortition_burn,fill,stacks_block_height,miner,vtxindex) \
                        VALUES (?1,?2,?3,?4,?5,?6,?7,?8,?9,?10,?11,?12,?13,?14,?15)",
                        &[&user_support.address.to_string(), &block_reward.block_hash.to_hex(), &block_reward.burn_header_hash.to_hex(), &block_reward.parent_block_hash.to_hex(), &block_reward.parent_burn_header_hash.to_hex(),
                        &format!("{}", block_reward.coinbase), &"0".to_string(), &"0".to_string(), &"0".to_string(),
                        &(user_support.burn_amount as i64) as &dyn ToSql, &(block_reward.burnchain_sortition_burn as i64) as &dyn ToSql, &format!("{}", block_reward.fill), &(block_reward.stacks_block_height as i64) as &dyn ToSql,
                        &false as &dyn ToSql, &user_support.vtxindex as &dyn ToSql])
                .map_err(|e| Error::DBError(db_error::SqliteError(e)))?;
        }

        Ok(())
    }
 
    /// Get the scheduled miner rewards in a particular Stacks fork at a particular height
    fn get_scheduled_block_rewards_in_fork<'a>(tx: &mut StacksDBTx<'a>, tip: &StacksHeaderInfo, block_height: u64) -> Result<Vec<MinerPaymentSchedule>, Error> {
        let ancestor_info = match StacksChainState::get_tip_ancestor(tx, tip, block_height)? {
            Some(info) => info,
            None => {
                return Ok(vec![]);
            }
        };
        
        let row_order = MinerPaymentSchedule::row_order().join(",");
        let qry = format!("SELECT {} FROM payments WHERE block_hash = ?1 AND burn_header_hash = ?2 ORDER BY vtxindex ASC", row_order);
        let args = [&ancestor_info.anchored_header.block_hash().to_hex(), &ancestor_info.burn_header_hash.to_hex()];
        let rows = query_rows::<MinerPaymentSchedule, _>(tx, &qry, &args).map_err(Error::DBError)?;
        Ok(rows)
    }

    /// Calculate the total reward for a miner (or user burn support), given a sample of scheduled miner payments.
    /// The scheduled miner payments must be in order by block height (sample[0] is the oldest).
    /// The first tuple item is the miner's reward; the second tuple item is the list of
    /// user-support burns that helped the miner win.
    ///
    /// There must be MINER_REWARD_WINDOW items in the sample.
    ///
    /// TODO: .burns?
    fn calculate_miner_reward(miner: &MinerPaymentSchedule, sample: &Vec<(MinerPaymentSchedule, Vec<MinerPaymentSchedule>)>) -> MinerReward {
        assert!(miner.burnchain_sortition_burn > 0);        // don't call this method if there was no sortition for this block!

        let mut num_mined : u128 = 0;

        // this miner gets (r*b)/(R*B) of the coinbases over the reward window, where:
        // * r is the number of tokens added by the blocks mined (or supported) by this miner
        // * R is the number of tokens added by all blocks mined in this interval
        // * b is the amount of burn tokens destroyed by this miner 
        // * B is the total amount of burn tokens destroyed over this interval
        let mut coinbase_reward : u128 = 0;

        // the transaction fee _actually paid_ by each transaction is equal to the fraction of the
        // block's compute budget used, multipled by the block-wide STX/compute-unit rate set by
        // all transactions.
        // Miners share the first F% of the anchored tx fees over the next B blocks, proportional
        // to the fraction of mining power they supply.
        // Miners receive exclusively the remaining tx fees for the block, if the block used more
        // than F% of the computing budget.
        let mut anchored_tx_fee_exclusive : u128 = 0;
        let mut anchored_tx_fee_shared : u128 = 0;
        let mut anchored_tx_fee_shared_total : u128 = 0;

        // this miner gets 60% of the streamed tx fees of the microblocks it confirmed (built on), and
        // 40% of the streamed tx fees of the microblocks it produced.
        let mut microblock_fees_produced : u128 = 0;
        let mut microblock_fees_confirmed : u128 = 0;

        ////////////////////// number of blocks this miner mined or supported //////
        for i in 0..sample.len() {
            let block_miner = &sample[i].0;
            let user_supports = &sample[i].1;

            if block_miner.address == miner.address {
                num_mined += 1;
            }
            else {
                for user_support in user_supports.iter() {
                    if user_support.address == miner.address {
                        num_mined += 1;
                        break;
                    }
                }
            }
        }

        ////////////////////// coinbase reward total /////////////////////////////////
        test_debug!("Coinbase reward = {} * ({}/{})", miner.coinbase, miner.burnchain_commit_burn, miner.burnchain_sortition_burn);
        coinbase_reward = miner.coinbase.checked_mul(miner.burnchain_commit_burn as u128).expect("FATAL: STX coinbase reward overflow") / (miner.burnchain_sortition_burn as u128);

        ////////////////////// anchored tx fees (miner only) //////////////////////////
        if miner.miner {
            let fill_cutoff = ((MINER_FEE_MINIMUM_BLOCK_USAGE as u128) << 64) / 100u128;       // scale fill fraction to between 0 and 2**64 - 1
            assert!(fill_cutoff <= u64::max_value() as u128);

            let mut shared_fees_total : u128 = 0;
            let mut fees_total : u128 = 0;

            for i in 0..sample.len() {
                let block_miner = &sample[i].0;
                if block_miner.fill < (fill_cutoff as u64) {
                    // block was underfull but relayed.
                    // The fees are entirely shared -- this will be metered at the minimum STX/compute ratio
                    shared_fees_total = shared_fees_total.checked_add(block_miner.tx_fees_anchored << 64).expect("FATAL: STX shared-total anchored fee overflow");
                }
                else {
                    // block met or exceeded budget.
                    // The first F% is shared.
                    // The remaining (1 - F%) is given exclusively to this miner.
                    let shared_fees = block_miner.tx_fees_anchored.checked_mul(fill_cutoff).expect("FATAL: STX shared-total anchored fee calculation overflow");
                    shared_fees_total = shared_fees_total.checked_add(shared_fees).expect("FATAL: STX shared-total anchored fee calculation overflow");

                    if block_miner.address == miner.address {
                        assert!((block_miner.tx_fees_anchored << 64) >= shared_fees);
                        let exclusive_fees = (block_miner.tx_fees_anchored << 64) - shared_fees;
                        
                        test_debug!("Anchored tx fees exclusive: {} = {} + {}", (fees_total + exclusive_fees) >> 64, fees_total >> 64, exclusive_fees >> 64);
                        fees_total = fees_total.checked_add((block_miner.tx_fees_anchored << 64) - shared_fees).expect("FATAL: STX exclusive total anchored fee calculation overflow");
                    }
                }
            }

            let decimal_mask = 0x0000000000000000ffffffffffffffffu128;
            let decimal_half = 0x00000000000000007fffffffffffffffu128;

            anchored_tx_fee_shared_total = 
                if shared_fees_total & decimal_mask > decimal_half {
                    // round up
                    (shared_fees_total >> 64) + 1
                }
                else {
                    // round down
                    shared_fees_total >> 64
                };

            anchored_tx_fee_exclusive = 
                if fees_total & decimal_mask > decimal_half {
                    // round up
                    (fees_total >> 64) + 1
                }
                else {
                    // round down
                    fees_total >> 64
                };
            
            test_debug!("Anchored tx fees shared = {} * ({}/{})", anchored_tx_fee_shared_total, num_mined, sample.len());
            anchored_tx_fee_shared = anchored_tx_fee_shared_total.checked_mul(num_mined).expect("FATAL: STX shared anchored tx fee overflow") / (sample.len() as u128);
        }

        ////////////////////// microblock tx fees confirmed (miner only) /////////////
        if miner.miner {
            let mut fees_confirmed : u128 = 0;
            for i in 1..sample.len() {
                let prev_block_miner = &sample[i-1].0;
                let block_miner = &sample[i].0;
                if block_miner.address == miner.address {
                    test_debug!("Confirmed streamd tx fees: 3/5 * {} = 3/5 * ({} + {})", fees_confirmed + prev_block_miner.tx_fees_streamed, fees_confirmed, prev_block_miner.tx_fees_streamed);
                    fees_confirmed = fees_confirmed.checked_add(prev_block_miner.tx_fees_streamed).expect("FATAL: STX tx fees streamed confirmation overflow");
                }
            }
            
            // built on top of the previous block's microblocks, so get 60%
            microblock_fees_confirmed = fees_confirmed.checked_mul(3).expect("FATAL: failed to calculate microblock STX stream fee") / 5;
        }

        ////////////////////// microblock tx fees produced (miner only) //////////////
        if miner.miner {
            let mut fees_produced : u128 = miner.tx_fees_streamed;
            for i in 0..sample.len() {
                let block_miner = &sample[i].0;
                if block_miner.address == miner.address {
                    test_debug!("Produced streamd tx fees: 2/5 * {} = 2/5 * ({} + {})", fees_produced + block_miner.tx_fees_streamed, fees_produced, block_miner.tx_fees_streamed);
                    fees_produced = fees_produced.checked_add(block_miner.tx_fees_streamed).expect("FATAL: STX tx fees streamed production overflow");
                }
            }
            
            // produced this block's microblocks, so get 40%
            microblock_fees_produced = fees_produced.checked_mul(2).expect("FATAL: failed to calculate microblock STX stream fee") / 5;
        }

        let miner_reward = MinerReward {
            address: miner.address.clone(),
            coinbase: coinbase_reward,
            tx_fees_anchored_shared: anchored_tx_fee_shared,
            tx_fees_anchored_exclusive: anchored_tx_fee_exclusive,
            tx_fees_streamed_produced: microblock_fees_produced,
            tx_fees_streamed_confirmed: microblock_fees_confirmed,
            vtxindex: miner.vtxindex
        };
        miner_reward
    }

    /// Find the latest miner reward to mature, assuming that there are mature rewards.
    /// Returns a list of payments to make to each address -- miners and user-support burners
    pub fn find_mature_miner_rewards<'a>(tx: &mut StacksDBTx<'a>, tip: &StacksHeaderInfo) -> Result<Option<Vec<MinerReward>>, Error> {
        if tip.block_height < MINER_REWARD_MATURITY + MINER_REWARD_WINDOW + 1 {
            // no mature rewards exist
            return Ok(None);
        }

        let matured_miners = StacksChainState::get_scheduled_block_rewards_in_fork(tx, tip, tip.block_height - MINER_REWARD_MATURITY - MINER_REWARD_WINDOW)?;
        if matured_miners.len() == 0 {
            // no sortition happened here
            return Ok(None);
        }

        let mut scheduled_payments = vec![];
        for i in 0..MINER_REWARD_WINDOW {
            let height = tip.block_height - MINER_REWARD_MATURITY - MINER_REWARD_WINDOW + i;      // safe due to the above check
            let scheduled_rewards = 
                if i == 0 {
                    matured_miners.clone()
                }
                else {
                    StacksChainState::get_scheduled_block_rewards_in_fork(tx, tip, height)?
                };

            assert!(scheduled_rewards.len() > 0);

            let mut miner_reward_opt = None;
            for reward in scheduled_rewards.iter() {
                if reward.miner {
                    miner_reward_opt = Some(reward.clone());
                    break;
                }
            }
            
            let miner_reward = miner_reward_opt.expect(&format!("FATAL: missing miner reward for block {}", height));
            let mut user_burns = vec![];
            for reward in scheduled_rewards.iter() {
                if !reward.miner {
                    user_burns.push(reward.clone());
                }
            }

            assert_eq!(user_burns.len(), scheduled_rewards.len() - 1);
            scheduled_payments.push((miner_reward, user_burns));
        }

        let mut rewards = vec![];
        for matured_miner in matured_miners {
            let reward = StacksChainState::calculate_miner_reward(&matured_miner, &scheduled_payments);
            rewards.push(reward);
        }
        Ok(Some(rewards))
    }
}

#[cfg(test)]
mod test {
    use super::*;
    use burnchains::*;
    use chainstate::burn::*;
    use chainstate::stacks::*;

    fn make_dummy_miner_payment_schedule(addr: &StacksAddress, coinbase: u128, tx_fees_anchored: u128, tx_fees_streamed: u128, commit_burn: u64, sortition_burn: u64) -> MinerPaymentSchedule {
        MinerPaymentSchedule {
            address: addr.clone(),
            block_hash: BlockHeaderHash([0u8; 32]),
            burn_header_hash: BurnchainHeaderHash([0u8; 32]),
            parent_block_hash: BlockHeaderHash([0u8; 32]),
            parent_burn_header_hash: BurnchainHeaderHash([0u8; 32]),
            coinbase,
            tx_fees_anchored,
            tx_fees_streamed, 
            stx_burns: 0,
            burnchain_commit_burn: commit_burn,
            burnchain_sortition_burn: sortition_burn, 
            fill: 0xffffffffffffffff,
            miner: true,
            stacks_block_height: 0,
            vtxindex: 0
        }
    }
    
    fn make_dummy_user_payment_schedule(addr: &StacksAddress, coinbase: u128, tx_fees_anchored: u128, tx_fees_streamed: u128, commit_burn: u64, sortition_burn: u64, vtxindex: u32) -> MinerPaymentSchedule {
        let mut sched = make_dummy_miner_payment_schedule(addr, coinbase, tx_fees_anchored, tx_fees_streamed, commit_burn, sortition_burn);
        sched.miner = false;
        sched.vtxindex = vtxindex;
        sched
    }

    #[test]
    fn miner_reward_one_miner_no_tx_fees_no_users() {
        let mut sample = vec![];
        let miner_1 = StacksAddress::from_string(&"SP1A2K3ENNA6QQ7G8DVJXM24T6QMBDVS7D0TRTAR5".to_string()).unwrap();
        let participant = make_dummy_miner_payment_schedule(&miner_1, 500, 0, 0, 1000, 1000);
        sample.push((participant.clone(), vec![]));

        for i in 0..9 {
            let next_participant = make_dummy_miner_payment_schedule(&miner_1, 500, 0, 0, 1000, 1000);
        }

        let reward = StacksChainState::calculate_miner_reward(&participant, &sample);
        
        // miner should have received the entire coinbase
        assert_eq!(reward.coinbase, 500);
        assert_eq!(reward.tx_fees_anchored_shared, 0);
        assert_eq!(reward.tx_fees_anchored_exclusive, 0);
        assert_eq!(reward.tx_fees_streamed_produced, 0);
        assert_eq!(reward.tx_fees_streamed_confirmed, 0);
    }
    
    #[test]
    fn miner_reward_two_miners_no_tx_fees_no_users() {
        let mut sample = vec![];
        let miner_1 = StacksAddress::from_string(&"SP1A2K3ENNA6QQ7G8DVJXM24T6QMBDVS7D0TRTAR5".to_string()).unwrap();
        let participant = make_dummy_miner_payment_schedule(&miner_1, 500, 0, 0, 1000, 1000);
        sample.push((participant.clone(), vec![]));

        for i in 0..9 {
            let next_participant = make_dummy_miner_payment_schedule(&miner_1, 500, 0, 0, 1000, 1000);
            sample.push((next_participant, vec![]));
        }

        let reward = StacksChainState::calculate_miner_reward(&participant, &sample);
        
        // miner should have received the entire coinbase
        assert_eq!(reward.coinbase, 500);
        assert_eq!(reward.tx_fees_anchored_shared, 0);
        assert_eq!(reward.tx_fees_anchored_exclusive, 0);
        assert_eq!(reward.tx_fees_streamed_produced, 0);
        assert_eq!(reward.tx_fees_streamed_confirmed, 0);
    }
    
    #[test]
    fn miner_reward_one_miner_one_user_no_tx_fees() {
        let mut sample = vec![];
        let miner_1 = StacksAddress::from_string(&"SP1A2K3ENNA6QQ7G8DVJXM24T6QMBDVS7D0TRTAR5".to_string()).unwrap();
        let user_1 = StacksAddress::from_string(&"SP2837ZMC89J40K4YTS64B00M7065C6X46JX6ARG0".to_string()).unwrap();
        let participant = make_dummy_miner_payment_schedule(&miner_1, 500, 0, 0, 250, 1000);
        let user = make_dummy_user_payment_schedule(&user_1, 500, 0, 0, 750, 1000, 1);
        sample.push((participant.clone(), vec![user.clone()]));

        for i in 0..9 {
            let next_participant = make_dummy_miner_payment_schedule(&miner_1, 500, 0, 0, 1000, 1000);
            sample.push((next_participant, vec![]));
        }

        let reward_miner_1 = StacksChainState::calculate_miner_reward(&participant, &sample);
        let reward_user_1 = StacksChainState::calculate_miner_reward(&user, &sample);
        
        // miner should have received 1/4 the coinbase
        assert_eq!(reward_miner_1.coinbase, 125);
        assert_eq!(reward_miner_1.tx_fees_anchored_shared, 0);
        assert_eq!(reward_miner_1.tx_fees_anchored_exclusive, 0);
        assert_eq!(reward_miner_1.tx_fees_streamed_produced, 0);
        assert_eq!(reward_miner_1.tx_fees_streamed_confirmed, 0);
        
        // user should have received 3/4 the coinbase
        assert_eq!(reward_user_1.coinbase, 375);
        assert_eq!(reward_user_1.tx_fees_anchored_shared, 0);
        assert_eq!(reward_user_1.tx_fees_anchored_exclusive, 0);
        assert_eq!(reward_user_1.tx_fees_streamed_produced, 0);
        assert_eq!(reward_user_1.tx_fees_streamed_confirmed, 0);

    }
    
    #[test]
    fn miner_reward_one_miner_one_user_anchored_tx_fees_unfull() {
        let mut sample = vec![];
        let miner_1 = StacksAddress::from_string(&"SP1A2K3ENNA6QQ7G8DVJXM24T6QMBDVS7D0TRTAR5".to_string()).unwrap();
        let user_1 = StacksAddress::from_string(&"SP2837ZMC89J40K4YTS64B00M7065C6X46JX6ARG0".to_string()).unwrap();
        let mut participant = make_dummy_miner_payment_schedule(&miner_1, 500, 100, 0, 250, 1000);
        let mut user = make_dummy_user_payment_schedule(&user_1, 500, 0, 0, 750, 1000, 1);

        // blocks are NOT full
        let fill_cutoff = (((MINER_FEE_MINIMUM_BLOCK_USAGE as u128) << 64) / 100u128) as u64;
        participant.fill = fill_cutoff - 1;
        user.fill = fill_cutoff - 1;

        sample.push((participant.clone(), vec![user.clone()]));

        for i in 0..9 {
            let mut next_participant = make_dummy_miner_payment_schedule(&miner_1, 250, 100, 0, 250, 1000);
            let mut next_user = make_dummy_user_payment_schedule(&user_1, 750, 0, 0, 750, 1000, 1);

            next_participant.fill = fill_cutoff - 1;
            next_user.fill = fill_cutoff - 1;

            sample.push((next_participant, vec![next_user]));
        }

        let reward_miner_1 = StacksChainState::calculate_miner_reward(&participant, &sample);
        let reward_user_1 = StacksChainState::calculate_miner_reward(&user, &sample);
        
        // miner should have received 1/4 the coinbase, and miner should have received only shared
        assert_eq!(reward_miner_1.coinbase, 125);
        assert_eq!(reward_miner_1.tx_fees_anchored_shared, 1000);        // same miner, so they get everything
        assert_eq!(reward_miner_1.tx_fees_anchored_exclusive, 0);
        assert_eq!(reward_miner_1.tx_fees_streamed_produced, 0);
        assert_eq!(reward_miner_1.tx_fees_streamed_confirmed, 0);
        
        // user should have received 3/4 the coinbase, but no tx fees
        assert_eq!(reward_user_1.coinbase, 375);
        assert_eq!(reward_user_1.tx_fees_anchored_shared, 0);
        assert_eq!(reward_user_1.tx_fees_anchored_exclusive, 0);
        assert_eq!(reward_user_1.tx_fees_streamed_produced, 0);
        assert_eq!(reward_user_1.tx_fees_streamed_confirmed, 0);
    }
    
    #[test]
    fn miner_reward_two_miners_one_user_anchored_tx_fees_unfull() {
        let mut sample = vec![];
        let miner_1 = StacksAddress::from_string(&"SP1A2K3ENNA6QQ7G8DVJXM24T6QMBDVS7D0TRTAR5".to_string()).unwrap();
        let miner_2 = StacksAddress::from_string(&"SP8WWTGMNCCSB88QF4VYWN69PAMQRMF34FCT498G".to_string()).unwrap();
        let user_1 = StacksAddress::from_string(&"SP2837ZMC89J40K4YTS64B00M7065C6X46JX6ARG0".to_string()).unwrap();
        let mut participant_1 = make_dummy_miner_payment_schedule(&miner_1, 500, 100, 0, 250, 1000);
        let mut participant_2 = make_dummy_miner_payment_schedule(&miner_2, 500, 0, 0, 1000, 1000);
        let mut user = make_dummy_user_payment_schedule(&user_1, 500, 0, 0, 750, 1000, 1);

        // blocks are NOT full
        let fill_cutoff = (((MINER_FEE_MINIMUM_BLOCK_USAGE as u128) << 64) / 100u128) as u64;
        participant_1.fill = fill_cutoff - 1;
        participant_2.fill = fill_cutoff - 1;
        user.fill = fill_cutoff - 1;

        sample.push((participant_1.clone(), vec![user.clone()]));

        for i in 0..4 {
            let mut next_participant = make_dummy_miner_payment_schedule(&miner_1, 250, 100, 0, 250, 1000);
            let mut next_user = make_dummy_user_payment_schedule(&user_1, 750, 0, 0, 750, 1000, 1);

            next_participant.fill = fill_cutoff - 1;
            next_user.fill = fill_cutoff - 1;

            sample.push((next_participant, vec![next_user]));
        }
        
        for i in 0..5 {
            let mut next_participant = make_dummy_miner_payment_schedule(&miner_2, 250, 100, 0, 250, 1000);
            let mut next_user = make_dummy_user_payment_schedule(&user_1, 750, 0, 0, 750, 1000, 1);

            next_participant.fill = fill_cutoff - 1;
            next_user.fill = fill_cutoff - 1;

            sample.push((next_participant, vec![next_user]));
        }

        let reward_miner_1 = StacksChainState::calculate_miner_reward(&participant_1, &sample);
        let reward_miner_2 = StacksChainState::calculate_miner_reward(&participant_2, &sample);
        let reward_user_1 = StacksChainState::calculate_miner_reward(&user, &sample);
        
        // if miner 1 won, then it should have received 1/4 the coinbase, and miner should have received only shared tx fees
        assert_eq!(reward_miner_1.coinbase, 125);
        assert_eq!(reward_miner_1.tx_fees_anchored_shared, 500);        // did half the work over the sample
        assert_eq!(reward_miner_1.tx_fees_anchored_exclusive, 0);
        assert_eq!(reward_miner_1.tx_fees_streamed_produced, 0);
        assert_eq!(reward_miner_1.tx_fees_streamed_confirmed, 0);
       
        // if miner 2 won, then it would get all the coinbase (since it did all the burn), and
        // should only receive the shared tx fees
        assert_eq!(reward_miner_2.coinbase, 500);
        assert_eq!(reward_miner_2.tx_fees_anchored_shared, 500);        // did half the work over the sample
        assert_eq!(reward_miner_2.tx_fees_anchored_exclusive, 0);
        assert_eq!(reward_miner_2.tx_fees_streamed_produced, 0);
        assert_eq!(reward_miner_2.tx_fees_streamed_confirmed, 0);
        
        // user should have received 3/4 the coinbase, but no tx fees
        assert_eq!(reward_user_1.coinbase, 375);
        assert_eq!(reward_user_1.tx_fees_anchored_shared, 0);
        assert_eq!(reward_user_1.tx_fees_anchored_exclusive, 0);
        assert_eq!(reward_user_1.tx_fees_streamed_produced, 0);
        assert_eq!(reward_user_1.tx_fees_streamed_confirmed, 0);
    }
    
    #[test]
    fn miner_reward_two_miners_one_user_anchored_tx_fees_full() {
        let mut sample = vec![];
        let miner_1 = StacksAddress::from_string(&"SP1A2K3ENNA6QQ7G8DVJXM24T6QMBDVS7D0TRTAR5".to_string()).unwrap();
        let miner_2 = StacksAddress::from_string(&"SP8WWTGMNCCSB88QF4VYWN69PAMQRMF34FCT498G".to_string()).unwrap();
        let user_1 = StacksAddress::from_string(&"SP2837ZMC89J40K4YTS64B00M7065C6X46JX6ARG0".to_string()).unwrap();
        let mut participant_1 = make_dummy_miner_payment_schedule(&miner_1, 500, 100, 0, 250, 1000);
        let mut participant_2 = make_dummy_miner_payment_schedule(&miner_2, 500, 0, 0, 1000, 1000);
        let mut user = make_dummy_user_payment_schedule(&user_1, 500, 0, 0, 750, 1000, 1);

        let fill_cutoff = ((MINER_FEE_MINIMUM_BLOCK_USAGE as u128) << 64) / 100u128;

        // blocks are full to 90%
        let fill = ((90u128 << 64) / (100u128)) as u64;
        participant_1.fill = fill;
        participant_2.fill = fill;
        user.fill = fill;

        sample.push((participant_1.clone(), vec![user.clone()]));

        for i in 0..4 {
            let mut next_participant = make_dummy_miner_payment_schedule(&miner_1, 250, 100, 0, 250, 1000);
            let mut next_user = make_dummy_user_payment_schedule(&user_1, 750, 0, 0, 750, 1000, 1);

            next_participant.fill = fill;
            next_user.fill = fill;

            sample.push((next_participant, vec![next_user]));
        }
        
        for i in 0..5 {
            let mut next_participant = make_dummy_miner_payment_schedule(&miner_2, 250, 100, 0, 250, 1000);
            let mut next_user = make_dummy_user_payment_schedule(&user_1, 750, 0, 0, 750, 1000, 1);

            next_participant.fill = fill;
            next_user.fill = fill;

            sample.push((next_participant, vec![next_user]));
        }

        let reward_miner_1 = StacksChainState::calculate_miner_reward(&participant_1, &sample);
        let reward_miner_2 = StacksChainState::calculate_miner_reward(&participant_2, &sample);
        let reward_user_1 = StacksChainState::calculate_miner_reward(&user, &sample);

        let expected_shared = 
            if (500 * fill_cutoff) & 0x0000000000000000ffffffffffffffff > 0x00000000000000007fffffffffffffff {
                ((500 * fill_cutoff) >> 64) + 1
            }
            else {
                (500 * fill_cutoff) >> 64
            };
        
        // if miner 1 won, then it should have received 1/4 the coinbase
        assert_eq!(reward_miner_1.coinbase, 125);
        assert_eq!(reward_miner_1.tx_fees_anchored_shared, expected_shared);        // did half the work over the sample
        assert_eq!(reward_miner_1.tx_fees_anchored_exclusive, 500 - expected_shared);
        assert_eq!(reward_miner_1.tx_fees_streamed_produced, 0);
        assert_eq!(reward_miner_1.tx_fees_streamed_confirmed, 0);
       
        // if miner 2 won, then it would get all the coinbase (since it did all the burn)
        assert_eq!(reward_miner_2.coinbase, 500);
        assert_eq!(reward_miner_2.tx_fees_anchored_shared, expected_shared);        // did half the work over the sample
        assert_eq!(reward_miner_2.tx_fees_anchored_exclusive, 500 - expected_shared);
        assert_eq!(reward_miner_2.tx_fees_streamed_produced, 0);
        assert_eq!(reward_miner_2.tx_fees_streamed_confirmed, 0);
        
        // user should have received 3/4 the coinbase, but no tx fees
        assert_eq!(reward_user_1.coinbase, 375);
        assert_eq!(reward_user_1.tx_fees_anchored_shared, 0);
        assert_eq!(reward_user_1.tx_fees_anchored_exclusive, 0);
        assert_eq!(reward_user_1.tx_fees_streamed_produced, 0);
        assert_eq!(reward_user_1.tx_fees_streamed_confirmed, 0);
    }
    
    #[test]
    fn miner_reward_two_miners_one_user_anchored_tx_fees_full_streamed() {
        let mut sample = vec![];
        let miner_1 = StacksAddress::from_string(&"SP1A2K3ENNA6QQ7G8DVJXM24T6QMBDVS7D0TRTAR5".to_string()).unwrap();
        let miner_2 = StacksAddress::from_string(&"SP8WWTGMNCCSB88QF4VYWN69PAMQRMF34FCT498G".to_string()).unwrap();
        let user_1 = StacksAddress::from_string(&"SP2837ZMC89J40K4YTS64B00M7065C6X46JX6ARG0".to_string()).unwrap();
        let mut participant_1 = make_dummy_miner_payment_schedule(&miner_1, 500, 100, 100, 250, 1000);
        let mut participant_2 = make_dummy_miner_payment_schedule(&miner_2, 500, 0, 0, 1000, 1000);
        let mut user = make_dummy_user_payment_schedule(&user_1, 500, 0, 0, 750, 1000, 1);

        let fill_cutoff = ((MINER_FEE_MINIMUM_BLOCK_USAGE as u128) << 64) / 100u128;

        // blocks are full to 90%
        let fill = ((90u128 << 64) / (100u128)) as u64;
        participant_1.fill = fill;
        participant_2.fill = fill;
        user.fill = fill;

        sample.push((participant_1.clone(), vec![user.clone()]));

        for i in 0..4 {
            let mut next_participant = make_dummy_miner_payment_schedule(&miner_1, 250, 100, 100, 250, 1000);
            let mut next_user = make_dummy_user_payment_schedule(&user_1, 750, 0, 0, 750, 1000, 1);

            next_participant.fill = fill;
            next_user.fill = fill;

            sample.push((next_participant, vec![next_user]));
        }
        
        for i in 0..5 {
            let mut next_participant = make_dummy_miner_payment_schedule(&miner_2, 250, 100, 100, 250, 1000);
            let mut next_user = make_dummy_user_payment_schedule(&user_1, 750, 0, 0, 750, 1000, 1);

            next_participant.fill = fill;
            next_user.fill = fill;

            sample.push((next_participant, vec![next_user]));
        }

        let reward_miner_1 = StacksChainState::calculate_miner_reward(&participant_1, &sample);
        let reward_miner_2 = StacksChainState::calculate_miner_reward(&participant_2, &sample);
        let reward_user_1 = StacksChainState::calculate_miner_reward(&user, &sample);

        let expected_shared = 
            if (500 * fill_cutoff) & 0x0000000000000000ffffffffffffffff > 0x00000000000000007fffffffffffffff {
                ((500 * fill_cutoff) >> 64) + 1
            }
            else {
                (500 * fill_cutoff) >> 64
            };
        
        // if miner 1 won, then it should have received 1/4 the coinbase
        assert_eq!(reward_miner_1.coinbase, 125);
        assert_eq!(reward_miner_1.tx_fees_anchored_shared, expected_shared);        // did half the work over the sample
        assert_eq!(reward_miner_1.tx_fees_anchored_exclusive, 500 - expected_shared);
        assert_eq!(reward_miner_1.tx_fees_streamed_produced, 240);                  // produced half of the microblocks, should get half the 2/5 of the reward
        assert_eq!(reward_miner_1.tx_fees_streamed_confirmed, 240);                 // confirmed half of the microblocks, should get half of the 3/5 reward
       
        // if miner 2 won, then it would get all the coinbase (since it did all the burn)
        assert_eq!(reward_miner_2.coinbase, 500);
        assert_eq!(reward_miner_2.tx_fees_anchored_shared, expected_shared);        // did half the work over the sample
        assert_eq!(reward_miner_2.tx_fees_anchored_exclusive, 500 - expected_shared);
        assert_eq!(reward_miner_2.tx_fees_streamed_produced, 200);
        assert_eq!(reward_miner_2.tx_fees_streamed_confirmed, 300);
        
        // user should have received 3/4 the coinbase, but no tx fees
        assert_eq!(reward_user_1.coinbase, 375);
        assert_eq!(reward_user_1.tx_fees_anchored_shared, 0);
        assert_eq!(reward_user_1.tx_fees_anchored_exclusive, 0);
        assert_eq!(reward_user_1.tx_fees_streamed_produced, 0);
        assert_eq!(reward_user_1.tx_fees_streamed_confirmed, 0);
    }
}
