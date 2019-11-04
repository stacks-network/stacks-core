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
use vm::database::*;
use vm::database::marf::*;

use vm::types::*;

use util::db::*;
use util::db::Error as db_error;

impl MinerPaymentSchedule {
    /// Get the fraction of the stream fees that go to the miner that _mined_ the stream
    pub fn get_tx_fees_streamed_mined(&self) -> u128 {
        // 40% of the stream
        (self.tx_fees_anchored * 2) / 5
    }

    /// Get the fraction of the stream fees that go to the miner that _confirmed_ the stream
    pub fn get_tx_fees_streamed_confirmed(&self) -> u128 {
        // 60% of the stream
        (self.tx_fees_anchored * 3) / 5
    }
}

impl RowOrder for MinerPaymentSchedule {
    fn row_order() -> Vec<&'static str> {
        vec!["address","block_hash","coinbase","tx_fees_anchored","tx_fees_streamed","burns"]
    }
}

impl FromRow<MinerPaymentSchedule> for MinerPaymentSchedule {
    fn from_row<'a>(row: &'a Row, index: usize) -> Result<MinerPaymentSchedule, db_error> {
        let address = StacksAddress::from_row(row, 0 + index)?;
        let block_hash = BlockHeaderHash::from_row(row, 1 + index)?;
        
        let coinbase_text : String = row.get(2 + index);
        let tx_fees_anchored_text : String = row.get(3 + index);
        let tx_fees_streamed_text : String = row.get(4 + index);
        let burns_text : String = row.get(5 + index);

        let coinbase = coinbase_text.parse::<u128>().map_err(|_e| db_error::ParseError)?;
        let tx_fees_anchored = tx_fees_anchored_text.parse::<u128>().map_err(|_e| db_error::ParseError)?;
        let tx_fees_streamed = tx_fees_streamed_text.parse::<u128>().map_err(|_e| db_error::ParseError)?;
        let burns = burns_text.parse::<u128>().map_err(|_e| db_error::ParseError)?;

        let payment_data = MinerPaymentSchedule {
            address,
            block_hash,
            coinbase,
            tx_fees_anchored,
            tx_fees_streamed,
            burns,
        };
        Ok(payment_data)
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
        }).unwrap()
    }

    pub fn get_account_ft<'a>(clarity_tx: &mut ClarityTx<'a>, contract_id: &QualifiedContractIdentifier, token_name: &str, principal: &PrincipalData) -> Result<i128, Error> {
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
        }).unwrap()
    }

    /// Called each time a transaction sends STX to this principal.
    /// No nonce update is needed, since the transfer action is not taken by the principal.
    pub fn account_credit<'a>(clarity_tx: &mut ClarityTx<'a>, principal: &PrincipalData, amount: u64) {
        clarity_tx.connection().with_clarity_db(|ref mut db| {
            let cur_balance = db.get_account_stx_balance(principal);
            let final_balance = cur_balance.checked_add(amount as u128).expect("FATAL: account balance overflow");
            db.set_account_stx_balance(principal, amount as u128);
            Ok(())
        }).unwrap()
    }
    
    /// Verify that this transaction is not a replay, and update its nonce.
    pub fn update_account_nonce<'a>(clarity_tx: &mut ClarityTx<'a>, tx: &StacksTransaction, account: &StacksAccount) {
        clarity_tx.connection().with_clarity_db(|ref mut db| {
            let next_nonce = account.nonce.checked_add(1).expect("OUT OF NONCES");
            db.set_account_nonce(&account.principal, next_nonce);
            Ok(())
        }).unwrap()
    }

    // TODO: this needs to be inserted directly into a miner trust smart contract
    pub fn insert_miner_payment_schedule<'a>(tx: &mut StacksDBTx<'a>, tip_info: &StacksHeaderInfo, block_reward: &MinerPaymentSchedule) -> Result<(), Error> {
        let child_streamed_tx_fee = block_reward.get_tx_fees_streamed_confirmed();
        let parent_streamed_tx_fee = block_reward.get_tx_fees_streamed_mined();

        let tip = &tip_info.anchored_header;

        tx.execute("INSERT INTO payments (address,block_hash,burn_block_hash,coinbase,tx_fees_anchored,tx_fees_streamed,burns,index_root,stacks_block_height) \
                    VALUES (?1,?2,?3,?4,?5,?6,?7,?8,?9,?10,?11)",
                    &[&block_reward.address.to_string(), &tip.block_hash().to_hex(), &tip_info.burn_block_hash.to_hex(), &format!("{}", block_reward.coinbase), &format!("{}", block_reward.tx_fees_anchored),
                      &format!("{}", child_streamed_tx_fee), &format!("{}", block_reward.burns), &tip_info.index_root.to_hex(), &(tip_info.block_height as i64) as &ToSql])
            .map_err(|e| Error::DBError(db_error::SqliteError(e)))?;

        if tip_info.block_height > 0 {
            match StacksChainState::get_block_reward_in_fork(tx, tip_info, tip_info.block_height - 1)? {
                Some(payment_schedule) => {
                    tx.execute("UPDATE payments SET tx_fees_streamed = tx_fees_streamed + ?1 WHERE address = ?2 AND block_hash = ?3",
                               &[&format!("{}", parent_streamed_tx_fee), &tip.parent_block.to_hex(), &payment_schedule.address.to_string()])
                        .map_err(|e| Error::DBError(db_error::SqliteError(e)))?;
                },
                None => {
                    panic!("No reward for non-zero parent block {}", tip_info.block_height - 1);
                }
            };
        }
        Ok(())
    }
 
    fn get_block_reward(conn: &DBConn, block_hash: &BlockHeaderHash) -> Result<Option<MinerPaymentSchedule>, Error> {
        let row_order = MinerPaymentSchedule::row_order().join(",");
        let qry = format!("SELECT {} FROM rewards WHERE block_hash = ?1", row_order);
        let args = [&block_hash.to_hex()];
        let rows = query_rows::<MinerPaymentSchedule, _>(conn, &qry, &args).map_err(Error::DBError)?;
        match rows.len() {
            0 => Ok(None),
            1 => Ok(Some(rows[0].clone())),
            _ => panic!("Multiple block rewards for block {}", block_hash.to_hex())
        }
    }

    fn get_block_reward_in_fork<'a>(tx: &mut StacksDBTx<'a>, tip: &StacksHeaderInfo, block_height: u64) -> Result<Option<MinerPaymentSchedule>, Error> {
        let ancestor_info = match StacksChainState::get_tip_ancestor(tx, tip, block_height)? {
            Some(info) => info,
            None => {
                return Ok(None);
            }
        };
        
        let row_order = MinerPaymentSchedule::row_order().join(",");
        let qry = format!("SELECT {} FROM rewards WHERE block_hash = ?1 AND burn_block_hash = ?2", row_order);
        let args = [&ancestor_info.anchored_header.block_hash().to_hex(), &ancestor_info.burn_block_hash.to_hex()];
        let rows = query_rows::<MinerPaymentSchedule, _>(tx, &qry, &args).map_err(Error::DBError)?;
        match rows.len() {
            0 => Ok(None),
            1 => Ok(Some(rows[0].clone())),
            _ => panic!("Multiple block rewards for block {}", ancestor_info.anchored_header.block_hash().to_hex())
        }
    }
}
