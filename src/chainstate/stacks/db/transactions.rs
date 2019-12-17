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

use std::io;
use std::io::prelude::*;
use std::fmt;
use std::fs;
use std::collections::{HashSet, HashMap};

use chainstate::stacks::Error;
use chainstate::stacks::*;
use chainstate::stacks::db::*;

use std::path::{Path, PathBuf};

use util::db::Error as db_error;
use util::db::{
    DBConn,
    query_rows,
    query_count
};

use util::strings::StacksString;

use util::hash::to_hex;

use chainstate::burn::db::burndb::*;

use net::Error as net_error;

use vm::types::{
    PrincipalData,
    StandardPrincipalData,
    QualifiedContractIdentifier
};

use vm::contexts::{
    AssetMap
};

use vm::ast::build_ast;
use vm::analysis::run_analysis;
use vm::types::{
    Value,
    AssetIdentifier
};

use vm::clarity::{
    ClarityBlockConnection,
    ClarityInstance
};

pub use vm::analysis::errors::CheckErrors;
use vm::clarity::Error as clarity_error;

use vm::database::ClarityDatabase;

use vm::contracts::Contract;

impl StacksChainState {
    /// Look up an account given the spending condition
    fn get_spending_account<'a>(clarity_tx: &mut ClarityTx<'a>, spending_condition: &TransactionSpendingCondition) -> StacksAccount {
        let addr = 
            if clarity_tx.config.mainnet {
                spending_condition.address_mainnet()
            }
            else {
                spending_condition.address_testnet()
            };
        
        let principal_data = PrincipalData::Standard(StandardPrincipalData::from(addr));
        StacksChainState::get_account(clarity_tx, &principal_data)
    }

    /// Pay the transaction fee (but don't credit it to the miner yet).
    /// Does not touch the account nonce
    /// TODO: the fee paid here isn't the bare fee in the transaction, but is instead the
    /// block-wide STX/compute-unit rate, times the compute units used by this tx.
    fn pay_transaction_fee<'a>(clarity_tx: &mut ClarityTx<'a>, tx: &StacksTransaction, payer_account: &StacksAccount) -> Result<u64, Error> {
        if payer_account.stx_balance < tx.get_fee_rate() as u128 {
            return Err(Error::InvalidFee);
        }
        StacksChainState::account_debit(clarity_tx, &payer_account.principal, tx.get_fee_rate());
        Ok(tx.get_fee_rate())
    }

    /// Pre-check a transaction -- make sure it's well-formed
    fn process_transaction_precheck<'a>(clarity_tx: &mut ClarityTx<'a>, tx: &StacksTransaction) -> Result<(), Error> {
        // valid auth?
        if !tx.verify().map_err(Error::NetError)? {
            let msg = format!("Invalid tx {}: invalid signature(s)", tx.txid().to_hex());
            warn!("{}", &msg);

            return Err(Error::InvalidStacksTransaction(msg));
        }

        // destined for us?
        if clarity_tx.config.chain_id != tx.chain_id {
            let msg = format!("Invalid tx {}: invalid chain ID {} (expected {})", tx.txid().to_hex(), tx.chain_id, clarity_tx.config.chain_id);
            warn!("{}", &msg);

            return Err(Error::InvalidStacksTransaction(msg));
        }

        match tx.version {
            TransactionVersion::Mainnet => {
                if !clarity_tx.config.mainnet {
                    let msg = format!("Invalid tx {}: on testnet; got mainnet", tx.txid().to_hex());
                    warn!("{}", &msg);

                    return Err(Error::InvalidStacksTransaction(msg));
                }
            },
            TransactionVersion::Testnet => {
                if clarity_tx.config.mainnet {
                    let msg = format!("Invalid tx {}: on mainnet; got testnet", tx.txid().to_hex());
                    warn!("{}", &msg);

                    return Err(Error::InvalidStacksTransaction(msg));
                }
            }
        }

        Ok(())
    }
    
    /// Apply a post-conditions check.
    /// Return true if they all pass.
    /// Return false if at least one fails.
    fn check_transaction_postconditions<'a>(clarity_db: &mut ClarityDatabase<'a>, tx: &StacksTransaction, origin_account: &StacksAccount, asset_map: &AssetMap) -> bool {
        let mut checked_assets : HashMap<PrincipalData, HashSet<AssetIdentifier>> = HashMap::new();
        let allow_unchecked_assets = tx.post_condition_mode == TransactionPostConditionMode::Allow;

        for postcond in tx.post_conditions.iter() {
            match postcond {
                TransactionPostCondition::STX(ref principal, ref condition_code, ref amount_sent_condition) => {
                    let account_principal = principal.to_principal_data(&origin_account.principal);
                    let amount_sent = asset_map.get_stx(&account_principal).unwrap_or(0);
                    if !condition_code.check(*amount_sent_condition as u128, amount_sent) {
                        debug!("Post-condition check failure on STX owned by {:?}: {:?} {:?} {}", account_principal, amount_sent_condition, condition_code, amount_sent);
                        return false;
                    }

                    if let Some(ref mut asset_ids) = checked_assets.get_mut(&account_principal) {
                        asset_ids.insert(AssetIdentifier::STX());
                    }
                    else {
                        let mut h = HashSet::new();
                        h.insert(AssetIdentifier::STX());
                        checked_assets.insert(account_principal, h);
                    }
                },
                TransactionPostCondition::Fungible(ref principal, ref asset_info, ref condition_code, ref amount_sent_condition) => {
                    let account_principal = principal.to_principal_data(&origin_account.principal);
                    let asset_id = AssetIdentifier {
                        contract_identifier: QualifiedContractIdentifier::new(StandardPrincipalData::from(asset_info.contract_address.clone()), asset_info.contract_name.clone()),
                        asset_name: asset_info.asset_name.clone()
                    };

                    let amount_sent = asset_map.get_fungible_tokens(&account_principal, &asset_id).unwrap_or(0);
                    if !condition_code.check(*amount_sent_condition as u128, amount_sent) {
                        debug!("Post-condition check failure on fungible asset {:?} owned by {:?}: {:?} {:?} {}", &asset_id, account_principal, amount_sent_condition, condition_code, amount_sent);
                        return false;
                    }
                    
                    if let Some(ref mut asset_ids) = checked_assets.get_mut(&account_principal) {
                        asset_ids.insert(asset_id);
                    }
                    else {
                        let mut h = HashSet::new();
                        h.insert(asset_id);
                        checked_assets.insert(account_principal, h);
                    }
                },
                TransactionPostCondition::Nonfungible(ref principal, ref asset_info, ref asset_value, ref condition_code) => {
                    let account_principal = principal.to_principal_data(&origin_account.principal);
                    let asset_id = AssetIdentifier {
                        contract_identifier: QualifiedContractIdentifier::new(StandardPrincipalData::from(asset_info.contract_address.clone()), asset_info.contract_name.clone()),
                        asset_name: asset_info.asset_name.clone()
                    };

                    let empty_assets = vec![];
                    let assets_sent = asset_map.get_nonfungible_tokens(&account_principal, &asset_id).unwrap_or(&empty_assets);
                    if !condition_code.check(asset_value, assets_sent) {
                        debug!("Post-condition check failure on non-fungible asset {:?} owned by {:?}: {:?} {:?}", &asset_id, account_principal, &asset_value, condition_code);
                        return false;
                    }

                    if let Some(ref mut asset_ids) = checked_assets.get_mut(&account_principal) {
                        asset_ids.insert(asset_id);
                    }
                    else {
                        let mut h = HashSet::new();
                        h.insert(asset_id);
                        checked_assets.insert(account_principal, h);
                    }
                }
            }
        }

        if !allow_unchecked_assets {
            // make sure every asset transferred is covered by a postcondition
            let asset_map_copy = (*asset_map).clone();
            let mut all_assets_sent = asset_map_copy.to_table();
            for (principal, mut assets) in all_assets_sent.drain() {
                if checked_assets.get(&principal).is_none() {
                    debug!("Post-condition check failure: checks did not cover transfers from {:?}", &principal);
                    return false;
                };
                for (asset_identifier, _) in assets.drain() {
                    let checked_asset_ids = checked_assets.get(&principal).expect("FATAL: principal transferred no assets, despite earlier check");
                    if !checked_asset_ids.contains(&asset_identifier) {
                        debug!("Post-condition check failure: checks did not cover transfer of {:?} by {:?}", &asset_identifier, &principal);
                        return false;
                    }
                }
            }
        }
        return true;
    }

    /// Process a token transfer payload (but pass the transaction that wraps it, in order to do
    /// post-condition checks).
    fn process_transaction_token_transfer<'a>(clarity_tx: &mut ClarityTx<'a>, txid: &Txid, addr: &StacksAddress, amount: u64, origin_account: &StacksAccount) -> Result<(), Error> {
        let recipient_principal = PrincipalData::Standard(StandardPrincipalData::from(addr.clone()));
        
        if origin_account.principal == recipient_principal {
            // not allowed to send to yourself
            let msg = format!("Error validating STX-transfer transaction: address tried to send to itself");
            warn!("{}", &msg);
            return Err(Error::InvalidStacksTransaction(msg));
        }

        clarity_tx.connection().with_clarity_db(|ref mut db| {
            // does the sender have ths amount?
            let cur_balance = db.get_account_stx_balance(&origin_account.principal);
            if cur_balance < (amount as u128) {
                return Err(clarity_error::BadTransaction(format!("Address {:?} has {} microSTX; needed at least {}", &origin_account.principal, cur_balance, amount)));
            }

            let recipient_balance = db.get_account_stx_balance(&recipient_principal);
            if recipient_balance.checked_add(amount as u128).is_none() {
                return Err(clarity_error::BadTransaction(format!("Address {:?} has {} microSTX; cannot add {}", &recipient_principal, recipient_balance, amount)));
            }

            let new_balance = cur_balance - (amount as u128);
            let new_recipient_balance = recipient_balance + (amount as u128);

            db.set_account_stx_balance(&origin_account.principal, new_balance);
            db.set_account_stx_balance(&recipient_principal, new_recipient_balance);

            let mut asset_map = AssetMap::new();
            asset_map.add_stx_transfer(&origin_account.principal, amount as u128)?;

            Ok(())
        }).map_err(|e| {
            match e {
                clarity_error::BadTransaction(ref s) => {
                    let msg = format!("Error validating STX-transfer transaction {:?}: {}", txid.to_hex(), s);
                    warn!("{}", &msg);

                    Error::InvalidStacksTransaction(msg)
                },
                clarity_error::PostCondition(ref s) => {
                    unreachable!()
                },
                _ => Error::ClarityError(e)
            }
        })
    }

    /// Process the transaction's payload, and run the post-conditions against the resulting state.
    /// Returns the number of STX burned.
    pub fn process_transaction_payload<'a>(clarity_tx: &mut ClarityTx<'a>, tx: &StacksTransaction, origin_account: &StacksAccount) -> Result<u128, Error> {
        let stx_burned = match tx.payload {
            TransactionPayload::TokenTransfer(ref addr, ref amount, ref _memo) => {
                // post-conditions are not allowed for this variant, since they're non-sensical 
                if tx.post_conditions.len() > 0 {
                    let msg = format!("Invalid Stacks transaction: TokenTransfer transactions do not support post-conditions");
                    warn!("{}", &msg);

                    return Err(Error::InvalidStacksTransaction(msg));
                }

                StacksChainState::process_transaction_token_transfer(clarity_tx, &tx.txid(), addr, *amount, origin_account)?;

                // no burns
                0
            },
            TransactionPayload::ContractCall(ref contract_call) => {
                let contract_id = contract_call.to_clarity_contract_id();
                let (_, asset_map) = clarity_tx.connection().run_contract_call(&origin_account.principal, &contract_id, &contract_call.function_name, &contract_call.function_args,
                                                                               |asset_map, ref mut clarity_db| { !StacksChainState::check_transaction_postconditions(clarity_db, tx, origin_account, asset_map) })
                    .map_err(Error::ClarityError)?;

                asset_map.get_stx_burned_total()
            },
            TransactionPayload::SmartContract(ref smart_contract) => {
                let issuer_principal = match origin_account.principal {
                    PrincipalData::Standard(ref p) => {
                        p.clone()
                    },
                    _ => {
                        panic!("Transaction issued by something other than a standard principal");
                    }
                };

                let contract_id = QualifiedContractIdentifier::new(issuer_principal, smart_contract.name.clone());
                let contract_code_str = smart_contract.code_body.to_string();

                // can't be instantiated already
                if StacksChainState::get_contract(clarity_tx, &contract_id)?.is_some() {
                    let msg = format!("Duplicate contract '{}'", &contract_id);
                    warn!("{}", &msg);

                    return Err(Error::InvalidStacksTransaction(msg));
                }

                // analysis pass
                let (contract_ast, contract_analysis) = clarity_tx.connection().analyze_smart_contract(&contract_id, &contract_code_str).map_err(Error::ClarityError)?;

                // execution
                let asset_map = clarity_tx.connection().initialize_smart_contract(&contract_id, &contract_ast,
                                                                                 |asset_map, ref mut clarity_db| { !StacksChainState::check_transaction_postconditions(clarity_db, tx, origin_account, asset_map) })
                    .map_err(Error::ClarityError)?;

                // store analysis
                clarity_tx.connection().save_analysis(&contract_id, &contract_analysis).map_err(|e| Error::ClarityError(clarity_error::Analysis(e)))?;
                
                asset_map.get_stx_burned_total()
            },
            TransactionPayload::PoisonMicroblock(ref mblock_header_1, ref mblock_header_2) => {
                panic!("Not implemented yet");
            },
            TransactionPayload::Coinbase(ref miner_payload) => {
                // no-op; not handled here
                0
            }
        };

        Ok(stx_burned as u128)
    }

    /// Process a transaction.  Return the fee and amount of STX destroyed
    pub fn process_transaction<'a>(clarity_tx: &mut ClarityTx<'a>, tx: &StacksTransaction) -> Result<(u64, u128), Error> {
        test_debug!("Process transaction {}", tx.txid().to_hex());

        StacksChainState::process_transaction_precheck(clarity_tx, tx)?;

        // who's sending it?
        let origin = tx.get_origin();
        let origin_account = StacksChainState::get_spending_account(clarity_tx, &origin);

        // who's paying the fee?
        let payer = tx.get_payer();
        let payer_account = StacksChainState::get_spending_account(clarity_tx, &payer);

        // check nonces
        if origin.nonce() != origin_account.nonce {
            let msg = format!("Bad nonce: origin account nonce of tx {} is {} (expected {})", tx.txid().to_hex(), origin.nonce(), origin_account.nonce);
            warn!("{}", &msg);
            return Err(Error::InvalidStacksTransaction(msg));
        }

        if payer.nonce() != payer_account.nonce {
            let msg = format!("Bad nonce: payer account nonce of tx {} is {} (expected {})", tx.txid().to_hex(), payer.nonce(), payer_account.nonce);
            warn!("{}", &msg);
            return Err(Error::InvalidStacksTransaction(msg));
        }

        // pay fee
        // TODO: don't do this here; do it when we know what the STX/compute rate will be, and then
        // debit the account (aborting the _whole block_ if the balance would go negative)
        let fee = StacksChainState::pay_transaction_fee(clarity_tx, tx, &payer_account)?;
    
        let burns = StacksChainState::process_transaction_payload(clarity_tx, tx, &origin_account)?;

        // update the account nonces
        StacksChainState::update_account_nonce(clarity_tx, tx, &origin_account);
        if origin != payer {
            StacksChainState::update_account_nonce(clarity_tx, tx, &payer_account);
        }

        Ok((fee, burns))
    }
}

#[cfg(test)]
pub mod test {
    use super::*;
    use chainstate::*;
    use chainstate::stacks::*;
    use chainstate::stacks::Error;
    use chainstate::stacks::db::test::*;
    use chainstate::stacks::index::*;
    use chainstate::stacks::index::storage::*;
    use burnchains::Address;

    use vm::contracts::Contract;
    use vm::types::*;
    use vm::representations::ContractName;
    use vm::representations::ClarityName;
   
    #[test]
    fn process_token_transfer_stx_transaction() {
        let mut chainstate = instantiate_chainstate(false, 0x80000000, "process-token-transfer-stx-transaction");

        let privk = StacksPrivateKey::from_hex("6d430bb91222408e7706c9001cfaeb91b08c2be6d5ac95779ab52c6b431950e001").unwrap();
        let auth = TransactionAuth::from_p2pkh(&privk).unwrap();
        let addr = auth.origin().address_testnet();
        let recv_addr = StacksAddress { version: 1, bytes: Hash160([0xff; 20]) };

        let mut tx_stx_transfer = StacksTransaction::new(TransactionVersion::Testnet,
                                                         auth.clone(),
                                                         TransactionPayload::TokenTransfer(recv_addr.clone(), 123, TokenTransferMemo([0u8; 34])));

        tx_stx_transfer.chain_id = 0x80000000;
        tx_stx_transfer.post_condition_mode = TransactionPostConditionMode::Allow;
        tx_stx_transfer.set_fee_rate(0);
        
        let mut signer = StacksTransactionSigner::new(&tx_stx_transfer);
        signer.sign_origin(&privk).unwrap();

        let signed_tx = signer.get_tx().unwrap();

        let mut conn = chainstate.block_begin(&FIRST_BURNCHAIN_BLOCK_HASH, &FIRST_STACKS_BLOCK_HASH, &BurnchainHeaderHash([1u8; 32]), &BlockHeaderHash([1u8; 32]));

        // give the spending account some stx
        let account = StacksChainState::get_account(&mut conn, &addr.to_account_principal());
        let recv_account = StacksChainState::get_account(&mut conn, &recv_addr.to_account_principal());

        assert_eq!(recv_account.stx_balance, 0);
        assert_eq!(recv_account.nonce, 0);

        StacksChainState::account_credit(&mut conn, &addr.to_account_principal(), 123);

        let (fee, _) = StacksChainState::process_transaction(&mut conn, &signed_tx).unwrap();
        
        let account_after = StacksChainState::get_account(&mut conn, &addr.to_account_principal());
        assert_eq!(account_after.nonce, 1);
        assert_eq!(account_after.stx_balance, 0);

        let recv_account_after = StacksChainState::get_account(&mut conn, &recv_addr.to_account_principal());
        assert_eq!(recv_account_after.nonce, 0);
        assert_eq!(recv_account_after.stx_balance, 123);
        
        conn.commit_block();

        assert_eq!(fee, 0);
    }
    
    #[test]
    fn process_token_transfer_stx_transaction_invalid() {
        let mut chainstate = instantiate_chainstate(false, 0x80000000, "process-token-transfer-stx-transaction-invalid");

        let privk = StacksPrivateKey::from_hex("6d430bb91222408e7706c9001cfaeb91b08c2be6d5ac95779ab52c6b431950e001").unwrap();
        let privk_sponsor = StacksPrivateKey::from_hex("7e3af4db6af6b3c67e2c6c6d7d5983b519f4d9b3a6e00580ae96dcace3bde8bc01").unwrap();

        let auth = TransactionAuth::from_p2pkh(&privk).unwrap();
        let addr = auth.origin().address_testnet();
        let recv_addr = addr.clone();       // shouldn't be allowed
        
        let auth_sponsored = {
            let auth_origin = TransactionAuth::from_p2pkh(&privk).unwrap();
            let auth_sponsor = TransactionAuth::from_p2pkh(&privk_sponsor).unwrap();
            auth_origin.into_sponsored(auth_sponsor).unwrap()
        };

        let mut tx_stx_transfer_same_receiver = StacksTransaction::new(TransactionVersion::Testnet,
                                                                       auth.clone(),
                                                                       TransactionPayload::TokenTransfer(recv_addr.clone(), 123, TokenTransferMemo([0u8; 34])));

        let mut tx_stx_transfer_wrong_network = StacksTransaction::new(TransactionVersion::Mainnet,
                                                                       auth.clone(),
                                                                       TransactionPayload::TokenTransfer(recv_addr.clone(), 123, TokenTransferMemo([0u8; 34])));
        
        let mut tx_stx_transfer_wrong_chain_id = StacksTransaction::new(TransactionVersion::Testnet,
                                                                        auth.clone(),
                                                                        TransactionPayload::TokenTransfer(recv_addr.clone(), 123, TokenTransferMemo([0u8; 34])));
        
        let mut wrong_nonce_auth = auth.clone();
        wrong_nonce_auth.set_origin_nonce(1);
        let mut tx_stx_transfer_wrong_nonce = StacksTransaction::new(TransactionVersion::Testnet,
                                                                     wrong_nonce_auth,
                                                                     TransactionPayload::TokenTransfer(recv_addr.clone(), 123, TokenTransferMemo([0u8; 34])));

        let mut wrong_nonce_auth_sponsored = auth_sponsored.clone();
        wrong_nonce_auth_sponsored.set_sponsor_nonce(1);
        let mut tx_stx_transfer_wrong_nonce_sponsored = StacksTransaction::new(TransactionVersion::Testnet,
                                                                               wrong_nonce_auth_sponsored,
                                                                               TransactionPayload::TokenTransfer(recv_addr.clone(), 123, TokenTransferMemo([0u8; 34])));

        tx_stx_transfer_same_receiver.chain_id = 0x80000000;
        tx_stx_transfer_wrong_network.chain_id = 0x80000000;
        tx_stx_transfer_wrong_chain_id.chain_id = 0x80000001;
        tx_stx_transfer_wrong_nonce.chain_id = 0x80000000;
        tx_stx_transfer_wrong_nonce_sponsored.chain_id = 0x80000000;

        tx_stx_transfer_same_receiver.post_condition_mode = TransactionPostConditionMode::Allow;
        tx_stx_transfer_wrong_network.post_condition_mode = TransactionPostConditionMode::Allow;
        tx_stx_transfer_wrong_chain_id.post_condition_mode = TransactionPostConditionMode::Allow;
        tx_stx_transfer_wrong_nonce.post_condition_mode = TransactionPostConditionMode::Allow;
        tx_stx_transfer_wrong_nonce_sponsored.post_condition_mode = TransactionPostConditionMode::Allow;

        tx_stx_transfer_same_receiver.set_fee_rate(0);
        tx_stx_transfer_wrong_network.set_fee_rate(0);
        tx_stx_transfer_wrong_chain_id.set_fee_rate(0);
        tx_stx_transfer_wrong_nonce.set_fee_rate(0);
        tx_stx_transfer_wrong_nonce_sponsored.set_fee_rate(0);

        let error_frags = vec![
            "address tried to send to itself".to_string(),
            "on testnet; got mainnet".to_string(),
            "invalid chain ID".to_string(),
            "Bad nonce".to_string(),
            "Bad nonce".to_string(),
        ];

        let mut conn = chainstate.block_begin(&FIRST_BURNCHAIN_BLOCK_HASH, &FIRST_STACKS_BLOCK_HASH, &BurnchainHeaderHash([1u8; 32]), &BlockHeaderHash([1u8; 32]));
        StacksChainState::account_credit(&mut conn, &addr.to_account_principal(), 123);
        
        for (tx_stx_transfer, err_frag) in [tx_stx_transfer_same_receiver, tx_stx_transfer_wrong_network, tx_stx_transfer_wrong_chain_id, tx_stx_transfer_wrong_nonce, tx_stx_transfer_wrong_nonce_sponsored].iter().zip(error_frags) {
            let mut signer = StacksTransactionSigner::new(&tx_stx_transfer);
            signer.sign_origin(&privk).unwrap();
            
            if tx_stx_transfer.auth.is_sponsored() {
                signer.sign_sponsor(&privk_sponsor).unwrap();
            }

            let signed_tx = signer.get_tx().unwrap();

            // give the spending account some stx
            let account = StacksChainState::get_account(&mut conn, &addr.to_account_principal());

            assert_eq!(account.stx_balance, 123);
            assert_eq!(account.nonce, 0);

            let res = StacksChainState::process_transaction(&mut conn, &signed_tx);
            assert!(res.is_err());
            
            match res {
                Err(Error::InvalidStacksTransaction(msg)) => {
                    assert!(msg.contains(&err_frag), err_frag);
                },
                _ => {
                    eprintln!("bad error: {:?}", &res);
                    assert!(false);
                }
            }
        
            let account_after = StacksChainState::get_account(&mut conn, &addr.to_account_principal());
            assert_eq!(account_after.stx_balance, 123);
            assert_eq!(account_after.nonce, 0);
        }

        conn.commit_block();
    }
    
    #[test]
    fn process_token_transfer_stx_sponsored_transaction() {
        let mut chainstate = instantiate_chainstate(false, 0x80000000, "process-token-transfer-stx-sponsored-transaction");

        let privk_origin = StacksPrivateKey::from_hex("6d430bb91222408e7706c9001cfaeb91b08c2be6d5ac95779ab52c6b431950e001").unwrap();
        let privk_sponsor = StacksPrivateKey::from_hex("7e3af4db6af6b3c67e2c6c6d7d5983b519f4d9b3a6e00580ae96dcace3bde8bc01").unwrap();

        let auth_origin = TransactionAuth::from_p2pkh(&privk_origin).unwrap();
        let auth_sponsor = TransactionAuth::from_p2pkh(&privk_sponsor).unwrap();
        let auth = auth_origin.into_sponsored(auth_sponsor).unwrap();

        let addr = auth.origin().address_testnet();
        let addr_sponsor = auth.sponsor().unwrap().address_testnet();

        let recv_addr = StacksAddress { version: 1, bytes: Hash160([0xff; 20]) };

        let mut tx_stx_transfer = StacksTransaction::new(TransactionVersion::Testnet,
                                                         auth.clone(),
                                                         TransactionPayload::TokenTransfer(recv_addr.clone(), 123, TokenTransferMemo([0u8; 34])));

        tx_stx_transfer.chain_id = 0x80000000;
        tx_stx_transfer.post_condition_mode = TransactionPostConditionMode::Allow;
        tx_stx_transfer.set_fee_rate(0);
        
        let mut signer = StacksTransactionSigner::new(&tx_stx_transfer);
        signer.sign_origin(&privk_origin).unwrap();
        signer.sign_sponsor(&privk_sponsor).unwrap();

        let signed_tx = signer.get_tx().unwrap();

        let mut conn = chainstate.block_begin(&FIRST_BURNCHAIN_BLOCK_HASH, &FIRST_STACKS_BLOCK_HASH, &BurnchainHeaderHash([1u8; 32]), &BlockHeaderHash([1u8; 32]));

        let account = StacksChainState::get_account(&mut conn, &addr.to_account_principal());
        let account_sponsor = StacksChainState::get_account(&mut conn, &addr_sponsor.to_account_principal());
        let recv_account = StacksChainState::get_account(&mut conn, &recv_addr.to_account_principal());

        assert_eq!(account.nonce, 0);
        assert_eq!(account_sponsor.nonce, 0);
        assert_eq!(account_sponsor.stx_balance, 0);
        assert_eq!(recv_account.nonce, 0);
        assert_eq!(recv_account.stx_balance, 0);

        // give the spending account some stx
        StacksChainState::account_credit(&mut conn, &addr.to_account_principal(), 123);

        let (fee, _) = StacksChainState::process_transaction(&mut conn, &signed_tx).unwrap();
        
        let account_after = StacksChainState::get_account(&mut conn, &addr.to_account_principal());
        assert_eq!(account_after.nonce, 1);
        assert_eq!(account_after.stx_balance, 0);

        let account_sponsor_after = StacksChainState::get_account(&mut conn, &addr_sponsor.to_account_principal());
        assert_eq!(account_sponsor_after.nonce, 1);
        assert_eq!(account_sponsor_after.stx_balance, 0);

        let recv_account_after = StacksChainState::get_account(&mut conn, &recv_addr.to_account_principal());
        assert_eq!(recv_account_after.nonce, 0);
        assert_eq!(recv_account_after.stx_balance, 123);
        
        conn.commit_block();

        assert_eq!(fee, 0);
    }
     
    #[test]
    fn process_smart_contract_transaction() {
        let contract = "
        (define-data-var bar int 0)
        (define-public (get-bar) (ok (var-get bar)))
        (define-public (set-bar (x int) (y int))
          (begin (var-set! bar (/ x y)) (ok (var-get bar))))";

        let mut chainstate = instantiate_chainstate(false, 0x80000000, "process-smart-contract-transaction");

        let privk = StacksPrivateKey::from_hex("6d430bb91222408e7706c9001cfaeb91b08c2be6d5ac95779ab52c6b431950e001").unwrap();
        let auth = TransactionAuth::from_p2pkh(&privk).unwrap();
        let addr = auth.origin().address_testnet();
        
        let mut tx_contract_call = StacksTransaction::new(TransactionVersion::Testnet,
                                                          auth.clone(),
                                                          TransactionPayload::new_smart_contract(&"hello-world".to_string(), &contract.to_string()).unwrap());

        tx_contract_call.chain_id = 0x80000000;
        tx_contract_call.set_fee_rate(0);

        let mut signer = StacksTransactionSigner::new(&tx_contract_call);
        signer.sign_origin(&privk).unwrap();

        let signed_tx = signer.get_tx().unwrap();

        let mut conn = chainstate.block_begin(&FIRST_BURNCHAIN_BLOCK_HASH, &FIRST_STACKS_BLOCK_HASH, &BurnchainHeaderHash([1u8; 32]), &BlockHeaderHash([1u8; 32]));

        let contract_id = QualifiedContractIdentifier::new(StandardPrincipalData::from(addr.clone()), ContractName::from("hello-world"));
        let contract_before_res = StacksChainState::get_contract(&mut conn, &contract_id).unwrap();
        assert!(contract_before_res.is_none());

        let account = StacksChainState::get_account(&mut conn, &addr.to_account_principal());
        assert_eq!(account.nonce, 0);

        let (fee, _) = StacksChainState::process_transaction(&mut conn, &signed_tx).unwrap();

        let account = StacksChainState::get_account(&mut conn, &addr.to_account_principal());
        assert_eq!(account.nonce, 1);

        let contract_res = StacksChainState::get_contract(&mut conn, &contract_id);
        
        conn.commit_block();

        assert_eq!(fee, 0);
        assert!(contract_res.is_ok());
    }

    #[test]
    fn process_smart_contract_sponsored_transaction() {
        let contract = "
        (define-data-var bar int 0)
        (define-public (get-bar) (ok (var-get bar)))
        (define-public (set-bar (x int) (y int))
          (begin (var-set! bar (/ x y)) (ok (var-get bar))))";

        let mut chainstate = instantiate_chainstate(false, 0x80000000, "process-smart-contract-transaction");

        let privk_origin = StacksPrivateKey::from_hex("6d430bb91222408e7706c9001cfaeb91b08c2be6d5ac95779ab52c6b431950e001").unwrap();
        let privk_sponsor = StacksPrivateKey::from_hex("7e3af4db6af6b3c67e2c6c6d7d5983b519f4d9b3a6e00580ae96dcace3bde8bc01").unwrap();

        let auth_origin = TransactionAuth::from_p2pkh(&privk_origin).unwrap();
        let auth_sponsor = TransactionAuth::from_p2pkh(&privk_sponsor).unwrap();

        let auth = auth_origin.into_sponsored(auth_sponsor).unwrap();

        let addr = auth.origin().address_testnet();
        let addr_sponsor = auth.sponsor().unwrap().address_testnet();
        
        let mut tx_contract_call = StacksTransaction::new(TransactionVersion::Testnet,
                                                          auth.clone(),
                                                          TransactionPayload::new_smart_contract(&"hello-world".to_string(), &contract.to_string()).unwrap());

        tx_contract_call.chain_id = 0x80000000;
        tx_contract_call.set_fee_rate(0);

        let mut signer = StacksTransactionSigner::new(&tx_contract_call);
        signer.sign_origin(&privk_origin).unwrap();
        signer.sign_sponsor(&privk_sponsor).unwrap();

        let signed_tx = signer.get_tx().unwrap();

        let mut conn = chainstate.block_begin(&FIRST_BURNCHAIN_BLOCK_HASH, &FIRST_STACKS_BLOCK_HASH, &BurnchainHeaderHash([1u8; 32]), &BlockHeaderHash([1u8; 32]));

        let contract_id = QualifiedContractIdentifier::new(StandardPrincipalData::from(addr.clone()), ContractName::from("hello-world"));
        let contract_before_res = StacksChainState::get_contract(&mut conn, &contract_id).unwrap();
        assert!(contract_before_res.is_none());

        let account = StacksChainState::get_account(&mut conn, &addr.to_account_principal());
        assert_eq!(account.nonce, 0);
        
        let account_sponsor = StacksChainState::get_account(&mut conn, &addr_sponsor.to_account_principal());
        assert_eq!(account.nonce, 0);

        let (fee, _) = StacksChainState::process_transaction(&mut conn, &signed_tx).unwrap();

        let account = StacksChainState::get_account(&mut conn, &addr.to_account_principal());
        assert_eq!(account.nonce, 1);
        
        let account_sponsor = StacksChainState::get_account(&mut conn, &addr_sponsor.to_account_principal());
        assert_eq!(account_sponsor.nonce, 1);

        let contract_res = StacksChainState::get_contract(&mut conn, &contract_id);
        
        conn.commit_block();

        assert_eq!(fee, 0);
        assert!(contract_res.is_ok());
    }
    
    #[test]
    fn process_smart_contract_contract_call_transaction() {
        let contract = "
        (define-data-var bar int 0)
        (define-public (get-bar) (ok (var-get bar)))
        (define-public (set-bar (x int) (y int))
          (begin (var-set! bar (/ x y)) (ok (var-get bar))))";

        let mut chainstate = instantiate_chainstate(false, 0x80000000, "process-smart-contract-transaction");

        // contract instantiation
        let privk = StacksPrivateKey::from_hex("6d430bb91222408e7706c9001cfaeb91b08c2be6d5ac95779ab52c6b431950e001").unwrap();
        let auth = TransactionAuth::from_p2pkh(&privk).unwrap();
        let addr = auth.origin().address_testnet();
        
        let mut tx_contract = StacksTransaction::new(TransactionVersion::Testnet,
                                                     auth.clone(),
                                                     TransactionPayload::new_smart_contract(&"hello-world".to_string(), &contract.to_string()).unwrap());

        tx_contract.chain_id = 0x80000000;
        tx_contract.set_fee_rate(0);

        let mut signer = StacksTransactionSigner::new(&tx_contract);
        signer.sign_origin(&privk).unwrap();

        let signed_tx = signer.get_tx().unwrap();

        // contract-call
        let privk_2 = StacksPrivateKey::from_hex("d2c340ebcc0794b6fabdd8ac8b1c983e363b05dc8adcdf7e30db205a3fa54c1601").unwrap();
        let auth_2 = TransactionAuth::from_p2pkh(&privk_2).unwrap();
        let addr_2 = auth.origin().address_testnet();
        
        let mut tx_contract_call = StacksTransaction::new(TransactionVersion::Testnet,
                                                          auth_2.clone(),
                                                          TransactionPayload::new_contract_call(addr.clone(), "hello-world", "set-bar", vec![Value::Int(6), Value::Int(2)]).unwrap());

        tx_contract_call.chain_id = 0x80000000;
        tx_contract_call.set_fee_rate(0);

        let mut signer_2 = StacksTransactionSigner::new(&tx_contract_call);
        signer_2.sign_origin(&privk_2).unwrap();
       
        let signed_tx_2 = signer_2.get_tx().unwrap();

        // process both
        let mut conn = chainstate.block_begin(&FIRST_BURNCHAIN_BLOCK_HASH, &FIRST_STACKS_BLOCK_HASH, &BurnchainHeaderHash([1u8; 32]), &BlockHeaderHash([1u8; 32]));

        let account = StacksChainState::get_account(&mut conn, &addr.to_account_principal());
        assert_eq!(account.nonce, 0);
        
        let account_2 = StacksChainState::get_account(&mut conn, &addr_2.to_account_principal());
        assert_eq!(account_2.nonce, 0);
        
        let contract_id = QualifiedContractIdentifier::new(StandardPrincipalData::from(addr.clone()), ContractName::from("hello-world"));
        let contract_before_res = StacksChainState::get_contract(&mut conn, &contract_id).unwrap();
        assert!(contract_before_res.is_none());

        let var_before_res = StacksChainState::get_data_var(&mut conn, &contract_id, "bar").unwrap();
        assert!(var_before_res.is_none());

        let (fee, _) = StacksChainState::process_transaction(&mut conn, &signed_tx).unwrap();

        let var_before_set_res = StacksChainState::get_data_var(&mut conn, &contract_id, "bar").unwrap();
        assert_eq!(var_before_set_res, Some(Value::Int(0)));

        let (fee_2, _) = StacksChainState::process_transaction(&mut conn, &signed_tx_2).unwrap();

        let account = StacksChainState::get_account(&mut conn, &addr.to_account_principal());
        assert_eq!(account.nonce, 1);
        
        let account_2 = StacksChainState::get_account(&mut conn, &addr_2.to_account_principal());
        assert_eq!(account.nonce, 1);

        let contract_res = StacksChainState::get_contract(&mut conn, &contract_id).unwrap();
        let var_res = StacksChainState::get_data_var(&mut conn, &contract_id, "bar").unwrap();
        
        conn.commit_block();

        assert_eq!(fee, 0);
        assert_eq!(fee_2, 0);
        assert!(contract_res.is_some());
        assert!(var_res.is_some());
        assert_eq!(var_res, Some(Value::Int(3)));
    }
    
    #[test]
    fn process_smart_contract_contract_call_sponsored_transaction() {
        let contract = "
        (define-data-var bar int 0)
        (define-public (get-bar) (ok (var-get bar)))
        (define-public (set-bar (x int) (y int))
          (begin (var-set! bar (/ x y)) (ok (var-get bar))))";

        let mut chainstate = instantiate_chainstate(false, 0x80000000, "process-smart-contract-transaction");

        // contract instantiation
        let privk = StacksPrivateKey::from_hex("6d430bb91222408e7706c9001cfaeb91b08c2be6d5ac95779ab52c6b431950e001").unwrap();
        let auth = TransactionAuth::from_p2pkh(&privk).unwrap();
        let addr_publisher = auth.origin().address_testnet();
        
        let mut tx_contract = StacksTransaction::new(TransactionVersion::Testnet,
                                                     auth.clone(),
                                                     TransactionPayload::new_smart_contract(&"hello-world".to_string(), &contract.to_string()).unwrap());

        tx_contract.chain_id = 0x80000000;
        tx_contract.set_fee_rate(0);

        let mut signer = StacksTransactionSigner::new(&tx_contract);
        signer.sign_origin(&privk).unwrap();

        let signed_tx = signer.get_tx().unwrap();

        // sponsored contract-call
        let privk_origin = StacksPrivateKey::from_hex("027682d2f7b05c3801fe4467883ab4cff0568b5e36412b5289e83ea5b519de8a01").unwrap();
        let privk_sponsor = StacksPrivateKey::from_hex("7e3af4db6af6b3c67e2c6c6d7d5983b519f4d9b3a6e00580ae96dcace3bde8bc01").unwrap();

        let auth_origin = TransactionAuth::from_p2pkh(&privk_origin).unwrap();
        let auth_sponsor = TransactionAuth::from_p2pkh(&privk_sponsor).unwrap();

        let auth_contract_call = auth_origin.into_sponsored(auth_sponsor).unwrap();

        let addr_origin = auth_contract_call.origin().address_testnet();
        let addr_sponsor = auth_contract_call.sponsor().unwrap().address_testnet();

        let mut tx_contract_call = StacksTransaction::new(TransactionVersion::Testnet,
                                                          auth_contract_call.clone(),
                                                          TransactionPayload::new_contract_call(addr_publisher.clone(), "hello-world", "set-bar", vec![Value::Int(6), Value::Int(2)]).unwrap());

        tx_contract_call.chain_id = 0x80000000;
        tx_contract_call.set_fee_rate(0);

        let mut signer_2 = StacksTransactionSigner::new(&tx_contract_call);
        signer_2.sign_origin(&privk_origin).unwrap();
        signer_2.sign_sponsor(&privk_sponsor).unwrap();
       
        let signed_tx_2 = signer_2.get_tx().unwrap();

        // process both
        let mut conn = chainstate.block_begin(&FIRST_BURNCHAIN_BLOCK_HASH, &FIRST_STACKS_BLOCK_HASH, &BurnchainHeaderHash([1u8; 32]), &BlockHeaderHash([1u8; 32]));

        let account_publisher = StacksChainState::get_account(&mut conn, &addr_publisher.to_account_principal());
        assert_eq!(account_publisher.nonce, 0);

        let account_origin = StacksChainState::get_account(&mut conn, &addr_origin.to_account_principal());
        assert_eq!(account_origin.nonce, 0);
        
        let account_sponsor = StacksChainState::get_account(&mut conn, &addr_sponsor.to_account_principal());
        assert_eq!(account_sponsor.nonce, 0);
        
        let contract_id = QualifiedContractIdentifier::new(StandardPrincipalData::from(addr_publisher.clone()), ContractName::from("hello-world"));
        let contract_before_res = StacksChainState::get_contract(&mut conn, &contract_id).unwrap();
        assert!(contract_before_res.is_none());

        let var_before_res = StacksChainState::get_data_var(&mut conn, &contract_id, "bar").unwrap();
        assert!(var_before_res.is_none());

        let (fee, _) = StacksChainState::process_transaction(&mut conn, &signed_tx).unwrap();
        
        let account_publisher = StacksChainState::get_account(&mut conn, &addr_publisher.to_account_principal());
        assert_eq!(account_publisher.nonce, 1);

        let var_before_set_res = StacksChainState::get_data_var(&mut conn, &contract_id, "bar").unwrap();
        assert_eq!(var_before_set_res, Some(Value::Int(0)));

        let (fee_2, _) = StacksChainState::process_transaction(&mut conn, &signed_tx_2).unwrap();
        
        let account_origin = StacksChainState::get_account(&mut conn, &addr_origin.to_account_principal());
        assert_eq!(account_origin.nonce, 1);
        
        let account_sponsor = StacksChainState::get_account(&mut conn, &addr_sponsor.to_account_principal());
        assert_eq!(account_sponsor.nonce, 1);

        let contract_res = StacksChainState::get_contract(&mut conn, &contract_id).unwrap();
        let var_res = StacksChainState::get_data_var(&mut conn, &contract_id, "bar").unwrap();
        
        conn.commit_block();

        assert_eq!(fee, 0);
        assert_eq!(fee_2, 0);
        assert!(contract_res.is_some());
        assert!(var_res.is_some());
        assert_eq!(var_res, Some(Value::Int(3)));
    }

    // TODO: post-conditions
    // TODO: test poison microblock
}
