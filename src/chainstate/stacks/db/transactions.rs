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
use hashbrown::HashMap;
use hashbrown::HashSet;

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
use vm::errors::Error as clarity_vm_error;
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
        if payer_account.stx_balance < tx.fee as u128 {
            return Err(Error::InvalidFee);
        }
        StacksChainState::account_debit(clarity_tx, &payer_account.principal, tx.fee);
        Ok(tx.fee)
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
    fn check_transaction_postconditions<'a>(clarity_db: &mut ClarityDatabase<'a>, tx: &StacksTransaction, account: &StacksAccount, asset_map: &AssetMap) -> bool {
        let mut checked_stx = false;
        let mut checked_assets = HashSet::new();
        let allow_unchecked_assets = tx.post_condition_mode == TransactionPostConditionMode::Allow;

        for postcond in tx.post_conditions.iter() {
            match postcond {
                TransactionPostCondition::STX(ref condition_code, ref amount_sent_condition) => {
                    let amount_sent = asset_map.get_stx(&account.principal).unwrap_or(0);
                    if !condition_code.check(*amount_sent_condition as u128, amount_sent) {
                        debug!("Post-condition check failure on STX owned by {:?}: {:?} {:?} {}", account, amount_sent_condition, condition_code, amount_sent);
                        return false;
                    }
                    checked_stx = true;
                },
                TransactionPostCondition::Fungible(ref asset_info, ref condition_code, ref amount_sent_condition) => {
                    let asset_id = AssetIdentifier {
                        contract_identifier: QualifiedContractIdentifier::new(StandardPrincipalData::from(asset_info.contract_address.clone()), asset_info.contract_name.clone()),
                        asset_name: asset_info.asset_name.clone()
                    };

                    let amount_sent = asset_map.get_fungible_tokens(&account.principal, &asset_id).unwrap_or(0);
                    if !condition_code.check(*amount_sent_condition as u128, amount_sent) {
                        debug!("Post-condition check failure on fungible asset {:?} owned by {:?}: {:?} {:?} {}", &asset_id, account, amount_sent_condition, condition_code, amount_sent);
                        return false;
                    }
                    checked_assets.insert(asset_id);
                },
                TransactionPostCondition::Nonfungible(ref asset_info, ref asset_value_str, ref condition_code) => {
                    let asset_id = AssetIdentifier {
                        contract_identifier: QualifiedContractIdentifier::new(StandardPrincipalData::from(asset_info.contract_address.clone()), asset_info.contract_name.clone()),
                        asset_name: asset_info.asset_name.clone()
                    };

                    let asset_sent_condition = match asset_value_str.try_as_clarity_literal() {
                        Some(value) => value,
                        None => {
                            return false;
                        }
                    };

                    let empty_assets = vec![];
                    let assets_sent = asset_map.get_nonfungible_tokens(&account.principal, &asset_id).unwrap_or(&empty_assets);
                    if !condition_code.check(&asset_sent_condition, assets_sent) {
                        debug!("Post-condition check failure on non-fungible asset {:?} owned by {:?}: {:?} {:?}", &asset_id, account, &asset_sent_condition, condition_code);
                        return false;
                    }

                    checked_assets.insert(asset_id);
                }
            }
        }

        if !allow_unchecked_assets {
            // make sure every asset transferred is covered by a postcondition
            let mut fungible_asset_ids = asset_map.get_fungible_token_ids(&account.principal);
            let mut nonfungible_asset_ids = asset_map.get_nonfungible_token_ids(&account.principal);
            let stx_transfer_opt = asset_map.get_stx(&account.principal);

            for asset_id in fungible_asset_ids.drain(..) {
                if !checked_assets.contains(&asset_id) {
                    debug!("Post-condition check failure on fungible asset {:?} owned by {:?}: missing post-condition check", &asset_id, account);
                    return false;
                }
            }

            for asset_id in nonfungible_asset_ids.drain(..) {
                if !checked_assets.contains(&asset_id) {
                    debug!("Post-condition check failure on non-fungible asset {:?} owned by {:?}: missing post-condition check", &asset_id, account);
                    return false;
                }
            }

            if stx_transfer_opt.is_some() && !checked_stx {
                debug!("Post-condition check failure on STX: missing post-condition check");
                return false;
            }
        }
        return true;
    }

    /// Process a token transfer payload (but wrapped in its transaction still, in order to do
    /// post-condition checks).
    fn process_transaction_token_transfer<'a>(clarity_tx: &mut ClarityTx<'a>, tx: &StacksTransaction, origin_account: &StacksAccount) -> Result<(), Error> {
        match tx.payload {
            TransactionPayload::TokenTransfer(ref token_transfer) => {
                match *token_transfer {
                    TransactionTokenTransfer::STX(ref addr, ref amount) => {
                        let recipient_principal = PrincipalData::Standard(StandardPrincipalData::from(addr.clone()));
                        clarity_tx.connection().with_clarity_db(|ref mut db| {
                            // does the sender have ths amount?
                            let cur_balance = db.get_account_stx_balance(&origin_account.principal);
                            if cur_balance < (*amount as u128) {
                                return Err(clarity_error::BadTransaction(format!("Address {:?} has {} microSTX; needed at least {}", &origin_account.principal, cur_balance, amount)));
                            }

                            let recipient_balance = db.get_account_stx_balance(&recipient_principal);
                            if recipient_balance.checked_add(*amount as u128).is_none() {
                                return Err(clarity_error::BadTransaction(format!("Address {:?} has {} microSTX; cannot add {}", &recipient_principal, recipient_balance, amount)));
                            }

                            let new_balance = cur_balance - (*amount as u128);
                            let new_recipient_balance = recipient_balance + (*amount as u128);

                            db.set_account_stx_balance(&origin_account.principal, new_balance);
                            db.set_account_stx_balance(&recipient_principal, new_recipient_balance);

                            let mut asset_map = AssetMap::new();
                            asset_map.add_stx_transfer(&origin_account.principal, *amount as u128)?;

                            if !StacksChainState::check_transaction_postconditions(db, tx, origin_account, &asset_map) {
                                return Err(clarity_error::PostCondition(format!("Token transfer from {} to {} of {} microSTX failed post-condition checks",
                                                                                origin_account.principal, recipient_principal, amount)));
                            }

                            Ok(())
                        }).map_err(|e| {
                            match e {
                                clarity_error::BadTransaction(ref s) => {
                                    let msg = format!("Error validating STX-transfer transaction {:?}: {}", tx.txid().to_hex(), s);
                                    warn!("{}", &msg);

                                    Error::InvalidStacksTransaction(msg)
                                },
                                clarity_error::PostCondition(ref s) => {
                                    let msg = format!("Error validating STX-transfer transaction {:?} post-conditions: {}", tx.txid().to_hex(), s);
                                    warn!("{}", &msg);

                                    Error::PostConditionFailed(msg)
                                },
                                _ => Error::ClarityError(e)
                            }
                        })?;
                    },
                    TransactionTokenTransfer::Fungible(ref asset_info, ref addr, ref amount) => {
                        let recipient_principal = PrincipalData::Standard(StandardPrincipalData::from(addr.clone()));
                        let contract_id = QualifiedContractIdentifier::new(StandardPrincipalData::from(asset_info.contract_address.clone()), asset_info.contract_name.clone());
                        
                        clarity_tx.connection().with_clarity_db(|ref mut db| {
                            // does the sender have this asset and amount?
                            let cur_balance = db.get_ft_balance(&contract_id, &asset_info.asset_name, &origin_account.principal)?;
                            if cur_balance < (*amount).into() {
                                return Err(clarity_error::BadTransaction(format!("Address {:?} has {} {:?}.{:?}; needed at least {}", 
                                                                                 &origin_account.principal, cur_balance, &contract_id, &asset_info.asset_name, amount)));
                            }

                            let recipient_balance = db.get_ft_balance(&contract_id, &asset_info.asset_name, &recipient_principal)?;
                            if recipient_balance.checked_add(*amount as u128).is_none() {
                                return Err(clarity_error::BadTransaction(format!("Address {:?} has {} {:?}.{:?}; cannot add {}", 
                                                                                 &origin_account.principal, cur_balance, &contract_id, &asset_info.asset_name, amount)));
                            }

                            let new_balance = cur_balance - (*amount as u128);
                            let new_recipient_balance = recipient_balance + (*amount as u128);

                            db.set_ft_balance(&contract_id, &asset_info.asset_name, &origin_account.principal, new_balance)?;
                            db.set_ft_balance(&contract_id, &asset_info.asset_name, &recipient_principal, new_recipient_balance)?;

                            let mut asset_map = AssetMap::new();
                            let asset_id = AssetIdentifier {
                                contract_identifier: contract_id.clone(),
                                asset_name: asset_info.asset_name.clone()
                            };
                            asset_map.add_token_transfer(&origin_account.principal, asset_id, (*amount).into())?;
                            
                            if !StacksChainState::check_transaction_postconditions(db, tx, origin_account, &asset_map) {
                                return Err(clarity_error::PostCondition(format!("Token transfer from {} to {} of fungible token {} {:?}.{:?} failed post-condition checks", 
                                                                                origin_account.principal, recipient_principal, amount, &contract_id, &asset_info.asset_name)));
                            }
                            Ok(())
                        }).map_err(|e| {
                            match e {
                                clarity_error::BadTransaction(ref s) => {
                                    let msg = format!("Error validating FT-transfer transaction {:?}: {}", tx.txid().to_hex(), s);
                                    warn!("{}", &msg);

                                    Error::InvalidStacksTransaction(msg)
                                },
                                clarity_error::PostCondition(ref s) => {
                                    let msg = format!("Error validating FT-transfer transaction {:?} post-conditions: {}", tx.txid().to_hex(), s);
                                    warn!("{}", &msg);

                                    Error::PostConditionFailed(msg)
                                },
                                _ => Error::ClarityError(e)
                            }
                        })?;
                    },
                    TransactionTokenTransfer::Nonfungible(ref asset_info, ref token_name, ref addr) => {
                        let recipient_principal = PrincipalData::Standard(StandardPrincipalData::from(addr.clone()));
                        let contract_id = QualifiedContractIdentifier::new(StandardPrincipalData::from(asset_info.contract_address.clone()), asset_info.contract_name.clone());
                        let asset = token_name.try_as_clarity_literal().ok_or(Error::InvalidStacksTransaction(format!("Asset '{:?}' does not encode a Clarity literal", token_name)))?;
                        
                        clarity_tx.connection().with_clarity_db(|ref mut db| {
                            // does the sender have this asset?
                            let cur_owner = db.get_nft_owner(&contract_id, &asset_info.asset_name, &asset)?;
                            if cur_owner != origin_account.principal {
                                return Err(clarity_error::BadTransaction(format!("Address {:?} does not own non-fungible token {:?}.{:?} '{:?}'",
                                                                                 &origin_account.principal, &contract_id, &asset_info.asset_name, &asset)));
                            }

                            db.set_nft_owner(&contract_id, &asset_info.asset_name, &asset, &recipient_principal)?;

                            let mut asset_map = AssetMap::new();
                            let asset_id = AssetIdentifier {
                                contract_identifier: contract_id.clone(),
                                asset_name: asset_info.asset_name.clone()
                            };
                            asset_map.add_asset_transfer(&origin_account.principal, asset_id, asset.clone());

                            if !StacksChainState::check_transaction_postconditions(db, tx, origin_account, &asset_map) {
                                return Err(clarity_error::PostCondition(format!("Token transfer from {} to {} of non-fungible token {:?}.{:?} '{:?}' failed post-condition checks", 
                                                                                origin_account.principal, recipient_principal, &contract_id, &asset_info.asset_name, &asset)));
                            }
                            Ok(())
                        }).map_err(|e| {
                            match e {
                                clarity_error::BadTransaction(ref s) => {
                                    let msg = format!("Error validating NFT-transfer transaction {:?}: {}", tx.txid().to_hex(), s);
                                    warn!("{}", &msg);

                                    Error::InvalidStacksTransaction(msg)
                                },
                                clarity_error::PostCondition(ref s) => {
                                    let msg = format!("Error validating FT-transfer transaction {:?} post-conditions: {}", tx.txid().to_hex(), s);
                                    warn!("{}", &msg);

                                    Error::PostConditionFailed(msg)
                                },
                                _ => Error::ClarityError(e)
                            }
                        })?;
                    }
                }
                Ok(())
            },
            _ => {
                panic!("Tried to process a non-token-transfer");
            }
        }
    }

    /// Process the transaction's payload, and run the post-conditions against the resulting state.
    /// Returns the number of STX burned.
    pub fn process_transaction_payload<'a>(clarity_tx: &mut ClarityTx<'a>, tx: &StacksTransaction, origin_account: &StacksAccount) -> Result<u128, Error> {
        let stx_burned = match tx.payload {
            TransactionPayload::TokenTransfer(_) => {
                // this only works for standard authorizations
                if tx.auth.sponsor().is_some() {
                    let msg = "Sponsored transactions cannot transfer tokens".to_string();
                    warn!("{}", &msg);

                    return Err(Error::InvalidStacksTransaction(msg));
                }

                StacksChainState::process_transaction_token_transfer(clarity_tx,tx, origin_account)?;

                // no burns
                0
            },
            TransactionPayload::ContractCall(ref contract_call) => {
                let contract_id = contract_call.to_clarity_contract_id();
                let arguments = contract_call.try_as_clarity_args()?;
                let (_, asset_map) = clarity_tx.connection().run_contract_call(&origin_account.principal, &contract_id, &contract_call.function_name, &arguments, 
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
                clarity_tx.connection().save_analysis(&contract_id, &contract_analysis).map_err(Error::ClarityError)?;
                
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

        // update the account nonces
        StacksChainState::update_account_nonce(clarity_tx, tx, &origin_account);
        if origin != payer {
            StacksChainState::update_account_nonce(clarity_tx, tx, &payer_account);
        }

        // pay fee
        let fee = StacksChainState::pay_transaction_fee(clarity_tx, tx, &payer_account)?;
    
        let burns = StacksChainState::process_transaction_payload(clarity_tx, tx, &origin_account)?;
        Ok((fee, burns))
    }
}

#[cfg(test)]
pub mod test {
    use super::*;
    use chainstate::*;
    use chainstate::stacks::*;
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
                                                         TransactionPayload::TokenTransfer(TransactionTokenTransfer::STX(recv_addr.clone(), 123)));

        tx_stx_transfer.chain_id = 0x80000000;
        tx_stx_transfer.post_condition_mode = TransactionPostConditionMode::Allow;
        tx_stx_transfer.set_fee(0);
        
        let mut signer = StacksTransactionSigner::new(&tx_stx_transfer);
        signer.sign_origin(&privk).unwrap();

        let signed_tx = signer.get_tx().unwrap();

        let mut conn = chainstate.block_begin(&BurnchainHeaderHash([0u8; 32]), &BlockHeaderHash([0u8; 32]), &BurnchainHeaderHash([1u8; 32]), &BlockHeaderHash([1u8; 32]));

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
    fn process_token_transfer_contract_transaction() {
        let privk = StacksPrivateKey::from_hex("6d430bb91222408e7706c9001cfaeb91b08c2be6d5ac95779ab52c6b431950e001").unwrap();
        let auth = TransactionAuth::from_p2pkh(&privk).unwrap();
        let addr = auth.origin().address_testnet();
        let addr_str = addr.to_string();
        let recv_addr = StacksAddress { version: 1, bytes: Hash160([0xff; 20]) };

        // create a contract with a fungible and non-fungible token
        let contract = format!("
        (define-fungible-token hello-asset u1000)
        (define-non-fungible-token hello-token (buff 20))
        (begin
           (ft-mint! hello-asset u123 '{})
           (nft-mint! hello-token \"abc\" '{})
        )", &addr_str, &addr_str);

        let mut chainstate = instantiate_chainstate(false, 0x80000000, "process-token-transfer-contract-transaction");
        
        let hello_contract_name = "hello-contract-name";
        let hello_asset_name = "hello-asset";
        let hello_token_name = "hello-token";
        
        let contract_name = ContractName::try_from(hello_contract_name).unwrap();
        let asset_name = ClarityName::try_from(hello_asset_name).unwrap();
        let token_name = ClarityName::try_from(hello_token_name).unwrap();
        let asset_value = StacksString::from_str("\"abc\"").unwrap();
        
        let ft_asset_info = AssetInfo {
            contract_address: addr.clone(),
            contract_name: contract_name.clone(),
            asset_name: asset_name.clone()
        };
        
        let nft_asset_info = AssetInfo {
            contract_address: addr.clone(),
            contract_name: contract_name.clone(),
            asset_name: token_name.clone()
        };

        // make the contract transaction
        let mut tx_contract_call = StacksTransaction::new(TransactionVersion::Testnet,
                                                          auth.clone(),
                                                          TransactionPayload::new_smart_contract(&hello_contract_name.to_string(), &contract.to_string()).unwrap());

        tx_contract_call.chain_id = 0x80000000;
        tx_contract_call.set_fee(0);

        let mut contract_signer = StacksTransactionSigner::new(&tx_contract_call);
        contract_signer.sign_origin(&privk).unwrap();

        let signed_contract_tx = contract_signer.get_tx().unwrap();

        let contract_id = QualifiedContractIdentifier::new(StandardPrincipalData::from(addr.clone()), contract_name.clone());

        let mut conn = chainstate.block_begin(&BurnchainHeaderHash([0u8; 32]), &BlockHeaderHash([0u8; 32]), &BurnchainHeaderHash([1u8; 32]), &BlockHeaderHash([1u8; 32]));

        // instantiate the contract and its tokens
        {
            // token shouldn't exist yet
            let account_before = StacksChainState::get_account(&mut conn, &addr.to_account_principal());
            let ft_before_res = StacksChainState::get_account_ft(&mut conn, &contract_id, &hello_asset_name, &addr.to_account_principal());
            let nft_before_res = StacksChainState::get_account_nft(&mut conn, &contract_id, &hello_token_name, &asset_value.try_as_clarity_literal().unwrap());

            assert!(ft_before_res.is_err());
            assert!(nft_before_res.is_err());
            assert_eq!(account_before.nonce, 0);

            let (fee, _) = StacksChainState::process_transaction(&mut conn, &signed_contract_tx).unwrap();

            assert_eq!(fee, 0);

            // now the token should exist, and our addr should have a balance
            let account_after = StacksChainState::get_account(&mut conn, &addr.to_account_principal());
            let ft_after_res = StacksChainState::get_account_ft(&mut conn, &contract_id, &hello_asset_name, &addr.to_account_principal());
            let nft_after_res = StacksChainState::get_account_nft(&mut conn, &contract_id, &hello_token_name, &asset_value.try_as_clarity_literal().unwrap());

            assert_eq!(account_after.nonce, 1);
            assert_eq!(ft_after_res.unwrap(), 123);
            assert_eq!(nft_after_res.unwrap(), PrincipalData::Standard(StandardPrincipalData::from(addr.clone())));
        }

        // make the fungible token transfer transaction
        let mut tx_fungible_transfer = StacksTransaction::new(TransactionVersion::Testnet,
                                                              auth.clone(),
                                                              TransactionPayload::TokenTransfer(TransactionTokenTransfer::Fungible(ft_asset_info.clone(), recv_addr.clone(), 123)));

        tx_fungible_transfer.chain_id = 0x80000000;
        tx_fungible_transfer.post_condition_mode = TransactionPostConditionMode::Allow;
        tx_fungible_transfer.set_fee(0);
        
        let mut ft_signer = StacksTransactionSigner::new(&tx_fungible_transfer);
        ft_signer.sign_origin(&privk).unwrap();

        let ft_signed_tx = ft_signer.get_tx().unwrap();

        {
            // token should exist but recipient should have 0
            let recv_account_before = StacksChainState::get_account(&mut conn, &recv_addr.to_account_principal());
            let recv_ft_before = StacksChainState::get_account_ft(&mut conn, &contract_id, &hello_asset_name, &recv_addr.to_account_principal()).unwrap();

            assert_eq!(recv_ft_before, 0);
            assert_eq!(recv_account_before.nonce, 0);

            let (fee, _) = StacksChainState::process_transaction(&mut conn, &ft_signed_tx).unwrap();

            assert_eq!(fee, 0);

            // now the recipient should have the tokens
            let account_after = StacksChainState::get_account(&mut conn, &addr.to_account_principal());
            let account_ft_after = StacksChainState::get_account_ft(&mut conn, &contract_id, &hello_asset_name, &addr.to_account_principal()).unwrap();
            let recv_account_after = StacksChainState::get_account(&mut conn, &recv_addr.to_account_principal());
            let recv_ft_after = StacksChainState::get_account_ft(&mut conn, &contract_id, &hello_asset_name, &recv_addr.to_account_principal()).unwrap();

            assert_eq!(account_after.nonce, 2);
            assert_eq!(account_ft_after, 0);
            
            assert_eq!(recv_account_after.nonce, 0);
            assert_eq!(recv_ft_after, 123);
        }

        // make the non-fungible token transfer transaction 
        let mut tx_nft_transfer = StacksTransaction::new(TransactionVersion::Testnet,
                                                         auth.clone(),
                                                         TransactionPayload::TokenTransfer(TransactionTokenTransfer::Nonfungible(nft_asset_info.clone(), asset_value.clone(), recv_addr.clone())));

        tx_nft_transfer.chain_id = 0x80000000;
        tx_nft_transfer.post_condition_mode = TransactionPostConditionMode::Allow;
        tx_nft_transfer.set_fee(0);

        let mut nft_signer = StacksTransactionSigner::new(&tx_nft_transfer);
        nft_signer.sign_origin(&privk).unwrap();

        let nft_signed_tx = nft_signer.get_tx().unwrap();

        {
            // token should exist but the origin should be the owner
            let account_before = StacksChainState::get_account_nft(&mut conn, &contract_id, &hello_token_name, &asset_value.try_as_clarity_literal().unwrap()).unwrap();
            assert_eq!(account_before, PrincipalData::Standard(StandardPrincipalData::from(addr.clone())));

            let (fee, _) = StacksChainState::process_transaction(&mut conn, &nft_signed_tx).unwrap();

            assert_eq!(fee, 0);

            // now the recipient should own it
            let account_after = StacksChainState::get_account_nft(&mut conn, &contract_id, &hello_token_name, &asset_value.try_as_clarity_literal().unwrap()).unwrap();
            assert_eq!(account_after, PrincipalData::Standard(StandardPrincipalData::from(recv_addr.clone())));
        }

        conn.commit_block();
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
        tx_contract_call.set_fee(0);

        let mut signer = StacksTransactionSigner::new(&tx_contract_call);
        signer.sign_origin(&privk).unwrap();

        let signed_tx = signer.get_tx().unwrap();

        let mut conn = chainstate.block_begin(&BurnchainHeaderHash([0u8; 32]), &BlockHeaderHash([0u8; 32]), &BurnchainHeaderHash([1u8; 32]), &BlockHeaderHash([1u8; 32]));

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
        tx_contract_call.set_fee(0);

        let mut signer = StacksTransactionSigner::new(&tx_contract_call);
        signer.sign_origin(&privk_origin).unwrap();
        signer.sign_sponsor(&privk_sponsor).unwrap();

        let signed_tx = signer.get_tx().unwrap();

        let mut conn = chainstate.block_begin(&BurnchainHeaderHash([0u8; 32]), &BlockHeaderHash([0u8; 32]), &BurnchainHeaderHash([1u8; 32]), &BlockHeaderHash([1u8; 32]));

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
        tx_contract.set_fee(0);

        let mut signer = StacksTransactionSigner::new(&tx_contract);
        signer.sign_origin(&privk).unwrap();

        let signed_tx = signer.get_tx().unwrap();

        // contract-call
        let privk_2 = StacksPrivateKey::from_hex("d2c340ebcc0794b6fabdd8ac8b1c983e363b05dc8adcdf7e30db205a3fa54c1601").unwrap();
        let auth_2 = TransactionAuth::from_p2pkh(&privk_2).unwrap();
        let addr_2 = auth.origin().address_testnet();
        
        let mut tx_contract_call = StacksTransaction::new(TransactionVersion::Testnet,
                                                          auth_2.clone(),
                                                          TransactionPayload::new_contract_call(&addr, "hello-world", "set-bar", &vec!["6", "2"]).unwrap());

        tx_contract_call.chain_id = 0x80000000;
        tx_contract_call.set_fee(0);

        let mut signer_2 = StacksTransactionSigner::new(&tx_contract_call);
        signer_2.sign_origin(&privk_2).unwrap();
       
        let signed_tx_2 = signer_2.get_tx().unwrap();

        // process both
        let mut conn = chainstate.block_begin(&BurnchainHeaderHash([0u8; 32]), &BlockHeaderHash([0u8; 32]), &BurnchainHeaderHash([1u8; 32]), &BlockHeaderHash([1u8; 32]));

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
        tx_contract.set_fee(0);

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
                                                          TransactionPayload::new_contract_call(&addr_publisher, "hello-world", "set-bar", &vec!["6", "2"]).unwrap());

        tx_contract_call.chain_id = 0x80000000;
        tx_contract_call.set_fee(0);

        let mut signer_2 = StacksTransactionSigner::new(&tx_contract_call);
        signer_2.sign_origin(&privk_origin).unwrap();
        signer_2.sign_sponsor(&privk_sponsor).unwrap();
       
        let signed_tx_2 = signer_2.get_tx().unwrap();

        // process both
        let mut conn = chainstate.block_begin(&BurnchainHeaderHash([0u8; 32]), &BlockHeaderHash([0u8; 32]), &BurnchainHeaderHash([1u8; 32]), &BlockHeaderHash([1u8; 32]));

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

    // TODO: test that you can't send to yourself
}
