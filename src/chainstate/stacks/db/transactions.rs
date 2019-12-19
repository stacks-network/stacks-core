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

use vm::errors::Error as InterpreterError;

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
                        debug!("Post-condition check failure on fungible asset {:?} owned by {:?}: {} {:?} {}", &asset_id, account_principal, amount_sent_condition, condition_code, amount_sent);
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
        })
        .map_err(|e| {
            match e {
                clarity_error::BadTransaction(ref s) => {
                    let msg = format!("Error validating STX-transfer transaction {:?}: {}", txid.to_hex(), s);
                    warn!("{}", &msg);

                    Error::InvalidStacksTransaction(msg)
                },
                // TODO: catch runtime errors -- these are okay
                _ => Error::ClarityError(e)
            }
        })
    }

    /// Process the transaction's payload, and run the post-conditions against the resulting state.
    /// Returns the number of STX burned.
    /// TODO: catch runtime errors -- these are okay!
    pub fn process_transaction_payload<'a>(clarity_tx: &mut ClarityTx<'a>, tx: &StacksTransaction, origin_account: &StacksAccount) -> Result<u128, Error> {
        let stx_burned = match tx.payload {
            TransactionPayload::TokenTransfer(ref addr, ref amount, ref _memo) => {
                // post-conditions are not allowed for this variant, since they're non-sensical.
                // Their presence in this variant makes the transaction invalid.
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
                // if this calls a function that doesn't exist or is syntatically invalid, then the
                // transaction is invalid (since this can be checked statically by the miner).
                // if on the other hand the contract being called has a runtime error, then the
                // transaction is still valid, but no changes will materialize besides debiting the
                // tx fee.
                let contract_id = contract_call.to_clarity_contract_id();
                let asset_map = match clarity_tx.connection().run_contract_call(&origin_account.principal, &contract_id, &contract_call.function_name, &contract_call.function_args,
                                                                                |asset_map, ref mut clarity_db| { !StacksChainState::check_transaction_postconditions(clarity_db, tx, origin_account, asset_map) }) {
                    Ok((return_value, asset_map)) => {
                        // TODO: pretty-print return value if in debug mode
                        Ok(asset_map)
                    },
                    Err(e) => {
                        match e {
                            // runtime errors are okay -- we just have an empty asset map
                            clarity_error::Interpreter(ref ie) => {
                                match ie {
                                    InterpreterError::Runtime(ref runtime_error, ref stack) => {
                                        // TODO: pretty-print this if in debug mode
                                        Ok(AssetMap::new())
                                    },
                                    _ => Err(e)
                                }
                            },
                            _ => Err(e)
                        }
                    }
                }.map_err(Error::ClarityError)?;

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

                // can't be instantiated already -- if this fails, then the transaction is invalid
                // (because this can be checked statically by the miner before mining the block).
                if StacksChainState::get_contract(clarity_tx, &contract_id)?.is_some() {
                    let msg = format!("Duplicate contract '{}'", &contract_id);
                    warn!("{}", &msg);

                    return Err(Error::InvalidStacksTransaction(msg));
                }

                // analysis pass -- if this fails, then the transaction is invalid (because this can be
                // checked statically by the miner before mining the block).
                let (contract_ast, contract_analysis) = clarity_tx.connection().analyze_smart_contract(&contract_id, &contract_code_str).map_err(Error::ClarityError)?;

                // execution -- if this fails due to a runtime error, then the transaction is still
                // valid, but the contract does not materialize (but the sender is out their fee).
                let asset_map = match clarity_tx.connection().initialize_smart_contract(&contract_id, &contract_ast,
                                                                                       |asset_map, ref mut clarity_db| { !StacksChainState::check_transaction_postconditions(clarity_db, tx, origin_account, asset_map) }) {
                    Ok(asset_map) => {
                        Ok(asset_map)
                    },
                    Err(e) => {
                        match e {
                            // runtime errors are okay -- we just have an empty asset map
                            clarity_error::Interpreter(ref ie) => {
                                match ie {
                                    InterpreterError::Runtime(ref runtime_error, ref stack) => {
                                        // TODO: pretty-print this if in debug mode
                                        Ok(AssetMap::new())
                                    },
                                    _ => Err(e)
                                }
                            },
                            _ => Err(e)
                        }
                    }
                }.map_err(Error::ClarityError)?;
                
                // store analysis -- if this fails, then the have some pretty bad problems
                clarity_tx.connection().save_analysis(&contract_id, &contract_analysis)
                    .map_err(|e| Error::ClarityError(clarity_error::Analysis(e)))?;
                
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
        let sponsor_addr = StacksAddress::from_public_keys(C32_ADDRESS_VERSION_TESTNET_SINGLESIG, &AddressHashMode::SerializeP2PKH, 1, &vec![StacksPublicKey::from_private(&privk_sponsor)]).unwrap();
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
                                                                       TransactionPayload::TokenTransfer(sponsor_addr.clone(), 123, TokenTransferMemo([0u8; 34])));
        
        let mut tx_stx_transfer_wrong_chain_id = StacksTransaction::new(TransactionVersion::Testnet,
                                                                        auth.clone(),
                                                                        TransactionPayload::TokenTransfer(sponsor_addr.clone(), 123, TokenTransferMemo([0u8; 34])));
        
        let mut tx_stx_transfer_postconditions = StacksTransaction::new(TransactionVersion::Testnet,
                                                                        auth.clone(),
                                                                        TransactionPayload::TokenTransfer(sponsor_addr.clone(), 123, TokenTransferMemo([0u8; 34])));

        tx_stx_transfer_postconditions.add_post_condition(TransactionPostCondition::STX(PostConditionPrincipal::Origin, FungibleConditionCode::SentGt, 0));
        
        let mut wrong_nonce_auth = auth.clone();
        wrong_nonce_auth.set_origin_nonce(1);
        let mut tx_stx_transfer_wrong_nonce = StacksTransaction::new(TransactionVersion::Testnet,
                                                                     wrong_nonce_auth,
                                                                     TransactionPayload::TokenTransfer(recv_addr.clone(), 123, TokenTransferMemo([0u8; 34])));

        let mut wrong_nonce_auth_sponsored = auth_sponsored.clone();
        wrong_nonce_auth_sponsored.set_sponsor_nonce(1).unwrap();
        let mut tx_stx_transfer_wrong_nonce_sponsored = StacksTransaction::new(TransactionVersion::Testnet,
                                                                               wrong_nonce_auth_sponsored,
                                                                               TransactionPayload::TokenTransfer(recv_addr.clone(), 123, TokenTransferMemo([0u8; 34])));

        tx_stx_transfer_same_receiver.chain_id = 0x80000000;
        tx_stx_transfer_wrong_network.chain_id = 0x80000000;
        tx_stx_transfer_wrong_chain_id.chain_id = 0x80000001;
        tx_stx_transfer_postconditions.chain_id = 0x80000000;
        tx_stx_transfer_wrong_nonce.chain_id = 0x80000000;
        tx_stx_transfer_wrong_nonce_sponsored.chain_id = 0x80000000;

        tx_stx_transfer_same_receiver.post_condition_mode = TransactionPostConditionMode::Allow;
        tx_stx_transfer_wrong_network.post_condition_mode = TransactionPostConditionMode::Allow;
        tx_stx_transfer_wrong_chain_id.post_condition_mode = TransactionPostConditionMode::Allow;
        tx_stx_transfer_postconditions.post_condition_mode = TransactionPostConditionMode::Allow;
        tx_stx_transfer_wrong_nonce.post_condition_mode = TransactionPostConditionMode::Allow;
        tx_stx_transfer_wrong_nonce_sponsored.post_condition_mode = TransactionPostConditionMode::Allow;

        tx_stx_transfer_same_receiver.set_fee_rate(0);
        tx_stx_transfer_wrong_network.set_fee_rate(0);
        tx_stx_transfer_wrong_chain_id.set_fee_rate(0);
        tx_stx_transfer_postconditions.set_fee_rate(0);
        tx_stx_transfer_wrong_nonce.set_fee_rate(0);
        tx_stx_transfer_wrong_nonce_sponsored.set_fee_rate(0);

        let error_frags = vec![
            "address tried to send to itself".to_string(),
            "on testnet; got mainnet".to_string(),
            "invalid chain ID".to_string(),
            "do not support post-conditions".to_string(),
            "Bad nonce".to_string(),
            "Bad nonce".to_string(),
        ];

        let mut conn = chainstate.block_begin(&FIRST_BURNCHAIN_BLOCK_HASH, &FIRST_STACKS_BLOCK_HASH, &BurnchainHeaderHash([1u8; 32]), &BlockHeaderHash([1u8; 32]));
        StacksChainState::account_credit(&mut conn, &addr.to_account_principal(), 123);
        
        for (tx_stx_transfer, err_frag) in [tx_stx_transfer_same_receiver, tx_stx_transfer_wrong_network, tx_stx_transfer_wrong_chain_id, tx_stx_transfer_postconditions, tx_stx_transfer_wrong_nonce, tx_stx_transfer_wrong_nonce_sponsored].iter().zip(error_frags) {
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
          (begin (var-set bar (/ x y)) (ok (var-get bar))))";

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
          (begin (var-set bar (/ x y)) (ok (var-get bar))))";

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
          (begin (var-set bar (/ x y)) (ok (var-get bar))))";

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
          (begin (var-set bar (/ x y)) (ok (var-get bar))))";

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

    #[test]
    fn process_post_conditions_tokens() {
        let contract = "
        (define-data-var bar int 0)
        (define-fungible-token stackaroos)
        (define-non-fungible-token names (buff 50))
        (define-public (send-stackaroos (recipient principal))
          (begin 
             (as-contract  ;; used to test post-conditions on contract principal
               (begin (unwrap-panic (ft-mint? stackaroos u100 tx-sender))
                      (unwrap-panic (ft-transfer? stackaroos u100 tx-sender recipient))
                      (ok 'true))
             )
           )
        )
        (define-public (send-name (name (buff 50)) (recipient principal))
          (begin 
            (as-contract   ;; used to test post-conditions on contract principal
              (begin (unwrap-panic (nft-mint? names name tx-sender))
                     (unwrap-panic (nft-transfer? names name tx-sender recipient))
                     (ok 'true))
            )
          )
        )
        (define-public (user-send-stackaroos (recipient principal))
          (begin
             (unwrap-panic (ft-transfer? stackaroos u100 tx-sender recipient))
             (ok 'true))
        )
        (define-public (user-send-name (name (buff 50)) (recipient principal))
          (begin
             (unwrap-panic (nft-transfer? names name tx-sender recipient))
             (ok 'true))
        )
        (define-public (send-stackaroos-and-name (name (buff 50)) (recipient principal))
          (begin
             (as-contract  ;; used to test post-conditions on contract principal
               (begin (unwrap-panic (nft-mint? names name tx-sender))
                      (unwrap-panic (nft-transfer? names name tx-sender recipient))
                      (unwrap-panic (ft-mint? stackaroos u100 tx-sender))
                      (unwrap-panic (ft-transfer? stackaroos u100 tx-sender recipient))
                      (ok 'true))
             )
          )
        )
        (define-public (user-send-stackaroos-and-name (name (buff 50)) (recipient principal))
           (begin
             (unwrap-panic (ft-transfer? stackaroos u100 tx-sender recipient))
             (unwrap-panic (nft-transfer? names name tx-sender recipient))
             (ok 'true))
        )
        (define-public (get-bar) (ok (var-get bar)))
        (define-public (set-bar (x int) (y int))
          (begin (var-set bar (/ x y)) (ok (var-get bar))))";

        let privk_origin = StacksPrivateKey::from_hex("027682d2f7b05c3801fe4467883ab4cff0568b5e36412b5289e83ea5b519de8a01").unwrap();
        let privk_recipient = StacksPrivateKey::from_hex("7e3af4db6af6b3c67e2c6c6d7d5983b519f4d9b3a6e00580ae96dcace3bde8bc01").unwrap();
        let auth_origin = TransactionAuth::from_p2pkh(&privk_origin).unwrap();
        let auth_recv = TransactionAuth::from_p2pkh(&privk_recipient).unwrap();
        let addr_publisher = auth_origin.origin().address_testnet();
        let addr_principal = addr_publisher.to_account_principal();

        let contract_name = ContractName::try_from("hello-world").unwrap();

        let recv_addr = StacksAddress::from_public_keys(C32_ADDRESS_VERSION_TESTNET_SINGLESIG, &AddressHashMode::SerializeP2PKH, 1, &vec![StacksPublicKey::from_private(&privk_recipient)]).unwrap();
        let recv_principal = recv_addr.to_account_principal();
        let contract_id = QualifiedContractIdentifier::new(StandardPrincipalData::from(addr_publisher.clone()), contract_name.clone());
        let contract_principal = PrincipalData::Contract(contract_id.clone());

        let asset_info = AssetInfo {
            contract_address: addr_publisher.clone(),
            contract_name: contract_name.clone(),
            asset_name: ClarityName::try_from("stackaroos").unwrap(),
        };
        
        let name_asset_info = AssetInfo {
            contract_address: addr_publisher.clone(),
            contract_name: contract_name.clone(),
            asset_name: ClarityName::try_from("names").unwrap(),
        };
        
        let mut tx_contract = StacksTransaction::new(TransactionVersion::Testnet,
                                                     auth_origin.clone(),
                                                     TransactionPayload::new_smart_contract(&"hello-world".to_string(), &contract.to_string()).unwrap());

        tx_contract.chain_id = 0x80000000;
        tx_contract.set_fee_rate(0);

        let mut signer = StacksTransactionSigner::new(&tx_contract);
        signer.sign_origin(&privk_origin).unwrap();
        
        let signed_contract_tx = signer.get_tx().unwrap();

        let mut post_conditions_pass = vec![];
        let mut post_conditions_pass_payback = vec![];
        let mut post_conditions_pass_nft = vec![];
        let mut post_conditions_fail = vec![];
        let mut post_conditions_fail_payback = vec![];
        let mut post_conditions_fail_nft = vec![];
        let mut nonce = 1;
        let mut recv_nonce = 0;
        let mut next_name : u64 = 0;

        let mut tx_contract_call_stackaroos = StacksTransaction::new(TransactionVersion::Testnet,
                                                                     auth_origin.clone(),
                                                                     TransactionPayload::new_contract_call(addr_publisher.clone(), "hello-world", "send-stackaroos", vec![Value::Principal(recv_principal.clone())]).unwrap());

        tx_contract_call_stackaroos.chain_id = 0x80000000;
        tx_contract_call_stackaroos.set_fee_rate(0);

        // mint 100 stackaroos to recv_addr, and set a post-condition on the contract-principal
        // to check it.
        // assert contract sent ==, <=, or >= 100 stackaroos
        for pass_condition in [FungibleConditionCode::SentEq, FungibleConditionCode::SentGe, FungibleConditionCode::SentLe].iter() {
            let mut tx_contract_call_pass = tx_contract_call_stackaroos.clone();
            tx_contract_call_pass.set_origin_nonce(nonce);
            tx_contract_call_pass.add_post_condition(TransactionPostCondition::Fungible(PostConditionPrincipal::Contract(addr_publisher.clone(), contract_name.clone()), asset_info.clone(), *pass_condition, 100));

            let mut signer = StacksTransactionSigner::new(&tx_contract_call_pass);
            signer.sign_origin(&privk_origin).unwrap();
            post_conditions_pass.push(signer.get_tx().unwrap());

            nonce += 1;
        }
        
        // mint 100 stackaroos to recv_addr, and set a post-condition on the contract-principal
        // to check it.
        // assert contract sent >= or > 99 stackaroos
        for pass_condition in [FungibleConditionCode::SentGe, FungibleConditionCode::SentGt].iter() {
            let mut tx_contract_call_pass = tx_contract_call_stackaroos.clone();
            tx_contract_call_pass.set_origin_nonce(nonce);
            tx_contract_call_pass.add_post_condition(TransactionPostCondition::Fungible(PostConditionPrincipal::Contract(addr_publisher.clone(), contract_name.clone()), asset_info.clone(), *pass_condition, 99));

            let mut signer = StacksTransactionSigner::new(&tx_contract_call_pass);
            signer.sign_origin(&privk_origin).unwrap();
            post_conditions_pass.push(signer.get_tx().unwrap());
            
            nonce += 1;
        }
        
        // mint 100 stackaroos to recv_addr, and set a post-condition on the contract-principal
        // to check it.
        // assert contract sent <= or < 101 stackaroos
        for pass_condition in [FungibleConditionCode::SentLe, FungibleConditionCode::SentLt].iter() {
            let mut tx_contract_call_pass = tx_contract_call_stackaroos.clone();
            tx_contract_call_pass.set_origin_nonce(nonce);
            tx_contract_call_pass.add_post_condition(TransactionPostCondition::Fungible(PostConditionPrincipal::Contract(addr_publisher.clone(), contract_name.clone()), asset_info.clone(), *pass_condition, 101));

            let mut signer = StacksTransactionSigner::new(&tx_contract_call_pass);
            signer.sign_origin(&privk_origin).unwrap();
            post_conditions_pass.push(signer.get_tx().unwrap());
            
            nonce += 1;
        }
        
        // give recv_addr 100 more stackaroos so we can test failure-to-send-back
        {
            let mut tx_contract_call_pass = tx_contract_call_stackaroos.clone();
            tx_contract_call_pass.set_origin_nonce(nonce);
            tx_contract_call_pass.add_post_condition(TransactionPostCondition::Fungible(PostConditionPrincipal::Contract(addr_publisher.clone(), contract_name.clone()), asset_info.clone(), FungibleConditionCode::SentEq, 100));

            let mut signer = StacksTransactionSigner::new(&tx_contract_call_pass);
            signer.sign_origin(&privk_origin).unwrap();
            post_conditions_pass.push(signer.get_tx().unwrap());
            
            nonce += 1;
        }

        let mut tx_contract_call_user_stackaroos = StacksTransaction::new(TransactionVersion::Testnet,
                                                                          auth_recv.clone(),
                                                                          TransactionPayload::new_contract_call(addr_publisher.clone(), "hello-world", "user-send-stackaroos", vec![Value::Principal(addr_principal.clone())]).unwrap());

        tx_contract_call_user_stackaroos.chain_id = 0x80000000;
        tx_contract_call_user_stackaroos.set_fee_rate(0);
        
        // recv_addr sends 100 stackaroos back to addr_publisher.
        // assert recv_addr sent ==, <=, or >= 100 stackaroos
        for pass_condition in [FungibleConditionCode::SentEq, FungibleConditionCode::SentGe, FungibleConditionCode::SentLe].iter() {
            let mut tx_contract_call_pass = tx_contract_call_user_stackaroos.clone();
            tx_contract_call_pass.set_origin_nonce(recv_nonce);
            tx_contract_call_pass.add_post_condition(TransactionPostCondition::Fungible(PostConditionPrincipal::Standard(recv_addr.clone()), asset_info.clone(), *pass_condition, 100));

            let mut signer = StacksTransactionSigner::new(&tx_contract_call_pass);
            signer.sign_origin(&privk_recipient).unwrap();
            post_conditions_pass_payback.push(signer.get_tx().unwrap());

            recv_nonce += 1;
        }
        
        // recv_addr sends 100 stackaroos back to addr_publisher.
        // assert recv_addr sent >= or > 99 stackaroos
        for pass_condition in [FungibleConditionCode::SentGe, FungibleConditionCode::SentGt].iter() {
            let mut tx_contract_call_pass = tx_contract_call_user_stackaroos.clone();
            tx_contract_call_pass.set_origin_nonce(recv_nonce);
            tx_contract_call_pass.add_post_condition(TransactionPostCondition::Fungible(PostConditionPrincipal::Standard(recv_addr.clone()), asset_info.clone(), *pass_condition, 99));

            let mut signer = StacksTransactionSigner::new(&tx_contract_call_pass);
            signer.sign_origin(&privk_recipient).unwrap();
            post_conditions_pass_payback.push(signer.get_tx().unwrap());

            recv_nonce += 1;
        }

        // recv_addr sends 100 stackaroos back to addr_publisher
        // assert recv_addr sent <= or < 101 stackaroos
        for pass_condition in [FungibleConditionCode::SentLe, FungibleConditionCode::SentLt].iter() {
            let mut tx_contract_call_pass = tx_contract_call_user_stackaroos.clone();
            tx_contract_call_pass.set_origin_nonce(recv_nonce);
            tx_contract_call_pass.add_post_condition(TransactionPostCondition::Fungible(PostConditionPrincipal::Standard(recv_addr.clone()), asset_info.clone(), *pass_condition, 101));

            let mut signer = StacksTransactionSigner::new(&tx_contract_call_pass);
            signer.sign_origin(&privk_recipient).unwrap();
            post_conditions_pass_payback.push(signer.get_tx().unwrap());

            recv_nonce += 1;
        }

        // mint names to recv_addr, and set a post-condition on the contract-principal to check it.
        // assert contract does not possess the name
        for (i, pass_condition) in [NonfungibleConditionCode::Absent].iter().enumerate() {
            let name = Value::buff_from(next_name.to_be_bytes().to_vec()).unwrap();
            next_name += 1;

            let mut tx_contract_call_names = StacksTransaction::new(TransactionVersion::Testnet,
                                                                    auth_origin.clone(),
                                                                    TransactionPayload::new_contract_call(addr_publisher.clone(), "hello-world", "send-name", vec![name.clone(),
                                                                                                                                                                   Value::Principal(recv_principal.clone())]).unwrap());

            tx_contract_call_names.chain_id = 0x80000000;
            tx_contract_call_names.set_fee_rate(0);
            tx_contract_call_names.set_origin_nonce(nonce);

            tx_contract_call_names.add_post_condition(TransactionPostCondition::Nonfungible(PostConditionPrincipal::Contract(addr_publisher.clone(), contract_name.clone()), name_asset_info.clone(), name.clone(), *pass_condition));

            let mut signer = StacksTransactionSigner::new(&tx_contract_call_names);
            signer.sign_origin(&privk_origin).unwrap();
            post_conditions_pass_nft.push(signer.get_tx().unwrap());

            nonce += 1;
        }

        // mint 100 stackaroos to recv_addr, and set a post-condition on the contract-principal
        // to check it.
        // assert contract sent < or > 100 stackaroos (should fail)
        for fail_condition in [FungibleConditionCode::SentLt, FungibleConditionCode::SentGt].iter() {
            let mut tx_contract_call_fail = tx_contract_call_stackaroos.clone();
            tx_contract_call_fail.set_origin_nonce(nonce);
            tx_contract_call_fail.add_post_condition(TransactionPostCondition::Fungible(PostConditionPrincipal::Contract(addr_publisher.clone(), contract_name.clone()), asset_info.clone(), *fail_condition, 100));

            let mut signer = StacksTransactionSigner::new(&tx_contract_call_fail);
            signer.sign_origin(&privk_origin).unwrap();
            post_conditions_fail.push(signer.get_tx().unwrap());

            nonce += 1;
        }
        
        // mint 100 stackaroos to recv_addr, and set a post-condition on the contract-principal
        // to check it.
        // assert contract sent <= or < 99 stackaroos (should fail)
        for fail_condition in [FungibleConditionCode::SentLe, FungibleConditionCode::SentLt].iter() {
            let mut tx_contract_call_fail = tx_contract_call_stackaroos.clone();
            tx_contract_call_fail.set_origin_nonce(nonce);
            tx_contract_call_fail.add_post_condition(TransactionPostCondition::Fungible(PostConditionPrincipal::Contract(addr_publisher.clone(), contract_name.clone()), asset_info.clone(), *fail_condition, 99));

            let mut signer = StacksTransactionSigner::new(&tx_contract_call_fail);
            signer.sign_origin(&privk_origin).unwrap();
            post_conditions_fail.push(signer.get_tx().unwrap());

            nonce += 1;
        }
        
        // mint 100 stackaroos to recv_addr, and set a post-condition on the contract-principal
        // to check it.
        // assert contract sent > or >= 101 stackaroos (should fail)
        for fail_condition in [FungibleConditionCode::SentGe, FungibleConditionCode::SentGt].iter() {
            let mut tx_contract_call_fail = tx_contract_call_stackaroos.clone();
            tx_contract_call_fail.set_origin_nonce(nonce);
            tx_contract_call_fail.add_post_condition(TransactionPostCondition::Fungible(PostConditionPrincipal::Contract(addr_publisher.clone(), contract_name.clone()), asset_info.clone(), *fail_condition, 101));

            let mut signer = StacksTransactionSigner::new(&tx_contract_call_fail);
            signer.sign_origin(&privk_origin).unwrap();
            post_conditions_fail.push(signer.get_tx().unwrap());

            nonce += 1;
        }

        // recv_addr tries sends 100 stackaroos back to addr_publisher
        // assert recv_addr sent < or > 100 stackaroos (should fail)
        for fail_condition in [FungibleConditionCode::SentLt, FungibleConditionCode::SentLt].iter() {
            let mut tx_contract_call_fail = tx_contract_call_user_stackaroos.clone();
            tx_contract_call_fail.set_origin_nonce(recv_nonce);
            tx_contract_call_fail.add_post_condition(TransactionPostCondition::Fungible(PostConditionPrincipal::Standard(recv_addr.clone()), asset_info.clone(), *fail_condition, 100));

            let mut signer = StacksTransactionSigner::new(&tx_contract_call_fail);
            signer.sign_origin(&privk_recipient).unwrap();
            post_conditions_fail_payback.push(signer.get_tx().unwrap());

            recv_nonce += 1;
        }
        
        // mint names to recv_addr, and set a post-condition on the contract-principal to check it.
        // assert contract still possesses the name (should fail)
        for (i, fail_condition) in [NonfungibleConditionCode::Present].iter().enumerate() {
            let name = Value::buff_from(next_name.to_be_bytes().to_vec()).unwrap();
            next_name += 1;

            let mut tx_contract_call_names = StacksTransaction::new(TransactionVersion::Testnet,
                                                                    auth_origin.clone(),
                                                                    TransactionPayload::new_contract_call(addr_publisher.clone(), "hello-world", "send-name", vec![name.clone(),
                                                                                                                                                                   Value::Principal(recv_principal.clone())]).unwrap());

            tx_contract_call_names.chain_id = 0x80000000;
            tx_contract_call_names.set_fee_rate(0);
            tx_contract_call_names.set_origin_nonce(nonce);

            tx_contract_call_names.add_post_condition(TransactionPostCondition::Nonfungible(PostConditionPrincipal::Contract(addr_publisher.clone(), contract_name.clone()), name_asset_info.clone(), name.clone(), *fail_condition));

            let mut signer = StacksTransactionSigner::new(&tx_contract_call_names);
            signer.sign_origin(&privk_origin).unwrap();
            post_conditions_fail_nft.push(signer.get_tx().unwrap());

            nonce += 1;
        }

        let mut chainstate = instantiate_chainstate(false, 0x80000000, "process-post-conditions");
        let mut conn = chainstate.block_begin(&FIRST_BURNCHAIN_BLOCK_HASH, &FIRST_STACKS_BLOCK_HASH, &BurnchainHeaderHash([1u8; 32]), &BlockHeaderHash([1u8; 32]));

        let account_publisher = StacksChainState::get_account(&mut conn, &addr_publisher.to_account_principal());
        assert_eq!(account_publisher.nonce, 0);

        // no initial stackaroos balance -- there is no stackaroos token (yet)
        let _ = StacksChainState::get_account_ft(&mut conn, &contract_id, "stackaroos", &recv_principal).unwrap_err();

        // publish contract
        let _ = StacksChainState::process_transaction(&mut conn, &signed_contract_tx).unwrap();
        
        // no initial stackaroos balance
        let account_stackaroos_balance = StacksChainState::get_account_ft(&mut conn, &contract_id, "stackaroos", &recv_principal).unwrap();
        assert_eq!(account_stackaroos_balance, 0);

        let mut expected_stackaroos_balance = 0;
        let mut expected_nonce = 1;
        let mut expected_recv_nonce = 0;
        let mut expected_payback_stackaroos_balance = 0;
        let mut expected_next_name : u64 = 0;

        for tx_pass in post_conditions_pass.iter() {
            let (fee, _) = StacksChainState::process_transaction(&mut conn, &tx_pass).unwrap();
            expected_stackaroos_balance += 100;
            expected_nonce += 1;

            let account_recipient_stackaroos_after = StacksChainState::get_account_ft(&mut conn, &contract_id, "stackaroos", &recv_principal).unwrap();
            assert_eq!(account_recipient_stackaroos_after, expected_stackaroos_balance);

            let account_publisher_after = StacksChainState::get_account(&mut conn, &addr_publisher.to_account_principal());
            assert_eq!(account_publisher_after.nonce, expected_nonce);
        }
        
        for tx_pass in post_conditions_pass_payback.iter() {
            let (fee, _) = StacksChainState::process_transaction(&mut conn, &tx_pass).unwrap();
            expected_stackaroos_balance -= 100;
            expected_payback_stackaroos_balance += 100;
            expected_recv_nonce += 1;

            let account_recipient_stackaroos_after = StacksChainState::get_account_ft(&mut conn, &contract_id, "stackaroos", &recv_principal).unwrap();
            assert_eq!(account_recipient_stackaroos_after, expected_stackaroos_balance);
            
            let account_pub_stackaroos_after = StacksChainState::get_account_ft(&mut conn, &contract_id, "stackaroos", &addr_principal).unwrap();
            assert_eq!(account_pub_stackaroos_after, expected_payback_stackaroos_balance);

            let account_publisher_after = StacksChainState::get_account(&mut conn, &addr_publisher.to_account_principal());
            assert_eq!(account_publisher_after.nonce, expected_nonce);
            
            let account_recv_publisher_after = StacksChainState::get_account(&mut conn, &recv_addr.to_account_principal());
            assert_eq!(account_recv_publisher_after.nonce, expected_recv_nonce);
        }
        
        for (i, tx_pass) in post_conditions_pass_nft.iter().enumerate() {
            let (fee, _) = StacksChainState::process_transaction(&mut conn, &tx_pass).unwrap();
            expected_nonce += 1;

            let expected_value = Value::buff_from(expected_next_name.to_be_bytes().to_vec()).unwrap();
            expected_next_name += 1;

            let account_recipient_names_after = StacksChainState::get_account_nft(&mut conn, &contract_id, "names", &expected_value).unwrap();
            assert_eq!(account_recipient_names_after, recv_principal);

            let account_publisher_after = StacksChainState::get_account(&mut conn, &addr_publisher.to_account_principal());
            assert_eq!(account_publisher_after.nonce, expected_nonce);
        }

        for tx_fail in post_conditions_fail.iter() {
            let (fee, _) = StacksChainState::process_transaction(&mut conn, &tx_fail).unwrap();
            expected_nonce += 1;
            
            // no change in balance
            let account_recipient_stackaroos_after = StacksChainState::get_account_ft(&mut conn, &contract_id, "stackaroos", &recv_principal).unwrap();
            assert_eq!(account_recipient_stackaroos_after, expected_stackaroos_balance);
            
            let account_pub_stackaroos_after = StacksChainState::get_account_ft(&mut conn, &contract_id, "stackaroos", &addr_principal).unwrap();
            assert_eq!(account_pub_stackaroos_after, expected_payback_stackaroos_balance);
            
            // but nonce _does_ change
            let account_publisher_after = StacksChainState::get_account(&mut conn, &addr_publisher.to_account_principal());
            assert_eq!(account_publisher_after.nonce, expected_nonce);
        }
        
        for tx_fail in post_conditions_fail_payback.iter() {
            let (fee, _) = StacksChainState::process_transaction(&mut conn, &tx_fail).unwrap();
            expected_recv_nonce += 1;
            
            // no change in balance
            let account_recipient_stackaroos_after = StacksChainState::get_account_ft(&mut conn, &contract_id, "stackaroos", &recv_principal).unwrap();
            assert_eq!(account_recipient_stackaroos_after, expected_stackaroos_balance);
            
            let account_pub_stackaroos_after = StacksChainState::get_account_ft(&mut conn, &contract_id, "stackaroos", &addr_principal).unwrap();
            assert_eq!(account_pub_stackaroos_after, expected_payback_stackaroos_balance);
            
            // nonce for publisher doesn't change
            let account_publisher_after = StacksChainState::get_account(&mut conn, &addr_publisher.to_account_principal());
            assert_eq!(account_publisher_after.nonce, expected_nonce);
            
            // but nonce _does_ change for reciever, who sent back
            let account_publisher_after = StacksChainState::get_account(&mut conn, &recv_addr.to_account_principal());
            assert_eq!(account_publisher_after.nonce, expected_recv_nonce);
        }

        for (i, tx_fail) in post_conditions_fail_nft.iter().enumerate() {
            let (fee, _) = StacksChainState::process_transaction(&mut conn, &tx_fail).unwrap();
            expected_nonce += 1;
           
            // nft shouldn't exist -- the nft-mint! should have been rolled back
            let expected_value = Value::buff_from(expected_next_name.to_be_bytes().to_vec()).unwrap();
            expected_next_name += 1;

            let res = StacksChainState::get_account_nft(&mut conn, &contract_id, "names", &expected_value);
            assert!(res.is_err());
            
            // but nonce _does_ change
            let account_publisher_after = StacksChainState::get_account(&mut conn, &addr_publisher.to_account_principal());
            assert_eq!(account_publisher_after.nonce, expected_nonce);
        }
        
        conn.commit_block();
    }
    
    #[test]
    fn process_post_conditions_tokens_deny() {
        let contract = "
        (define-data-var bar int 0)
        (define-fungible-token stackaroos)
        (define-non-fungible-token names (buff 50))
        (define-public (send-stackaroos (recipient principal))
          (begin 
             (as-contract  ;; used to test post-conditions on contract principal
               (begin (unwrap-panic (ft-mint? stackaroos u100 tx-sender))
                      (unwrap-panic (ft-transfer? stackaroos u100 tx-sender recipient))
                      (ok 'true))
             )
           )
        )
        (define-public (send-name (name (buff 50)) (recipient principal))
          (begin 
            (as-contract   ;; used to test post-conditions on contract principal
              (begin (unwrap-panic (nft-mint? names name tx-sender))
                     (unwrap-panic (nft-transfer? names name tx-sender recipient))
                     (ok 'true))
            )
          )
        )
        (define-public (user-send-stackaroos (recipient principal))
          (begin
             (unwrap-panic (ft-transfer? stackaroos u100 tx-sender recipient))
             (ok 'true))
        )
        (define-public (user-send-name (name (buff 50)) (recipient principal))
          (begin
             (unwrap-panic (nft-transfer? names name tx-sender recipient))
             (ok 'true))
        )
        (define-public (send-stackaroos-and-name (name (buff 50)) (recipient principal))
          (begin
             (as-contract  ;; used to test post-conditions on contract principal
               (begin (unwrap-panic (nft-mint? names name tx-sender))
                      (unwrap-panic (nft-transfer? names name tx-sender recipient))
                      (unwrap-panic (ft-mint? stackaroos u100 tx-sender))
                      (unwrap-panic (ft-transfer? stackaroos u100 tx-sender recipient))
                      (ok 'true))
             )
          )
        )
        (define-public (user-send-stackaroos-and-name (name (buff 50)) (recipient principal))
           (begin
             (unwrap-panic (ft-transfer? stackaroos u100 tx-sender recipient))
             (unwrap-panic (nft-transfer? names name tx-sender recipient))
             (ok 'true))
        )
        (define-public (get-bar) (ok (var-get bar)))
        (define-public (set-bar (x int) (y int))
          (begin (var-set bar (/ x y)) (ok (var-get bar))))";

        let privk_origin = StacksPrivateKey::from_hex("027682d2f7b05c3801fe4467883ab4cff0568b5e36412b5289e83ea5b519de8a01").unwrap();
        let privk_recipient = StacksPrivateKey::from_hex("7e3af4db6af6b3c67e2c6c6d7d5983b519f4d9b3a6e00580ae96dcace3bde8bc01").unwrap();
        let auth_origin = TransactionAuth::from_p2pkh(&privk_origin).unwrap();
        let auth_recv = TransactionAuth::from_p2pkh(&privk_recipient).unwrap();
        let addr_publisher = auth_origin.origin().address_testnet();
        let addr_principal = addr_publisher.to_account_principal();

        let contract_name = ContractName::try_from("hello-world").unwrap();

        let recv_addr = StacksAddress::from_public_keys(C32_ADDRESS_VERSION_TESTNET_SINGLESIG, &AddressHashMode::SerializeP2PKH, 1, &vec![StacksPublicKey::from_private(&privk_recipient)]).unwrap();
        let recv_principal = recv_addr.to_account_principal();
        let contract_id = QualifiedContractIdentifier::new(StandardPrincipalData::from(addr_publisher.clone()), contract_name.clone());
        let contract_principal = PrincipalData::Contract(contract_id.clone());

        let asset_info = AssetInfo {
            contract_address: addr_publisher.clone(),
            contract_name: contract_name.clone(),
            asset_name: ClarityName::try_from("stackaroos").unwrap(),
        };
        
        let name_asset_info = AssetInfo {
            contract_address: addr_publisher.clone(),
            contract_name: contract_name.clone(),
            asset_name: ClarityName::try_from("names").unwrap(),
        };
        
        let mut tx_contract = StacksTransaction::new(TransactionVersion::Testnet,
                                                     auth_origin.clone(),
                                                     TransactionPayload::new_smart_contract(&"hello-world".to_string(), &contract.to_string()).unwrap());

        tx_contract.chain_id = 0x80000000;
        tx_contract.set_fee_rate(0);

        let mut signer = StacksTransactionSigner::new(&tx_contract);
        signer.sign_origin(&privk_origin).unwrap();
        
        let signed_contract_tx = signer.get_tx().unwrap();

        let mut post_conditions_pass = vec![];
        let mut post_conditions_pass_payback = vec![];
        let mut post_conditions_fail = vec![];
        let mut post_conditions_fail_payback = vec![];
        let mut nonce = 1;
        let mut recv_nonce = 0;
        let mut next_name : u64 = 0;
        let mut next_recv_name : u64 = 0;
        let final_recv_name = 3;

        // mint 100 stackaroos and the name to recv_addr, and set a post-condition for each asset on the contract-principal
        // assert contract sent ==, <=, or >= 100 stackaroos
        for (i, pass_condition) in [FungibleConditionCode::SentEq, FungibleConditionCode::SentGe, FungibleConditionCode::SentLe].iter().enumerate() {
            let name = Value::buff_from(next_name.to_be_bytes().to_vec()).unwrap();
            next_name += 1;

            let mut tx_contract_call_both = StacksTransaction::new(TransactionVersion::Testnet,
                                                                   auth_origin.clone(),
                                                                   TransactionPayload::new_contract_call(addr_publisher.clone(), "hello-world", "send-stackaroos-and-name", vec![name.clone(), Value::Principal(recv_principal.clone())]).unwrap());

            tx_contract_call_both.chain_id = 0x80000000;
            tx_contract_call_both.set_fee_rate(0);
            tx_contract_call_both.set_origin_nonce(nonce);
            
            tx_contract_call_both.post_condition_mode = TransactionPostConditionMode::Deny;
            tx_contract_call_both.add_post_condition(TransactionPostCondition::Fungible(PostConditionPrincipal::Contract(addr_publisher.clone(), contract_name.clone()), asset_info.clone(), *pass_condition, 100));
            tx_contract_call_both.add_post_condition(TransactionPostCondition::Nonfungible(PostConditionPrincipal::Contract(addr_publisher.clone(), contract_name.clone()), name_asset_info.clone(), name.clone(), NonfungibleConditionCode::Absent));

            let mut signer = StacksTransactionSigner::new(&tx_contract_call_both);
            signer.sign_origin(&privk_origin).unwrap();
            post_conditions_pass.push(signer.get_tx().unwrap());

            nonce += 1;
        }
        
        // give recv_addr 100 more stackaroos so we can test failure-to-send-back
        {
            let name = Value::buff_from(next_name.to_be_bytes().to_vec()).unwrap();
            next_name += 1;

            let mut tx_contract_call_both = StacksTransaction::new(TransactionVersion::Testnet,
                                                                   auth_origin.clone(),
                                                                   TransactionPayload::new_contract_call(addr_publisher.clone(), "hello-world", "send-stackaroos-and-name", vec![name.clone(), Value::Principal(recv_principal.clone())]).unwrap());

            tx_contract_call_both.post_condition_mode = TransactionPostConditionMode::Allow;
            tx_contract_call_both.chain_id = 0x80000000;
            tx_contract_call_both.set_fee_rate(0);
            tx_contract_call_both.set_origin_nonce(nonce);

            let mut signer = StacksTransactionSigner::new(&tx_contract_call_both);
            signer.sign_origin(&privk_origin).unwrap();
            post_conditions_pass.push(signer.get_tx().unwrap());
            
            nonce += 1;
        }

        assert_eq!(next_name, final_recv_name + 1);
        
        // recv_addr sends 100 stackaroos and name back to addr_publisher.
        // assert recv_addr sent ==, <=, or >= 100 stackaroos
        for (i, pass_condition) in [FungibleConditionCode::SentEq, FungibleConditionCode::SentGe, FungibleConditionCode::SentLe].iter().enumerate() {
            let name = Value::buff_from(next_recv_name.to_be_bytes().to_vec()).unwrap();
            next_recv_name += 1;

            let mut tx_contract_call_both = StacksTransaction::new(TransactionVersion::Testnet,
                                                                   auth_recv.clone(),
                                                                   TransactionPayload::new_contract_call(addr_publisher.clone(), "hello-world", "user-send-stackaroos-and-name", vec![name.clone(), Value::Principal(addr_principal.clone())]).unwrap());

            tx_contract_call_both.chain_id = 0x80000000;
            tx_contract_call_both.set_fee_rate(0);
            tx_contract_call_both.set_origin_nonce(recv_nonce);
            
            tx_contract_call_both.post_condition_mode = TransactionPostConditionMode::Deny;
            tx_contract_call_both.add_post_condition(TransactionPostCondition::Fungible(PostConditionPrincipal::Standard(recv_addr.clone()), asset_info.clone(), *pass_condition, 100));
            tx_contract_call_both.add_post_condition(TransactionPostCondition::Nonfungible(PostConditionPrincipal::Standard(recv_addr.clone()), name_asset_info.clone(), name.clone(), NonfungibleConditionCode::Absent));
            
            let mut signer = StacksTransactionSigner::new(&tx_contract_call_both);
            signer.sign_origin(&privk_recipient).unwrap();
            post_conditions_pass_payback.push(signer.get_tx().unwrap());

            recv_nonce += 1;
        }
        
        // mint 100 stackaroos and the name to recv_addr, but neglect to set a fungible post-condition.
        // assert contract sent ==, <=, or >= 100 stackaroos, and that the name was removed from
        // the contract
        for (i, fail_condition) in [FungibleConditionCode::SentEq, FungibleConditionCode::SentGe, FungibleConditionCode::SentLe].iter().enumerate() {
            let name = Value::buff_from(next_name.to_be_bytes().to_vec()).unwrap();
            next_name += 1;

            let mut tx_contract_call_both = StacksTransaction::new(TransactionVersion::Testnet,
                                                                   auth_origin.clone(),
                                                                   TransactionPayload::new_contract_call(addr_publisher.clone(), "hello-world", "send-stackaroos-and-name", vec![name.clone(), Value::Principal(recv_principal.clone())]).unwrap());

            tx_contract_call_both.chain_id = 0x80000000;
            tx_contract_call_both.set_fee_rate(0);
            tx_contract_call_both.set_origin_nonce(nonce);
            
            tx_contract_call_both.post_condition_mode = TransactionPostConditionMode::Deny;
            // tx_contract_call_both.add_post_condition(TransactionPostCondition::Fungible(PostConditionPrincipal::Contract(addr_publisher.clone(), contract_name.clone()), asset_info.clone(), *fail_condition, 100));
            tx_contract_call_both.add_post_condition(TransactionPostCondition::Nonfungible(PostConditionPrincipal::Contract(addr_publisher.clone(), contract_name.clone()), name_asset_info.clone(), name.clone(), NonfungibleConditionCode::Absent));

            let mut signer = StacksTransactionSigner::new(&tx_contract_call_both);
            signer.sign_origin(&privk_origin).unwrap();
            post_conditions_fail.push(signer.get_tx().unwrap());

            nonce += 1;
        }

        // mint 100 stackaroos and the name to recv_addr, but neglect to set a non-fungible post-condition.
        // assert contract sent ==, <=, or >= 100 stackaroos, and that the name was removed from
        // the contract
        for (i, fail_condition) in [FungibleConditionCode::SentEq, FungibleConditionCode::SentGe, FungibleConditionCode::SentLe].iter().enumerate() {
            let name = Value::buff_from(next_name.to_be_bytes().to_vec()).unwrap();
            next_name += 1;

            let mut tx_contract_call_both = StacksTransaction::new(TransactionVersion::Testnet,
                                                                   auth_origin.clone(),
                                                                   TransactionPayload::new_contract_call(addr_publisher.clone(), "hello-world", "send-stackaroos-and-name", vec![name.clone(), Value::Principal(recv_principal.clone())]).unwrap());

            tx_contract_call_both.chain_id = 0x80000000;
            tx_contract_call_both.set_fee_rate(0);
            tx_contract_call_both.set_origin_nonce(nonce);
            
            tx_contract_call_both.post_condition_mode = TransactionPostConditionMode::Deny;
            tx_contract_call_both.add_post_condition(TransactionPostCondition::Fungible(PostConditionPrincipal::Contract(addr_publisher.clone(), contract_name.clone()), asset_info.clone(), *fail_condition, 100));
            // tx_contract_call_both.add_post_condition(TransactionPostCondition::Nonfungible(PostConditionPrincipal::Contract(addr_publisher.clone(), contract_name.clone()), name_asset_info.clone(), name.clone(), NonfungibleConditionCode::Absent));

            let mut signer = StacksTransactionSigner::new(&tx_contract_call_both);
            signer.sign_origin(&privk_origin).unwrap();
            post_conditions_fail.push(signer.get_tx().unwrap());

            nonce += 1;
        }
        
        // recv_addr sends 100 stackaroos and name back to addr_publisher, but forgets a fungible
        // post-condition.
        // assert recv_addr sent ==, <=, or >= 100 stackaroos
        for (i, fail_condition) in [FungibleConditionCode::SentEq, FungibleConditionCode::SentGe, FungibleConditionCode::SentLe].iter().enumerate() {
            let name = Value::buff_from(final_recv_name.to_be_bytes().to_vec()).unwrap();

            let mut tx_contract_call_both = StacksTransaction::new(TransactionVersion::Testnet,
                                                                   auth_recv.clone(),
                                                                   TransactionPayload::new_contract_call(addr_publisher.clone(), "hello-world", "user-send-stackaroos-and-name", vec![name.clone(), Value::Principal(addr_principal.clone())]).unwrap());

            tx_contract_call_both.chain_id = 0x80000000;
            tx_contract_call_both.set_fee_rate(0);
            tx_contract_call_both.set_origin_nonce(recv_nonce);
            
            tx_contract_call_both.post_condition_mode = TransactionPostConditionMode::Deny;
            // tx_contract_call_both.add_post_condition(TransactionPostCondition::Fungible(PostConditionPrincipal::Standard(recv_addr.clone()), asset_info.clone(), *fail_condition, 100));
            tx_contract_call_both.add_post_condition(TransactionPostCondition::Nonfungible(PostConditionPrincipal::Standard(recv_addr.clone()), name_asset_info.clone(), name.clone(), NonfungibleConditionCode::Absent));
            
            let mut signer = StacksTransactionSigner::new(&tx_contract_call_both);
            signer.sign_origin(&privk_recipient).unwrap();
            post_conditions_fail_payback.push(signer.get_tx().unwrap());

            recv_nonce += 1;
        }

        next_recv_name -= 3;    // reset
       
        // recv_addr sends 100 stackaroos and name back to addr_publisher, but forgets a non-fungible
        // post-condition.
        // assert recv_addr sent ==, <=, or >= 100 stackaroos
        for (i, fail_condition) in [FungibleConditionCode::SentEq, FungibleConditionCode::SentGe, FungibleConditionCode::SentLe].iter().enumerate() {
            let name = Value::buff_from(final_recv_name.to_be_bytes().to_vec()).unwrap();

            let mut tx_contract_call_both = StacksTransaction::new(TransactionVersion::Testnet,
                                                                   auth_recv.clone(),
                                                                   TransactionPayload::new_contract_call(addr_publisher.clone(), "hello-world", "user-send-stackaroos-and-name", vec![name.clone(), Value::Principal(addr_principal.clone())]).unwrap());

            tx_contract_call_both.chain_id = 0x80000000;
            tx_contract_call_both.set_fee_rate(0);
            tx_contract_call_both.set_origin_nonce(recv_nonce);
            
            tx_contract_call_both.post_condition_mode = TransactionPostConditionMode::Deny;
            tx_contract_call_both.add_post_condition(TransactionPostCondition::Fungible(PostConditionPrincipal::Standard(recv_addr.clone()), asset_info.clone(), *fail_condition, 100));
            // tx_contract_call_both.add_post_condition(TransactionPostCondition::Nonfungible(PostConditionPrincipal::Standard(recv_addr.clone()), name_asset_info.clone(), name.clone(), NonfungibleConditionCode::Absent));
            
            let mut signer = StacksTransactionSigner::new(&tx_contract_call_both);
            signer.sign_origin(&privk_recipient).unwrap();
            post_conditions_fail_payback.push(signer.get_tx().unwrap());

            recv_nonce += 1;
        }
        
        let mut chainstate = instantiate_chainstate(false, 0x80000000, "process-post-conditions");
        let mut conn = chainstate.block_begin(&FIRST_BURNCHAIN_BLOCK_HASH, &FIRST_STACKS_BLOCK_HASH, &BurnchainHeaderHash([1u8; 32]), &BlockHeaderHash([1u8; 32]));

        let account_publisher = StacksChainState::get_account(&mut conn, &addr_publisher.to_account_principal());
        assert_eq!(account_publisher.nonce, 0);

        // no initial stackaroos balance -- there is no stackaroos token (yet)
        let _ = StacksChainState::get_account_ft(&mut conn, &contract_id, "stackaroos", &recv_principal).unwrap_err();

        // publish contract
        let _ = StacksChainState::process_transaction(&mut conn, &signed_contract_tx).unwrap();
        
        // no initial stackaroos balance
        let account_stackaroos_balance = StacksChainState::get_account_ft(&mut conn, &contract_id, "stackaroos", &recv_principal).unwrap();
        assert_eq!(account_stackaroos_balance, 0);

        let mut expected_stackaroos_balance = 0;
        let mut expected_nonce = 1;
        let mut expected_recv_nonce = 0;
        let mut expected_payback_stackaroos_balance = 0;

        for (i, tx_pass) in post_conditions_pass.iter().enumerate() {
            let (fee, _) = StacksChainState::process_transaction(&mut conn, &tx_pass).unwrap();
            expected_stackaroos_balance += 100;
            expected_nonce += 1;

            // should have gotten stackaroos
            let account_recipient_stackaroos_after = StacksChainState::get_account_ft(&mut conn, &contract_id, "stackaroos", &recv_principal).unwrap();
            assert_eq!(account_recipient_stackaroos_after, expected_stackaroos_balance);

            // should have gotten name we created here
            let expected_value = match tx_pass.payload {
                TransactionPayload::ContractCall(ref cc) => cc.function_args[0].clone(),
                _ => { panic!("Not a contract call") }
            };

            let account_recipient_names_after = StacksChainState::get_account_nft(&mut conn, &contract_id, "names", &expected_value).unwrap();
            assert_eq!(account_recipient_names_after, recv_principal);

            // sender's nonce increased
            let account_publisher_after = StacksChainState::get_account(&mut conn, &addr_publisher.to_account_principal());
            assert_eq!(account_publisher_after.nonce, expected_nonce);
        }
        
        for (i, tx_pass) in post_conditions_pass_payback.iter().enumerate() {
            let (fee, _) = StacksChainState::process_transaction(&mut conn, &tx_pass).unwrap();
            expected_stackaroos_balance -= 100;
            expected_payback_stackaroos_balance += 100;
            expected_recv_nonce += 1;

            // recipient should have sent stackaroos
            let account_recipient_stackaroos_after = StacksChainState::get_account_ft(&mut conn, &contract_id, "stackaroos", &recv_principal).unwrap();
            assert_eq!(account_recipient_stackaroos_after, expected_stackaroos_balance);
            
            // publisher should have gotten them
            let account_pub_stackaroos_after = StacksChainState::get_account_ft(&mut conn, &contract_id, "stackaroos", &addr_principal).unwrap();
            assert_eq!(account_pub_stackaroos_after, expected_payback_stackaroos_balance);
            
            // should have gotten name we created here
            let expected_value = match tx_pass.payload {
                TransactionPayload::ContractCall(ref cc) => cc.function_args[0].clone(),
                _ => { panic!("Not a contract call") }
            };

            let account_publisher_names_after = StacksChainState::get_account_nft(&mut conn, &contract_id, "names", &expected_value).unwrap();
            assert_eq!(account_publisher_names_after, addr_principal);

            // no change in nonce
            let account_publisher_after = StacksChainState::get_account(&mut conn, &addr_publisher.to_account_principal());
            assert_eq!(account_publisher_after.nonce, expected_nonce);
            
            // receiver nonce changed
            let account_recv_publisher_after = StacksChainState::get_account(&mut conn, &recv_addr.to_account_principal());
            assert_eq!(account_recv_publisher_after.nonce, expected_recv_nonce);
        }
       
        for (i, tx_fail) in post_conditions_fail.iter().enumerate() {
            let (fee, _) = StacksChainState::process_transaction(&mut conn, &tx_fail).unwrap();
            expected_nonce += 1;
           
            // no change in balance
            let account_recipient_stackaroos_after = StacksChainState::get_account_ft(&mut conn, &contract_id, "stackaroos", &recv_principal).unwrap();
            assert_eq!(account_recipient_stackaroos_after, expected_stackaroos_balance);
            
            let account_pub_stackaroos_after = StacksChainState::get_account_ft(&mut conn, &contract_id, "stackaroos", &addr_principal).unwrap();
            assert_eq!(account_pub_stackaroos_after, expected_payback_stackaroos_balance);

            // new names the transaction tried to create don't exist -- transaction was aborted
            let expected_value = match tx_fail.payload {
                TransactionPayload::ContractCall(ref cc) => cc.function_args[0].clone(),
                _ => { panic!("Not a contract call") }
            };

            let res = StacksChainState::get_account_nft(&mut conn, &contract_id, "names", &expected_value);
            assert!(res.is_err());

            // but nonce _does_ change
            let account_publisher_after = StacksChainState::get_account(&mut conn, &addr_publisher.to_account_principal());
            assert_eq!(account_publisher_after.nonce, expected_nonce);
        }
        
        for (i, tx_fail) in post_conditions_fail_payback.iter().enumerate() {
            eprintln!("tx fail {:?}", &tx_fail);
            let (fee, _) = StacksChainState::process_transaction(&mut conn, &tx_fail).unwrap();
            expected_recv_nonce += 1;
           
            // no change in balance
            let account_recipient_stackaroos_after = StacksChainState::get_account_ft(&mut conn, &contract_id, "stackaroos", &recv_principal).unwrap();
            assert_eq!(account_recipient_stackaroos_after, expected_stackaroos_balance);
            
            let account_pub_stackaroos_after = StacksChainState::get_account_ft(&mut conn, &contract_id, "stackaroos", &addr_principal).unwrap();
            assert_eq!(account_pub_stackaroos_after, expected_payback_stackaroos_balance);
            
            // name we tried to send back is still owned by recv_addr
            let expected_value = match tx_fail.payload {
                TransactionPayload::ContractCall(ref cc) => cc.function_args[0].clone(),
                _ => { panic!("Not a contract call") }
            };

            // name remains owned by recv_addr
            let res = StacksChainState::get_account_nft(&mut conn, &contract_id, "names", &expected_value);
            assert!(res.is_ok());
            assert_eq!(res.unwrap(), recv_principal);

            // nonce for publisher doesn't change
            let account_publisher_after = StacksChainState::get_account(&mut conn, &addr_publisher.to_account_principal());
            assert_eq!(account_publisher_after.nonce, expected_nonce);
            
            // but nonce _does_ change for reciever, who sent back
            let account_publisher_after = StacksChainState::get_account(&mut conn, &recv_addr.to_account_principal());
            assert_eq!(account_publisher_after.nonce, expected_recv_nonce);
        }

        conn.commit_block();
    }

    // TODO: test post_conditions_check directly
    // TODO: test post_conditions that try to make statements about assets and principals that
    // don't exist or didn't move.
    // TODO: catch runtime exceptions and handle them properly (i.e. abort)
    // TODO: test common invalid-contract scenarios:
    // * duplicate contract
    // * invalid contract (doesn't check)
    // TODO: post-conditions on STX (blocked on stx-transfer!)
    // TODO: test poison microblock
}
