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

use std::convert::TryFrom;

use net::StacksMessageCodec;
use net::Error as net_error;
use net::codec::{read_next, write_next};

use burnchains::Txid;

use chainstate::stacks::*;

use core::*;

use net::StacksPublicKeyBuffer;

use util::hash::Sha512Trunc256Sum;

use util::secp256k1::MessageSignature;
use vm::{SymbolicExpression, SymbolicExpressionType, Value};
use vm::ast::build_ast;
use vm::types::{
    StandardPrincipalData,
    QualifiedContractIdentifier
};

use vm::representations::{
    ContractName,
    ClarityName
};

impl StacksMessageCodec for Value {
    fn serialize(&self) -> Vec<u8> {
        use vm::database::ClaritySerializable;
        let mut res = vec![];
        let value_str : String = ClaritySerializable::serialize(self);
        write_next(&mut res, &value_str.as_bytes().to_vec());
        res
    }

    fn deserialize(buf: &Vec<u8>, index_ptr: &mut u32, max_size: u32) -> Result<Value, net_error> {
        let mut index = *index_ptr;
        let bytes : Vec<u8> = read_next(buf, &mut index, max_size)?;
        let bytes_json = String::from_utf8(bytes[..].to_vec())
            .map_err(|_e| net_error::DeserializeError("Value byte sequence does not decode to utf8 string".to_string()))?;

        let value = Value::try_deserialize_untyped(&bytes_json)
            .map_err(|e| net_error::DeserializeError(format!("Failed to decode Value from '{}': {:?}", &bytes_json, &e)))?;
       
        *index_ptr = index;
        Ok(value)
    }
}

impl StacksMessageCodec for TransactionContractCall {
    fn serialize(&self) -> Vec<u8> {
        let mut res = vec![];
        write_next(&mut res, &self.address);
        write_next(&mut res, &self.contract_name);
        write_next(&mut res, &self.function_name);
        write_next(&mut res, &self.function_args);
        res
    }

    fn deserialize(buf: &Vec<u8>, index_ptr: &mut u32, max_size: u32) -> Result<TransactionContractCall, net_error> {
        let mut index = *index_ptr;
      
        let address : StacksAddress = read_next(buf, &mut index, max_size)?;
        let contract_name : ContractName = read_next(buf, &mut index, max_size)?;
        let function_name: ClarityName = read_next(buf, &mut index, max_size)?;
        let function_args: Vec<Value> = read_next(buf, &mut index, max_size)?;        // TODO: maximum number of arguments?

        // function name must be valid Clarity variable
        if !StacksString::from(function_name.clone()).is_clarity_variable() {
            warn!("Invalid function name -- not a clarity variable");
            return Err(net_error::DeserializeError("Failed to parse transaction: invalid function name -- not a Clarity variable".to_string()));
        }

        *index_ptr = index;
        Ok(TransactionContractCall {
            address,
            contract_name,
            function_name,
            function_args
        })
    }
}

impl TransactionContractCall {
    pub fn to_clarity_contract_id(&self) -> QualifiedContractIdentifier {
        QualifiedContractIdentifier::new(StandardPrincipalData::from(self.address.clone()), self.contract_name.clone())
    }
}

impl StacksMessageCodec for TransactionSmartContract {
    fn serialize(&self) -> Vec<u8> {
        let mut res = vec![];
        write_next(&mut res, &self.name);
        write_next(&mut res, &self.code_body);
        res
    }

    fn deserialize(buf: &Vec<u8>, index_ptr: &mut u32, max_size: u32) -> Result<TransactionSmartContract, net_error> {
        let mut index = *index_ptr;

        let name : ContractName = read_next(buf, &mut index, max_size)?;
        let code_body : StacksString = read_next(buf, &mut index, max_size)?;

        *index_ptr = index;

        Ok(TransactionSmartContract {
            name,
            code_body
        })
    }
}

impl StacksMessageCodec for TransactionPayload {
    fn serialize(&self) -> Vec<u8> {
        let mut res = vec![];
        match *self {
            TransactionPayload::TokenTransfer(ref address, ref amount, ref memo) => {
                write_next(&mut res, &(TransactionPayloadID::TokenTransfer as u8));
                write_next(&mut res, address);
                write_next(&mut res, amount);
                write_next(&mut res, memo);
            },
            TransactionPayload::ContractCall(ref cc) => {
                write_next(&mut res, &(TransactionPayloadID::ContractCall as u8));
                let mut body = cc.serialize();
                res.append(&mut body);
            },
            TransactionPayload::SmartContract(ref sc) => {
                write_next(&mut res, &(TransactionPayloadID::SmartContract as u8));
                let mut body = sc.serialize();
                res.append(&mut body)
            },
            TransactionPayload::PoisonMicroblock(ref h1, ref h2) => {
                write_next(&mut res, &(TransactionPayloadID::PoisonMicroblock as u8));
                let mut h1_body = h1.serialize();
                let mut h2_body = h2.serialize();
                res.append(&mut h1_body);
                res.append(&mut h2_body);
            },
            TransactionPayload::Coinbase(ref buf) => {
                write_next(&mut res, &(TransactionPayloadID::Coinbase as u8));
                write_next(&mut res, buf);
            }
        }
        res
    }
    
    fn deserialize(buf: &Vec<u8>, index_ptr: &mut u32, max_size: u32) -> Result<TransactionPayload, net_error> {
        let mut index = *index_ptr;

        let type_id : u8 = read_next(buf, &mut index, max_size)?;
        let payload = match type_id {
            x if x == TransactionPayloadID::TokenTransfer as u8 => {
                let addr : StacksAddress = read_next(buf, &mut index, max_size)?;
                let amount : u64 = read_next(buf, &mut index, max_size)?;
                let memo : TokenTransferMemo = read_next(buf, &mut index, max_size)?;
                TransactionPayload::TokenTransfer(addr, amount, memo)
            },
            x if x == TransactionPayloadID::ContractCall as u8 => {
                let payload = TransactionContractCall::deserialize(buf, &mut index, max_size)?;
                TransactionPayload::ContractCall(payload)
            }
            x if x == TransactionPayloadID::SmartContract as u8 => {
                let payload = TransactionSmartContract::deserialize(buf, &mut index, max_size)?;
                TransactionPayload::SmartContract(payload)
            }
            x if x == TransactionPayloadID::PoisonMicroblock as u8 => {
                let h1 = StacksMicroblockHeader::deserialize(buf, &mut index, max_size)?;
                let h2 = StacksMicroblockHeader::deserialize(buf, &mut index, max_size)?;

                // must differ in some field
                if h1 == h2 {
                    return Err(net_error::DeserializeError("Failed to parse transaction -- microblock headers match".to_string()));
                }

                // must have the same sequence number or same block parent
                if h1.sequence != h2.sequence && h1.prev_block != h2.prev_block {
                    return Err(net_error::DeserializeError("Failed to parse transaction -- microblock headers do not identify a fork".to_string()));
                }

                TransactionPayload::PoisonMicroblock(h1, h2)
            },
            x if x == TransactionPayloadID::Coinbase as u8 => {
                let payload : CoinbasePayload = CoinbasePayload::deserialize(buf, &mut index, max_size)?;
                TransactionPayload::Coinbase(payload)
            },
            _ => {
                return Err(net_error::DeserializeError(format!("Failed to parse transaction -- unknown payload ID {}", type_id)));
            }
        };

        *index_ptr = index;
        Ok(payload)
    }
}

impl TransactionPayload {
    pub fn new_contract_call(contract_address: StacksAddress, contract_name: &str, function_name: &str, args: Vec<Value>) -> Option<TransactionPayload> {
        let contract_name_str = match ContractName::try_from(contract_name.to_string()) {
            Ok(s) => s,
            Err(_) => {
                test_debug!("Not a clarity name: '{}'", contract_name);
                return None;
            }
        };

        let function_name_str = match ClarityName::try_from(function_name.to_string()) {
            Ok(s) => s,
            Err(_) => {
                test_debug!("Not a clarity name: '{}'", contract_name);
                return None;
            }
        };
        
        Some(TransactionPayload::ContractCall(TransactionContractCall {
            address: contract_address,
            contract_name: contract_name_str, 
            function_name: function_name_str,
            function_args: args
        }))
    }

    pub fn new_smart_contract(name: &String, contract: &String) -> Option<TransactionPayload> {
        match (ContractName::try_from((*name).clone()), StacksString::from_string(contract)) {
            (Ok(s_name), Some(s_body)) => Some(TransactionPayload::SmartContract(TransactionSmartContract { name: s_name, code_body: s_body })),
            (_, _) => None
        }
    }
}

impl StacksMessageCodec for AssetInfo {
    fn serialize(&self) -> Vec<u8> {
        let mut ret = vec![];
        write_next(&mut ret, &self.contract_address);
        write_next(&mut ret, &self.contract_name);
        write_next(&mut ret, &self.asset_name);
        ret
    }

    fn deserialize(buf: &Vec<u8>, index_ptr: &mut u32, max_size: u32) -> Result<AssetInfo, net_error> {
        let mut index = *index_ptr;

        let contract_address : StacksAddress = read_next(buf, &mut index, max_size)?;
        let contract_name : ContractName = read_next(buf, &mut index, max_size)?;
        let asset_name : ClarityName = read_next(buf, &mut index, max_size)?;
        
        *index_ptr = index;

        Ok(AssetInfo {
            contract_address,
            contract_name,
            asset_name
        })
    }
}

impl StacksMessageCodec for PostConditionPrincipal {
    fn serialize(&self) -> Vec<u8> {
        let mut res = vec![];
        match *self {
            PostConditionPrincipal::Origin => {
                write_next(&mut res, &(PostConditionPrincipalID::Origin as u8));
            },
            PostConditionPrincipal::Standard(ref address) => {
                write_next(&mut res, &(PostConditionPrincipalID::Standard as u8));
                write_next(&mut res, address);
            },
            PostConditionPrincipal::Contract(ref address, ref contract_name) => {
                write_next(&mut res, &(PostConditionPrincipalID::Contract as u8));
                write_next(&mut res, address);
                write_next(&mut res, contract_name);
            }
        }
        res
    }

    fn deserialize(buf: &Vec<u8>, index_ptr: &mut u32, max_size: u32) -> Result<PostConditionPrincipal, net_error> {
        let mut index = *index_ptr;
        let principal_id : u8 = read_next(buf, &mut index, max_size)?;
        let principal = match principal_id {
            x if x == PostConditionPrincipalID::Origin as u8 => {
                PostConditionPrincipal::Origin
            },
            x if x == PostConditionPrincipalID::Standard as u8 => {
                let addr : StacksAddress = read_next(buf, &mut index, max_size)?;
                PostConditionPrincipal::Standard(addr)
            },
            x if x == PostConditionPrincipalID::Contract as u8 => {
                let addr : StacksAddress = read_next(buf, &mut index, max_size)?;
                let contract_name : ContractName = read_next(buf, &mut index, max_size)?;
                PostConditionPrincipal::Contract(addr, contract_name)
            },
            _ => {
                return Err(net_error::DeserializeError(format!("Failed to parse transaction: unknown post condition principal ID {}", principal_id)));
            }
        };

        *index_ptr = index;
        Ok(principal)
    }
}

impl StacksMessageCodec for TransactionPostCondition {
    fn serialize(&self) -> Vec<u8> {
        let mut ret = vec![];
        match *self {
            TransactionPostCondition::STX(ref principal, ref fungible_condition, ref amount) => {
                write_next(&mut ret, &(AssetInfoID::STX as u8));
                write_next(&mut ret, principal);
                write_next(&mut ret, &(*fungible_condition as u8));
                write_next(&mut ret, amount);
            },
            TransactionPostCondition::Fungible(ref principal, ref asset_info, ref fungible_condition, ref amount) => {
                write_next(&mut ret, &(AssetInfoID::FungibleAsset as u8));
                write_next(&mut ret, principal);
                write_next(&mut ret, asset_info);
                write_next(&mut ret, &(*fungible_condition as u8));
                write_next(&mut ret, amount);
            }
            TransactionPostCondition::Nonfungible(ref principal, ref asset_info, ref asset_value, ref nonfungible_condition) => {
                write_next(&mut ret, &(AssetInfoID::NonfungibleAsset as u8));
                write_next(&mut ret, principal);
                write_next(&mut ret, asset_info);
                write_next(&mut ret, asset_value);
                write_next(&mut ret, &(*nonfungible_condition as u8));
            }
        };
        ret
    }

    fn deserialize(buf: &Vec<u8>, index_ptr: &mut u32, max_size: u32) -> Result<TransactionPostCondition, net_error> {
        let mut index = *index_ptr;
        let asset_info_id : u8 = read_next(buf, &mut index, max_size)?;
        let postcond = match asset_info_id {
            x if x == AssetInfoID::STX as u8 => {
                let principal : PostConditionPrincipal = read_next(buf, &mut index, max_size)?;
                let condition_u8 : u8 = read_next(buf, &mut index, max_size)?;
                let amount : u64 = read_next(buf, &mut index, max_size)?;

                let condition_code = FungibleConditionCode::from_u8(condition_u8)
                    .ok_or(net_error::DeserializeError(format!("Failed to parse transaction: Failed to parse STX fungible condition code {}", condition_u8)))?;

                TransactionPostCondition::STX(principal, condition_code, amount)
            },
            x if x == AssetInfoID::FungibleAsset as u8 => {
                let principal : PostConditionPrincipal = read_next(buf, &mut index, max_size)?;
                let asset : AssetInfo = read_next(buf, &mut index, max_size)?;
                let condition_u8 : u8 = read_next(buf, &mut index, max_size)?;
                let amount : u64 = read_next(buf, &mut index, max_size)?;

                let condition_code = FungibleConditionCode::from_u8(condition_u8)
                    .ok_or(net_error::DeserializeError(format!("Failed to parse transaction: Failed to parse FungibleAsset condition code {}", condition_u8)))?;

                TransactionPostCondition::Fungible(principal, asset, condition_code, amount)
            },
            x if x == AssetInfoID::NonfungibleAsset as u8 => {
                let principal : PostConditionPrincipal = read_next(buf, &mut index, max_size)?;
                let asset : AssetInfo = read_next(buf, &mut index, max_size)?;
                let asset_value : Value = read_next(buf, &mut index, max_size)?;
                let condition_u8 : u8 = read_next(buf, &mut index, max_size)?;

                let condition_code = NonfungibleConditionCode::from_u8(condition_u8)
                    .ok_or(net_error::DeserializeError(format!("Failed to parse transaction: Failed to parse NonfungibleAsset condition code {}", condition_u8)))?;

                TransactionPostCondition::Nonfungible(principal, asset, asset_value, condition_code)
            },
            _ => {
                return Err(net_error::DeserializeError(format!("Failed to aprse transaction: unknown asset info ID {}", asset_info_id)));
            }
        };
        
        *index_ptr = index;
        Ok(postcond)
    }
}

impl StacksMessageCodec for StacksTransaction {
    fn serialize(&self) -> Vec<u8> {
        let mut ret = vec![];

        write_next(&mut ret, &(self.version as u8));
        write_next(&mut ret, &self.chain_id);
        write_next(&mut ret, &self.auth);
        write_next(&mut ret, &(self.anchor_mode as u8));
        write_next(&mut ret, &(self.post_condition_mode as u8));
        write_next(&mut ret, &self.post_conditions);
        write_next(&mut ret, &self.payload);
        
        ret
    }

    fn deserialize(buf: &Vec<u8>, index_ptr: &mut u32, max_size: u32) -> Result<StacksTransaction, net_error> {
        let mut index = *index_ptr;

        let version_u8 : u8             = read_next(buf, &mut index, max_size)?;
        let chain_id : u32              = read_next(buf, &mut index, max_size)?;
        let auth : TransactionAuth      = read_next(buf, &mut index, max_size)?;
        let anchor_mode_u8 : u8         = read_next(buf, &mut index, max_size)?;
        let post_condition_mode_u8 : u8 = read_next(buf, &mut index, max_size)?;
        let post_conditions : Vec<TransactionPostCondition> = read_next(buf, &mut index, max_size)?;
        let payload : TransactionPayload = read_next(buf, &mut index, max_size)?;

        let version = 
            if (version_u8 & 0x80) == 0 {
                TransactionVersion::Mainnet
            }
            else {
                TransactionVersion::Testnet
            };

        let anchor_mode = match anchor_mode_u8 {
            x if x == TransactionAnchorMode::OffChainOnly as u8 => {
                TransactionAnchorMode::OffChainOnly
            },
            x if x == TransactionAnchorMode::OnChainOnly as u8 => {
                TransactionAnchorMode::OnChainOnly
            },
            x if x == TransactionAnchorMode::Any as u8 => {
                TransactionAnchorMode::Any
            },
            _ => {
                warn!("Invalid tx: invalid anchor mode");
                return Err(net_error::DeserializeError(format!("Failed to parse transaction: invalid anchor mode {}", anchor_mode_u8)));
            }
        };

        // if the payload is a proof of a poisoned microblock stream, or is a coinbase, then this _must_ be anchored.
        // Otherwise, if the offending leader is the next leader, they can just orphan their proof
        // of malfeasance.
        match payload {
            TransactionPayload::PoisonMicroblock(_, _) => {
                if anchor_mode != TransactionAnchorMode::OnChainOnly {
                    warn!("Invalid tx: invalid anchor mode for poison microblock");
                    return Err(net_error::DeserializeError("Failed to parse transaction: invalid anchor mode for PoisonMicroblock".to_string()));
                }
            },
            TransactionPayload::Coinbase(_) => {
                if anchor_mode != TransactionAnchorMode::OnChainOnly {
                    warn!("Invalid tx: invalid anchor mode for coinbase");
                    return Err(net_error::DeserializeError("Failed to parse transaction: invalid anchor mode for Coinbase".to_string()));
                }
            },
            _ => {}
        }

        let post_condition_mode = match post_condition_mode_u8 {
            x if x == TransactionPostConditionMode::Allow as u8 => {
                TransactionPostConditionMode::Allow
            },
            x if x == TransactionPostConditionMode::Deny as u8 => {
                TransactionPostConditionMode::Deny
            },
            _ => {
                warn!("Invalid tx: invalid post condition mode");
                return Err(net_error::DeserializeError(format!("Failed to parse transaction: invalid post-condition mode {}", post_condition_mode_u8)));
            }
        };

        *index_ptr = index;
        let ret = StacksTransaction {
            version,
            chain_id,
            auth,
            anchor_mode,
            post_condition_mode,
            post_conditions,
            payload
        };

        Ok(ret)
    }
}

impl StacksTransaction {
    /// Create a new, unsigned transaction and an empty STX fee with no post-conditions.
    pub fn new(version: TransactionVersion, auth: TransactionAuth, payload: TransactionPayload) -> StacksTransaction {
        let anchor_mode = match payload {
            TransactionPayload::Coinbase(_) => TransactionAnchorMode::OnChainOnly,
            TransactionPayload::PoisonMicroblock(_, _) => TransactionAnchorMode::OnChainOnly,
            _ => TransactionAnchorMode::Any
        };

        StacksTransaction {
            version: version,
            chain_id: 0,
            auth: auth,
            anchor_mode: anchor_mode,
            post_condition_mode: TransactionPostConditionMode::Deny,
            post_conditions: vec![],
            payload: payload
        }
    }

    /// Get fee rate
    pub fn get_fee_rate(&self) -> u64 {
        self.auth.get_fee_rate()
    }

    /// Set fee rate
    pub fn set_fee_rate(&mut self, fee_rate: u64) -> () {
        self.auth.set_fee_rate(fee_rate);
    }

    /// Get origin nonce
    pub fn get_origin_nonce(&self) -> u64 {
        self.auth.get_origin_nonce()
    }

    /// get sponsor nonce
    pub fn get_sponsor_nonce(&self) -> Option<u64> {
        self.auth.get_sponsor_nonce()
    }

    /// set origin nonce
    pub fn set_origin_nonce(&mut self, n: u64) -> () {
        self.auth.set_origin_nonce(n);
    }

    /// set sponsor nonce
    pub fn set_sponsor_nonce(&mut self, n: u64) -> Result<(), Error> {
        self.auth.set_sponsor_nonce(n)
    }
    
    /// Set anchor mode
    pub fn set_anchor_mode(&mut self, anchor_mode: TransactionAnchorMode) -> () {
        self.anchor_mode = anchor_mode;
    }

    /// Set post-condition mode 
    pub fn set_post_condition_mode(&mut self, postcond_mode: TransactionPostConditionMode) -> () {
        self.post_condition_mode = postcond_mode;
    }

    /// Add a post-condition
    pub fn add_post_condition(&mut self, post_condition: TransactionPostCondition) -> () {
        self.post_conditions.push(post_condition);
    }

    /// a txid of a stacks transaction is its sha512/256 hash
    pub fn txid(&self) -> Txid {
        Txid::from_stacks_tx(&self.serialize()[..])
    }
    
    /// Get a mutable reference to the internal auth structure
    pub fn borrow_auth(&mut self) -> &mut TransactionAuth {
        &mut self.auth
    }

    /// Get an immutable reference to the internal auth structure
    pub fn auth(&self) -> &TransactionAuth {
        &self.auth
    }

    /// begin signing the transaction.
    /// If this is a sponsored transaction, then the origin only commits to knowing that it is
    /// sponsored.  It does _not_ commit to the sponsored fields, so set them all to sentinel
    /// values.
    /// Return the initial sighash.
    fn sign_begin(&self) -> Txid {
        let mut tx = self.clone();
        tx.auth = tx.auth.into_initial_sighash_auth();
        tx.txid()
    }

    /// begin verifying a transaction.
    /// return the initial sighash
    fn verify_begin(&self) -> Txid {
        let mut tx = self.clone();
        tx.auth = tx.auth.into_initial_sighash_auth();
        tx.txid()
    }

    /// Sign a sighash and append the signature and public key to the given spending condition.
    /// Returns the next sighash
    fn sign_and_append(condition: &mut TransactionSpendingCondition, cur_sighash: &Txid, auth_flag: &TransactionAuthFlags, privk: &StacksPrivateKey) -> Result<Txid, net_error> {
        let (next_sig, next_sighash) = TransactionSpendingCondition::next_signature(cur_sighash, auth_flag, condition.fee_rate(), condition.nonce(), privk)?;
        match condition {
            TransactionSpendingCondition::Multisig(ref mut cond) => {
                cond.push_signature(if privk.compress_public() { TransactionPublicKeyEncoding::Compressed } else { TransactionPublicKeyEncoding::Uncompressed }, next_sig);
                Ok(next_sighash)
            },
            TransactionSpendingCondition::Singlesig(ref mut cond) => {
                cond.set_signature(next_sig);
                Ok(next_sighash)
            }
        }
    }

    /// Pop the last auth field
    fn pop_auth_field(condition: &mut TransactionSpendingCondition) -> Option<TransactionAuthField> {
        match condition {
            TransactionSpendingCondition::Multisig(ref mut cond) => {
                cond.pop_auth_field()
            },
            TransactionSpendingCondition::Singlesig(ref mut cond) => {
                cond.pop_signature()
            }
        }
    }
    
    /// Append a public key to a multisig condition
    fn append_pubkey(condition: &mut TransactionSpendingCondition, pubkey: &StacksPublicKey) -> Result<(), net_error> {
        match condition {
            TransactionSpendingCondition::Multisig(ref mut cond) => {
                cond.push_public_key(pubkey.clone());
                Ok(())
            },
            _ => {
                Err(net_error::SigningError("Not a multisig condition".to_string()))
            }
        }
    }

    /// Append the next signature from the origin account authorization.
    /// Return the next sighash.
    pub fn sign_next_origin(&mut self, cur_sighash: &Txid, privk: &StacksPrivateKey) -> Result<Txid, net_error> {
        let next_sighash = match self.auth {
            TransactionAuth::Standard(ref mut origin_condition) => {
                StacksTransaction::sign_and_append(origin_condition, cur_sighash, &TransactionAuthFlags::AuthStandard, privk)?
            },
            TransactionAuth::Sponsored(ref mut origin_condition, _) => {
                StacksTransaction::sign_and_append(origin_condition, cur_sighash, &TransactionAuthFlags::AuthStandard, privk)?
            }
        };
        Ok(next_sighash)
    }

    /// Append the next public key to the origin account authorization.
    pub fn append_next_origin(&mut self, pubk: &StacksPublicKey) -> Result<(), net_error> {
        match self.auth {
            TransactionAuth::Standard(ref mut origin_condition) => {
                StacksTransaction::append_pubkey(origin_condition, pubk)
            },
            TransactionAuth::Sponsored(ref mut origin_condition, _) => {
                StacksTransaction::append_pubkey(origin_condition, pubk)
            }
        }
    }

    /// Append the next signature from the sponsoring account.
    /// Return the next sighash
    pub fn sign_next_sponsor(&mut self, cur_sighash: &Txid, privk: &StacksPrivateKey) -> Result<Txid, net_error> {
        let next_sighash = match self.auth {
            TransactionAuth::Standard(_) => {
                // invalid
                return Err(net_error::SigningError("Cannot sign standard authorization with a sponsoring private key".to_string()));
            }
            TransactionAuth::Sponsored(_, ref mut sponsor_condition) => {
                StacksTransaction::sign_and_append(sponsor_condition, cur_sighash, &TransactionAuthFlags::AuthSponsored, privk)?
            }
        };
        Ok(next_sighash)
    }
    
    /// Append the next public key to the sponsor account authorization.
    pub fn append_next_sponsor(&mut self, pubk: &StacksPublicKey) -> Result<(), net_error> {
        match self.auth {
            TransactionAuth::Standard(_) => {
                Err(net_error::SigningError("Cannot appned a public key to the sponsor of a standard auth condition".to_string()))
            },
            TransactionAuth::Sponsored(_, ref mut sponsor_condition) => {
                StacksTransaction::append_pubkey(sponsor_condition, pubk)
            }
        }
    }

    /// Verify this transaction's signatures
    pub fn verify(&self) -> Result<bool, net_error> {
        self.auth.verify(&self.verify_begin())
    }

    /// Verify the transaction's origin signatures only.
    /// Used by sponsors to get the next sig-hash to sign.
    pub fn verify_origin(&self) -> Result<Txid, net_error> {
        self.auth.verify_origin(&self.verify_begin())
    }

    /// Get the origin account's address
    pub fn origin_address(&self) -> StacksAddress {
        match (&self.version, &self.auth) {
            (&TransactionVersion::Mainnet, &TransactionAuth::Standard(ref origin_condition)) => origin_condition.address_mainnet(),
            (&TransactionVersion::Testnet, &TransactionAuth::Standard(ref origin_condition)) => origin_condition.address_testnet(),
            (&TransactionVersion::Mainnet, &TransactionAuth::Sponsored(ref origin_condition, ref _unused)) => origin_condition.address_mainnet(),
            (&TransactionVersion::Testnet, &TransactionAuth::Sponsored(ref origin_condition, ref _unused)) => origin_condition.address_testnet()
        }
    }

    /// Get the sponsor account's address, if this transaction is sponsored
    pub fn sponsor_address(&self) -> Option<StacksAddress> {
        match (&self.version, &self.auth) {
            (&TransactionVersion::Mainnet, &TransactionAuth::Standard(ref _unused)) => None,
            (&TransactionVersion::Testnet, &TransactionAuth::Standard(ref _unused)) => None,
            (&TransactionVersion::Mainnet, &TransactionAuth::Sponsored(ref _unused, ref sponsor_condition)) => Some(sponsor_condition.address_mainnet()),
            (&TransactionVersion::Testnet, &TransactionAuth::Sponsored(ref _unused, ref sponsor_condition)) => Some(sponsor_condition.address_testnet())
        }
    }

    /// Get a copy of the origin spending condition
    pub fn get_origin(&self) -> TransactionSpendingCondition {
        self.auth.origin().clone()
    }

    /// Get a copy of the sending condition that will pay the tx fee
    pub fn get_payer(&self) -> TransactionSpendingCondition {
        match self.auth.sponsor() {
            Some(ref tsc) => (*tsc).clone(),
            None => self.auth.origin().clone()
        }
    }

    /// Is this a mainnet transaction?  false means 'testnet'
    pub fn is_mainnet(&self) -> bool {
        match self.version {
            TransactionVersion::Mainnet => true,
            _ => false
        }
    }
}

impl StacksTransactionSigner {
    pub fn new(tx: &StacksTransaction) -> StacksTransactionSigner {
        StacksTransactionSigner {
            tx: tx.clone(),
            sighash: tx.sign_begin(),
            origin_done: false,
            check_oversign: true, 
            check_overlap: true
        }
    }

    pub fn new_sponsor(tx: &StacksTransaction, spending_condition: TransactionSpendingCondition) -> Result<StacksTransactionSigner, Error> {
        if !tx.auth.is_sponsored() {
            return Err(Error::IncompatibleSpendingConditionError);
        }
        let mut new_tx = tx.clone();
        new_tx.auth.set_sponsor(spending_condition)?;
        let origin_sighash = new_tx.verify_origin()
            .map_err(Error::NetError)?;

        Ok(StacksTransactionSigner {
            tx: new_tx,
            sighash: origin_sighash,
            origin_done: true,
            check_oversign: true,
            check_overlap: true
        })
    }

    pub fn resume(&mut self, tx: &StacksTransaction) -> () {
        self.tx = tx.clone()
    }

    pub fn disable_checks(&mut self) -> () {
        self.check_oversign = false;
        self.check_overlap = false;
    }

    pub fn sign_origin(&mut self, privk: &StacksPrivateKey) -> Result<(), net_error> {
        if self.check_overlap && self.origin_done {
            // can't sign another origin private key since we started signing sponsors
            return Err(net_error::SigningError("Cannot sign origin after sponsor key".to_string()));
        }

        match self.tx.auth {
            TransactionAuth::Standard(ref origin_condition) => {
                if self.check_oversign && origin_condition.num_signatures() >= origin_condition.signatures_required() {
                    return Err(net_error::SigningError("Origin would have too many signatures".to_string()));
                }
            },
            TransactionAuth::Sponsored(ref origin_condition, _) => {
                if self.check_oversign && origin_condition.num_signatures() >= origin_condition.signatures_required() {
                    return Err(net_error::SigningError("Origin would have too many signatures".to_string()));
                }
            }
        }

        let next_sighash = self.tx.sign_next_origin(&self.sighash, privk)?;
        self.sighash = next_sighash;
        Ok(())
    }

    pub fn append_origin(&mut self, pubk: &StacksPublicKey) -> Result<(), net_error> {
        if self.check_overlap && self.origin_done {
            // can't append another origin key
            return Err(net_error::SigningError("Cannot append public key to origin after sponsor key".to_string()));
        }

        self.tx.append_next_origin(pubk)
    }
    
    pub fn sign_sponsor(&mut self, privk: &StacksPrivateKey) -> Result<(), net_error> {
        match self.tx.auth {
            TransactionAuth::Sponsored(_, ref sponsor_condition) => {
                if self.check_oversign && sponsor_condition.num_signatures() >= sponsor_condition.signatures_required() {
                    return Err(net_error::SigningError("Sponsor would have too many signatures".to_string()));
                }
            },
            _ => {}
        }

        let next_sighash = self.tx.sign_next_sponsor(&self.sighash, privk)?;
        self.sighash = next_sighash;
        self.origin_done = true;
        Ok(())
    }

    pub fn append_sponsor(&mut self, pubk: &StacksPublicKey) -> Result<(), net_error> {
        self.tx.append_next_sponsor(pubk)
    }

    pub fn pop_origin_auth_field(&mut self) -> Option<TransactionAuthField> {
        match self.tx.auth {
            TransactionAuth::Standard(ref mut origin_condition) => StacksTransaction::pop_auth_field(origin_condition),
            TransactionAuth::Sponsored(ref mut origin_condition, _) => StacksTransaction::pop_auth_field(origin_condition)
        }
    }

    pub fn pop_sponsor_auth_field(&mut self) -> Option<TransactionAuthField> {
        match self.tx.auth {
            TransactionAuth::Sponsored(_, ref mut sponsor_condition) => StacksTransaction::pop_auth_field(sponsor_condition),
            _ => None
        }
    }

    pub fn complete(&self) -> bool {
        match self.tx.auth {
            TransactionAuth::Standard(ref origin_condition) => {
                origin_condition.num_signatures() >= origin_condition.signatures_required()
            },
            TransactionAuth::Sponsored(ref origin_condition, ref sponsored_condition) => {
                origin_condition.num_signatures() >= origin_condition.signatures_required() &&
                sponsored_condition.num_signatures() >= sponsored_condition.signatures_required() &&
                (self.origin_done || !self.check_overlap)
            }
        }
    }

    pub fn get_tx_incomplete(&self) -> StacksTransaction {
        self.tx.clone()
    }

    pub fn get_tx(&self) -> Option<StacksTransaction> {
        if self.complete() {
            Some(self.tx.clone())
        }
        else {
            None
        }
    }

    pub fn get_incomplete_tx(&self) -> StacksTransaction {
        self.tx.clone()
    }
}


#[cfg(test)]
mod test {
    // TODO: test with invalid StacksStrings
    // TODO: test with different tx versions 
    // TODO: test error values for signing and verifying
    use super::*;
    use chainstate::stacks::*;
    use net::*;
    use net::codec::*;
    use net::codec::test::check_codec_and_corruption;
    use chainstate::stacks::test::codec_all_transactions;

    use chainstate::stacks::StacksPublicKey as PubKey;

    use util::log;
    use util::hash::*;

    use vm::representations::{ClarityName, ContractName};

    fn corrupt_auth_field(corrupt_auth_fields: &TransactionAuth, i: usize, corrupt_origin: bool, corrupt_sponsor: bool) -> TransactionAuth {
        let mut new_corrupt_auth_fields = corrupt_auth_fields.clone();
        match new_corrupt_auth_fields {
            TransactionAuth::Standard(ref mut origin_condition) => {
                if corrupt_origin {
                    match origin_condition {
                        TransactionSpendingCondition::Singlesig(ref mut data) => {
                            let mut sig_bytes = data.signature.as_bytes().to_vec();
                            sig_bytes[1] ^= 1u8;        // this breaks the `r` parameter
                            data.signature = MessageSignature::from_raw(&sig_bytes);
                        },
                        TransactionSpendingCondition::Multisig(ref mut data) => {
                            let corrupt_field = match data.fields[i] {
                                TransactionAuthField::PublicKey(ref pubkey) => {
                                    TransactionAuthField::PublicKey(StacksPublicKey::from_hex("0270790e675116a63a75008832d82ad93e4332882ab0797b0f156de9d739160a0b").unwrap())
                                },
                                TransactionAuthField::Signature(ref key_encoding, ref sig) => {
                                    let mut sig_bytes = sig.as_bytes().to_vec();
                                    sig_bytes[1] ^= 1u8;    // this breaks the `r` paramter
                                    let corrupt_sig = MessageSignature::from_raw(&sig_bytes);
                                    TransactionAuthField::Signature(*key_encoding, corrupt_sig)
                                }
                            };
                            data.fields[i] = corrupt_field
                        }
                    }
                }
            },
            TransactionAuth::Sponsored(ref mut origin_condition, ref mut sponsor_condition) => {
                if corrupt_origin {
                    match origin_condition {
                        TransactionSpendingCondition::Singlesig(ref mut data) => {
                            let mut sig_bytes = data.signature.as_bytes().to_vec();
                            sig_bytes[1] ^= 1u8;        // this breaks the `r` parameter
                            data.signature = MessageSignature::from_raw(&sig_bytes);
                        },
                        TransactionSpendingCondition::Multisig(ref mut data) => {
                            let corrupt_field = match data.fields[i] {
                                TransactionAuthField::PublicKey(ref pubkey) => {
                                    TransactionAuthField::PublicKey(StacksPublicKey::from_hex("0270790e675116a63a75008832d82ad93e4332882ab0797b0f156de9d739160a0b").unwrap())
                                },
                                TransactionAuthField::Signature(ref key_encoding, ref sig) => {
                                    let mut sig_bytes = sig.as_bytes().to_vec();
                                    sig_bytes[1] ^= 1u8;    // this breaks the `r` paramter
                                    let corrupt_sig = MessageSignature::from_raw(&sig_bytes);
                                    TransactionAuthField::Signature(*key_encoding, corrupt_sig)
                                }
                            };
                            data.fields[i] = corrupt_field
                        }
                    }
                }
                if corrupt_sponsor {
                    match sponsor_condition {
                        TransactionSpendingCondition::Singlesig(ref mut data) => {
                            let mut sig_bytes = data.signature.as_bytes().to_vec();
                            sig_bytes[1] ^= 1u8;    // this breaks the `r` parameter
                            data.signature = MessageSignature::from_raw(&sig_bytes);
                        },
                        TransactionSpendingCondition::Multisig(ref mut data) => {
                            let corrupt_field = match data.fields[i] {
                                TransactionAuthField::PublicKey(ref pubkey) => {
                                    TransactionAuthField::PublicKey(StacksPublicKey::from_hex("0270790e675116a63a75008832d82ad93e4332882ab0797b0f156de9d739160a0b").unwrap())
                                },
                                TransactionAuthField::Signature(ref key_encoding, ref sig) => {
                                    let mut sig_bytes = sig.as_bytes().to_vec();
                                    sig_bytes[1] ^= 1u8;    // this breaks the `r` paramter
                                    let corrupt_sig = MessageSignature::from_raw(&sig_bytes);
                                    TransactionAuthField::Signature(*key_encoding, corrupt_sig)
                                }
                            };
                            data.fields[i] = corrupt_field
                        }
                    }
                }
            }
        };
        new_corrupt_auth_fields
    }

    fn find_signature(spend: &TransactionSpendingCondition) -> usize {
        match spend {
            TransactionSpendingCondition::Singlesig(_) => 0,
            TransactionSpendingCondition::Multisig(ref data) => {
                let mut j = 0;
                for f in 0..data.fields.len() {
                    match data.fields[f] {
                        TransactionAuthField::Signature(_, _) => {
                            j = f;
                            break;
                        },
                        _ => {
                            continue;
                        }
                    }
                }
                j
            }
        }
    }
    
    fn find_public_key(spend: &TransactionSpendingCondition) -> usize {
        match spend {
            TransactionSpendingCondition::Singlesig(_) => 0,
            TransactionSpendingCondition::Multisig(ref data) => {
                let mut j = 0;
                for f in 0..data.fields.len() {
                    match data.fields[f] {
                        TransactionAuthField::PublicKey(_) => {
                            j = f;
                            break;
                        },
                        _ => {
                            continue;
                        }
                    }
                }
                j
            }
        }
    }

    fn corrupt_auth_field_signature(corrupt_auth_fields: &TransactionAuth, corrupt_origin: bool, corrupt_sponsor: bool) -> TransactionAuth {
        let i = match corrupt_auth_fields {
            TransactionAuth::Standard(ref spend) => {
                if corrupt_origin {
                    find_signature(spend)
                }
                else {
                    0
                }
            },
            TransactionAuth::Sponsored(ref origin_spend, ref sponsor_spend) => {
                if corrupt_sponsor {
                    find_signature(sponsor_spend)
                }
                else if corrupt_origin {
                    find_signature(origin_spend)
                }
                else {
                    0
                }
            }
        };
        corrupt_auth_field(corrupt_auth_fields, i, corrupt_origin, corrupt_sponsor)
    }

    fn corrupt_auth_field_public_key(corrupt_auth_fields: &TransactionAuth, corrupt_origin: bool, corrupt_sponsor: bool) -> TransactionAuth {
        let i = match corrupt_auth_fields {
            TransactionAuth::Standard(ref spend) => {
                if corrupt_origin {
                    find_public_key(spend)
                }
                else {
                    0
                }
            },
            TransactionAuth::Sponsored(ref origin_spend, ref sponsor_spend) => {
                if corrupt_sponsor {
                    find_public_key(sponsor_spend)
                }
                else if corrupt_origin {
                    find_public_key(origin_spend)
                }
                else {
                    0
                }
            }
        };
        corrupt_auth_field(corrupt_auth_fields, i, corrupt_origin, corrupt_sponsor)
    }

    // verify that we can verify signatures over a transaction.
    // also verify that we can corrupt any field and fail to verify the transaction.
    // corruption tests should obviously fail -- the initial sighash changes if any of the
    // serialized data changes.
    fn test_signature_and_corruption(signed_tx: &StacksTransaction, corrupt_origin: bool, corrupt_sponsor: bool) -> () {
        // signature is well-formed otherwise
        assert!(signed_tx.verify().unwrap());

        // mess with the auth hash code
        let mut corrupt_tx_hash_mode = signed_tx.clone();
        let mut corrupt_auth_hash_mode = corrupt_tx_hash_mode.auth().clone();
        match corrupt_auth_hash_mode {
            TransactionAuth::Standard(ref mut origin_condition) => {
                if corrupt_origin {
                    match origin_condition {
                        TransactionSpendingCondition::Singlesig(ref mut data) => {
                            data.hash_mode = 
                                if data.hash_mode == SinglesigHashMode::P2PKH {
                                    SinglesigHashMode::P2WPKH
                                }
                                else {
                                    SinglesigHashMode::P2PKH
                                };
                        },
                        TransactionSpendingCondition::Multisig(ref mut data) => {
                            data.hash_mode = 
                                if data.hash_mode == MultisigHashMode::P2SH {
                                    MultisigHashMode::P2WSH
                                }
                                else {
                                    MultisigHashMode::P2SH
                                };
                        }
                    }
                }
            },
            TransactionAuth::Sponsored(ref mut origin_condition, ref mut sponsored_condition) => {
                if corrupt_origin {
                    match origin_condition {
                        TransactionSpendingCondition::Singlesig(ref mut data) => {
                            data.hash_mode = 
                                if data.hash_mode == SinglesigHashMode::P2PKH {
                                    SinglesigHashMode::P2WPKH
                                }
                                else {
                                    SinglesigHashMode::P2PKH
                                };
                        },
                        TransactionSpendingCondition::Multisig(ref mut data) => {
                            data.hash_mode = 
                                if data.hash_mode == MultisigHashMode::P2SH {
                                    MultisigHashMode::P2WSH
                                }
                                else {
                                    MultisigHashMode::P2SH
                                };
                        }
                    }
                }
                if corrupt_sponsor {
                    match sponsored_condition {
                        TransactionSpendingCondition::Singlesig(ref mut data) => {
                            data.hash_mode = 
                                if data.hash_mode == SinglesigHashMode::P2PKH {
                                    SinglesigHashMode::P2WPKH
                                }
                                else {
                                    SinglesigHashMode::P2PKH
                                };
                        },
                        TransactionSpendingCondition::Multisig(ref mut data) => {
                            data.hash_mode = 
                                if data.hash_mode == MultisigHashMode::P2SH {
                                    MultisigHashMode::P2WSH
                                }
                                else {
                                    MultisigHashMode::P2SH
                                };
                        }
                    }
                }
            }
        };
        corrupt_tx_hash_mode.auth = corrupt_auth_hash_mode;
        assert!(corrupt_tx_hash_mode.txid() != signed_tx.txid());

        // mess with the auth nonce
        let mut corrupt_tx_nonce = signed_tx.clone();
        let mut corrupt_auth_nonce = corrupt_tx_nonce.auth().clone();
        match corrupt_auth_nonce {
            TransactionAuth::Standard(ref mut origin_condition) => {
                if corrupt_origin {
                    match origin_condition {
                        TransactionSpendingCondition::Singlesig(ref mut data) => {
                            data.nonce += 1;
                        },
                        TransactionSpendingCondition::Multisig(ref mut data) => {
                            data.nonce += 1;
                        }
                    };
                }
            },
            TransactionAuth::Sponsored(ref mut origin_condition, ref mut sponsored_condition) => {
                if corrupt_origin {
                    match origin_condition {
                        TransactionSpendingCondition::Singlesig(ref mut data) => {
                            data.nonce += 1;
                        },
                        TransactionSpendingCondition::Multisig(ref mut data) => {
                            data.nonce += 1;
                        }
                    }
                }
                if corrupt_sponsor {
                    match sponsored_condition {
                        TransactionSpendingCondition::Singlesig(ref mut data) => {
                            data.nonce += 1;
                        },
                        TransactionSpendingCondition::Multisig(ref mut data) => {
                            data.nonce += 1;
                        }
                    }
                }
            }
        };
        corrupt_tx_nonce.auth = corrupt_auth_nonce;
        assert!(corrupt_tx_nonce.txid() != signed_tx.txid());
       
        // corrupt a signature
        let mut corrupt_tx_signature = signed_tx.clone();
        let corrupt_auth_signature = corrupt_tx_signature.auth.clone();
        corrupt_tx_signature.auth = corrupt_auth_field_signature(&corrupt_auth_signature, corrupt_origin, corrupt_sponsor);
        
        assert!(corrupt_tx_signature.txid() != signed_tx.txid());

        // corrupt a public key
        let mut corrupt_tx_public_key = signed_tx.clone();
        let corrupt_auth_public_key = corrupt_tx_public_key.auth.clone();
        corrupt_tx_public_key.auth = corrupt_auth_field_public_key(&corrupt_auth_public_key, corrupt_origin, corrupt_sponsor);

        assert!(corrupt_tx_public_key.txid() != signed_tx.txid());

        // mess with the auth num-signatures required, if applicable
        let mut corrupt_tx_signatures_required = signed_tx.clone();
        let mut corrupt_auth_signatures_required = corrupt_tx_signatures_required.auth().clone();
        let mut is_multisig_origin = false;
        let mut is_multisig_sponsor = false;
        match corrupt_auth_signatures_required {
            TransactionAuth::Standard(ref mut origin_condition) => {
                if corrupt_origin {
                    match origin_condition {
                        TransactionSpendingCondition::Singlesig(ref mut data) => {},
                        TransactionSpendingCondition::Multisig(ref mut data) => {
                            is_multisig_origin = true;
                            data.signatures_required += 1;
                        }
                    };
                }
            },
            TransactionAuth::Sponsored(ref mut origin_condition, ref mut sponsored_condition) => {
                if corrupt_origin {
                    match origin_condition {
                        TransactionSpendingCondition::Singlesig(ref mut data) => {},
                        TransactionSpendingCondition::Multisig(ref mut data) => {
                            is_multisig_origin = true;
                            data.signatures_required += 1;
                        }
                    }
                }
                if corrupt_sponsor {
                    match sponsored_condition {
                        TransactionSpendingCondition::Singlesig(ref mut data) => {},
                        TransactionSpendingCondition::Multisig(ref mut data) => {
                            is_multisig_sponsor = true;
                            data.signatures_required += 1;
                        }
                    }
                }
            }
        };
        corrupt_tx_signatures_required.auth = corrupt_auth_signatures_required;
        if is_multisig_origin || is_multisig_sponsor { 
            assert!(corrupt_tx_signatures_required.txid() != signed_tx.txid());
        }
        
        // mess with transaction version 
        let mut corrupt_tx_version = signed_tx.clone();
        corrupt_tx_version.version = 
            if corrupt_tx_version.version == TransactionVersion::Mainnet {
                TransactionVersion::Testnet
            }
            else {
                TransactionVersion::Mainnet
            };

        assert!(corrupt_tx_version.txid() != signed_tx.txid());
        
        // mess with chain ID
        let mut corrupt_tx_chain_id = signed_tx.clone();
        corrupt_tx_chain_id.chain_id = signed_tx.chain_id + 1;
        assert!(corrupt_tx_chain_id.txid() != signed_tx.txid());

        // mess with transaction fee 
        let mut corrupt_tx_fee = signed_tx.clone();
        corrupt_tx_fee.set_fee_rate(corrupt_tx_fee.get_fee_rate() + 1);
        assert!(corrupt_tx_fee.txid() != signed_tx.txid());

        // mess with anchor mode
        let mut corrupt_tx_anchor_mode = signed_tx.clone();
        corrupt_tx_anchor_mode.anchor_mode = 
            if corrupt_tx_anchor_mode.anchor_mode == TransactionAnchorMode::OffChainOnly {
                TransactionAnchorMode::OnChainOnly
            }
            else if corrupt_tx_anchor_mode.anchor_mode == TransactionAnchorMode::OnChainOnly {
                TransactionAnchorMode::Any
            }
            else {
                TransactionAnchorMode::OffChainOnly
            };

        assert!(corrupt_tx_anchor_mode.txid() != signed_tx.txid());

        // mess with post conditions
        let mut corrupt_tx_post_conditions = signed_tx.clone();
        corrupt_tx_post_conditions.post_conditions.push(TransactionPostCondition::STX(PostConditionPrincipal::Origin, FungibleConditionCode::SentGt, 0));

        let mut corrupt_tx_post_condition_mode = signed_tx.clone();
        corrupt_tx_post_condition_mode.post_condition_mode =
            if corrupt_tx_post_condition_mode.post_condition_mode == TransactionPostConditionMode::Allow {
                TransactionPostConditionMode::Deny
            }
            else {
                TransactionPostConditionMode::Allow
            };

        // mess with payload
        let mut corrupt_tx_payload = signed_tx.clone();
        corrupt_tx_payload.payload = match corrupt_tx_payload.payload {
            TransactionPayload::TokenTransfer(ref addr, ref amount, ref memo) => {
                TransactionPayload::TokenTransfer(addr.clone(), amount + 1, memo.clone())
            },
            TransactionPayload::ContractCall(_) => {
                TransactionPayload::SmartContract(TransactionSmartContract { name: ContractName::try_from("corrupt-name").unwrap(), code_body: StacksString::from_str("corrupt body").unwrap() })
            },
            TransactionPayload::SmartContract(_) => {
                TransactionPayload::ContractCall(TransactionContractCall { 
                    address: StacksAddress { version: 1, bytes: Hash160([0xff; 20]) },
                    contract_name: ContractName::try_from("hello-world").unwrap(),
                    function_name: ClarityName::try_from("hello-function").unwrap(),
                    function_args: vec![Value::Int(0)],
                })
            },
            TransactionPayload::PoisonMicroblock(ref h1, ref h2) => {
                let mut corrupt_h1 = h1.clone();
                let mut corrupt_h2 = h2.clone();

                corrupt_h1.sequence += 1;
                corrupt_h2.sequence += 1;
                TransactionPayload::PoisonMicroblock(corrupt_h1, corrupt_h2)
            },
            TransactionPayload::Coinbase(ref buf) => {
                let mut corrupt_buf_bytes = buf.as_bytes().clone();
                corrupt_buf_bytes[0] = (((corrupt_buf_bytes[0] as u16) + 1) % 256) as u8;

                let corrupt_buf = CoinbasePayload(corrupt_buf_bytes);
                TransactionPayload::Coinbase(corrupt_buf)
            }
        };
        assert!(corrupt_tx_payload.txid() != signed_tx.txid());

        let mut corrupt_transactions = vec![
            corrupt_tx_hash_mode,
            corrupt_tx_nonce,
            corrupt_tx_signature.clone(),       // needed below
            corrupt_tx_public_key,
            corrupt_tx_version,
            corrupt_tx_chain_id,
            corrupt_tx_fee,
            corrupt_tx_anchor_mode,
            corrupt_tx_post_condition_mode,
            corrupt_tx_post_conditions,
            corrupt_tx_payload
        ];
        if is_multisig_origin || is_multisig_sponsor {
            corrupt_transactions.push(corrupt_tx_signatures_required.clone());
        }

        // make sure all corrupted transactions fail
        for corrupt_tx in corrupt_transactions.iter() {
            match corrupt_tx.verify() {
                Ok(_) => {
                    eprintln!("{:?}", &corrupt_tx);
                    assert!(false);
                }
                Err(e) => {
                    match e {
                        net_error::VerifyingError(msg) => {},
                        _ => assert!(false)
                    }
                }
            }
        }
        
        // exhaustive test -- mutate each byte
        let mut tx_bytes = signed_tx.serialize();
        for i in 0..tx_bytes.len() {
            let next_byte = tx_bytes[i] as u16;
            tx_bytes[i] = ((next_byte + 1) % 0xff) as u8;

            let mut index = 0;
            match StacksTransaction::deserialize(&tx_bytes, &mut index, tx_bytes.len() as u32) {
                Ok(corrupt_tx) => {
                    if index < tx_bytes.len() as u32 {
                        // didn't parse fully; the block-parsing logic would reject this block.
                        tx_bytes[i] = next_byte as u8;
                        continue;
                    }
                    if corrupt_tx.verify().is_ok() {
                        if corrupt_tx != *signed_tx {
                            eprintln!("corrupt tx: {:#?}", &corrupt_tx);
                            eprintln!("signed tx:  {:#?}", &signed_tx);
                            assert!(false);
                        }
                    }
                },
                Err(_) => {}
            }
            // restore
            tx_bytes[i] = next_byte as u8;
        }
    }

    #[test]
    fn tx_stacks_transaction_payload_tokens() {
        let addr = StacksAddress {
            version: 1,
            bytes: Hash160([0xff; 20])
        };
        
        let tt_stx = TransactionPayload::TokenTransfer(addr.clone(), 123, TokenTransferMemo([1u8; 34]));
        
        // wire encodings of the same
        let mut tt_stx_bytes = vec![];
        tt_stx_bytes.push(TransactionPayloadID::TokenTransfer as u8);
        tt_stx_bytes.append(&mut addr.serialize());
        tt_stx_bytes.append(&mut vec![0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 123]);
        tt_stx_bytes.append(&mut vec![1u8; 34]);

        check_codec_and_corruption::<TransactionPayload>(&tt_stx, &tt_stx_bytes);
    }

    #[test]
    fn tx_stacks_transacton_payload_contracts() {
        let hello_contract_call = "hello-contract-call";
        let hello_contract_name = "hello-contract-name";
        let hello_function_name = "hello-function-name";
        let hello_contract_body = "hello contract code body";

        let contract_call = TransactionContractCall {
            address: StacksAddress { version: 1, bytes: Hash160([0xff; 20]) },
            contract_name: ContractName::try_from(hello_contract_name).unwrap(),
            function_name: ClarityName::try_from(hello_function_name).unwrap(),
            function_args: vec![Value::Int(0)]
        };

        let smart_contract = TransactionSmartContract {
            name: ContractName::try_from(hello_contract_name).unwrap(),
            code_body: StacksString::from_str(hello_contract_body).unwrap(),
        };

        let mut contract_call_bytes = vec![];
        contract_call_bytes.append(&mut contract_call.address.serialize());
        contract_call_bytes.append(&mut contract_call.contract_name.serialize());
        contract_call_bytes.append(&mut contract_call.function_name.serialize());
        contract_call_bytes.append(&mut contract_call.function_args.serialize());

        let mut smart_contract_bytes = vec![];
        smart_contract_bytes.append(&mut smart_contract.name.serialize());
        smart_contract_bytes.append(&mut smart_contract.code_body.serialize());

        let mut transaction_contract_call = vec![
            TransactionPayloadID::ContractCall as u8
        ];
        transaction_contract_call.append(&mut contract_call_bytes.clone());

        let mut transaction_smart_contract = vec![
            TransactionPayloadID::SmartContract as u8
        ];
        transaction_smart_contract.append(&mut smart_contract_bytes.clone());

        check_codec_and_corruption::<TransactionContractCall>(&contract_call, &contract_call_bytes);
        check_codec_and_corruption::<TransactionSmartContract>(&smart_contract, &smart_contract_bytes);
        check_codec_and_corruption::<TransactionPayload>(&TransactionPayload::ContractCall(contract_call.clone()), &transaction_contract_call);
        check_codec_and_corruption::<TransactionPayload>(&TransactionPayload::SmartContract(smart_contract.clone()), &transaction_smart_contract);
    }

    #[test]
    fn tx_stacks_transaction_payload_coinbase() {
        let coinbase_payload = TransactionPayload::Coinbase(CoinbasePayload([0x12; 32]));
        let coinbase_payload_bytes = vec![
            // payload type ID
            TransactionPayloadID::Coinbase as u8,
            // buffer
            0x12, 0x12, 0x12, 0x12, 0x12, 0x12, 0x12, 0x12, 0x12, 0x12, 0x12, 0x12, 0x12, 0x12, 0x12, 0x12, 0x12, 0x12, 0x12, 0x12, 0x12, 0x12, 0x12, 0x12, 0x12, 0x12, 0x12, 0x12, 0x12, 0x12, 0x12, 0x12
        ];

        check_codec_and_corruption::<TransactionPayload>(&coinbase_payload, &coinbase_payload_bytes);
    }

    #[test]
    fn tx_stacks_transaction_payload_microblock_poison() {
        let header_1 = StacksMicroblockHeader {
            version: 0x12,
            sequence: 0x34,
            prev_block: EMPTY_MICROBLOCK_PARENT_HASH.clone(),
            tx_merkle_root: Sha512Trunc256Sum([1u8; 32]),
            signature: MessageSignature([2u8; 65]),
        };
        
        let header_2 = StacksMicroblockHeader {
            version: 0x12,
            sequence: 0x34,
            prev_block: EMPTY_MICROBLOCK_PARENT_HASH.clone(),
            tx_merkle_root: Sha512Trunc256Sum([2u8; 32]),
            signature: MessageSignature([3u8; 65]),
        };
        
        let payload = TransactionPayload::PoisonMicroblock(header_1, header_2);

        let payload_bytes = vec![
            // payload type ID
            TransactionPayloadID::PoisonMicroblock as u8,

            // header_1
            // version
            0x12,
            // sequence
            0x00, 0x34,
            // prev block
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            // tx merkle root
            0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01,
            // signature
            0x02, 0x02, 0x02, 0x02, 0x02, 0x02, 0x02, 0x02, 0x02, 0x02, 0x02, 0x02, 0x02, 0x02, 0x02, 0x02, 0x02, 0x02, 0x02, 0x02, 0x02, 0x02, 0x02, 0x02, 0x02, 0x02, 0x02, 0x02, 0x02, 0x02, 0x02, 0x02,
            0x02, 0x02, 0x02, 0x02, 0x02, 0x02, 0x02, 0x02, 0x02, 0x02, 0x02, 0x02, 0x02, 0x02, 0x02, 0x02, 0x02, 0x02, 0x02, 0x02, 0x02, 0x02, 0x02, 0x02, 0x02, 0x02, 0x02, 0x02, 0x02, 0x02, 0x02, 0x02,
            0x02,

            // header_2
            // version
            0x12,
            // sequence
            0x00, 0x34,
            // prev block
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            // tx merkle root
            0x02, 0x02, 0x02, 0x02, 0x02, 0x02, 0x02, 0x02, 0x02, 0x02, 0x02, 0x02, 0x02, 0x02, 0x02, 0x02, 0x02, 0x02, 0x02, 0x02, 0x02, 0x02, 0x02, 0x02, 0x02, 0x02, 0x02, 0x02, 0x02, 0x02, 0x02, 0x02,
            // signature
            0x03, 0x03, 0x03, 0x03, 0x03, 0x03, 0x03, 0x03, 0x03, 0x03, 0x03, 0x03, 0x03, 0x03, 0x03, 0x03, 0x03, 0x03, 0x03, 0x03, 0x03, 0x03, 0x03, 0x03, 0x03, 0x03, 0x03, 0x03, 0x03, 0x03, 0x03, 0x03,
            0x03, 0x03, 0x03, 0x03, 0x03, 0x03, 0x03, 0x03, 0x03, 0x03, 0x03, 0x03, 0x03, 0x03, 0x03, 0x03, 0x03, 0x03, 0x03, 0x03, 0x03, 0x03, 0x03, 0x03, 0x03, 0x03, 0x03, 0x03, 0x03, 0x03, 0x03, 0x03,
            0x03
        ];

        check_codec_and_corruption::<TransactionPayload>(&payload, &payload_bytes);

        // TODO: test same sequence, different parent header hash
        // TODO: test different sequence, same parent header hash
        // TODO: test deserialization failure 
    }

    #[test]
    fn tx_stacks_transaction_payload_invalid() {
        // test invalid payload type ID 
        let hello_contract_call = "hello contract call";
        let mut contract_call_bytes = vec![
            0x00, 0x00, 0x00, hello_contract_call.len() as u8
        ];
        contract_call_bytes.extend_from_slice(hello_contract_call.as_bytes());
        
        let mut payload_contract_call = vec![];
        payload_contract_call.append(&mut contract_call_bytes);

        let mut transaction_contract_call = vec![
            0xff        // invalid type ID
        ];
        transaction_contract_call.append(&mut payload_contract_call.clone());

        let mut idx = 0;
        assert!(TransactionPayload::deserialize(&transaction_contract_call, &mut idx, transaction_contract_call.len() as u32).is_err());
        assert_eq!(idx, 0);
    }
    
    #[test]
    fn tx_stacks_asset() {
        let addr = StacksAddress { version: 1, bytes: Hash160([0xff; 20]) };
        let addr_bytes = vec![
            // version
            0x01,
            // bytes
            0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff
        ];

        let asset_name = ClarityName::try_from("hello-asset").unwrap();
        let mut asset_name_bytes = vec![
            // length
            asset_name.len() as u8,
        ];
        asset_name_bytes.extend_from_slice(&asset_name.to_string().as_str().as_bytes());

        let contract_name = ContractName::try_from("hello-world").unwrap();
        let mut contract_name_bytes = vec![
            // length
            contract_name.len() as u8,
        ];
        contract_name_bytes.extend_from_slice(&contract_name.to_string().as_str().as_bytes());

        let asset_info = AssetInfo {
            contract_address: addr.clone(),
            contract_name: contract_name.clone(),
            asset_name: asset_name.clone()
        };

        let mut asset_info_bytes = vec![];
        asset_info_bytes.extend_from_slice(&addr_bytes[..]);
        asset_info_bytes.extend_from_slice(&contract_name_bytes[..]);
        asset_info_bytes.extend_from_slice(&asset_name_bytes[..]);

        assert_eq!(asset_info.serialize(), asset_info_bytes);

        let mut idx = 0;
        assert_eq!(AssetInfo::deserialize(&asset_info_bytes, &mut idx, asset_info_bytes.len() as u32).unwrap(), asset_info);
        assert_eq!(idx, asset_info_bytes.len() as u32);
    }

    #[test]
    fn tx_stacks_postcondition() {
        let tx_post_condition_principals = vec![
            PostConditionPrincipal::Origin,
            PostConditionPrincipal::Standard(StacksAddress { version: 1, bytes: Hash160([1u8; 20]) }),
            PostConditionPrincipal::Contract(StacksAddress { version: 2, bytes: Hash160([2u8; 20]) }, ContractName::try_from("hello-world").unwrap())
        ];

        for tx_pcp in tx_post_condition_principals {
            let addr = StacksAddress { version: 1, bytes: Hash160([0xff; 20]) };
            let asset_name = ClarityName::try_from("hello-asset").unwrap();
            let contract_name = ContractName::try_from("contract-name").unwrap();

            let stx_pc = TransactionPostCondition::STX(tx_pcp.clone(), FungibleConditionCode::SentGt, 12345);
            let fungible_pc = TransactionPostCondition::Fungible(
                tx_pcp.clone(),
                AssetInfo { contract_address: addr.clone(), contract_name: contract_name.clone(), asset_name: asset_name.clone() },
                FungibleConditionCode::SentGt,
                23456);

            let nonfungible_pc = TransactionPostCondition::Nonfungible(
                tx_pcp.clone(),
                AssetInfo { contract_address: addr.clone(), contract_name: contract_name.clone(), asset_name: asset_name.clone() },
                Value::buff_from(vec![0, 1, 2, 3]).unwrap(),
                NonfungibleConditionCode::NotSent);

            let mut stx_pc_bytes = (AssetInfoID::STX as u8).serialize();
            stx_pc_bytes.append(&mut tx_pcp.serialize());
            stx_pc_bytes.append(&mut vec![
                // condition code
                FungibleConditionCode::SentGt as u8,
                // amount 
                0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x30, 0x39
            ]);

            let mut fungible_pc_bytes = (AssetInfoID::FungibleAsset as u8).serialize();
            fungible_pc_bytes.append(&mut tx_pcp.serialize());
            fungible_pc_bytes.append(&mut AssetInfo {contract_address: addr.clone(), contract_name: contract_name.clone(), asset_name: asset_name.clone()}.serialize());
            fungible_pc_bytes.append(&mut vec![
                // condition code 
                FungibleConditionCode::SentGt as u8,
                // amount
                0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x5b, 0xa0
            ]);

            let mut nonfungible_pc_bytes = (AssetInfoID::NonfungibleAsset as u8).serialize();
            nonfungible_pc_bytes.append(&mut tx_pcp.serialize());
            nonfungible_pc_bytes.append(&mut AssetInfo {contract_address: addr.clone(), contract_name: contract_name.clone(), asset_name: asset_name.clone()}.serialize());
            nonfungible_pc_bytes.append(&mut Value::buff_from(vec![0, 1, 2, 3]).unwrap().serialize());
            nonfungible_pc_bytes.append(&mut vec![
                // condition code
                NonfungibleConditionCode::NotSent as u8
            ]);

            let pcs = vec![stx_pc, fungible_pc, nonfungible_pc];
            let pc_bytes = vec![stx_pc_bytes, fungible_pc_bytes, nonfungible_pc_bytes];
            for i in 0..3 {
                check_codec_and_corruption::<TransactionPostCondition>(&pcs[i], &pc_bytes[i]);
            }
        }
    }

    #[test]
    fn tx_stacks_postcondition_invalid() {
        let addr = StacksAddress { version: 1, bytes: Hash160([0xff; 20]) };
        let asset_name = ClarityName::try_from("hello-asset").unwrap();
        let contract_name = ContractName::try_from("hello-world").unwrap();

        // can't parse a postcondition with an invalid condition code

        let mut stx_pc_bytes_bad_condition = (AssetInfoID::STX as u8).serialize();
        stx_pc_bytes_bad_condition.append(&mut vec![
            // principal
            PostConditionPrincipalID::Origin as u8,
            // condition code
            NonfungibleConditionCode::NotSent as u8,
            // amount 
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x30, 0x39
        ]);

        let mut fungible_pc_bytes_bad_condition = (AssetInfoID::FungibleAsset as u8).serialize();
        fungible_pc_bytes_bad_condition.append(&mut vec![PostConditionPrincipalID::Origin as u8]);
        fungible_pc_bytes_bad_condition.append(&mut AssetInfo {contract_address: addr.clone(), contract_name: contract_name.clone(), asset_name: asset_name.clone()}.serialize());
        fungible_pc_bytes_bad_condition.append(&mut vec![
            // condition code 
            NonfungibleConditionCode::Sent as u8,
            // amount
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x5b, 0xa0
        ]);
        
        let mut nonfungible_pc_bytes_bad_condition = (AssetInfoID::NonfungibleAsset as u8).serialize();
        nonfungible_pc_bytes_bad_condition.append(&mut vec![PostConditionPrincipalID::Origin as u8]);
        nonfungible_pc_bytes_bad_condition.append(&mut AssetInfo {contract_address: addr.clone(), contract_name: contract_name.clone(), asset_name: asset_name.clone()}.serialize());
        nonfungible_pc_bytes_bad_condition.append(&mut Value::buff_from(vec![0, 1, 2, 3]).unwrap().serialize());
        nonfungible_pc_bytes_bad_condition.append(&mut vec![
            // condition code
            FungibleConditionCode::SentGt as u8
        ]);

        let bad_pc_bytes = vec![stx_pc_bytes_bad_condition, fungible_pc_bytes_bad_condition, nonfungible_pc_bytes_bad_condition];
        for i in 0..3 {
            let mut idx = 0;
            assert!(TransactionPostCondition::deserialize(&bad_pc_bytes[i], &mut idx, bad_pc_bytes[i].len() as u32).is_err());
            assert_eq!(idx, 0);
        }
        
        // can't parse a postcondition with an invalid principal

        let mut stx_pc_bytes_bad_principal = (AssetInfoID::STX as u8).serialize();
        stx_pc_bytes_bad_principal.append(&mut vec![
            // principal
            0xff,
            // condition code
            NonfungibleConditionCode::NotSent as u8,
            // amount 
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x30, 0x39
        ]);

        let mut fungible_pc_bytes_bad_principal = (AssetInfoID::FungibleAsset as u8).serialize();
        fungible_pc_bytes_bad_principal.append(&mut vec![0xff]);
        fungible_pc_bytes_bad_principal.append(&mut AssetInfo {contract_address: addr.clone(), contract_name: contract_name.clone(), asset_name: asset_name.clone()}.serialize());
        fungible_pc_bytes_bad_principal.append(&mut vec![
            // condition code 
            NonfungibleConditionCode::Sent as u8,
            // amount
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x5b, 0xa0
        ]);
        
        let mut nonfungible_pc_bytes_bad_principal = (AssetInfoID::NonfungibleAsset as u8).serialize();
        nonfungible_pc_bytes_bad_principal.append(&mut vec![0xff]);
        nonfungible_pc_bytes_bad_principal.append(&mut AssetInfo {contract_address: addr.clone(), contract_name: contract_name.clone(), asset_name: asset_name.clone()}.serialize());
        nonfungible_pc_bytes_bad_principal.append(&mut Value::buff_from(vec![0, 1, 2, 3]).unwrap().serialize());
        nonfungible_pc_bytes_bad_principal.append(&mut vec![
            // condition code
            FungibleConditionCode::SentGt as u8
        ]);

        let bad_pc_bytes = vec![stx_pc_bytes_bad_principal, fungible_pc_bytes_bad_principal, nonfungible_pc_bytes_bad_principal];
        for i in 0..3 {
            let mut idx = 0;
            assert!(TransactionPostCondition::deserialize(&bad_pc_bytes[i], &mut idx, bad_pc_bytes[i].len() as u32).is_err());
            assert_eq!(idx, 0);
        }
    }

    #[test]
    fn tx_stacks_transaction_codec() {
        let all_txs = codec_all_transactions(&TransactionVersion::Mainnet, 0, &TransactionAnchorMode::OnChainOnly, &TransactionPostConditionMode::Deny);
        for tx in all_txs.iter() {
            let mut tx_bytes = vec![
                // version
                TransactionVersion::Mainnet as u8,
                // chain ID
                0x00, 0x00, 0x00, 0x00
            ];
            
            tx_bytes.append(&mut (tx.auth.serialize()));
            tx_bytes.append(&mut vec![TransactionAnchorMode::OnChainOnly as u8]);
            tx_bytes.append(&mut vec![TransactionPostConditionMode::Deny as u8]);
            tx_bytes.append(&mut (tx.post_conditions.serialize()));
            tx_bytes.append(&mut (tx.payload.serialize()));

            test_debug!("---------");
            test_debug!("test tx:\n{:?}", &tx);

            check_codec_and_corruption::<StacksTransaction>(&tx, &tx_bytes);
        }
    }

    fn tx_stacks_transaction_test_txs(auth: &TransactionAuth) -> Vec<StacksTransaction> {
        let header_1 = StacksMicroblockHeader {
            version: 0x12,
            sequence: 0x34,
            prev_block: EMPTY_MICROBLOCK_PARENT_HASH.clone(),
            tx_merkle_root: Sha512Trunc256Sum([1u8; 32]),
            signature: MessageSignature([2u8; 65]),
        };
        
        let header_2 = StacksMicroblockHeader {
            version: 0x12,
            sequence: 0x34,
            prev_block: EMPTY_MICROBLOCK_PARENT_HASH.clone(),
            tx_merkle_root: Sha512Trunc256Sum([2u8; 32]),
            signature: MessageSignature([3u8; 65]),
        };

        let hello_contract_name = "hello-contract-name";
        let hello_asset_name = "hello-asset";
        let hello_token_name = "hello-token";

        let contract_name = ContractName::try_from(hello_contract_name).unwrap();
        let asset_name = ClarityName::try_from(hello_asset_name).unwrap();
        let token_name = StacksString::from_str(hello_token_name).unwrap();
        
        let asset_value = StacksString::from_str("asset-value").unwrap();

        let contract_addr = StacksAddress {
            version: 2,
            bytes: Hash160([0xfe; 20])
        };

        let asset_info = AssetInfo {
            contract_address: contract_addr.clone(),
            contract_name: contract_name.clone(),
            asset_name: asset_name.clone()
        };

        let tx_contract_call = StacksTransaction::new(TransactionVersion::Mainnet,
                                                      auth.clone(),
                                                      TransactionPayload::new_contract_call(StacksAddress { version: 1, bytes: Hash160([0xff; 20]) }, "hello", "world", vec![Value::Int(1)]).unwrap());

        let tx_smart_contract = StacksTransaction::new(TransactionVersion::Mainnet,
                                                       auth.clone(),
                                                       TransactionPayload::new_smart_contract(&"name".to_string(), &"hello smart contract".to_string()).unwrap());

        let tx_coinbase = StacksTransaction::new(TransactionVersion::Mainnet,
                                                 auth.clone(),
                                                 TransactionPayload::Coinbase(CoinbasePayload([0u8; 32])));

        let tx_stx = StacksTransaction::new(TransactionVersion::Mainnet,
                                            auth.clone(),
                                            TransactionPayload::TokenTransfer(StacksAddress { version: 1, bytes: Hash160([0xff; 20]) }, 123, TokenTransferMemo([0u8; 34])));

        let tx_poison = StacksTransaction::new(TransactionVersion::Mainnet,
                                               auth.clone(),
                                               TransactionPayload::PoisonMicroblock(header_1, header_2));

        let txs = vec![tx_contract_call, tx_smart_contract, tx_coinbase, tx_stx, tx_poison];
        txs
    }

    fn check_oversign_origin_singlesig(signed_tx: &mut StacksTransaction) -> () {
        let txid_before = signed_tx.txid();
        match signed_tx.append_next_origin(&StacksPublicKey::from_hex("03442a63b6d312710b1d6b24d803120dc6f5714352ba57907863b78de55974123c").unwrap()) {
            Ok(_) => assert!(false),
            Err(e) => match e {
                net_error::SigningError(msg) => {
                    assert_eq!(&msg, "Not a multisig condition");
                },
                _ => assert!(false)
            }
        };

        // no change affected
        assert_eq!(txid_before, signed_tx.txid());
    }
    
    fn check_sign_no_sponsor(signed_tx: &mut StacksTransaction) -> () {
        let txid_before = signed_tx.txid();
        match signed_tx.append_next_sponsor(&StacksPublicKey::from_hex("03442a63b6d312710b1d6b24d803120dc6f5714352ba57907863b78de55974123c").unwrap()) {
            Ok(_) => assert!(false),
            Err(e) => match e {
                net_error::SigningError(msg) => {
                    assert_eq!(&msg, "Cannot appned a public key to the sponsor of a standard auth condition")
                },
                _ => assert!(false)
            }
        }
        assert_eq!(txid_before, signed_tx.txid());
    }

    fn check_oversign_sponsor_singlesig(signed_tx: &mut StacksTransaction) -> () {
        let txid_before = signed_tx.txid();
        match signed_tx.append_next_sponsor(&StacksPublicKey::from_hex("03442a63b6d312710b1d6b24d803120dc6f5714352ba57907863b78de55974123c").unwrap()) {
            Ok(_) => assert!(false),
            Err(e) => match e {
                net_error::SigningError(msg) => {
                    assert_eq!(&msg, "Not a multisig condition")
                },
                _ => assert!(false)
            }
        }
        assert_eq!(txid_before, signed_tx.txid());
    }

    fn check_oversign_origin_multisig(signed_tx: &StacksTransaction) -> () {
        let tx = signed_tx.clone();
        let privk = StacksPrivateKey::from_hex("c6ebf45dabca8cac9a25ae39ab690743b96eb2b0960066e98ba6df50d6f9293b01").unwrap();

        let mut tx_signer = StacksTransactionSigner::new(&tx);
        tx_signer.disable_checks();
        tx_signer.sign_origin(&privk).unwrap();
        let oversigned_tx = tx_signer.get_tx().unwrap();
        
        match oversigned_tx.verify() {
            Ok(_) => assert!(false),
            Err(e) => match e {
                net_error::VerifyingError(msg) => {
                    assert_eq!(&msg, "Incorrect number of signatures")
                },
                _ => assert!(false)
            }
        }
    }
    
    fn check_oversign_origin_multisig_uncompressed(signed_tx: &StacksTransaction) -> () {
        let tx = signed_tx.clone();
        let privk = StacksPrivateKey::from_hex("c6ebf45dabca8cac9a25ae39ab690743b96eb2b0960066e98ba6df50d6f9293b").unwrap();

        let mut tx_signer = StacksTransactionSigner::new(&tx);
        tx_signer.disable_checks();

        match tx_signer.pop_origin_auth_field().unwrap() {
            TransactionAuthField::Signature(_, _) => {
                tx_signer.sign_origin(&privk).unwrap();
            },
            TransactionAuthField::PublicKey(_) => {
                tx_signer.append_origin(&StacksPublicKey::from_private(&privk)).unwrap();
            }
        };

        let oversigned_tx = tx_signer.get_tx().unwrap();

        match oversigned_tx.verify() {
            Ok(_) => assert!(false),
            Err(e) => match e {
                net_error::VerifyingError(msg) => {
                    assert_eq!(&msg, "Uncompressed keys are not allowed in this hash mode");
                },
                _ => assert!(false)
            }
        }
    }

    fn check_oversign_sponsor_multisig(signed_tx: &StacksTransaction) -> () {
        let tx = signed_tx.clone();
        let privk = StacksPrivateKey::from_hex("c6ebf45dabca8cac9a25ae39ab690743b96eb2b0960066e98ba6df50d6f9293b01").unwrap();

        let mut tx_signer = StacksTransactionSigner::new(&tx);
        tx_signer.disable_checks();
        tx_signer.sign_sponsor(&privk).unwrap();
        let oversigned_tx = tx_signer.get_tx().unwrap();

        match oversigned_tx.verify() {
            Ok(_) => assert!(false),
            Err(e) => match e {
                net_error::VerifyingError(msg) => {
                    assert_eq!(&msg, "Incorrect number of signatures")
                },
                _ => assert!(false)
            }
        }
    }
    
    fn check_oversign_sponsor_multisig_uncompressed(signed_tx: &StacksTransaction) -> () {
        let tx = signed_tx.clone();
        let privk = StacksPrivateKey::from_hex("c6ebf45dabca8cac9a25ae39ab690743b96eb2b0960066e98ba6df50d6f9293b").unwrap();

        let mut tx_signer = StacksTransactionSigner::new(&tx);
        tx_signer.disable_checks();

        match tx_signer.pop_sponsor_auth_field().unwrap() {
            TransactionAuthField::Signature(_, _) => {
                tx_signer.sign_sponsor(&privk).unwrap();
            },
            TransactionAuthField::PublicKey(_) => {
                tx_signer.append_sponsor(&StacksPublicKey::from_private(&privk)).unwrap();
            }
        };

        let oversigned_tx = tx_signer.get_tx().unwrap();
        
        match oversigned_tx.verify() {
            Ok(_) => assert!(false),
            Err(e) => match e {
                net_error::VerifyingError(msg) => {
                    assert_eq!(&msg, "Uncompressed keys are not allowed in this hash mode");
                },
                _ => assert!(false)
            }
        }
    }

    #[test]
    fn tx_stacks_transaction_sign_verify_standard_p2pkh() {
        let privk = StacksPrivateKey::from_hex("6d430bb91222408e7706c9001cfaeb91b08c2be6d5ac95779ab52c6b431950e001").unwrap();
        let origin_auth = TransactionAuth::Standard(TransactionSpendingCondition::new_singlesig_p2pkh(StacksPublicKey::from_private(&privk)).unwrap());

        let origin_address = origin_auth.origin().address_mainnet();
        assert_eq!(origin_address, StacksAddress { version: C32_ADDRESS_VERSION_MAINNET_SINGLESIG, bytes: Hash160::from_hex("143e543243dfcd8c02a12ad7ea371bd07bc91df9").unwrap() });
        
        let txs = tx_stacks_transaction_test_txs(&origin_auth);

        for tx in txs {
            assert_eq!(tx.auth().origin().num_signatures(), 0);

            let mut tx_signer = StacksTransactionSigner::new(&tx);
            tx_signer.sign_origin(&privk).unwrap();
            let mut signed_tx = tx_signer.get_tx().unwrap();

            assert_eq!(signed_tx.auth().origin().num_signatures(), 1);

            // try to over-sign
            check_oversign_origin_singlesig(&mut signed_tx);
            check_sign_no_sponsor(&mut signed_tx);

            // tx and signed_tx are otherwise equal
            assert_eq!(tx.version, signed_tx.version);
            assert_eq!(tx.get_fee_rate(), signed_tx.get_fee_rate());
            assert_eq!(tx.get_origin_nonce(), signed_tx.get_origin_nonce());
            assert_eq!(tx.get_sponsor_nonce(), signed_tx.get_sponsor_nonce());
            assert_eq!(tx.anchor_mode, signed_tx.anchor_mode);
            assert_eq!(tx.post_condition_mode, signed_tx.post_condition_mode);
            assert_eq!(tx.post_conditions, signed_tx.post_conditions);
            assert_eq!(tx.payload, signed_tx.payload);

            // auth is standard and public key is compressed
            match signed_tx.auth {
                TransactionAuth::Standard(ref origin) => {
                    match origin {
                        TransactionSpendingCondition::Singlesig(ref data) => {
                            assert_eq!(data.key_encoding, TransactionPublicKeyEncoding::Compressed);
                            assert_eq!(data.signer, origin_address.bytes);
                        },
                        _ => assert!(false)
                    }
                },
                _ => assert!(false)
            };

            test_signature_and_corruption(&signed_tx, true, false);
        }
    } 
    
    #[test]
    fn tx_stacks_transaction_sign_verify_sponsored_p2pkh() {
        let privk = StacksPrivateKey::from_hex("6d430bb91222408e7706c9001cfaeb91b08c2be6d5ac95779ab52c6b431950e001").unwrap();
        let privk_sponsor = StacksPrivateKey::from_hex("807bbe9e471ac976592cc35e3056592ecc0f778ee653fced3b491a122dd8d59701").unwrap();
        let privk_diff_sponsor = StacksPrivateKey::from_hex("d5200dee706ee53ae98a03fba6cf4fdcc5084c30cfa9e1b3462dcdeaa3e0f1d2").unwrap();

        let auth = TransactionAuth::Sponsored(
            TransactionSpendingCondition::new_singlesig_p2pkh(StacksPublicKey::from_private(&privk)).unwrap(),
            TransactionSpendingCondition::new_singlesig_p2pkh(StacksPublicKey::from_private(&privk_sponsor)).unwrap()       // will be replaced once the origin finishes signing
        );

        let origin_address = auth.origin().address_mainnet();
        assert_eq!(origin_address, StacksAddress { version: C32_ADDRESS_VERSION_MAINNET_SINGLESIG, bytes: Hash160::from_hex("143e543243dfcd8c02a12ad7ea371bd07bc91df9").unwrap() });

        let sponsor_address = auth.sponsor().unwrap().address_mainnet();
        assert_eq!(sponsor_address, StacksAddress { version: C32_ADDRESS_VERSION_MAINNET_SINGLESIG, bytes: Hash160::from_hex("3597aaa4bde720be93e3829aae24e76e7fcdfd3e").unwrap() });
        
        let diff_sponsor_address = StacksAddress { version: C32_ADDRESS_VERSION_MAINNET_SINGLESIG, bytes: Hash160::from_hex("a139de6733cef9e4663c4a093c1a7390a1dcc297").unwrap() };
        
        let txs = tx_stacks_transaction_test_txs(&auth);

        for mut tx in txs {
            assert_eq!(tx.auth().origin().num_signatures(), 0);
            assert_eq!(tx.auth().sponsor().unwrap().num_signatures(), 0);

            tx.set_fee_rate(123);
            tx.set_sponsor_nonce(456).unwrap();
            let mut tx_signer = StacksTransactionSigner::new(&tx);

            test_debug!("Sign origin");
            tx_signer.sign_origin(&privk).unwrap();

            // sponsor sets keys, nonce, and fee after origin signs
            let origin_tx = tx_signer.get_tx_incomplete();
            
            let mut sponsor_auth = TransactionSpendingCondition::new_singlesig_p2pkh(StacksPublicKey::from_private(&privk_diff_sponsor)).unwrap();
            sponsor_auth.set_fee_rate(456);
            sponsor_auth.set_nonce(789);

            let mut tx_sponsor_signer = StacksTransactionSigner::new_sponsor(&origin_tx, sponsor_auth).unwrap();

            test_debug!("Sign sponsor");
            tx_sponsor_signer.sign_sponsor(&privk_diff_sponsor).unwrap();

            // make comparable
            tx.set_fee_rate(456);
            tx.set_sponsor_nonce(789).unwrap();
            let mut signed_tx = tx_sponsor_signer.get_tx().unwrap();

            assert_eq!(signed_tx.auth().origin().num_signatures(), 1);
            assert_eq!(signed_tx.auth().sponsor().unwrap().num_signatures(), 1);
            
            // try to over-sign
            check_oversign_origin_singlesig(&mut signed_tx);
            check_oversign_sponsor_singlesig(&mut signed_tx);

            // tx and signed_tx are otherwise equal
            assert_eq!(tx.version, signed_tx.version);
            assert_eq!(tx.chain_id, signed_tx.chain_id);
            assert_eq!(tx.get_fee_rate(), 456);
            assert_eq!(tx.get_origin_nonce(), signed_tx.get_origin_nonce());
            assert_eq!(tx.get_sponsor_nonce(), signed_tx.get_sponsor_nonce());
            assert_eq!(tx.anchor_mode, signed_tx.anchor_mode);
            assert_eq!(tx.post_condition_mode, signed_tx.post_condition_mode);
            assert_eq!(tx.post_conditions, signed_tx.post_conditions);
            assert_eq!(tx.payload, signed_tx.payload);

            // auth is a sponsor and public key is compressed.
            // auth sponsor is privk_diff_sponsor
            match signed_tx.auth {
                TransactionAuth::Sponsored(ref origin, ref sponsor) => {
                    match origin {
                        TransactionSpendingCondition::Singlesig(ref data) => {
                            assert_eq!(data.key_encoding, TransactionPublicKeyEncoding::Compressed);
                            assert_eq!(data.signer, origin_address.bytes);
                        },
                        _ => assert!(false)
                    }
                    match sponsor {
                        TransactionSpendingCondition::Singlesig(ref data) => {
                            assert_eq!(data.key_encoding, TransactionPublicKeyEncoding::Uncompressed);   // not what the origin would have seen
                            assert_eq!(data.signer, diff_sponsor_address.bytes);                         // not what the origin would have seen
                        },
                        _ => assert!(false)
                    }
                },
                _ => assert!(false)
            };

            test_signature_and_corruption(&signed_tx, true, false);
            test_signature_and_corruption(&signed_tx, false, true);
        }
    } 
    
    #[test]
    fn tx_stacks_transaction_sign_verify_standard_p2pkh_uncompressed() {
        let privk = StacksPrivateKey::from_hex("6d430bb91222408e7706c9001cfaeb91b08c2be6d5ac95779ab52c6b431950e0").unwrap();
        let origin_auth = TransactionAuth::Standard(TransactionSpendingCondition::new_singlesig_p2pkh(StacksPublicKey::from_private(&privk)).unwrap());

        let origin_address = origin_auth.origin().address_mainnet();
        assert_eq!(origin_address, StacksAddress { version: C32_ADDRESS_VERSION_MAINNET_SINGLESIG, bytes: Hash160::from_hex("693cd53eb47d4749762d7cfaf46902bda5be5f97").unwrap() });
        
        let txs = tx_stacks_transaction_test_txs(&origin_auth);

        for tx in txs {
            assert_eq!(tx.auth().origin().num_signatures(), 0);

            let mut tx_signer = StacksTransactionSigner::new(&tx);
            tx_signer.sign_origin(&privk).unwrap();
            let mut signed_tx = tx_signer.get_tx().unwrap();
            
            // try to over-sign
            check_oversign_origin_singlesig(&mut signed_tx);
            check_sign_no_sponsor(&mut signed_tx);

            assert_eq!(signed_tx.auth().origin().num_signatures(), 1);

            // tx and signed_tx are otherwise equal
            assert_eq!(tx.version, signed_tx.version);
            assert_eq!(tx.get_fee_rate(), signed_tx.get_fee_rate());
            assert_eq!(tx.get_origin_nonce(), signed_tx.get_origin_nonce());
            assert_eq!(tx.get_sponsor_nonce(), signed_tx.get_sponsor_nonce());
            assert_eq!(tx.anchor_mode, signed_tx.anchor_mode);
            assert_eq!(tx.post_condition_mode, signed_tx.post_condition_mode);
            assert_eq!(tx.post_conditions, signed_tx.post_conditions);
            assert_eq!(tx.payload, signed_tx.payload);
            
            // auth is standard and public key is uncompressed
            match signed_tx.auth {
                TransactionAuth::Standard(ref origin) => {
                    match origin {
                        TransactionSpendingCondition::Singlesig(ref data) => {
                            assert_eq!(data.key_encoding, TransactionPublicKeyEncoding::Uncompressed);
                            assert_eq!(data.signer, origin_address.bytes);
                        },
                        _ => assert!(false)
                    }
                },
                _ => assert!(false)
            };

            test_signature_and_corruption(&signed_tx, true, false);
        }
    } 
    
    #[test]
    fn tx_stacks_transaction_sign_verify_sponsored_p2pkh_uncompressed() {
        let privk = StacksPrivateKey::from_hex("807bbe9e471ac976592cc35e3056592ecc0f778ee653fced3b491a122dd8d59701").unwrap();
        let privk_sponsored = StacksPrivateKey::from_hex("6d430bb91222408e7706c9001cfaeb91b08c2be6d5ac95779ab52c6b431950e0").unwrap();

        let mut random_sponsor = StacksPrivateKey::new();       // what the origin sees
        random_sponsor.set_compress_public(true);
        
        let auth = TransactionAuth::Sponsored(
            TransactionSpendingCondition::new_singlesig_p2pkh(StacksPublicKey::from_private(&privk)).unwrap(),
            TransactionSpendingCondition::new_singlesig_p2pkh(StacksPublicKey::from_private(&random_sponsor)).unwrap(),
        );
        
        let real_sponsor = TransactionSpendingCondition::new_singlesig_p2pkh(StacksPublicKey::from_private(&privk_sponsored)).unwrap();

        let origin_address = auth.origin().address_mainnet();
        let sponsor_address = real_sponsor.address_mainnet();
        
        assert_eq!(origin_address, StacksAddress { version: C32_ADDRESS_VERSION_MAINNET_SINGLESIG, bytes: Hash160::from_hex("3597aaa4bde720be93e3829aae24e76e7fcdfd3e").unwrap() });
        assert_eq!(sponsor_address, StacksAddress { version: C32_ADDRESS_VERSION_MAINNET_SINGLESIG, bytes: Hash160::from_hex("693cd53eb47d4749762d7cfaf46902bda5be5f97").unwrap() });
        
        let txs = tx_stacks_transaction_test_txs(&auth);

        for mut tx in txs {
            assert_eq!(tx.auth().origin().num_signatures(), 0);
            assert_eq!(tx.auth().sponsor().unwrap().num_signatures(), 0);

            tx.set_fee_rate(123);
            tx.set_sponsor_nonce(456).unwrap();

            let mut tx_signer = StacksTransactionSigner::new(&tx);
            tx_signer.sign_origin(&privk).unwrap();

            // sponsor sets and pays fee after origin signs
            let mut origin_tx = tx_signer.get_tx_incomplete();
            origin_tx.auth.set_sponsor(real_sponsor.clone()).unwrap();
            origin_tx.set_fee_rate(456);
            origin_tx.set_sponsor_nonce(789).unwrap();
            tx_signer.resume(&origin_tx);

            tx_signer.sign_sponsor(&privk_sponsored).unwrap();

            tx.set_fee_rate(456);
            tx.set_sponsor_nonce(789).unwrap();
            let mut signed_tx = tx_signer.get_tx().unwrap();
            
            // try to over-sign
            check_oversign_origin_singlesig(&mut signed_tx);
            check_oversign_sponsor_singlesig(&mut signed_tx);

            assert_eq!(signed_tx.auth().origin().num_signatures(), 1);
            assert_eq!(signed_tx.auth().sponsor().unwrap().num_signatures(), 1);

            // tx and signed_tx are otherwise equal
            assert_eq!(tx.version, signed_tx.version);
            assert_eq!(tx.chain_id, signed_tx.chain_id);
            assert_eq!(tx.get_fee_rate(), signed_tx.get_fee_rate());
            assert_eq!(tx.get_origin_nonce(), signed_tx.get_origin_nonce());
            assert_eq!(tx.get_sponsor_nonce(), signed_tx.get_sponsor_nonce());
            assert_eq!(tx.anchor_mode, signed_tx.anchor_mode);
            assert_eq!(tx.post_condition_mode, signed_tx.post_condition_mode);
            assert_eq!(tx.post_conditions, signed_tx.post_conditions);
            assert_eq!(tx.payload, signed_tx.payload);
            
            // auth is standard and public key is uncompressed
            match signed_tx.auth {
                TransactionAuth::Sponsored(ref origin, ref sponsor) => {
                    match origin {
                        TransactionSpendingCondition::Singlesig(ref data) => {
                            assert_eq!(data.key_encoding, TransactionPublicKeyEncoding::Compressed);
                            assert_eq!(data.signer, origin_address.bytes);
                        },
                        _ => assert!(false)
                    }
                    match sponsor {
                        TransactionSpendingCondition::Singlesig(ref data) => {
                            assert_eq!(data.key_encoding, TransactionPublicKeyEncoding::Uncompressed);
                            assert_eq!(data.signer, sponsor_address.bytes);
                        },
                        _ => assert!(false)
                    }
                },
                _ => assert!(false)
            };

            test_signature_and_corruption(&signed_tx, true, false);
            test_signature_and_corruption(&signed_tx, false, true);
        }
    } 
    
    #[test]
    fn tx_stacks_transaction_sign_verify_standard_p2sh() {
        let privk_1 = StacksPrivateKey::from_hex("6d430bb91222408e7706c9001cfaeb91b08c2be6d5ac95779ab52c6b431950e001").unwrap();
        let privk_2 = StacksPrivateKey::from_hex("2a584d899fed1d24e26b524f202763c8ab30260167429f157f1c119f550fa6af01").unwrap();
        let privk_3 = StacksPrivateKey::from_hex("d5200dee706ee53ae98a03fba6cf4fdcc5084c30cfa9e1b3462dcdeaa3e0f1d201").unwrap();

        let pubk_1 = StacksPublicKey::from_private(&privk_1);
        let pubk_2 = StacksPublicKey::from_private(&privk_2);
        let pubk_3 = StacksPublicKey::from_private(&privk_3);

        let origin_auth = TransactionAuth::Standard(TransactionSpendingCondition::new_multisig_p2sh(2, vec![pubk_1.clone(), pubk_2.clone(), pubk_3.clone()]).unwrap());

        let origin_address = origin_auth.origin().address_mainnet();
        assert_eq!(origin_address, StacksAddress { version: C32_ADDRESS_VERSION_MAINNET_MULTISIG, bytes: Hash160::from_hex("a23ea89d6529ac48ac766f720e480beec7f19273").unwrap() });

        let txs = tx_stacks_transaction_test_txs(&origin_auth);

        for tx in txs {
            assert_eq!(tx.auth().origin().num_signatures(), 0);

            let mut tx_signer = StacksTransactionSigner::new(&tx);
            tx_signer.sign_origin(&privk_1).unwrap();
            tx_signer.sign_origin(&privk_2).unwrap();
            tx_signer.append_origin(&pubk_3).unwrap();
            let mut signed_tx = tx_signer.get_tx().unwrap();
            
            check_oversign_origin_multisig(&mut signed_tx);
            check_sign_no_sponsor(&mut signed_tx);

            assert_eq!(signed_tx.auth().origin().num_signatures(), 2);

            // tx and signed_tx are otherwise equal
            assert_eq!(tx.version, signed_tx.version);
            assert_eq!(tx.get_fee_rate(), signed_tx.get_fee_rate());
            assert_eq!(tx.get_origin_nonce(), signed_tx.get_origin_nonce());
            assert_eq!(tx.get_sponsor_nonce(), signed_tx.get_sponsor_nonce());
            assert_eq!(tx.anchor_mode, signed_tx.anchor_mode);
            assert_eq!(tx.post_condition_mode, signed_tx.post_condition_mode);
            assert_eq!(tx.post_conditions, signed_tx.post_conditions);
            assert_eq!(tx.payload, signed_tx.payload);

            // auth is standard and first two auth fields are signatures for compressed keys.
            // third field is the third public key
            match signed_tx.auth {
                TransactionAuth::Standard(ref origin) => {
                    match origin {
                        TransactionSpendingCondition::Multisig(ref data) => {
                            assert_eq!(data.signer, origin_address.bytes);
                            assert_eq!(data.fields.len(), 3);
                            assert!(data.fields[0].is_signature());
                            assert!(data.fields[1].is_signature());
                            assert!(data.fields[2].is_public_key());

                            assert_eq!(data.fields[0].as_signature().unwrap().0, TransactionPublicKeyEncoding::Compressed);
                            assert_eq!(data.fields[1].as_signature().unwrap().0, TransactionPublicKeyEncoding::Compressed);
                            assert_eq!(data.fields[2].as_public_key().unwrap(), pubk_3);
                        },
                        _ => assert!(false)
                    }
                },
                _ => assert!(false)
            };

            test_signature_and_corruption(&signed_tx, true, false);
        }
    } 
    
    #[test]
    fn tx_stacks_transaction_sign_verify_sponsored_p2sh() {
        let origin_privk = StacksPrivateKey::from_hex("807bbe9e471ac976592cc35e3056592ecc0f778ee653fced3b491a122dd8d59701").unwrap();

        let privk_1 = StacksPrivateKey::from_hex("6d430bb91222408e7706c9001cfaeb91b08c2be6d5ac95779ab52c6b431950e001").unwrap();
        let privk_2 = StacksPrivateKey::from_hex("2a584d899fed1d24e26b524f202763c8ab30260167429f157f1c119f550fa6af01").unwrap();
        let privk_3 = StacksPrivateKey::from_hex("d5200dee706ee53ae98a03fba6cf4fdcc5084c30cfa9e1b3462dcdeaa3e0f1d201").unwrap();

        let pubk_1 = StacksPublicKey::from_private(&privk_1);
        let pubk_2 = StacksPublicKey::from_private(&privk_2);
        let pubk_3 = StacksPublicKey::from_private(&privk_3);

        let random_sponsor = StacksPrivateKey::new();       // what the origin sees

        let auth = TransactionAuth::Sponsored(
            TransactionSpendingCondition::new_singlesig_p2pkh(StacksPublicKey::from_private(&origin_privk)).unwrap(),
            TransactionSpendingCondition::new_singlesig_p2pkh(StacksPublicKey::from_private(&random_sponsor)).unwrap(),
        );
        
        let real_sponsor = TransactionSpendingCondition::new_multisig_p2sh(2, vec![pubk_1.clone(), pubk_2.clone(), pubk_3.clone()]).unwrap();

        let origin_address = auth.origin().address_mainnet();
        let sponsor_address = real_sponsor.address_mainnet();
        
        assert_eq!(origin_address, StacksAddress { version: C32_ADDRESS_VERSION_MAINNET_SINGLESIG, bytes: Hash160::from_hex("3597aaa4bde720be93e3829aae24e76e7fcdfd3e").unwrap() });
        assert_eq!(sponsor_address, StacksAddress { version: C32_ADDRESS_VERSION_MAINNET_MULTISIG, bytes: Hash160::from_hex("a23ea89d6529ac48ac766f720e480beec7f19273").unwrap() });

        let txs = tx_stacks_transaction_test_txs(&auth);

        for mut tx in txs {
            assert_eq!(tx.auth().origin().num_signatures(), 0);
            assert_eq!(tx.auth().sponsor().unwrap().num_signatures(), 0);

            tx.set_fee_rate(123);
            tx.set_sponsor_nonce(456).unwrap();
            let mut tx_signer = StacksTransactionSigner::new(&tx);

            tx_signer.sign_origin(&origin_privk).unwrap();

            // sponsor sets and pays fee after origin signs
            let mut origin_tx = tx_signer.get_tx_incomplete();
            origin_tx.auth.set_sponsor(real_sponsor.clone()).unwrap();
            origin_tx.set_fee_rate(456);
            origin_tx.set_sponsor_nonce(789).unwrap();
            tx_signer.resume(&origin_tx);

            tx_signer.sign_sponsor(&privk_1).unwrap();
            tx_signer.sign_sponsor(&privk_2).unwrap();
            tx_signer.append_sponsor(&pubk_3).unwrap();
            
            tx.set_fee_rate(456);
            tx.set_sponsor_nonce(789).unwrap();
            let mut signed_tx = tx_signer.get_tx().unwrap();

            check_oversign_origin_singlesig(&mut signed_tx);
            check_oversign_sponsor_multisig(&mut signed_tx);

            assert_eq!(signed_tx.auth().origin().num_signatures(), 1);
            assert_eq!(signed_tx.auth().sponsor().unwrap().num_signatures(), 2);

            // tx and signed_tx are otherwise equal
            assert_eq!(tx.version, signed_tx.version);
            assert_eq!(tx.chain_id, signed_tx.chain_id);
            assert_eq!(tx.get_fee_rate(), signed_tx.get_fee_rate());
            assert_eq!(tx.get_origin_nonce(), signed_tx.get_origin_nonce());
            assert_eq!(tx.get_sponsor_nonce(), signed_tx.get_sponsor_nonce());
            assert_eq!(tx.anchor_mode, signed_tx.anchor_mode);
            assert_eq!(tx.post_condition_mode, signed_tx.post_condition_mode);
            assert_eq!(tx.post_conditions, signed_tx.post_conditions);
            assert_eq!(tx.payload, signed_tx.payload);

            // auth is standard and first two auth fields are signatures for compressed keys.
            // third field is the third public key
            match signed_tx.auth {
                TransactionAuth::Sponsored(ref origin, ref sponsor) => {
                    match origin {
                        TransactionSpendingCondition::Singlesig(ref data) => {
                            assert_eq!(data.key_encoding, TransactionPublicKeyEncoding::Compressed);
                            assert_eq!(data.signer, origin_address.bytes);
                        },
                        _ => assert!(false)
                    }
                    match sponsor {
                        TransactionSpendingCondition::Multisig(ref data) => {
                            assert_eq!(data.signer, sponsor_address.bytes);
                            assert_eq!(data.fields.len(), 3);
                            assert!(data.fields[0].is_signature());
                            assert!(data.fields[1].is_signature());
                            assert!(data.fields[2].is_public_key());

                            assert_eq!(data.fields[0].as_signature().unwrap().0, TransactionPublicKeyEncoding::Compressed);
                            assert_eq!(data.fields[1].as_signature().unwrap().0, TransactionPublicKeyEncoding::Compressed);
                            assert_eq!(data.fields[2].as_public_key().unwrap(), pubk_3);
                        },
                        _ => assert!(false)
                    }
                },
                _ => assert!(false)
            };

            test_signature_and_corruption(&signed_tx, true, false);
            test_signature_and_corruption(&signed_tx, false, true);
        }
    } 
    
    #[test]
    fn tx_stacks_transaction_sign_verify_standard_p2sh_uncompressed() {
        let privk_1 = StacksPrivateKey::from_hex("6d430bb91222408e7706c9001cfaeb91b08c2be6d5ac95779ab52c6b431950e0").unwrap();
        let privk_2 = StacksPrivateKey::from_hex("2a584d899fed1d24e26b524f202763c8ab30260167429f157f1c119f550fa6af").unwrap();
        let privk_3 = StacksPrivateKey::from_hex("d5200dee706ee53ae98a03fba6cf4fdcc5084c30cfa9e1b3462dcdeaa3e0f1d2").unwrap();

        let pubk_1 = StacksPublicKey::from_private(&privk_1);
        let pubk_2 = StacksPublicKey::from_private(&privk_2);
        let pubk_3 = StacksPublicKey::from_private(&privk_3);

        let auth = TransactionAuth::Standard(TransactionSpendingCondition::new_multisig_p2sh(2, vec![pubk_1.clone(), pubk_2.clone(), pubk_3.clone()]).unwrap());

        let origin_address = auth.origin().address_mainnet();
        
        assert_eq!(origin_address, StacksAddress { version: C32_ADDRESS_VERSION_MAINNET_MULTISIG, bytes: Hash160::from_hex("73a8b4a751a678fe83e9d35ce301371bb3d397f7").unwrap() });
        
        let txs = tx_stacks_transaction_test_txs(&auth);

        for tx in txs {
            assert_eq!(tx.auth().origin().num_signatures(), 0);

            let mut tx_signer = StacksTransactionSigner::new(&tx);

            tx_signer.sign_origin(&privk_1).unwrap();
            tx_signer.sign_origin(&privk_2).unwrap();
            tx_signer.append_origin(&pubk_3).unwrap();
            
            let mut signed_tx = tx_signer.get_tx().unwrap(); 
            
            check_oversign_origin_multisig(&mut signed_tx);
            check_sign_no_sponsor(&mut signed_tx);

            assert_eq!(signed_tx.auth().origin().num_signatures(), 2);

            // tx and signed_tx are otherwise equal
            assert_eq!(tx.version, signed_tx.version);
            assert_eq!(tx.chain_id, signed_tx.chain_id);
            assert_eq!(tx.get_fee_rate(), signed_tx.get_fee_rate());
            assert_eq!(tx.get_origin_nonce(), signed_tx.get_origin_nonce());
            assert_eq!(tx.get_sponsor_nonce(), signed_tx.get_sponsor_nonce());
            assert_eq!(tx.anchor_mode, signed_tx.anchor_mode);
            assert_eq!(tx.post_condition_mode, signed_tx.post_condition_mode);
            assert_eq!(tx.post_conditions, signed_tx.post_conditions);
            assert_eq!(tx.payload, signed_tx.payload);

            // auth is standard and first two auth fields are signatures for uncompressed keys.
            // third field is the third public key
            match signed_tx.auth {
                TransactionAuth::Standard(ref origin) => {
                    match origin {
                        TransactionSpendingCondition::Multisig(ref data) => {
                            assert_eq!(data.signer, origin_address.bytes);
                            assert_eq!(data.fields.len(), 3);
                            assert!(data.fields[0].is_signature());
                            assert!(data.fields[1].is_signature());
                            assert!(data.fields[2].is_public_key());

                            assert_eq!(data.fields[0].as_signature().unwrap().0, TransactionPublicKeyEncoding::Uncompressed);
                            assert_eq!(data.fields[1].as_signature().unwrap().0, TransactionPublicKeyEncoding::Uncompressed);
                            assert_eq!(data.fields[2].as_public_key().unwrap(), pubk_3);
                        },
                        _ => assert!(false)
                    }
                },
                _ => assert!(false)
            };

            test_signature_and_corruption(&signed_tx, true, false);
        }
    } 
    
    #[test]
    fn tx_stacks_transaction_sign_verify_sponsored_p2sh_uncompressed() {
        let origin_privk = StacksPrivateKey::from_hex("807bbe9e471ac976592cc35e3056592ecc0f778ee653fced3b491a122dd8d59701").unwrap();

        let privk_1 = StacksPrivateKey::from_hex("6d430bb91222408e7706c9001cfaeb91b08c2be6d5ac95779ab52c6b431950e0").unwrap();
        let privk_2 = StacksPrivateKey::from_hex("2a584d899fed1d24e26b524f202763c8ab30260167429f157f1c119f550fa6af").unwrap();
        let privk_3 = StacksPrivateKey::from_hex("d5200dee706ee53ae98a03fba6cf4fdcc5084c30cfa9e1b3462dcdeaa3e0f1d2").unwrap();

        let pubk_1 = StacksPublicKey::from_private(&privk_1);
        let pubk_2 = StacksPublicKey::from_private(&privk_2);
        let pubk_3 = StacksPublicKey::from_private(&privk_3);
        
        let random_sponsor = StacksPrivateKey::new();       // what the origin sees

        let auth = TransactionAuth::Sponsored(
            TransactionSpendingCondition::new_singlesig_p2pkh(StacksPublicKey::from_private(&origin_privk)).unwrap(),
            TransactionSpendingCondition::new_singlesig_p2pkh(StacksPublicKey::from_private(&random_sponsor)).unwrap(),
        );
        
        let real_sponsor = TransactionSpendingCondition::new_multisig_p2sh(2, vec![pubk_1.clone(), pubk_2.clone(), pubk_3.clone()]).unwrap();

        let origin_address = auth.origin().address_mainnet();
        let sponsor_address = real_sponsor.address_mainnet();
        
        assert_eq!(origin_address, StacksAddress { version: C32_ADDRESS_VERSION_MAINNET_SINGLESIG, bytes: Hash160::from_hex("3597aaa4bde720be93e3829aae24e76e7fcdfd3e").unwrap() });
        assert_eq!(sponsor_address, StacksAddress { version: C32_ADDRESS_VERSION_MAINNET_MULTISIG, bytes: Hash160::from_hex("73a8b4a751a678fe83e9d35ce301371bb3d397f7").unwrap() });
        
        let txs = tx_stacks_transaction_test_txs(&auth);

        for mut tx in txs {
            assert_eq!(tx.auth().origin().num_signatures(), 0);
            assert_eq!(tx.auth().sponsor().unwrap().num_signatures(), 0);

            tx.set_fee_rate(123);
            tx.set_sponsor_nonce(456).unwrap();
            let mut tx_signer = StacksTransactionSigner::new(&tx);

            tx_signer.sign_origin(&origin_privk).unwrap();
            
            // sponsor sets and pays fee after origin signs
            let mut origin_tx = tx_signer.get_tx_incomplete();
            origin_tx.auth.set_sponsor(real_sponsor.clone()).unwrap();
            origin_tx.set_fee_rate(456);
            origin_tx.set_sponsor_nonce(789).unwrap();
            tx_signer.resume(&origin_tx);

            tx_signer.sign_sponsor(&privk_1).unwrap();
            tx_signer.sign_sponsor(&privk_2).unwrap();
            tx_signer.append_sponsor(&pubk_3).unwrap();
            
            tx.set_fee_rate(456);
            tx.set_sponsor_nonce(789).unwrap();
            let mut signed_tx = tx_signer.get_tx().unwrap(); 
            
            check_oversign_origin_singlesig(&mut signed_tx);
            check_oversign_sponsor_multisig(&mut signed_tx);

            assert_eq!(signed_tx.auth().origin().num_signatures(), 1);
            assert_eq!(signed_tx.auth().sponsor().unwrap().num_signatures(), 2);

            // tx and signed_tx are otherwise equal
            assert_eq!(tx.version, signed_tx.version);
            assert_eq!(tx.get_fee_rate(), signed_tx.get_fee_rate());
            assert_eq!(tx.get_origin_nonce(), signed_tx.get_origin_nonce());
            assert_eq!(tx.get_sponsor_nonce(), signed_tx.get_sponsor_nonce());
            assert_eq!(tx.anchor_mode, signed_tx.anchor_mode);
            assert_eq!(tx.post_condition_mode, signed_tx.post_condition_mode);
            assert_eq!(tx.post_conditions, signed_tx.post_conditions);
            assert_eq!(tx.payload, signed_tx.payload);

            // auth is standard and first two auth fields are signatures for uncompressed keys.
            // third field is the third public key
            match signed_tx.auth {
                TransactionAuth::Sponsored(ref origin, ref sponsor) => {
                    match origin {
                        TransactionSpendingCondition::Singlesig(ref data) => {
                            assert_eq!(data.key_encoding, TransactionPublicKeyEncoding::Compressed);
                            assert_eq!(data.signer, origin_address.bytes);
                        },
                        _ => assert!(false)
                    }
                    match sponsor {
                        TransactionSpendingCondition::Multisig(ref data) => {
                            assert_eq!(data.signer, sponsor_address.bytes);
                            assert_eq!(data.fields.len(), 3);
                            assert!(data.fields[0].is_signature());
                            assert!(data.fields[1].is_signature());
                            assert!(data.fields[2].is_public_key());

                            assert_eq!(data.fields[0].as_signature().unwrap().0, TransactionPublicKeyEncoding::Uncompressed);
                            assert_eq!(data.fields[1].as_signature().unwrap().0, TransactionPublicKeyEncoding::Uncompressed);
                            assert_eq!(data.fields[2].as_public_key().unwrap(), pubk_3);
                        },
                        _ => assert!(false)
                    }
                },
                _ => assert!(false)
            };

            test_signature_and_corruption(&signed_tx, true, false);
            test_signature_and_corruption(&signed_tx, false, true);
        }
    } 
    
    #[test]
    fn tx_stacks_transaction_sign_verify_standard_p2sh_mixed() {
        let privk_1 = StacksPrivateKey::from_hex("6d430bb91222408e7706c9001cfaeb91b08c2be6d5ac95779ab52c6b431950e001").unwrap();
        let privk_2 = StacksPrivateKey::from_hex("2a584d899fed1d24e26b524f202763c8ab30260167429f157f1c119f550fa6af").unwrap();
        let privk_3 = StacksPrivateKey::from_hex("d5200dee706ee53ae98a03fba6cf4fdcc5084c30cfa9e1b3462dcdeaa3e0f1d2").unwrap();

        let pubk_1 = StacksPublicKey::from_private(&privk_1);
        let pubk_2 = StacksPublicKey::from_private(&privk_2);
        let pubk_3 = StacksPublicKey::from_private(&privk_3);

        let origin_auth = TransactionAuth::Standard(TransactionSpendingCondition::new_multisig_p2sh(2, vec![pubk_1.clone(), pubk_2.clone(), pubk_3.clone()]).unwrap());
        
        let origin_address = origin_auth.origin().address_mainnet();
        assert_eq!(origin_address, StacksAddress { version: C32_ADDRESS_VERSION_MAINNET_MULTISIG, bytes: Hash160::from_hex("2136367c9c740e7dbed8795afdf8a6d273096718").unwrap() });
        
        let txs = tx_stacks_transaction_test_txs(&origin_auth);

        for tx in txs {
            assert_eq!(tx.auth().origin().num_signatures(), 0);

            let mut tx_signer = StacksTransactionSigner::new(&tx);
            tx_signer.sign_origin(&privk_1).unwrap();
            tx_signer.append_origin(&pubk_2).unwrap();
            tx_signer.sign_origin(&privk_3).unwrap();
            let mut signed_tx = tx_signer.get_tx().unwrap();

            check_oversign_origin_multisig(&mut signed_tx);
            check_sign_no_sponsor(&mut signed_tx);

            assert_eq!(signed_tx.auth().origin().num_signatures(), 2);

            // tx and signed_tx are otherwise equal
            assert_eq!(tx.version, signed_tx.version);
            assert_eq!(tx.get_fee_rate(), signed_tx.get_fee_rate());
            assert_eq!(tx.get_origin_nonce(), signed_tx.get_origin_nonce());
            assert_eq!(tx.get_sponsor_nonce(), signed_tx.get_sponsor_nonce());
            assert_eq!(tx.anchor_mode, signed_tx.anchor_mode);
            assert_eq!(tx.post_condition_mode, signed_tx.post_condition_mode);
            assert_eq!(tx.post_conditions, signed_tx.post_conditions);
            assert_eq!(tx.payload, signed_tx.payload);

            // auth is standard and first & third auth fields are signatures for (un)compressed keys.
            // 2nd field is the 2nd public key
            match signed_tx.auth {
                TransactionAuth::Standard(ref origin) => {
                    match origin {
                        TransactionSpendingCondition::Multisig(ref data) => {
                            assert_eq!(data.signer, origin_address.bytes);
                            assert_eq!(data.fields.len(), 3);
                            assert!(data.fields[0].is_signature());
                            assert!(data.fields[1].is_public_key());
                            assert!(data.fields[2].is_signature());

                            assert_eq!(data.fields[0].as_signature().unwrap().0, TransactionPublicKeyEncoding::Compressed);
                            assert_eq!(data.fields[1].as_public_key().unwrap(), pubk_2);
                            assert_eq!(data.fields[2].as_signature().unwrap().0, TransactionPublicKeyEncoding::Uncompressed);
                        },
                        _ => assert!(false)
                    }
                },
                _ => assert!(false)
            };

            test_signature_and_corruption(&signed_tx, true, false);
        }
    } 
    
    #[test]
    fn tx_stacks_transaction_sign_verify_sponsored_p2sh_mixed() {
        let origin_privk = StacksPrivateKey::from_hex("807bbe9e471ac976592cc35e3056592ecc0f778ee653fced3b491a122dd8d59701").unwrap();

        let privk_1 = StacksPrivateKey::from_hex("6d430bb91222408e7706c9001cfaeb91b08c2be6d5ac95779ab52c6b431950e001").unwrap();
        let privk_2 = StacksPrivateKey::from_hex("2a584d899fed1d24e26b524f202763c8ab30260167429f157f1c119f550fa6af").unwrap();
        let privk_3 = StacksPrivateKey::from_hex("d5200dee706ee53ae98a03fba6cf4fdcc5084c30cfa9e1b3462dcdeaa3e0f1d2").unwrap();

        let pubk_1 = StacksPublicKey::from_private(&privk_1);
        let pubk_2 = StacksPublicKey::from_private(&privk_2);
        let pubk_3 = StacksPublicKey::from_private(&privk_3);
        
        let random_sponsor = StacksPrivateKey::new();       // what the origin sees

        let auth = TransactionAuth::Sponsored(
            TransactionSpendingCondition::new_singlesig_p2pkh(StacksPublicKey::from_private(&origin_privk)).unwrap(),
            TransactionSpendingCondition::new_singlesig_p2pkh(StacksPublicKey::from_private(&random_sponsor)).unwrap(),
        );
        
        let real_sponsor = TransactionSpendingCondition::new_multisig_p2sh(2, vec![pubk_1.clone(), pubk_2.clone(), pubk_3.clone()]).unwrap();

        let origin_address = auth.origin().address_mainnet();
        let sponsor_address = real_sponsor.address_mainnet();

        assert_eq!(origin_address, StacksAddress { version: C32_ADDRESS_VERSION_MAINNET_SINGLESIG, bytes: Hash160::from_hex("3597aaa4bde720be93e3829aae24e76e7fcdfd3e").unwrap() });
        assert_eq!(sponsor_address, StacksAddress { version: C32_ADDRESS_VERSION_MAINNET_MULTISIG, bytes: Hash160::from_hex("2136367c9c740e7dbed8795afdf8a6d273096718").unwrap() });
        
        let txs = tx_stacks_transaction_test_txs(&auth);

        for mut tx in txs {
            assert_eq!(tx.auth().origin().num_signatures(), 0);
            assert_eq!(tx.auth().sponsor().unwrap().num_signatures(), 0);

            tx.set_fee_rate(123);
            tx.set_sponsor_nonce(456).unwrap();
            let mut tx_signer = StacksTransactionSigner::new(&tx);

            tx_signer.sign_origin(&origin_privk).unwrap();

            // sponsor sets and pays fee after origin signs
            let mut origin_tx = tx_signer.get_tx_incomplete();
            origin_tx.auth.set_sponsor(real_sponsor.clone()).unwrap();
            origin_tx.set_fee_rate(456);
            origin_tx.set_sponsor_nonce(789).unwrap();
            tx_signer.resume(&origin_tx);

            tx_signer.sign_sponsor(&privk_1).unwrap();
            tx_signer.append_sponsor(&pubk_2).unwrap();
            tx_signer.sign_sponsor(&privk_3).unwrap();
            
            tx.set_fee_rate(456);
            tx.set_sponsor_nonce(789).unwrap();
            let mut signed_tx = tx_signer.get_tx().unwrap();
            
            check_oversign_origin_singlesig(&mut signed_tx);
            check_oversign_sponsor_multisig(&mut signed_tx);

            assert_eq!(signed_tx.auth().origin().num_signatures(), 1);
            assert_eq!(signed_tx.auth().sponsor().unwrap().num_signatures(), 2);

            // tx and signed_tx are otherwise equal
            assert_eq!(tx.version, signed_tx.version);
            assert_eq!(tx.chain_id, signed_tx.chain_id);
            assert_eq!(tx.get_fee_rate(), signed_tx.get_fee_rate());
            assert_eq!(tx.get_origin_nonce(), signed_tx.get_origin_nonce());
            assert_eq!(tx.get_sponsor_nonce(), signed_tx.get_sponsor_nonce());
            assert_eq!(tx.anchor_mode, signed_tx.anchor_mode);
            assert_eq!(tx.post_condition_mode, signed_tx.post_condition_mode);
            assert_eq!(tx.post_conditions, signed_tx.post_conditions);
            assert_eq!(tx.payload, signed_tx.payload);

            // auth is standard and first & third auth fields are signatures for (un)compressed keys.
            // 2nd field is the 2nd public key
            match signed_tx.auth {
                TransactionAuth::Sponsored(ref origin, ref sponsor) => {
                    match origin {
                        TransactionSpendingCondition::Singlesig(ref data) => {
                            assert_eq!(data.key_encoding, TransactionPublicKeyEncoding::Compressed);
                            assert_eq!(data.signer, origin_address.bytes);
                        },
                        _ => assert!(false)
                    }
                    match sponsor {
                        TransactionSpendingCondition::Multisig(ref data) => {
                            assert_eq!(data.signer, sponsor_address.bytes);
                            assert_eq!(data.fields.len(), 3);
                            assert!(data.fields[0].is_signature());
                            assert!(data.fields[1].is_public_key());
                            assert!(data.fields[2].is_signature());

                            assert_eq!(data.fields[0].as_signature().unwrap().0, TransactionPublicKeyEncoding::Compressed);
                            assert_eq!(data.fields[1].as_public_key().unwrap(), pubk_2);
                            assert_eq!(data.fields[2].as_signature().unwrap().0, TransactionPublicKeyEncoding::Uncompressed);
                        },
                        _ => assert!(false)
                    }
                },
                _ => assert!(false)
            };

            test_signature_and_corruption(&signed_tx, true, false);
            test_signature_and_corruption(&signed_tx, false, true);
        }
    } 
     
    #[test]
    fn tx_stacks_transaction_sign_verify_standard_p2wpkh() {
        let privk = StacksPrivateKey::from_hex("6d430bb91222408e7706c9001cfaeb91b08c2be6d5ac95779ab52c6b431950e001").unwrap();
        let origin_auth = TransactionAuth::Standard(TransactionSpendingCondition::new_singlesig_p2wpkh(StacksPublicKey::from_private(&privk)).unwrap());

        let origin_address = origin_auth.origin().address_mainnet();
        assert_eq!(origin_address, StacksAddress { version: C32_ADDRESS_VERSION_MAINNET_MULTISIG, bytes: Hash160::from_hex("f15fa5c59d14ffcb615fa6153851cd802bb312d2").unwrap() });
        
        let txs = tx_stacks_transaction_test_txs(&origin_auth);

        for tx in txs {
            assert_eq!(tx.auth().origin().num_signatures(), 0);

            let mut tx_signer = StacksTransactionSigner::new(&tx);
            tx_signer.sign_origin(&privk).unwrap();
            let mut signed_tx = tx_signer.get_tx().unwrap();

            // try to over-sign
            check_oversign_origin_singlesig(&mut signed_tx);
            check_sign_no_sponsor(&mut signed_tx);
            
            assert_eq!(signed_tx.auth().origin().num_signatures(), 1);

            // tx and signed_tx are otherwise equal
            assert_eq!(tx.version, signed_tx.version);
            assert_eq!(tx.get_fee_rate(), signed_tx.get_fee_rate());
            assert_eq!(tx.get_origin_nonce(), signed_tx.get_origin_nonce());
            assert_eq!(tx.get_sponsor_nonce(), signed_tx.get_sponsor_nonce());
            assert_eq!(tx.anchor_mode, signed_tx.anchor_mode);
            assert_eq!(tx.post_condition_mode, signed_tx.post_condition_mode);
            assert_eq!(tx.post_conditions, signed_tx.post_conditions);
            assert_eq!(tx.payload, signed_tx.payload);
            
            // auth is standard and public key is compressed
            match signed_tx.auth {
                TransactionAuth::Standard(ref origin) => {
                    match origin {
                        TransactionSpendingCondition::Singlesig(ref data) => {
                            assert_eq!(data.signer, origin_address.bytes);
                            assert_eq!(data.key_encoding, TransactionPublicKeyEncoding::Compressed);
                        },
                        _ => assert!(false)
                    }
                },
                _ => assert!(false)
            };

            test_signature_and_corruption(&signed_tx, true, false);
        }
    }
    
    #[test]
    fn tx_stacks_transaction_sign_verify_sponsored_p2wpkh() {
        let origin_privk = StacksPrivateKey::from_hex("807bbe9e471ac976592cc35e3056592ecc0f778ee653fced3b491a122dd8d59701").unwrap();
        let privk = StacksPrivateKey::from_hex("6d430bb91222408e7706c9001cfaeb91b08c2be6d5ac95779ab52c6b431950e001").unwrap();

        let random_sponsor = StacksPrivateKey::new();

        let auth = TransactionAuth::Sponsored(
            TransactionSpendingCondition::new_singlesig_p2pkh(StacksPublicKey::from_private(&origin_privk)).unwrap(),
            TransactionSpendingCondition::new_singlesig_p2pkh(StacksPublicKey::from_private(&random_sponsor)).unwrap()
        );

        let real_sponsor = TransactionSpendingCondition::new_singlesig_p2wpkh(StacksPublicKey::from_private(&privk)).unwrap();

        let origin_address = auth.origin().address_mainnet();
        let sponsor_address = real_sponsor.address_mainnet();

        assert_eq!(origin_address, StacksAddress { version: C32_ADDRESS_VERSION_MAINNET_SINGLESIG, bytes: Hash160::from_hex("3597aaa4bde720be93e3829aae24e76e7fcdfd3e").unwrap() });
        assert_eq!(sponsor_address, StacksAddress { version: C32_ADDRESS_VERSION_MAINNET_MULTISIG, bytes: Hash160::from_hex("f15fa5c59d14ffcb615fa6153851cd802bb312d2").unwrap() });
        
        let txs = tx_stacks_transaction_test_txs(&auth);

        for mut tx in txs {
            assert_eq!(tx.auth().origin().num_signatures(), 0);
            assert_eq!(tx.auth().sponsor().unwrap().num_signatures(), 0);

            tx.set_fee_rate(123);
            tx.set_sponsor_nonce(456).unwrap();
            let mut tx_signer = StacksTransactionSigner::new(&tx);
            
            tx_signer.sign_origin(&origin_privk).unwrap();

            // sponsor sets and pays fee after origin signs
            let mut origin_tx = tx_signer.get_tx_incomplete();
            origin_tx.auth.set_sponsor(real_sponsor.clone()).unwrap();
            origin_tx.set_fee_rate(456);
            origin_tx.set_sponsor_nonce(789).unwrap();
            tx_signer.resume(&origin_tx);

            tx_signer.sign_sponsor(&privk).unwrap();

            tx.set_fee_rate(456);
            tx.set_sponsor_nonce(789).unwrap();
            let mut signed_tx = tx_signer.get_tx().unwrap();

            // try to over-sign
            check_oversign_origin_singlesig(&mut signed_tx);
            check_oversign_sponsor_singlesig(&mut signed_tx);
            
            assert_eq!(signed_tx.auth().origin().num_signatures(), 1);
            assert_eq!(signed_tx.auth().sponsor().unwrap().num_signatures(), 1);

            // tx and signed_tx are otherwise equal
            assert_eq!(tx.version, signed_tx.version);
            assert_eq!(tx.get_fee_rate(), signed_tx.get_fee_rate());
            assert_eq!(tx.get_origin_nonce(), signed_tx.get_origin_nonce());
            assert_eq!(tx.get_sponsor_nonce(), signed_tx.get_sponsor_nonce());
            assert_eq!(tx.anchor_mode, signed_tx.anchor_mode);
            assert_eq!(tx.post_condition_mode, signed_tx.post_condition_mode);
            assert_eq!(tx.post_conditions, signed_tx.post_conditions);
            assert_eq!(tx.payload, signed_tx.payload);
            
            // auth is standard and public key is compressed
            match signed_tx.auth {
                TransactionAuth::Sponsored(ref origin, ref sponsor) => {
                    match origin {
                        TransactionSpendingCondition::Singlesig(ref data) => {
                            assert_eq!(data.key_encoding, TransactionPublicKeyEncoding::Compressed);
                            assert_eq!(data.signer, origin_address.bytes);
                        },
                        _ => assert!(false)
                    }
                    match sponsor {
                        TransactionSpendingCondition::Singlesig(ref data) => {
                            assert_eq!(data.signer, sponsor_address.bytes);
                            assert_eq!(data.key_encoding, TransactionPublicKeyEncoding::Compressed);
                        },
                        _ => assert!(false)
                    }
                },
                _ => assert!(false)
            };

            test_signature_and_corruption(&signed_tx, true, false);
            test_signature_and_corruption(&signed_tx, false, true);
        }
    }

    #[test]
    fn tx_stacks_transaction_sign_verify_standard_p2wsh() {
        let privk_1 = StacksPrivateKey::from_hex("6d430bb91222408e7706c9001cfaeb91b08c2be6d5ac95779ab52c6b431950e001").unwrap();
        let privk_2 = StacksPrivateKey::from_hex("2a584d899fed1d24e26b524f202763c8ab30260167429f157f1c119f550fa6af01").unwrap();
        let privk_3 = StacksPrivateKey::from_hex("d5200dee706ee53ae98a03fba6cf4fdcc5084c30cfa9e1b3462dcdeaa3e0f1d201").unwrap();

        let pubk_1 = StacksPublicKey::from_private(&privk_1);
        let pubk_2 = StacksPublicKey::from_private(&privk_2);
        let pubk_3 = StacksPublicKey::from_private(&privk_3);

        let origin_auth = TransactionAuth::Standard(TransactionSpendingCondition::new_multisig_p2wsh(2, vec![pubk_1.clone(), pubk_2.clone(), pubk_3.clone()]).unwrap());

        let origin_address = origin_auth.origin().address_mainnet();
        assert_eq!(origin_address, StacksAddress { version: C32_ADDRESS_VERSION_MAINNET_MULTISIG, bytes: Hash160::from_hex("f5cfb61a07fb41a32197da01ce033888f0fe94a7").unwrap() });
        
        let txs = tx_stacks_transaction_test_txs(&origin_auth);

        for tx in txs {
            assert_eq!(tx.auth().origin().num_signatures(), 0);

            let mut tx_signer = StacksTransactionSigner::new(&tx);
            tx_signer.sign_origin(&privk_1).unwrap();
            tx_signer.sign_origin(&privk_2).unwrap();
            tx_signer.append_origin(&pubk_3).unwrap();
            let mut signed_tx = tx_signer.get_tx().unwrap();

            check_oversign_origin_multisig(&mut signed_tx);
            check_oversign_origin_multisig_uncompressed(&mut signed_tx);
            check_sign_no_sponsor(&mut signed_tx);

            assert_eq!(signed_tx.auth().origin().num_signatures(), 2);

            // tx and signed_tx are otherwise equal
            assert_eq!(tx.version, signed_tx.version);
            assert_eq!(tx.get_fee_rate(), signed_tx.get_fee_rate());
            assert_eq!(tx.get_origin_nonce(), signed_tx.get_origin_nonce());
            assert_eq!(tx.get_sponsor_nonce(), signed_tx.get_sponsor_nonce());
            assert_eq!(tx.anchor_mode, signed_tx.anchor_mode);
            assert_eq!(tx.post_condition_mode, signed_tx.post_condition_mode);
            assert_eq!(tx.post_conditions, signed_tx.post_conditions);
            assert_eq!(tx.payload, signed_tx.payload);

            // auth is standard and first two auth fields are signatures for compressed keys.
            // third field is the third public key
            match signed_tx.auth {
                TransactionAuth::Standard(ref origin) => {
                    match origin {
                        TransactionSpendingCondition::Multisig(ref data) => {
                            assert_eq!(data.signer, origin_address.bytes);
                            assert_eq!(data.fields.len(), 3);
                            assert!(data.fields[0].is_signature());
                            assert!(data.fields[1].is_signature());
                            assert!(data.fields[2].is_public_key());

                            assert_eq!(data.fields[0].as_signature().unwrap().0, TransactionPublicKeyEncoding::Compressed);
                            assert_eq!(data.fields[1].as_signature().unwrap().0, TransactionPublicKeyEncoding::Compressed);
                            assert_eq!(data.fields[2].as_public_key().unwrap(), pubk_3);
                        },
                        _ => assert!(false)
                    }
                },
                _ => assert!(false)
            };

            test_signature_and_corruption(&signed_tx, true, false);
        }
    } 

    #[test]
    fn tx_stacks_transaction_sign_verify_sponsored_p2wsh() {
        let origin_privk = StacksPrivateKey::from_hex("807bbe9e471ac976592cc35e3056592ecc0f778ee653fced3b491a122dd8d59701").unwrap();

        let privk_1 = StacksPrivateKey::from_hex("6d430bb91222408e7706c9001cfaeb91b08c2be6d5ac95779ab52c6b431950e001").unwrap();
        let privk_2 = StacksPrivateKey::from_hex("2a584d899fed1d24e26b524f202763c8ab30260167429f157f1c119f550fa6af01").unwrap();
        let privk_3 = StacksPrivateKey::from_hex("d5200dee706ee53ae98a03fba6cf4fdcc5084c30cfa9e1b3462dcdeaa3e0f1d201").unwrap();

        let pubk_1 = StacksPublicKey::from_private(&privk_1);
        let pubk_2 = StacksPublicKey::from_private(&privk_2);
        let pubk_3 = StacksPublicKey::from_private(&privk_3);

        let random_sponsor = StacksPrivateKey::new();

        let auth = TransactionAuth::Sponsored(
            TransactionSpendingCondition::new_singlesig_p2pkh(StacksPublicKey::from_private(&origin_privk)).unwrap(),
            TransactionSpendingCondition::new_singlesig_p2pkh(StacksPublicKey::from_private(&random_sponsor)).unwrap()
        );
        
        let real_sponsor = TransactionSpendingCondition::new_multisig_p2wsh(2, vec![pubk_1.clone(), pubk_2.clone(), pubk_3.clone()]).unwrap();

        let origin_address = auth.origin().address_mainnet();
        let sponsor_address = real_sponsor.address_mainnet();

        assert_eq!(origin_address, StacksAddress { version: C32_ADDRESS_VERSION_MAINNET_SINGLESIG, bytes: Hash160::from_hex("3597aaa4bde720be93e3829aae24e76e7fcdfd3e").unwrap() });
        assert_eq!(sponsor_address, StacksAddress { version: C32_ADDRESS_VERSION_MAINNET_MULTISIG, bytes: Hash160::from_hex("f5cfb61a07fb41a32197da01ce033888f0fe94a7").unwrap() });
        
        let txs = tx_stacks_transaction_test_txs(&auth);

        for mut tx in txs {
            assert_eq!(tx.auth().origin().num_signatures(), 0);
            assert_eq!(tx.auth().sponsor().unwrap().num_signatures(), 0);

            tx.set_fee_rate(123);
            tx.set_sponsor_nonce(456).unwrap();
            let mut tx_signer = StacksTransactionSigner::new(&tx);

            tx_signer.sign_origin(&origin_privk).unwrap();
            
            // sponsor sets and pays fee after origin signs
            let mut origin_tx = tx_signer.get_tx_incomplete();
            origin_tx.auth.set_sponsor(real_sponsor.clone()).unwrap();
            origin_tx.set_fee_rate(456);
            origin_tx.set_sponsor_nonce(789).unwrap();
            tx_signer.resume(&origin_tx);

            tx_signer.sign_sponsor(&privk_1).unwrap();
            tx_signer.sign_sponsor(&privk_2).unwrap();
            tx_signer.append_sponsor(&pubk_3).unwrap();

            tx.set_fee_rate(456);
            tx.set_sponsor_nonce(789).unwrap();
            let mut signed_tx = tx_signer.get_tx().unwrap();

            check_oversign_origin_singlesig(&mut signed_tx);
            check_oversign_sponsor_multisig(&mut signed_tx);
            check_oversign_sponsor_multisig_uncompressed(&mut signed_tx);

            assert_eq!(signed_tx.auth().origin().num_signatures(), 1);
            assert_eq!(signed_tx.auth().sponsor().unwrap().num_signatures(), 2);

            // tx and signed_tx are otherwise equal
            assert_eq!(tx.version, signed_tx.version);
            assert_eq!(tx.chain_id, signed_tx.chain_id);
            assert_eq!(tx.get_fee_rate(), signed_tx.get_fee_rate());
            assert_eq!(tx.get_origin_nonce(), signed_tx.get_origin_nonce());
            assert_eq!(tx.get_sponsor_nonce(), signed_tx.get_sponsor_nonce());
            assert_eq!(tx.anchor_mode, signed_tx.anchor_mode);
            assert_eq!(tx.post_condition_mode, signed_tx.post_condition_mode);
            assert_eq!(tx.post_conditions, signed_tx.post_conditions);
            assert_eq!(tx.payload, signed_tx.payload);

            // auth is standard and first two auth fields are signatures for compressed keys.
            // third field is the third public key
            match signed_tx.auth {
                TransactionAuth::Sponsored(ref origin, ref sponsor) => {
                    match origin {
                        TransactionSpendingCondition::Singlesig(ref data) => {
                            assert_eq!(data.key_encoding, TransactionPublicKeyEncoding::Compressed);
                            assert_eq!(data.signer, origin_address.bytes);
                        },
                        _ => assert!(false)
                    }
                    match sponsor {
                        TransactionSpendingCondition::Multisig(ref data) => {
                            assert_eq!(data.signer, sponsor_address.bytes);
                            assert_eq!(data.fields.len(), 3);
                            assert!(data.fields[0].is_signature());
                            assert!(data.fields[1].is_signature());
                            assert!(data.fields[2].is_public_key());

                            assert_eq!(data.fields[0].as_signature().unwrap().0, TransactionPublicKeyEncoding::Compressed);
                            assert_eq!(data.fields[1].as_signature().unwrap().0, TransactionPublicKeyEncoding::Compressed);
                            assert_eq!(data.fields[2].as_public_key().unwrap(), pubk_3);
                        },
                        _ => assert!(false)
                    }
                },
                _ => assert!(false)
            };

            test_signature_and_corruption(&signed_tx, true, false);
            test_signature_and_corruption(&signed_tx, false, true);
        }
    } 
}
