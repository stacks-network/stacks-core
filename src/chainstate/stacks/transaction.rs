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
        let function_args: Vec<ClarityName> = read_next(buf, &mut index, max_size)?;        // TODO: maximum number of arguments?

        // function name must be a literal
        if !StacksString::from(function_name.clone()).is_clarity_literal() {
            return Err(net_error::DeserializeError);
        }

        // the function arguments must all be literals
        for arg in function_args.iter() {
            if !StacksString::from(arg.clone()).is_clarity_literal() {
                return Err(net_error::DeserializeError);
            }
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
        QualifiedContractIdentifier::new(StandardPrincipalData::from_address(&self.address), self.contract_name.clone())
    }

    pub fn try_to_clarity_args(&self) -> Result<Vec<SymbolicExpression>, Error> {
        let contract_id = self.to_clarity_contract_id();
        let mut arguments = vec![];
        for arg in self.function_args.iter() {
            let value = match StacksString::from((*arg).clone()).try_as_clarity_literal() {
                Some(v) => v,
                None => {
                    return Err(Error::InvalidStacksTransaction);
                }
            };
            arguments.push(SymbolicExpression::atom_value(value));
        }
        Ok(arguments)
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
            TransactionPayload::ContractCall(ref cc) => {
                write_next(&mut res, &(TransactionPayloadID::ContractCall as u8));
                let mut body = cc.serialize();
                res.append(&mut body);
            }
            TransactionPayload::SmartContract(ref sc) => {
                write_next(&mut res, &(TransactionPayloadID::SmartContract as u8));
                let mut body = sc.serialize();
                res.append(&mut body)
            }
            TransactionPayload::PoisonMicroblock(ref h1, ref h2) => {
                write_next(&mut res, &(TransactionPayloadID::PoisonMicroblock as u8));
                let mut h1_body = h1.serialize();
                let mut h2_body = h2.serialize();
                res.append(&mut h1_body);
                res.append(&mut h2_body);
            }
        }
        res
    }
    
    fn deserialize(buf: &Vec<u8>, index_ptr: &mut u32, max_size: u32) -> Result<TransactionPayload, net_error> {
        let mut index = *index_ptr;

        let type_id : u8 = read_next(buf, &mut index, max_size)?;
        match type_id {
            x if x == TransactionPayloadID::ContractCall as u8 => {
                let payload = TransactionContractCall::deserialize(buf, &mut index, max_size)?;

                *index_ptr = index;
                Ok(TransactionPayload::ContractCall(payload))
            }
            x if x == TransactionPayloadID::SmartContract as u8 => {
                let payload = TransactionSmartContract::deserialize(buf, &mut index, max_size)?;
                
                *index_ptr = index;
                Ok(TransactionPayload::SmartContract(payload))
            }
            x if x == TransactionPayloadID::PoisonMicroblock as u8 => {
                let h1 = StacksMicroblockHeader::deserialize(buf, &mut index, max_size)?;
                let h2 = StacksMicroblockHeader::deserialize(buf, &mut index, max_size)?;

                // must differ in some field
                if h1 == h2 {
                    return Err(net_error::DeserializeError);
                }

                // must have the same sequence number and block parent
                if h1.sequence != h2.sequence || h1.prev_block != h2.prev_block {
                    return Err(net_error::DeserializeError);
                }

                *index_ptr = index;
                Ok(TransactionPayload::PoisonMicroblock(h1, h2))
            }
            _ => {
                Err(net_error::DeserializeError)
            }
        }
    }
}

impl TransactionPayload {
    pub fn new_contract_call(contract_address: &StacksAddress, contract_name: &str, function_name: &str, args: &Vec<&str>) -> Option<TransactionPayload> {
        let contract_name_str = match ContractName::try_from(contract_name) {
            Ok(s) => s,
            Err(_) => { return None; }
        };

        let function_name_str = match ClarityName::try_from(function_name) {
            Ok(s) => s,
            Err(_) => { return None; }
        };

        let mut arg_strs = Vec::with_capacity(args.len());
        for arg in args {
            let a = match ClarityName::try_from(*arg) {
                Ok(s) => s,
                Err(_) => { return None; }
            };
            arg_strs.push(a);
        }
        
        Some(TransactionPayload::ContractCall(TransactionContractCall {
            address: contract_address.clone(),
            contract_name: contract_name_str, 
            function_name: function_name_str,
            function_args: arg_strs
        }))
    }

    pub fn new_smart_contract(name: &String, contract: &String) -> Option<TransactionPayload> {
        match (ContractName::try_from(name.as_str()), StacksString::from_string(contract)) {
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

impl StacksMessageCodec for TransactionPostCondition {
    fn serialize(&self) -> Vec<u8> {
        let mut ret = vec![];
        match *self {
            TransactionPostCondition::STX(ref fungible_condition, ref amount) => {
                write_next(&mut ret, &(AssetInfoID::STX as u8));
                write_next(&mut ret, &(*fungible_condition as u8));
                write_next(&mut ret, amount);
            },
            TransactionPostCondition::Fungible(ref asset_info, ref fungible_condition, ref amount) => {
                write_next(&mut ret, &(AssetInfoID::FungibleAsset as u8));
                write_next(&mut ret, asset_info);
                write_next(&mut ret, &(*fungible_condition as u8));
                write_next(&mut ret, amount);
            }
            TransactionPostCondition::Nonfungible(ref asset_info, ref asset_value, ref nonfungible_condition) => {
                write_next(&mut ret, &(AssetInfoID::NonfungibleAsset as u8));
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
        match asset_info_id {
            x if x == AssetInfoID::STX as u8 => {
                let condition_u8 : u8 = read_next(buf, &mut index, max_size)?;
                let amount : u64 = read_next(buf, &mut index, max_size)?;

                let condition_code = FungibleConditionCode::from_u8(condition_u8)
                    .ok_or(net_error::DeserializeError)?;

                *index_ptr = index;
                Ok(TransactionPostCondition::STX(condition_code, amount))
            },
            x if x == AssetInfoID::FungibleAsset as u8 => {
                let asset : AssetInfo = read_next(buf, &mut index, max_size)?;
                let condition_u8 : u8 = read_next(buf, &mut index, max_size)?;
                let amount : u64 = read_next(buf, &mut index, max_size)?;

                let condition_code = FungibleConditionCode::from_u8(condition_u8)
                    .ok_or(net_error::DeserializeError)?;

                *index_ptr = index;
                Ok(TransactionPostCondition::Fungible(asset, condition_code, amount))
            },
            x if x == AssetInfoID::NonfungibleAsset as u8 => {
                let asset : AssetInfo = read_next(buf, &mut index, max_size)?;
                let asset_value : StacksString = read_next(buf, &mut index, max_size)?;
                let condition_u8 : u8 = read_next(buf, &mut index, max_size)?;

                let condition_code = NonfungibleConditionCode::from_u8(condition_u8)
                    .ok_or(net_error::DeserializeError)?;

                if !asset_value.is_clarity_literal() {
                    return Err(net_error::DeserializeError);
                }

                *index_ptr = index;
                Ok(TransactionPostCondition::Nonfungible(asset, asset_value, condition_code))
            },
            _ => {
                return Err(net_error::DeserializeError);
            }
        }
    }
}

impl StacksMessageCodec for StacksTransaction {
    fn serialize(&self) -> Vec<u8> {
        let mut ret = vec![];
        let anchor_mode = self.anchor_mode;

        write_next(&mut ret, &(self.version as u8));
        write_next(&mut ret, &self.chain_id);
        write_next(&mut ret, &self.auth);
        write_next(&mut ret, &self.fee);
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
        let fee : u64                   = read_next(buf, &mut index, max_size)?;
        let anchor_mode_u8 : u8         = read_next(buf, &mut index, max_size)?;
        let post_condition_mode_u8 : u8 = read_next(buf, &mut index, max_size)?;
        let post_conditions : Vec<TransactionPostCondition> = read_next(buf, &mut index, max_size)?;
        let payload : TransactionPayload = read_next(buf, &mut index, max_size)?;

        let version = match version_u8 {
            x if x == TransactionVersion::Mainnet as u8 => TransactionVersion::Mainnet,
            x if x == TransactionVersion::Testnet as u8 => TransactionVersion::Testnet,
            _ => {
                return Err(net_error::DeserializeError);
            }
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
                return Err(net_error::DeserializeError);
            }
        };

        // if the payload is a proof of a poisoned microblock stream, then this _must_ be anchored.
        // Otherwise, if the offending leader is the next leader, they can just orphan their proof
        // of malfeasance.
        match payload {
            TransactionPayload::PoisonMicroblock(_, _) => {
                if anchor_mode != TransactionAnchorMode::OnChainOnly {
                    return Err(net_error::DeserializeError);
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
                return Err(net_error::DeserializeError);
            }
        };

        *index_ptr = index;
        Ok(StacksTransaction {
            version,
            chain_id,
            auth,
            fee,
            anchor_mode,
            post_condition_mode,
            post_conditions,
            payload
        })
    }
}

impl StacksTransaction {
    /// Create a new, unsigned transaction and an empty STX fee with no post-conditions.
    pub fn new(version: TransactionVersion, auth: TransactionAuth, payload: TransactionPayload) -> StacksTransaction {
        StacksTransaction {
            version: version,
            chain_id: 0,
            auth: auth,
            fee: 0,
            anchor_mode: TransactionAnchorMode::Any,
            post_condition_mode: TransactionPostConditionMode::Deny,
            post_conditions: vec![],
            payload: payload
        }
    }

    /// Set the transaction fee in STX
    pub fn set_fee(&mut self, tx_fee: u64) -> () {
        self.fee = tx_fee;
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
    pub fn add_postcondition(&mut self, post_condition: TransactionPostCondition) -> () {
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
    /// Return the initial sighash.
    fn sign_begin(&self) -> Txid {
        let mut tx = self.clone();
        tx.auth.clear();
        tx.txid()
    }

    /// begin verifying a transaction
    /// return the initial sighash
    fn verify_begin(&self) -> Txid {
        let mut tx = self.clone();
        tx.auth.clear();
        tx.txid()
    }

    /// Sign a sighash and append the signature and public key to the given spending condition.
    /// Returns the next sighash
    fn sign_and_append(condition: &mut TransactionSpendingCondition, cur_sighash: &Txid, auth_flag: &TransactionAuthFlags, privk: &StacksPrivateKey) -> Result<Txid, net_error> {
        let pubk = StacksPublicKey::from_private(privk);
        let (next_sig, next_sighash) = TransactionSpendingCondition::next_signature(cur_sighash, auth_flag, privk)?;

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
        let pubk = StacksPublicKey::from_private(privk);
        let next_sighash = match self.auth {
            TransactionAuth::Standard(ref mut origin_condition) => {
                StacksTransaction::sign_and_append(origin_condition, cur_sighash, &TransactionAuthFlags::AuthStandard, privk)?
            },
            TransactionAuth::Sponsored(ref mut origin_condition, _) => {
                StacksTransaction::sign_and_append(origin_condition, cur_sighash, &TransactionAuthFlags::AuthSponsored, privk)?
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
        let pubk = StacksPublicKey::from_private(privk);
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
}

impl StacksTransactionSigner {
    pub fn new(tx: &StacksTransaction) -> StacksTransactionSigner {
        StacksTransactionSigner {
            tx: tx.clone(),
            sighash: tx.sign_begin(),
            origin_done: false
        }
    }

    pub fn sign_origin(&mut self, privk: &StacksPrivateKey) -> Result<(), net_error> {
        if self.origin_done {
            // can't sign another origin private key since we started signing sponsors
            return Err(net_error::SigningError("Cannot sign origin after sponsor key".to_string()));
        }

        match self.tx.auth {
            TransactionAuth::Standard(ref origin_condition) => {
                if origin_condition.num_signatures() >= origin_condition.signatures_required() {
                    return Err(net_error::SigningError("Origin would have too many signatures".to_string()));
                }
            },
            TransactionAuth::Sponsored(ref origin_condition, _) => {
                if origin_condition.num_signatures() >= origin_condition.signatures_required() {
                    return Err(net_error::SigningError("Origin would have too many signatures".to_string()));
                }
            }
        }

        let next_sighash = self.tx.sign_next_origin(&self.sighash, privk)?;
        self.sighash = next_sighash;
        Ok(())
    }

    pub fn append_origin(&mut self, pubk: &StacksPublicKey) -> Result<(), net_error> {
        if self.origin_done {
            // can't append another origin key
            return Err(net_error::SigningError("Cannot append public key to origin after sponsor key".to_string()));
        }

        self.tx.append_next_origin(pubk)
    }
    
    pub fn sign_sponsor(&mut self, privk: &StacksPrivateKey) -> Result<(), net_error> {
        match self.tx.auth {
            TransactionAuth::Sponsored(_, ref sponsor_condition) => {
                if sponsor_condition.num_signatures() >= sponsor_condition.signatures_required() {
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

    pub fn complete(&self) -> bool {
        match self.tx.auth {
            TransactionAuth::Standard(ref origin_condition) => {
                origin_condition.num_signatures() >= origin_condition.signatures_required()
            },
            TransactionAuth::Sponsored(ref origin_condition, ref sponsored_condition) => {
                origin_condition.num_signatures() >= origin_condition.signatures_required() &&
                sponsored_condition.num_signatures() >= sponsored_condition.signatures_required() &&
                self.origin_done
            }
        }
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
    use super::*;
    use chainstate::stacks::*;
    use net::*;
    use net::codec::*;
    use net::codec::test::check_codec_and_corruption;

    use chainstate::stacks::StacksPublicKey as PubKey;

    use util::log;

    use vm::representations::{ClarityName, ContractName};

    // verify that we can verify signatures over a transaction.
    // also verify that we can corrupt any field and fail to verify the transaction.
    // corruption tests should obviously fail -- the initial sighash changes if any of the
    // serialized data changes.
    fn test_signature_and_corruption(signed_tx: &StacksTransaction, corrupt_origin: bool, corrupt_sponsor: bool) -> () {
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
        
        // mess with fields
        let mut corrupt_tx_fields = signed_tx.clone();
        let mut corrupt_auth_fields = corrupt_tx_fields.auth().clone();
        match corrupt_auth_fields {
            TransactionAuth::Standard(ref mut origin_condition) => {
                if corrupt_origin {
                    match origin_condition {
                        TransactionSpendingCondition::Singlesig(ref mut data) => {
                            let mut sig_bytes = data.signature.as_bytes().to_vec();
                            sig_bytes[0] = (((sig_bytes[0] as u16) + 1) % 0xff) as u8;
                            data.signature = MessageSignature::from_raw(&sig_bytes);
                        },
                        TransactionSpendingCondition::Multisig(ref mut data) => {
                            let corrupt_field = match data.fields[0] {
                                TransactionAuthField::PublicKey(ref pubkey) => {
                                    TransactionAuthField::PublicKey(StacksPublicKey::from_hex("0270790e675116a63a75008832d82ad93e4332882ab0797b0f156de9d739160a0b").unwrap())
                                },
                                TransactionAuthField::Signature(ref key_encoding, ref sig) => {
                                    let mut sig_bytes = sig.as_bytes().to_vec();
                                    sig_bytes[0] = (((sig_bytes[0] as u16) + 1) % 0xff) as u8;
                                    let corrupt_sig = MessageSignature::from_raw(&sig_bytes);
                                    TransactionAuthField::Signature(*key_encoding, corrupt_sig)
                                }
                            };
                            data.fields[0] = corrupt_field
                        }
                    }
                }
            },
            TransactionAuth::Sponsored(ref mut origin_condition, ref mut sponsor_condition) => {
                if corrupt_origin {
                    match origin_condition {
                        TransactionSpendingCondition::Singlesig(ref mut data) => {
                            let mut sig_bytes = data.signature.as_bytes().to_vec();
                            sig_bytes[0] = (((sig_bytes[0] as u16) + 1) % 0xff) as u8;
                            data.signature = MessageSignature::from_raw(&sig_bytes);
                        },
                        TransactionSpendingCondition::Multisig(ref mut data) => {
                            let corrupt_field = match data.fields[0] {
                                TransactionAuthField::PublicKey(ref pubkey) => {
                                    TransactionAuthField::PublicKey(StacksPublicKey::from_hex("0270790e675116a63a75008832d82ad93e4332882ab0797b0f156de9d739160a0b").unwrap())
                                },
                                TransactionAuthField::Signature(ref key_encoding, ref sig) => {
                                    let mut sig_bytes = sig.as_bytes().to_vec();
                                    sig_bytes[0] = (((sig_bytes[0] as u16) + 1) % 0xff) as u8;
                                    let corrupt_sig = MessageSignature::from_raw(&sig_bytes);
                                    TransactionAuthField::Signature(*key_encoding, corrupt_sig)
                                }
                            };
                            data.fields[0] = corrupt_field
                        }
                    }
                }
                if corrupt_sponsor {
                    match sponsor_condition {
                        TransactionSpendingCondition::Singlesig(ref mut data) => {
                            let mut sig_bytes = data.signature.as_bytes().to_vec();
                            sig_bytes[0] = (((sig_bytes[0] as u16) + 1) % 0xff) as u8;
                            data.signature = MessageSignature::from_raw(&sig_bytes);
                        },
                        TransactionSpendingCondition::Multisig(ref mut data) => {
                            let corrupt_field = match data.fields[0] {
                                TransactionAuthField::PublicKey(ref pubkey) => {
                                    TransactionAuthField::PublicKey(StacksPublicKey::from_hex("0270790e675116a63a75008832d82ad93e4332882ab0797b0f156de9d739160a0b").unwrap())
                                },
                                TransactionAuthField::Signature(ref key_encoding, ref sig) => {
                                    let mut sig_bytes = sig.as_bytes().to_vec();
                                    sig_bytes[0] = (((sig_bytes[0] as u16) + 1) % 0xff) as u8;
                                    let corrupt_sig = MessageSignature::from_raw(&sig_bytes);
                                    TransactionAuthField::Signature(*key_encoding, corrupt_sig)
                                }
                            };
                            data.fields[0] = corrupt_field
                        }
                    }
                }
            }
        }
        corrupt_tx_fields.auth = corrupt_auth_fields;
        assert!(corrupt_tx_fields.txid() != signed_tx.txid());

        // mess with the auth signatures required, if applicable
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
        corrupt_tx_fee.fee += 1;
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
        corrupt_tx_post_conditions.post_conditions.push(TransactionPostCondition::STX(FungibleConditionCode::SentGt, 0));

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
            TransactionPayload::ContractCall(_) => {
                TransactionPayload::SmartContract(TransactionSmartContract { name: ContractName::try_from("corrupt name").unwrap(), code_body: StacksString::from_str("corrupt body").unwrap() })
            },
            TransactionPayload::SmartContract(_) => {
                TransactionPayload::ContractCall(TransactionContractCall { 
                    address: StacksAddress { version: 1, bytes: Hash160([0xff; 20]) },
                    contract_name: ContractName::try_from("hello-world").unwrap(),
                    function_name: ClarityName::try_from("hello-function").unwrap(),
                    function_args: vec![ClarityName::try_from("0").unwrap()]
                })
            },
            TransactionPayload::PoisonMicroblock(ref h1, ref h2) => {
                let mut corrupt_h1 = h1.clone();
                let mut corrupt_h2 = h2.clone();

                corrupt_h1.sequence += 1;
                corrupt_h2.sequence += 1;
                TransactionPayload::PoisonMicroblock(corrupt_h1, corrupt_h2)
            }
        };
        assert!(corrupt_tx_payload.txid() != signed_tx.txid());

        let mut corrupt_transactions = vec![
            corrupt_tx_hash_mode,
            corrupt_tx_nonce,
            corrupt_tx_fields,
            corrupt_tx_version,
            corrupt_tx_chain_id,
            corrupt_tx_fee,
            corrupt_tx_anchor_mode,
            corrupt_tx_post_condition_mode,
            corrupt_tx_post_conditions,
            corrupt_tx_payload
        ];
        if is_multisig_origin || is_multisig_sponsor {
            corrupt_transactions.push(corrupt_tx_signatures_required);
        }

        // make sure all corrupted transactions fail
        for corrupt_tx in corrupt_transactions.iter() {
            assert!(corrupt_tx.verify().is_err());
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
    fn tx_stacks_transacton_payload() {
        let hello_contract_call = "hello-contract-call";
        let hello_contract_name = "hello-contract-name";
        let hello_function_name = "hello-function-name";
        let hello_contract_body = "hello contract code body";

        let contract_call = TransactionContractCall {
            address: StacksAddress { version: 1, bytes: Hash160([0xff; 20]) },
            contract_name: ContractName::try_from(hello_contract_name).unwrap(),
            function_name: ClarityName::try_from(hello_function_name).unwrap(),
            function_args: vec![ClarityName::try_from("0").unwrap()]
        };

        let smart_contract = TransactionSmartContract {
            name: ContractName::try_from(hello_contract_name).unwrap(),
            code_body: StacksString::from_str(hello_contract_body).unwrap(),
        };

        let mut contract_call_bytes = vec![
            0x00, 0x00, 0x00, hello_contract_call.len() as u8
        ];
        contract_call_bytes.extend_from_slice(hello_contract_call.as_bytes());

        let mut smart_contract_name_bytes = vec![
            0x00, 0x00, 0x00, hello_contract_name.len() as u8
        ];
        smart_contract_name_bytes.extend_from_slice(hello_contract_name.as_bytes());

        let mut smart_contract_code_bytes = vec![
            0x00, 0x00, 0x00, hello_contract_body.len() as u8
        ];
        smart_contract_code_bytes.extend_from_slice(hello_contract_body.as_bytes());

        let mut payload_contract_call = vec![];
        payload_contract_call.append(&mut contract_call_bytes);
        
        let mut payload_smart_contract = vec![];
        payload_smart_contract.append(&mut smart_contract_name_bytes);
        payload_smart_contract.append(&mut smart_contract_code_bytes);

        let mut transaction_contract_call = vec![
            TransactionPayloadID::ContractCall as u8
        ];
        transaction_contract_call.append(&mut payload_contract_call.clone());

        let mut transaction_smart_contract = vec![
            TransactionPayloadID::SmartContract as u8
        ];
        transaction_smart_contract.append(&mut payload_smart_contract.clone());

        check_codec_and_corruption::<TransactionContractCall>(&contract_call, &payload_contract_call);
        check_codec_and_corruption::<TransactionSmartContract>(&smart_contract, &payload_smart_contract);
        check_codec_and_corruption::<TransactionPayload>(&TransactionPayload::ContractCall(contract_call.clone()), &transaction_contract_call);
        check_codec_and_corruption::<TransactionPayload>(&TransactionPayload::SmartContract(smart_contract.clone()), &transaction_smart_contract);
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

        let asset_name = ClarityName::try_from("hello asset").unwrap();
        let mut asset_name_bytes = vec![
            // length
            0x00, 0x00, 0x00, asset_name.len() as u8,
        ];
        asset_name_bytes.extend_from_slice(&asset_name.to_string().as_str().as_bytes());

        let contract_name = ContractName::try_from("hello-world").unwrap();
        let mut contract_name_bytes = vec![
            // length
            0x00, 0x00, 0x00, contract_name.len() as u8,
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
        let addr = StacksAddress { version: 1, bytes: Hash160([0xff; 20]) };
        let asset_name = ClarityName::try_from("hello-asset").unwrap();
        let contract_name = ContractName::try_from("contract-name").unwrap();

        let stx_pc = TransactionPostCondition::STX(FungibleConditionCode::SentGt, 12345);
        let fungible_pc = TransactionPostCondition::Fungible(
            AssetInfo { contract_address: addr.clone(), contract_name: contract_name.clone(), asset_name: asset_name.clone() },
            FungibleConditionCode::SentGt,
            23456);

        let nonfungible_pc = TransactionPostCondition::Nonfungible(
            AssetInfo { contract_address: addr.clone(), contract_name: contract_name.clone(), asset_name: asset_name.clone() },
            StacksString::from_str(&"asdf").unwrap(),
            NonfungibleConditionCode::Present);

        let mut stx_pc_bytes = (AssetInfoID::STX as u8).serialize();
        stx_pc_bytes.append(&mut vec![
            // condition code
            FungibleConditionCode::SentGt as u8,
            // amount 
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x30, 0x39
        ]);

        let mut fungible_pc_bytes = (AssetInfoID::FungibleAsset as u8).serialize();
        fungible_pc_bytes.append(&mut AssetInfo {contract_address: addr.clone(), contract_name: contract_name.clone(), asset_name: asset_name.clone()}.serialize());
        fungible_pc_bytes.append(&mut vec![
            // condition code 
            FungibleConditionCode::SentGt as u8,
            // amount
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x5b, 0xa0
        ]);

        let mut nonfungible_pc_bytes = (AssetInfoID::NonfungibleAsset as u8).serialize();
        nonfungible_pc_bytes.append(&mut AssetInfo {contract_address: addr.clone(), contract_name: contract_name.clone(), asset_name: asset_name.clone()}.serialize());
        nonfungible_pc_bytes.append(&mut StacksString::from_str(&"asdf").unwrap().serialize());
        nonfungible_pc_bytes.append(&mut vec![
            // condition code
            NonfungibleConditionCode::Present as u8
        ]);

        let pcs = vec![stx_pc, fungible_pc, nonfungible_pc];
        let pc_bytes = vec![stx_pc_bytes, fungible_pc_bytes, nonfungible_pc_bytes];
        for i in 0..3 {
            check_codec_and_corruption::<TransactionPostCondition>(&pcs[i], &pc_bytes[i]);
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
            // condition code
            NonfungibleConditionCode::Present as u8,
            // amount 
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x30, 0x39
        ]);

        let mut fungible_pc_bytes_bad_condition = (AssetInfoID::FungibleAsset as u8).serialize();
        fungible_pc_bytes_bad_condition.append(&mut AssetInfo {contract_address: addr.clone(), contract_name: contract_name.clone(), asset_name: asset_name.clone()}.serialize());
        fungible_pc_bytes_bad_condition.append(&mut vec![
            // condition code 
            NonfungibleConditionCode::Absent as u8,
            // amount
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x5b, 0xa0
        ]);
        
        let mut nonfungible_pc_bytes_bad_condition = (AssetInfoID::NonfungibleAsset as u8).serialize();
        nonfungible_pc_bytes_bad_condition.append(&mut AssetInfo {contract_address: addr.clone(), contract_name: contract_name.clone(), asset_name: asset_name.clone()}.serialize());
        nonfungible_pc_bytes_bad_condition.append(&mut StacksString::from_str(&"asdf").unwrap().serialize());
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
    }

    #[test]
    fn tx_stacks_transaction() {
        let addr = StacksAddress { version: 1, bytes: Hash160([0xff; 20]) };
        let asset_name = ClarityName::try_from("hello-asset").unwrap();
        let contract_name = ContractName::try_from("hello-world").unwrap();
        let hello_contract_call = "hello contract call";
        let hello_contract_name = "hello-contract-name";
        let hello_contract_body = "hello contract code body";
        let asset_info = AssetInfo {
            contract_address: addr.clone(),
            contract_name: contract_name.clone(),
            asset_name: asset_name.clone(),
        };

        let spending_conditions = vec![
            TransactionSpendingCondition::Singlesig(SinglesigSpendingCondition {
                signer: Hash160([0x11; 20]),
                hash_mode: SinglesigHashMode::P2PKH,
                key_encoding: TransactionPublicKeyEncoding::Uncompressed,
                nonce: 123,
                signature: MessageSignature::from_raw(&vec![0xff; 65])
            }),
            TransactionSpendingCondition::Singlesig(SinglesigSpendingCondition {
                signer: Hash160([0x11; 20]),
                hash_mode: SinglesigHashMode::P2PKH,
                key_encoding: TransactionPublicKeyEncoding::Compressed,
                nonce: 234,
                signature: MessageSignature::from_raw(&vec![0xff; 65])
            }),
            TransactionSpendingCondition::Multisig(MultisigSpendingCondition {
                signer: Hash160([0x11; 20]),
                hash_mode: MultisigHashMode::P2SH,
                nonce: 345,
                fields: vec![
                    TransactionAuthField::Signature(TransactionPublicKeyEncoding::Uncompressed, MessageSignature::from_raw(&vec![0xff; 65])),
                    TransactionAuthField::Signature(TransactionPublicKeyEncoding::Uncompressed, MessageSignature::from_raw(&vec![0xfe; 65])),
                    TransactionAuthField::PublicKey(PubKey::from_hex("04ef2340518b5867b23598a9cf74611f8b98064f7d55cdb8c107c67b5efcbc5c771f112f919b00a6c6c5f51f7c63e1762fe9fac9b66ec75a053db7f51f4a52712b").unwrap()),
                ],
                signatures_required: 2
            }),
            TransactionSpendingCondition::Multisig(MultisigSpendingCondition {
                signer: Hash160([0x11; 20]),
                hash_mode: MultisigHashMode::P2SH,
                nonce: 456,
                fields: vec![
                    TransactionAuthField::Signature(TransactionPublicKeyEncoding::Compressed, MessageSignature::from_raw(&vec![0xff; 65])),
                    TransactionAuthField::Signature(TransactionPublicKeyEncoding::Compressed, MessageSignature::from_raw(&vec![0xfe; 65])),
                    TransactionAuthField::PublicKey(PubKey::from_hex("03ef2340518b5867b23598a9cf74611f8b98064f7d55cdb8c107c67b5efcbc5c77").unwrap())
                ],
                signatures_required: 2
            }),
            TransactionSpendingCondition::Singlesig(SinglesigSpendingCondition {
                signer: Hash160([0x11; 20]),
                hash_mode: SinglesigHashMode::P2WPKH,
                key_encoding: TransactionPublicKeyEncoding::Compressed,
                nonce: 567,
                signature: MessageSignature::from_raw(&vec![0xfe; 65]),
            }),
            TransactionSpendingCondition::Multisig(MultisigSpendingCondition {
                signer: Hash160([0x11; 20]),
                hash_mode: MultisigHashMode::P2WSH,
                nonce: 678,
                fields: vec![
                    TransactionAuthField::Signature(TransactionPublicKeyEncoding::Compressed, MessageSignature::from_raw(&vec![0xff; 65])),
                    TransactionAuthField::Signature(TransactionPublicKeyEncoding::Compressed, MessageSignature::from_raw(&vec![0xfe; 65])),
                    TransactionAuthField::PublicKey(PubKey::from_hex("03ef2340518b5867b23598a9cf74611f8b98064f7d55cdb8c107c67b5efcbc5c77").unwrap())
                ],
                signatures_required: 2
            })
        ];

        let mut tx_auths = vec![];
        for i in 0..spending_conditions.len() {
            let spending_condition = &spending_conditions[i];
            let next_spending_condition = &spending_conditions[(i + 1) % spending_conditions.len()];

            tx_auths.push(TransactionAuth::Standard(spending_condition.clone()));
            tx_auths.push(TransactionAuth::Sponsored(spending_condition.clone(), next_spending_condition.clone()));
        }

        let tx_fees = vec![123];

        let tx_post_conditions = vec![
            vec![TransactionPostCondition::STX(FungibleConditionCode::SentLt, 12345)],
            vec![TransactionPostCondition::Fungible(
                AssetInfo { contract_address: addr.clone(), contract_name: contract_name.clone(), asset_name: asset_name.clone() }, 
                FungibleConditionCode::SentGt, 
                23456)
            ],
            vec![TransactionPostCondition::Nonfungible(
                AssetInfo { contract_address: addr.clone(), contract_name: contract_name.clone(), asset_name: asset_name.clone() },
                StacksString::from_str(&"asdf").unwrap(), 
                NonfungibleConditionCode::Present)
            ],
            vec![TransactionPostCondition::STX(FungibleConditionCode::SentLt, 12345),
                TransactionPostCondition::Fungible(AssetInfo { contract_address: addr.clone(), contract_name: contract_name.clone(), asset_name: asset_name.clone() }, 
                                                   FungibleConditionCode::SentGt, 
                                                   23456)
            ],
            vec![TransactionPostCondition::STX(FungibleConditionCode::SentLt, 12345), 
                TransactionPostCondition::Nonfungible(AssetInfo { contract_address: addr.clone(), contract_name: contract_name.clone(), asset_name: asset_name.clone() }, 
                                                      StacksString::from_str(&"asdf").unwrap(), 
                                                      NonfungibleConditionCode::Present)
            ],
            vec![TransactionPostCondition::Fungible(AssetInfo { contract_address: addr.clone(), contract_name: contract_name.clone(), asset_name: asset_name.clone() }, 
                                                    FungibleConditionCode::SentGt, 
                                                    23456),
                 TransactionPostCondition::Nonfungible(AssetInfo { contract_address: addr.clone(), contract_name: contract_name.clone(), asset_name: asset_name.clone() }, 
                                                       StacksString::from_str(&"asdf").unwrap(), 
                                                       NonfungibleConditionCode::Present)
            ],
            vec![TransactionPostCondition::STX(FungibleConditionCode::SentLt, 12345),
                 TransactionPostCondition::Nonfungible(AssetInfo { contract_address: addr.clone(), contract_name: contract_name.clone(), asset_name: asset_name.clone() }, 
                                                       StacksString::from_str("&asdf").unwrap(), 
                                                       NonfungibleConditionCode::Present),
                 TransactionPostCondition::Fungible(AssetInfo { contract_address: addr.clone(), contract_name: contract_name.clone(), asset_name: asset_name.clone() }, 
                                                    FungibleConditionCode::SentGt, 
                                                    23456)
            ],
        ];

        let tx_payloads = vec![
            TransactionPayload::ContractCall(TransactionContractCall {
                address: StacksAddress { version: 1, bytes: Hash160([0xff; 20]) },
                contract_name: ContractName::try_from("hello-contract-name").unwrap(),
                function_name: ClarityName::try_from("hello-contract-call").unwrap(),
                function_args: vec![ClarityName::try_from("0").unwrap()]
            }),
            TransactionPayload::SmartContract(TransactionSmartContract {
                name: ContractName::try_from(hello_contract_name).unwrap(),
                code_body: StacksString::from_str(hello_contract_body).unwrap(),
            })
        ];

        // test all combinations
        for spending_condition in spending_conditions.iter() {
            for tx_auth in tx_auths.iter() {
                for tx_fee in tx_fees.iter() {
                    for tx_post_condition in tx_post_conditions.iter() {
                        for tx_payload in tx_payloads.iter() {
                            let tx_mainnet = StacksTransaction {
                                version: TransactionVersion::Mainnet,
                                chain_id: 0,
                                auth: tx_auth.clone(),
                                fee: *tx_fee,
                                anchor_mode: TransactionAnchorMode::OnChainOnly,
                                post_condition_mode: TransactionPostConditionMode::Deny,
                                post_conditions: tx_post_condition.clone(),
                                payload: tx_payload.clone()
                            };

                            let mut tx_bytes = vec![
                                // version
                                TransactionVersion::Mainnet as u8,
                                // chain ID
                                0x00, 0x00, 0x00, 0x00
                            ];
                            
                            tx_bytes.append(&mut (tx_auth.serialize()));
                            tx_bytes.append(&mut (tx_fee.serialize()));
                            tx_bytes.append(&mut vec![TransactionAnchorMode::OnChainOnly as u8]);
                            tx_bytes.append(&mut vec![TransactionPostConditionMode::Deny as u8]);
                            tx_bytes.append(&mut (tx_post_condition.serialize()));
                            tx_bytes.append(&mut (tx_payload.serialize()));

                            check_codec_and_corruption::<StacksTransaction>(&tx_mainnet, &tx_bytes);
                        }
                    }
                }
            }
        }
    }

    #[test]
    fn tx_stacks_transaction_sign_verify_standard_p2pkh() {
        let privk = StacksPrivateKey::from_hex("6d430bb91222408e7706c9001cfaeb91b08c2be6d5ac95779ab52c6b431950e001").unwrap();
        let origin_auth = TransactionAuth::Standard(TransactionSpendingCondition::new_singlesig_p2pkh(StacksPublicKey::from_private(&privk)).unwrap());

        let origin_address = origin_auth.origin().address_mainnet();
        assert_eq!(origin_address, StacksAddress { version: C32_ADDRESS_VERSION_MAINNET_SINGLESIG, bytes: Hash160::from_hex("143e543243dfcd8c02a12ad7ea371bd07bc91df9").unwrap() });
        
        let tx_contract_call = StacksTransaction::new(TransactionVersion::Mainnet,
                                                      origin_auth.clone(),
                                                      TransactionPayload::new_contract_call(&StacksAddress { version: 1, bytes: Hash160([0xff; 20]) }, "hello", "world", &vec!["1"]).unwrap());

        let tx_smart_contract = StacksTransaction::new(TransactionVersion::Mainnet,
                                                       origin_auth.clone(),
                                                       TransactionPayload::new_smart_contract(&"name".to_string(), &"hello smart contract".to_string()).unwrap());

        let txs = vec![tx_contract_call, tx_smart_contract];

        for tx in txs {
            assert_eq!(tx.auth().origin().num_signatures(), 0);

            let mut tx_signer = StacksTransactionSigner::new(&tx);
            tx_signer.sign_origin(&privk).unwrap();
            let signed_tx = tx_signer.get_tx().unwrap();

            assert_eq!(signed_tx.auth().origin().num_signatures(), 1);

            // tx and signed_tx are otherwise equal
            assert_eq!(tx.version, signed_tx.version);
            assert_eq!(tx.fee, signed_tx.fee);
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

        let auth = TransactionAuth::Sponsored(
            TransactionSpendingCondition::new_singlesig_p2pkh(StacksPublicKey::from_private(&privk)).unwrap(),
            TransactionSpendingCondition::new_singlesig_p2pkh(StacksPublicKey::from_private(&privk_sponsor)).unwrap()
        );

        let origin_address = auth.origin().address_mainnet();
        assert_eq!(origin_address, StacksAddress { version: C32_ADDRESS_VERSION_MAINNET_SINGLESIG, bytes: Hash160::from_hex("143e543243dfcd8c02a12ad7ea371bd07bc91df9").unwrap() });

        let sponsor_address = auth.sponsor().unwrap().address_mainnet();
        assert_eq!(sponsor_address, StacksAddress { version: C32_ADDRESS_VERSION_MAINNET_SINGLESIG, bytes: Hash160::from_hex("3597aaa4bde720be93e3829aae24e76e7fcdfd3e").unwrap() });
        
        let tx_contract_call = StacksTransaction::new(TransactionVersion::Mainnet,
                                                      auth.clone(),
                                                      TransactionPayload::new_contract_call(&StacksAddress { version: 1, bytes: Hash160([0xff; 20]) }, "hello", "world", &vec!["1"]).unwrap());

        let tx_smart_contract = StacksTransaction::new(TransactionVersion::Mainnet,
                                                       auth.clone(),
                                                       TransactionPayload::new_smart_contract(&"name".to_string(), &"hello smart contract".to_string()).unwrap());

        let txs = vec![tx_contract_call, tx_smart_contract];

        for tx in txs {
            assert_eq!(tx.auth().origin().num_signatures(), 0);
            assert_eq!(tx.auth().sponsor().unwrap().num_signatures(), 0);

            let mut tx_signer = StacksTransactionSigner::new(&tx);
            tx_signer.sign_origin(&privk).unwrap();
            tx_signer.sign_sponsor(&privk_sponsor).unwrap();
            let signed_tx = tx_signer.get_tx().unwrap();

            assert_eq!(signed_tx.auth().origin().num_signatures(), 1);
            assert_eq!(signed_tx.auth().sponsor().unwrap().num_signatures(), 1);

            // tx and signed_tx are otherwise equal
            assert_eq!(tx.version, signed_tx.version);
            assert_eq!(tx.chain_id, signed_tx.chain_id);
            assert_eq!(tx.fee, signed_tx.fee);
            assert_eq!(tx.anchor_mode, signed_tx.anchor_mode);
            assert_eq!(tx.post_condition_mode, signed_tx.post_condition_mode);
            assert_eq!(tx.post_conditions, signed_tx.post_conditions);
            assert_eq!(tx.payload, signed_tx.payload);

            // auth is a sponsor and public key is compressed
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
                            assert_eq!(data.key_encoding, TransactionPublicKeyEncoding::Compressed);
                            assert_eq!(data.signer, sponsor_address.bytes);
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
    fn tx_stacks_transaction_sign_verify_standard_p2pkh_uncompressed() {
        let privk = StacksPrivateKey::from_hex("6d430bb91222408e7706c9001cfaeb91b08c2be6d5ac95779ab52c6b431950e0").unwrap();
        let origin_auth = TransactionAuth::Standard(TransactionSpendingCondition::new_singlesig_p2pkh(StacksPublicKey::from_private(&privk)).unwrap());

        let origin_address = origin_auth.origin().address_mainnet();
        assert_eq!(origin_address, StacksAddress { version: C32_ADDRESS_VERSION_MAINNET_SINGLESIG, bytes: Hash160::from_hex("693cd53eb47d4749762d7cfaf46902bda5be5f97").unwrap() });
        
        let tx_contract_call = StacksTransaction::new(TransactionVersion::Mainnet,
                                                      origin_auth.clone(),
                                                      TransactionPayload::new_contract_call(&StacksAddress { version: 1, bytes: Hash160([0xff; 20]) }, "hello", "world", &vec!["1"]).unwrap());

        let tx_smart_contract = StacksTransaction::new(TransactionVersion::Mainnet,
                                                       origin_auth.clone(),
                                                       TransactionPayload::new_smart_contract(&"name".to_string(), &"hello smart contract".to_string()).unwrap());

        let txs = vec![tx_contract_call, tx_smart_contract];

        for tx in txs {
            assert_eq!(tx.auth().origin().num_signatures(), 0);

            let mut tx_signer = StacksTransactionSigner::new(&tx);
            tx_signer.sign_origin(&privk).unwrap();
            let signed_tx = tx_signer.get_tx().unwrap();

            assert_eq!(signed_tx.auth().origin().num_signatures(), 1);

            // tx and signed_tx are otherwise equal
            assert_eq!(tx.version, signed_tx.version);
            assert_eq!(tx.fee, signed_tx.fee);
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

        let auth = TransactionAuth::Sponsored(
            TransactionSpendingCondition::new_singlesig_p2pkh(StacksPublicKey::from_private(&privk)).unwrap(),
            TransactionSpendingCondition::new_singlesig_p2pkh(StacksPublicKey::from_private(&privk_sponsored)).unwrap(),
        );

        let origin_address = auth.origin().address_mainnet();
        let sponsor_address = auth.sponsor().unwrap().address_mainnet();
        
        assert_eq!(origin_address, StacksAddress { version: C32_ADDRESS_VERSION_MAINNET_SINGLESIG, bytes: Hash160::from_hex("3597aaa4bde720be93e3829aae24e76e7fcdfd3e").unwrap() });
        assert_eq!(sponsor_address, StacksAddress { version: C32_ADDRESS_VERSION_MAINNET_SINGLESIG, bytes: Hash160::from_hex("693cd53eb47d4749762d7cfaf46902bda5be5f97").unwrap() });
        
        let tx_contract_call = StacksTransaction::new(TransactionVersion::Mainnet,
                                                      auth.clone(),
                                                      TransactionPayload::new_contract_call(&StacksAddress { version: 1, bytes: Hash160([0xff; 20]) }, "hello", "world", &vec!["1"]).unwrap());

        let tx_smart_contract = StacksTransaction::new(TransactionVersion::Mainnet,
                                                       auth.clone(),
                                                       TransactionPayload::new_smart_contract(&"name".to_string(), &"hello smart contract".to_string()).unwrap());

        let txs = vec![tx_contract_call, tx_smart_contract];

        for tx in txs {
            assert_eq!(tx.auth().origin().num_signatures(), 0);
            assert_eq!(tx.auth().sponsor().unwrap().num_signatures(), 0);

            let mut tx_signer = StacksTransactionSigner::new(&tx);
            tx_signer.sign_origin(&privk).unwrap();
            tx_signer.sign_sponsor(&privk_sponsored).unwrap();
            let signed_tx = tx_signer.get_tx().unwrap();

            assert_eq!(signed_tx.auth().origin().num_signatures(), 1);
            assert_eq!(signed_tx.auth().sponsor().unwrap().num_signatures(), 1);

            // tx and signed_tx are otherwise equal
            assert_eq!(tx.version, signed_tx.version);
            assert_eq!(tx.chain_id, signed_tx.chain_id);
            assert_eq!(tx.fee, signed_tx.fee);
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

        let tx_contract_call = StacksTransaction::new(TransactionVersion::Mainnet,
                                                      origin_auth.clone(),
                                                      TransactionPayload::new_contract_call(&StacksAddress { version: 1, bytes: Hash160([0xff; 20]) }, "hello", "world", &vec!["1"]).unwrap());

        let tx_smart_contract = StacksTransaction::new(TransactionVersion::Mainnet,
                                                       origin_auth.clone(),
                                                       TransactionPayload::new_smart_contract(&"name".to_string(), &"hello smart contract".to_string()).unwrap());

        let txs = vec![tx_contract_call, tx_smart_contract];

        for tx in txs {
            assert_eq!(tx.auth().origin().num_signatures(), 0);

            let mut tx_signer = StacksTransactionSigner::new(&tx);
            tx_signer.sign_origin(&privk_1).unwrap();
            tx_signer.sign_origin(&privk_2).unwrap();
            tx_signer.append_origin(&pubk_3).unwrap();
            let signed_tx = tx_signer.get_tx().unwrap();

            assert_eq!(signed_tx.auth().origin().num_signatures(), 2);

            // tx and signed_tx are otherwise equal
            assert_eq!(tx.version, signed_tx.version);
            assert_eq!(tx.fee, signed_tx.fee);
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

        let auth = TransactionAuth::Sponsored(
            TransactionSpendingCondition::new_singlesig_p2pkh(StacksPublicKey::from_private(&origin_privk)).unwrap(),
            TransactionSpendingCondition::new_multisig_p2sh(2, vec![pubk_1.clone(), pubk_2.clone(), pubk_3.clone()]).unwrap()
        );

        let origin_address = auth.origin().address_mainnet();
        let sponsor_address = auth.sponsor().unwrap().address_mainnet();
        
        assert_eq!(origin_address, StacksAddress { version: C32_ADDRESS_VERSION_MAINNET_SINGLESIG, bytes: Hash160::from_hex("3597aaa4bde720be93e3829aae24e76e7fcdfd3e").unwrap() });
        assert_eq!(sponsor_address, StacksAddress { version: C32_ADDRESS_VERSION_MAINNET_MULTISIG, bytes: Hash160::from_hex("a23ea89d6529ac48ac766f720e480beec7f19273").unwrap() });

        let tx_contract_call = StacksTransaction::new(TransactionVersion::Mainnet,
                                                      auth.clone(),
                                                      TransactionPayload::new_contract_call(&StacksAddress { version: 1, bytes: Hash160([0xff; 20]) }, "hello", "world", &vec!["1"]).unwrap());

        let tx_smart_contract = StacksTransaction::new(TransactionVersion::Mainnet,
                                                       auth.clone(),
                                                       TransactionPayload::new_smart_contract(&"name".to_string(), &"hello smart contract".to_string()).unwrap());

        let txs = vec![tx_contract_call, tx_smart_contract];

        for tx in txs {
            assert_eq!(tx.auth().origin().num_signatures(), 0);
            assert_eq!(tx.auth().sponsor().unwrap().num_signatures(), 0);

            let mut tx_signer = StacksTransactionSigner::new(&tx);

            tx_signer.sign_origin(&origin_privk).unwrap();

            tx_signer.sign_sponsor(&privk_1).unwrap();
            tx_signer.sign_sponsor(&privk_2).unwrap();
            tx_signer.append_sponsor(&pubk_3).unwrap();
            
            let signed_tx = tx_signer.get_tx().unwrap();

            assert_eq!(signed_tx.auth().origin().num_signatures(), 1);
            assert_eq!(signed_tx.auth().sponsor().unwrap().num_signatures(), 2);

            // tx and signed_tx are otherwise equal
            assert_eq!(tx.version, signed_tx.version);
            assert_eq!(tx.chain_id, signed_tx.chain_id);
            assert_eq!(tx.fee, signed_tx.fee);
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
        
        let tx_contract_call = StacksTransaction::new(TransactionVersion::Mainnet,
                                                      auth.clone(),
                                                      TransactionPayload::new_contract_call(&StacksAddress { version: 1, bytes: Hash160([0xff; 20]) }, "hello", "world", &vec!["1"]).unwrap());

        let tx_smart_contract = StacksTransaction::new(TransactionVersion::Mainnet,
                                                       auth.clone(),
                                                       TransactionPayload::new_smart_contract(&"name".to_string(), &"hello smart contract".to_string()).unwrap());

        let txs = vec![tx_contract_call, tx_smart_contract];

        for tx in txs {
            assert_eq!(tx.auth().origin().num_signatures(), 0);

            let mut tx_signer = StacksTransactionSigner::new(&tx);

            tx_signer.sign_origin(&privk_1).unwrap();
            tx_signer.sign_origin(&privk_2).unwrap();
            tx_signer.append_origin(&pubk_3).unwrap();
            
            let signed_tx = tx_signer.get_tx().unwrap();

            assert_eq!(signed_tx.auth().origin().num_signatures(), 2);

            // tx and signed_tx are otherwise equal
            assert_eq!(tx.version, signed_tx.version);
            assert_eq!(tx.chain_id, signed_tx.chain_id);
            assert_eq!(tx.fee, signed_tx.fee);
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

        let auth = TransactionAuth::Sponsored(
            TransactionSpendingCondition::new_singlesig_p2pkh(StacksPublicKey::from_private(&origin_privk)).unwrap(),
            TransactionSpendingCondition::new_multisig_p2sh(2, vec![pubk_1.clone(), pubk_2.clone(), pubk_3.clone()]).unwrap()
        );

        let origin_address = auth.origin().address_mainnet();
        let sponsor_address = auth.sponsor().unwrap().address_mainnet();
        
        assert_eq!(origin_address, StacksAddress { version: C32_ADDRESS_VERSION_MAINNET_SINGLESIG, bytes: Hash160::from_hex("3597aaa4bde720be93e3829aae24e76e7fcdfd3e").unwrap() });
        assert_eq!(sponsor_address, StacksAddress { version: C32_ADDRESS_VERSION_MAINNET_MULTISIG, bytes: Hash160::from_hex("73a8b4a751a678fe83e9d35ce301371bb3d397f7").unwrap() });
        
        let tx_contract_call = StacksTransaction::new(TransactionVersion::Mainnet,
                                                      auth.clone(),
                                                      TransactionPayload::new_contract_call(&StacksAddress { version: 1, bytes: Hash160([0xff; 20]) }, "hello", "world", &vec!["1"]).unwrap());

        let tx_smart_contract = StacksTransaction::new(TransactionVersion::Mainnet,
                                                       auth.clone(),
                                                       TransactionPayload::new_smart_contract(&"name".to_string(), &"hello smart contract".to_string()).unwrap());

        let txs = vec![tx_contract_call, tx_smart_contract];

        for tx in txs {
            assert_eq!(tx.auth().origin().num_signatures(), 0);
            assert_eq!(tx.auth().sponsor().unwrap().num_signatures(), 0);

            let mut tx_signer = StacksTransactionSigner::new(&tx);

            tx_signer.sign_origin(&origin_privk).unwrap();

            tx_signer.sign_sponsor(&privk_1).unwrap();
            tx_signer.sign_sponsor(&privk_2).unwrap();
            tx_signer.append_sponsor(&pubk_3).unwrap();
            
            let signed_tx = tx_signer.get_tx().unwrap();

            assert_eq!(signed_tx.auth().origin().num_signatures(), 1);
            assert_eq!(signed_tx.auth().sponsor().unwrap().num_signatures(), 2);

            // tx and signed_tx are otherwise equal
            assert_eq!(tx.version, signed_tx.version);
            assert_eq!(tx.fee, signed_tx.fee);
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
        
        let tx_contract_call = StacksTransaction::new(TransactionVersion::Mainnet,
                                                      origin_auth.clone(),
                                                      TransactionPayload::new_contract_call(&StacksAddress { version: 1, bytes: Hash160([0xff; 20]) }, "hello", "world", &vec!["1"]).unwrap());

        let tx_smart_contract = StacksTransaction::new(TransactionVersion::Mainnet,
                                                       origin_auth.clone(),
                                                       TransactionPayload::new_smart_contract(&"name".to_string(), &"hello smart contract".to_string()).unwrap());

        let txs = vec![tx_contract_call, tx_smart_contract];

        for tx in txs {
            assert_eq!(tx.auth().origin().num_signatures(), 0);

            let mut tx_signer = StacksTransactionSigner::new(&tx);
            tx_signer.sign_origin(&privk_1).unwrap();
            tx_signer.append_origin(&pubk_2).unwrap();
            tx_signer.sign_origin(&privk_3).unwrap();
            let signed_tx = tx_signer.get_tx().unwrap();

            assert_eq!(signed_tx.auth().origin().num_signatures(), 2);

            // tx and signed_tx are otherwise equal
            assert_eq!(tx.version, signed_tx.version);
            assert_eq!(tx.fee, signed_tx.fee);
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

        let auth = TransactionAuth::Sponsored(
            TransactionSpendingCondition::new_singlesig_p2pkh(StacksPublicKey::from_private(&origin_privk)).unwrap(),
            TransactionSpendingCondition::new_multisig_p2sh(2, vec![pubk_1.clone(), pubk_2.clone(), pubk_3.clone()]).unwrap()
        );

        let origin_address = auth.origin().address_mainnet();
        let sponsor_address = auth.sponsor().unwrap().address_mainnet();

        assert_eq!(origin_address, StacksAddress { version: C32_ADDRESS_VERSION_MAINNET_SINGLESIG, bytes: Hash160::from_hex("3597aaa4bde720be93e3829aae24e76e7fcdfd3e").unwrap() });
        assert_eq!(sponsor_address, StacksAddress { version: C32_ADDRESS_VERSION_MAINNET_MULTISIG, bytes: Hash160::from_hex("2136367c9c740e7dbed8795afdf8a6d273096718").unwrap() });
        
        let tx_contract_call = StacksTransaction::new(TransactionVersion::Mainnet,
                                                      auth.clone(),
                                                      TransactionPayload::new_contract_call(&StacksAddress { version: 1, bytes: Hash160([0xff; 20]) }, "hello", "world", &vec!["1"]).unwrap());

        let tx_smart_contract = StacksTransaction::new(TransactionVersion::Mainnet,
                                                       auth.clone(),
                                                       TransactionPayload::new_smart_contract(&"name".to_string(), &"hello smart contract".to_string()).unwrap());

        let txs = vec![tx_contract_call, tx_smart_contract];

        for tx in txs {
            assert_eq!(tx.auth().origin().num_signatures(), 0);
            assert_eq!(tx.auth().sponsor().unwrap().num_signatures(), 0);

            let mut tx_signer = StacksTransactionSigner::new(&tx);

            tx_signer.sign_origin(&origin_privk).unwrap();

            tx_signer.sign_sponsor(&privk_1).unwrap();
            tx_signer.append_sponsor(&pubk_2).unwrap();
            tx_signer.sign_sponsor(&privk_3).unwrap();
            
            let signed_tx = tx_signer.get_tx().unwrap();

            assert_eq!(signed_tx.auth().origin().num_signatures(), 1);
            assert_eq!(signed_tx.auth().sponsor().unwrap().num_signatures(), 2);

            // tx and signed_tx are otherwise equal
            assert_eq!(tx.version, signed_tx.version);
            assert_eq!(tx.chain_id, signed_tx.chain_id);
            assert_eq!(tx.fee, signed_tx.fee);
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
        }
    } 
     
    #[test]
    fn tx_stacks_transaction_sign_verify_standard_p2wpkh() {
        let privk = StacksPrivateKey::from_hex("6d430bb91222408e7706c9001cfaeb91b08c2be6d5ac95779ab52c6b431950e001").unwrap();
        let origin_auth = TransactionAuth::Standard(TransactionSpendingCondition::new_singlesig_p2wpkh(StacksPublicKey::from_private(&privk)).unwrap());

        let origin_address = origin_auth.origin().address_mainnet();
        assert_eq!(origin_address, StacksAddress { version: C32_ADDRESS_VERSION_MAINNET_MULTISIG, bytes: Hash160::from_hex("f15fa5c59d14ffcb615fa6153851cd802bb312d2").unwrap() });
        
        let tx_contract_call = StacksTransaction::new(TransactionVersion::Mainnet,
                                                      origin_auth.clone(),
                                                      TransactionPayload::new_contract_call(&StacksAddress { version: 1, bytes: Hash160([0xff; 20]) }, "hello", "world", &vec!["1"]).unwrap());

        let tx_smart_contract = StacksTransaction::new(TransactionVersion::Mainnet,
                                                       origin_auth.clone(),
                                                       TransactionPayload::new_smart_contract(&"name".to_string(), &"hello smart contract".to_string()).unwrap());

        let txs = vec![tx_contract_call, tx_smart_contract];

        for tx in txs {
            assert_eq!(tx.auth().origin().num_signatures(), 0);

            let mut tx_signer = StacksTransactionSigner::new(&tx);
            tx_signer.sign_origin(&privk).unwrap();
            let signed_tx = tx_signer.get_tx().unwrap();
            
            assert_eq!(signed_tx.auth().origin().num_signatures(), 1);

            // tx and signed_tx are otherwise equal
            assert_eq!(tx.version, signed_tx.version);
            assert_eq!(tx.fee, signed_tx.fee);
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

        let auth = TransactionAuth::Sponsored(
            TransactionSpendingCondition::new_singlesig_p2pkh(StacksPublicKey::from_private(&origin_privk)).unwrap(),
            TransactionSpendingCondition::new_singlesig_p2wpkh(StacksPublicKey::from_private(&privk)).unwrap()
        );

        let origin_address = auth.origin().address_mainnet();
        let sponsor_address = auth.sponsor().unwrap().address_mainnet();

        assert_eq!(origin_address, StacksAddress { version: C32_ADDRESS_VERSION_MAINNET_SINGLESIG, bytes: Hash160::from_hex("3597aaa4bde720be93e3829aae24e76e7fcdfd3e").unwrap() });
        assert_eq!(sponsor_address, StacksAddress { version: C32_ADDRESS_VERSION_MAINNET_MULTISIG, bytes: Hash160::from_hex("f15fa5c59d14ffcb615fa6153851cd802bb312d2").unwrap() });
        
        let tx_contract_call = StacksTransaction::new(TransactionVersion::Mainnet,
                                                      auth.clone(),
                                                      TransactionPayload::new_contract_call(&StacksAddress { version: 1, bytes: Hash160([0xff; 20]) }, "hello", "world", &vec!["1"]).unwrap());

        let tx_smart_contract = StacksTransaction::new(TransactionVersion::Mainnet,
                                                       auth.clone(),
                                                       TransactionPayload::new_smart_contract(&"name".to_string(), &"hello smart contract".to_string()).unwrap());

        let txs = vec![tx_contract_call, tx_smart_contract];

        for tx in txs {
            assert_eq!(tx.auth().origin().num_signatures(), 0);
            assert_eq!(tx.auth().sponsor().unwrap().num_signatures(), 0);

            let mut tx_signer = StacksTransactionSigner::new(&tx);
            
            tx_signer.sign_origin(&origin_privk).unwrap();
            tx_signer.sign_sponsor(&privk).unwrap();
            let signed_tx = tx_signer.get_tx().unwrap();
            
            assert_eq!(signed_tx.auth().origin().num_signatures(), 1);
            assert_eq!(signed_tx.auth().sponsor().unwrap().num_signatures(), 1);

            // tx and signed_tx are otherwise equal
            assert_eq!(tx.version, signed_tx.version);
            assert_eq!(tx.fee, signed_tx.fee);
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
        
        let tx_contract_call = StacksTransaction::new(TransactionVersion::Mainnet,
                                                      origin_auth.clone(),
                                                      TransactionPayload::new_contract_call(&StacksAddress { version: 1, bytes: Hash160([0xff; 20]) }, "hello", "world", &vec!["1"]).unwrap());

        let tx_smart_contract = StacksTransaction::new(TransactionVersion::Mainnet,
                                                       origin_auth.clone(),
                                                       TransactionPayload::new_smart_contract(&"name".to_string(), &"hello smart contract".to_string()).unwrap());

        let txs = vec![tx_contract_call, tx_smart_contract];

        for tx in txs {
            assert_eq!(tx.auth().origin().num_signatures(), 0);

            let mut tx_signer = StacksTransactionSigner::new(&tx);
            tx_signer.sign_origin(&privk_1).unwrap();
            tx_signer.sign_origin(&privk_2).unwrap();
            tx_signer.append_origin(&pubk_3).unwrap();
            let signed_tx = tx_signer.get_tx().unwrap();

            assert_eq!(signed_tx.auth().origin().num_signatures(), 2);

            // tx and signed_tx are otherwise equal
            assert_eq!(tx.version, signed_tx.version);
            assert_eq!(tx.fee, signed_tx.fee);
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

        let auth = TransactionAuth::Sponsored(
            TransactionSpendingCondition::new_singlesig_p2pkh(StacksPublicKey::from_private(&origin_privk)).unwrap(),
            TransactionSpendingCondition::new_multisig_p2wsh(2, vec![pubk_1.clone(), pubk_2.clone(), pubk_3.clone()]).unwrap()
        );

        let origin_address = auth.origin().address_mainnet();
        let sponsor_address = auth.sponsor().unwrap().address_mainnet();

        assert_eq!(origin_address, StacksAddress { version: C32_ADDRESS_VERSION_MAINNET_SINGLESIG, bytes: Hash160::from_hex("3597aaa4bde720be93e3829aae24e76e7fcdfd3e").unwrap() });
        assert_eq!(sponsor_address, StacksAddress { version: C32_ADDRESS_VERSION_MAINNET_MULTISIG, bytes: Hash160::from_hex("f5cfb61a07fb41a32197da01ce033888f0fe94a7").unwrap() });
        
        let tx_contract_call = StacksTransaction::new(TransactionVersion::Mainnet,
                                                      auth.clone(),
                                                      TransactionPayload::new_contract_call(&StacksAddress { version: 1, bytes: Hash160([0xff; 20]) }, "hello", "world", &vec!["1"]).unwrap());

        let tx_smart_contract = StacksTransaction::new(TransactionVersion::Mainnet,
                                                       auth.clone(),
                                                       TransactionPayload::new_smart_contract(&"name".to_string(), &"hello smart contract".to_string()).unwrap());

        let txs = vec![tx_contract_call, tx_smart_contract];

        for tx in txs {
            assert_eq!(tx.auth().origin().num_signatures(), 0);
            assert_eq!(tx.auth().sponsor().unwrap().num_signatures(), 0);

            let mut tx_signer = StacksTransactionSigner::new(&tx);

            tx_signer.sign_origin(&origin_privk).unwrap();

            tx_signer.sign_sponsor(&privk_1).unwrap();
            tx_signer.sign_sponsor(&privk_2).unwrap();
            tx_signer.append_sponsor(&pubk_3).unwrap();

            let signed_tx = tx_signer.get_tx().unwrap();

            assert_eq!(signed_tx.auth().origin().num_signatures(), 1);
            assert_eq!(signed_tx.auth().sponsor().unwrap().num_signatures(), 2);

            // tx and signed_tx are otherwise equal
            assert_eq!(tx.version, signed_tx.version);
            assert_eq!(tx.chain_id, signed_tx.chain_id);
            assert_eq!(tx.fee, signed_tx.fee);
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
        }
    } 

    // TODO: test microblock poison transaction
    // TODO: test StacksStrings that are not Clarity literals
}
