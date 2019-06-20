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

use net::StacksMessageCodec;
use net::Error as net_error;
use net::codec::{read_next, write_next};

use burnchains::PublicKey;
use burnchains::PrivateKey;
use burnchains::Txid;

use chainstate::stacks::StacksAddress;
use chainstate::stacks::TransactionAuth;
use chainstate::stacks::TransactionAnchorMode;
use chainstate::stacks::TransactionPayloadID;
use chainstate::stacks::TransactionPayload;
use chainstate::stacks::TransactionPayment;
use chainstate::stacks::TransactionSmartContract;
use chainstate::stacks::StacksTransaction;

use util::hash::DoubleSha256;

impl StacksMessageCodec for TransactionPayment {
    fn serialize(&self) -> Vec<u8> {
        let mut res = vec![];
        write_next(&mut res, &self.paid);
        write_next(&mut res, &self.recipient);
        res
    }

    fn deserialize(buf: &Vec<u8>, index: &mut u32, max_size: u32) -> Result<TransactionPayment, net_error> {
        let paid : u64                  = read_next(buf, index, max_size)?;
        let recipient : StacksAddress   = read_next(buf, index, max_size)?;

        Ok(TransactionPayment {
            paid,
            recipient
        })
    }
}

impl StacksMessageCodec for TransactionSmartContract {
    fn serialize(&self) -> Vec<u8> {
        let mut res = vec![];
        write_next(&mut res, &self.contract_name);
        write_next(&mut res, &self.code_body);
        res
    }

    fn deserialize(buf: &Vec<u8>, index: &mut u32, max_size: u32) -> Result<TransactionSmartContract, net_error> {
        let contract_name: Vec<u8> = read_next(buf, index, max_size)?;
        let code_body : Vec<u8> = read_next(buf, index, max_size)?;
        Ok(TransactionSmartContract {
            contract_name,
            code_body
        })
    }
}

impl StacksMessageCodec for TransactionSmartContractCall {
    fn serialize(&self) -> Vec<u8> {
        let mut res = vec![];
        write_next(&mut res, &self.code_body);
        res
    }

    fn deserialize(buf: &Vec<u8>, index: &mut u32, max_size: u32) -> Result<TransactionSmartContractCall, net_error> {
        let code_body : Vec<u8> = read_next(buf, index, max_size)?;
        Ok(TransactionSmartContractCall {
            code_body
        })
    }
}

impl StacksMessageCodec for StacksTransaction {
    fn serialize(&self) -> Vec<u8> {
        let mut ret = vec![];
        let anchor_mode = self.anchor_mode;

        write_next(&mut ret, &self.version);
        write_next(&mut ret, &self.fee);
        write_next(&mut ret, &(self.anchor_mode as u8));

        // payload will be formatted as "type (u8) payload (vec<u8>)"
        let transaction_type_id : u8 = 
            match self.payload {
                TransactionPayload::Payment(ref _t) => TransactionPayloadID::Payment as u8,
                TransactionPayload::SmartContract(ref _t) => TransactionPayloadID::SmartContract as u8,
                TransactionPayload::SmartContractCall(ref _t) => TransactionPayloadID::SmartContractCall as u8,
            };
        
        write_next(&mut ret, &transaction_type_id);

        match self.payload {
            TransactionPayload::Payment(ref t) => write_next(&mut ret, t),
            TransactionPayload::SmartContract(ref t) => write_next(&mut ret, t),
            TransactionPayload::SmartContractCall(ref t) => write_next(&mut ret, t),
        };
        
        write_next(&mut ret, &self.auth);
        ret
    }

    fn deserialize(buf: &Vec<u8>, index: &mut u32, max_size: u32) -> Result<StacksTransaction, net_error> {
        let version : u8                = read_next(buf, index, max_size)?;
        let fee : u64                   = read_next(buf, index, max_size)?;
        let transaction_anchor_id : u8  = read_next(buf, index, max_size)?;
        let transaction_type_id : u8    = read_next(buf, index, max_size)?;

        let anchor_mode = 
            if transaction_anchor_id == (TransactionAnchorMode::OffChainOnly as u8) {
                TransactionAnchorMode::OffChainOnly
            }
            else if transaction_anchor_id == (TransactionAnchorMode::OnChainOnly as u8) {
                TransactionAnchorMode::OnChainOnly
            }
            else if transaction_anchor_id == (TransactionAnchorMode::Any as u8) {
                TransactionAnchorMode::Any
            }
            else {
                return Err(net_error::DeserializeError);
            };

        let payload = 
            if transaction_type_id == (TransactionPayloadID::Payment as u8) {
                let payload_data = TransactionPayment::deserialize(buf, index, max_size)?;
                TransactionPayload::Payment(payload_data)
            }
            else if transaction_type_id == (TransactionPayloadID::SmartContract as u8) {
                let payload_data = TransactionSmartContract::deserialize(buf, index, max_size)?;
                TransactionPayload::SmartContract(payload_data)
            }
            else if transaction_type_id == (TransactionPayloadID::SmartContractCall as u8) {
                let payload_data = TransactionSmartContractCall::deserialize(buf, index, max_size)?;
                TransactionPayload::SmartContractCall(payload_data)
            }
            else {
                return Err(net_error::DeserializeError);
            };

        let auth : TransactionAuth = read_next(buf, index, max_size)?;

        Ok(StacksTransaction {
            version,
            fee,
            anchor_mode,
            payload,
            auth
        })
    }
}

impl StacksTransaction {
    /// a txid of a stacks transaction is its double-sha256 hash.
    /// Get the "raw" txid -- i.e. we don't care if the transaction is well-formed or signed
    pub fn txid(&self) -> Txid {
        let bytes_vec = self.serialize();
        let h = DoubleSha256::from_data(&bytes_vec[..]);
        
        // NOTE: safe to unwrap here since a double-sha256 and a txid are both 32 bytes
        Txid::from_bytes(h.as_bytes()).unwrap()
    }

    /// Generates a signature over the transaction with the given key.
    /// Implementation notes:
    /// * Signatures are calculated over the _double_ sha256 of the serialized bytes
    /// * The nth signature signs signatures 1...n-1, as well as the current length fields.
    /// The resulting signature will be a serialized DER-encoded signature with a low-S value.
    pub fn make_signature<K: PrivateKey>(&self, pk: &PrivateKey) -> Result<Vec<u8>, stacks_error> {
        let bytes_vec = self.serialize();
        let msg = DoubleSha256::from_data(&bytes_vec[..]).to_vec();
        let sig = pk.sign(msg).map_err(stacks_error::SigningError)?;
        sig
    }

    /// Append a signature to the transaction's auth.
    /// Can fail if sig is not well-formed
    pub fn add_signature(&mut self, pubk: &StacksPublicKey, sig: &Vec<u8>) -> Result<(), stacks_error> {
        self.auth.append_signature(pubk, sig)
    }

    /// Sign a transaction and add its public key and signature.
    pub fn sign(&mut self, pk: &Secp256k1PrivateKey) -> Result<(), stacks_error> {
        let sig = self.make_signature(pk)?;
        let pubk = StacksPublicKey::from_private(pk);
        self.add_signature(&pubk, &sig)
    }

    /// Verify a single signature over the transaction.
    /// sig is a DER-encoded low-S signature.
    /// TODO: verify over a byte range for efficiency.
    fn verify_signature(&self, pubk: &StacksPublicKey, sig: &[u8]) -> Result<(), stacks_error> {
        let bytes_vec = self.serialize();
        let msg = DoubleSha256::from_data(&bytes_vec[..]).as_bytes();
        pubk.verify(msg, sig)
            .and_then(|res| Ok(()))
            .map_err(stacks_error::VerifyingError)
    }

    /// Verify all signatures against the transaction, and verify that the principal matches the
    /// public keys, signatures, and network ID.
    /// TODO; we placed the transaction authorization struct at the very end of the transaction in
    /// order to remove the need to continuously re-serialize the transaction.  It should be
    /// possible to just update the payload length and key/sig array size fields in-place
    /// and append keys and signatures to the serialized transaction without having to re-serialize
    /// the whole transaction each time.  This method needs to be updated to do this.
    pub fn verify_principal_signatures(&self, network_id: u32) -> Result<(), stacks_error> {
        // trivial case -- there must be enough signatures
        if (self.auth.signatures_required as usize) > self.auth.signatures.len() {
            return Err(stacks_error::VerifyingError("Not enough signatures to verify"));
        }

        // must be on the same network
        if !TransactionAuth::check_principal_network(&self.auth.principal, network_id) {
            return Err(stacks_error::VerifyingError("Principal is not valid on this network"));
        }

        let mut tx = self.clone();
        let sigs_opt = tx.auth.get_signatures();

        if sigs_opt.is_none() {
            return Err(stacks_error::VerifyingError("Unencodable signature buffer"));
        }
        let sigs = sigs_opt.unwrap();
        let pubkeys = tx.auth.get_public_keys();

        // principal must match these keys 
        if !TransactionAuth::check_principal_keys(&self.auth.principal, self.auth.signatures_required, &pubkeys) {
            return Err(stacks_error::VerifyingError("Principal does not match public keys and signatures"));
        }

        // check signatures against public keys in the order they would have been applied.
        tx.auth.signatures.clear();
        tx.auth.pubkeys.clear();

        let mut sig_i = 0;
        let mut pubkey_i = 0;
        let mut num_matched = 0;

        while sig_i < sigs.len() && pubkey_i < pubkeys.len() {
            let sig = &sigs[sig_i];
            let pubkey = &pubkeys[pubkey_i];

            // TODO: avoid re-serializing the whole transaction for the sake of appending the
            // public key and signature in the auth trailer.
            match tx.verify_signature(pubkey, sig) {
                Ok(_) => {
                    // matched!
                    tx.auth.pubkeys.push(pubk.clone());
                    tx.auth.signatures.push(sigbuf.clone());

                    sig_i += 1;
                    pubkey_i += 1;
                    num_matched += 1;
                },
                Err(stacks_error::VerifyingError(_)) => {
                    // did not match!
                    // try the next public key 
                    pubkey_i += 1;
                }
                Err(e) => {
                    // some other error
                    return Err(e);
                }
            }
        }

        // no remaining signatures 
        if sig_i < sigs.len() {
            return Err(stacks_error::VerifyingError("Trailing signatures"));
        }

        // sufficiently many signatures
        if num_matched < tx.auth.signatures_required {
            return Err(stacks_error::VerifyingError("Not enough signatures"));
        }

        Ok(())
    }
}
