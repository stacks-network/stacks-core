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

use address::AddressHashMode;
use address::public_keys_to_address_hash;
use chainstate::stacks::TransactionSpendingCondition;
use chainstate::stacks::TransactionAuth;
use chainstate::stacks::TransactionAuthFlags;
use chainstate::stacks::TransactionPublicKeyEncoding;
use chainstate::stacks::TransactionAuthFieldID;
use chainstate::stacks::TransactionAuthField;
use chainstate::stacks::StacksPublicKey;
use chainstate::stacks::StacksPrivateKey;
use chainstate::stacks::StacksAddress;
use chainstate::stacks::SinglesigSpendingCondition;
use chainstate::stacks::MultisigSpendingCondition;
use chainstate::stacks::SinglesigHashMode;
use chainstate::stacks::MultisigHashMode;
use chainstate::stacks::{
    C32_ADDRESS_VERSION_MAINNET_SINGLESIG,
    C32_ADDRESS_VERSION_MAINNET_MULTISIG,
    C32_ADDRESS_VERSION_TESTNET_SINGLESIG,
    C32_ADDRESS_VERSION_TESTNET_MULTISIG,
};
use net::StacksPublicKeyBuffer;
use net::STACKS_PUBLIC_KEY_ENCODED_SIZE;
use burnchains::Txid;
use burnchains::PrivateKey;
use burnchains::PublicKey;

use util::hash::Sha512Trunc256Sum;
use util::hash::to_hex;
use util::hash::Hash160;
use util::secp256k1::MessageSignature;
use util::secp256k1::MESSAGE_SIGNATURE_ENCODED_SIZE;

impl StacksMessageCodec for TransactionAuthField {
    fn serialize(&self) -> Vec<u8> {
        let mut res = vec![];
        match *self {
            TransactionAuthField::PublicKey(ref pubk) => {
                let field_id = 
                    if pubk.compressed() {
                        TransactionAuthFieldID::PublicKeyCompressed
                    }
                    else {
                        TransactionAuthFieldID::PublicKeyUncompressed
                    };

                let pubkey_buf = StacksPublicKeyBuffer::from_public_key(pubk);

                write_next(&mut res, &(field_id as u8));
                write_next(&mut res, &pubkey_buf);
            },
            TransactionAuthField::Signature(ref key_encoding, ref sig) => {
                let field_id = 
                    if *key_encoding == TransactionPublicKeyEncoding::Compressed {
                        TransactionAuthFieldID::SignatureCompressed
                    }
                    else {
                        TransactionAuthFieldID::SignatureUncompressed
                    };
                
                write_next(&mut res, &(field_id as u8));
                write_next(&mut res, sig);
            }
        }
        res
    }

    fn deserialize(buf: &Vec<u8>, index_ptr: &mut u32, max_size: u32) -> Result<TransactionAuthField, net_error> {
        let mut index = *index_ptr;
        let field_id : u8 = read_next(buf, &mut index, max_size)?;
        let field = match field_id {
            x if x == TransactionAuthFieldID::PublicKeyCompressed as u8 => {
                let pubkey_buf : StacksPublicKeyBuffer = read_next(buf, &mut index, max_size)?;
                let mut pubkey = pubkey_buf.to_public_key()?;
                pubkey.set_compressed(true);
                
                TransactionAuthField::PublicKey(pubkey)
            },
            x if x == TransactionAuthFieldID::PublicKeyUncompressed as u8 => {
                let pubkey_buf : StacksPublicKeyBuffer = read_next(buf, &mut index, max_size)?;
                let mut pubkey = pubkey_buf.to_public_key()?;
                pubkey.set_compressed(false);
                
                TransactionAuthField::PublicKey(pubkey)
            },
            x if x == TransactionAuthFieldID::SignatureCompressed as u8 => {
                let sig : MessageSignature = read_next(buf, &mut index, max_size)?;
                TransactionAuthField::Signature(TransactionPublicKeyEncoding::Compressed, sig)
            },
            x if x == TransactionAuthFieldID::SignatureUncompressed as u8 => {
                let sig : MessageSignature = read_next(buf, &mut index, max_size)?;
                TransactionAuthField::Signature(TransactionPublicKeyEncoding::Uncompressed, sig)
            },
            _ => {
                test_debug!("Failed to deserialize auth field ID {}", field_id);
                return Err(net_error::DeserializeError);
            }
        };

        *index_ptr = index;
        Ok(field)
    }
}

impl StacksMessageCodec for MultisigSpendingCondition {
    fn serialize(&self) -> Vec<u8> {
        let mut res = vec![];
       
        write_next(&mut res, &(self.hash_mode.clone() as u8));
        write_next(&mut res, &self.signer);
        write_next(&mut res, &self.nonce);
        write_next(&mut res, &self.fields);
        write_next(&mut res, &self.signatures_required);
        
        res
    }

    fn deserialize(buf: &Vec<u8>, index_ptr: &mut u32, max_size: u32) -> Result<MultisigSpendingCondition, net_error> {
        let mut index = *index_ptr;

        let hash_mode_u8 : u8 = read_next(buf, &mut index, max_size)?;
        let hash_mode = MultisigHashMode::from_u8(hash_mode_u8)
            .ok_or(net_error::DeserializeError)?;

        let signer : Hash160 = read_next(buf, &mut index, max_size)?;
        let nonce : u64 = read_next(buf, &mut index, max_size)?;

        let fields : Vec<TransactionAuthField> = read_next(buf, &mut index, max_size)?;
        let signatures_required: u16 = read_next(buf, &mut index, max_size)?;
        
        // read and decode _exactly_ num_signatures signature buffers
        let mut num_sigs_given : u16 = 0;
        let mut have_uncompressed = false;
        for f in fields.iter() { 
            match *f {
                TransactionAuthField::Signature(ref key_encoding, _) => {
                    num_sigs_given = num_sigs_given.checked_add(1).ok_or(net_error::DeserializeError)?;
                    if *key_encoding == TransactionPublicKeyEncoding::Uncompressed {
                        have_uncompressed = true;
                    }
                },
                TransactionAuthField::PublicKey(ref pubk) => {
                    if !pubk.compressed() {
                        have_uncompressed = true;
                    }
                }
            };
        }

        // must be given the right number of signatures
        if num_sigs_given != signatures_required {
            test_debug!("Failed to deserialize multisig spending condition: got {} sigs, expected {}", num_sigs_given, signatures_required);
            return Err(net_error::DeserializeError);
        }
        
        // must all be compressed if we're using P2WSH
        if have_uncompressed && hash_mode == MultisigHashMode::P2WSH {
            test_debug!("Failed to deserialize multisig spending condition: expected compressed keys only");
            return Err(net_error::DeserializeError);
        }

        *index_ptr = index;

        Ok(MultisigSpendingCondition {
            signer,
            nonce,
            hash_mode,
            fields,
            signatures_required
        })
    }
}

impl MultisigSpendingCondition {
    pub fn push_signature(&mut self, key_encoding: TransactionPublicKeyEncoding, signature: MessageSignature) -> () {
        self.fields.push(TransactionAuthField::Signature(key_encoding, signature));
    }

    pub fn push_public_key(&mut self, public_key: StacksPublicKey) -> () {
        self.fields.push(TransactionAuthField::PublicKey(public_key));
    }

    pub fn address_mainnet(&self) -> StacksAddress {
        StacksAddress {
            version: C32_ADDRESS_VERSION_MAINNET_MULTISIG,
            bytes: self.signer.clone()
        }
    }
    
    pub fn address_testnet(&self) -> StacksAddress {
        StacksAddress {
            version: C32_ADDRESS_VERSION_TESTNET_MULTISIG,
            bytes: self.signer.clone()
        }
    }
    
    /// Authenticate a spending condition against an initial sighash.
    /// In doing so, recover all public keys and verify that they hash to the signer
    /// via the given hash mode.
    pub fn verify(&self, initial_sighash: &Txid, cond_code: &TransactionAuthFlags) -> Result<Txid, net_error> {
        let mut pubkeys = vec![];
        let mut cur_sighash = initial_sighash.clone();
        let mut num_sigs : u16 = 0;
        let mut have_uncompressed = false;
        for field in self.fields.iter() {
            let pubkey = match field {
                TransactionAuthField::PublicKey(ref pubkey) => {
                    if !pubkey.compressed() {
                        have_uncompressed = true;
                    }
                    pubkey.clone()
                },
                TransactionAuthField::Signature(ref pubkey_encoding, ref sigbuf) => {
                    if *pubkey_encoding == TransactionPublicKeyEncoding::Uncompressed {
                        have_uncompressed = true;
                    }

                    let (pubkey, next_sighash) = TransactionSpendingCondition::next_verification(&cur_sighash, cond_code, pubkey_encoding, sigbuf)?;
                    cur_sighash = next_sighash;
                    num_sigs = num_sigs.checked_add(1).ok_or(net_error::VerifyingError("Too many signatures".to_string()))?;
                    pubkey
                }
            };
            pubkeys.push(pubkey);
        }

        if num_sigs != self.signatures_required {
            return Err(net_error::VerifyingError("Incorrect number of signatures".to_string()));
        }

        if have_uncompressed && self.hash_mode == MultisigHashMode::P2WSH {
            return Err(net_error::VerifyingError("Invalid keys -- uncompressed keys are not allowed in this hash mode".to_string()));
        }

        let addr_bytes = match StacksAddress::from_public_keys(0, &self.hash_mode.to_address_hash_mode(), num_sigs as usize, &pubkeys) {
            Some(a) => {
                a.bytes
            },
            None => {
                return Err(net_error::VerifyingError("Failed to generate address from public keys".to_string()));
            }
        };

        if addr_bytes != self.signer {
            return Err(net_error::VerifyingError(format!("Signer hash {} does not equal hash of public keys {}", addr_bytes.to_hex(), self.signer.to_hex())));
        }

        Ok(cur_sighash)
    }
}

impl StacksMessageCodec for SinglesigSpendingCondition {
    fn serialize(&self) -> Vec<u8> {
        let mut res = vec![];
       
        write_next(&mut res, &(self.hash_mode.clone() as u8));
        write_next(&mut res, &self.signer);
        write_next(&mut res, &self.nonce);
        write_next(&mut res, &(self.key_encoding.clone() as u8));
        write_next(&mut res, &self.signature);
        res
    }

    fn deserialize(buf: &Vec<u8>, index_ptr: &mut u32, max_size: u32) -> Result<SinglesigSpendingCondition, net_error> {
        let mut index = *index_ptr;
        let hash_mode_u8 : u8 = read_next(buf, &mut index, max_size)?;
        let hash_mode = SinglesigHashMode::from_u8(hash_mode_u8)
            .ok_or(net_error::DeserializeError)?;

        let signer : Hash160 = read_next(buf, &mut index, max_size)?;
        let nonce : u64 = read_next(buf, &mut index, max_size)?;

        let key_encoding_u8 : u8 = read_next(buf, &mut index, max_size)?;
        let key_encoding = TransactionPublicKeyEncoding::from_u8(key_encoding_u8)
            .ok_or(net_error::DeserializeError)?;
        
        let signature : MessageSignature = read_next(buf, &mut index, max_size)?;

        // sanity check -- must be compressed if we're using p2wpkh
        if hash_mode == SinglesigHashMode::P2WPKH && key_encoding != TransactionPublicKeyEncoding::Compressed {
            test_debug!("Incompatible hashing mode and key encoding");
            return Err(net_error::DeserializeError)
        }
        
        *index_ptr = index;

        Ok(SinglesigSpendingCondition {
            signer: signer,
            nonce: nonce,
            hash_mode: hash_mode,
            key_encoding: key_encoding,
            signature: signature
        })
    }
}

impl SinglesigSpendingCondition {
    pub fn set_signature(&mut self, signature: MessageSignature) -> () {
        self.signature = signature;
    }
   
    pub fn address_mainnet(&self) -> StacksAddress {
        let version = match self.hash_mode {
            SinglesigHashMode::P2PKH => C32_ADDRESS_VERSION_MAINNET_SINGLESIG,
            SinglesigHashMode::P2WPKH => C32_ADDRESS_VERSION_MAINNET_MULTISIG
        };
        StacksAddress {
            version: version,
            bytes: self.signer.clone()
        }
    }
    
    pub fn address_testnet(&self) -> StacksAddress {
        let version = match self.hash_mode {
            SinglesigHashMode::P2PKH => C32_ADDRESS_VERSION_TESTNET_SINGLESIG,
            SinglesigHashMode::P2WPKH => C32_ADDRESS_VERSION_TESTNET_MULTISIG
        };
        StacksAddress {
            version: version,
            bytes: self.signer.clone()
        }
    }
    
    /// Authenticate a spending condition against an initial sighash.
    /// In doing so, recover all public keys and verify that they hash to the signer
    /// via the given hash mode.
    /// Returns the final sighash
    pub fn verify(&self, initial_sighash: &Txid, cond_code: &TransactionAuthFlags) -> Result<Txid, net_error> {
        let (pubkey, next_sighash) = TransactionSpendingCondition::next_verification(initial_sighash, cond_code, &self.key_encoding, &self.signature)?;
        let addr_bytes = match StacksAddress::from_public_keys(0, &self.hash_mode.to_address_hash_mode(), 1, &vec![pubkey]) {
            Some(a) => {
                a.bytes
            }
            None => {
                return Err(net_error::VerifyingError("Failed to generate address from public key".to_string()));
            }
        };
        
        if addr_bytes != self.signer {
            return Err(net_error::VerifyingError(format!("Public key hash {} does not match signer hash {}", &addr_bytes.to_hex(), &self.signer.to_hex())));
        }

        Ok(next_sighash)
    }
}

impl StacksMessageCodec for TransactionSpendingCondition {
    fn serialize(&self) -> Vec<u8> {
        match *self {
            TransactionSpendingCondition::Singlesig(ref data) => data.serialize(),
            TransactionSpendingCondition::Multisig(ref data) => data.serialize()
        }
    }

    fn deserialize(buf: &Vec<u8>, index_ptr: &mut u32, max_size: u32) -> Result<TransactionSpendingCondition, net_error> {
        let mut index = *index_ptr;

        if (buf.len() as u32) <= index {
            return Err(net_error::UnderflowError);
        }

        // NOTE: this takes advantage of the fact that the first byte of each type variant's
        // serialized byte representation -- the hash mode -- uniquely identifies the variant.
        let hash_mode_u8 = buf[index as usize];
        let cond = match hash_mode_u8 {
            x if x == SinglesigHashMode::P2PKH as u8 || x == SinglesigHashMode::P2WPKH as u8 => {
                let cond = SinglesigSpendingCondition::deserialize(buf, &mut index, max_size)?;
                TransactionSpendingCondition::Singlesig(cond)
            }
            x if x == MultisigHashMode::P2SH as u8 || x == MultisigHashMode::P2WSH as u8 => {
                let cond = MultisigSpendingCondition::deserialize(buf, &mut index, max_size)?;
                TransactionSpendingCondition::Multisig(cond)
            }
            _ => {
                test_debug!("Invalid hash mode {}", hash_mode_u8);
                return Err(net_error::DeserializeError)
            }
        };

        *index_ptr = index;
        Ok(cond)
    }
}

impl TransactionSpendingCondition {
    pub fn new_singlesig_p2pkh(pubkey: StacksPublicKey) -> Option<TransactionSpendingCondition> {
        let signer_addr = match StacksAddress::from_public_keys(0, &AddressHashMode::SerializeP2PKH, 1, &vec![pubkey.clone()]) {
            Some(addr) => addr,
            None => {
                return None;
            }
        };

        Some(TransactionSpendingCondition::Singlesig(SinglesigSpendingCondition {
            signer: signer_addr.bytes.clone(),
            nonce: 0,
            hash_mode: SinglesigHashMode::P2PKH,
            key_encoding: if pubkey.compressed() { TransactionPublicKeyEncoding::Compressed } else { TransactionPublicKeyEncoding::Uncompressed },
            signature: MessageSignature::empty()
        }))
    }
    
    pub fn new_singlesig_p2wpkh(pubkey: StacksPublicKey) -> Option<TransactionSpendingCondition> {
        let signer_addr = match StacksAddress::from_public_keys(0, &AddressHashMode::SerializeP2WPKH, 1, &vec![pubkey.clone()]) {
            Some(addr) => addr,
            None => {
                return None;
            }
        };

        Some(TransactionSpendingCondition::Singlesig(SinglesigSpendingCondition {
            signer: signer_addr.bytes.clone(),
            nonce: 0,
            hash_mode: SinglesigHashMode::P2WPKH,
            key_encoding: TransactionPublicKeyEncoding::Compressed,
            signature: MessageSignature::empty()
        }))
    }

    pub fn new_multisig_p2sh(num_sigs: u16, pubkeys: Vec<StacksPublicKey>) -> Option<TransactionSpendingCondition> {
        let signer_addr = match StacksAddress::from_public_keys(0, &AddressHashMode::SerializeP2SH, num_sigs as usize, &pubkeys) {
            Some(addr) => addr,
            None => {
                return None;
            }
        };

        Some(TransactionSpendingCondition::Multisig(MultisigSpendingCondition {
            signer: signer_addr.bytes.clone(),
            nonce: 0,
            hash_mode: MultisigHashMode::P2SH,
            fields: vec![],
            signatures_required: num_sigs
        }))
    }

    pub fn new_multisig_p2wsh(num_sigs: u16, pubkeys: Vec<StacksPublicKey>) -> Option<TransactionSpendingCondition> {
        let signer_addr = match StacksAddress::from_public_keys(0, &AddressHashMode::SerializeP2WSH, num_sigs as usize, &pubkeys) {
            Some(addr) => addr,
            None => {
                return None;
            }
        };

        Some(TransactionSpendingCondition::Multisig(MultisigSpendingCondition {
            signer: signer_addr.bytes.clone(),
            nonce: 0,
            hash_mode: MultisigHashMode::P2WSH,
            fields: vec![],
            signatures_required: num_sigs
        }))
    }
   
    pub fn num_signatures(&self) -> u16 {
        match *self {
            TransactionSpendingCondition::Singlesig(ref data) => {
                if data.signature != MessageSignature::empty() {
                    1
                }
                else {
                    0
                }
            },
            TransactionSpendingCondition::Multisig(ref data) => {
                let mut num_sigs : u16 = 0;
                for field in data.fields.iter() {
                    if field.is_signature() {
                        num_sigs = num_sigs.checked_add(1).expect("Unreasonable amount of signatures");   // something is seriously wrong if this fails
                    }
                }
                num_sigs
            }
        }
    }

    pub fn signatures_required(&self) -> u16 {
        match *self {
            TransactionSpendingCondition::Singlesig(_) => 1,
            TransactionSpendingCondition::Multisig(ref multisig_data) => multisig_data.signatures_required
        }
    }

    pub fn nonce(&self) -> u64 {
        match *self {
            TransactionSpendingCondition::Singlesig(ref data) => data.nonce,
            TransactionSpendingCondition::Multisig(ref data) => data.nonce,
        }
    }

    pub fn set_nonce(&mut self, n: u64) -> () {
        match *self {
            TransactionSpendingCondition::Singlesig(ref mut singlesig_data) => {
                singlesig_data.nonce = n;
            }
            TransactionSpendingCondition::Multisig(ref mut multisig_data) => {
                multisig_data.nonce = n;
            }
        }
    }

    /// Get the mainnet account address of the spending condition
    pub fn address_mainnet(&self) -> StacksAddress {
        match *self {
            TransactionSpendingCondition::Singlesig(ref data) => data.address_mainnet(),
            TransactionSpendingCondition::Multisig(ref data) => data.address_mainnet()
        }
    }
    
    /// Get the mainnet account address of the spending condition
    pub fn address_testnet(&self) -> StacksAddress {
        match *self {
            TransactionSpendingCondition::Singlesig(ref data) => data.address_testnet(),
            TransactionSpendingCondition::Multisig(ref data) => data.address_testnet()
        }
    }

    /// Clear signatures and public keys
    pub fn clear(&mut self) -> () {
        match *self {
            TransactionSpendingCondition::Singlesig(ref mut singlesig_data) => {
                singlesig_data.signature = MessageSignature::empty();
            }
            TransactionSpendingCondition::Multisig(ref mut multisig_data) => {
                multisig_data.fields.clear();
            }
        }
    }

    /// Calculate the next sighash from the current sighash (initially the hash of the transaction
    /// with a cleared TransactionAuth), as well as the data being committed to.
    pub fn make_sighash(cur_sighash: &Txid, cond_code: &TransactionAuthFlags, pubkey: &StacksPublicKey, sig: &MessageSignature) -> Txid {
        // new hash combines the previous hash and all the new data this signature will add.  This
        // includes:
        // * the previous hash
        // * the auth flag
        // * the public key's compressed bit
        // * the public key
        // * the signature
        let new_tx_hash_bits_len = 32 + 1 + 1 + STACKS_PUBLIC_KEY_ENCODED_SIZE + MESSAGE_SIGNATURE_ENCODED_SIZE;
        let mut new_tx_hash_bits = Vec::with_capacity(new_tx_hash_bits_len as usize);
        let pubkey_encoding = 
            if pubkey.compressed() {
                TransactionPublicKeyEncoding::Compressed
            }
            else {
                TransactionPublicKeyEncoding::Uncompressed
            };

        let pubkey_buf = StacksPublicKeyBuffer::from_public_key(pubkey);

        new_tx_hash_bits.extend_from_slice(cur_sighash.as_bytes());
        new_tx_hash_bits.extend_from_slice(&[*cond_code as u8]);
        new_tx_hash_bits.extend_from_slice(&[pubkey_encoding as u8]);
        new_tx_hash_bits.extend_from_slice(pubkey_buf.as_bytes());
        new_tx_hash_bits.extend_from_slice(sig.as_bytes());

        assert!(new_tx_hash_bits.len() == new_tx_hash_bits_len as usize);

        let next_sighash = Txid::from_sighash_bytes(&new_tx_hash_bits);
        next_sighash
    }

    /// Linear-complexity signing algorithm -- we sign a rolling hash over all data committed to by
    /// the previous signer (instead of naively re-serializing the transaction each time).
    /// Calculates and returns the next signature and sighash, which the subsequent private key
    /// must sign.
    pub fn next_signature(cur_sighash: &Txid, cond_code: &TransactionAuthFlags, privk: &StacksPrivateKey) -> Result<(MessageSignature, Txid), net_error> {
        // sign the current hash
        let mut digest_bits = [0u8; 32];
        digest_bits.copy_from_slice(cur_sighash.as_bytes());

        let sig = privk.sign(&digest_bits)
            .map_err(|se| net_error::SigningError(se.to_string()))?;

        let pubk = StacksPublicKey::from_private(privk);
        let next_sighash = TransactionSpendingCondition::make_sighash(cur_sighash, cond_code, &pubk, &sig);
        
        Ok((sig, next_sighash))
    }
    
    /// Linear-complexity verifying algorithm -- we verify a rolling hash over all data committed
    /// to by order of signers (instead of re-serializing the tranasction each time).
    /// Calculates the next sighash and public key, which the next verifier must verify.
    /// Used by StacksTransaction::verify*
    pub fn next_verification(cur_sighash: &Txid, cond_code: &TransactionAuthFlags, key_encoding: &TransactionPublicKeyEncoding, sig: &MessageSignature) -> Result<(StacksPublicKey, Txid), net_error> {
        // verify the current signature
        let mut digest_bits = [0u8; 32];
        digest_bits.copy_from_slice(cur_sighash.as_bytes());

        let mut pubk = StacksPublicKey::recover_to_pubkey(cur_sighash.as_bytes(), sig)
            .map_err(|ve| net_error::VerifyingError(ve.to_string()))?;

        match key_encoding {
            TransactionPublicKeyEncoding::Compressed => pubk.set_compressed(true),
            TransactionPublicKeyEncoding::Uncompressed => pubk.set_compressed(false)
        };

        // what's the next sighash going to be?
        let next_sighash = TransactionSpendingCondition::make_sighash(cur_sighash, cond_code, &pubk, sig);
        Ok((pubk, next_sighash))
    }

    /// Verify all signatures
    pub fn verify(&self, initial_sighash: &Txid, cond_code: &TransactionAuthFlags) -> Result<Txid, net_error> {
        match *self {
            TransactionSpendingCondition::Singlesig(ref data) => data.verify(initial_sighash, cond_code),
            TransactionSpendingCondition::Multisig(ref data) => data.verify(initial_sighash, cond_code)
        }
    }
}

impl StacksMessageCodec for TransactionAuth {
    fn serialize(&self) -> Vec<u8> {
        let mut res = vec![];
        match *self {
            TransactionAuth::Standard(ref origin_condition) => {
                write_next(&mut res, &(TransactionAuthFlags::AuthStandard as u8));
                write_next(&mut res, origin_condition);
            },
            TransactionAuth::Sponsored(ref origin_condition, ref sponsor_condition) => {
                write_next(&mut res, &(TransactionAuthFlags::AuthSponsored as u8));
                write_next(&mut res, origin_condition);
                write_next(&mut res, sponsor_condition);
            }
        }
        res
    }

    fn deserialize(buf: &Vec<u8>, index_ptr: &mut u32, max_size: u32) -> Result<TransactionAuth, net_error> {
        let mut index = *index_ptr;
        
        let type_id : u8 = read_next(buf, &mut index, max_size)?;
        let auth = match type_id {
            x if x == TransactionAuthFlags::AuthStandard as u8 => {
                let origin_auth : TransactionSpendingCondition = read_next(buf, &mut index, max_size)?;
                TransactionAuth::Standard(origin_auth)
            },
            x if x == TransactionAuthFlags::AuthSponsored as u8 => {
                let origin_auth : TransactionSpendingCondition = read_next(buf, &mut index, max_size)?;
                let sponsor_auth : TransactionSpendingCondition = read_next(buf, &mut index, max_size)?;
                TransactionAuth::Sponsored(origin_auth, sponsor_auth)
            },
            _ => {
                test_debug!("Unrecognized transaction auth flags {:?}", type_id);
                return Err(net_error::DeserializeError);
            }
        };
        
        *index_ptr = index;
        Ok(auth)
    }
}

impl TransactionAuth {
    pub fn from_p2pkh(privk: &StacksPrivateKey) -> Option<TransactionAuth> {
        match TransactionSpendingCondition::new_singlesig_p2pkh(StacksPublicKey::from_private(privk)) {
            Some(auth) => Some(TransactionAuth::Standard(auth)),
            None => None
        }
    }

    pub fn from_p2sh(privks: &Vec<StacksPrivateKey>, num_sigs: u16) -> Option<TransactionAuth> {
        let mut pubks = vec![];
        for privk in privks.iter() {
            pubks.push(StacksPublicKey::from_private(privk));
        }

        match TransactionSpendingCondition::new_multisig_p2sh(num_sigs, pubks) {
            Some(auth) => Some(TransactionAuth::Standard(auth)),
            None => None
        }
    }

    pub fn from_p2wpkh(privk: &StacksPrivateKey) -> Option<TransactionAuth> {
        match TransactionSpendingCondition::new_singlesig_p2wpkh(StacksPublicKey::from_private(privk)) {
            Some(auth) => Some(TransactionAuth::Standard(auth)),
            None => None
        }
    }

    pub fn from_p2wsh(privks: &Vec<StacksPrivateKey>, num_sigs: u16) -> Option<TransactionAuth> {
        let mut pubks = vec![];
        for privk in privks.iter() {
            pubks.push(StacksPublicKey::from_private(privk));
        }

        match TransactionSpendingCondition::new_multisig_p2wsh(num_sigs, pubks) {
            Some(auth) => Some(TransactionAuth::Standard(auth)),
            None => None
        }
    }

    // merge two standard auths into a sponsored auth.
    // build them with the above helper methods
    pub fn into_sponsored(self, sponsor_auth: TransactionAuth) -> Option<TransactionAuth> {
        match (self, sponsor_auth) {
            (TransactionAuth::Standard(sc), TransactionAuth::Standard(sp)) => Some(TransactionAuth::Sponsored(sc, sp)),
            (_, _) => None,
        }
    }

    pub fn is_standard(&self) -> bool {
        match *self {
            TransactionAuth::Standard(_) => true,
            _ => false
        }
    }

    pub fn is_sponsored(&self) -> bool {
        match *self {
            TransactionAuth::Sponsored(_, _) => true,
            _ => false
        }
    }

    pub fn origin(&self) -> &TransactionSpendingCondition {
        match *self {
            TransactionAuth::Standard(ref s) => s,
            TransactionAuth::Sponsored(ref s, _) => s
        }
    }
   
    pub fn sponsor(&self) -> Option<&TransactionSpendingCondition> {
        match *self {
            TransactionAuth::Standard(_) => None,
            TransactionAuth::Sponsored(_, ref s) => Some(s)
        }
    }

    pub fn verify(&self, initial_sighash: &Txid) -> Result<bool, net_error> {
        match *self {
            TransactionAuth::Standard(ref origin_condition) => {
                origin_condition.verify(initial_sighash, &TransactionAuthFlags::AuthStandard)
                    .and_then(|_sigh| Ok(true))
            }
            TransactionAuth::Sponsored(ref origin_condition, ref sponsor_condition) => {
                let next_sighash = origin_condition.verify(initial_sighash, &TransactionAuthFlags::AuthStandard)?;
                sponsor_condition.verify(&next_sighash, &TransactionAuthFlags::AuthSponsored)
                    .and_then(|_sigh| Ok(true))
            }
        }
    }
    
    pub fn clear(&mut self) -> () {
        match *self {
            TransactionAuth::Standard(ref mut origin_condition) => {
                origin_condition.clear();
            },
            TransactionAuth::Sponsored(ref mut origin_condition, ref mut sponsor_condition) => {
                origin_condition.clear();
                sponsor_condition.clear();
            }
        }
    }
}

#[cfg(test)]
mod test {
    use super::*;
    use chainstate::stacks::*;
    use net::*;
    use net::codec::*;
    use net::codec::test::check_codec_and_corruption;
    use chainstate::stacks::StacksPublicKey as PubKey;

    #[test]
    fn tx_stacks_spending_condition_p2pkh() {
        // p2pkh
        let spending_condition_p2pkh_uncompressed = SinglesigSpendingCondition {
            signer: Hash160([0x11; 20]),
            hash_mode: SinglesigHashMode::P2PKH,
            key_encoding: TransactionPublicKeyEncoding::Uncompressed,
            nonce: 123,
            signature: MessageSignature::from_raw(&vec![0xff; 65])
        };

        let spending_condition_p2pkh_uncompressed_bytes = vec![
            // hash mode
            SinglesigHashMode::P2PKH as u8,
            // signer
            0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11,
            // nonce
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x7b,
            // key encoding,
            TransactionPublicKeyEncoding::Uncompressed as u8,
            // signature
            0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
            0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
            0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
            0xff, 0xff, 0xff, 0xff, 0xff
        ];
        
        let spending_condition_p2pkh_compressed = SinglesigSpendingCondition {
            signer: Hash160([0x11; 20]),
            hash_mode: SinglesigHashMode::P2PKH,
            key_encoding: TransactionPublicKeyEncoding::Compressed,
            nonce: 345,
            signature: MessageSignature::from_raw(&vec![0xfe; 65]),
        };

        let spending_condition_p2pkh_compressed_bytes = vec![
            // hash mode
            SinglesigHashMode::P2PKH as u8,
            // signer
            0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11,
            // nonce
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01, 0x59,
            // key encoding
            TransactionPublicKeyEncoding::Compressed as u8,
            // signature
            0xfe, 0xfe, 0xfe, 0xfe, 0xfe, 0xfe, 0xfe, 0xfe, 0xfe, 0xfe, 0xfe, 0xfe, 0xfe, 0xfe, 0xfe, 0xfe, 0xfe, 0xfe, 0xfe, 0xfe,
            0xfe, 0xfe, 0xfe, 0xfe, 0xfe, 0xfe, 0xfe, 0xfe, 0xfe, 0xfe, 0xfe, 0xfe, 0xfe, 0xfe, 0xfe, 0xfe, 0xfe, 0xfe, 0xfe, 0xfe,
            0xfe, 0xfe, 0xfe, 0xfe, 0xfe, 0xfe, 0xfe, 0xfe, 0xfe, 0xfe, 0xfe, 0xfe, 0xfe, 0xfe, 0xfe, 0xfe, 0xfe, 0xfe, 0xfe, 0xfe,
            0xfe, 0xfe, 0xfe, 0xfe, 0xfe
        ];

        let spending_conditions = vec![spending_condition_p2pkh_compressed, spending_condition_p2pkh_uncompressed];
        let spending_conditions_bytes = vec![spending_condition_p2pkh_compressed_bytes, spending_condition_p2pkh_uncompressed_bytes];

        for i in 0..spending_conditions.len() {
            check_codec_and_corruption::<SinglesigSpendingCondition>(&spending_conditions[i], &spending_conditions_bytes[i]);
        }
    }
    
    #[test]
    fn tx_stacks_spending_condition_p2sh() {
        // p2sh
        let spending_condition_p2sh_uncompressed = MultisigSpendingCondition {
            signer: Hash160([0x11; 20]),
            hash_mode: MultisigHashMode::P2SH,
            nonce: 123,
            fields: vec![
                TransactionAuthField::Signature(TransactionPublicKeyEncoding::Uncompressed, MessageSignature::from_raw(&vec![0xff; 65])),
                TransactionAuthField::Signature(TransactionPublicKeyEncoding::Uncompressed, MessageSignature::from_raw(&vec![0xfe; 65])),
                TransactionAuthField::PublicKey(PubKey::from_hex("04ef2340518b5867b23598a9cf74611f8b98064f7d55cdb8c107c67b5efcbc5c771f112f919b00a6c6c5f51f7c63e1762fe9fac9b66ec75a053db7f51f4a52712b").unwrap()),
            ],
            signatures_required: 2
        };
        
        let spending_condition_p2sh_uncompressed_bytes = vec![
            // hash mode
            MultisigHashMode::P2SH as u8,
            // signer
            0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11,
            // nonce
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x7b,
            // fields length
            0x00, 0x00, 0x00, 0x03,
            // field #1: signature 
            TransactionAuthFieldID::SignatureUncompressed as u8,
            // field #1: signature
            0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
            0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
            0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
            0xff, 0xff, 0xff, 0xff, 0xff,
            // field #2: signature
            TransactionAuthFieldID::SignatureUncompressed as u8,
            // filed #2: signature
            0xfe, 0xfe, 0xfe, 0xfe, 0xfe, 0xfe, 0xfe, 0xfe, 0xfe, 0xfe, 0xfe, 0xfe, 0xfe, 0xfe, 0xfe, 0xfe, 0xfe, 0xfe, 0xfe, 0xfe,
            0xfe, 0xfe, 0xfe, 0xfe, 0xfe, 0xfe, 0xfe, 0xfe, 0xfe, 0xfe, 0xfe, 0xfe, 0xfe, 0xfe, 0xfe, 0xfe, 0xfe, 0xfe, 0xfe, 0xfe,
            0xfe, 0xfe, 0xfe, 0xfe, 0xfe, 0xfe, 0xfe, 0xfe, 0xfe, 0xfe, 0xfe, 0xfe, 0xfe, 0xfe, 0xfe, 0xfe, 0xfe, 0xfe, 0xfe, 0xfe,
            0xfe, 0xfe, 0xfe, 0xfe, 0xfe,
            // field #3: public key
            TransactionAuthFieldID::PublicKeyUncompressed as u8,
            // field #3: key (compressed)
            0x03, 0xef, 0x23, 0x40, 0x51, 0x8b, 0x58, 0x67, 0xb2, 0x35, 0x98, 0xa9, 0xcf, 0x74, 0x61, 0x1f, 0x8b, 0x98, 0x06, 0x4f, 0x7d, 0x55, 0xcd, 0xb8, 0xc1, 0x07, 0xc6, 0x7b, 0x5e, 0xfc, 0xbc, 0x5c, 0x77,
            // number of signatures required
            0x00, 0x02
        ];
        
        let spending_condition_p2sh_compressed = MultisigSpendingCondition {
            signer: Hash160([0x11; 20]),
            hash_mode: MultisigHashMode::P2SH,
            nonce: 456,
            fields: vec![
                TransactionAuthField::Signature(TransactionPublicKeyEncoding::Compressed, MessageSignature::from_raw(&vec![0xff; 65])),
                TransactionAuthField::Signature(TransactionPublicKeyEncoding::Compressed, MessageSignature::from_raw(&vec![0xfe; 65])),
                TransactionAuthField::PublicKey(PubKey::from_hex("03ef2340518b5867b23598a9cf74611f8b98064f7d55cdb8c107c67b5efcbc5c77").unwrap())
            ],
            signatures_required: 2
        };

        let spending_condition_p2sh_compressed_bytes = vec![
            // hash mode
            MultisigHashMode::P2SH as u8,
            // signer
            0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11,
            // nonce
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01, 0xc8,
            // fields length
            0x00, 0x00, 0x00, 0x03,
            // field #1: signature 
            TransactionAuthFieldID::SignatureCompressed as u8,
            // field #1: signature
            0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
            0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
            0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
            0xff, 0xff, 0xff, 0xff, 0xff,
            // field #2: signature
            TransactionAuthFieldID::SignatureCompressed as u8,
            // filed #2: signature
            0xfe, 0xfe, 0xfe, 0xfe, 0xfe, 0xfe, 0xfe, 0xfe, 0xfe, 0xfe, 0xfe, 0xfe, 0xfe, 0xfe, 0xfe, 0xfe, 0xfe, 0xfe, 0xfe, 0xfe,
            0xfe, 0xfe, 0xfe, 0xfe, 0xfe, 0xfe, 0xfe, 0xfe, 0xfe, 0xfe, 0xfe, 0xfe, 0xfe, 0xfe, 0xfe, 0xfe, 0xfe, 0xfe, 0xfe, 0xfe,
            0xfe, 0xfe, 0xfe, 0xfe, 0xfe, 0xfe, 0xfe, 0xfe, 0xfe, 0xfe, 0xfe, 0xfe, 0xfe, 0xfe, 0xfe, 0xfe, 0xfe, 0xfe, 0xfe, 0xfe,
            0xfe, 0xfe, 0xfe, 0xfe, 0xfe,
            // field #3: public key
            TransactionAuthFieldID::PublicKeyCompressed as u8,
            // field #3: key (compressed)
            0x03, 0xef, 0x23, 0x40, 0x51, 0x8b, 0x58, 0x67, 0xb2, 0x35, 0x98, 0xa9, 0xcf, 0x74, 0x61, 0x1f, 0x8b, 0x98, 0x06, 0x4f, 0x7d, 0x55, 0xcd, 0xb8, 0xc1, 0x07, 0xc6, 0x7b, 0x5e, 0xfc, 0xbc, 0x5c, 0x77,
            // number of signatures
            0x00, 0x02
        ];

        let spending_conditions = vec![spending_condition_p2sh_compressed, spending_condition_p2sh_uncompressed];
        let spending_conditions_bytes = vec![spending_condition_p2sh_compressed_bytes, spending_condition_p2sh_uncompressed_bytes];

        for i in 0..spending_conditions.len() {
            check_codec_and_corruption::<MultisigSpendingCondition>(&spending_conditions[i], &spending_conditions_bytes[i]);
        }
    }

    #[test]
    fn tx_stacks_spending_condition_p2wpkh() {
        let spending_condition_p2wpkh_compressed = SinglesigSpendingCondition {
            signer: Hash160([0x11; 20]),
            hash_mode: SinglesigHashMode::P2WPKH,
            key_encoding: TransactionPublicKeyEncoding::Compressed,
            nonce: 345,
            signature: MessageSignature::from_raw(&vec![0xfe; 65]),
        };

        let spending_condition_p2wpkh_compressed_bytes = vec![
            // hash mode
            SinglesigHashMode::P2WPKH as u8,
            // signer
            0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11,
            // nonce
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01, 0x59,
            // key encoding
            TransactionPublicKeyEncoding::Compressed as u8,
            // signature
            0xfe, 0xfe, 0xfe, 0xfe, 0xfe, 0xfe, 0xfe, 0xfe, 0xfe, 0xfe, 0xfe, 0xfe, 0xfe, 0xfe, 0xfe, 0xfe, 0xfe, 0xfe, 0xfe, 0xfe,
            0xfe, 0xfe, 0xfe, 0xfe, 0xfe, 0xfe, 0xfe, 0xfe, 0xfe, 0xfe, 0xfe, 0xfe, 0xfe, 0xfe, 0xfe, 0xfe, 0xfe, 0xfe, 0xfe, 0xfe,
            0xfe, 0xfe, 0xfe, 0xfe, 0xfe, 0xfe, 0xfe, 0xfe, 0xfe, 0xfe, 0xfe, 0xfe, 0xfe, 0xfe, 0xfe, 0xfe, 0xfe, 0xfe, 0xfe, 0xfe,
            0xfe, 0xfe, 0xfe, 0xfe, 0xfe
        ];

        let spending_conditions = vec![spending_condition_p2wpkh_compressed];
        let spending_conditions_bytes = vec![spending_condition_p2wpkh_compressed_bytes];

        for i in 0..spending_conditions.len() {
            check_codec_and_corruption::<SinglesigSpendingCondition>(&spending_conditions[i], &spending_conditions_bytes[i]);
        }
    }

    #[test]
    fn tx_stacks_spending_condition_p2wsh() {
        let spending_condition_p2wsh = MultisigSpendingCondition {
            signer: Hash160([0x11; 20]),
            hash_mode: MultisigHashMode::P2WSH,
            nonce: 456,
            fields: vec![
                TransactionAuthField::Signature(TransactionPublicKeyEncoding::Compressed, MessageSignature::from_raw(&vec![0xff; 65])),
                TransactionAuthField::Signature(TransactionPublicKeyEncoding::Compressed, MessageSignature::from_raw(&vec![0xfe; 65])),
                TransactionAuthField::PublicKey(PubKey::from_hex("03ef2340518b5867b23598a9cf74611f8b98064f7d55cdb8c107c67b5efcbc5c77").unwrap())
            ],
            signatures_required: 2
        };

        let spending_condition_p2wsh_bytes = vec![
            // hash mode
            MultisigHashMode::P2WSH as u8,
            // signer
            0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11,
            // nonce
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01, 0xc8,
            // fields length
            0x00, 0x00, 0x00, 0x03,
            // field #1: signature 
            TransactionAuthFieldID::SignatureCompressed as u8,
            // field #1: signature
            0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
            0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
            0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
            0xff, 0xff, 0xff, 0xff, 0xff,
            // field #2: signature
            TransactionAuthFieldID::SignatureCompressed as u8,
            // filed #2: signature
            0xfe, 0xfe, 0xfe, 0xfe, 0xfe, 0xfe, 0xfe, 0xfe, 0xfe, 0xfe, 0xfe, 0xfe, 0xfe, 0xfe, 0xfe, 0xfe, 0xfe, 0xfe, 0xfe, 0xfe,
            0xfe, 0xfe, 0xfe, 0xfe, 0xfe, 0xfe, 0xfe, 0xfe, 0xfe, 0xfe, 0xfe, 0xfe, 0xfe, 0xfe, 0xfe, 0xfe, 0xfe, 0xfe, 0xfe, 0xfe,
            0xfe, 0xfe, 0xfe, 0xfe, 0xfe, 0xfe, 0xfe, 0xfe, 0xfe, 0xfe, 0xfe, 0xfe, 0xfe, 0xfe, 0xfe, 0xfe, 0xfe, 0xfe, 0xfe, 0xfe,
            0xfe, 0xfe, 0xfe, 0xfe, 0xfe,
            // field #3: public key
            TransactionAuthFieldID::PublicKeyCompressed as u8,
            // field #3: key (compressed)
            0x03, 0xef, 0x23, 0x40, 0x51, 0x8b, 0x58, 0x67, 0xb2, 0x35, 0x98, 0xa9, 0xcf, 0x74, 0x61, 0x1f, 0x8b, 0x98, 0x06, 0x4f, 0x7d, 0x55, 0xcd, 0xb8, 0xc1, 0x07, 0xc6, 0x7b, 0x5e, 0xfc, 0xbc, 0x5c, 0x77,
            // number of signatures
            0x00, 0x02
        ];

        let spending_conditions = vec![spending_condition_p2wsh];
        let spending_conditions_bytes = vec![spending_condition_p2wsh_bytes];

        for i in 0..spending_conditions.len() {
            check_codec_and_corruption::<MultisigSpendingCondition>(&spending_conditions[i], &spending_conditions_bytes[i]);
        }
    }

    #[test]
    fn tx_stacks_auth() {
        // same spending conditions above
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
                nonce: 345,
                signature: MessageSignature::from_raw(&vec![0xff; 65])
            }),
            TransactionSpendingCondition::Multisig(MultisigSpendingCondition {
                signer: Hash160([0x11; 20]),
                hash_mode: MultisigHashMode::P2SH,
                nonce: 123,
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
                nonce: 345,
                signature: MessageSignature::from_raw(&vec![0xfe; 65]),
            }),
            TransactionSpendingCondition::Multisig(MultisigSpendingCondition {
                signer: Hash160([0x11; 20]),
                hash_mode: MultisigHashMode::P2WSH,
                nonce: 456,
                fields: vec![
                    TransactionAuthField::Signature(TransactionPublicKeyEncoding::Compressed, MessageSignature::from_raw(&vec![0xff; 65])),
                    TransactionAuthField::Signature(TransactionPublicKeyEncoding::Compressed, MessageSignature::from_raw(&vec![0xfe; 65])),
                    TransactionAuthField::PublicKey(PubKey::from_hex("03ef2340518b5867b23598a9cf74611f8b98064f7d55cdb8c107c67b5efcbc5c77").unwrap())
                ],
                signatures_required: 2
            })
        ];

        for i in 0..spending_conditions.len() {
            let spending_condition_bytes = spending_conditions[i].serialize();
            let spending_condition_2_bytes = spending_conditions[(i+1) % spending_conditions.len()].serialize();

            let auth_standard = TransactionAuth::Standard(spending_conditions[i].clone());
            let mut auth_standard_bytes = vec![
                TransactionAuthFlags::AuthStandard as u8
            ];
            auth_standard_bytes.append(&mut spending_condition_bytes.clone());

            let auth_sponsored = TransactionAuth::Sponsored(spending_conditions[i].clone(), spending_conditions[(i+1) % spending_conditions.len()].clone());
            let mut auth_sponsored_bytes = vec![
                TransactionAuthFlags::AuthSponsored as u8
            ];
            auth_sponsored_bytes.append(&mut spending_condition_bytes.clone());
            auth_sponsored_bytes.append(&mut spending_condition_2_bytes.clone());

            check_codec_and_corruption::<TransactionAuth>(&auth_standard, &auth_standard_bytes);
            check_codec_and_corruption::<TransactionAuth>(&auth_sponsored, &auth_sponsored_bytes);
        }
    }

    #[test]
    fn tx_stacks_invalid_spending_conditions() {
        let bad_hash_mode_bytes = vec![
            // hash mode
            0xff,
            // signer
            0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11,
            // nonce
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01, 0xc8,
            // key encoding,
            TransactionPublicKeyEncoding::Compressed as u8,
            // signature
            0xfd, 0xfd, 0xfd, 0xfd, 0xfd, 0xfd, 0xfd, 0xfd, 0xfd, 0xfd, 0xfd, 0xfd, 0xfd, 0xfd, 0xfd, 0xfd, 0xfd, 0xfd, 0xfd, 0xfd,
            0xfd, 0xfd, 0xfd, 0xfd, 0xfd, 0xfd, 0xfd, 0xfd, 0xfd, 0xfd, 0xfd, 0xfd, 0xfd, 0xfd, 0xfd, 0xfd, 0xfd, 0xfd, 0xfd, 0xfd,
            0xfd, 0xfd, 0xfd, 0xfd, 0xfd, 0xfd, 0xfd, 0xfd, 0xfd, 0xfd, 0xfd, 0xfd, 0xfd, 0xfd, 0xfd, 0xfd, 0xfd, 0xfd, 0xfd, 0xfd,
            0xfd, 0xfd, 0xfd, 0xfd, 0xfd, 0xfd
        ];
        
        let bad_hash_mode_multisig_bytes = vec![
            // hash mode
            MultisigHashMode::P2SH as u8,
            // signer
            0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11,
            // nonce
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01, 0xc8,
            // key encoding,
            TransactionPublicKeyEncoding::Compressed as u8,
            // signature
            0xfd, 0xfd, 0xfd, 0xfd, 0xfd, 0xfd, 0xfd, 0xfd, 0xfd, 0xfd, 0xfd, 0xfd, 0xfd, 0xfd, 0xfd, 0xfd, 0xfd, 0xfd, 0xfd, 0xfd,
            0xfd, 0xfd, 0xfd, 0xfd, 0xfd, 0xfd, 0xfd, 0xfd, 0xfd, 0xfd, 0xfd, 0xfd, 0xfd, 0xfd, 0xfd, 0xfd, 0xfd, 0xfd, 0xfd, 0xfd,
            0xfd, 0xfd, 0xfd, 0xfd, 0xfd, 0xfd, 0xfd, 0xfd, 0xfd, 0xfd, 0xfd, 0xfd, 0xfd, 0xfd, 0xfd, 0xfd, 0xfd, 0xfd, 0xfd, 0xfd,
            0xfd, 0xfd, 0xfd, 0xfd, 0xfd, 0xfd
        ];

        // this will parse into a singlesig spending condition, but data will still remain.
        // the reason it parses is because the public keys length field encodes a valid 2-byte
        // prefix of a public key, and the parser will lump it into a public key
        let bad_hash_mode_singlesig_bytes_parseable = vec![
            // hash mode
            SinglesigHashMode::P2PKH as u8,
            // signer
            0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11,
            // nonce (embeds key encoding and part of the parsed nonce)
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01, 0xc8,
            // number of fields (embed part of the signature)
            0x00, 0x00, 0x00, 0x01,
            // field #1: signature 
            TransactionAuthFieldID::SignatureCompressed as u8,
            // field #1: signature
            0x01, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
            0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
            0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
            0xff, 0xff, 0xff, 0xff, 0xff,
            // number of signatures
            0x00, 0x01
        ];
      
        // wrong number of public keys (too many signatures)
        let bad_public_key_count_bytes = vec![
            // hash mode
            MultisigHashMode::P2SH as u8,
            // signer
            0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11,
            // nonce
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01, 0xc8,
            // fields length
            0x00, 0x00, 0x00, 0x03,
            // field #1: signature 
            TransactionAuthFieldID::SignatureCompressed as u8,
            // field #1: signature
            0x01, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
            0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
            0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
            0xff, 0xff, 0xff, 0xff, 0xff,
            // field #2: signature
            TransactionAuthFieldID::SignatureCompressed as u8,
            // filed #2: signature
            0x02, 0xfe, 0xfe, 0xfe, 0xfe, 0xfe, 0xfe, 0xfe, 0xfe, 0xfe, 0xfe, 0xfe, 0xfe, 0xfe, 0xfe, 0xfe, 0xfe, 0xfe, 0xfe, 0xfe,
            0xfe, 0xfe, 0xfe, 0xfe, 0xfe, 0xfe, 0xfe, 0xfe, 0xfe, 0xfe, 0xfe, 0xfe, 0xfe, 0xfe, 0xfe, 0xfe, 0xfe, 0xfe, 0xfe, 0xfe,
            0xfe, 0xfe, 0xfe, 0xfe, 0xfe, 0xfe, 0xfe, 0xfe, 0xfe, 0xfe, 0xfe, 0xfe, 0xfe, 0xfe, 0xfe, 0xfe, 0xfe, 0xfe, 0xfe, 0xfe,
            0xfe, 0xfe, 0xfe, 0xfe, 0xfe,
            // field #3: public key
            TransactionAuthFieldID::PublicKeyCompressed as u8,
            // field #3: key (compressed)
            0x03, 0xef, 0x23, 0x40, 0x51, 0x8b, 0x58, 0x67, 0xb2, 0x35, 0x98, 0xa9, 0xcf, 0x74, 0x61, 0x1f, 0x8b, 0x98, 0x06, 0x4f, 0x7d, 0x55, 0xcd, 0xb8, 0xc1, 0x07, 0xc6, 0x7b, 0x5e, 0xfc, 0xbc, 0x5c, 0x77,
            // number of signatures
            0x00, 0x01
        ];
        
        // wrong number of public keys (not enough signatures)
        let bad_public_key_count_bytes_2 = vec![
            // hash mode
            MultisigHashMode::P2SH as u8,
            // signer
            0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11,
            // nonce
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01, 0xc8,
            // fields length
            0x00, 0x00, 0x00, 0x03,
            // field #1: signature 
            TransactionAuthFieldID::SignatureCompressed as u8,
            // field #1: signature
            0x01, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
            0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
            0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
            0xff, 0xff, 0xff, 0xff, 0xff,
            // field #2: signature
            TransactionAuthFieldID::SignatureCompressed as u8,
            // filed #2: signature
            0x02, 0xfe, 0xfe, 0xfe, 0xfe, 0xfe, 0xfe, 0xfe, 0xfe, 0xfe, 0xfe, 0xfe, 0xfe, 0xfe, 0xfe, 0xfe, 0xfe, 0xfe, 0xfe, 0xfe,
            0xfe, 0xfe, 0xfe, 0xfe, 0xfe, 0xfe, 0xfe, 0xfe, 0xfe, 0xfe, 0xfe, 0xfe, 0xfe, 0xfe, 0xfe, 0xfe, 0xfe, 0xfe, 0xfe, 0xfe,
            0xfe, 0xfe, 0xfe, 0xfe, 0xfe, 0xfe, 0xfe, 0xfe, 0xfe, 0xfe, 0xfe, 0xfe, 0xfe, 0xfe, 0xfe, 0xfe, 0xfe, 0xfe, 0xfe, 0xfe,
            0xfe, 0xfe, 0xfe, 0xfe, 0xfe,
            // field #3: public key
            TransactionAuthFieldID::PublicKeyCompressed as u8,
            // field #3: key (compressed)
            0x03, 0xef, 0x23, 0x40, 0x51, 0x8b, 0x58, 0x67, 0xb2, 0x35, 0x98, 0xa9, 0xcf, 0x74, 0x61, 0x1f, 0x8b, 0x98, 0x06, 0x4f, 0x7d, 0x55, 0xcd, 0xb8, 0xc1, 0x07, 0xc6, 0x7b, 0x5e, 0xfc, 0xbc, 0x5c, 0x77,
            // number of signatures
            0x00, 0x03
        ];

        // hashing mode doesn't allow uncompressed keys
        let bad_p2wpkh_uncompressed = TransactionSpendingCondition::Singlesig(SinglesigSpendingCondition {
            signer: Hash160([0x11; 20]),
            hash_mode: SinglesigHashMode::P2WPKH,
            nonce: 123,
            key_encoding: TransactionPublicKeyEncoding::Uncompressed,
            signature: MessageSignature::from_raw(&vec![0xff; 65]),
        });

        let bad_p2wpkh_uncompressed_bytes = vec![
            // hash mode
            SinglesigHashMode::P2WPKH as u8,
            // signer
            0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11,
            // nonce
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x7b,
            // public key uncompressed
            TransactionPublicKeyEncoding::Uncompressed as u8,
            // signature
            0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
            0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
            0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
            0xff, 0xff, 0xff, 0xff, 0xff
        ];
        
        // hashing mode doesn't allow uncompressed keys
        let bad_p2wsh_uncompressed = TransactionSpendingCondition::Multisig(MultisigSpendingCondition {
            signer: Hash160([0x11; 20]),
            hash_mode: MultisigHashMode::P2WSH,
            nonce: 456,
            fields: vec![
                TransactionAuthField::Signature(TransactionPublicKeyEncoding::Uncompressed, MessageSignature::from_raw(&vec![0xff; 65])),
                TransactionAuthField::Signature(TransactionPublicKeyEncoding::Uncompressed, MessageSignature::from_raw(&vec![0xfe; 65])),
                TransactionAuthField::PublicKey(PubKey::from_hex("04b7e10dd2c02dec648880ea346ece86a7820c4fa5114fb500b2645f6c972092dbe2334a653db0ab8d8ccffa6c35d3919e4cf8da3aeedafc7b9eb8235d0f2e7fdc").unwrap()),
            ],
            signatures_required: 2
        });

        let bad_p2wsh_uncompressed_bytes = vec![
            // hash mode
            MultisigHashMode::P2WSH as u8,
            // signer
            0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11,
            // nonce
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01, 0xc8,
            // number of fields
            0x00, 0x00, 0x00, 0x03,
            // signature
            TransactionAuthFieldID::SignatureUncompressed as u8,
            0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
            0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
            0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
            0xff, 0xff, 0xff, 0xff, 0xff,
            // signature
            TransactionAuthFieldID::SignatureUncompressed as u8,
            0xfe, 0xfe, 0xfe, 0xfe, 0xfe, 0xfe, 0xfe, 0xfe, 0xfe, 0xfe, 0xfe, 0xfe, 0xfe, 0xfe, 0xfe, 0xfe, 0xfe, 0xfe, 0xfe, 0xfe,
            0xfe, 0xfe, 0xfe, 0xfe, 0xfe, 0xfe, 0xfe, 0xfe, 0xfe, 0xfe, 0xfe, 0xfe, 0xfe, 0xfe, 0xfe, 0xfe, 0xfe, 0xfe, 0xfe, 0xfe,
            0xfe, 0xfe, 0xfe, 0xfe, 0xfe, 0xfe, 0xfe, 0xfe, 0xfe, 0xfe, 0xfe, 0xfe, 0xfe, 0xfe, 0xfe, 0xfe, 0xfe, 0xfe, 0xfe, 0xfe,
            0xfe, 0xfe, 0xfe, 0xfe, 0xfe,
            // key 
            TransactionAuthFieldID::PublicKeyUncompressed as u8,
            0x02, 0xb7, 0xe1, 0x0d, 0xd2, 0xc0, 0x2d, 0xec, 0x64, 0x88, 0x80, 0xea, 0x34, 0x6e, 0xce, 0x86, 0xa7, 0x82, 0x0c, 0x4f,
            0xa5, 0x11, 0x4f, 0xb5, 0x00, 0xb2, 0x64, 0x5f, 0x6c, 0x97, 0x20, 0x92, 0xdb,
            // signatures
            0x00, 0x02
        ];

        // we can serialize the invalid p2wpkh uncompressed condition, but we can't deserialize it
        assert_eq!(bad_p2wpkh_uncompressed.serialize(), bad_p2wpkh_uncompressed_bytes);
        
        // we can serialize the invalid p2wsh uncompressed condition, but we can't deserialize it
        assert_eq!(bad_p2wsh_uncompressed.serialize(), bad_p2wsh_uncompressed_bytes);

        let mut index = 0;
        assert!(TransactionSpendingCondition::deserialize(&bad_public_key_count_bytes, &mut index, bad_public_key_count_bytes.len() as u32).is_err());
        assert_eq!(index, 0);
        
        let mut index = 0;
        assert!(TransactionSpendingCondition::deserialize(&bad_public_key_count_bytes_2, &mut index, bad_public_key_count_bytes_2.len() as u32).is_err());
        assert_eq!(index, 0);

        index = 0;
        assert!(TransactionSpendingCondition::deserialize(&bad_hash_mode_bytes, &mut index, bad_hash_mode_bytes.len() as u32).is_err());
        assert_eq!(index, 0);

        index = 0;
        assert!(TransactionSpendingCondition::deserialize(&bad_hash_mode_multisig_bytes, &mut index, bad_hash_mode_multisig_bytes.len() as u32).is_err());
        assert_eq!(index, 0);
        
        index = 0;
        assert!(TransactionSpendingCondition::deserialize(&bad_p2wpkh_uncompressed_bytes, &mut index, bad_p2wpkh_uncompressed_bytes.len() as u32).is_err());
        assert_eq!(index, 0);
        
        index = 0;
        assert!(TransactionSpendingCondition::deserialize(&bad_p2wsh_uncompressed_bytes, &mut index, bad_p2wsh_uncompressed_bytes.len() as u32).is_err());
        assert_eq!(index, 0);
        
        // corrupt but will parse with trailing bits
        index = 0;
        assert!(TransactionSpendingCondition::deserialize(&bad_hash_mode_singlesig_bytes_parseable, &mut index, bad_hash_mode_singlesig_bytes_parseable.len() as u32).is_ok());
        assert!(index < bad_hash_mode_singlesig_bytes_parseable.len() as u32);   // should be trailing bytes, which isn't allowed
    }

    #[test]
    fn tx_stacks_sighash() {
        let cur_sighash = Txid([0u8; 32]);
        let pubkey = StacksPublicKey::from_hex("02b30fafab3a12372c5d150d567034f37d60a91168009a779498168b0e9d8ec7f2").unwrap();
        let pubkey_uncompressed = StacksPublicKey::from_hex("04b7c7cbe36a1aed38c6324b143584a1e822bbf0c4435b102f0497ccb592baf8e964a5a270f9348285595b78855c3e33dc36708e34f9abdeeaad4d2977cb81e3a1").unwrap();
        let sig = MessageSignature([0u8; 65]);

        let mut next_sighash = TransactionSpendingCondition::make_sighash(&cur_sighash, &TransactionAuthFlags::AuthStandard, &pubkey, &sig);

        let mut expected_sighash_bytes = vec![];
        expected_sighash_bytes.extend_from_slice(cur_sighash.as_bytes());
        expected_sighash_bytes.extend_from_slice(&[TransactionAuthFlags::AuthStandard as u8]);
        expected_sighash_bytes.extend_from_slice(&[TransactionPublicKeyEncoding::Compressed as u8]);
        expected_sighash_bytes.extend_from_slice(StacksPublicKeyBuffer::from_public_key(&pubkey).as_bytes());
        expected_sighash_bytes.extend_from_slice(sig.as_bytes());
        let mut expected_sighash = Txid::from_sighash_bytes(&expected_sighash_bytes[..]);

        assert_eq!(next_sighash, expected_sighash);

        next_sighash = TransactionSpendingCondition::make_sighash(&cur_sighash, &TransactionAuthFlags::AuthStandard, &pubkey_uncompressed, &sig);

        expected_sighash_bytes.clear();
        expected_sighash_bytes.extend_from_slice(cur_sighash.as_bytes());
        expected_sighash_bytes.extend_from_slice(&[TransactionAuthFlags::AuthStandard as u8]);
        expected_sighash_bytes.extend_from_slice(&[TransactionPublicKeyEncoding::Uncompressed as u8]);
        expected_sighash_bytes.extend_from_slice(StacksPublicKeyBuffer::from_public_key(&pubkey_uncompressed).as_bytes());
        expected_sighash_bytes.extend_from_slice(sig.as_bytes());
        expected_sighash = Txid::from_sighash_bytes(&expected_sighash_bytes[..]);

        assert_eq!(next_sighash, expected_sighash);

        next_sighash = TransactionSpendingCondition::make_sighash(&cur_sighash, &TransactionAuthFlags::AuthSponsored, &pubkey, &sig);

        expected_sighash_bytes.clear();
        expected_sighash_bytes.extend_from_slice(cur_sighash.as_bytes());
        expected_sighash_bytes.extend_from_slice(&[TransactionAuthFlags::AuthSponsored as u8]);
        expected_sighash_bytes.extend_from_slice(&[TransactionPublicKeyEncoding::Compressed as u8]);
        expected_sighash_bytes.extend_from_slice(StacksPublicKeyBuffer::from_public_key(&pubkey).as_bytes());
        expected_sighash_bytes.extend_from_slice(sig.as_bytes());
        expected_sighash = Txid::from_sighash_bytes(&expected_sighash_bytes[..]);

        assert_eq!(next_sighash, expected_sighash);

        next_sighash = TransactionSpendingCondition::make_sighash(&cur_sighash, &TransactionAuthFlags::AuthSponsored, &pubkey_uncompressed, &sig);
        
        expected_sighash_bytes.clear();
        expected_sighash_bytes.extend_from_slice(cur_sighash.as_bytes());
        expected_sighash_bytes.extend_from_slice(&[TransactionAuthFlags::AuthSponsored as u8]);
        expected_sighash_bytes.extend_from_slice(&[TransactionPublicKeyEncoding::Uncompressed as u8]);
        expected_sighash_bytes.extend_from_slice(StacksPublicKeyBuffer::from_public_key(&pubkey_uncompressed).as_bytes());
        expected_sighash_bytes.extend_from_slice(sig.as_bytes());
        expected_sighash = Txid::from_sighash_bytes(&expected_sighash_bytes[..]);
        
        assert_eq!(next_sighash, expected_sighash);
    }

    #[test]
    fn tx_stacks_signature() {
        let cur_sighash = Txid([0u8; 32]);
        let privk = StacksPrivateKey::from_hex("6d430bb91222408e7706c9001cfaeb91b08c2be6d5ac95779ab52c6b431950e001").unwrap();
        let privk_uncompressed = StacksPrivateKey::from_hex("6d430bb91222408e7706c9001cfaeb91b08c2be6d5ac95779ab52c6b431950e0").unwrap();

        let keys = vec![
            privk.clone(),
            privk.clone(),
            privk_uncompressed.clone(),
            privk_uncompressed.clone(),
        ];

        let key_modes = vec![
            TransactionPublicKeyEncoding::Compressed,
            TransactionPublicKeyEncoding::Compressed,
            TransactionPublicKeyEncoding::Uncompressed,
            TransactionPublicKeyEncoding::Uncompressed,
        ];

        let auth_flags = vec![
            TransactionAuthFlags::AuthStandard,
            TransactionAuthFlags::AuthSponsored,
            TransactionAuthFlags::AuthStandard,
            TransactionAuthFlags::AuthSponsored,
        ];

        for i in 0..4 {
            let (sig, next_sighash) = TransactionSpendingCondition::next_signature(&cur_sighash, &auth_flags[i], &keys[i]).unwrap();
            
            let mut expected_sighash_bytes = vec![];
            let mut expected_sighash = Txid([0u8; 32]);

            expected_sighash_bytes.clear();
            expected_sighash_bytes.extend_from_slice(cur_sighash.as_bytes());
            expected_sighash_bytes.extend_from_slice(&[auth_flags[i] as u8]);
            expected_sighash_bytes.extend_from_slice(&[key_modes[i] as u8]);
            expected_sighash_bytes.extend_from_slice(StacksPublicKeyBuffer::from_public_key(&StacksPublicKey::from_private(&keys[i])).as_bytes());
            expected_sighash_bytes.extend_from_slice(sig.as_bytes());
            expected_sighash = Txid::from_sighash_bytes(&expected_sighash_bytes[..]);

            assert_eq!(next_sighash, expected_sighash);

            let key_encoding = 
                if keys[i].compress_public() {
                    TransactionPublicKeyEncoding::Compressed
                }
                else {
                    TransactionPublicKeyEncoding::Uncompressed
                };
        
            let (next_pubkey, verified_next_sighash) = TransactionSpendingCondition::next_verification(&cur_sighash, &auth_flags[i], &key_encoding, &sig).unwrap();
            
            assert_eq!(verified_next_sighash, next_sighash);
            assert_eq!(next_pubkey, StacksPublicKey::from_private(&keys[i]));
        }
    }
}
