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

use address::c32::{
    C32_ADDRESS_VERSION_MAINNET_SINGLESIG,
    C32_ADDRESS_VERSION_MAINNET_MULTISIG,
    C32_ADDRESS_VERSION_TESTNET_SINGLESIG,
    C32_ADDRESS_VERSION_TESTNET_MULTISIG
};
    
use core::NETWORK_ID_MAINNET;
use core::NETWORK_ID_TESTNET;

use net::StacksMessageCodec;
use net::Error as net_error;
use net::codec::{read_next, write_next};

use chainstate::stacks::Error as stacks_error;

use chainstate::keys::{
    KeyEncoding,
    get_encoding_strategy
}

use chainstate::stacks::TransactionAuth;
use chainstate::stacks::StacksPublicKey;
use net::StacksPublicKeyBuffer;
use net::MessageSignature;

use util::secp256k1::Secp256k1PublicKey;

impl StacksMessageCodec for TransactionAuth {
    fn serialize(&self) -> Vec<u8> {
        let mut res = vec![];
        let public_key_buffers : Vec<StacksPublicKeyBuffer> = self.public_keys
            .iter()
            .map(|pubk| StacksPublicKeyBuffer::from_public_key(&pubk))
            .collect();

        write_next(&mut res, &self.principal);
        write_next(&mut res, &self.nonce);
        write_next(&mut res, &self.signatures_required);
        write_next(&mut res, &public_key_buffers);
        write_next(&mut res, &self.signatures);
        res
    }

    fn deserialize(buf: &Vec<u8>, index: &mut u32, max_size: u32) -> Result<TransactionAuth, net_error> {
        let principal : StacksAddress                       = read_next(buf, index, max_size)?;
        let nonce : u64                                     = read_next(buf, index, max_size)?;
        let signatures_required: u8                         = read_next(buf, index, max_size)?;
        let public_key_buffers: Vec<StacksPublicKeyBuffer>  = read_next(buf, index, max_size)?;
        let signatures: Vec<MessageSignature>               = read_next(buf, index, max_size)?;

        // attempt to parse all public keys
        let mut public_keys = vec![];
        for pubkey_buf in &public_key_buffers {
            let pubk = pubkey_buf.to_public_key()?;
            public_keys.push(pubk);
        }

        // there must be enough signatures 
        if signatures.len() < signatures_required {
            return Err(net_error::DeserializeError);
        }

        // principal address must be consistent with public key signature scheme
        if !TransactionAuth::check_principal_keys(&principal, &public_keys, signatures_required) {
            return Err(net_error::DeserializeError);
        }

        Ok(TransactionAuth {
            principal,
            nonce,
            public_keys,
            signatures,
            signatures_required
        })
    } 
}

impl TransactionAuth {
    pub fn from_raw(principal: &StacksAddress, nonce: u64, pubkeys: &Vec<StacksPublicKey>, sigs_req: u8, sigs: &Vec<[u8]>) -> Result<TransactionAuth, stacks_error> {
        let key_bufs = public_keys.iter().map(|ref pk| StacksPublicKeyBuffer::from_public_key(pk)).collect();
        let sig_bufs = vec![];

        for sig in sigs {
            match MessageSignature::from_sig(sig) {
                Some(sigbuf) => sig_bufs.push(sigbuf),
                None => return Err(stacks_error::EncodeError)
            }
        }
        
        Ok(TransactionAuth {
            principal: principal.clone(),
            nonce,
            public_keys: key_bufs,
            signatures: sig_bufs,
            signatures_required: sigs_req
        })
    }

    /// Get the public keys as StacksPublicKeys instead of buffers 
    pub fn get_public_keys(&self) -> Vec<StacksPublicKey> {
        self.public_keys.iter().map(|pkb| pkb.to_public_key()).collect()
    }

    /// Get the signatures as slices.
    /// Returns None if at least one signature buffer is invalid.
    pub fn get_signatures(&self) -> Option<Vec<[u8]>> {
        let mut sigs = vec![];
        for sig in self.signatures.iter() {
            match sig.to_sig() {
                None => {
                    return None;
                },
                Some(bits) => {
                    sigs.push(bits);
                }
            }
        }
        Some(sigs)
    }

    /// Determine if the principal is consistent with the public keys.
    /// There are four ways to encode a principal from its public key(s): via Bitcoin's p2pkh, p2sh, p2sh-p2wpkh, or p2sh-p2wsh.
    /// This is because users of Stacks v1 could have had addresses generated any of these ways.
    /// The principal StacksAddress in the TransactionAuth struct identifies which way.
    /// Note that this method does _not_ verify whether or not we're on mainnet or testnet; it only
    /// checks that the principal agrees with the keys and number of signatures
    pub fn check_principal_keys(principal: &StacksAddress, sigs_req: u8, pubkeys: &Vec<StacksPublicKey>) -> bool {
        let strategy_opt = get_encoding_strategy(&principal.bytes.as_bytes().to_vec(), sigs_req, pubkeys);
        match strategy_opt {
            None => {
                false
            },
            Some(strategy) => {
                // version byte must match strategy 
                match strategy {
                    KeyEncoding::P2PKH => {
                        principal.version_byte == C32_ADDRESS_VERSION_MAINNET_SINGLESIG || principle.version_byte == C32_ADDRESS_VERSION_TESTNET_SINGLESIG
                    }
                    _ => {
                        principal.version_byte == C32_ADDRESS_VERSION_MAINNET_MULTISIG || principle.version_byte == C32_ADDRESS_VERSION_TESTNET_MULTISIG
                    }
                }
            }
        }
    }

    /// Check that the principal matches the network
    pub fn check_principal_network(principal: &StacksAddress, network_id: u32) -> bool {
        if network_id == NETWORK_ID_MAINNET {
            principal.version_byte == C32_ADDRESS_VERSION_MAINNET_SINGLESIG || principal.version_byte == C32_ADDRESS_VERSION_MAINNET_MULTISIG
        }
        else if network_id == NETWORK_ID_TESTNET {
            principal.version_byte == C32_ADDRESS_VERSION_TESTNET_SINGLESIG || principal.version_byte == C32_ADDRESS_VERSION_TESTNET_MULTISIG
        }
        else {
            false
        }
    }

    /// Append a signature from a public key
    pub fn append_signature(&mut self, pubk: &StacksPublicKey, sig: &[u8]) -> Result<(), stacks_error> {
        match MessageSignature::from_sig(sig) {
            None => {
                return Err(stacks_error::EncodeError);
            },
            Some(sigbuf) => {
                self.public_keys.push(StacksPublicKeyBuffer::from_public_key(pubk));
                self.signatures.push(sigbuf);
            }
        }
        Ok(())
    }
}
