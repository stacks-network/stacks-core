// Copyright (C) 2013-2020 Blockstack PBC, a public benefit corporation
// Copyright (C) 2020-2023 Stacks Open Internet Foundation
//
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.
//
// This program is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
// GNU General Public License for more details.
//
// You should have received a copy of the GNU General Public License
// along with this program.  If not, see <http://www.gnu.org/licenses/>.

/*
/// This module contains methods for interacting with the data contained within the messages
use crate::net::{
    Error as net_error, StackerDBChunkData, StackerDBChunkInvData, StackerDBGetChunkData,
    StackerDBGetChunkInvData,
};

use sha2::{Digest, Sha512_256};

use stacks_common::util::hash::{Hash160, Sha512Trunc256Sum};

use stacks_common::types::chainstate::{ConsensusHash, StacksAddress, StacksPrivateKey};

use stacks_common::types::PrivateKey;

use crate::net::stackerdb::SlotMetadata;

use crate::chainstate::stacks::StacksPublicKey;

use stacks_common::util::secp256k1::MessageSignature;

impl SlotMetadata {
    /// Make a new unsigned slot metadata
    pub fn new_unsigned(
        slot_id: u32,
        slot_version: u32,
        data_hash: Sha512Trunc256Sum,
    ) -> SlotMetadata {
        SlotMetadata {
            slot_id,
            slot_version,
            data_hash,
            signature: MessageSignature::empty(),
        }
    }

    /// Get the digest to sign that authenticates this chunk data and metadata
    fn auth_digest(&self) -> Sha512Trunc256Sum {
        let mut hasher = Sha512_256::new();
        hasher.update(&self.slot_id.to_be_bytes());
        hasher.update(&self.slot_version.to_be_bytes());
        hasher.update(&self.data_hash.0);
        Sha512Trunc256Sum::from_hasher(hasher)
    }

    /// Sign this slot metadata, committing to slot_id, slot_version, and
    /// data_hash.  Sets self.signature to the signature.
    /// Fails if the underlying crypto library fails
    pub fn sign(&mut self, privkey: &StacksPrivateKey) -> Result<(), net_error> {
        let auth_digest = self.auth_digest();
        let sig = privkey
            .sign(&auth_digest.0)
            .map_err(|se| net_error::SigningError(se.to_string()))?;

        self.signature = sig;
        Ok(())
    }

    /// Verify that a given principal signed this chunk metadata.
    /// Note that the address version is ignored.
    pub fn verify(&self, principal: &StacksAddress) -> Result<bool, net_error> {
        let sigh = self.auth_digest();
        let pubk = StacksPublicKey::recover_to_pubkey(sigh.as_bytes(), &self.signature)
            .map_err(|ve| net_error::VerifyingError(ve.to_string()))?;

        let pubkh = Hash160::from_node_public_key(&pubk);
        Ok(pubkh == principal.bytes)
    }
}

/// Helper methods for StackerDBChunkData messages
impl StackerDBChunkData {
    /// Create a new StackerDBChunkData instance.
    pub fn new(slot_id: u32, slot_version: u32, data: Vec<u8>) -> StackerDBChunkData {
        StackerDBChunkData {
            slot_id,
            slot_version,
            sig: MessageSignature::empty(),
            data,
        }
    }

    /// Calculate the hash of the chunk bytes.  This is the SHA512/256 hash of the data.
    pub fn data_hash(&self) -> Sha512Trunc256Sum {
        Sha512Trunc256Sum::from_data(&self.data)
    }

    /// Create an owned SlotMetadata describing the metadata of this slot.
    pub fn get_slot_metadata(&self) -> SlotMetadata {
        SlotMetadata {
            slot_id: self.slot_id,
            slot_version: self.slot_version,
            data_hash: self.data_hash(),
            signature: self.sig.clone(),
        }
    }

    /// Sign this given chunk data message with the given private key.
    /// Sets self.signature to the signature.
    /// Fails if the underlying signing library fails.
    pub fn sign(&mut self, privk: &StacksPrivateKey) -> Result<(), net_error> {
        let mut md = self.get_slot_metadata();
        md.sign(privk)?;
        self.sig = md.signature;
        Ok(())
    }

    /// Verify that this chunk was signed by the given
    /// public key hash (`addr`).  Only fails if the underlying signing library fails.
    pub fn verify(&self, addr: &StacksAddress) -> Result<bool, net_error> {
        let md = self.get_slot_metadata();
        md.verify(addr)
    }
}
*/
