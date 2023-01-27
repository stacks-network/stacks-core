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

/// This module contains methods for interacting with the data contained within the messages
use crate::net::{
    Error as net_error, StackerDBChunkData, StackerDBChunkInvData, StackerDBGetChunkData,
    StackerDBGetChunkInvData,
};

use stacks_common::util::hash::{Hash160, Sha512Trunc256Sum};

use stacks_common::types::chainstate::{ConsensusHash, StacksAddress, StacksPrivateKey};

use stacks_common::types::PrivateKey;

use crate::net::stackerdb::ChunkMetadata;

use crate::chainstate::stacks::StacksPublicKey;

use stacks_common::util::secp256k1::MessageSignature;

impl ChunkMetadata {
    /// Get the digest to sign that authenticates this chunk data and metadata
    fn sighash(&self) -> Sha512Trunc256Sum {
        let mut bytes = vec![];
        bytes.extend_from_slice(&self.rc_consensus_hash.0);
        bytes.extend_from_slice(&self.chunk_id.to_be_bytes());
        bytes.extend_from_slice(&self.chunk_version.to_be_bytes());
        bytes.extend_from_slice(&self.data_hash.0);

        Sha512Trunc256Sum::from_data(&bytes)
    }

    /// Sign this chunk metadata, committing to rc_consensus_hash, chunk_id, chunk_version, and
    /// data_hash.
    pub fn sign(&mut self, privkey: &StacksPrivateKey) -> Result<(), net_error> {
        let sigh = self.sighash();
        let sig = privkey
            .sign(&sigh.0)
            .map_err(|se| net_error::SigningError(se.to_string()))?;

        self.signature = sig;
        Ok(())
    }

    /// Verify that a given principal signed this chunk metadata.
    /// Note that the address version is ignored.
    pub fn verify(&self, principal: &StacksAddress) -> Result<bool, net_error> {
        let sigh = self.sighash();
        let pubk = StacksPublicKey::recover_to_pubkey(sigh.as_bytes(), &self.signature)
            .map_err(|ve| net_error::VerifyingError(ve.to_string()))?;

        let pubkh = Hash160::from_node_public_key(&pubk);
        Ok(pubkh == principal.bytes)
    }
}

impl StackerDBChunkData {
    pub fn new(chunk_id: u32, chunk_version: u32, data: Vec<u8>) -> StackerDBChunkData {
        StackerDBChunkData {
            chunk_id,
            chunk_version,
            sig: MessageSignature::empty(),
            data,
        }
    }

    pub fn data_hash(&self) -> Sha512Trunc256Sum {
        Sha512Trunc256Sum::from_data(&self.data)
    }

    pub fn get_chunk_metadata(&self, rc_consensus_hash: ConsensusHash) -> ChunkMetadata {
        ChunkMetadata {
            rc_consensus_hash,
            chunk_id: self.chunk_id,
            chunk_version: self.chunk_version,
            data_hash: self.data_hash(),
            signature: self.sig.clone(),
        }
    }

    pub fn sign(
        &mut self,
        rc_consensus_hash: ConsensusHash,
        privk: &StacksPrivateKey,
    ) -> Result<(), net_error> {
        let mut md = self.get_chunk_metadata(rc_consensus_hash);
        md.sign(privk)?;
        self.sig = md.signature;
        Ok(())
    }

    pub fn verify(
        &self,
        rc_consensus_hash: ConsensusHash,
        addr: &StacksAddress,
    ) -> Result<bool, net_error> {
        let md = self.get_chunk_metadata(rc_consensus_hash);
        md.verify(addr)
    }
}
