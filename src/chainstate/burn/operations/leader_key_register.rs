// Copyright (C) 2013-2020 Blockstack PBC, a public benefit corporation
// Copyright (C) 2020 Stacks Open Internet Foundation
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

use std::io::{Read, Write};

use crate::codec::{write_next, Error as codec_error, StacksMessageCodec};
use crate::types::chainstate::StacksAddress;
use crate::types::proof::TrieHash;
use address::AddressHashMode;
use burnchains::Address;
use burnchains::Burnchain;
use burnchains::BurnchainBlockHeader;
use burnchains::BurnchainTransaction;
use burnchains::PublicKey;
use burnchains::Txid;
use chainstate::burn::db::sortdb::SortitionHandleTx;
use chainstate::burn::operations::Error as op_error;
use chainstate::burn::operations::{
    BlockstackOperationType, LeaderBlockCommitOp, LeaderKeyRegisterOp, UserBurnSupportOp,
};
use chainstate::burn::ConsensusHash;
use chainstate::burn::Opcodes;
use chainstate::stacks::StacksPrivateKey;
use chainstate::stacks::StacksPublicKey;
use net::Error as net_error;
use util::db::DBConn;
use util::db::DBTx;
use util::hash::DoubleSha256;
use util::log;
use util::vrf::{VRFPrivateKey, VRFPublicKey, VRF};

use crate::types::chainstate::BlockHeaderHash;
use crate::types::chainstate::BurnchainHeaderHash;

struct ParsedData {
    pub consensus_hash: ConsensusHash,
    pub public_key: VRFPublicKey,
    pub memo: Vec<u8>,
}

impl LeaderKeyRegisterOp {
    fn parse_data(data: &Vec<u8>) -> Option<ParsedData> {
        /*
            Wire format:

            0      2  3              23                       55                          80
            |------|--|---------------|-----------------------|---------------------------|
             magic  op consensus hash   proving public key               memo
                       (ignored)                                       (ignored)

             Note that `data` is missing the first 3 bytes -- the magic and op have been stripped
        */
        // memo can be empty, and magic + op are omitted
        if data.len() < 52 {
            // too short to have a consensus hash and proving public key
            warn!(
                "LEADER_KEY_REGISTER payload is malformed ({} bytes)",
                data.len()
            );
            return None;
        }

        let consensus_hash = ConsensusHash::from_bytes(&data[0..20])
            .expect("FATAL: invalid byte slice for consensus hash");
        let pubkey = match VRFPublicKey::from_bytes(&data[20..52].to_vec()) {
            Some(pubk) => pubk,
            None => {
                warn!("Invalid VRF public key");
                return None;
            }
        };

        let memo = &data[52..];

        Some(ParsedData {
            consensus_hash,
            public_key: pubkey,
            memo: memo.to_vec(),
        })
    }

    fn parse_from_tx(
        block_height: u64,
        block_hash: &BurnchainHeaderHash,
        tx: &BurnchainTransaction,
    ) -> Result<LeaderKeyRegisterOp, op_error> {
        // can't be too careful...
        let inputs = tx.get_signers();
        let outputs = tx.get_recipients();

        if inputs.len() == 0 {
            test_debug!(
                "Invalid tx: inputs: {}, outputs: {}",
                inputs.len(),
                outputs.len()
            );
            return Err(op_error::InvalidInput);
        }

        if outputs.len() < 1 {
            test_debug!(
                "Invalid tx: inputs: {}, outputs: {}",
                inputs.len(),
                outputs.len()
            );
            return Err(op_error::InvalidInput);
        }

        if tx.opcode() != Opcodes::LeaderKeyRegister as u8 {
            test_debug!("Invalid tx: invalid opcode {}", tx.opcode());
            return Err(op_error::InvalidInput);
        }

        let data = match LeaderKeyRegisterOp::parse_data(&tx.data()) {
            Some(data) => data,
            None => {
                test_debug!("Invalid tx data");
                return Err(op_error::ParseError);
            }
        };

        let address = outputs[0].address.clone();

        Ok(LeaderKeyRegisterOp {
            consensus_hash: data.consensus_hash,
            public_key: data.public_key,
            memo: data.memo,
            address: address,

            txid: tx.txid(),
            vtxindex: tx.vtxindex(),
            block_height: block_height,
            burn_header_hash: block_hash.clone(),
        })
    }
}

impl StacksMessageCodec for LeaderKeyRegisterOp {
    /*
        Wire format:

        0      2  3              23                       55                          80
        |------|--|---------------|-----------------------|---------------------------|
         magic  op consensus hash    proving public key               memo
                   (ignored)                                       (ignored)
    */
    fn consensus_serialize<W: Write>(&self, fd: &mut W) -> Result<(), codec_error> {
        write_next(fd, &(Opcodes::LeaderKeyRegister as u8))?;
        write_next(fd, &self.consensus_hash)?;
        fd.write_all(&self.public_key.as_bytes()[..])
            .map_err(codec_error::WriteError)?;

        let memo = match self.memo.len() {
            l if l <= 25 => self.memo[0..].to_vec(),
            _ => self.memo[0..25].to_vec(),
        };
        fd.write_all(&memo).map_err(codec_error::WriteError)?;
        Ok(())
    }

    fn consensus_deserialize<R: Read>(_fd: &mut R) -> Result<LeaderKeyRegisterOp, codec_error> {
        // Op deserialized through burchain indexer
        unimplemented!();
    }
}

impl LeaderKeyRegisterOp {
    pub fn from_tx(
        block_header: &BurnchainBlockHeader,
        tx: &BurnchainTransaction,
    ) -> Result<LeaderKeyRegisterOp, op_error> {
        LeaderKeyRegisterOp::parse_from_tx(block_header.block_height, &block_header.block_hash, tx)
    }

    pub fn check(
        &self,
        _burnchain: &Burnchain,
        tx: &mut SortitionHandleTx,
    ) -> Result<(), op_error> {
        /////////////////////////////////////////////////////////////////
        // Keys must be unique -- no one can register the same key twice
        /////////////////////////////////////////////////////////////////

        // key selected here must never have been submitted on this fork before
        let has_key_already = tx.has_VRF_public_key(&self.public_key)?;

        if has_key_already {
            warn!(
                "Invalid leader key registration: public key {} previously used",
                &self.public_key.to_hex()
            );
            return Err(op_error::LeaderKeyAlreadyRegistered);
        }

        Ok(())
    }
}
