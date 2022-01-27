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
use std::marker::PhantomData;

use crate::codec::{write_next, Error as codec_error, StacksMessageCodec};
use crate::types::proof::TrieHash;
use burnchains::Address;
use burnchains::Burnchain;
use burnchains::BurnchainBlockHeader;
use burnchains::BurnchainTransaction;
use burnchains::PublicKey;
use burnchains::Txid;
use chainstate::burn::db::sortdb::SortitionHandleTx;
use chainstate::burn::operations::Error as op_error;
use chainstate::burn::operations::{
    parse_u16_from_be, parse_u32_from_be, BlockstackOperationType, LeaderBlockCommitOp,
    LeaderKeyRegisterOp, UserBurnSupportOp,
};
use chainstate::burn::ConsensusHash;
use chainstate::burn::Opcodes;
use net::Error as net_error;
use util::db::DBConn;
use util::db::DBTx;
use util::hash::Hash160;
use util::log;
use util::vrf::{VRFPublicKey, VRF};

use crate::types::chainstate::BlockHeaderHash;
use crate::types::chainstate::BurnchainHeaderHash;

// return type for parse_data (below)
struct ParsedData {
    pub consensus_hash: ConsensusHash,
    pub public_key: VRFPublicKey,
    pub key_block_ptr: u32,
    pub key_vtxindex: u16,
    pub block_header_hash_160: Hash160,
}

impl UserBurnSupportOp {
    fn parse_data(data: &Vec<u8>) -> Option<ParsedData> {
        /*
            Wire format:

            0      2  3              22                       54                 74       78        80
            |------|--|---------------|-----------------------|------------------|--------|---------|
             magic  op consensus hash    proving public key       block hash 160   key blk  key
                       (truncated by 1)                                                     vtxindex


             Note that `data` is missing the first 3 bytes -- the magic and op have been stripped
        */
        if data.len() < 77 {
            warn!(
                "USER_BURN_SUPPORT payload is malformed ({} bytes)",
                data.len()
            );
            return None;
        }

        let mut consensus_hash_trunc = data[0..19].to_vec();
        consensus_hash_trunc.push(0);

        let consensus_hash = ConsensusHash::from_vec(&consensus_hash_trunc)
            .expect("FATAL: invalid data slice for consensus hash");
        let pubkey = match VRFPublicKey::from_bytes(&data[19..51].to_vec()) {
            Some(pubk) => pubk,
            None => {
                warn!("Invalid VRF public key");
                return None;
            }
        };

        let block_header_hash_160 = Hash160::from_vec(&data[51..71].to_vec())
            .expect("FATAL: invalid data slice for block hash160");
        let key_block_ptr = parse_u32_from_be(&data[71..75]).unwrap();
        let key_vtxindex = parse_u16_from_be(&data[75..77]).unwrap();

        Some(ParsedData {
            consensus_hash,
            public_key: pubkey,
            block_header_hash_160,
            key_block_ptr,
            key_vtxindex,
        })
    }

    fn parse_from_tx(
        block_height: u64,
        block_hash: &BurnchainHeaderHash,
        tx: &BurnchainTransaction,
    ) -> Result<UserBurnSupportOp, op_error> {
        // can't be too careful...
        let inputs = tx.get_signers();
        let outputs = tx.get_recipients();

        if inputs.len() == 0 || outputs.len() == 0 {
            test_debug!(
                "Invalid tx: inputs: {}, outputs: {}",
                inputs.len(),
                outputs.len()
            );
            return Err(op_error::InvalidInput);
        }

        if outputs.len() < 2 {
            test_debug!(
                "Invalid tx: inputs: {}, outputs: {}",
                inputs.len(),
                outputs.len()
            );
            return Err(op_error::InvalidInput);
        }

        if tx.opcode() != Opcodes::UserBurnSupport as u8 {
            test_debug!("Invalid tx: invalid opcode {}", tx.opcode());
            return Err(op_error::InvalidInput);
        }

        // outputs[0] should be the burn output
        if !outputs[0].address.is_burn() {
            // wrong burn output
            test_debug!("Invalid tx: burn output missing (got {:?})", outputs[0]);
            return Err(op_error::ParseError);
        }

        let burn_fee = outputs[0].amount;

        let data = match UserBurnSupportOp::parse_data(&tx.data()) {
            None => {
                test_debug!("Invalid tx data");
                return Err(op_error::ParseError);
            }
            Some(d) => d,
        };

        // basic sanity checks
        if data.key_block_ptr == 0 {
            warn!("Invalid tx: key block pointer must be positive");
            return Err(op_error::ParseError);
        }

        if data.key_block_ptr as u64 > block_height {
            warn!(
                "Invalid tx: key block back-pointer {} exceeds block height {}",
                data.key_block_ptr, block_height
            );
            return Err(op_error::ParseError);
        }

        Ok(UserBurnSupportOp {
            address: outputs[1].address.clone(),
            consensus_hash: data.consensus_hash,
            public_key: data.public_key,
            block_header_hash_160: data.block_header_hash_160,
            key_block_ptr: data.key_block_ptr,
            key_vtxindex: data.key_vtxindex,
            burn_fee: burn_fee,

            txid: tx.txid(),
            vtxindex: tx.vtxindex(),
            block_height: block_height,
            burn_header_hash: block_hash.clone(),
        })
    }
}

impl StacksMessageCodec for UserBurnSupportOp {
    /*
        Wire format:

        0      2  3              22                       54                 74       78        80
        |------|--|---------------|-----------------------|------------------|--------|---------|
         magic  op consensus hash   proving public key       block hash 160   key blk  key
                (truncated by 1)                                                        vtxindex
    */
    fn consensus_serialize<W: Write>(&self, fd: &mut W) -> Result<(), codec_error> {
        write_next(fd, &(Opcodes::UserBurnSupport as u8))?;
        let truncated_consensus = self.consensus_hash.to_bytes();
        fd.write_all(&truncated_consensus[0..19])
            .map_err(codec_error::WriteError)?;
        fd.write_all(&self.public_key.as_bytes()[..])
            .map_err(codec_error::WriteError)?;
        write_next(fd, &self.block_header_hash_160)?;
        write_next(fd, &self.key_block_ptr)?;
        write_next(fd, &self.key_vtxindex)?;
        Ok(())
    }

    fn consensus_deserialize<R: Read>(_fd: &mut R) -> Result<UserBurnSupportOp, codec_error> {
        // Op deserialized through burchain indexer
        unimplemented!();
    }
}

impl UserBurnSupportOp {
    pub fn from_tx(
        _block_header: &BurnchainBlockHeader,
        _tx: &BurnchainTransaction,
    ) -> Result<UserBurnSupportOp, op_error> {
        Err(op_error::UserBurnSupportNotSupported)
    }

    pub fn check(&self, burnchain: &Burnchain, tx: &mut SortitionHandleTx) -> Result<(), op_error> {
        let leader_key_block_height = self.key_block_ptr as u64;

        /////////////////////////////////////////////////////////////////
        // Consensus hash must be recent and valid
        /////////////////////////////////////////////////////////////////

        // NOTE: we only care about the first 19 bytes
        let is_fresh = tx.is_fresh_consensus_hash_check_19b(
            burnchain.consensus_hash_lifetime.into(),
            &self.consensus_hash,
        )?;

        if !is_fresh {
            warn!(
                "Invalid user burn: invalid consensus hash {}",
                &self.consensus_hash
            );
            return Err(op_error::UserBurnSupportBadConsensusHash);
        }

        /////////////////////////////////////////////////////////////////////////////////////
        // There must exist a previously-accepted LeaderKeyRegisterOp that matches this
        // user support burn's VRF public key.
        /////////////////////////////////////////////////////////////////////////////////////
        if self.key_block_ptr == 0 {
            warn!("Invalid tx: key block back-pointer must be positive");
            return Err(op_error::ParseError);
        }

        if self.key_block_ptr as u64 > self.block_height {
            warn!(
                "Invalid tx: key block back-pointer {} exceeds block height {}",
                self.key_block_ptr, self.block_height
            );
            return Err(op_error::ParseError);
        }

        let chain_tip = tx.context.chain_tip.clone();
        let register_key_opt = tx.get_leader_key_at(
            leader_key_block_height,
            self.key_vtxindex.into(),
            &chain_tip,
        )?;

        if register_key_opt.is_none() {
            warn!(
                "Invalid user burn: no such leader VRF key {}",
                &self.public_key.to_hex()
            );
            return Err(op_error::UserBurnSupportNoLeaderKey);
        }

        /////////////////////////////////////////////////////////////////////////////////////
        // The block hash can't be checked here -- the corresponding LeaderBlockCommitOp may
        // not have been checked yet, so we don't know yet if it exists.  The sortition
        // algorithm will carry out this check, and only consider user burns if they match
        // a block commit and the commit's corresponding leader key.
        /////////////////////////////////////////////////////////////////////////////////////

        Ok(())
    }
}
