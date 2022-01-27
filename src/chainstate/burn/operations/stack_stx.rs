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
use crate::types::proof::TrieHash;
use address::AddressHashMode;
use burnchains::Address;
use burnchains::Burnchain;
use burnchains::BurnchainBlockHeader;
use burnchains::Txid;
use burnchains::{BurnchainRecipient, BurnchainSigner};
use burnchains::{BurnchainTransaction, PublicKey};
use chainstate::burn::db::sortdb::{SortitionDB, SortitionHandleTx};
use chainstate::burn::operations::Error as op_error;
use chainstate::burn::operations::{
    parse_u128_from_be, BlockstackOperationType, PreStxOp, StackStxOp,
};
use chainstate::burn::ConsensusHash;
use chainstate::burn::Opcodes;
use chainstate::stacks::index::storage::TrieFileStorage;
use chainstate::stacks::{StacksPrivateKey, StacksPublicKey};
use core::POX_MAX_NUM_CYCLES;
use net::Error as net_error;
use util::hash::to_hex;
use util::log;
use util::vrf::{VRFPrivateKey, VRFPublicKey, VRF};

use crate::types::chainstate::VRFSeed;
use crate::types::chainstate::{BlockHeaderHash, BurnchainHeaderHash, StacksAddress};

// return type from parse_data below
struct ParsedData {
    stacked_ustx: u128,
    num_cycles: u8,
}

pub static OUTPUTS_PER_COMMIT: usize = 2;

impl PreStxOp {
    pub fn from_tx(
        block_header: &BurnchainBlockHeader,
        tx: &BurnchainTransaction,
        pox_sunset_ht: u64,
    ) -> Result<PreStxOp, op_error> {
        PreStxOp::parse_from_tx(
            block_header.block_height,
            &block_header.block_hash,
            tx,
            pox_sunset_ht,
        )
    }

    /// parse a PreStxOp
    /// `pox_sunset_ht` is the height at which PoX *disables*
    pub fn parse_from_tx(
        block_height: u64,
        block_hash: &BurnchainHeaderHash,
        tx: &BurnchainTransaction,
        pox_sunset_ht: u64,
    ) -> Result<PreStxOp, op_error> {
        // can't be too careful...
        let inputs = tx.get_signers();
        let outputs = tx.get_recipients();

        if inputs.len() == 0 {
            warn!(
                "Invalid tx: inputs: {}, outputs: {}",
                inputs.len(),
                outputs.len()
            );
            return Err(op_error::InvalidInput);
        }

        if outputs.len() == 0 {
            warn!(
                "Invalid tx: inputs: {}, outputs: {}",
                inputs.len(),
                outputs.len()
            );
            return Err(op_error::InvalidInput);
        }

        if tx.opcode() != Opcodes::PreStx as u8 {
            warn!("Invalid tx: invalid opcode {}", tx.opcode());
            return Err(op_error::InvalidInput);
        };

        // check if we've reached PoX disable
        if block_height >= pox_sunset_ht {
            debug!(
                "PreStxOp broadcasted after sunset. Ignoring. txid={}",
                tx.txid()
            );
            return Err(op_error::InvalidInput);
        }

        Ok(PreStxOp {
            output: outputs[0].address,
            txid: tx.txid(),
            vtxindex: tx.vtxindex(),
            block_height,
            burn_header_hash: block_hash.clone(),
        })
    }
}

impl StackStxOp {
    fn parse_data(data: &Vec<u8>) -> Option<ParsedData> {
        /*
            Wire format:
            0      2  3                             19        20
            |------|--|-----------------------------|---------|
             magic  op         uSTX to lock (u128)     cycles (u8)

             Note that `data` is missing the first 3 bytes -- the magic and op have been stripped

             The values ustx to lock and cycles are in big-endian order.

             parent-delta and parent-txoff will both be 0 if this block builds off of the genesis block.
        */

        if data.len() < 17 {
            // too short
            warn!(
                "StacksStxOp payload is malformed ({} bytes, expected {})",
                data.len(),
                17
            );
            return None;
        }

        let stacked_ustx = parse_u128_from_be(&data[0..16]).unwrap();
        let num_cycles = data[16];

        Some(ParsedData {
            stacked_ustx,
            num_cycles,
        })
    }

    pub fn get_sender_txid(tx: &BurnchainTransaction) -> Result<&Txid, op_error> {
        match tx.get_input_tx_ref(0) {
            Some((ref txid, vout)) => {
                if *vout != 1 {
                    warn!("Invalid tx: StackStxOp must spend the second output of the PreStxOp");
                    Err(op_error::InvalidInput)
                } else {
                    Ok(txid)
                }
            }
            None => {
                warn!("Invalid tx: StackStxOp must have at least one input");
                Err(op_error::InvalidInput)
            }
        }
    }

    pub fn from_tx(
        block_header: &BurnchainBlockHeader,
        tx: &BurnchainTransaction,
        sender: &StacksAddress,
        pox_sunset_ht: u64,
    ) -> Result<StackStxOp, op_error> {
        StackStxOp::parse_from_tx(
            block_header.block_height,
            &block_header.block_hash,
            tx,
            sender,
            pox_sunset_ht,
        )
    }

    /// parse a StackStxOp
    /// `pox_sunset_ht` is the height at which PoX *disables*
    pub fn parse_from_tx(
        block_height: u64,
        block_hash: &BurnchainHeaderHash,
        tx: &BurnchainTransaction,
        sender: &StacksAddress,
        pox_sunset_ht: u64,
    ) -> Result<StackStxOp, op_error> {
        // can't be too careful...
        let outputs = tx.get_recipients();

        if tx.num_signers() == 0 {
            warn!(
                "Invalid tx: inputs: {}, outputs: {}",
                tx.num_signers(),
                outputs.len()
            );
            return Err(op_error::InvalidInput);
        }

        if outputs.len() == 0 {
            warn!(
                "Invalid tx: inputs: {}, outputs: {}",
                tx.num_signers(),
                outputs.len()
            );
            return Err(op_error::InvalidInput);
        }

        if tx.opcode() != Opcodes::StackStx as u8 {
            warn!("Invalid tx: invalid opcode {}", tx.opcode());
            return Err(op_error::InvalidInput);
        };

        let data = StackStxOp::parse_data(&tx.data()).ok_or_else(|| {
            warn!("Invalid tx data");
            op_error::ParseError
        })?;

        // check if we've reached PoX disable
        if block_height >= pox_sunset_ht {
            debug!(
                "StackStxOp broadcasted after sunset. Ignoring. txid={}",
                tx.txid()
            );
            return Err(op_error::InvalidInput);
        }

        Ok(StackStxOp {
            sender: sender.clone(),
            reward_addr: outputs[0].address,
            stacked_ustx: data.stacked_ustx,
            num_cycles: data.num_cycles,
            txid: tx.txid(),
            vtxindex: tx.vtxindex(),
            block_height,
            burn_header_hash: block_hash.clone(),
        })
    }
}

impl StacksMessageCodec for StackStxOp {
    /*
            Wire format:
            0      2  3                             19        20
            |------|--|-----------------------------|---------|
             magic  op         uSTX to lock (u128)     cycles (u8)
    */
    fn consensus_serialize<W: Write>(&self, fd: &mut W) -> Result<(), codec_error> {
        write_next(fd, &(Opcodes::StackStx as u8))?;
        fd.write_all(&self.stacked_ustx.to_be_bytes())
            .map_err(|e| codec_error::WriteError(e))?;
        write_next(fd, &self.num_cycles)?;
        Ok(())
    }

    fn consensus_deserialize<R: Read>(_fd: &mut R) -> Result<StackStxOp, codec_error> {
        // Op deserialized through burchain indexer
        unimplemented!();
    }
}

impl StackStxOp {
    pub fn check(&self) -> Result<(), op_error> {
        if self.stacked_ustx == 0 {
            warn!("Invalid StackStxOp, must have positive ustx");
            return Err(op_error::StackStxMustBePositive);
        }

        if self.num_cycles == 0 || self.num_cycles > POX_MAX_NUM_CYCLES {
            warn!(
                "Invalid StackStxOp, num_cycles = {}, but must be in (0, {}]",
                self.num_cycles, POX_MAX_NUM_CYCLES
            );
        }
        Ok(())
    }
}
