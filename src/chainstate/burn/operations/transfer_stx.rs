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
use chainstate::burn::operations::{parse_u128_from_be, BlockstackOperationType, TransferStxOp};
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
    transfered_ustx: u128,
    memo: Vec<u8>,
}

impl TransferStxOp {
    fn parse_data(data: &Vec<u8>) -> Option<ParsedData> {
        /*
            Wire format:
            0      2  3                             19        80
            |------|--|-----------------------------|---------|
             magic  op     uSTX to transfer (u128)     memo (up to 61 bytes)

             Note that `data` is missing the first 3 bytes -- the magic and op have been stripped

             The values ustx to transfer are in big-endian order.
        */

        if data.len() < 16 {
            // too short
            warn!(
                "TransferStxOp payload is malformed ({} bytes, expected >= {})",
                data.len(),
                16
            );
            return None;
        }

        if data.len() > (61 + 16) {
            // too long
            warn!(
                "TransferStxOp payload is malformed ({} bytes, expected <= {})",
                data.len(),
                16 + 61
            );
            return None;
        }

        let transfered_ustx = parse_u128_from_be(&data[0..16]).unwrap();
        let memo = Vec::from(&data[16..]);

        Some(ParsedData {
            transfered_ustx,
            memo,
        })
    }

    pub fn get_sender_txid(tx: &BurnchainTransaction) -> Result<&Txid, op_error> {
        match tx.get_input_tx_ref(0) {
            Some((ref txid, vout)) => {
                if *vout != 1 {
                    warn!(
                        "Invalid tx: TransferStxOp must spend the second output of the PreStacksOp"
                    );
                    Err(op_error::InvalidInput)
                } else {
                    Ok(txid)
                }
            }
            None => {
                warn!("Invalid tx: TransferStxOp must have at least one input");
                Err(op_error::InvalidInput)
            }
        }
    }

    pub fn from_tx(
        block_header: &BurnchainBlockHeader,
        tx: &BurnchainTransaction,
        sender: &StacksAddress,
    ) -> Result<TransferStxOp, op_error> {
        TransferStxOp::parse_from_tx(
            block_header.block_height,
            &block_header.block_hash,
            tx,
            sender,
        )
    }

    /// parse a StackStxOp
    pub fn parse_from_tx(
        block_height: u64,
        block_hash: &BurnchainHeaderHash,
        tx: &BurnchainTransaction,
        sender: &StacksAddress,
    ) -> Result<TransferStxOp, op_error> {
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

        if tx.opcode() != Opcodes::TransferStx as u8 {
            warn!("Invalid tx: invalid opcode {}", tx.opcode());
            return Err(op_error::InvalidInput);
        };

        let data = TransferStxOp::parse_data(&tx.data()).ok_or_else(|| {
            warn!("Invalid tx data");
            op_error::ParseError
        })?;

        Ok(TransferStxOp {
            sender: sender.clone(),
            recipient: outputs[0].address,
            transfered_ustx: data.transfered_ustx,
            memo: data.memo,
            txid: tx.txid(),
            vtxindex: tx.vtxindex(),
            block_height,
            burn_header_hash: block_hash.clone(),
        })
    }
}

impl StacksMessageCodec for TransferStxOp {
    fn consensus_serialize<W: Write>(&self, fd: &mut W) -> Result<(), codec_error> {
        write_next(fd, &(Opcodes::TransferStx as u8))?;
        fd.write_all(&self.transfered_ustx.to_be_bytes())
            .map_err(|e| codec_error::WriteError(e))?;
        if self.memo.len() > 61 {
            return Err(codec_error::ArrayTooLong);
        }
        write_next(fd, &self.memo)?;
        Ok(())
    }

    fn consensus_deserialize<R: Read>(_fd: &mut R) -> Result<TransferStxOp, codec_error> {
        // Op deserialized through burchain indexer
        unimplemented!();
    }
}

impl TransferStxOp {
    pub fn check(&self) -> Result<(), op_error> {
        if self.transfered_ustx == 0 {
            warn!("Invalid TransferStxOp, must have positive ustx");
            return Err(op_error::TransferStxMustBePositive);
        }
        if self.sender == self.recipient {
            warn!("Invalid TransferStxOp, sender is recipient");
            return Err(op_error::TransferStxSelfSend);
        }
        Ok(())
    }
}
