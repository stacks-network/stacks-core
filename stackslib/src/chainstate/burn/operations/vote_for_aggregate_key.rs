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

use stacks_common::codec::{write_next, Error as codec_error, StacksMessageCodec};
use stacks_common::types::chainstate::{BurnchainHeaderHash, StacksAddress};
use stacks_common::types::StacksPublicKeyBuffer;
use stacks_common::util::secp256k1::Secp256k1PublicKey;

use crate::burnchains::bitcoin::BitcoinTxInput;
use crate::burnchains::{BurnchainBlockHeader, BurnchainTransaction, Txid};
use crate::chainstate::burn::operations::{
    parse_u128_from_be, parse_u16_from_be, parse_u32_from_be, parse_u64_from_be,
    BlockstackOperationType, Error as op_error, PreStxOp, VoteForAggregateKeyOp,
};
use crate::chainstate::burn::Opcodes;
use crate::chainstate::stacks::address::PoxAddress;

struct ParsedData {
    signer_index: u16,
    aggregate_key: StacksPublicKeyBuffer,
    round: u32,
    reward_cycle: u64,
}

impl VoteForAggregateKeyOp {
    pub fn from_tx(
        block_header: &BurnchainBlockHeader,
        tx: &BurnchainTransaction,
        sender: &StacksAddress,
    ) -> Result<VoteForAggregateKeyOp, op_error> {
        VoteForAggregateKeyOp::parse_from_tx(
            block_header.block_height,
            &block_header.block_hash,
            tx,
            sender,
        )
    }

    fn parse_data(data: &Vec<u8>) -> Option<ParsedData> {
        /*
           Wire format:

           0     2    3           5              38     42           50
           |-----|----|-----------|--------------|------|------------|
           magic  op  signer_index aggregate_key  round  reward_cycle

           Note that `data` is missing the first 3 bytes -- the magic and op have been stripped
        */

        if data.len() != 47 {
            warn!(
                "Vote for aggregate key operation data has an invalid length ({} bytes)",
                data.len()
            );
            return None;
        }

        let signer_index = parse_u16_from_be(&data[0..2]).unwrap();
        let aggregate_key = StacksPublicKeyBuffer::from(&data[2..35]);

        let round = parse_u32_from_be(&data[35..39]).unwrap();
        let reward_cycle = parse_u64_from_be(&data[39..47]).unwrap();

        Some(ParsedData {
            signer_index,
            aggregate_key,
            round,
            reward_cycle,
        })
    }

    pub fn get_sender_txid(tx: &BurnchainTransaction) -> Result<&Txid, op_error> {
        match tx.get_input_tx_ref(0) {
            Some((ref txid, vout)) => {
                if *vout != 1 {
                    warn!("Invalid tx: DelegateStxOp must spend the second output of the PreStxOp");
                    Err(op_error::InvalidInput)
                } else {
                    Ok(txid)
                }
            }
            None => {
                warn!("Invalid tx: DelegateStxOp must have at least one input");
                Err(op_error::InvalidInput)
            }
        }
    }

    pub fn get_sender_pubkey(tx: &BurnchainTransaction) -> Result<&Secp256k1PublicKey, op_error> {
        match tx {
            BurnchainTransaction::Bitcoin(ref btc) => match btc.inputs.get(0) {
                Some(BitcoinTxInput::Raw(_)) => Err(op_error::InvalidInput),
                Some(BitcoinTxInput::Structured(input)) => {
                    input.keys.get(0).ok_or(op_error::InvalidInput)
                }
                _ => Err(op_error::InvalidInput),
            },
        }
    }

    pub fn parse_from_tx(
        block_height: u64,
        block_hash: &BurnchainHeaderHash,
        tx: &BurnchainTransaction,
        sender: &StacksAddress,
    ) -> Result<VoteForAggregateKeyOp, op_error> {
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

        if tx.opcode() != Opcodes::VoteForAggregateKey as u8 {
            warn!("Invalid tx: invalid opcode {}", tx.opcode());
            return Err(op_error::InvalidInput);
        };

        let data = VoteForAggregateKeyOp::parse_data(&tx.data()).ok_or_else(|| {
            warn!("Invalid tx data");
            op_error::ParseError
        })?;

        let signer_key = VoteForAggregateKeyOp::get_sender_pubkey(tx)?;

        Ok(VoteForAggregateKeyOp {
            sender: sender.clone(),
            signer_index: data.signer_index,
            aggregate_key: data.aggregate_key,
            round: data.round,
            reward_cycle: data.reward_cycle,
            signer_key: signer_key.to_bytes_compressed().as_slice().into(),
            txid: tx.txid(),
            vtxindex: tx.vtxindex(),
            block_height,
            burn_header_hash: block_hash.clone(),
        })
    }

    pub fn check(&self) -> Result<(), op_error> {
        // TODO

        Ok(())
    }
}
