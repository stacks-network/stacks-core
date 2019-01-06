/*
 copyright: (c) 2013-2018 by Blockstack PBC, a public benefit corporation.

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

use chainstate::operations::{BlockstackOperation, BlockstackOperationType};
use chainstate::operations::Error as op_error;
use chainstate::{ConsensusHash, BlockHeaderHash, VRFSeed};

use chainstate::db::namedb::NameDB;

use burnchains::{BurnchainTransaction, PublicKey};
use burnchains::bitcoin::keys::BitcoinPublicKey;
use burnchains::bitcoin::indexer::BitcoinNetworkType;
use burnchains::bitcoin::address::{BitcoinAddressType, BitcoinAddress};
use burnchains::Txid;
use burnchains::Hash160;
use burnchains::Address;

use util::hash::hex_bytes;

use ed25519_dalek::PublicKey as VRFPublicKey;

use crypt::sha2::Sha256;

pub const OPCODE: u8 = '[' as u8;

#[derive(Debug, PartialEq, Copy, Clone)]
pub struct LeaderBlockCommitOp<A: Address, K: PublicKey> {
    block_header_hash: BlockHeaderHash, // hash of block header (double-sha256)
    new_seed: VRFSeed,                  // new seed for this block
    parent_block_backptr: u32,          // back-pointer to the block that contains the parent block hash 
    parent_vtxindex: u16,               // offset in the parent block where the parent block hash can be found
    key_block_backptr: u32,             // back-pointer to the block that contains the leader key registration 
    key_vtxindex: u16,                  // offset in the block where the leader key can be found
    memo: Option<u8>,                   // extra unused byte

    burn_fee: u64,                      // how many burn tokens (e.g. satoshis) were destroyed to produce this block
    input: BurnchainTxInput<A, K>,      // burn chain keys that must match the key registration

    // common to all transactions
    op: u8,                             // bytecode describing the operation
    txid: Txid,                         // transaction ID
    vtxindex: u64,                      // index in the block where this tx occurs
    block_number: u64,                  // block height at which this tx occurs
}

fn u32_from_be(bytes: &[u8]) -> Option<u32> {
    match bytes.len() {
        4 => {
            Some(((bytes[0] as u32)) +
                 ((bytes[1] as u32) << 8) +
                 ((bytes[2] as u32) << 16) +
                 ((bytes[3] as u32) << 24))
        },
        _ => None
    }
}

fn u16_from_be(bytes: &[u8]) -> Option<u16> {
    match bytes.len() {
        2 => {
            Some(((bytes[0] as u16) +
                 ((bytes[1] as u16) << 8)))
        },
        _ => None
    }
}

impl LeaderBlockCommitOp {
    fn parse_data(data: &Vec<u8>) -> Option<(BlockHeaderHash, VRFSeed, u32, u16, u32, u16, Option<u8>> {
        /*
            Wire format:

            0      2  3              35                 67     71     73    77   79       80
            |------|--|---------------|-----------------|------|------|-----|-----|-------|
             magic  op   block hash       new seed       parent parent key   key    memo
                                                         delta  txoff  delta txoff 

             Note that `data` is missing the first 3 bytes -- the magic and op have been stripped

             The values parent-delta, parent-txoff, key-delta, and key-txoff are in network byte order
        */
        if data.len() < 76 {
            // too short
            warn!("LEADER_BLOCK_COMMIT payload is malformed");
            return None;
        }

        let block_header_hash = BlockHeaderHash::from_bytes(&data[0..32]).unwrap();
        let new_seed = VRFSeed::from_bytes(&data[32..64]).unwrap();
        let parent_block_backptr = u32_from_be(&data[64..68]).unwrap();
        let parent_vtxindex = u16_from_be(&data[68..70]).unwrap();
        let key_block_backptr = u32_from_be(&data[70..74]).unwrap();
        let key_vtxindex = u16_from_be(&data[74..76]).unwrap();
        let memo = 
            if data.len() == 77 {
                Some(data[77])
            }
            else {
                None
            };

        Some(block_header_hash, new_seed, parent_block_backptr, parent_vtxindex, key_block_backptr, key_vtxindex, memo)
    }

    pub fn from_bitcoin_tx(network_id: BitcoinNetworkType, block_height: u64, tx: &BurnchainTransaction<BitcoinAddress, BitcoinPublicKey>) -> Result<LeaderBlockCommitOp<BitcoinAddress, BitcoinPublicKey>, op_error> {

        // can't be too careful...
        if tx.inputs.len() == 0 {
            test_debug!("Invalid tx: inputs: {}, outputs: {}", tx.inputs.len(), tx.outputs.len());
            return Err(op_error::ParseError);
        }

        if tx.outputs.len() == 0 {
            test_debug!("Invalid tx: inputs: {}, outputs: {}", tx.inputs.len(), tx.outputs.len());
            return Err(op_error::ParseError);
        }

        // outputs[1] should be the burn output
        if tx.outputs[1].address.to_bytes() != hex_bytes("0000000000000000000000000000000000000000").unwrap() || tx.outputs[1].address.get_type() != BitcoinAddressType::PublicKeyHash {
            // wrong burn output
            test_debug!("Invalid tx: burn output missing");
            return Err(op_error::ParseError);
        }

        let burn_fee = tx.outputs[1].units;

        let parse_data_opt = LeaderBlockCommitOp::parse_data(&tx.data);
        if parse_data_opt.is_none() {
            test_debug!("Invalid tx data");
            return Err(op_error::ParseError);
        }

        let (block_header_hash, new_seed, parent_block_backptr, parent_vtxindex, key_block_backptr, key_vtxindex, memo) = parse_data_opt.unwrap();

        Ok(LeaderBlockCommitOp {
            block_header_hash: block_header_hash,
            new_seed: new_seed,
            parent_block_backptr: parent_block_backptr,
            parent_vtxindex: parent_vtxindex,
            key_block_backptr: key_block_backptr,
            key_vtxindex: key_vtxindex,
            memo: memo,

            burn_fee: burn_fee,
            input: tx.inputs[0],

            op: OPCODE,
            txid: tx.txid.clone(),
            vtxindex: tx.vtxindex,
            block_number: block_height
        })
    }
}

impl BlockstackOperation for LeaderBlockCommitOp {
    fn check(&self, db: &NameDB, block_height: u64, checked_block_ops: &Vec<BlockstackOperationType>) -> bool {
        return false;
    }

    fn consensus_serialize(&self) -> Vec<u8> {
        return self.txid.as_bytes().to_vec();
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use burnchains::{BurnchainTransaction, BurnchainTxInput, BurnchainTxOutput};
    use burnchains::bitcoin::address::{BitcoinAddress, BitcoinAddressType};
    use burnchains::bitcoin::keys::BitcoinPublicKey;
    use burnchains::bitcoin::indexer::{BitcoinNetworkType};
    use burnchains::bitcoin::blocks::BitcoinBlockParser;
    use burnchains::{Txid, Hash160};
    use burnchains::BLOCKSTACK_MAGIC_MAINNET;

    use bitcoin::network::serialize::deserialize;
    use bitcoin::network::encodable::VarInt;
    use bitcoin::blockdata::transaction::Transaction;
    use bitcoin::blockdata::block::{Block, LoneBlockHeader};

    use chainstate::operations::Error as op_error;
    use chainstate::{ConsensusHash, BlockHeaderHash, VRFSeed};

    use util::hash::hex_bytes;
    use util::log as logger;

    struct OpFixture {
        txstr: String,
        result: Option<LeaderBlockCommitOp>
    }

    fn make_tx(hex_str: &str) -> Result<Transaction, &'static str> {
        let tx_bin = hex_bytes(hex_str)?;
        let tx = deserialize(&tx_bin.to_vec())
            .map_err(|_e| "failed to deserialize")?;
        Ok(tx)
    }

    #[test]
    fn test_parse() {
        logger::init();

        let vtxindex = 1;
        let block_height = 694;

        let tx_fixtures: Vec<OpFixture> = vec![];

        let parser = BitcoinBlockParser::new(BitcoinNetworkType::testnet, BLOCKSTACK_MAGIC_MAINNET);

        for tx_fixture in tx_fixtures {
            let tx = make_tx(&tx_fixture.txstr).unwrap();
            let burnchain_tx = parser.parse_tx(&tx, vtxindex as usize).unwrap();
            let op = LeaderBlockCommitOp::from_tx(BitcoinNetworkType::testnet, block_height, &burnchain_tx);

            match (op, tx_fixture.result) {
                (Ok(parsed_tx), Some(result)) => {
                    assert_eq!(parsed_tx, result);
                },
                (Err(_e), None) => {},
                (Ok(parsed_tx), None) => {
                    test_debug!("Parsed a tx when we should not have");
                    assert!(false);
                },
                (Err(_e), Some(result)) => {
                    test_debug!("Did not parse a tx when we should have");
                    assert!(false);
                }
            };
        }
    }
}

