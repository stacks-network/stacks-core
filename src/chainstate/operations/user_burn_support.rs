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

use chainstate::db::burndb::BurnDB;

use burnchains::{BurnchainTransaction, PublicKey};
use burnchains::bitcoin::keys::BitcoinPublicKey;
use burnchains::bitcoin::indexer::BitcoinNetworkType;
use burnchains::bitcoin::address::{BitcoinAddressType, BitcoinAddress};
use burnchains::Txid;
use burnchains::Hash160;
use burnchains::Address;

use util::hash::hex_bytes;

use ed25519_dalek::PublicKey as VRFPublicKey;

pub const OPCODE: u8 = '_' as u8;

#[derive(Debug, PartialEq, Clone)]
pub struct UserBurnSupportOp {
    consensus_hash: ConsensusHash,
    public_key: VRFPublicKey,
    block_header_hash_160: Hash160,
    memo: Vec<u8>,

    // common to all transactions
    op: u8,                             // bytecode describing the operation
    txid: Txid,                         // transaction ID
    vtxindex: u64,                      // index in the block where this tx occurs
    block_number: u64,                  // block height at which this tx occurs
}

impl UserBurnSupportOp {
    fn parse_data(data: &Vec<u8>) -> Option<(ConsensusHash, VRFPublicKey, Hash160, Vec<u8>)> {
        /*
            Wire format:

            0      2  3              19                       51                 71       80
            |------|--|---------------|-----------------------|------------------|--------|
             magic  op consensus hash    proving public key       block hash 160    memo

            
             Note that `data` is missing the first 3 bytes -- the magic and op have been stripped
        */
        // memo can be empty, and magic + op are omitted 
        if data.len() < 72 {
            warn!("USER_BURN_SUPPORT payload is malformed");
            return None;
        }

        let consensus_hash = ConsensusHash::from_vec(&data[0..16].to_vec()).unwrap();
        let pubkey = VRFPublicKey::from_bytes(&data[16..48]).unwrap();
        let block_header_hash_160 = Hash160::from_vec(&data[48..68].to_vec()).unwrap();
        let memo = data[58..].to_vec();

        return Some((consensus_hash, pubkey, block_header_hash_160, memo));
    }

    pub fn from_bitcoin_tx(network_id: BitcoinNetworkType, block_height: u64, tx: &BurnchainTransaction<BitcoinAddress, BitcoinPublicKey>) -> Result<UserBurnSupportOp, op_error> {

        // can't be too careful...
        if tx.inputs.len() == 0 {
            test_debug!("Invalid tx: inputs: {}, outputs: {}", tx.inputs.len(), tx.outputs.len());
            return Err(op_error::ParseError);
        }

        let parse_data_opt = UserBurnSupportOp::parse_data(&tx.data);
        if parse_data_opt.is_none() {
            test_debug!("Invalid tx data");
            return Err(op_error::ParseError);
        }

        let (consensus_hash, pubkey, block_header_hash_160, memo) = parse_data_opt.unwrap();
        Ok(UserBurnSupportOp {
            consensus_hash: consensus_hash,
            public_key: pubkey,
            block_header_hash_160: block_header_hash_160,
            memo: memo,

            op: OPCODE,
            txid: tx.txid.clone(),
            vtxindex: tx.vtxindex,
            block_number: block_height
        })
    }
}

impl BlockstackOperation for UserBurnSupportOp {
    fn check(&self, db: &BurnDB, block_height: u64, checked_block_ops: &Vec<BlockstackOperationType>) -> bool {
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
    use chainstate::ConsensusHash;
    
    use util::hash::hex_bytes;
    use util::log as logger;

    struct OpFixture {
        txstr: String,
        result: Option<UserBurnSupportOp>
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
            let op = UserBurnSupportOp::from_bitcoin_tx(BitcoinNetworkType::testnet, block_height, &burnchain_tx);

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

