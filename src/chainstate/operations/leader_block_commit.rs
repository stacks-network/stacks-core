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

use burnchains::{BurnchainTransaction, BurnchainTxInput, PublicKey};
use burnchains::bitcoin::keys::BitcoinPublicKey;
use burnchains::bitcoin::BitcoinNetworkType;
use burnchains::bitcoin::address::{BitcoinAddressType, BitcoinAddress};
use burnchains::Txid;
use burnchains::Hash160;
use burnchains::Address;

use util::hash::hex_bytes;

use ed25519_dalek::PublicKey as VRFPublicKey;

use crypto::sha2::Sha256;

pub const OPCODE: u8 = '[' as u8;

#[derive(Debug, PartialEq, Clone)]
pub struct LeaderBlockCommitOp<K: PublicKey> {
    pub block_header_hash: BlockHeaderHash, // hash of block header (double-sha256)
    pub new_seed: VRFSeed,                  // new seed for this block
    pub parent_block_backptr: u32,          // back-pointer to the block that contains the parent block hash 
    pub parent_vtxindex: u16,               // offset in the parent block where the parent block hash can be found
    pub key_block_backptr: u32,             // back-pointer to the block that contains the leader key registration 
    pub key_vtxindex: u16,                  // offset in the block where the leader key can be found
    pub memo: Vec<u8>,                      // extra unused byte

    pub burn_fee: u64,                      // how many burn tokens (e.g. satoshis) were destroyed to produce this block
    pub input: BurnchainTxInput<K>,         // burn chain keys that must match the key registration

    // common to all transactions
    pub op: u8,                             // bytecode describing the operation
    pub txid: Txid,                         // transaction ID
    pub vtxindex: u32,                      // index in the block where this tx occurs
    pub block_number: u64,                  // block height at which this tx occurs
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
            Some((bytes[0] as u16) +
                ((bytes[1] as u16) << 8))
        },
        _ => None
    }
}

impl LeaderBlockCommitOp<BitcoinPublicKey> {
    fn parse_data(data: &Vec<u8>) -> Option<(BlockHeaderHash, VRFSeed, u32, u16, u32, u16, Vec<u8>)> {
        /*
            Wire format:

            0      2  3              35                 67     71     73    77   79       80
            |------|--|---------------|-----------------|------|------|-----|-----|-------|
             magic  op   block hash       new seed       parent parent key   key    memo
                                                         delta  txoff  delta txoff 

             Note that `data` is missing the first 3 bytes -- the magic and op have been stripped

             The values parent-delta, parent-txoff, key-delta, and key-txoff are in network byte order
        */
        if data.len() < 77 {
            // too short
            warn!("LEADER_BLOCK_COMMIT payload is malformed ({} bytes)", data.len());
            return None;
        }

        let block_header_hash = BlockHeaderHash::from_bytes(&data[0..32]).unwrap();
        let new_seed = VRFSeed::from_bytes(&data[32..64]).unwrap();
        let parent_block_backptr = u32_from_be(&data[64..68]).unwrap();
        let parent_vtxindex = u16_from_be(&data[68..70]).unwrap();
        let key_block_backptr = u32_from_be(&data[70..74]).unwrap();
        let key_vtxindex = u16_from_be(&data[74..76]).unwrap();
        let memo = data[76..77].to_vec();

        Some((block_header_hash, new_seed, parent_block_backptr, parent_vtxindex, key_block_backptr, key_vtxindex, memo))
    }

    pub fn from_bitcoin_tx(network_id: BitcoinNetworkType, block_height: u64, tx: &BurnchainTransaction<BitcoinAddress, BitcoinPublicKey>) -> Result<LeaderBlockCommitOp<BitcoinPublicKey>, op_error> {

        // can't be too careful...
        if tx.inputs.len() == 0 {
            test_debug!("Invalid tx: inputs: {}, outputs: {}", tx.inputs.len(), tx.outputs.len());
            return Err(op_error::InvalidInput);
        }

        if tx.outputs.len() == 0 {
            test_debug!("Invalid tx: inputs: {}, outputs: {}", tx.inputs.len(), tx.outputs.len());
            return Err(op_error::InvalidInput);
        }

        if tx.opcode != OPCODE {
            test_debug!("Invalid tx: invalid opcode {}", tx.opcode);
            return Err(op_error::InvalidInput);
        }

        // outputs[0] should be the burn output
        if tx.outputs[0].address.to_bytes() != hex_bytes("0000000000000000000000000000000000000000").unwrap() || tx.outputs[0].address.get_type() != BitcoinAddressType::PublicKeyHash {
            // wrong burn output
            test_debug!("Invalid tx: burn output missing (got {:?})", tx.outputs[0]);
            return Err(op_error::ParseError);
        }

        let burn_fee = tx.outputs[0].units;

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
            input: tx.inputs[0].clone(),

            op: OPCODE,
            txid: tx.txid.clone(),
            vtxindex: tx.vtxindex,
            block_number: block_height
        })
    }
}

impl BlockstackOperation for LeaderBlockCommitOp<BitcoinPublicKey> {
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
    use burnchains::{BurnchainTransaction, BurnchainTxInput, BurnchainTxOutput, BurnchainInputType};
    use burnchains::bitcoin::address::{BitcoinAddress, BitcoinAddressType};
    use burnchains::bitcoin::keys::BitcoinPublicKey;
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
        result: Option<LeaderBlockCommitOp<BitcoinPublicKey>>
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

        let tx_fixtures = vec![
            OpFixture {
                // valid
                txstr: "01000000011111111111111111111111111111111111111111111111111111111111111111000000006b483045022100eba8c0a57c1eb71cdfba0874de63cf37b3aace1e56dcbd61701548194a79af34022041dd191256f3f8a45562e5d60956bb871421ba69db605716250554b23b08277b012102d8015134d9db8178ac93acbc43170a2f20febba5087a5b0437058765ad5133d000000000030000000000000000536a4c5069645b222222222222222222222222222222222222222222222222222222222222222233333333333333333333333333333333333333333333333333333333333333334041424350516061626370718039300000000000001976a914000000000000000000000000000000000000000088aca05b0000000000001976a9140be3e286a15ea85882761618e366586b5574100d88ac00000000".to_string(),
                result: Some(LeaderBlockCommitOp {
                    block_header_hash: BlockHeaderHash::from_bytes(&hex_bytes("2222222222222222222222222222222222222222222222222222222222222222").unwrap()).unwrap(),
                    new_seed: VRFSeed::from_bytes(&hex_bytes("3333333333333333333333333333333333333333333333333333333333333333").unwrap()).unwrap(),
                    parent_block_backptr: 1128415552,       // 0x40414243 (network byte order)
                    parent_vtxindex: 20816,                 // 0x5051 (network byte order)
                    key_block_backptr: 1667391840,          // 0x60616263 (network byte order)
                    key_vtxindex: 29040,                    // 0x7071 (network byte order)
                    memo: vec![128],                        // 0x80

                    burn_fee: 12345,
                    input: BurnchainTxInput {
                        keys: vec![
                            BitcoinPublicKey::from_hex("02d8015134d9db8178ac93acbc43170a2f20febba5087a5b0437058765ad5133d0").unwrap(),
                        ],
                        num_required: 1, 
                        in_type: BurnchainInputType::BitcoinInput,
                    },

                    op: 91,     // '[' in ascii
                    txid: Txid::from_bytes_be(&hex_bytes("3c07a0a93360bc85047bbaadd49e30c8af770f73a37e10fec400174d2e5f27cf").unwrap()).unwrap(),
                    vtxindex: vtxindex,
                    block_number: block_height
                })
            },
            OpFixture {
                // invalid -- wrong opcode 
                txstr: "01000000011111111111111111111111111111111111111111111111111111111111111111000000006946304302207129fa2054a61cdb4b7db0b8fab6e8ff4af0edf979627aa5cf41665b7475a451021f70032b48837df091223c1d0bb57fb0298818eb11d0c966acff4b82f4b2d5c8012102d8015134d9db8178ac93acbc43170a2f20febba5087a5b0437058765ad5133d000000000030000000000000000536a4c5069645c222222222222222222222222222222222222222222222222222222222222222233333333333333333333333333333333333333333333333333333333333333334041424350516061626370718039300000000000001976a914000000000000000000000000000000000000000088aca05b0000000000001976a9140be3e286a15ea85882761618e366586b5574100d88ac00000000".to_string(),
                result: None,
            },
            OpFixture {
                // invalid -- wrong burn address
                txstr: "01000000011111111111111111111111111111111111111111111111111111111111111111000000006b483045022100e25f5f9f660339cd665caba231d5bdfc3f0885bcc0b3f85dc35564058c9089d702206aa142ea6ccd89e56fdc0743cdcf3a2744e133f335e255e9370e4f8a6d0f6ffd012102d8015134d9db8178ac93acbc43170a2f20febba5087a5b0437058765ad5133d000000000030000000000000000536a4c5069645b222222222222222222222222222222222222222222222222222222222222222233333333333333333333333333333333333333333333333333333333333333334041424350516061626370718039300000000000001976a914000000000000000000000000000000000000000188aca05b0000000000001976a9140be3e286a15ea85882761618e366586b5574100d88ac00000000".to_string(),
                result: None,
            },
            OpFixture {
                // invalid -- bad OP_RETURN (missing memo)
                txstr: "01000000011111111111111111111111111111111111111111111111111111111111111111000000006b483045022100c6c3ccc9b5a6ba5161706f3a5e4518bc3964e8de1cf31dbfa4d38082535c88e902205860de620cfe68a72d5a1fc3be1171e6fd8b2cdde0170f76724faca0db5ee0b6012102d8015134d9db8178ac93acbc43170a2f20febba5087a5b0437058765ad5133d000000000030000000000000000526a4c4f69645b2222222222222222222222222222222222222222222222222222222222222222333333333333333333333333333333333333333333333333333333333333333340414243505160616263707139300000000000001976a914000000000000000000000000000000000000000088aca05b0000000000001976a9140be3e286a15ea85882761618e366586b5574100d88ac00000000".to_string(),
                result: None,
            }
        ];

        let parser = BitcoinBlockParser::new(BitcoinNetworkType::testnet, BLOCKSTACK_MAGIC_MAINNET);

        for tx_fixture in tx_fixtures {
            let tx = make_tx(&tx_fixture.txstr).unwrap();
            let burnchain_tx = parser.parse_tx(&tx, vtxindex as usize).unwrap();
            let op = LeaderBlockCommitOp::from_bitcoin_tx(BitcoinNetworkType::testnet, block_height, &burnchain_tx);

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

