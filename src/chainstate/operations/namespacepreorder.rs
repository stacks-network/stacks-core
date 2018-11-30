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

use chainstate::db::namedb::NameDB;

use burnchains::{BurnchainTransaction, PublicKey};
use burnchains::bitcoin::keys::BitcoinPublicKey;
use burnchains::bitcoin::indexer::BitcoinNetworkType;
use burnchains::bitcoin::address::{BitcoinAddressType, BitcoinAddress};
use burnchains::ConsensusHash;
use burnchains::Txid;
use burnchains::Hash160;
use burnchains::Address;

use util::hash::hex_bytes;

/*
# consensus hash fields (ORDER MATTERS!) 
FIELDS = [
    'preorder_hash',        # hash(namespace_id,sender,reveal_addr)
    'consensus_hash',       # consensus hash at the time issued
    'op',                   # bytecode describing the operation (not necessarily 1 byte)
    'op_fee',               # fee paid for the namespace to the burn address
    'txid',                 # transaction ID
    'vtxindex',             # the index in the block where the tx occurs
    'block_number',         # block number at which this transaction occurred
    'sender',               # scriptPubKey hex from the principal that issued this preorder (identifies the preorderer)
    'sender_pubkey',        # if sender is a p2pkh script, this is the public key
    'address'               # address from the scriptPubKey
]

# save everything
MUTATE_FIELDS = FIELDS[:] + [
    'token_fee'
]

@state_preorder("check_preorder_collision")
def check( state_engine, nameop, block_id, checked_ops ):
*/

#[derive(Debug, PartialEq)]
pub struct NamespacePreorderOp {
    preorder_hash: Hash160,             // hash(namesapce_id, sender, reveal_addr)
    consensus_hash: ConsensusHash,      // consensus hash at time of issuance
    op: u8,                             // bytecode describing the operation
    op_fee: u64,                        // satoshi fee paid for the namespace to the burn address
    txid: Txid,                         // transaction ID
    vtxindex: u64,                      // index in the block where this tx occurs
    block_number: u64,                  // block height at which this tx occurs
    sender: Vec<u8>,                    // hex string of the scriptpubkey of the principal that sent this transaction 
    sender_pubkey: Option<Vec<u8>>,     // if the sender is a p2pkh script, this is the public key as a hex string
    address: BitcoinAddress,            // serialized address derived from the scriptsig (i.e. the address from sender_pubkey)
    token_fee: Option<u64>              // microstacks paid for this namespace, if any
}

impl NamespacePreorderOp {
    fn parse_data(data: &Vec<u8>) -> Option<(Hash160, ConsensusHash, Option<u64>)> {
        /*
            wire format (Pre-STACKs Phase 1)

            0     2   3                                      23               39
            |-----|---|--------------------------------------|----------------|
            magic op  hash(ns_id,script_pubkey,reveal_addr)   consensus hash

            wire format (Post-STACKs phase 1)

            0     2   3                                      23               39                         47
            |-----|---|--------------------------------------|----------------|--------------------------|
            magic op  hash(ns_id,script_pubkey,reveal_addr)   consensus hash    token fee (little-endian)

            Note that `data` is missing the first 3 bytes -- the magic and op have been stripped
        */
        if data.len() != 36 && data.len() != 44 {
            // can't be either format
            warn!("NAMESPACE_PREORDER payload is malformed");
            return None;
        }

        let preorder_hash = Hash160::from_vec(&data[0..20].to_vec()).unwrap();
        let consensus_hash = ConsensusHash::from_vec(&data[20..36].to_vec()).unwrap();
        let token_fee_opt = 
            if data.len() == 44 {
                // have token free as well
                let token_fee_bytes = &data[36..44];
                Some(((token_fee_bytes[0] as u64) << (7 * 8)) +
                     ((token_fee_bytes[1] as u64) << (6 * 8)) +
                     ((token_fee_bytes[2] as u64) << (5 * 8)) +
                     ((token_fee_bytes[3] as u64) << (4 * 8)) + 
                     ((token_fee_bytes[4] as u64) << (3 * 8)) +
                     ((token_fee_bytes[5] as u64) << (2 * 8)) +
                     ((token_fee_bytes[6] as u64) << (1 * 8)) +
                       token_fee_bytes[7] as u64)
            }
            else {
                None
            };

        return Some((preorder_hash, consensus_hash, token_fee_opt));
    }

    pub fn from_tx(network_id: BitcoinNetworkType, block_height: u64, tx: &BurnchainTransaction<BitcoinAddress, BitcoinPublicKey>) -> Result<NamespacePreorderOp, op_error> {
        // can't be too careful...
        if tx.inputs.len() == 0 || tx.outputs.len() != 2 {
            test_debug!("Invalid tx: inputs: {}, outputs: {}", tx.inputs.len(), tx.outputs.len());
            return Err(op_error::ParseError);
        }

        let parse_data_opt = NamespacePreorderOp::parse_data(&tx.data);
        if parse_data_opt.is_none() {
            test_debug!("Invalid tx data");
            return Err(op_error::ParseError);
        }

        let (preorder_hash, consensus_hash, token_fee_opt) = parse_data_opt.unwrap();
        let sender_address_opt = tx.inputs[0].address(network_id);
        if sender_address_opt.is_none() {
            test_debug!("Invalid tx: could not calculate sender address");
            return Err(op_error::ParseError);
        }

        let sender_address = sender_address_opt.unwrap();

        // outputs[1] should be the burn output
        if tx.outputs[1].address.to_bytes() != hex_bytes("0000000000000000000000000000000000000000").unwrap() || tx.outputs[1].address.get_type() != BitcoinAddressType::PublicKeyHash {
            // wrong burn output
            test_debug!("Invalid tx: burn output missing");
            return Err(op_error::ParseError);
        }

        let op_fee = tx.outputs[1].units;

        return Ok(NamespacePreorderOp {
            preorder_hash: preorder_hash,
            consensus_hash: consensus_hash,
            op: '*' as u8,
            op_fee: op_fee,
            txid: tx.txid.clone(),
            vtxindex: tx.vtxindex,
            block_number: block_height,
            sender: tx.inputs[0].sender_scriptpubkey.clone(),
            sender_pubkey: 
                if tx.inputs[0].sender_pubkey.is_some() {
                    Some(tx.inputs[0].sender_pubkey.unwrap().to_bytes())
                }
                else {
                    None
                },
            address: sender_address,
            token_fee: token_fee_opt
        });
    }
}

impl BlockstackOperation for NamespacePreorderOp {
    fn check(&self, db: &NameDB, block_height: u64, checked_block_ops: &Vec<BlockstackOperationType>) -> bool {
        return false;
    }

    fn consensus_serialize(&self) -> Vec<u8> {
        return String::from("").into_bytes();
    }
}

#[cfg(test)]
mod tests {
    use super::NamespacePreorderOp;
    use burnchains::{BurnchainTransaction, BurnchainTxInput, BurnchainTxOutput};
    use burnchains::bitcoin::address::{BitcoinAddress, BitcoinAddressType};
    use burnchains::bitcoin::keys::BitcoinPublicKey;
    use burnchains::bitcoin::indexer::{BitcoinNetworkType};
    use burnchains::bitcoin::blocks::BitcoinBlockParser;
    use burnchains::{Txid, ConsensusHash, Hash160};
    use burnchains::BLOCKSTACK_MAGIC_MAINNET;

    use bitcoin::network::serialize::deserialize;
    use bitcoin::network::encodable::VarInt;
    use bitcoin::blockdata::transaction::Transaction;
    use bitcoin::blockdata::block::{Block, LoneBlockHeader};

    use chainstate::operations::Error as op_error;
    
    use util::hash::hex_bytes;
    use util::log as logger;

    struct OpFixture {
        txstr: String,
        result: Option<NamespacePreorderOp>
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
                // NAMESPACE_PREORDER transaction from a p2pkh output and token fee
                txstr: "010000000155916dbf7db76869241da77ce07c8728e12ed373860bb4aa7dc6804cd04927a9010000006b483045022100c668a7eee5856141e0f78c8be0ef2e2632644b22266df88eb8674af15795658f02200dab1cb00016d2567244aafaef2d416a93dfd916a0d285a0dede07de527ea11d012103d6fd1ba0effaf1e8d94ea7b7a3d0ef26fea00a14ce5ffcc1495fe588a2c6d0f3ffffffff030000000000000000316a2f69642adb67800bdfa5da781e177cc268f7cf030952629a2a9148d8b13939723d2aca16c75c6d68000000017d7840002487012a010000001976a91474178497e927ff3ff1428a241be454d393c3c91c88ac7c150000000000001976a914000000000000000000000000000000000000000088ac00000000".to_owned(),
                result: Some(NamespacePreorderOp {
                    preorder_hash: Hash160::from_hex("db67800bdfa5da781e177cc268f7cf030952629a").unwrap(),
                    consensus_hash: ConsensusHash::from_hex("2a9148d8b13939723d2aca16c75c6d68").unwrap(),
                    op: '*' as u8,
                    op_fee: 5500,
                    txid: Txid::from_hex("5bd20de53d184fa2aa5fca730dab15102a250310805eda3026592c1eb4a698a1").unwrap(),
                    vtxindex: vtxindex,
                    block_number: block_height,
                    sender: hex_bytes("76a91474178497e927ff3ff1428a241be454d393c3c91c88ac").unwrap(),
                    sender_pubkey: Some(hex_bytes("03d6fd1ba0effaf1e8d94ea7b7a3d0ef26fea00a14ce5ffcc1495fe588a2c6d0f3").unwrap()),
                    address: BitcoinAddress::from_b58("mr6nrMvvh44sR5MiX929mMXP5hqgaTr6fx").unwrap(),
                    token_fee: Some(6400000000)
                })
            },
            OpFixture {
                // NAMESPACE_PREORDER transaction from a p2pkh output and no token fee 
                txstr: "0100000001ab36b4088304b7647cf2034bde27f1f3efe17820d9de2c59113d54d97c1e138f000000006a47304402203029c3c0e53f16464a8d5720f332bb5cc1e818884e4f92bebbfa8b1b224d8d2102203ea168979a00f679edecdbe1bd1f683327fc81e7ce395be49d0f409de29ccc96012103d6fd1ba0effaf1e8d94ea7b7a3d0ef26fea00a14ce5ffcc1495fe588a2c6d0f3ffffffff030000000000000000296a2769642adb67800bdfa5da781e177cc268f7cf030952629a2a9148d8b13939723d2aca16c75c6d68e0372a12010000001976a91474178497e927ff3ff1428a241be454d393c3c91c88ac0084d717000000001976a914000000000000000000000000000000000000000088ac00000000".to_owned(),
                result: Some(NamespacePreorderOp {
                    preorder_hash: Hash160::from_hex("db67800bdfa5da781e177cc268f7cf030952629a").unwrap(),
                    consensus_hash: ConsensusHash::from_hex("2a9148d8b13939723d2aca16c75c6d68").unwrap(),
                    op: '*' as u8,
                    op_fee: 400000000,
                    txid: Txid::from_hex("3564976059b4cbc33e8c8f2b06f2c0a9483eabfe95ee557dd1a646ec20c9c74a").unwrap(),
                    vtxindex: vtxindex,
                    block_number: block_height,
                    sender: hex_bytes("76a91474178497e927ff3ff1428a241be454d393c3c91c88ac").unwrap(),
                    sender_pubkey: Some(hex_bytes("03d6fd1ba0effaf1e8d94ea7b7a3d0ef26fea00a14ce5ffcc1495fe588a2c6d0f3").unwrap()),
                    address: BitcoinAddress::from_b58("mr6nrMvvh44sR5MiX929mMXP5hqgaTr6fx").unwrap(),
                    token_fee: None
                })
            },
            OpFixture {
                // NAMESPACE_PREORDER transaction from a p2sh output and no token fee
                txstr: "01000000019e1421deea5198ab7f52bb739dbe449e4422e9d3ccf3038ae0868dd7a510808a01000000fdfd000047304402205e117b0af3b13ff6c7afdbf7c7e9bcc4f4631459d79124f2205d70b0a35bc96202202054c52116dc7336c055e50ae2d89d3be1aee4f9da0ffe3f69b390333079a96c01483045022100a9cf7090edbcc89898048186d7dfdd92f92eac67d3ac9f296e160e831fffacbc02202306e7c50be0032df825bb1f4124f7ada191f7fbe9f953c634aa0815cfe90e87014c69522102d341f728783eb93e6fb5921a1ebe9d149e941de31e403cd69afa2f0f1e698e812102f21b29694df4c2188bee97103d10d017d1865fb40528f25589af9db6e0786b6521028791dc45c049107fb99e673265a38a096536aacdf78aa90710a32fff7750f9f953aeffffffff030000000000000000296a2769642afd357ee00b6c0365fb61184555ccfa35494a3fe02a9148d8b13939723d2aca16c75c6d68b0699f270100000017a914d1558340e7651a8a1d5801a8335eae5ca2e87ba187005a6202000000001976a914000000000000000000000000000000000000000088ac00000000".to_owned(),
                result: Some(NamespacePreorderOp {
                    preorder_hash: Hash160::from_hex("fd357ee00b6c0365fb61184555ccfa35494a3fe0").unwrap(),
                    consensus_hash: ConsensusHash::from_hex("2a9148d8b13939723d2aca16c75c6d68").unwrap(),
                    op: '*' as u8,
                    op_fee: 40000000,
                    txid: Txid::from_hex("e0f0956886a5d8f00c9342e2e5086943c6e50cb593f7ea52780ba0008701d766").unwrap(),
                    vtxindex: vtxindex,
                    block_number: block_height,
                    sender: hex_bytes("a914d1558340e7651a8a1d5801a8335eae5ca2e87ba187").unwrap(),
                    sender_pubkey: None,
                    address: BitcoinAddress::from_b58("2NCL5euNJV9wNcKWQkTtEv7BxUdSTbaf7W1").unwrap(),
                    token_fee: None
                })
            },
            OpFixture {
                // NAMESPACE_PREORDER transaction from a p2sh output and a token fee
                txstr: "01000000017f85a11a0eb7765e87531b53b4dc2d39ec69a16c8fd0a867f733b7eeab41ed7a00000000fdfe00004830450221009507318060bca113ab8a4dddcd626e97c050c0e336a9242aeaafc07d1109ca3d0220388542a6104ec519ea28a7770f6710058a9e0944b026b7c8e83da1d3dcf1273801483045022100d31875bbf396febf12f17edd94a6fd586d9f6b4a9b424c34972270f09d82445402201943b9ff70ce9595249bb6788c9511aaa82114d821c261159eac1b5b55b84c58014c69522102d341f728783eb93e6fb5921a1ebe9d149e941de31e403cd69afa2f0f1e698e812102f21b29694df4c2188bee97103d10d017d1865fb40528f25589af9db6e0786b6521028791dc45c049107fb99e673265a38a096536aacdf78aa90710a32fff7750f9f953aeffffffff030000000000000000316a2f69642afd357ee00b6c0365fb61184555ccfa35494a3fe02a9148d8b13939723d2aca16c75c6d68000000017d784000f48e012a0100000017a914d1558340e7651a8a1d5801a8335eae5ca2e87ba1877c150000000000001976a914000000000000000000000000000000000000000088ac00000000".to_owned(),
                result: Some(NamespacePreorderOp {
                    preorder_hash: Hash160::from_hex("fd357ee00b6c0365fb61184555ccfa35494a3fe0").unwrap(),
                    consensus_hash: ConsensusHash::from_hex("2a9148d8b13939723d2aca16c75c6d68").unwrap(),
                    op: '*' as u8,
                    op_fee: 5500,
                    txid: Txid::from_hex("f9cb46f15261fdf8135de9da4605ea65c526a1cef3873f025d0fd8fae1e6eae5").unwrap(),
                    vtxindex: vtxindex,
                    block_number: block_height,
                    sender: hex_bytes("a914d1558340e7651a8a1d5801a8335eae5ca2e87ba187").unwrap(),
                    sender_pubkey: None,
                    address: BitcoinAddress::from_b58("2NCL5euNJV9wNcKWQkTtEv7BxUdSTbaf7W1").unwrap(),
                    token_fee: Some(6400000000)
                })
            },
        
            // TODO NAMESPACE_PREORDER transactions with invalid burns, invalid lengths, invalid
            // #'s of inputs and outputs
        ];

        let parser = BitcoinBlockParser::new(BitcoinNetworkType::testnet, BLOCKSTACK_MAGIC_MAINNET);

        for tx_fixture in tx_fixtures {
            let tx = make_tx(&tx_fixture.txstr).unwrap();
            let burnchain_tx = parser.parse_tx(&tx, vtxindex as usize).unwrap();
            let op = NamespacePreorderOp::from_tx(BitcoinNetworkType::testnet, block_height, &burnchain_tx);

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

