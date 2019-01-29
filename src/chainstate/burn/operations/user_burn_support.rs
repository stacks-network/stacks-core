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
use std::fmt;
use std::marker::PhantomData;

use chainstate::burn::operations::BlockstackOperation;
use chainstate::burn::operations::Error as op_error;
use chainstate::burn::ConsensusHash;

use chainstate::burn::db::burndb::BurnDB;
use chainstate::burn::db::DBConn;

use burnchains::BurnchainTransaction;
use burnchains::bitcoin::keys::BitcoinPublicKey;
use burnchains::bitcoin::BitcoinNetworkType;
use burnchains::bitcoin::address::{BitcoinAddressType, BitcoinAddress};
use burnchains::Txid;
use burnchains::Address;
use burnchains::PublicKey;
use burnchains::BurnchainHeaderHash;

use util::hash::{hex_bytes, Hash160};
use util::vrf::ECVRF_check_public_key;

use ed25519_dalek::PublicKey as VRFPublicKey;

pub const OPCODE: u8 = '_' as u8;

#[derive(Debug, PartialEq, Clone)]
pub struct UserBurnSupportOp<A, K> {
    pub consensus_hash: ConsensusHash,
    pub public_key: VRFPublicKey,
    pub block_header_hash_160: Hash160,
    pub memo: Vec<u8>,
    pub burn_fee: u64,

    // common to all transactions
    pub op: u8,                             // bytecode describing the operation
    pub txid: Txid,                         // transaction ID
    pub vtxindex: u32,                      // index in the block where this tx occurs
    pub block_number: u64,                  // block height at which this tx occurs
    pub burn_header_hash: BurnchainHeaderHash,   // hash of burnchain block with this tx

    // required to help the compiler figure out impls
    pub _phantom_a: PhantomData<A>,
    pub _phantom_k: PhantomData<K>
}

impl<AddrType, PubkeyType> UserBurnSupportOp<AddrType, PubkeyType>
where
    AddrType: Address,
    PubkeyType: PublicKey
{
    fn parse_data(data: &Vec<u8>) -> Option<(ConsensusHash, VRFPublicKey, Hash160, Vec<u8>)> {
        /*
            Wire format:

            0      2  3              23                       55                 75       80
            |------|--|---------------|-----------------------|------------------|--------|
             magic  op consensus hash    proving public key       block hash 160    memo

            
             Note that `data` is missing the first 3 bytes -- the magic and op have been stripped
        */
        // memo can be empty, and magic + op are omitted 
        if data.len() < 72 {
            warn!("USER_BURN_SUPPORT payload is malformed ({} bytes)", data.len());
            return None;
        }

        let consensus_hash = ConsensusHash::from_vec(&data[0..20].to_vec()).unwrap();
        let pubkey_opt = ECVRF_check_public_key(&data[20..52].to_vec());
        if pubkey_opt.is_none() {
            warn!("Invalid VRF public key");
            return None;
        }
        let pubkey = pubkey_opt.unwrap(); 
        let block_header_hash_160 = Hash160::from_vec(&data[52..72].to_vec()).unwrap();
        let memo = data[72..].to_vec();

        return Some((consensus_hash, pubkey, block_header_hash_160, memo));
    }

    fn parse_from_tx<A, K>(block_height: u64, block_hash: &BurnchainHeaderHash, tx: &BurnchainTransaction<A, K>) -> Result<UserBurnSupportOp<A, K>, op_error>
    where
        A: Address,
        K: PublicKey
    {
        // can't be too careful...
        if tx.inputs.len() == 0 || tx.outputs.len() == 0 {
            test_debug!("Invalid tx: inputs: {}, outputs: {}", tx.inputs.len(), tx.outputs.len());
            return Err(op_error::InvalidInput);
        }

        if tx.opcode != OPCODE {
            test_debug!("Invalid tx: invalid opcode {}", tx.opcode);
            return Err(op_error::InvalidInput);
        }

        // outputs[0] should be the burn output
        // TODO: replace with Address::burn_address() trait method
        if tx.outputs[0].address.to_bytes() != hex_bytes("0000000000000000000000000000000000000000").unwrap() {
            // wrong burn output
            test_debug!("Invalid tx: burn output missing (got {:?})", tx.outputs[0]);
            return Err(op_error::ParseError);
        }

        let burn_fee = tx.outputs[0].units;

        let parse_data_opt = UserBurnSupportOp::<A, K>::parse_data(&tx.data);
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
            burn_fee: burn_fee,

            op: OPCODE,
            txid: tx.txid.clone(),
            vtxindex: tx.vtxindex,
            block_number: block_height,
            burn_header_hash: block_hash.clone(),

            _phantom_a: PhantomData,
            _phantom_k: PhantomData
        })
    }
}

impl<A, K> BlockstackOperation<A, K> for UserBurnSupportOp<A, K>
where
    A: Address,
    K: PublicKey
{
    fn from_tx(block_height: u64, block_hash: &BurnchainHeaderHash, tx: &BurnchainTransaction<A, K>) -> Result<UserBurnSupportOp<A, K>, op_error> {
        UserBurnSupportOp::<A, K>::parse_from_tx(block_height, block_hash, tx)
    }

    fn check(&self, conn: &DBConn) -> Result<bool, op_error> {
        Ok(false)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use burnchains::bitcoin::blocks::BitcoinBlockParser;
    use burnchains::Txid;
    use burnchains::BLOCKSTACK_MAGIC_MAINNET;

    use bitcoin::network::serialize::deserialize;
    use bitcoin::blockdata::transaction::Transaction;

    use chainstate::burn::ConsensusHash;
    
    use util::hash::{hex_bytes, Hash160};
    use util::log as logger;

    struct OpFixture {
        txstr: String,
        result: Option<UserBurnSupportOp<BitcoinAddress, BitcoinPublicKey>>
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
        let burn_header_hash = BurnchainHeaderHash::from_hex("0000000000000000000000000000000000000000000000000000000000000000").unwrap();

        let tx_fixtures: Vec<OpFixture> = vec![
            OpFixture {
                txstr: "01000000011111111111111111111111111111111111111111111111111111111111111111000000006a47304402204c51707ac34b6dcbfc518ba40c5fc4ef737bf69cc21a9f8a8e6f621f511f78e002200caca0f102d5df509c045c4fe229d957aa7ef833dc8103dc2fe4db15a22bab9e012102d8015134d9db8178ac93acbc43170a2f20febba5087a5b0437058765ad5133d000000000030000000000000000536a4c5069645f2222222222222222222222222222222222222222a366b51292bef4edd64063d9145c617fec373bceb0758e98cd72becd84d54c7a3333333333333333333333333333333333333333010203040539300000000000001976a914000000000000000000000000000000000000000088aca05b0000000000001976a9140be3e286a15ea85882761618e366586b5574100d88ac00000000".to_string(),
                result: Some(UserBurnSupportOp {
                    consensus_hash: ConsensusHash::from_bytes(&hex_bytes("2222222222222222222222222222222222222222").unwrap()).unwrap(),
                    public_key: VRFPublicKey::from_bytes(&hex_bytes("a366b51292bef4edd64063d9145c617fec373bceb0758e98cd72becd84d54c7a").unwrap()).unwrap(),
                    block_header_hash_160: Hash160::from_bytes(&hex_bytes("3333333333333333333333333333333333333333").unwrap()).unwrap(),
                    memo: vec![0x01, 0x02, 0x03, 0x04, 0x05],
                    burn_fee: 12345,

                    op: OPCODE,
                    txid: Txid::from_bytes_be(&hex_bytes("1d5cbdd276495b07f0e0bf0181fa57c175b217bc35531b078d62fc20986c716c").unwrap()).unwrap(),
                    vtxindex: vtxindex,
                    block_number: block_height,
                    burn_header_hash: burn_header_hash,

                    _phantom_a: PhantomData,
                    _phantom_k: PhantomData
                })
            },
            OpFixture {
                // invalid -- no burn output
                txstr: "01000000011111111111111111111111111111111111111111111111111111111111111111000000006a473044022073490a3958b9e6128d3b7a4a8c77203c56862b2da382e96551f7efae7029b0e1022046672d1e61bdfd3dca9cc199bffd0bfb9323e432f8431bb6749da3c5bd06e9ca012102d8015134d9db8178ac93acbc43170a2f20febba5087a5b0437058765ad5133d000000000020000000000000000536a4c5069645f2222222222222222222222222222222222222222a366b51292bef4edd64063d9145c617fec373bceb0758e98cd72becd84d54c7a33333333333333333333333333333333333333330102030405a05b0000000000001976a9140be3e286a15ea85882761618e366586b5574100d88ac00000000".to_string(),
                result: None,
            },
            OpFixture {
                // invalid -- bad public key
                txstr: "01000000011111111111111111111111111111111111111111111111111111111111111111000000006a47304402202bf944fa4d1dbbdd4f53e915c85f07c8a5afbf917f7cc9169e9c7d3bbadff05a022064b33a1020dd9cdd0ac6de213ee1bd8f364c9c876e716ad289f324c2a4bbe48a012102d8015134d9db8178ac93acbc43170a2f20febba5087a5b0437058765ad5133d000000000030000000000000000536a4c5069645f2222222222222222222222222222222222222222a366b51292bef4edd64063d9145c617fec373bceb0758e98cd72becd84d54c7b3333333333333333333333333333333333333333010203040539300000000000001976a914000000000000000000000000000000000000000088aca05b0000000000001976a9140be3e286a15ea85882761618e366586b5574100d88ac00000000".to_string(),
                result: None,
            },
            OpFixture {
                // invalid -- too short 
                txstr: "01000000011111111111111111111111111111111111111111111111111111111111111111000000006a473044022038534377d738ba91df50a4bc885bcd6328520438d42cc29636cc299a24dcb4c202202953e87b6c176697d01d66a742a27fd48b8d2167fb9db184d59a3be23a59992e012102d8015134d9db8178ac93acbc43170a2f20febba5087a5b0437058765ad5133d0000000000300000000000000004c6a4a69645f2222222222222222222222222222222222222222a366b51292bef4edd64063d9145c617fec373bceb0758e98cd72becd84d54c7a3333333333333333333333333333333333333339300000000000001976a914000000000000000000000000000000000000000088aca05b0000000000001976a9140be3e286a15ea85882761618e366586b5574100d88ac00000000".to_string(),
                result: None,
            },
            OpFixture {
                // invalid -- wrong opcode
                txstr: "01000000011111111111111111111111111111111111111111111111111111111111111111000000006a47304402200e6dbb4ccefc44582135091678a49228716431583dab3d789b1211d5737d02e402205b523ad156cad4ae6bb29f046b144c8c82b7c85698616ee8f5d59ea40d594dd4012102d8015134d9db8178ac93acbc43170a2f20febba5087a5b0437058765ad5133d000000000030000000000000000536a4c5069645e2222222222222222222222222222222222222222a366b51292bef4edd64063d9145c617fec373bceb0758e98cd72becd84d54c7a3333333333333333333333333333333333333333010203040539300000000000001976a914000000000000000000000000000000000000000088aca05b0000000000001976a9140be3e286a15ea85882761618e366586b5574100d88ac00000000".to_string(),
                result: None,
            }
        ];

        let parser = BitcoinBlockParser::new(BitcoinNetworkType::testnet, BLOCKSTACK_MAGIC_MAINNET);

        for tx_fixture in tx_fixtures {
            let tx = make_tx(&tx_fixture.txstr).unwrap();
            let burnchain_tx = parser.parse_tx(&tx, vtxindex as usize).unwrap();
            let op = UserBurnSupportOp::from_tx(block_height, &burn_header_hash, &burnchain_tx);

            match (op, tx_fixture.result) {
                (Ok(parsed_tx), Some(result)) => {
                    assert_eq!(parsed_tx, result);
                },
                (Err(_e), None) => {},
                (Ok(_parsed_tx), None) => {
                    test_debug!("Parsed a tx when we should not have");
                    assert!(false);
                },
                (Err(_e), Some(_result)) => {
                    test_debug!("Did not parse a tx when we should have");
                    assert!(false);
                }
            };
        }
    }
}

