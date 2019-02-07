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

use std::marker::PhantomData;

use chainstate::burn::operations::BlockstackOperation;
use chainstate::burn::operations::Error as op_error;
use chainstate::burn::ConsensusHash;

use chainstate::burn::db::burndb::BurnDB;
use chainstate::burn::db::DBConn;

use burnchains::BurnchainTransaction;
use burnchains::Txid;
use burnchains::Address;
use burnchains::PublicKey;
use burnchains::BurnchainHeaderHash;

use util::vrf::{ECVRF_check_public_key, ECVRF_public_key_to_hex};

use ed25519_dalek::PublicKey as VRFPublicKey;

use util::log;

pub const OPCODE: u8 = '^' as u8;

#[derive(Debug, PartialEq, Clone)]
pub struct LeaderKeyRegisterOp<A, K> {
    pub consensus_hash: ConsensusHash,      // consensus hash at time of issuance
    pub public_key: VRFPublicKey,           // EdDSA public key 
    pub memo: Vec<u8>,                      // extra bytes in the op-return
    pub address: A,                         // second output's address -- will be used to help pair this tx up with a leader block commit tx
    
    // common to all transactions
    pub op: u8,                             // bytecode describing the operation
    pub txid: Txid,                         // transaction ID
    pub vtxindex: u32,                      // index in the block where this tx occurs
    pub block_number: u64,                  // block height at which this tx occurs
    pub burn_header_hash: BurnchainHeaderHash,    // hash of burn chain block 

    // required in order to help the type checker reason about impls for K
    pub _phantom: PhantomData<K>
}

impl<AddrType, PubkeyType> LeaderKeyRegisterOp<AddrType, PubkeyType> 
where
    AddrType: Address,
    PubkeyType: PublicKey
{
    fn parse_data(data: &Vec<u8>) -> Option<(ConsensusHash, VRFPublicKey, Vec<u8>)> {
        /*
            Wire format:

            0      2  3              23                       55                          80
            |------|--|---------------|-----------------------|---------------------------|
             magic  op consensus hash   proving public key               memo

            
             Note that `data` is missing the first 3 bytes -- the magic and op have been stripped
        */
        // memo can be empty, and magic + op are omitted 
        if data.len() < 52 {
            // too short to have a consensus hash and proving public key
            warn!("LEADER_KEY_REGISTER payload is malformed ({} bytes)", data.len());
            return None;
        }

        let consensus_hash = ConsensusHash::from_bytes(&data[0..20]).unwrap();
        let pubkey_opt = ECVRF_check_public_key(&data[20..52].to_vec());
        if pubkey_opt.is_none() {
            warn!("Invalid VRF public key");
            return None;
        }

        let pubkey = pubkey_opt.unwrap();
        let memo = &data[52..];

        return Some((consensus_hash, pubkey, memo.to_vec()));
    }

    fn parse_from_tx<A, K>(block_height: u64, block_hash: &BurnchainHeaderHash, tx: &BurnchainTransaction<A, K>) -> Result<LeaderKeyRegisterOp<A, K>, op_error>
    where
        A: Address,
        K: PublicKey
    {
        // can't be too careful...
        if tx.inputs.len() == 0 {
            test_debug!("Invalid tx: inputs: {}, outputs: {}", tx.inputs.len(), tx.outputs.len());
            return Err(op_error::InvalidInput);
        }

        if tx.outputs.len() < 1 {
            test_debug!("Invalid tx: inputs: {}, outputs: {}", tx.inputs.len(), tx.outputs.len());
            return Err(op_error::InvalidInput);
        }

        if tx.opcode != OPCODE {
            test_debug!("Invalid tx: invalid opcode {}", tx.opcode);
            return Err(op_error::InvalidInput);
        }

        let parse_data_opt = LeaderKeyRegisterOp::<A, K>::parse_data(&tx.data);
        if parse_data_opt.is_none() {
            test_debug!("Invalid tx data");
            return Err(op_error::ParseError);
        }

        let (consensus_hash, pubkey, memo) = parse_data_opt.unwrap();
        let address = tx.outputs[0].address.clone();

        Ok(LeaderKeyRegisterOp {
            consensus_hash: consensus_hash,
            public_key: pubkey,
            memo: memo,
            address: address,

            op: OPCODE,
            txid: tx.txid.clone(),
            vtxindex: tx.vtxindex,
            block_number: block_height,
            burn_header_hash: block_hash.clone(),

            _phantom: PhantomData
        })
    }
}

impl<A, K> BlockstackOperation<A, K> for LeaderKeyRegisterOp<A, K> 
where
    A: Address,
    K: PublicKey
{
    fn from_tx(block_height: u64, block_hash: &BurnchainHeaderHash, tx: &BurnchainTransaction<A, K>) -> Result<LeaderKeyRegisterOp<A, K>, op_error> {
        LeaderKeyRegisterOp::<A, K>::parse_from_tx(block_height, block_hash, tx)
    }

    fn check(&self, conn: &DBConn) -> Result<bool, op_error> {
        /////////////////////////////////////////////////////////////////
        // Keys must be unique -- no one can register the same key twice
        /////////////////////////////////////////////////////////////////

        // key selected here must never have been submitted before 
        let has_key_already = BurnDB::<A, K>::has_VRF_public_key(conn, &self.public_key)
            .map_err(op_error::DBError)?;

        if has_key_already {
            warn!("Invalid leader key registration: public key {} previously used", ECVRF_public_key_to_hex(&self.public_key));
            return Ok(false);
        }

        /////////////////////////////////////////////////////////////////
        // Consensus hash must be recent and valid
        /////////////////////////////////////////////////////////////////

        let consensus_hash_recent = BurnDB::<A, K>::is_fresh_consensus_hash(conn, self.block_number, &self.consensus_hash)
            .map_err(op_error::DBError)?;

        if !consensus_hash_recent {
            warn!("Invalid consensus hash {}", &self.consensus_hash.to_hex());
            return Ok(false);
        }

        return Ok(true);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use burnchains::bitcoin::address::BitcoinAddress;
    use burnchains::bitcoin::keys::BitcoinPublicKey;
    use burnchains::bitcoin::blocks::BitcoinBlockParser;
    use burnchains::bitcoin::BitcoinNetworkType;
    use burnchains::Txid;
    use burnchains::BLOCKSTACK_MAGIC_MAINNET;

    use bitcoin::network::serialize::deserialize;
    use bitcoin::blockdata::transaction::Transaction;

    use chainstate::burn::ConsensusHash;
    
    use util::hash::hex_bytes;
    use util::log;

    struct OpFixture {
        txstr: String,
        result: Option<LeaderKeyRegisterOp<BitcoinAddress, BitcoinPublicKey>>
    }

    fn make_tx(hex_str: &str) -> Result<Transaction, &'static str> {
        let tx_bin = hex_bytes(hex_str)?;
        let tx = deserialize(&tx_bin.to_vec())
            .map_err(|_e| "failed to deserialize")?;
        Ok(tx)
    }

    #[test]
    fn test_parse() {
        let vtxindex = 1;
        let block_height = 694;
        let burn_header_hash = BurnchainHeaderHash::from_hex("0000000000000000000000000000000000000000000000000000000000000000").unwrap();

        let tx_fixtures: Vec<OpFixture> = vec![
            OpFixture {
                txstr: "01000000011111111111111111111111111111111111111111111111111111111111111111000000006a47304402203a176d95803e8d51e7884d38750322c4bfa55307a71291ef8db65191edd665f1022056f5d1720d1fde8d6a163c79f73f22f874ef9e186e98e5b60fa8ac64d298e77a012102d8015134d9db8178ac93acbc43170a2f20febba5087a5b0437058765ad5133d0000000000200000000000000003e6a3c69645e2222222222222222222222222222222222222222a366b51292bef4edd64063d9145c617fec373bceb0758e98cd72becd84d54c7a010203040539300000000000001976a9140be3e286a15ea85882761618e366586b5574100d88ac00000000".to_string(),
                result: Some(LeaderKeyRegisterOp {
                    consensus_hash: ConsensusHash::from_bytes(&hex_bytes("2222222222222222222222222222222222222222").unwrap()).unwrap(),
                    public_key: VRFPublicKey::from_bytes(&hex_bytes("a366b51292bef4edd64063d9145c617fec373bceb0758e98cd72becd84d54c7a").unwrap()).unwrap(),
                    memo: vec![01, 02, 03, 04, 05],
                    address: BitcoinAddress::from_scriptpubkey(BitcoinNetworkType::testnet, &hex_bytes("76a9140be3e286a15ea85882761618e366586b5574100d88ac").unwrap()).unwrap(),

                    op: OPCODE,
                    txid: Txid::from_bytes_be(&hex_bytes("1bfa831b5fc56c858198acb8e77e5863c1e9d8ac26d49ddb914e24d8d4083562").unwrap()).unwrap(),
                    vtxindex: vtxindex,
                    block_number: block_height,
                    burn_header_hash: burn_header_hash.clone(),
            
                    _phantom: PhantomData
                })
            },
            OpFixture {
                txstr: "01000000011111111111111111111111111111111111111111111111111111111111111111000000006a473044022037d0b9d4e98eab190522acf5fb8ea8e89b6a4704e0ac6c1883d6ffa629b3edd30220202757d710ec0fb940d1715e02588bb2150110161a9ee08a83b750d961431a8e012102d8015134d9db8178ac93acbc43170a2f20febba5087a5b0437058765ad5133d000000000020000000000000000396a3769645e2222222222222222222222222222222222222222a366b51292bef4edd64063d9145c617fec373bceb0758e98cd72becd84d54c7a39300000000000001976a9140be3e286a15ea85882761618e366586b5574100d88ac00000000".to_string(),
                result: Some(LeaderKeyRegisterOp {
                    consensus_hash: ConsensusHash::from_bytes(&hex_bytes("2222222222222222222222222222222222222222").unwrap()).unwrap(),
                    public_key: VRFPublicKey::from_bytes(&hex_bytes("a366b51292bef4edd64063d9145c617fec373bceb0758e98cd72becd84d54c7a").unwrap()).unwrap(),
                    memo: vec![],
                    address: BitcoinAddress::from_scriptpubkey(BitcoinNetworkType::testnet, &hex_bytes("76a9140be3e286a15ea85882761618e366586b5574100d88ac").unwrap()).unwrap(),

                    op: OPCODE,
                    txid: Txid::from_bytes_be(&hex_bytes("2fbf8d5be32dce49790d203ba59acbb0929d5243413174ff5d26a5c6f23dea65").unwrap()).unwrap(),
                    vtxindex: vtxindex,
                    block_number: block_height,
                    burn_header_hash: burn_header_hash,
                    
                    _phantom: PhantomData
                })
            },
            OpFixture {
                // invalid VRF public key 
                txstr: "01000000011111111111111111111111111111111111111111111111111111111111111111000000006b483045022100ddbbaf029174a9bd1588fc0b34094e9f48fec9c89704eb12a3ee70dd5ca4142e02202eab7cbf985da23e890766331f7e0009268d1db75da8b583a953528e6a099499012102d8015134d9db8178ac93acbc43170a2f20febba5087a5b0437058765ad5133d0000000000200000000000000003e6a3c69645e2222222222222222222222222222222222222222a366b51292bef4edd64063d9145c617fec373bceb0758e98cd72becd84d54c7b010203040539300000000000001976a9140be3e286a15ea85882761618e366586b5574100d88ac00000000".to_string(),
                result: None,
            },
            OpFixture {
                // too short
                txstr: "01000000011111111111111111111111111111111111111111111111111111111111111111000000006b483045022100b2680431ab771826f42b93f5238e518c6483af7026c25ddd6e970f26fec80473022050ab510ede8d7b50cea1a286d1e05fa2b2d62ffbb9983e4cade9899474d0f8b9012102d8015134d9db8178ac93acbc43170a2f20febba5087a5b0437058765ad5133d000000000020000000000000000386a3669645e22222222222222222222222222222222222222a366b51292bef4edd64063d9145c617fec373bceb0758e98cd72becd84d54c7a39300000000000001976a9140be3e286a15ea85882761618e366586b5574100d88ac00000000".to_string(),
                result: None,
            },
            OpFixture {
                // not enough outputs
                txstr: "01000000011111111111111111111111111111111111111111111111111111111111111111000000006a473044022070c8ce3786cee46d283b8a02a9c6ba87ef693960a0200b4a85e1b4808ea7b23a02201c6926162fe8cf4d3bbc3fcea80baa8307543af69b5dbbad72aa659a3a87f08e012102d8015134d9db8178ac93acbc43170a2f20febba5087a5b0437058765ad5133d0000000000100000000000000003e6a3c69645e2222222222222222222222222222222222222222a366b51292bef4edd64063d9145c617fec373bceb0758e98cd72becd84d54c7a010203040500000000".to_string(),
                result: None,
            },
            OpFixture {
                // wrong opcode
                txstr: "01000000011111111111111111111111111111111111111111111111111111111111111111000000006b483045022100a72df03441bdd08b8fd042f417e37e7ba7dc6212078835840f4cbd64f690533a0220385309a6096044828ec7889107a73da23b009157a752251ed68f8084834d4d44012102d8015134d9db8178ac93acbc43170a2f20febba5087a5b0437058765ad5133d0000000000200000000000000003e6a3c69645f2222222222222222222222222222222222222222a366b51292bef4edd64063d9145c617fec373bceb0758e98cd72becd84d54c7a010203040539300000000000001976a9140be3e286a15ea85882761618e366586b5574100d88ac00000000".to_string(),
                result: None,
            }
        ];

        let parser = BitcoinBlockParser::new(BitcoinNetworkType::testnet, BLOCKSTACK_MAGIC_MAINNET);

        for tx_fixture in tx_fixtures {
            let tx = make_tx(&tx_fixture.txstr).unwrap();
            let burnchain_tx = parser.parse_tx(&tx, vtxindex as usize).unwrap();
            let op = LeaderKeyRegisterOp::from_tx(block_height, &burn_header_hash, &burnchain_tx);

            match (op, tx_fixture.result) {
                (Ok(parsed_tx), Some(result)) => {
                    assert_eq!(parsed_tx, result);
                },
                (Err(_e), None) => {},
                (Ok(_parsed_tx), None) => {
                    test_debug!("Parsed a tx when we should not have: {}", tx_fixture.txstr);
                    assert!(false);
                },
                (Err(_e), Some(_result)) => {
                    test_debug!("Did not parse a tx when we should have: {}", tx_fixture.txstr);
                    assert!(false);
                }
            };
        }
    }
}

