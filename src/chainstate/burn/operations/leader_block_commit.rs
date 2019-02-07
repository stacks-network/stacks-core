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
use chainstate::burn::{BlockHeaderHash, VRFSeed};

use chainstate::burn::db::DBConn;
use chainstate::burn::db::burndb::BurnDB;

use burnchains::{BurnchainTransaction, BurnchainTxInput, PublicKey};
use burnchains::Txid;
use burnchains::Address;
use burnchains::BurnchainHeaderHash;

use util::log;
use util::hash::to_hex;

pub const OPCODE: u8 = '[' as u8;

#[derive(Debug, PartialEq, Clone, Eq)]
pub struct LeaderBlockCommitOp<A, K> {
    pub block_header_hash: BlockHeaderHash, // hash of Stacks block header (double-sha256)
    pub new_seed: VRFSeed,                  // new seed for this block
    pub parent_block_backptr: u16,          // back-pointer to the block that contains the parent block hash 
    pub parent_vtxindex: u16,               // offset in the parent block where the parent block hash can be found
    pub key_block_backptr: u16,             // back-pointer to the block that contains the leader key registration 
    pub key_vtxindex: u16,                  // offset in the block where the leader key can be found
    pub epoch_num: u32,                     // which epoch this commit was meant for?
    pub memo: Vec<u8>,                      // extra unused byte

    pub burn_fee: u64,                      // how many burn tokens (e.g. satoshis) were destroyed to produce this block
    pub input: BurnchainTxInput<K>,         // burn chain keys that must match the key registration

    // common to all transactions
    pub op: u8,                             // bytecode describing the operation
    pub txid: Txid,                         // transaction ID
    pub vtxindex: u32,                      // index in the block where this tx occurs
    pub block_number: u64,                  // block height at which this tx occurs
    pub burn_header_hash: BurnchainHeaderHash,      // hash of the burn chain block header

    // required in order to help the type checker reason about impls for A
    pub _phantom: PhantomData<A>
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

// return type from parse_data below
struct ParsedData {
    block_header_hash: BlockHeaderHash,
    new_seed: VRFSeed,
    parent_block_backptr: u16,
    parent_vtxindex: u16,
    key_block_backptr: u16,
    key_vtxindex: u16,
    epoch_num: u32,
    memo: Vec<u8>
}

impl<AddrType, PubkeyType> LeaderBlockCommitOp<AddrType, PubkeyType>
where
    AddrType: Address,
    PubkeyType: PublicKey
{
    fn parse_data(data: &Vec<u8>) -> Option<ParsedData> {
        /*
         
            Wire format:
            0      2  3           35               67     69     71    73   75     79    80
            |------|--|-------------|---------------|------|------|-----|-----|-----|-----|
             magic  op   block hash     new seed     parent parent key   key   epoch  memo
                                                     delta  txoff  delta txoff num.

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
        let parent_block_backptr = u16_from_be(&data[64..66]).unwrap();
        let parent_vtxindex = u16_from_be(&data[66..68]).unwrap();
        let key_block_backptr = u16_from_be(&data[68..70]).unwrap();
        let key_vtxindex = u16_from_be(&data[70..72]).unwrap();
        let epoch_num = u32_from_be(&data[72..76]).unwrap();
        let memo = data[76..77].to_vec();

        Some(ParsedData {
            block_header_hash,
            new_seed,
            parent_block_backptr,
            parent_vtxindex,
            key_block_backptr,
            key_vtxindex,
            epoch_num,
            memo
        })
    }

    fn parse_from_tx<A, K>(block_height: u64, block_hash: &BurnchainHeaderHash, tx: &BurnchainTransaction<A, K>) -> Result<LeaderBlockCommitOp<A, K>, op_error>
    where
        A: Address,
        K: PublicKey
    {
        // can't be too careful...
        if tx.inputs.len() == 0 {
            warn!("Invalid tx: inputs: {}, outputs: {}", tx.inputs.len(), tx.outputs.len());
            return Err(op_error::InvalidInput);
        }

        if tx.outputs.len() == 0 {
            warn!("Invalid tx: inputs: {}, outputs: {}", tx.inputs.len(), tx.outputs.len());
            return Err(op_error::InvalidInput);
        }

        if tx.opcode != OPCODE {
            warn!("Invalid tx: invalid opcode {}", tx.opcode);
            return Err(op_error::InvalidInput);
        }

        // outputs[0] should be the burn output
        if tx.outputs[0].address.to_bytes() != A::burn_bytes() {
            // wrong burn output
            warn!("Invalid tx: burn output missing (got {:?})", tx.outputs[0]);
            return Err(op_error::ParseError);
        }

        let burn_fee = tx.outputs[0].units;

        let parse_data_opt = LeaderBlockCommitOp::<A, K>::parse_data(&tx.data);
        if parse_data_opt.is_none() {
            warn!("Invalid tx data");
            return Err(op_error::ParseError);
        }

        let data = parse_data_opt.unwrap();

        // basic sanity checks 
        if data.parent_block_backptr as u64 >= block_height {
            warn!("Invalid tx: parent block back-pointer {} exceeds block height {}", data.parent_block_backptr, block_height);
            return Err(op_error::ParseError);
        }

        if data.key_block_backptr as u64 >= block_height {
            warn!("Invalid tx: key block back-pointer {} exceeds block height {}", data.key_block_backptr, block_height);
            return Err(op_error::ParseError);
        }

        if data.epoch_num as u64 >= block_height {
            warn!("Invalid tx: epoch number {} exceeds block height {}", data.epoch_num, block_height);
            return Err(op_error::ParseError);
        }

        Ok(LeaderBlockCommitOp {
            block_header_hash: data.block_header_hash,
            new_seed: data.new_seed,
            parent_block_backptr: data.parent_block_backptr,
            parent_vtxindex: data.parent_vtxindex,
            key_block_backptr: data.key_block_backptr,
            key_vtxindex: data.key_vtxindex,
            epoch_num: data.epoch_num,
            memo: data.memo,

            burn_fee: burn_fee,
            input: tx.inputs[0].clone(),

            op: OPCODE,
            txid: tx.txid.clone(),
            vtxindex: tx.vtxindex,
            block_number: block_height,
            burn_header_hash: block_hash.clone(),

            _phantom: PhantomData
        })
    }
}

impl<A, K> BlockstackOperation<A, K> for LeaderBlockCommitOp<A, K> 
where
    A: Address,
    K: PublicKey
{
    fn from_tx(block_height: u64, block_hash: &BurnchainHeaderHash, tx: &BurnchainTransaction<A, K>) -> Result<LeaderBlockCommitOp<A, K>, op_error> {
        LeaderBlockCommitOp::<A, K>::parse_from_tx(block_height, block_hash, tx)
    }
        
    fn check(&self, conn: &DBConn) -> Result<bool, op_error> {
        let leader_key_block_height = self.block_number - (self.key_block_backptr as u64);
        let parent_block_height = self.block_number - (self.parent_block_backptr as u64);
        
        /////////////////////////////////////////////////////////////////////////////////////
        // This tx's epoch number must match the current epoch
        /////////////////////////////////////////////////////////////////////////////////////
    
        let first_block_snapshot = BurnDB::<A, K>::get_first_block_snapshot(conn)
            .map_err(op_error::DBError)?;

        if self.block_number < first_block_snapshot.block_height {
            warn!("Invalid block commit: predates genesis height {}", first_block_snapshot.block_height);
            return Ok(false);
        }

        let target_epoch = self.block_number - first_block_snapshot.block_height;
        if (self.epoch_num as u64) != target_epoch {
            warn!("Invalid block commit: current epoch is {}; got {}", target_epoch, self.epoch_num);
            return Ok(false);
        }
        
        /////////////////////////////////////////////////////////////////////////////////////
        // There must exist a previously-accepted *unused* key from a LeaderKeyRegister
        /////////////////////////////////////////////////////////////////////////////////////

        let register_key_opt = BurnDB::<A, K>::get_leader_key(conn, leader_key_block_height, self.key_vtxindex.into())
            .map_err(op_error::DBError)?;

        if register_key_opt.is_none() {
            warn!("Invalid block commit: no corresponding leader key");
            return Ok(false);
        }

        let register_key = register_key_opt.unwrap();
    
        let is_key_available = BurnDB::<A, K>::is_leader_key_available(conn, &register_key)
            .map_err(op_error::DBError)?;

        if !is_key_available {
            warn!("Invalid block commit: leader key at {},{} is already used", register_key.block_number, register_key.vtxindex);
            return Ok(false);
        }

        /////////////////////////////////////////////////////////////////////////////////////
        // There must exist a previously-accepted block from a LeaderBlockCommit
        /////////////////////////////////////////////////////////////////////////////////////

        let parent_block_opt = BurnDB::<A, K>::get_block_commit(conn, parent_block_height, self.parent_vtxindex.into())
            .map_err(op_error::DBError)?;

        if parent_block_opt.is_none() {
            warn!("Invalid block commit: no corresponding parent block");
            return Ok(false);
        }
        
        /////////////////////////////////////////////////////////////////////////////////////
        // This LeaderBlockCommit's input public keys must match the address of the LeaderKeyRegister
        // -- the hash of the inputs' public key(s) must equal the hash contained within the
        // LeaderKeyRegister's address.  Note that we only need to check the address bytes,
        // not the entire address (since finding two sets of different public keys that
        // hash to the same address is considered intractible).
        //
        // Under the hood, the blockchain further ensures that the tx was signed with the
        // associated private keys, so only the private key owner(s) are in a position to 
        // reveal the keys that hash to the address's hash.
        /////////////////////////////////////////////////////////////////////////////////////

        let input_address_bytes = BurnchainTxInput::to_address_bits(&self.input);
        let addr_bytes = register_key.address.to_bytes();

        if input_address_bytes != addr_bytes {
            warn!("Invalid block commit: leader key at {},{} has address bytes {}, but this tx input has address bytes {}",
                  register_key.block_number, register_key.vtxindex, &to_hex(&input_address_bytes[..]), &to_hex(&addr_bytes[..]));
            return Ok(false);
        }

        Ok(true)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use burnchains::{BurnchainTxInput, BurnchainInputType};
    use burnchains::bitcoin::keys::BitcoinPublicKey;
    use burnchains::bitcoin::address::BitcoinAddress;
    use burnchains::bitcoin::blocks::BitcoinBlockParser;
    use burnchains::Txid;
    use burnchains::BLOCKSTACK_MAGIC_MAINNET;

    use burnchains::bitcoin::BitcoinNetworkType;

    use bitcoin::network::serialize::deserialize;
    use bitcoin::blockdata::transaction::Transaction;
    
    use chainstate::burn::{BlockHeaderHash, VRFSeed};

    use util::hash::hex_bytes;
    use util::log;

    struct OpFixture {
        txstr: String,
        result: Option<LeaderBlockCommitOp<BitcoinAddress, BitcoinPublicKey>>
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
        let block_height = 0x71706363;  // epoch number must be strictly smaller than block height
        let burn_header_hash = BurnchainHeaderHash::from_hex("0000000000000000000000000000000000000000000000000000000000000000").unwrap();

        let tx_fixtures = vec![
            OpFixture {
                // valid
                txstr: "01000000011111111111111111111111111111111111111111111111111111111111111111000000006b483045022100eba8c0a57c1eb71cdfba0874de63cf37b3aace1e56dcbd61701548194a79af34022041dd191256f3f8a45562e5d60956bb871421ba69db605716250554b23b08277b012102d8015134d9db8178ac93acbc43170a2f20febba5087a5b0437058765ad5133d000000000030000000000000000536a4c5069645b222222222222222222222222222222222222222222222222222222222222222233333333333333333333333333333333333333333333333333333333333333334041424350516061626370718039300000000000001976a914000000000000000000000000000000000000000088aca05b0000000000001976a9140be3e286a15ea85882761618e366586b5574100d88ac00000000".to_string(),
                result: Some(LeaderBlockCommitOp {
                    block_header_hash: BlockHeaderHash::from_bytes(&hex_bytes("2222222222222222222222222222222222222222222222222222222222222222").unwrap()).unwrap(),
                    new_seed: VRFSeed::from_bytes(&hex_bytes("3333333333333333333333333333333333333333333333333333333333333333").unwrap()).unwrap(),
                    parent_block_backptr: 0x4140,
                    parent_vtxindex: 0x4342,
                    key_block_backptr: 0x5150,
                    key_vtxindex: 0x6160,
                    epoch_num: 0x71706362,
                    memo: vec![0x80],

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
                    block_number: block_height,
                    burn_header_hash: burn_header_hash,
            
                    _phantom: PhantomData
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

        let parser = BitcoinBlockParser::new(BitcoinNetworkType::Testnet, BLOCKSTACK_MAGIC_MAINNET);

        for tx_fixture in tx_fixtures {
            let tx = make_tx(&tx_fixture.txstr).unwrap();
            let burnchain_tx = parser.parse_tx(&tx, vtxindex as usize).unwrap();
            let op = LeaderBlockCommitOp::from_tx(block_height, &burn_header_hash, &burnchain_tx);

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

