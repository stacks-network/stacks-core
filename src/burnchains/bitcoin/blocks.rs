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

use std::fs;
use std::cmp;
use std::sync::Arc;
use std::sync::mpsc::{SyncSender, Receiver, sync_channel};
use std::thread;
use std::thread::JoinHandle;
use std::ops::Deref;

use bitcoin::blockdata::block::{LoneBlockHeader, BlockHeader, Block};
use bitcoin::blockdata::transaction::{Transaction, TxIn, TxOut};
use bitcoin::blockdata::opcodes::All as btc_opcodes;
use bitcoin::blockdata::opcodes::Class;
use bitcoin::blockdata::script::{Script, Instruction, Instructions};

use bitcoin::network::encodable::{ConsensusEncodable, ConsensusDecodable, VarInt};
use bitcoin::network::serialize::{RawEncoder, RawDecoder, serialize, deserialize, BitcoinHash};
use bitcoin::network::message as btc_message;

use bitcoin::util::hash::{Sha256dHash, bitcoin_merkle_root};
use bitcoin::util::uint::Uint256;

use burnchains::bitcoin::indexer::{BitcoinIndexer, BITCOIN_MAINNET, BITCOIN_TESTNET, BITCOIN_REGTEST};
use burnchains::bitcoin::Error as btc_error;
use burnchains::bitcoin::spv::SpvClient;
use burnchains::bitcoin::messages::BitcoinMessageHandler;
use burnchains::bitcoin::network::PeerMessage;
use burnchains::bitcoin::bits;
use burnchains::bitcoin::keys::BitcoinPublicKey;

use burnchains::{
    BurnchainBlock, 
    BurnchainTxInput, 
    BurnchainTxOutput, 
    BurnchainTransaction, 
    AddressType, 
    Address, 
    PublicKey, 
    Txid, 
    MagicBytes, 
    Hash160, 
    MAGIC_BYTES_LENGTH
};

// IPC messages between threads
pub struct IPCHeader {
    height: u64
}

pub struct IPCBlock {
    height: u64,
    header: LoneBlockHeader,
    block: PeerMessage
}

pub struct BitcoinBlockDownloader {
    headers_path: String,
    start_block_height: u64,
    end_block_height: u64,
    cur_block_height: u64,
    network_id: u32,

    pub chan_in: Option<SyncSender<Arc<IPCHeader>>>,
    pub chan_out: Option<SyncSender<Arc<IPCBlock>>>,
    pub thread: Option<JoinHandle<()>>
}

struct BitcoinBlockParser {
    magic_bytes: MagicBytes,
    pub chan_in: Option<Receiver<Arc<IPCBlock>>>,
    pub chan_out: Option<SyncSender<Arc<BurnchainBlock<BitcoinPublicKey>>>>,
    pub thread: Option<JoinHandle<()>>
}

impl BitcoinBlockDownloader {
    pub fn new(headers_path: &str, start_block: u64, end_block: u64, network_id: u32) -> BitcoinBlockDownloader {
        BitcoinBlockDownloader {
            headers_path: headers_path.to_owned(),
            start_block_height: start_block,
            end_block_height: end_block,
            cur_block_height: start_block,
            network_id: network_id,
            chan_in: None,
            chan_out: None,
            thread: None
        }
    }

    // TODO: connection methods and thread start
    // TODO: receive a block and send it off

    /// Go get all the blocks.
    /// keep trying forever.
    pub fn run(&mut self, indexer: &mut BitcoinIndexer) -> Result<(), btc_error> {
        return indexer.peer_communicate(self);
    }
}

impl BitcoinMessageHandler for BitcoinBlockDownloader {

    /// Trait message handler 
    /// initiate the conversation with the bitcoin peer
    fn begin_session(&mut self, indexer: &mut BitcoinIndexer) -> Result<bool, btc_error> {
        // sanity check
        fs::metadata(&self.headers_path)
            .map_err(btc_error::FilesystemError)?;

        let header_opt = SpvClient::read_block_header(&self.headers_path, self.cur_block_height)?;
        match header_opt {
            None => {
                // not found yet 
                Ok(false)
            }
            Some(header) => {
                // ask for initial block
                indexer.send_getblocks(&vec![header.header.bitcoin_hash()])
                    .and_then(|_r| Ok(true))
            }
        }
    }

    /// Trait message handler
    /// Take headers, validate them, and ask for more
    fn handle_message(&mut self, indexer: &mut BitcoinIndexer, msg: &PeerMessage) -> Result<bool, btc_error> {
        // send to our consumer thread for parsing
        match msg.deref() {
            btc_message::NetworkMessage::Block(ref block) => {
                debug!("Got block {}: {}", self.cur_block_height, block.bitcoin_hash());

                // recover header
                // (it should be an error for it not to exist, since we already asked for the block
                // with this header's data).
                let cur_header_opt = SpvClient::read_block_header(&self.headers_path, self.cur_block_height)?;
                if cur_header_opt.is_none() {
                    return Ok(false);
                }

                let ipc_block = Arc::new(IPCBlock {
                    height: self.cur_block_height,
                    header: cur_header_opt.unwrap(),
                    block: msg.clone()
                });

                // send off to parser
                match self.chan_out {
                    Some(ref chan) => {
                        chan.send(ipc_block)
                            .map_err(|_e| btc_error::PipelineError)?;
                    }
                    None => {}
                };
                
                // request next block 
                self.cur_block_height += 1;
                match SpvClient::read_block_header(&self.headers_path, self.cur_block_height) {
                    Err(_) => {
                        // not found yet 
                        Ok(false)
                    }
                    Ok(header_opt) => {
                        match header_opt {
                            Some(header) => {
                                // next block 
                                indexer.send_getblocks(&vec![header.header.bitcoin_hash()])
                                    .and_then(|_r| Ok(true))
                            },
                            None => {
                                // no header yet 
                                Ok(false)
                            }
                        }
                    }
                }
            },
            _ => { 
                Err(btc_error::UnhandledMessage)
            }
        }
    }
}

impl BitcoinBlockParser {

    pub fn new(magic_bytes: MagicBytes) -> BitcoinBlockParser {
        BitcoinBlockParser {
            magic_bytes: magic_bytes.clone(),
            chan_in: None,
            chan_out: None,
            thread: None
        }
    }
    
    /// Parse the data output to get a byte payload 
    fn parse_data(&self, data_output: &Script) -> Option<(u8, Vec<u8>)> {
        if !data_output.is_op_return() {
            test_debug!("Data output is not an OP_RETURN");
            return None;
        }

        if data_output.len() <= self.magic_bytes.len() {
            test_debug!("Data output is too short to carry an operation");
            return None;
        }

        let script_pieces = bits::parse_script(&data_output);
        if script_pieces.len() != 2 {
            // not OP_RETURN <data>
            test_debug!("Data output does not encode a valid OP_RETURN");
            return None;
        }

        match (&script_pieces[0], &script_pieces[1]) {
            (Instruction::Op(ref opcode), Instruction::PushBytes(ref data)) => {
                if *opcode != btc_opcodes::OP_RETURN {
                    test_debug!("Data output does not use a standard OP_RETURN");
                    return None;
                }
                if !data.starts_with(self.magic_bytes.as_bytes()) {
                    test_debug!("Data output does not start with magic bytes");
                    return None;
                }
                
                let opcode = data[MAGIC_BYTES_LENGTH];
                Some((opcode, data[MAGIC_BYTES_LENGTH+1..data.len()].to_vec()))
            },
            (_, _) => {
                test_debug!("Data output is not OP_RETURN <data>");
                None
            }
        }
    }


    /// Is this an acceptable transaction?  It must have
    /// * an OP_RETURN output at output 0
    /// * only p2pkh or p2sh outputs for outputs 1...n
    fn maybe_burnchain_tx(&self, tx: &Transaction) -> bool {
        if self.parse_data(&tx.output[0].script_pubkey).is_none() {
            test_debug!("Tx {:?} has no valid OP_RETURN", tx.txid());
            return false;
        }

        for i in 1..tx.output.len() {
            if !tx.output[i].script_pubkey.is_p2pkh() && !tx.output[i].script_pubkey.is_p2sh() {
                // unrecognized output type
                test_debug!("Tx {:?} has unrecognized output type in output {}", tx.txid(), i);
                return false;
            }
        }

        return true;
    }


    /// Parse a transaction's inputs into burnchain tx inputs.
    /// Succeeds only if we can parse each input.
    fn parse_inputs(&self, tx: &Transaction) -> Option<Vec<BurnchainTxInput<BitcoinPublicKey>>> {
        let mut ret = vec![];
        for inp in &tx.input {
            match BurnchainTxInput::from_bitcoin_txin(&inp) {
                None => {
                    return None;
                }
                Some(i) => {
                    ret.push(i);
                }
            };
        }
        Some(ret)
    }

    /// Parse a transaction's outputs into burnchain tx outputs.
    /// Succeeds only if we can parse each output.
    /// Does not parse the first output -- this is the OP_RETURN
    fn parse_outputs(&self, tx: &Transaction) -> Option<Vec<BurnchainTxOutput>> {
        let mut ret = vec![];
        for outp in &tx.output[1..tx.output.len()] {
            match BurnchainTxOutput::from_bitcoin_txout(&outp) {
                None => {
                    return None;
                }
                Some(o) => {
                    ret.push(o);
                }
            };
        }
        Some(ret)
    }

    /// Parse a Bitcoin transaction into a Burnchain transaction 
    fn parse_tx(&self, tx: &Transaction, vtxindex: usize) -> Option<BurnchainTransaction<BitcoinPublicKey>> {
        if !self.maybe_burnchain_tx(tx) {
            return None;
        }

        let data_opt = self.parse_data(&tx.output[0].script_pubkey);
        if data_opt.is_none() {
            return None;
        }

        let (opcode, data) = data_opt.unwrap();
        let inputs_opt = self.parse_inputs(tx);
        let outputs_opt = self.parse_outputs(tx);

        match (inputs_opt, outputs_opt) {
            (Some(inputs), Some(outputs)) => {
                Some(BurnchainTransaction {
                    txid: Txid::from_vec_be(&tx.txid().as_bytes().to_vec()).unwrap(), // txids are little-endian in Blockstack, and this *should* panic if it fails
                    vtxindex: vtxindex as u64,
                    opcode: opcode,
                    data: data,
                    inputs: inputs,
                    outputs: outputs
                })
            }
            (_, _) => None
        }
    }
    
    /// Given a Bitcoin block, extract the transactions that have OP_RETURN <magic>.
    /// All outputs must also either be p2pkh or p2sh, and all inputs must encode
    /// eiher a p2pkh or multisig p2sh scriptsig.
    fn parse_block(&self, block: &Block, block_height: u64) -> BurnchainBlock<BitcoinPublicKey> {
        let mut accepted_txs = vec![];
        for i in 0..block.txdata.len() {
            let tx = &block.txdata[i];
            match self.parse_tx(tx, i) {
                Some(burnchain_tx) => {
                    accepted_txs.push(burnchain_tx);
                }
                None => {
                    continue;
                }
            }
        }

        BurnchainBlock {
            block_height: block_height,
            block_hash: block.bitcoin_hash()[..].to_vec(),
            txs: accepted_txs
        }
    }

    /// Return true if we handled the block, and we can receive the next one.  Update internal
    /// state, extract the BurnchainTransactions.
    ///
    /// Return false if the block we got did not match the next expected block's header
    /// (in which case, we should re-start the conversation with the peer and try again).
    fn process_block(&mut self, block: &Block, header: &LoneBlockHeader, height: u64) -> Option<BurnchainBlock<BitcoinPublicKey>> {
        // block header contents must match
        if header.header.bitcoin_hash() != block.bitcoin_hash() {
            error!("Expected block {} does not match received block {}", header.header.bitcoin_hash(), block.bitcoin_hash());
            return None;
        }

        // block transactions must match header merkle root
        let tx_merkle_root = bitcoin_merkle_root(block.txdata
                                                 .iter()
                                                 .map(|ref tx| { tx.txid() })
                                                 .collect());

        if block.header.merkle_root != tx_merkle_root {
            error!("Expected block {} merkle root {}, got {}", block.bitcoin_hash(), block.header.merkle_root, tx_merkle_root);
            return None;
        }

        // parse it 
        let burn_block = self.parse_block(&block, height);
        Some(burn_block)
    }
}

#[cfg(test)]
mod tests {
    
    use super::BitcoinBlockParser;
    use util::hash::hex_bytes;

    use bitcoin::network::serialize::deserialize;
    use bitcoin::blockdata::transaction::Transaction;

    use burnchains::{
        BurnchainBlock, 
        BurnchainTxInput, 
        BurnchainTxOutput, 
        BurnchainTransaction, 
        AddressType, 
        Address, 
        PublicKey, 
        Txid, 
        MagicBytes, 
        Hash160, 
        MAGIC_BYTES_LENGTH
    };

    use burnchains::bitcoin::keys::BitcoinPublicKey;

    use util::log as logger;

    struct TxFixture<T> {
        txstr: String,
        result: T
    }

    fn make_tx(hex_str: &str) -> Result<Transaction, &'static str> {
        let tx_bin = hex_bytes(hex_str)?;
        let tx = deserialize(&tx_bin.to_vec())
            .map_err(|_e| "failed to deserialize")?;
        Ok(tx)
    }
    
    fn to_hash160(inp: &Vec<u8>) -> Hash160 {
        let mut ret = [0; 20];
        let bytes = &inp[..inp.len()];
        ret.copy_from_slice(bytes);
        Hash160(ret)
    }
    
    fn to_txid(inp: &Vec<u8>) -> Txid {
        let mut ret = [0; 32];
        let bytes = &inp[..inp.len()];
        ret.copy_from_slice(bytes);
        Txid(ret)
    }

    #[test]
    fn maybe_burnchain_tx_test() {
        logger::init();
        let tx_fixtures = vec![
            TxFixture {
                // valid
                txstr: "010000000320a081bcd1a80d9c1945f863d29dc84278411ed74cb6dcba30541bf8d5770542020000008b483045022100be57031bf2c095945ba2876e97b3f86ee051643a29b908f22ed45ccf58620103022061e056e5f48c5a51c66604a1ca28e4bfaabab1478424c9bbb396cc6afe5c222e0141040fadbbcea0ff3b05f03195b41cd991d7a0af8bd38559943aec99cbdaf0b22cc806b9a4f07579934774cc0c155e781d45c989f94336765e88a66d91cfb9f060b0feffffff20a081bcd1a80d9c1945f863d29dc84278411ed74cb6dcba30541bf8d5770542010000008b483045022100fd9c04b330810694cb4bfef793b193f9cbfaa07325700f217b9cb03e5207005302202f07e7c9c6774c5619a043752444f6da6fd81b9d9d008ec965796d87271598de0141040fadbbcea0ff3b05f03195b41cd991d7a0af8bd38559943aec99cbdaf0b22cc806b9a4f07579934774cc0c155e781d45c989f94336765e88a66d91cfb9f060b0feffffff20a081bcd1a80d9c1945f863d29dc84278411ed74cb6dcba30541bf8d5770542040000008a47304402205e24943a40b8ef876cc218a7e8994f4be7afb7aa02403bb73510fac01b33ead3022033e5fb811c396b2fb50a825cd1d86e82eb83483901a1793d0eb15e3e9f1d1c5b814104c77f262dda02580d65c9069a8a34c56bd77325bba4110b693b90216f5a3edc0bebc8ce28d61aa86b414aa91ecb29823b11aeed06098fcd97fee4bc73d54b1e96feffffff030000000000000000296a2769642bfae543ff5672fb607fe15e16b1c3ef38737c631c7c5d911c6617993c21fba731363f1cfe6c6b0000000000001976a914395f3643cea07ec4eec73b4d9a973dcce56b9bf188acc5120100000000001976a9149f2660e75380675206b6f1e2b4f106ae33266be488ac00000000".to_owned(),
                result: true
            },
            TxFixture {
                // invalid magic
                txstr: "0100000001d8b97932f097b9fbf0c7584f29515862911ac830826fdfd72d06402c21543e38000000006a47304402202801bc5d11eefddc586b1171bf607cc2be1c661d22e215153f2630316f973a200220628cc08858bba3f0cda661dbef2f007e48f8cb531edc0b54edb573226816f253012103d6967618e0159c9bfcd03ea33d368c8b2a98af5a054364c6b5e7215d7d809169ffffffff030000000000000000356a336469240efa29f955c6ae3bb5037039d89dba5e00000000000000000000000000535441434b5300000000000003e854455354217c150000000000001976a914cfd25e09f2d33e1aec73bfcc5b608ec513bbe6c088ac34460200000000001976a9144cb912533a6935880df7647fd5232e40aca07b8088ac00000000".to_owned(),
                result: false
            },
            TxFixture {
                // no OP_RETURN 
                txstr: "0200000003620f7bc1087b0111f76978ef747001e3ae0a12f254cbfb858f028f891c40e5f6010000006a47304402207f5dfc2f7f7329b7cc731df605c83aa6f48ec2218495324bb4ab43376f313b840220020c769655e4bfcc54e55104f6adc723867d9d819266d27e755e098f646f689d0121038c2d1cbe4d731c69e67d16c52682e01cb70b046ead63e90bf793f52f541dafbdfefffffff15fe7d9e0815853738ce47deadee69339e027a1dfcfb6fa887cce3a72626e7b010000006a47304402203202e6c640c063989623fc782ac1c9dc3c6fcaed996d852ec876749ba63db63b02207ef86e262ad4b4bc9cebfadb609f52c35b0105e15d58a5ecbecc5e536d3a8cd8012103dc526ca188418ab128d998bf80942d66f1b3be585d0c89bd61c533bddbdaa729feffffff84e6431db86833897bab333d844486c183dd01e69862edea442e480c2d8cb549010000006a47304402200320bc83f35ceab4a7ef0f8181eedb5f54e3f617626826cc49c8c86efc9be0b302203705889d6aed50f716b81b0f3f5769d72d1b8a6b59d1b0b73bcf94245c283b8001210263591c21ce8ee0d96a617108d7c278e2e715ac6d8afd3fcd158bee472c590068feffffff02ca780a00000000001976a914811fb695e46e2386501bcd70e5c869fe6c0bb33988ac10f59600000000001976a9140f2408a811f6d24ab1833924d98d884c44ecee8888ac6fce0700".to_owned(),
                result: false
            }
        ];

        let parser = BitcoinBlockParser::new(MagicBytes([105, 100]));   // "id"
        for tx_fixture in tx_fixtures {
            let tx = make_tx(&tx_fixture.txstr).unwrap();
            let res = parser.maybe_burnchain_tx(&tx);
            assert_eq!(res, tx_fixture.result);
        }
    }

    #[test]
    fn parse_tx_test() {
        logger::init();

        let vtxindex = 4;
        let tx_fixtures = vec![
            TxFixture {
                // NAME_UPDATE transaction with 3 singlesig inputs
                txstr: "010000000320a081bcd1a80d9c1945f863d29dc84278411ed74cb6dcba30541bf8d5770542020000008b483045022100be57031bf2c095945ba2876e97b3f86ee051643a29b908f22ed45ccf58620103022061e056e5f48c5a51c66604a1ca28e4bfaabab1478424c9bbb396cc6afe5c222e0141040fadbbcea0ff3b05f03195b41cd991d7a0af8bd38559943aec99cbdaf0b22cc806b9a4f07579934774cc0c155e781d45c989f94336765e88a66d91cfb9f060b0feffffff20a081bcd1a80d9c1945f863d29dc84278411ed74cb6dcba30541bf8d5770542010000008b483045022100fd9c04b330810694cb4bfef793b193f9cbfaa07325700f217b9cb03e5207005302202f07e7c9c6774c5619a043752444f6da6fd81b9d9d008ec965796d87271598de0141040fadbbcea0ff3b05f03195b41cd991d7a0af8bd38559943aec99cbdaf0b22cc806b9a4f07579934774cc0c155e781d45c989f94336765e88a66d91cfb9f060b0feffffff20a081bcd1a80d9c1945f863d29dc84278411ed74cb6dcba30541bf8d5770542040000008a47304402205e24943a40b8ef876cc218a7e8994f4be7afb7aa02403bb73510fac01b33ead3022033e5fb811c396b2fb50a825cd1d86e82eb83483901a1793d0eb15e3e9f1d1c5b814104c77f262dda02580d65c9069a8a34c56bd77325bba4110b693b90216f5a3edc0bebc8ce28d61aa86b414aa91ecb29823b11aeed06098fcd97fee4bc73d54b1e96feffffff030000000000000000296a2769642bfae543ff5672fb607fe15e16b1c3ef38737c631c7c5d911c6617993c21fba731363f1cfe6c6b0000000000001976a914395f3643cea07ec4eec73b4d9a973dcce56b9bf188acc5120100000000001976a9149f2660e75380675206b6f1e2b4f106ae33266be488ac00000000".to_owned(),
                result: BurnchainTransaction {
                    txid: to_txid(&hex_bytes("185c112401590b11acdfea6bb26d2a8e37cb31f24a0c89dbb8cc14b3d6271fb1").unwrap()),
                    vtxindex: vtxindex,
                    opcode: '+' as u8,
                    data: hex_bytes("fae543ff5672fb607fe15e16b1c3ef38737c631c7c5d911c6617993c21fba731363f1cfe").unwrap(),
                    inputs: vec![
                        BurnchainTxInput {
                            keys: vec![
                                BitcoinPublicKey::from_hex("040fadbbcea0ff3b05f03195b41cd991d7a0af8bd38559943aec99cbdaf0b22cc806b9a4f07579934774cc0c155e781d45c989f94336765e88a66d91cfb9f060b0").unwrap(),
                            ],
                            num_required: 1,
                        },
                        BurnchainTxInput {
                            keys: vec![
                                BitcoinPublicKey::from_hex("040fadbbcea0ff3b05f03195b41cd991d7a0af8bd38559943aec99cbdaf0b22cc806b9a4f07579934774cc0c155e781d45c989f94336765e88a66d91cfb9f060b0").unwrap(),
                            ],
                            num_required: 1,
                        },
                        BurnchainTxInput {
                            keys: vec![
                                BitcoinPublicKey::from_hex("04c77f262dda02580d65c9069a8a34c56bd77325bba4110b693b90216f5a3edc0bebc8ce28d61aa86b414aa91ecb29823b11aeed06098fcd97fee4bc73d54b1e96").unwrap(),
                            ],
                            num_required: 1
                        }
                    ],
                    outputs: vec![
                        BurnchainTxOutput {
                            units: 27500,
                            address: Address {
                                addrtype: AddressType::PublicKeyHash,
                                bytes: to_hash160(&hex_bytes("395f3643cea07ec4eec73b4d9a973dcce56b9bf1").unwrap()),
                            },
                        },
                        BurnchainTxOutput {
                            units: 70341,
                            address: Address {
                                addrtype: AddressType::PublicKeyHash,
                                bytes: to_hash160(&hex_bytes("9f2660e75380675206b6f1e2b4f106ae33266be4").unwrap()),
                            },
                        }
                    ]
                }
            },
            TxFixture {
                // NAME_REVOKE with 2 2-of-3 multisig inputs
                txstr: "0100000002b4c2c2fede361654f0f6b65dd8ba385f3a4b05c76cd573f3689b09b7298b142201000000fd5c010047304402203537b5ded3716553b6f3fc7ccc7e55bc42b6caa1c069c9b2ce068d57f9024de7022026eb81e226b0de30448732835424eef52a3b9d67020c62b48df75974c5fe09870147304402201cc22e43302688d975df3bcad70065c8dad497b092a58e97c6c306b65176c70802200b9c3a62b22865e957331578d6e5d684cad87279fd8b852fcc2d34d3911e8643014cc9524104ff897d48c25c48c598aea0d6b1e835008e6679bddbc8d41d7d9f73e6a0dc2b8fe1402487ce2ba1e5365ee28fed024093499c11b8485fb6758a357c75730557674104f9478048ce8ff9cfc188a184c8c8c0a3e3dee68f96f6c3bc6f0f7e043ca8d241d5a03ab50157422ad43e9ee1a0a80b0dd17f0b0023f891dbd85daa3069554e2b41046fd8c7330fbe307a0fad0bf9472ca080f4941f4b6edea7ab090e3e26075e7277a0bd61f42eff54daf3e6141de46a98a5a8265c9e8d58bd1a86cf36d418788ab853aeffffffffb4c2c2fede361654f0f6b65dd8ba385f3a4b05c76cd573f3689b09b7298b142202000000fd5d0100473044022070cfd1e13d9844db995111ed5cc0578ca4d03504fdec1cf1636cd0054dffeeed022046c8d87291367402f4b54c2ef985a0171e400fe079da5234c912103cf2dd683b0148304502210099f092b12000dc78074934135443656091c606b40c7925bae30a6285946e36b9022062b5fa5e28986e0c27aad11f8fdb1409eb87a169972dc1ebbd91aa45810f9d9a014cc95241046097f22211c1f4832e54f0cc76c06b80a4e1fcf237ea487561c80bd5b28b6a483706a04d99038cb434eee82306902193e7b1a368dba33ad14b3f30e004c95e6e41048e264f76559020fdf50d3a7d9f57ccd548f3dfb962837f958e446add48429951d61e99a109cded2ba9812ee152ebba53a2a6c7b6dfb3c61fcba1b0852928374941044c9f30b4546c1f30087001fa6450e52c645bd49e91a18c9c16965b72f5153f0e4b04712218b42b2bc578017b471beaa7d8c0a9eb69174ad50714d7ef4117863d53aeffffffff030000000000000000176a1569647e7061747269636b7374616e6c6579322e6964f82a00000000000017a914eb1881fb0682c2eb37e478bf918525a2c61bc404876dbd13000000000017a914c26afc6cb80ca477c280780902b40cbef8cd804d8700000000".to_owned(),
                result: BurnchainTransaction {
                    txid: to_txid(&hex_bytes("eb2e84a45cf411e528185a98cd5fb45ed349843a83d39fd4dff2de47adad8c8f").unwrap()),
                    vtxindex: vtxindex,
                    opcode: '~' as u8,
                    data: hex_bytes("7061747269636b7374616e6c6579322e6964").unwrap(),
                    inputs: vec![
                        BurnchainTxInput {
                            keys: vec![
                                BitcoinPublicKey::from_hex("04ff897d48c25c48c598aea0d6b1e835008e6679bddbc8d41d7d9f73e6a0dc2b8fe1402487ce2ba1e5365ee28fed024093499c11b8485fb6758a357c7573055767").unwrap(),
                                BitcoinPublicKey::from_hex("04f9478048ce8ff9cfc188a184c8c8c0a3e3dee68f96f6c3bc6f0f7e043ca8d241d5a03ab50157422ad43e9ee1a0a80b0dd17f0b0023f891dbd85daa3069554e2b").unwrap(),
                                BitcoinPublicKey::from_hex("046fd8c7330fbe307a0fad0bf9472ca080f4941f4b6edea7ab090e3e26075e7277a0bd61f42eff54daf3e6141de46a98a5a8265c9e8d58bd1a86cf36d418788ab8").unwrap(),
                            ],
                            num_required: 2,
                        },
                        BurnchainTxInput {
                            keys: vec![
                                BitcoinPublicKey::from_hex("046097f22211c1f4832e54f0cc76c06b80a4e1fcf237ea487561c80bd5b28b6a483706a04d99038cb434eee82306902193e7b1a368dba33ad14b3f30e004c95e6e").unwrap(),
                                BitcoinPublicKey::from_hex("048e264f76559020fdf50d3a7d9f57ccd548f3dfb962837f958e446add48429951d61e99a109cded2ba9812ee152ebba53a2a6c7b6dfb3c61fcba1b08529283749").unwrap(),
                                BitcoinPublicKey::from_hex("044c9f30b4546c1f30087001fa6450e52c645bd49e91a18c9c16965b72f5153f0e4b04712218b42b2bc578017b471beaa7d8c0a9eb69174ad50714d7ef4117863d").unwrap(),
                            ],
                            num_required: 2,
                        },
                    ],
                    outputs: vec![
                        BurnchainTxOutput {
                            units: 11000,
                            address: Address {
                                addrtype: AddressType::ScriptHash,
                                bytes: to_hash160(&hex_bytes("eb1881fb0682c2eb37e478bf918525a2c61bc404").unwrap()),
                            },
                        },
                        BurnchainTxOutput {
                            units: 1293677,
                            address: Address {
                                addrtype: AddressType::ScriptHash,
                                bytes: to_hash160(&hex_bytes("c26afc6cb80ca477c280780902b40cbef8cd804d").unwrap()),
                            }
                        }
                    ]
                }
            },
            TxFixture {
                // NAME_REGISTRATION with p2wpkh-p2sh segwit input
                txstr: "01000000000101a7ef2b09722ad786c569c0812005a731ce19290bb0a2afc16cb91056c2e4c19e0100000017160014393ffec4f09b38895b8502377693f23c6ae00f19ffffffff0300000000000000000d6a0b69643a666f6f2e746573747c1500000000000017a9144b85301ba8e42bf98472b8ed4939d5f76b98fcea87144d9c290100000017a91431f8968eb1730c83fb58409a9a560a0a0835027f8702483045022100fc82815edf1c0ef0c601cf1e26494626d7b01597be5ab83df025ff1ee67730130220016c4c29d77aadb5ff57c0c9272a43950ca29b84d8adfaed95ac69db90b35d5b012102d341f728783eb93e6fb5921a1ebe9d149e941de31e403cd69afa2f0f1e698e8100000000".to_owned(),
                result: BurnchainTransaction {
                    txid: to_txid(&hex_bytes("b908952b30ccfdfa59985dc1ffdd2a22ef054d20fa253510d2af7797dddee459").unwrap()),
                    vtxindex: vtxindex,
                    opcode: ':' as u8,
                    data: hex_bytes("666f6f2e74657374").unwrap(),
                    inputs: vec![
                        BurnchainTxInput {
                            keys: vec![
                                BitcoinPublicKey::from_hex("02d341f728783eb93e6fb5921a1ebe9d149e941de31e403cd69afa2f0f1e698e81").unwrap()
                            ],
                            num_required: 1,
                        }
                    ],
                    outputs: vec![
                        BurnchainTxOutput {
                            units: 5500,
                            address: Address {
                                addrtype: AddressType::ScriptHash,
                                bytes: to_hash160(&hex_bytes("4b85301ba8e42bf98472b8ed4939d5f76b98fcea").unwrap()),
                            }
                        },
                        BurnchainTxOutput {
                            units: 4993076500,
                            address: Address {
                                addrtype: AddressType::ScriptHash,
                                bytes: to_hash160(&hex_bytes("31f8968eb1730c83fb58409a9a560a0a0835027f").unwrap()),
                            }
                        }
                    ]
                }
            },
            TxFixture {
                // NAME_PREORDER with a 2-of-3 p2wsh-p2sh multisig segwit input 
                txstr: "01000000000101e411dc967b8503a27450c614a5cd984698762a6b4bf547293ffdf846ed4ebd22010000002322002067091a41e9871c5ae20b0c69a786f02df5d3c7aa632689b608069181b43a28a2ffffffff030000000000000000296a2769643f9fab7f294936ddb6524a48feff691ecbd0ca9e8f107d845c417a5438d1cb441e827c5126b01ba0290100000017a91487a0487869af70b6b1cc79bd374b75ba1be5cff98700a86100000000001976a914000000000000000000000000000000000000000088ac0400473044022064c5b5f61baad8bb8ecad98666b99e09f1777ef805df41a1c7926f8468b6b6df02205eac177c77f274acb670cd24d504f01b27de767e0241c818c91e479cb0ddcf18014730440220053ce777bc7bb842d8eef83769a027797567624ab9eed5722889ed3192f431b30220256e8aaef8de2a571198acde708fcbca02fb18780ac470c0d7f811734af729af0169522102d341f728783eb93e6fb5921a1ebe9d149e941de31e403cd69afa2f0f1e698e812102f21b29694df4c2188bee97103d10d017d1865fb40528f25589af9db6e0786b6521028791dc45c049107fb99e673265a38a096536aacdf78aa90710a32fff7750f9f953ae00000000".to_owned(),
                result: BurnchainTransaction {
                    txid: to_txid(&hex_bytes("16751ca54407b922e3072830cf4be58c5562a6dc350f6703192b673c4cc86182").unwrap()),
                    vtxindex: vtxindex,
                    opcode: '?' as u8,
                    data: hex_bytes("9fab7f294936ddb6524a48feff691ecbd0ca9e8f107d845c417a5438d1cb441e827c5126").unwrap(),
                    inputs: vec![
                        BurnchainTxInput {
                            keys: vec![
                                BitcoinPublicKey::from_hex("02d341f728783eb93e6fb5921a1ebe9d149e941de31e403cd69afa2f0f1e698e81").unwrap(),
                                BitcoinPublicKey::from_hex("02f21b29694df4c2188bee97103d10d017d1865fb40528f25589af9db6e0786b65").unwrap(),
                                BitcoinPublicKey::from_hex("028791dc45c049107fb99e673265a38a096536aacdf78aa90710a32fff7750f9f9").unwrap()
                            ],
                            num_required: 2,
                        }
                    ],
                    outputs: vec![
                        BurnchainTxOutput {
                            units: 4993326000,
                            address: Address {
                                addrtype: AddressType::ScriptHash,
                                bytes: to_hash160(&hex_bytes("87a0487869af70b6b1cc79bd374b75ba1be5cff9").unwrap()),
                            },
                        },
                        BurnchainTxOutput {
                            units: 6400000,
                            address: Address {
                                addrtype: AddressType::PublicKeyHash,
                                bytes: to_hash160(&hex_bytes("0000000000000000000000000000000000000000").unwrap())
                            },
                        },
                    ]
                }
            }
        ];

        let parser = BitcoinBlockParser::new(MagicBytes([105, 100]));   // "id"
        for tx_fixture in tx_fixtures {
            let tx = make_tx(&tx_fixture.txstr).unwrap();
            let burnchain_tx = parser.parse_tx(&tx, vtxindex as usize);
            assert!(burnchain_tx.is_some());
            assert_eq!(burnchain_tx.unwrap(), tx_fixture.result);
        }
    }

    /*
    #[test]
    fn parse_tx_strange() {
        let tx_fixtures_strange : Vec<TxFixture<Option<BurnchainTransaction>>> = {
            TxFixture {
                // NAMESPACE_REVEAL with a segwit p2wph script pubkey
                txstr: "0100000001fde2146ec3ecf037ad515c0c1e2ba8abee348bd2b3c6a576bf909d78b0b18cd2010000006a47304402203ec06f11bc5b7e79fad54b2d69a375ba78576a2a0293f531a082fcfe13a9e9e802201afcf0038d9ccb9c88113248faaf812321b65d7b09b4a6e2f04f463d2741101e012103d6fd1ba0effaf1e8d94ea7b7a3d0ef26fea00a14ce5ffcc1495fe588a2c6d0f3ffffffff0300000000000000001a6a186964260000cd73fa046543210000000000aa0001746573747c1500000000000016001482093b62a3699282d926981bed7665e8384caa552076fd29010000001976a91474178497e927ff3ff1428a241be454d393c3c91c88ac00000000".to_owned(),
                result: None
            },
        };
    }
    */
}

