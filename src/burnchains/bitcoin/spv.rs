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
use std::io::{Read, Seek, Write, SeekFrom};

use bitcoin::blockdata::block::{LoneBlockHeader, BlockHeader};
use bitcoin::network::encodable::{ConsensusEncodable, ConsensusDecodable, VarInt};
use bitcoin::network::serialize::{RawEncoder, RawDecoder, serialize, deserialize, BitcoinHash};
use bitcoin::network::message as btc_message;

use bitcoin::util::hash::Sha256dHash;
use bitcoin::util::uint::Uint256;

use burnchains::bitcoin::indexer::{BitcoinIndexer, BITCOIN_MAINNET, BITCOIN_TESTNET, BITCOIN_REGTEST};
use burnchains::bitcoin::Error as btc_error;
use burnchains::bitcoin::messages::BitcoinMessageHandler;

const BLOCK_HEADER_SIZE: u64 = 81;

const GENESIS_BLOCK_HASH_MAINNET: &'static str = "000000000019d6689c085ae165831e934ff763ae46a2a6c172b3f1b60a8ce26f";
const GENESIS_BLOCK_MERKLE_ROOT_MAINNET: &'static str = "4a5e1e4baab89f3a32518a88c31bc87f618f76673e2cc77ab2127b7afdeda33b";

const GENESIS_BLOCK_HASH_TESTNET: &'static str = "0f9188f13cb7b2c71f2a335e3a4fc328bf5beb436012afca590b1a11466e2206";
const GENESIS_BLOCK_MERKLE_ROOT_TESTNET: &'static str = "4a5e1e4baab89f3a32518a88c31bc87f618f76673e2cc77ab2127b7afdeda33b";

const BLOCK_DIFFICULTY_CHUNK_SIZE: u64 = 2016;
const BLOCK_DIFFICULTY_INTERVAL: u32 = 14 * 24 * 60 * 60;   // two weeks, in seconds


pub struct SpvClient {
    headers_path: String,
    start_block_height: u64,
    end_block_height: u64,
    cur_block_height: u64,
    network_id: u32,
}

impl SpvClient {
    pub fn new(headers_path: &str, start_block: u64, end_block: u64, network_id: u32) -> SpvClient {
        SpvClient {
            headers_path: headers_path.to_owned(),
            start_block_height: start_block,
            end_block_height: end_block,
            cur_block_height: start_block,
            network_id: network_id
        }
    }

    // go get all the headers.
    // keep trying forever.
    pub fn run(&mut self, indexer: &mut BitcoinIndexer) -> Result<(), btc_error> {
        let network_id = self.network_id;

        if !fs::metadata(&self.headers_path).is_ok() {
            match SpvClient::init_block_headers(&self.headers_path, network_id) {
                Ok(()) => {},
                Err(e) => {
                    debug!("Failed to initialize block headers file: {:?}", e);
                    return Err(e);
                }
            }
        }

        return indexer.peer_communicate(self);
    }

    /// Validate a headers message we requested
    /// * must have at least one header
    /// * headers must be contiguous 
    fn validate_header_integrity(headers: &Vec<LoneBlockHeader>) -> Result<(), btc_error> {
        if headers.len() == 0 {
            return Err(btc_error::InvalidReply);
        }

        for i in 0..headers.len() {
            if headers[i].tx_count != VarInt(0) {
                return Err(btc_error::InvalidReply);
            }
        }

        for i in 1..headers.len() {
            let prev_header = &headers[i-1];
            let cur_header = &headers[i];

            if cur_header.header.prev_blockhash != prev_header.header.bitcoin_hash() {
                debug!("cur_header {} != prev_header {}", cur_header.header.prev_blockhash, prev_header.header.bitcoin_hash());
                return Err(btc_error::NoncontiguousHeader);
            }
        }

        return Ok(());
    }

    /// Verify that the given headers have the correct amount of work to be appended to our
    /// local header chain.  Checks the difficulty between [interval, interval+1]
    fn validate_header_work(headers_path: &str, interval_start: u64, interval_end: u64) -> Result<(), btc_error> {
        assert!(interval_start <= interval_end);
        if interval_start == 0 {
            return Ok(());
        }

        for i in interval_start..interval_end {
            let target_opt = SpvClient::get_target(headers_path, i)?;
            if target_opt.is_none() {
                // out of headers 
                return Ok(());
            }

            let (bits, difficulty) = target_opt.unwrap();
            for block_height in (i * BLOCK_DIFFICULTY_CHUNK_SIZE)..((i + 1) * BLOCK_DIFFICULTY_CHUNK_SIZE) {
                let header_opt = SpvClient::read_block_header(headers_path, block_height)?;
                match header_opt {
                    None => {
                        // out of headers
                        return Ok(());
                    }
                    Some(header_i) => {
                        if header_i.header.bits != bits {
                            error!("bits mismatch at block {}: {} != {}", block_height, header_i.header.bits, bits);
                            return Err(btc_error::InvalidPoW);
                        }
                        let header_hash = header_i.header.bitcoin_hash().into_le();
                        if difficulty < header_hash {
                            error!("block {} hash {} has less work than difficulty {}", block_height, header_i.header.bitcoin_hash(), difficulty);
                            return Err(btc_error::InvalidPoW);
                        }
                    }
                };
            }
        }
        return Ok(());
    }


    /// Report how many block headers we have downloaded to the given path.
    /// Returns Err(btc_error) if the file does not exist
    pub fn get_headers_height(headers_path: &str) -> Result<u64, btc_error> {
        let metadata = fs::metadata(headers_path)
            .map_err(btc_error::FilesystemError)?;
        
        let file_size = metadata.len();
        return Ok((file_size / BLOCK_HEADER_SIZE) - 1);
    }

    /// Read the block header at a particular height 
    /// Returns None if the requested block height is beyond the end of the headers file
    pub fn read_block_header(headers_path: &str, block_height: u64) -> Result<Option<LoneBlockHeader>, btc_error> {
        let headers_height = SpvClient::get_headers_height(headers_path)?;
        if headers_height < block_height {
            return Ok(None);
        }

        let mut headers_file = fs::File::open(headers_path)
                                 .map_err(btc_error::FilesystemError)?;

        headers_file.seek(SeekFrom::Start(BLOCK_HEADER_SIZE * block_height))
                            .map_err(btc_error::FilesystemError)?;

        let mut serialized_header = [0; 81];
        headers_file.read(&mut serialized_header)
                            .map_err(btc_error::FilesystemError)?;

        let header : LoneBlockHeader = deserialize(&serialized_header)
                            .map_err(btc_error::SerializationError)?;

        return Ok(Some(header));
    }

    /// Initialize the block headers file with the genesis block hash 
    fn init_block_headers(headers_path: &str, network_id: u32) -> Result<(), btc_error> {
        let genesis_merkle_root_str = match network_id {
            BITCOIN_MAINNET => GENESIS_BLOCK_MERKLE_ROOT_MAINNET,
            BITCOIN_TESTNET => GENESIS_BLOCK_MERKLE_ROOT_TESTNET,
            BITCOIN_REGTEST => GENESIS_BLOCK_MERKLE_ROOT_TESTNET,
            _ => panic!("Unrecognized network magic")
        };

        let genesis_block_hash_str = match network_id {
            BITCOIN_MAINNET => GENESIS_BLOCK_HASH_MAINNET,
            BITCOIN_TESTNET => GENESIS_BLOCK_HASH_TESTNET,
            BITCOIN_REGTEST => GENESIS_BLOCK_HASH_TESTNET,
            _ => panic!("Unrecognized network magic")
        };

        let genesis_prev_blockhash = Sha256dHash::from_hex("0000000000000000000000000000000000000000000000000000000000000000")
                .map_err(btc_error::HashError)?;

        let genesis_merkle_root = Sha256dHash::from_hex(genesis_merkle_root_str)
                .map_err(btc_error::HashError)?;

        let genesis_block_hash = Sha256dHash::from_hex(genesis_block_hash_str)
                .map_err(btc_error::HashError)?;

        let genesis_header = LoneBlockHeader {
            header: BlockHeader {
                version: 1,
                prev_blockhash: genesis_prev_blockhash,
                merkle_root: genesis_merkle_root,
                time: 1231006505,
                bits: 0x1d00ffff,
                nonce: 2083236893
            },
            tx_count: VarInt(0)
        };

        assert_eq!(genesis_header.header.bitcoin_hash(), genesis_block_hash);

        let genesis_header_vec = serialize(&genesis_header)
                .map_err(btc_error::SerializationError)?;

        let mut headers_file = fs::OpenOptions::new()
                                .read(true)
                                .write(true)
                                .create(true)
                                .open(headers_path)
                                .map_err(btc_error::FilesystemError)?;

        headers_file.write(genesis_header_vec.as_slice())
                .map_err(btc_error::FilesystemError)?;

        headers_file.flush()
                .map_err(btc_error::FilesystemError)?;

        debug!("Initialized block headers at {}", headers_path);
        return Ok(());
    }

    /// Handle a Headers message
    /// -- validate them
    /// -- store them
    fn handle_headers(&mut self, block_headers: &Vec<LoneBlockHeader>) -> Result<(), btc_error> {
        let valid_check = SpvClient::validate_header_integrity(block_headers);
        if valid_check.is_err() {
            error!("Received invalid headers");
            return valid_check;
        }

        self.append_block_headers(block_headers)?;

        // check work 
        let chain_tip = SpvClient::get_headers_height(&self.headers_path)?;
        let work_check = SpvClient::validate_header_work(&self.headers_path, (chain_tip - 1) / BLOCK_DIFFICULTY_CHUNK_SIZE, chain_tip / BLOCK_DIFFICULTY_CHUNK_SIZE + 1);
        if work_check.is_err() {
            error!("Received headers with bad target or difficulty");
            return work_check;
        }

        debug!("Handle {} Headers: {}-{}", block_headers.len(), block_headers[0].header.bitcoin_hash(), block_headers[block_headers.len()-1].header.bitcoin_hash());
        return Ok(()); 
    }

    /// Append block headers to our headers file
    fn append_block_headers(&mut self, headers: &Vec<LoneBlockHeader>) -> Result<(), btc_error> {
        let headers_path = self.headers_path.clone();
        let network_id = self.network_id;

        if !fs::metadata(&headers_path).is_ok() {
            // damn borrow checker
            let headers_path = self.headers_path.clone();
            SpvClient::init_block_headers(&headers_path, network_id)?;
        }

        let height = SpvClient::get_headers_height(&headers_path)?;
        let last_header_opt = SpvClient::read_block_header(&headers_path, height)?;
        assert!(last_header_opt.is_some());
        
        let last_header = last_header_opt.unwrap();

        // contiguous?
        if headers[0].header.prev_blockhash != last_header.header.bitcoin_hash() {
            debug!("headers[0]: {:?}", headers[0]);
            debug!("last_header at {}: {:?}", height, last_header);
            debug!("headers[0] {} != last_header {}", headers[0].header.prev_blockhash, last_header.header.bitcoin_hash());
            return Err(btc_error::NoncontiguousHeader);
        }

        // store them 
        let mut headers_file = fs::OpenOptions::new()
                                .write(true)
                                .open(headers_path)
                                .map_err(btc_error::FilesystemError)?;

        for i in 0..headers.len() {
            let offset = BLOCK_HEADER_SIZE * (height + 1 + (i as u64));
            headers_file.seek(SeekFrom::Start(offset))
                    .map_err(btc_error::FilesystemError)?;

            let header_vec = serialize(&headers[i])
                    .map_err(btc_error::SerializationError)?;

            headers_file.write(header_vec.as_slice())
                    .map_err(btc_error::FilesystemError)?;
        }

        headers_file.flush()
                .map_err(btc_error::FilesystemError)?;

        return Ok(());
    }

    /// Determine the target difficult over a given difficulty adjustment interval
    /// the `interval` parameter is the difficulty interval -- a 2016-block interval.
    /// Returns (new bits, new target)
    pub fn get_target(headers_path: &str, interval: u64) -> Result<Option<(u32, Uint256)>, btc_error> {
        let max_target = Uint256([0x0000000000000000, 0x0000000000000000, 0x0000000000000000, 0x00000000FFFF0000]);
        if interval == 0 {
            panic!("Invalid argument: interval must be positive (got {})", interval);
        }

        let first_header_opt = SpvClient::read_block_header(headers_path, (interval - 1) * BLOCK_DIFFICULTY_CHUNK_SIZE)?;
        let last_header_opt = SpvClient::read_block_header(headers_path, interval * BLOCK_DIFFICULTY_CHUNK_SIZE - 1)?;

        if first_header_opt.is_none() {
            // haven't got here yet
            return Ok(None);
        }

        let first_header = first_header_opt.unwrap();

        if last_header_opt.is_none() {
            // whatever the current header is 
            return Ok(None);
        }

        let last_header = last_header_opt.unwrap();

        // find actual timespan as being clamped between +/- 4x of the target timespan
        let measured_timespan = last_header.header.time - first_header.header.time;
        let target_timespan = BLOCK_DIFFICULTY_INTERVAL;
        let timespan_highpass = cmp::max(measured_timespan, target_timespan / 4);
        let filtered_timespan = cmp::min(timespan_highpass, target_timespan * 4);

        let last_target = last_header.header.target();
        let new_target = cmp::min(max_target, (last_target.mul_u32(filtered_timespan)) / (Uint256::from_u64(target_timespan as u64).unwrap()));
        let new_bits = BlockHeader::compact_target_from_u256(&new_target);

        return Ok(Some((new_bits, new_target)));
    }

    /// Ask for the next batch of headers
    pub fn send_next_getheaders(&mut self, indexer: &mut BitcoinIndexer, block_height: u64) -> Result<(), btc_error> {
        // ask for the next batch
        let lone_block_header = SpvClient::read_block_header(&self.headers_path, block_height)?;

        match lone_block_header {
            Some(hdr) => {
                indexer.send_getheaders(hdr.header.bitcoin_hash())
            }
            None => {
                Err(btc_error::MissingHeader)
            }
        }
    }
}

impl BitcoinMessageHandler for SpvClient {

    /// Trait message handler 
    /// initiate the conversation with the bitcoin peer
    fn begin_session(&mut self, indexer: &mut BitcoinIndexer) -> Result<bool, btc_error> {
        let start_height = self.start_block_height;
        self.send_next_getheaders(indexer, start_height).and_then(|_r| Ok(true))
    }

    /// Trait message handler
    /// Take headers, validate them, and ask for more
    fn handle_message(&mut self, indexer: &mut BitcoinIndexer, msg: &btc_message::NetworkMessage) -> Result<bool, btc_error> {
        match *msg {
            btc_message::NetworkMessage::Headers(ref block_headers) => {

                if self.cur_block_height >= self.end_block_height {
                    // done 
                    return Ok(false);
                }

                // only handle headers we asked for 
                let header_range = 
                    if self.end_block_height - self.cur_block_height < block_headers.len() as u64 {
                        block_headers.len() as u64 - (self.end_block_height - self.cur_block_height)
                    }
                    else {
                        block_headers.len() as u64
                    };
                
                let acceptable_headers = &block_headers[0..header_range as usize].to_vec();

                let handle_res = self.handle_headers(acceptable_headers)?;
                self.cur_block_height += acceptable_headers.len() as u64;

                // ask for the next batch
                let block_height = SpvClient::get_headers_height(&self.headers_path)?;

                debug!("Request headers for blocks {} - {}", block_height, block_height + 2000);
                let res = self.send_next_getheaders(indexer, block_height);
                match res {
                    Ok(()) => Ok(true),
                    Err(e) => {
                        panic!(format!("BUG: could not read block header at {} that we just stored", block_height));
                    }
                }
            }
            _ => {
                return Err(btc_error::UnhandledMessage);
            }
        }
    }
}
