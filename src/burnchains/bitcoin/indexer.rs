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
use std::path;
use std::net;
use std::ops::Deref;
use std::ops::DerefMut;
use std::sync::{Arc, Mutex, LockResult, MutexGuard};
use rand::{Rng, thread_rng};
use std::path::{PathBuf};

use ini::Ini;

use burnchains::Burnchain;
use burnchains::indexer::*;
use burnchains::bitcoin::spv::*;
use burnchains::bitcoin::rpc::BitcoinRPC;
use burnchains::bitcoin::Error as btc_error;
use burnchains::bitcoin::messages::BitcoinMessageHandler;
use burnchains::bitcoin::blocks::BitcoinHeaderIPC;
use burnchains::indexer::BurnchainIndexer;

use burnchains::bitcoin::BitcoinNetworkType;
use burnchains::bitcoin::blocks::{BitcoinBlockDownloader, BitcoinBlockParser};

use burnchains::BLOCKSTACK_MAGIC_MAINNET;
use burnchains::BurnchainHeaderHash;
use burnchains::Error as burnchain_error;
use burnchains::MagicBytes;

use bitcoin::blockdata::block::LoneBlockHeader;
use bitcoin::network::message::NetworkMessage;
use bitcoin::network::serialize::BitcoinHash;

use util::log;

use dirs;

pub type BitcoinIndexerPublicKey = <<BitcoinIndexer as BurnchainIndexer>::P as BurnchainBlockParser>::K;
pub type BitcoinIndexerAddress = <<BitcoinIndexer as BurnchainIndexer>::P as BurnchainBlockParser>::A;

pub const USER_AGENT: &'static str = "Blockstack Core v21";

pub const BITCOIN_MAINNET: u32 = 0xD9B4BEF9;
pub const BITCOIN_TESTNET: u32 = 0x0709110B;
pub const BITCOIN_REGTEST: u32 = 0xDAB5BFFA;

pub const BITCOIN_MAINNET_NAME: &'static str = "mainnet";
pub const BITCOIN_TESTNET_NAME: &'static str = "testnet";
pub const BITCOIN_REGTEST_NAME: &'static str = "regtest";

// maybe change this
pub const FIRST_BLOCK_MAINNET: u64 = 373601;
pub const FIRST_BLOCK_TESTNET: u64 = 0;
pub const FIRST_BLOCK_REGTEST: u64 = 0;

// batch size for searching for a reorg 
const REORG_BATCH_SIZE: u64 = 2000;

pub fn network_id_to_bytes(network_id: BitcoinNetworkType) -> u32 {
    match network_id {
        BitcoinNetworkType::Mainnet => BITCOIN_MAINNET,
        BitcoinNetworkType::Testnet => BITCOIN_TESTNET,
        BitcoinNetworkType::Regtest => BITCOIN_REGTEST,
    }
}

#[derive(Debug, Clone, PartialEq)]
pub struct BitcoinIndexerConfig {
    // config fields
    pub peer_host: String,
    pub peer_port: u16,
    pub rpc_port: u16,
    pub rpc_ssl: bool,
    pub username: Option<String>,
    pub password: Option<String>,
    pub timeout: u32,
    pub spv_headers_path: String,
    pub first_block: u64,
    pub magic_bytes: MagicBytes
}

#[derive(Debug, Clone)]
pub struct BitcoinIndexerRuntime {
    sock: Arc<Mutex<Option<net::TcpStream>>>,
    pub services: u64,
    pub user_agent: String,
    pub version_nonce: u64,
    pub network_id: BitcoinNetworkType
}

pub struct BitcoinIndexer {
    pub config: BitcoinIndexerConfig,
    pub runtime: BitcoinIndexerRuntime
}


impl BitcoinIndexerConfig {
    pub fn default() -> BitcoinIndexerConfig {
        BitcoinIndexerConfig {
            peer_host: "bitcoin.blockstack.com".to_string(),
            peer_port: 8333,
            rpc_port: 8332,
            rpc_ssl: false,
            username: Some("blockstack".to_string()),
            password: Some("blockstacksystem".to_string()),
            timeout: 30,
            spv_headers_path: "./spv-headers.dat".to_string(),
            first_block: FIRST_BLOCK_MAINNET,
            magic_bytes: BLOCKSTACK_MAGIC_MAINNET.clone()
        }
    }

    pub fn to_file(&self, path: &String) -> Result<(), btc_error> {
       let mut conf = Ini::new();

       let username = self.username.clone().unwrap_or("".to_string());
       let password = self.password.clone().unwrap_or("".to_string());

       conf.with_section(Some("bitcoin".to_owned()))
           .set("server", self.peer_host.as_str())
           .set("p2p_port", format!("{}", self.peer_port).as_str())
           .set("rpc_port", format!("{}", self.rpc_port).as_str())
           .set("rpc_ssl", format!("{}", self.rpc_ssl).as_str())
           .set("username", username.as_str())
           .set("password", password.as_str())
           .set("timeout", format!("{}", self.timeout).as_str())
           .set("spv_path", self.spv_headers_path.as_str())
           .set("first_block", format!("{}", self.first_block).as_str());

       conf.with_section(Some("blockstack".to_owned()))
           .set("network_id", format!("{}{}", self.magic_bytes.as_bytes()[0] as char, self.magic_bytes.as_bytes()[1] as char).as_str());

       conf.write_to_file(&path)
           .map_err(|e| btc_error::Io(e))
    }

    pub fn from_file(path: &String) -> Result<BitcoinIndexerConfig, btc_error> {
       let conf_path = PathBuf::from(path);
       if !conf_path.is_file() {
           return Err(btc_error::ConfigError("Failed to load BitcoinIndexerConfig file: No such file or directory".to_string()));
       }

       let mut home_pathbuf = PathBuf::from(dirs::home_dir().unwrap());
       home_pathbuf.push(".stacks");

       let default_config = BitcoinIndexerConfig::default();

       match Ini::load_from_file(path) {
           Ok(ini_file) => {
               // got data!
               let bitcoin_section_opt = ini_file.section(Some("bitcoin").to_owned());
               if None == bitcoin_section_opt {
                   return Err(btc_error::ConfigError("No [bitcoin] section in config file".to_string()));
               }

               let bitcoin_section = bitcoin_section_opt.unwrap();

               // [bitcoin]
               let peer_host = bitcoin_section.get("server")
                                              .unwrap_or(&default_config.peer_host);

               let peer_port = bitcoin_section.get("p2p_port")
                                              .unwrap_or(&format!("{}", default_config.peer_port))
                                              .trim().parse().map_err(|_e| btc_error::ConfigError("Invalid bitcoin:p2p_port value".to_string()))?;

               if peer_port <= 1024 || peer_port >= 65535 {
                   return Err(btc_error::ConfigError("Invalid p2p_port".to_string()));
               }

               let rpc_port = bitcoin_section.get("rpc_port")
                                             .unwrap_or(&format!("{}", default_config.rpc_port))
                                             .trim().parse().map_err(|_e| btc_error::ConfigError("Invalid bitcoin:port value".to_string()))?;

               if rpc_port <= 1024 || rpc_port >= 65535 {
                   return Err(btc_error::ConfigError("Invalid rpc_port".to_string()));
               }

               let username = bitcoin_section.get("username").and_then(|s| Some(s.clone()));
               let password = bitcoin_section.get("password").and_then(|s| Some(s.clone()));

               let timeout = bitcoin_section.get("timeout")
                                            .unwrap_or(&format!("{}", default_config.timeout))
                                            .trim().parse().map_err(|_e| btc_error::ConfigError("Invalid bitcoin:timeout value".to_string()))?;

               let spv_headers_path_cfg = bitcoin_section.get("spv_path")
                                            .unwrap_or(&default_config.spv_headers_path);

               let spv_headers_path = 
                   if path::is_separator(spv_headers_path_cfg.chars().next().unwrap()) {
                       // absolute
                       (*spv_headers_path_cfg).clone()
                   }
                   else {
                       // relative to config file 
                       let mut p = PathBuf::from(path);
                       p.pop();
                       let s = p.join(&spv_headers_path_cfg);
                       s.to_str().unwrap().to_string()
                   };
                   

               let first_block = bitcoin_section.get("first_block")
                                                .unwrap_or(&format!("{}", FIRST_BLOCK_MAINNET))
                                                .trim().parse().map_err(|_e| btc_error::ConfigError("Invalid bitcoin:first_block value".to_string()))?;

               let rpc_ssl_str = bitcoin_section.get("ssl")
                                                .unwrap_or(&format!("{}", default_config.rpc_ssl))
                                                .clone();
               
               let rpc_ssl = rpc_ssl_str == "1" || rpc_ssl_str == "true";

               // [blockstack]
               let blockstack_section_opt = ini_file.section(Some("blockstack").to_owned());
               if None == blockstack_section_opt {
                   return Err(btc_error::ConfigError("No [blockstack] section in config file".to_string()));
               }

               let blockstack_section = blockstack_section_opt.unwrap();

               let blockstack_magic_str = blockstack_section.get("network_id")
                                                            .unwrap_or(&"id".to_string())
                                                            .clone();

               if blockstack_magic_str.len() != 2 {
                   return Err(btc_error::ConfigError("Invalid blockstack:network_id value: must be two bytes".to_string()));
               }

               let blockstack_magic = MagicBytes([blockstack_magic_str.as_bytes()[0] as u8, blockstack_magic_str.as_bytes()[1] as u8]);

               let cfg = BitcoinIndexerConfig {
                   peer_host: peer_host.to_string(),
                   peer_port: peer_port,
                   rpc_port: rpc_port,
                   rpc_ssl: rpc_ssl,
                   username: username,
                   password: password,
                   timeout: timeout,
                   spv_headers_path: spv_headers_path.to_string(),
                   first_block: first_block,
                   magic_bytes: blockstack_magic
               };
               
               Ok(cfg)
           },
           Err(_) => {
               Err(btc_error::ConfigError("Failed to parse BitcoinConfigIndexer config file".to_string()))
           }
       }
    }
}


impl BitcoinIndexerRuntime {
    pub fn new(network_id: BitcoinNetworkType) -> BitcoinIndexerRuntime {
        let mut rng = thread_rng();
        BitcoinIndexerRuntime {
            sock: Arc::new(Mutex::new(None)),
            services: 0,
            user_agent: USER_AGENT.to_owned(),
            version_nonce: rng.gen(),
            network_id: network_id
        }
    }
}


impl BitcoinIndexer {
    pub fn from_file(network_id: BitcoinNetworkType, config_file: &String) -> Result<BitcoinIndexer, btc_error> {
        let config = BitcoinIndexerConfig::from_file(config_file)?;
        let runtime = BitcoinIndexerRuntime::new(network_id);
        Ok(BitcoinIndexer {
            config: config,
            runtime: runtime
        })
    }

    pub fn dup(&self) -> BitcoinIndexer {
        BitcoinIndexer {
            config: self.config.clone(),
            runtime: BitcoinIndexerRuntime::new(self.runtime.network_id)
        }
    }

    /// (re)connect to our configured network peer.
    /// Sets self.runtime.sock to a new socket referring to our configured
    /// Bitcoin peer.  If we fail to connect, this method sets the socket
    /// to None.
    fn reconnect_peer(&mut self) -> Result<(), btc_error> {
        match net::TcpStream::connect((self.config.peer_host.as_str(), self.config.peer_port)) {
            Ok(s) => {
                self.runtime.sock = Arc::new(Mutex::new(Some(s)));
                Ok(())
            },
            Err(_e) => {
                self.runtime.sock = Arc::new(Mutex::new(None));
                Err(btc_error::ConnectionError)
            }
        }
    }

    /// Get a locked handle to the internal socket 
    pub fn socket_locked(&mut self) -> LockResult<MutexGuard<Option<net::TcpStream>>> {
        self.runtime.sock.lock()
    }

    /// Open an RPC connection to bitcoind 
    pub fn get_bitcoin_client(&self) -> BitcoinRPC {
        BitcoinRPC::new(
            format!("{}://{}:{}", if self.config.rpc_ssl { "https" } else { "http" }, self.config.peer_host.as_str(), self.config.rpc_port),
            self.config.username.clone(),
            self.config.password.clone()
        )
    }

    /// Are we connected?
    fn is_connected(&mut self) -> bool {
        let sock_locked = self.socket_locked();
        match sock_locked {
            Err(_) => {
                false
            },
            Ok(mut guard) => {
                match *guard.deref_mut() {
                    Some(ref mut _sock) => {
                        true
                    },
                    None => {
                        false
                    }
                }
            }
        }
    }

    /// Carry on a conversation with the bitcoin peer.
    /// Handle version, verack, ping, and pong messages automatically.
    /// Reconnect to the peer automatically if the peer closes the connection.
    /// Pass any other messages to a given message handler.
    pub fn peer_communicate<T: BitcoinMessageHandler>(&mut self, message_handler: &mut T, initial_handshake: bool) -> Result<(), btc_error> {
        let mut do_handshake = initial_handshake || !self.is_connected();
        let mut keep_going = true;
        let mut initiated = false;

        while keep_going {
            if do_handshake {
                debug!("(Re)establish peer connection");

                initiated = false;
                let handshake_result = self.connect_handshake_backoff();
                match handshake_result {
                    Ok(()) => {
                        // connection established!
                        do_handshake = false;
                    }
                    Err(_) => {
                        // need to try again 
                        continue;
                    }
                }
            }
        
            if !initiated {
                // initiate the conversation 
                let initiation_res = message_handler.begin_session(self);
                match initiation_res {
                    Ok(status) => {
                        if !status {
                            debug!("begin_session() terminates conversation");
                            break;
                        }
                        initiated = true;
                    }
                    Err(btc_error::ConnectionBroken) => {
                        debug!("Re-establish peer connection");
                        do_handshake = true;
                    }
                    Err(e) => {
                        warn!("Unhandled error while initiating conversation: {:?}", e);
                        return Err(e);
                    }
                }
            }

            let msg_result = self.recv_message();
            match msg_result {
                Ok(msg) => {
                    // got a message; go consume it
                    let handled = self.handle_message(msg, Some(message_handler));
                    match handled {
                        Ok(do_continue) => {
                            keep_going = do_continue;
                            if !keep_going {
                                debug!("Message handler indicates to stop");
                            }
                        }
                        Err(btc_error::UnhandledMessage(m)) => {
                            match m.deref() {
                                // some Bitcoin nodes send this to tell us to upgrade, so just
                                // consume it
                                NetworkMessage::Alert(ref _alert_msg) => {},
                                _ => {
                                    debug!("Unhandled message {:?}", m);
                                }
                            }
                        }
                        Err(btc_error::ConnectionBroken) => {
                            debug!("Re-establish peer connection");
                            do_handshake = true;
                        }
                        Err(e) => {
                            warn!("Unhandled error {:?}", e);
                            return Err(e);
                        }
                    }
                }
                Err(btc_error::ConnectionBroken) => {
                    do_handshake = true;
                }
                Err(e) => {
                    warn!("Unhandled error while receiving a message: {:?}", e);
                    return Err(e);
                }
            }
        }
        Ok(())
    }

    pub fn get_bitcoin_blockchain_height(&self) -> Result<u64, btc_error> {
        let bitcoin_client = self.get_bitcoin_client();
        bitcoin_client.getblockcount()
    }

    /// Synchronize the last N headers from bitcoin to a specific file.
    /// Returns the number of headers fetched.
    pub fn sync_last_headers(&mut self, path: &String, start_block: u64, last_block: u64) -> Result<u64, btc_error> {
        debug!("Sync all headers for blocks {} - {}", start_block, last_block);
        let mut spv_client = SpvClient::new(&path, start_block, last_block, self.runtime.network_id);
        spv_client.run(self)
                  .and_then(|_r| Ok(last_block - start_block))
    }

    /// Get a range of block headers from a file.
    /// If the range falls of the end of the headers file, then the returned array will be
    /// truncated to not include them (note that this method can return an empty list of the
    /// start_block is off the end of the file).
    pub fn read_spv_headers(&self, headers_path: &String, start_block: u64, end_block: u64) -> Result<Vec<LoneBlockHeader>, btc_error> {
        let mut headers = vec![];
        for block_height in start_block..end_block {
            let header_opt = SpvClient::read_block_header(headers_path, block_height)?;
            match header_opt {
                Some(header) => {
                    headers.push(header.clone());
                },
                None => {
                    break;
                }
            }
        }
        Ok(headers)
    }

    /// Search for a bitcoin reorg.  Return the offset into the canonical bitcoin headers where
    /// the reorg starts.
    pub fn find_bitcoin_reorg(&mut self, headers_path: &String, db_height: u64) -> Result<u64, btc_error> {
        let reorg_headers_path = format!("{}.reorg", &headers_path);
        if PathBuf::from(&reorg_headers_path).exists() {
            fs::remove_file(&reorg_headers_path)
                .map_err(|e| {
                    error!("Failed to remove {}", reorg_headers_path);
                    btc_error::Io(e)
                })?;
        }

        let mut new_tip = 0;
        let mut found = false;

        // what's the last header we have from the canonical history?
        let canonical_end_block = SpvClient::get_headers_height(&headers_path)
            .map_err(|e| {
                error!("Failed to get the last block from {}", &headers_path);
                e
            })?;

        if canonical_end_block < db_height {
            // should never happen 
            panic!("Headers is at block {}, but database is at block {}", canonical_end_block, db_height);
        }
        
        let mut start_block = 
            if db_height < REORG_BATCH_SIZE {
                0 
            }
            else {
                db_height - REORG_BATCH_SIZE
            };

        while start_block > 0 && !found {
            debug!("Search for reorg'ed headers from {} - {}", start_block, start_block + REORG_BATCH_SIZE);

            // copy over the head of the existing headers so we can fetch to the .reorg file
            let copy_height_start = 
                if start_block < REORG_BATCH_SIZE - 1 {
                    0
                }
                else {
                    start_block - REORG_BATCH_SIZE - 1
                };

            let existing_headers = self.read_spv_headers(&headers_path, copy_height_start, start_block + 1)?;

            let mut spv_client = SpvClient::new(&reorg_headers_path, start_block, start_block + REORG_BATCH_SIZE, self.runtime.network_id);
            spv_client.write_block_headers(copy_height_start - 1, &existing_headers)
                .map_err(|e| {
                    error!("Failed to write block header {} to {}", start_block, &reorg_headers_path);
                    e
                })?;
           
            // get new headers, starting off of this one.
            spv_client.run(self)
                .map_err(|e| {
                    error!("Failed to fetch headers from {} - {}", start_block, start_block + REORG_BATCH_SIZE);
                    e
                })?;

            // check for reorg 
            let canonical_headers = self.read_spv_headers(&headers_path, start_block, start_block + REORG_BATCH_SIZE)
                .map_err(|e| {
                    error!("Failed to read canonical headers from {} to {}", start_block, start_block + REORG_BATCH_SIZE);
                    e
                })?;

            let reorg_headers = self.read_spv_headers(&reorg_headers_path, start_block, start_block + REORG_BATCH_SIZE)
                .map_err(|e| {
                    error!("Failed to read reorg headers from {} to {}", start_block, start_block + REORG_BATCH_SIZE);
                    e
                })?;
              
            for i in (start_block..(start_block + REORG_BATCH_SIZE)).rev() {
                if canonical_headers[(i - start_block) as usize] == reorg_headers[(i - start_block) as usize] {
                    // shared history 
                    new_tip = i + 1;
                    found = true;
                    break;
                }
            }

            start_block -= REORG_BATCH_SIZE;
        }

        debug!("Chain history is consistent up to {}", new_tip);
        Ok(new_tip)
    }
}

impl BurnchainIndexer for BitcoinIndexer {

    type P = BitcoinBlockParser;
    
    /// Instantiate the Bitcoin indexer, and connect to the peer network.
    /// Instead, load our configuration state and sanity-check it.
    /// 
    /// Pass a directory (working_dir) that contains a "bitcoin.ini" file.
    fn init(working_dir: &String, network_name: &String) -> Result<BitcoinIndexer, burnchain_error> {
        let conf_path_str = Burnchain::get_chainstate_config_path(working_dir, &"bitcoin".to_string(), network_name);

        let network_id_opt = match network_name.as_ref() {
            BITCOIN_MAINNET_NAME => Some(BitcoinNetworkType::Mainnet),
            BITCOIN_TESTNET_NAME => Some(BitcoinNetworkType::Testnet),
            BITCOIN_REGTEST_NAME => Some(BitcoinNetworkType::Regtest),
            _ => None
        };

        if network_id_opt.is_none() {
            return Err(burnchain_error::Bitcoin(btc_error::ConfigError(format!("Unrecognized network name '{}'", network_name).to_string())));
        }
        let bitcoin_network_id = network_id_opt.unwrap();
        
        if !PathBuf::from(&conf_path_str).exists() {
            let default_config = BitcoinIndexerConfig::default();
            default_config.to_file(&conf_path_str)
                .map_err(burnchain_error::Bitcoin)?;
        }

        let mut indexer = BitcoinIndexer::from_file(bitcoin_network_id, &conf_path_str)
            .map_err(burnchain_error::Bitcoin)?;

        indexer.connect()?;
        Ok(indexer)
    }

    /// Connect to the Bitcoin peer network.
    /// Use the peer host and peer port given in the config file,
    /// and loaded in on setup.  Don't call this before init().
    fn connect(&mut self) -> Result<(), burnchain_error> {
        self.reconnect_peer()
            .map_err(burnchain_error::Bitcoin)
    }

    /// Get the location on disk where we keep headers
    fn get_headers_path(&self) -> String {
        self.config.spv_headers_path.clone()
    }
    
    /// Get the number of headers we have 
    fn get_headers_height(&self, headers_path: &String) -> Result<u64, burnchain_error> {
        SpvClient::get_headers_height(headers_path)
            .map_err(burnchain_error::Bitcoin)
    }

    /// Get the first block height
    fn get_first_block_height(&self) -> u64 {
        match self.runtime.network_id {
            BitcoinNetworkType::Mainnet => {
                FIRST_BLOCK_MAINNET
            },
            BitcoinNetworkType::Testnet => {
                FIRST_BLOCK_TESTNET
            },
            BitcoinNetworkType::Regtest => {
                FIRST_BLOCK_REGTEST
            }
        }
    }

    /// Get the first block header hash 
    fn get_first_block_header_hash(&self, headers_path: &String) -> Result<BurnchainHeaderHash, burnchain_error> {
        let first_block_height = self.get_first_block_height();
        let first_headers = self.read_spv_headers(headers_path, first_block_height, first_block_height+1)
            .map_err(burnchain_error::Bitcoin)?;

        let first_block_header_hash = BurnchainHeaderHash::from_bitcoin_hash(&first_headers[0].header.bitcoin_hash());
        Ok(first_block_header_hash)
    }

    /// Get the height of the blockchain 
    fn get_blockchain_height(&self) -> Result<u64, burnchain_error> {
        self.get_bitcoin_blockchain_height()
            .map_err(burnchain_error::Bitcoin)
    }

    /// Read downloaded headers within a range 
    fn read_headers(&self, headers_path: &String, start_block: u64, end_block: u64) -> Result<Vec<BitcoinHeaderIPC>, burnchain_error> {
        let headers = self.read_spv_headers(headers_path, start_block, end_block)
                          .map_err(burnchain_error::Bitcoin)?;
        let mut ret_headers : Vec<BitcoinHeaderIPC> = vec![];
        for i in 0..headers.len() {
            ret_headers.push({
                BitcoinHeaderIPC {
                    block_header: headers[i].clone(),
                    block_height: (i as u64) + start_block
                }
            });
        }
        Ok(ret_headers)
    }

    /// Identify underlying reorgs and return the block height at which they occur
    fn find_chain_reorg(&mut self, headers_path: &String, db_height: u64) -> Result<u64, burnchain_error> {
        self.find_bitcoin_reorg(headers_path, db_height)
            .map_err(burnchain_error::Bitcoin)
    }

    /// Download and store all headers between two block heights 
    fn sync_headers(&mut self, headers_path: &String, start_height: u64, end_height: u64) -> Result<(), burnchain_error> {
        if end_height <= start_height {
            return Ok(());
        }

        self.sync_last_headers(headers_path, start_height, end_height - 1)
            .map_err(burnchain_error::Bitcoin)
            .and_then(|_num_fetched| Ok(()))
    }

    /// Drop headers after a given height
    fn drop_headers(&mut self, headers_path: &String, new_height: u64) -> Result<(), burnchain_error> {
        let canonical_end_block = SpvClient::get_headers_height(headers_path)
            .map_err(burnchain_error::Bitcoin)?;
        
        if canonical_end_block < new_height {
            return Err(burnchain_error::Bitcoin(btc_error::BlockchainHeight));
        }

        SpvClient::drop_headers(headers_path, new_height)
            .map_err(burnchain_error::Bitcoin)
    }

    fn downloader(&self) -> BitcoinBlockDownloader {
        BitcoinBlockDownloader::new(self.dup())
    }

    fn parser(&self) -> BitcoinBlockParser {
        BitcoinBlockParser::new(self.runtime.network_id, self.config.magic_bytes) 
    }
}
