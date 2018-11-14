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

use std::env;
use std::net;
use std::sync::{Arc, Mutex, LockResult, MutexGuard};
use rand::{Rng, thread_rng};
use std::path::{PathBuf};

use ini::Ini;
use burnchains::indexer::*;
use burnchains::bitcoin::spv::*;
use burnchains::bitcoin::rpc::BitcoinRPC;
use burnchains::bitcoin::Error as btc_error;
use burnchains::bitcoin::messages::BitcoinMessageHandler;

use bitcoin::network::constants as bitcoin_constants;

pub const USER_AGENT: &'static str = "Blockstack Core v21";

pub const BITCOIN_MAINNET: u32 = 0xD9B4BEF9;
pub const BITCOIN_TESTNET: u32 = 0x0709110B;
pub const BITCOIN_REGTEST: u32 = 0xDAB5BFFA;

pub const BITCOIN_MAINNET_NAME: &'static str = "mainnet";
pub const BITCOIN_TESTNET_NAME: &'static str = "testnet";
pub const BITCOIN_REGTEST_NAME: &'static str = "regtest";

pub const FIRST_BLOCK_MAINNET: u64 = 373601;

pub fn network_id_to_name(network_id: u32) -> &'static str {
    match network_id {
        BITCOIN_MAINNET => BITCOIN_MAINNET_NAME,
        BITCOIN_TESTNET => BITCOIN_TESTNET_NAME,
        BITCOIN_REGTEST => BITCOIN_REGTEST_NAME,
        _ => "unknown"
    }
}

#[derive(Debug)]
pub struct BitcoinIndexerConfig {
    // config fields
    pub peer_host: String,
    pub peer_port: u16,
    pub rpc_port: u16,
    pub username: Option<String>,
    pub password: Option<String>,
    pub timeout: u32,
    pub spv_headers_path: String,
    pub first_block: u64
}

pub struct BitcoinIndexerRuntime {
    sock: Arc<Mutex<Option<net::TcpStream>>>,
    pub services: u64,
    pub user_agent: String,
    pub version_nonce: u64,
    pub magic: u32
}

pub struct BitcoinIndexer {
    pub config: BitcoinIndexerConfig,
    pub runtime: BitcoinIndexerRuntime
}


impl BitcoinIndexerConfig {
    fn default() -> BitcoinIndexerConfig {
        let mut spv_headers_path = env::home_dir().unwrap();
        spv_headers_path.push(".blockstack-core");
        spv_headers_path.push("bitcoin-spv-headers.dat");

        return BitcoinIndexerConfig {
            peer_host: "bitcoin.blockstack.com".to_string(),
            peer_port: 8332,
            rpc_port: 8333,
            username: Some("blockstack".to_string()),
            password: Some("blockstacksystem".to_string()),
            timeout: 30,
            spv_headers_path: spv_headers_path.to_str().unwrap().to_string(),
            first_block: FIRST_BLOCK_MAINNET
        };
    }

    fn from_file(path: &str) -> Result<BitcoinIndexerConfig, &'static str> {
       let conf_path = PathBuf::from(path);
       if !conf_path.is_file() {
           return Err("Failed to load BitcoinIndexerConfig file: No such file or directory");
       }
       let default_config = BitcoinIndexerConfig::default();

       match Ini::load_from_file(path) {
           Ok(ini_file) => {
               // got data!
               let bitcoin_section_opt = ini_file.section(Some("bitcoin").to_owned());
               if None == bitcoin_section_opt {
                   return Err("No [bitcoin] section in config file");
               }

               let bitcoin_section = bitcoin_section_opt.unwrap();

               // defaults
               let peer_host = bitcoin_section.get("server")
                                              .unwrap_or(&default_config.peer_host);

               let peer_port = bitcoin_section.get("p2p_port")
                                              .unwrap_or(&format!("{}", default_config.peer_port))
                                              .trim().parse().map_err(|_e| "Invalid bitcoin:p2p_port value")?;

               if peer_port <= 1024 || peer_port >= 65535 {
                   return Err("Invalid p2p_port");
               }

               let rpc_port = bitcoin_section.get("port")
                                             .unwrap_or(&format!("{}", default_config.rpc_port))
                                             .trim().parse().map_err(|_e| "Invalid bitcoin:port value")?;

               if rpc_port <= 1024 || rpc_port >= 65535 {
                   return Err("Invalid rpc_port");
               }

               let username = bitcoin_section.get("user").and_then(|s| Some(s.clone()));
               let password = bitcoin_section.get("password").and_then(|s| Some(s.clone()));

               let timeout = bitcoin_section.get("timeout")
                                            .unwrap_or(&format!("{}", default_config.timeout))
                                            .trim().parse().map_err(|_e| "Invalid bitcoin:timeout value")?;

               let spv_headers_path = bitcoin_section.get("spv_path")
                                            .unwrap_or(&default_config.spv_headers_path);

               let first_block = bitcoin_section.get("first_block")
                                            .unwrap_or(&format!("{}", FIRST_BLOCK_MAINNET))
                                            .trim().parse().map_err(|_e| "Invalid bitcoin:first_block value")?;

               let cfg = BitcoinIndexerConfig {
                   peer_host: peer_host.to_string(),
                   peer_port: peer_port,
                   rpc_port: rpc_port,
                   username: username,
                   password: password,
                   timeout: timeout,
                   spv_headers_path: spv_headers_path.to_string(),
                   first_block: first_block
               };
               return Ok(cfg);
           },
           Err(_) => {
               return Err("Failed to parse BitcoinConfigIndexer config file");
           }
       }
    }
}


impl BitcoinIndexerRuntime {
    pub fn default(network_id: u32) -> BitcoinIndexerRuntime {
        let mut rng = thread_rng();
        return BitcoinIndexerRuntime {
            sock: Arc::new(Mutex::new(None)),
            services: 0,
            user_agent: USER_AGENT.to_owned(),
            version_nonce: rng.gen(),
            magic: network_id
        };
    }
}


impl BitcoinIndexer {
    pub fn new() -> BitcoinIndexer {
        let default_config = BitcoinIndexerConfig::default();
        return BitcoinIndexer {
            config: default_config,
            runtime: BitcoinIndexerRuntime::default(BITCOIN_MAINNET)
        };
    }

    /// (re)connect to our configured network peer.
    /// Sets self.runtime.sock to a new socket referring to our configured
    /// Bitcoin peer.  If we fail to connect, this method sets the socket
    /// to None.
    fn reconnect_peer(&mut self) -> Result<(), &'static str> {
        match net::TcpStream::connect((self.config.peer_host.as_str(), self.config.peer_port)) {
            Ok(s) => {
                self.runtime.sock = Arc::new(Mutex::new(Some(s)));
                return Ok(());
            },
            Err(_e) => {
                self.runtime.sock = Arc::new(Mutex::new(None));
                return Err("Failed to connect to remote peer");
            }
        }
    }

    /// Get a locked handle to the internal socket 
    pub fn socket_locked(&mut self) -> LockResult<MutexGuard<Option<net::TcpStream>>> {
        return self.runtime.sock.lock();
    }

    /// Open an RPC connection to bitcoind 
    pub fn get_bitcoin_client(&self) -> BitcoinRPC {
        let client = BitcoinRPC::new(
            format!("http://{}:{}", self.config.peer_host.as_str(), self.config.rpc_port),
            self.config.username.clone(),
            self.config.password.clone()
        );
        return client;
    }

    /// Carry on a conversation with the bitcoin peer.
    /// Handle version, verack, ping, and pong messages automatically.
    /// Reconnect to the peer automatically if the peer closes the connection.
    /// Pass any other messages to a given message handler.
    pub fn peer_communicate<T: BitcoinMessageHandler>(&mut self, message_handler: &mut T) -> Result<(), btc_error> {
        let mut do_handshake = true;
        let mut keep_going = true;
        let mut initiated = false;

        while keep_going {
            if do_handshake {
                debug!("(Re)establish peer connection");
                let magic = self.runtime.magic;
                let handshake_result = self.connect_handshake_backoff(network_id_to_name(magic));
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
                    // got a message, so handle it!
                    let handled = self.handle_message(&msg, Some(message_handler));
                    match handled {
                        Ok(do_continue) => {
                            keep_going = do_continue;
                            if !keep_going {
                                debug!("Message handler indicates to stop");
                            }
                        }
                        Err(btc_error::UnhandledMessage) => {
                            debug!("Unhandled message {:?}", msg);
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

        return Ok(());
    }
}


impl BurnchainIndexer for BitcoinIndexer {
    /// Instantiate the Bitcoin indexer, but don't connect to the peer network.
    /// Instead, load our configuration state and sanity-check it.
    /// Call connect() next.
    /// 
    /// Pass a directory (working_dir) that contains a "bitcoin.ini" file.
    fn setup(&mut self, working_dir: &str) -> Result<(), &'static str> {
       let mut conf_path = PathBuf::from(working_dir);
       conf_path.push("bitcoin.ini");

       match BitcoinIndexerConfig::from_file(conf_path.to_str().unwrap()) {
           Ok(cfg) => {
               self.config = cfg;
               return Ok(());
           },
           Err(e) => {
               return Err(e);
           }
       };
    }

    /// Connect to the Bitcoin peer network.
    /// Use the peer host and peer port given in the config file,
    /// and loaded in on setup.  Don't call this before setup().
    ///
    /// Pass "mainnet", "testnet", or "regtest" as the network name
    fn connect(&mut self, network_name: &str) -> Result<(), &'static str> {
        let network_id_opt = match network_name.as_ref() {
            "mainnet" => Some(BITCOIN_MAINNET),
            "testnet" => Some(BITCOIN_TESTNET),
            "regtest" => Some(BITCOIN_REGTEST),
            _ => None
        };

        if None == network_id_opt {
            return Err("Unrecognized network name");
        }

        let network_id = network_id_opt.unwrap();
        self.runtime = BitcoinIndexerRuntime::default(network_id);
        return self.reconnect_peer();
    }

    fn get_block_hash(&mut self, block_height: u64) -> Result<String, &'static str> {
        return Err("not implemented");
    }

    fn get_block_txs(&mut self, block_hash: &str) -> Result<Box<Vec<BurnchainTransaction>>, &'static str> {
        return Err("not implemented");
    }
}


/// Synchronize all block headers.
/// Returns the number of *new* headers fetched
pub fn sync_block_headers(indexer: &mut BitcoinIndexer, end_block: Option<u64>) -> Result<u64, btc_error> {
    // how many blocks are there?
    let last_block = match end_block {
        Some(block_height) => {
            block_height
        }
        None => {
            let bitcoin_client = indexer.get_bitcoin_client();
            let block_count = bitcoin_client.getblockcount()?;
            block_count
        }
    };

    let first_block = match SpvClient::get_headers_height(&indexer.config.spv_headers_path) {
        Ok(block_height) => {
            block_height
        }
        Err(btc_error::FilesystemError(ref e)) => {
            // headers path doesn't exist
            0
        }
        Err(e) => {
            // some other error
            debug!("Unable to find first block height: {:?}", e);
            return Err(e);
        }
    };

    if first_block >= last_block {
        debug!("Fetched 0 headers -- all caught up");
        return Ok(0);
    }

    debug!("Sync headers for blocks {} - {}", first_block, last_block);
    let mut spv_client = SpvClient::new(&indexer.config.spv_headers_path, first_block, last_block, indexer.runtime.magic);
    let spv_res = spv_client.run(indexer)
        .and_then(|_r| Ok(last_block - 1 - first_block));

    return spv_res;
}

