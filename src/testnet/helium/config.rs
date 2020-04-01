use std::convert::TryInto;
use std::io::{BufReader, Read};
use std::fs::{File};

use burnchains::{Address, MagicBytes, BLOCKSTACK_MAGIC_MAINNET};
use burnchains::bitcoin::indexer::{FIRST_BLOCK_REGTEST, FIRST_BLOCK_MAINNET};
use vm::types::{PrincipalData, QualifiedContractIdentifier, AssetIdentifier} ;
use rand::RngCore;
use util::hash::{to_hex};

#[derive(Clone, Deserialize)]
pub struct ConfigFile {
    pub burnchain: Option<BurnchainConfigFile>,
    pub node: Option<NodeConfigFile>,
    pub mempool: Option<MempoolConfig>,
    pub mstx_balance: Option<Vec<InitialBalanceFile>>,
    pub events_observer: Option<Vec<EventObserverConfigFile>>,
}

impl ConfigFile {

    pub fn from_path(path: &str) -> ConfigFile {
        let path = File::open(path).unwrap();
        let mut config_file_reader = BufReader::new(path);
        let mut config_file = vec![];
        config_file_reader.read_to_end(&mut config_file).unwrap();    
        toml::from_slice(&config_file[..]).unwrap()
    }

    pub fn from_str(content: &str) -> ConfigFile {
        toml::from_slice(&content.as_bytes()).unwrap()
    }
}

#[derive(Clone, Default)]
pub struct Config {
    pub burnchain: BurnchainConfig,
    pub node: NodeConfig,
    pub mempool: MempoolConfig,
    pub initial_balances: Vec<InitialBalance>,
    pub events_observers: Vec<EventObserverConfig>,
}

impl Config {

    pub fn from_config_file_path(path: &str) -> Config {
        let config_file = ConfigFile::from_path(path);
        Config::from_config_file(config_file)
    }

    pub fn from_config_file(config_file: ConfigFile) -> Config {

        let default_node_config = NodeConfig::default();
        let node = match config_file.node {
            Some(node) => {
                NodeConfig {
                    name: node.name.unwrap_or(default_node_config.name),
                    working_dir: node.working_dir.unwrap_or(default_node_config.working_dir),
                }
            },
            None => default_node_config
        };
    
        let default_burnchain_config = BurnchainConfig::default();
        let burnchain = match config_file.burnchain {
            Some(burnchain) => {
                BurnchainConfig {
                    chain: burnchain.chain.unwrap_or(default_burnchain_config.chain),
                    network: burnchain.network.unwrap_or(default_burnchain_config.network),
                    block_time: burnchain.block_time.unwrap_or(default_burnchain_config.block_time),
                    peer_host: burnchain.peer_host.unwrap_or(default_burnchain_config.peer_host),
                    peer_port: burnchain.peer_port.unwrap_or(default_burnchain_config.peer_port),
                    rpc_port: burnchain.rpc_port.unwrap_or(default_burnchain_config.rpc_port),
                    rpc_ssl: burnchain.rpc_ssl.unwrap_or(default_burnchain_config.rpc_ssl),
                    username: burnchain.username,
                    password: burnchain.password,
                    timeout: burnchain.timeout.unwrap_or(default_burnchain_config.timeout),
                    spv_headers_path: burnchain.spv_headers_path.unwrap_or(node.get_default_spv_headers_path()),
                    first_block: burnchain.first_block.unwrap_or(default_burnchain_config.first_block),
                    magic_bytes: default_burnchain_config.magic_bytes,
                    local_mining_public_key: burnchain.local_mining_public_key,
                    burnchain_op_tx_fee: burnchain.burnchain_op_tx_fee.unwrap_or(default_burnchain_config.burnchain_op_tx_fee)
                }
            },
            None => default_burnchain_config
        };

        let mempool = match config_file.mempool {
            Some(mempool) => mempool,
            None => MempoolConfig { path: node.get_default_mempool_path() }
        };
        
        let initial_balances: Vec<InitialBalance> = match config_file.mstx_balance {
            Some(balances) => {
                balances.iter().map(|balance| {
                    let address: PrincipalData = PrincipalData::parse_standard_principal(&balance.address).unwrap().into();
                    InitialBalance { address, amount: balance.amount }
                }).collect()
            },
            None => vec![]
        };

        let events_observers = match config_file.events_observer {
            Some(raw_observers) => {
                let mut observers = vec![];
                for observer in raw_observers {
                    let events_keys: Vec<EventKeyType> = observer.events_keys.iter()
                        .map(|e| EventKeyType::from_string(e).unwrap())
                        .collect();

                    observers.push(EventObserverConfig {
                        address: observer.address,
                        port: observer.port,
                        events_keys
                    });
                }
                observers
            }
            None => vec![]
        };

        Config {
            node,
            burnchain,
            mempool,
            initial_balances,
            events_observers,
        }
    }

    pub fn get_burnchain_path(&self) -> String {
        format!("{}/burnchain/", self.node.working_dir)
    }

    pub fn get_burn_db_path(&self) -> String {
        format!("{}/burnchain/db/", self.node.working_dir)
    }

    pub fn get_chainstate_path(&self) -> String{
        format!("{}/chainstate/", self.node.working_dir)
    }

    pub fn default() -> Config {
        // Testnet's name
        let node = NodeConfig {
            ..NodeConfig::default()
        };

        let burnchain = BurnchainConfig {
            ..BurnchainConfig::default()
        };

        let mempool = MempoolConfig {
            path: node.get_default_mempool_path(),
        };

        Config {
            burnchain: burnchain,
            node: node,
            mempool,
            initial_balances: vec![],
            events_observers: vec![],
        }
    }

    pub fn add_initial_balance(&mut self, address: String, amount: u64) {
        let new_balance = InitialBalance { address: PrincipalData::parse_standard_principal(&address).unwrap().into(), amount };
        self.initial_balances.push(new_balance);
    }
}

#[derive(Clone, Default)]
pub struct BurnchainConfig {
    pub chain: String,
    pub network: String,
    pub block_time: u64,
    pub peer_host: String,
    pub peer_port: u16,
    pub rpc_port: u16,
    pub rpc_ssl: bool,
    pub username: Option<String>,
    pub password: Option<String>,
    pub timeout: u32,
    pub spv_headers_path: String,
    pub first_block: u64,
    pub magic_bytes: MagicBytes,
    pub local_mining_public_key: Option<String>,
    pub burnchain_op_tx_fee: u64,
}

impl BurnchainConfig {
    fn default() -> BurnchainConfig {
        BurnchainConfig {
            chain: "bitcoin".to_string(),
            network: "sim".to_string(),
            block_time: 5000,
            peer_host: "bitcoin.blockstack.com".to_string(),
            peer_port: 8333,
            rpc_port: 8332,
            rpc_ssl: false,
            username: None,
            password: None,
            timeout: 30,
            spv_headers_path: "./spv-headers.dat".to_string(),
            first_block: FIRST_BLOCK_MAINNET,
            magic_bytes: BLOCKSTACK_MAGIC_MAINNET.clone(),
            local_mining_public_key: None,
            burnchain_op_tx_fee: 1000,
        }
    }

    pub fn get_rpc_url(&self) -> String {
        let scheme = match self.rpc_ssl {
            true => "https://",
            false => "http://"
        };
        format!("{}{}:{}", scheme, self.peer_host, self.rpc_port)
    }
}

#[derive(Clone, Deserialize)]
pub struct BurnchainConfigFile {
    pub chain: Option<String>,
    pub network: Option<String>,
    pub block_time: Option<u64>,
    pub peer_host: Option<String>,
    pub peer_port: Option<u16>,
    pub rpc_port: Option<u16>,
    pub rpc_ssl: Option<bool>,
    pub username: Option<String>,
    pub password: Option<String>,
    pub timeout: Option<u32>,
    pub spv_headers_path: Option<String>,
    pub first_block: Option<u64>,
    pub magic_bytes: Option<String>,
    pub local_mining_public_key: Option<String>,
    pub burnchain_op_tx_fee: Option<u64>
}

#[derive(Clone, Default)]
pub struct NodeConfig {
    pub name: String,
    pub working_dir: String,
}

impl NodeConfig {

    fn default() -> NodeConfig {
        let mut rng = rand::thread_rng();
        let mut buf = [0u8; 8];
        rng.fill_bytes(&mut buf);
        let testnet_id = format!("stacks-testnet-{}", to_hex(&buf));

        let name = "helium-node";
        NodeConfig {
            name: name.to_string(),
            working_dir: format!("/tmp/{}", testnet_id),
        }
    }

    pub fn get_default_mempool_path(&self) -> String {
        format!("{}/mempool/", self.working_dir)
    }

    pub fn get_burnchain_path(&self) -> String {
        format!("{}/burnchain", self.working_dir)
    }

    pub fn get_default_spv_headers_path(&self) -> String {
        format!("{}/spv-headers.dat", self.get_burnchain_path())
    }
}

#[derive(Clone, Default, Deserialize)]
pub struct NodeConfigFile {
    pub name: Option<String>,
    pub working_dir: Option<String>,
}

#[derive(Clone, Default, Deserialize)]
pub struct MempoolConfig {
    pub path: String,
}

#[derive(Clone, Deserialize)]
pub struct EventObserverConfigFile {
    pub port: u16,
    pub address: String,
    pub events_keys: Vec<String>,
}

#[derive(Clone, Default)]
pub struct EventObserverConfig {
    pub port: u16,
    pub address: String,
    pub events_keys: Vec<EventKeyType>,
}

#[derive(Clone)]
pub enum EventKeyType {
    SmartContractEvent((QualifiedContractIdentifier, String)),
    AssetEvent(AssetIdentifier),
    STXEvent,
    AnyEvent,
}

impl EventKeyType {
    fn from_string(raw_key: &str) -> Option<EventKeyType> {
        if raw_key == "*" {
            return Some(EventKeyType::AnyEvent);
        } 

        if raw_key == "stx" {
            return Some(EventKeyType::STXEvent);
        } 
        
        let comps: Vec<_> = raw_key.split("::").collect();
        if comps.len() ==  1 {
            let split: Vec<_> = comps[0].split(".").collect();
            if split.len() != 3 {
                return None
            }
            let components = (PrincipalData::parse_standard_principal(split[0]), split[1].to_string().try_into(), split[2].to_string().try_into());
            match components {
                (Ok(address), Ok(name), Ok(asset_name)) => {
                    let contract_identifier = QualifiedContractIdentifier::new(address, name);
                    let asset_identifier = AssetIdentifier { contract_identifier, asset_name };
                    Some(EventKeyType::AssetEvent(asset_identifier))
                },
                (_, _, _) => None
            }
        } else if comps.len() == 2 {
            if let Ok(contract_identifier) = QualifiedContractIdentifier::parse(comps[0]) {
                Some(EventKeyType::SmartContractEvent((contract_identifier, comps[1].to_string())))
            } else {
                None
            }
        } else {
            None
        }
    }
}

#[derive(Clone)]
pub struct InitialBalance {
    pub address: PrincipalData,
    pub amount: u64,
}

#[derive(Clone, Deserialize)]
pub struct InitialBalanceFile {
    pub address: String,
    pub amount: u64,
}
