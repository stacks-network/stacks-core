use util::hash::{to_hex};
use burnchains::{Address, Burnchain};
use vm::types::{PrincipalData, QualifiedContractIdentifier, AssetIdentifier} ;
use rand::RngCore;
use std::convert::TryInto;
use std::io::BufReader;
use std::io::Read;
use std::fs::File;
use net::connection::ConnectionOptions;

#[derive(Clone, Deserialize)]
pub struct ConfigFile {
    pub burnchain: Option<BurnchainConfigFile>,
    pub node: Option<NodeConfigFile>,
    pub mempool: Option<MempoolConfig>,
    pub mstx_balance: Option<Vec<InitialBalanceFile>>,
    pub events_observer: Option<Vec<EventObserverConfigFile>>,
    pub connection_options: Option<ConnectionOptionsFile>,
}

impl ConfigFile {

    pub fn from_path(path: &str) -> ConfigFile {
        let path = File::open(path).unwrap();
        let mut config_file_reader = BufReader::new(path);
        let mut config_file = vec![];
        config_file_reader.read_to_end(&mut config_file).unwrap();    
        toml::from_slice(&config_file[..]).unwrap()
    }
}

#[derive(Clone, Default)]
pub struct Config {
    pub burnchain: BurnchainConfig,
    pub node: NodeConfig,
    pub mempool: MempoolConfig,
    pub initial_balances: Vec<InitialBalance>,
    pub events_observers: Vec<EventObserverConfig>,
    pub connection_options: ConnectionOptions,
}

lazy_static! {
    static ref HELIUM_DEFAULT_CONNECTION_OPTIONS: ConnectionOptions = ConnectionOptions {
        inbox_maxlen: 100,
        outbox_maxlen: 100,
        timeout: 5000,
        idle_timeout: 15,               // how long a HTTP connection can be idle before it's closed
        heartbeat: 60000,
        // can't use u64::max, because sqlite stores as i64.
        private_key_lifetime: 9223372036854775807,
        num_neighbors: 4,
        num_clients: 1000,
        soft_num_neighbors: 4,
        soft_num_clients: 1000,
        max_neighbors_per_host: 10,
        max_clients_per_host: 1000,
        soft_max_neighbors_per_host: 10,
        soft_max_neighbors_per_org: 100,
        soft_max_clients_per_host: 1000,
        walk_interval: 9223372036854775807,
        dns_timeout: 15_000,
        max_inflight_blocks: 6,
        .. std::default::Default::default()
    };
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
                    rpc_bind: node.rpc_bind.unwrap_or(default_node_config.rpc_bind),
                    p2p_bind: node.p2p_bind.unwrap_or(default_node_config.p2p_bind),
                }
            },
            None => default_node_config
        };

        let default_burnchain_config = BurnchainConfig::default();
        let burnchain = match config_file.burnchain {
            Some(burnchain) => {
                BurnchainConfig {
                    chain: burnchain.chain.unwrap_or(default_burnchain_config.chain),
                    mode: burnchain.mode.unwrap_or(default_burnchain_config.mode),
                    block_time: burnchain.block_time.unwrap_or(default_burnchain_config.block_time),
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
                        endpoint: observer.endpoint,
                        events_keys
                    });
                }
                observers
            }
            None => vec![]
        };

        let connection_options = match config_file.connection_options {
            Some(opts) => {
                let mut read_only_call_limit = HELIUM_DEFAULT_CONNECTION_OPTIONS.read_only_call_limit.clone();
                opts.read_only_call_limit_write_length.map(|x| { read_only_call_limit.write_length = x; });
                opts.read_only_call_limit_write_count.map(|x| { read_only_call_limit.write_count = x; });
                opts.read_only_call_limit_read_length.map(|x| { read_only_call_limit.read_length = x; });
                opts.read_only_call_limit_read_count.map(|x| { read_only_call_limit.read_count = x; });
                opts.read_only_call_limit_runtime.map(|x| { read_only_call_limit.runtime = x; });
                ConnectionOptions {
                    read_only_call_limit,
                    inbox_maxlen: opts.inbox_maxlen.unwrap_or_else(|| HELIUM_DEFAULT_CONNECTION_OPTIONS.inbox_maxlen.clone()),
                    outbox_maxlen: opts.outbox_maxlen.unwrap_or_else(|| HELIUM_DEFAULT_CONNECTION_OPTIONS.outbox_maxlen.clone()),
                    timeout: opts.timeout.unwrap_or_else(|| HELIUM_DEFAULT_CONNECTION_OPTIONS.timeout.clone()),
                    idle_timeout: opts.idle_timeout.unwrap_or_else(|| HELIUM_DEFAULT_CONNECTION_OPTIONS.idle_timeout.clone()),
                    heartbeat: opts.heartbeat.unwrap_or_else(|| HELIUM_DEFAULT_CONNECTION_OPTIONS.heartbeat.clone()),
                    private_key_lifetime: opts.private_key_lifetime.unwrap_or_else(|| HELIUM_DEFAULT_CONNECTION_OPTIONS.private_key_lifetime.clone()),
                    num_neighbors: opts.num_neighbors.unwrap_or_else(|| HELIUM_DEFAULT_CONNECTION_OPTIONS.num_neighbors.clone()),
                    num_clients: opts.num_clients.unwrap_or_else(|| HELIUM_DEFAULT_CONNECTION_OPTIONS.num_clients.clone()),
                    soft_num_neighbors: opts.soft_num_neighbors.unwrap_or_else(|| HELIUM_DEFAULT_CONNECTION_OPTIONS.soft_num_neighbors.clone()),
                    soft_num_clients: opts.soft_num_clients.unwrap_or_else(|| HELIUM_DEFAULT_CONNECTION_OPTIONS.soft_num_clients.clone()),
                    max_neighbors_per_host: opts.max_neighbors_per_host.unwrap_or_else(|| HELIUM_DEFAULT_CONNECTION_OPTIONS.max_neighbors_per_host.clone()),
                    max_clients_per_host: opts.max_clients_per_host.unwrap_or_else(|| HELIUM_DEFAULT_CONNECTION_OPTIONS.max_clients_per_host.clone()),
                    soft_max_neighbors_per_host: opts.soft_max_neighbors_per_host.unwrap_or_else(|| HELIUM_DEFAULT_CONNECTION_OPTIONS.soft_max_neighbors_per_host.clone()),
                    soft_max_neighbors_per_org: opts.soft_max_neighbors_per_org.unwrap_or_else(|| HELIUM_DEFAULT_CONNECTION_OPTIONS.soft_max_neighbors_per_org.clone()),
                    soft_max_clients_per_host: opts.soft_max_clients_per_host.unwrap_or_else(|| HELIUM_DEFAULT_CONNECTION_OPTIONS.soft_max_clients_per_host.clone()),
                    walk_interval: opts.walk_interval.unwrap_or_else(|| HELIUM_DEFAULT_CONNECTION_OPTIONS.walk_interval.clone()),
                    dns_timeout: opts.dns_timeout.unwrap_or_else(|| HELIUM_DEFAULT_CONNECTION_OPTIONS.dns_timeout.clone()),
                    max_inflight_blocks: opts.max_inflight_blocks.unwrap_or_else(|| HELIUM_DEFAULT_CONNECTION_OPTIONS.max_inflight_blocks.clone()),
                    maximum_call_argument_size: opts.maximum_call_argument_size.unwrap_or_else(|| HELIUM_DEFAULT_CONNECTION_OPTIONS.maximum_call_argument_size.clone()),
                }
            },
            None => {
                HELIUM_DEFAULT_CONNECTION_OPTIONS.clone()
            }
        };

        Config {
            node,
            burnchain,
            mempool,
            initial_balances,
            events_observers,
            connection_options
        }
    }

    pub fn get_burn_db_path(&self) -> String {
        format!("{}/burn_db/", self.node.working_dir)
    }

    pub fn get_chainstate_path(&self) -> String {
        format!("{}/chainstate/", self.node.working_dir)
    }

    pub fn get_peer_db_path(&self) -> String {
        format!("{}/peer_db.sqlite", self.node.working_dir)
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

        let connection_options = HELIUM_DEFAULT_CONNECTION_OPTIONS.clone();

        Config {
            burnchain: burnchain,
            node: node,
            mempool,
            initial_balances: vec![],
            events_observers: vec![],
            connection_options,
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
    pub mode: String,
    pub block_time: u64,
}

impl BurnchainConfig {
    fn default() -> BurnchainConfig {
        BurnchainConfig {
            chain: "bitcoin".to_string(),
            mode: "regtest".to_string(),
            block_time: 5000,
        }
    }
}

#[derive(Clone, Deserialize)]
pub struct BurnchainConfigFile {
    pub chain: Option<String>,
    pub mode: Option<String>,
    pub block_time: Option<u64>,
}

#[derive(Clone, Default)]
pub struct NodeConfig {
    pub name: String,
    pub working_dir: String,
    pub rpc_bind: String,
    pub p2p_bind: String,
}

impl NodeConfig {

    fn default() -> NodeConfig {
        let mut rng = rand::thread_rng();
        let mut buf = [0u8; 8];
        rng.fill_bytes(&mut buf);
        let testnet_id = format!("stacks-testnet-{}", to_hex(&buf));

        let rpc_port = u16::from_be_bytes(buf[0..2].try_into().unwrap())
            .saturating_add(1024); // use a non-privileged port

        let p2p_port = u16::from_be_bytes(buf[2..4].try_into().unwrap())
            .saturating_add(1024); // use a non-privileged port

        let name = "helium-node";
        NodeConfig {
            name: name.to_string(),
            working_dir: format!("/tmp/{}", testnet_id),
            rpc_bind: format!("127.0.0.1:{}", rpc_port),
            p2p_bind: format!("127.0.0.1:{}", p2p_port)
        }
    }

    pub fn get_default_mempool_path(&self) -> String {
        format!("{}/mempool/", self.working_dir)
    }
}

#[derive(Clone, Default, Deserialize)]
pub struct ConnectionOptionsFile {
    pub inbox_maxlen: Option<usize>,
    pub outbox_maxlen: Option<usize>,
    pub timeout: Option<u64>,
    pub idle_timeout: Option<u64>,
    pub heartbeat: Option<u32>,
    pub private_key_lifetime: Option<u64>,
    pub num_neighbors: Option<u64>,
    pub num_clients: Option<u64>,
    pub soft_num_neighbors: Option<u64>,
    pub soft_num_clients: Option<u64>,
    pub max_neighbors_per_host: Option<u64>,
    pub max_clients_per_host: Option<u64>,
    pub soft_max_neighbors_per_host: Option<u64>,
    pub soft_max_neighbors_per_org: Option<u64>,
    pub soft_max_clients_per_host: Option<u64>,
    pub walk_interval: Option<u64>,
    pub dns_timeout: Option<u128>,
    pub max_inflight_blocks: Option<u64>,
    pub read_only_call_limit_write_length: Option<u64>,
    pub read_only_call_limit_read_length: Option<u64>,
    pub read_only_call_limit_write_count: Option<u64>,
    pub read_only_call_limit_read_count: Option<u64>,
    pub read_only_call_limit_runtime: Option<u64>,
    pub maximum_call_argument_size: Option<u32>,
}


#[derive(Clone, Default, Deserialize)]
pub struct NodeConfigFile {
    pub name: Option<String>,
    pub working_dir: Option<String>,
    pub rpc_bind: Option<String>,
    pub p2p_bind: Option<String>,
}

#[derive(Clone, Default, Deserialize)]
pub struct MempoolConfig {
    pub path: String,
}

#[derive(Clone, Deserialize)]
pub struct EventObserverConfigFile {
    pub endpoint: String,
    pub events_keys: Vec<String>,
}

#[derive(Clone, Default)]
pub struct EventObserverConfig {
    pub endpoint: String,
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
