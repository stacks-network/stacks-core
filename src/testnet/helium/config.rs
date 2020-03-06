use util::hash::{to_hex};
use burnchains::Address;
use vm::types::{PrincipalData, QualifiedContractIdentifier} ;
use rand::RngCore;

pub struct ConfigFile {
    pub burnchain: Option<BurnchainConfig>,
    pub node: Option<NodeConfig>,
    pub initial_balances: Option<Vec<InitialBalance>>,
    pub sidecars: Option<Vec<EventObserverConfig>>,
}

#[derive(Clone, Default)]
pub struct Config {
    pub burnchain: BurnchainConfig,
    pub node: NodeConfig,
    pub initial_balances: Option<Vec<InitialBalance>>,
    pub event_observers: Option<Vec<EventObserverConfig>>,
}

impl Config {

    pub fn default() -> Config {
        // Testnet's name
        let mut rng = rand::thread_rng();
        let mut buf = [0u8; 8];
        rng.fill_bytes(&mut buf);
        let testnet_id = format!("stacks-testnet-{}", to_hex(&buf));

        let burnchain = BurnchainConfig {
            db_path: format!("/tmp/{}/burnchain", testnet_id),
            ..BurnchainConfig::default()
        };

        let node = NodeConfig {
            name: "L1".to_string(),
            db_path: format!("/tmp/{}/L1", testnet_id),
            mempool_path: format!("/tmp/{}/L1/mempool", testnet_id),
            wif: None,
        };

        Config {
            burnchain: burnchain,
            node: node,
            initial_balances: None,
            event_observers: None,
        }
    }

    pub fn add_initial_balance(&mut self, address: String, amount: u64) {
        let new_balance = InitialBalance { address: PrincipalData::parse_standard_principal(&address).unwrap().into(), amount };
        match &mut self.initial_balances {
            Some(ref mut balances) => {
                balances.push(new_balance);
            }
            None => {
                self.initial_balances = Some(vec![new_balance]);
            }
        }
    }
}

#[derive(Clone, Default)]
pub struct BurnchainConfig {
    pub chain: String,
    pub mode: String,
    pub db_path: String,
    pub block_time: u64,
    pub wif: Option<String>,
    pub rpc_address: Option<String>,
    pub rpc_port: Option<u16>,
    pub rpc_auth: Option<String>,  
}

impl BurnchainConfig {
    fn default() -> BurnchainConfig {
        BurnchainConfig {
            chain: "bitcoin".to_string(),
            mode: "regtest".to_string(),
            db_path: "/tmp/stacks-testnet/".to_string(),
            block_time: 5000,
            wif: None,
            rpc_address: Some("127.0.0.1".to_string()),
            rpc_port: Some(18443),
            rpc_auth: None,  
        }
    }
}

#[derive(Clone, Default)]
pub struct NodeConfig {
    pub name: String,
    pub db_path: String,
    pub mempool_path: String,
    pub wif: Option<String>,
}

#[derive(Clone, Default)]
pub struct EventObserverConfig {
    pub port: u16,
    pub address: String,
    pub watched_event_keys: Vec<(QualifiedContractIdentifier, String)>,
}

#[derive(Clone)]
pub struct InitialBalance {
    pub address: PrincipalData,
    pub amount: u64,
}
