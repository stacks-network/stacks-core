use std::convert::TryInto;
use std::fs;
use std::net::{SocketAddr, ToSocketAddrs};

use rand::RngCore;

use stacks::burnchains::bitcoin::BitcoinNetworkType;
use stacks::burnchains::{MagicBytes, BLOCKSTACK_MAGIC_MAINNET};
use stacks::net::connection::ConnectionOptions;
use stacks::net::{Neighbor, NeighborKey, PeerAddress};
use stacks::util::hash::{hex_bytes, to_hex};
use stacks::util::secp256k1::Secp256k1PrivateKey;
use stacks::util::secp256k1::Secp256k1PublicKey;
use stacks::vm::costs::ExecutionCost;
use stacks::vm::types::{AssetIdentifier, PrincipalData, QualifiedContractIdentifier};

pub const TESTNET_CHAIN_ID: u32 = 0x80000000;
pub const TESTNET_PEER_VERSION: u32 = 0xfacade01;

pub const MAINNET_CHAIN_ID: u32 = 0x00000001;
pub const MAINNET_PEER_VERSION: u32 = 0x18000000;

const MINIMUM_DUST_FEE: u64 = 5500;

#[derive(Clone, Deserialize, Default)]
pub struct ConfigFile {
    pub burnchain: Option<BurnchainConfigFile>,
    pub node: Option<NodeConfigFile>,
    pub ustx_balance: Option<Vec<InitialBalanceFile>>,
    pub events_observer: Option<Vec<EventObserverConfigFile>>,
    pub connection_options: Option<ConnectionOptionsFile>,
    pub block_limit: Option<BlockLimitFile>,
}

#[derive(Clone, Deserialize, Default)]
pub struct LegacyMstxConfigFile {
    pub mstx_balance: Option<Vec<InitialBalanceFile>>,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn should_load_legacy_mstx_balances_toml() {
        let config = ConfigFile::from_str(
            r#"
            [[ustx_balance]]
            address = "STB44HYPYAT2BB2QE513NSP81HTMYWBJP02HPGK6"
            amount = 10000000000000000

            [[ustx_balance]]
            address = "ST11NJTTKGVT6D1HY4NJRVQWMQM7TVAR091EJ8P2Y"
            amount = 10000000000000000

            [[mstx_balance]] # legacy property name
            address = "ST1HB1T8WRNBYB0Y3T7WXZS38NKKPTBR3EG9EPJKR"
            amount = 10000000000000000

            [[mstx_balance]] # legacy property name
            address = "STRYYQQ9M8KAF4NS7WNZQYY59X93XEKR31JP64CP"
            amount = 10000000000000000
            "#,
        );
        assert!(config.ustx_balance.is_some());
        let balances = config
            .ustx_balance
            .expect("Failed to parse stx balances from toml");
        assert_eq!(balances.len(), 4);
        assert_eq!(
            balances[0].address,
            "STB44HYPYAT2BB2QE513NSP81HTMYWBJP02HPGK6"
        );
        assert_eq!(
            balances[1].address,
            "ST11NJTTKGVT6D1HY4NJRVQWMQM7TVAR091EJ8P2Y"
        );
        assert_eq!(
            balances[2].address,
            "ST1HB1T8WRNBYB0Y3T7WXZS38NKKPTBR3EG9EPJKR"
        );
        assert_eq!(
            balances[3].address,
            "STRYYQQ9M8KAF4NS7WNZQYY59X93XEKR31JP64CP"
        );
    }
}

impl ConfigFile {
    pub fn from_path(path: &str) -> ConfigFile {
        let content_str = fs::read_to_string(path).unwrap();
        Self::from_str(&content_str)
    }

    pub fn from_str(content: &str) -> ConfigFile {
        let mut config: ConfigFile = toml::from_str(content).unwrap();
        let legacy_config: LegacyMstxConfigFile = toml::from_str(content).unwrap();
        if let Some(mstx_balance) = legacy_config.mstx_balance {
            warn!("'mstx_balance' inside toml config is deprecated, replace with 'ustx_balance'");
            config.ustx_balance = match config.ustx_balance {
                Some(balance) => Some([balance, mstx_balance].concat()),
                None => Some(mstx_balance),
            };
        }
        config
    }

    pub fn neon() -> ConfigFile {
        let burnchain = BurnchainConfigFile {
            mode: Some("neon".to_string()),
            rpc_port: Some(18443),
            peer_port: Some(18444),
            peer_host: Some("neon.blockstack.org".to_string()),
            ..BurnchainConfigFile::default()
        };

        let node = NodeConfigFile {
            bootstrap_node: Some("038dd4f26101715853533dee005f0915375854fd5be73405f679c1917a5d4d16aa@neon.blockstack.org:20444".to_string()),
            miner: Some(false),
            ..NodeConfigFile::default()
        };

        let balances = vec![
            InitialBalanceFile {
                address: "STB44HYPYAT2BB2QE513NSP81HTMYWBJP02HPGK6".to_string(),
                amount: 10000000000000000,
            },
            InitialBalanceFile {
                address: "ST11NJTTKGVT6D1HY4NJRVQWMQM7TVAR091EJ8P2Y".to_string(),
                amount: 10000000000000000,
            },
            InitialBalanceFile {
                address: "ST1HB1T8WRNBYB0Y3T7WXZS38NKKPTBR3EG9EPJKR".to_string(),
                amount: 10000000000000000,
            },
            InitialBalanceFile {
                address: "STRYYQQ9M8KAF4NS7WNZQYY59X93XEKR31JP64CP".to_string(),
                amount: 10000000000000000,
            },
        ];

        ConfigFile {
            burnchain: Some(burnchain),
            node: Some(node),
            ustx_balance: Some(balances),
            ..ConfigFile::default()
        }
    }

    pub fn argon() -> ConfigFile {
        let burnchain = BurnchainConfigFile {
            mode: Some("argon".to_string()),
            rpc_port: Some(18443),
            peer_port: Some(18444),
            peer_host: Some("argon.blockstack.org".to_string()),
            process_exit_at_block_height: Some(28160), // 1 block every 30s, 24 hours * 8 + 300 blocks initially mined for seeding faucet / miner
            ..BurnchainConfigFile::default()
        };

        let node = NodeConfigFile {
            bootstrap_node: Some("048dd4f26101715853533dee005f0915375854fd5be73405f679c1917a5d4d16aaaf3c4c0d7a9c132a36b8c5fe1287f07dad8c910174d789eb24bdfb5ae26f5f27@argon.blockstack.org:20444".to_string()),
            miner: Some(false),
            ..NodeConfigFile::default()
        };

        let balances = vec![
            InitialBalanceFile {
                address: "STB44HYPYAT2BB2QE513NSP81HTMYWBJP02HPGK6".to_string(),
                amount: 10000000000000000,
            },
            InitialBalanceFile {
                address: "ST11NJTTKGVT6D1HY4NJRVQWMQM7TVAR091EJ8P2Y".to_string(),
                amount: 10000000000000000,
            },
            InitialBalanceFile {
                address: "ST1HB1T8WRNBYB0Y3T7WXZS38NKKPTBR3EG9EPJKR".to_string(),
                amount: 10000000000000000,
            },
            InitialBalanceFile {
                address: "STRYYQQ9M8KAF4NS7WNZQYY59X93XEKR31JP64CP".to_string(),
                amount: 10000000000000000,
            },
        ];

        ConfigFile {
            burnchain: Some(burnchain),
            node: Some(node),
            ustx_balance: Some(balances),
            ..ConfigFile::default()
        }
    }

    pub fn krypton() -> ConfigFile {
        let burnchain = BurnchainConfigFile {
            mode: Some("krypton".to_string()),
            rpc_port: Some(18443),
            peer_port: Some(18444),
            peer_host: Some("bitcoind.krypton.blockstack.org".to_string()),
            process_exit_at_block_height: Some(5130), // 1 block every 2m, 24 hours * 7 + 300 blocks initially mined for seeding faucet / miner
            ..BurnchainConfigFile::default()
        };

        let node = NodeConfigFile {
            bootstrap_node: Some("048dd4f26101715853533dee005f0915375854fd5be73405f679c1917a5d4d16aaaf3c4c0d7a9c132a36b8c5fe1287f07dad8c910174d789eb24bdfb5ae26f5f27@krypton.blockstack.org:20444".to_string()),
            miner: Some(false),
            ..NodeConfigFile::default()
        };

        let balances = vec![
            InitialBalanceFile {
                address: "STB44HYPYAT2BB2QE513NSP81HTMYWBJP02HPGK6".to_string(),
                amount: 10000000000000000,
            },
            InitialBalanceFile {
                address: "ST11NJTTKGVT6D1HY4NJRVQWMQM7TVAR091EJ8P2Y".to_string(),
                amount: 10000000000000000,
            },
            InitialBalanceFile {
                address: "ST1HB1T8WRNBYB0Y3T7WXZS38NKKPTBR3EG9EPJKR".to_string(),
                amount: 10000000000000000,
            },
            InitialBalanceFile {
                address: "STRYYQQ9M8KAF4NS7WNZQYY59X93XEKR31JP64CP".to_string(),
                amount: 10000000000000000,
            },
        ];

        ConfigFile {
            burnchain: Some(burnchain),
            node: Some(node),
            ustx_balance: Some(balances),
            ..ConfigFile::default()
        }
    }

    pub fn xenon() -> ConfigFile {
        let burnchain = BurnchainConfigFile {
            mode: Some("xenon".to_string()),
            rpc_port: Some(18332),
            peer_port: Some(18333),
            peer_host: Some("bitcoind.xenon.blockstack.org".to_string()),
            magic_bytes: Some("X4".into()),
            ..BurnchainConfigFile::default()
        };

        let node = NodeConfigFile {
            bootstrap_node: Some("047435c194e9b01b3d7f7a2802d6684a3af68d05bbf4ec8f17021980d777691f1d51651f7f1d566532c804da506c117bbf79ad62eea81213ba58f8808b4d9504ad@xenon.blockstack.org:20444".to_string()),
            miner: Some(false),
            ..NodeConfigFile::default()
        };

        let balances = vec![
            InitialBalanceFile {
                address: "STB44HYPYAT2BB2QE513NSP81HTMYWBJP02HPGK6".to_string(),
                amount: 10000000000000000,
            },
            InitialBalanceFile {
                address: "ST11NJTTKGVT6D1HY4NJRVQWMQM7TVAR091EJ8P2Y".to_string(),
                amount: 10000000000000000,
            },
            InitialBalanceFile {
                address: "ST1HB1T8WRNBYB0Y3T7WXZS38NKKPTBR3EG9EPJKR".to_string(),
                amount: 10000000000000000,
            },
            InitialBalanceFile {
                address: "STRYYQQ9M8KAF4NS7WNZQYY59X93XEKR31JP64CP".to_string(),
                amount: 10000000000000000,
            },
        ];

        ConfigFile {
            burnchain: Some(burnchain),
            node: Some(node),
            ustx_balance: Some(balances),
            ..ConfigFile::default()
        }
    }

    pub fn mainnet() -> ConfigFile {
        let burnchain = BurnchainConfigFile {
            mode: Some("mainnet".to_string()),
            rpc_port: Some(8332),
            peer_port: Some(8333),
            peer_host: Some("bitcoind.blockstack.org".to_string()),
            ..BurnchainConfigFile::default()
        };

        let node = NodeConfigFile {
            bootstrap_node: Some("047435c194e9b01b3d7f7a2802d6684a3af68d05bbf4ec8f17021980d777691f1d51651f7f1d566532c804da506c117bbf79ad62eea81213ba58f8808b4d9504ad@mainnet.blockstack.org:20444".to_string()),
            miner: Some(false),
            ..NodeConfigFile::default()
        };

        ConfigFile {
            burnchain: Some(burnchain),
            node: Some(node),
            ustx_balance: None,
            ..ConfigFile::default()
        }
    }

    pub fn helium() -> ConfigFile {
        // ## Settings for local testnet, relying on a local bitcoind server
        // ## running with the following bitcoin.conf:
        // ##
        // ##    chain=regtest
        // ##    disablewallet=0
        // ##    txindex=1
        // ##    server=1
        // ##    rpcuser=helium
        // ##    rpcpassword=helium
        // ##
        let burnchain = BurnchainConfigFile {
            mode: Some("helium".to_string()),
            commit_anchor_block_within: Some(10_000),
            rpc_port: Some(18443),
            peer_port: Some(18444),
            peer_host: Some("0.0.0.0".to_string()),
            username: Some("helium".to_string()),
            password: Some("helium".to_string()),
            local_mining_public_key: Some("04ee0b1602eb18fef7986887a7e8769a30c9df981d33c8380d255edef003abdcd243a0eb74afdf6740e6c423e62aec631519a24cf5b1d62bf8a3e06ddc695dcb77".to_string()),
            ..BurnchainConfigFile::default()
        };

        let node = NodeConfigFile {
            miner: Some(false),
            ..NodeConfigFile::default()
        };

        ConfigFile {
            burnchain: Some(burnchain),
            node: Some(node),
            ..ConfigFile::default()
        }
    }

    pub fn mocknet() -> ConfigFile {
        let burnchain = BurnchainConfigFile {
            mode: Some("mocknet".to_string()),
            commit_anchor_block_within: Some(10_000),
            ..BurnchainConfigFile::default()
        };

        let node = NodeConfigFile {
            miner: Some(false),
            ..NodeConfigFile::default()
        };

        ConfigFile {
            burnchain: Some(burnchain),
            node: Some(node),
            ..ConfigFile::default()
        }
    }
}

#[derive(Clone)]
pub struct Config {
    pub burnchain: BurnchainConfig,
    pub node: NodeConfig,
    pub initial_balances: Vec<InitialBalance>,
    pub events_observers: Vec<EventObserverConfig>,
    pub connection_options: ConnectionOptions,
    pub block_limit: ExecutionCost,
}

lazy_static! {
    static ref HELIUM_DEFAULT_CONNECTION_OPTIONS: ConnectionOptions = ConnectionOptions {
        inbox_maxlen: 100,
        outbox_maxlen: 100,
        timeout: 30,
        idle_timeout: 15,               // how long a HTTP connection can be idle before it's closed
        heartbeat: 3600,
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
        walk_interval: 30,
        inv_sync_interval: 45,
        download_interval: 10,
        dns_timeout: 15_000,
        max_inflight_blocks: 6,
        max_inflight_attachments: 6,
        .. std::default::Default::default()
    };
}

pub const HELIUM_BLOCK_LIMIT: ExecutionCost = ExecutionCost {
    write_length: 15_0_000_000,
    write_count: 5_0_000,
    read_length: 1_000_000_000,
    read_count: 5_0_000,
    // allow much more runtime in helium blocks than mainnet
    runtime: 100_000_000_000,
};

pub const MAINNET_BLOCK_LIMIT: ExecutionCost = ExecutionCost {
    write_length: 15_000_000, // roughly 15 mb
    write_count: 7_750,
    read_length: 100_000_000,
    read_count: 7_750,
    runtime: 5_000_000_000,
};

impl Config {
    pub fn from_config_file(config_file: ConfigFile) -> Config {
        let default_node_config = NodeConfig::default();
        let (mut node, bootstrap_node, deny_nodes) = match config_file.node {
            Some(node) => {
                let rpc_bind = node.rpc_bind.unwrap_or(default_node_config.rpc_bind);
                let node_config = NodeConfig {
                    name: node.name.unwrap_or(default_node_config.name),
                    seed: match node.seed {
                        Some(seed) => {
                            hex_bytes(&seed).expect("Seed should be a hex encoded string")
                        }
                        None => default_node_config.seed,
                    },
                    working_dir: node.working_dir.unwrap_or(default_node_config.working_dir),
                    rpc_bind: rpc_bind.clone(),
                    p2p_bind: node.p2p_bind.unwrap_or(default_node_config.p2p_bind),
                    p2p_address: node.p2p_address.unwrap_or(rpc_bind.clone()),
                    bootstrap_node: None,
                    deny_nodes: vec![],
                    data_url: match node.data_url {
                        Some(data_url) => data_url,
                        None => format!("http://{}", rpc_bind),
                    },
                    local_peer_seed: match node.local_peer_seed {
                        Some(seed) => {
                            hex_bytes(&seed).expect("Seed should be a hex encoded string")
                        }
                        None => default_node_config.local_peer_seed,
                    },
                    miner: node.miner.unwrap_or(default_node_config.miner),
                    mine_microblocks: node
                        .mine_microblocks
                        .unwrap_or(default_node_config.mine_microblocks),
                    microblock_frequency: node
                        .microblock_frequency
                        .unwrap_or(default_node_config.microblock_frequency),
                    max_microblocks: node
                        .max_microblocks
                        .unwrap_or(default_node_config.max_microblocks),
                    wait_time_for_microblocks: node
                        .wait_time_for_microblocks
                        .unwrap_or(default_node_config.wait_time_for_microblocks),
                    prometheus_bind: node.prometheus_bind,
                    pox_sync_sample_secs: node
                        .pox_sync_sample_secs
                        .unwrap_or(default_node_config.pox_sync_sample_secs),
                    use_test_genesis_chainstate: node.use_test_genesis_chainstate,
                };
                (node_config, node.bootstrap_node, node.deny_nodes)
            }
            None => (default_node_config, None, None),
        };

        let default_burnchain_config = BurnchainConfig::default();

        let burnchain = match config_file.burnchain {
            Some(mut burnchain) => {
                if burnchain.mode.as_deref() == Some("xenon") {
                    if burnchain.magic_bytes.is_none() {
                        burnchain.magic_bytes = ConfigFile::xenon().burnchain.unwrap().magic_bytes;
                    }
                }
                let burnchain_mode = burnchain.mode.unwrap_or(default_burnchain_config.mode);

                BurnchainConfig {
                    chain: burnchain.chain.unwrap_or(default_burnchain_config.chain),
                    chain_id: if &burnchain_mode == "mainnet" {
                        MAINNET_CHAIN_ID
                    } else {
                        TESTNET_CHAIN_ID
                    },
                    peer_version: if &burnchain_mode == "mainnet" {
                        MAINNET_PEER_VERSION
                    } else {
                        TESTNET_PEER_VERSION
                    },
                    mode: burnchain_mode.clone(),
                    burn_fee_cap: burnchain
                        .burn_fee_cap
                        .unwrap_or(default_burnchain_config.burn_fee_cap),
                    commit_anchor_block_within: burnchain
                        .commit_anchor_block_within
                        .unwrap_or(default_burnchain_config.commit_anchor_block_within),
                    peer_host: match burnchain.peer_host {
                        Some(peer_host) => {
                            // Using std::net::LookupHost would be preferable, but it's
                            // unfortunately unstable at this point.
                            // https://doc.rust-lang.org/1.6.0/std/net/struct.LookupHost.html
                            let mut addrs_iter =
                                format!("{}:1", peer_host).to_socket_addrs().unwrap();
                            let sock_addr = addrs_iter.next().unwrap();
                            format!("{}", sock_addr.ip())
                        }
                        None => default_burnchain_config.peer_host,
                    },
                    peer_port: burnchain
                        .peer_port
                        .unwrap_or(default_burnchain_config.peer_port),
                    rpc_port: burnchain
                        .rpc_port
                        .unwrap_or(default_burnchain_config.rpc_port),
                    rpc_ssl: burnchain
                        .rpc_ssl
                        .unwrap_or(default_burnchain_config.rpc_ssl),
                    username: burnchain.username,
                    password: burnchain.password,
                    timeout: burnchain
                        .timeout
                        .unwrap_or(default_burnchain_config.timeout),
                    spv_headers_path: burnchain
                        .spv_headers_path
                        .unwrap_or(node.get_default_spv_headers_path()),
                    magic_bytes: burnchain
                        .magic_bytes
                        .map(|magic_ascii| {
                            assert_eq!(magic_ascii.len(), 2, "Magic bytes must be length-2");
                            assert!(magic_ascii.is_ascii(), "Magic bytes must be ASCII");
                            MagicBytes::from(magic_ascii.as_bytes())
                        })
                        .unwrap_or(default_burnchain_config.magic_bytes),
                    local_mining_public_key: burnchain.local_mining_public_key,
                    burnchain_op_tx_fee: burnchain
                        .burnchain_op_tx_fee
                        .unwrap_or(default_burnchain_config.burnchain_op_tx_fee),
                    process_exit_at_block_height: burnchain.process_exit_at_block_height,
                    poll_time_secs: burnchain
                        .poll_time_secs
                        .unwrap_or(default_burnchain_config.poll_time_secs),
                }
            }
            None => default_burnchain_config,
        };

        let supported_modes = vec![
            "mocknet", "helium", "neon", "argon", "krypton", "xenon", "mainnet",
        ];

        if !supported_modes.contains(&burnchain.mode.as_str()) {
            panic!(
                "Setting burnchain.network not supported (should be: {})",
                supported_modes.join(", ")
            )
        }

        if burnchain.mode == "helium" && burnchain.local_mining_public_key.is_none() {
            panic!("Config is missing the setting `burnchain.local_mining_public_key` (mandatory for helium)")
        }

        node.set_bootstrap_node(bootstrap_node, burnchain.chain_id, burnchain.peer_version);
        if let Some(deny_nodes) = deny_nodes {
            node.set_deny_nodes(deny_nodes, burnchain.chain_id, burnchain.peer_version);
        }

        let initial_balances: Vec<InitialBalance> = match config_file.ustx_balance {
            Some(balances) => balances
                .iter()
                .map(|balance| {
                    let address: PrincipalData =
                        PrincipalData::parse_standard_principal(&balance.address)
                            .unwrap()
                            .into();
                    InitialBalance {
                        address,
                        amount: balance.amount,
                    }
                })
                .collect(),
            None => vec![],
        };

        let mut events_observers = match config_file.events_observer {
            Some(raw_observers) => {
                let mut observers = vec![];
                for observer in raw_observers {
                    let events_keys: Vec<EventKeyType> = observer
                        .events_keys
                        .iter()
                        .map(|e| EventKeyType::from_string(e).unwrap())
                        .collect();

                    let endpoint = format!("{}", observer.endpoint);

                    observers.push(EventObserverConfig {
                        endpoint,
                        events_keys,
                    });
                }
                observers
            }
            None => vec![],
        };

        // check for observer config in env vars
        match std::env::var("STACKS_EVENT_OBSERVER") {
            Ok(val) => events_observers.push(EventObserverConfig {
                endpoint: val,
                events_keys: vec![EventKeyType::AnyEvent],
            }),
            _ => (),
        };

        let connection_options = match config_file.connection_options {
            Some(opts) => {
                let ip_addr = match opts.public_ip_address {
                    Some(public_ip_address) => {
                        let addr = public_ip_address.parse::<SocketAddr>().unwrap();
                        debug!("addr.parse {:?}", addr);
                        Some((PeerAddress::from_socketaddr(&addr), addr.port()))
                    }
                    None => None,
                };
                let mut read_only_call_limit = HELIUM_DEFAULT_CONNECTION_OPTIONS
                    .read_only_call_limit
                    .clone();
                opts.read_only_call_limit_write_length.map(|x| {
                    read_only_call_limit.write_length = x;
                });
                opts.read_only_call_limit_write_count.map(|x| {
                    read_only_call_limit.write_count = x;
                });
                opts.read_only_call_limit_read_length.map(|x| {
                    read_only_call_limit.read_length = x;
                });
                opts.read_only_call_limit_read_count.map(|x| {
                    read_only_call_limit.read_count = x;
                });
                opts.read_only_call_limit_runtime.map(|x| {
                    read_only_call_limit.runtime = x;
                });
                ConnectionOptions {
                    read_only_call_limit,
                    inbox_maxlen: opts
                        .inbox_maxlen
                        .unwrap_or_else(|| HELIUM_DEFAULT_CONNECTION_OPTIONS.inbox_maxlen.clone()),
                    outbox_maxlen: opts
                        .outbox_maxlen
                        .unwrap_or_else(|| HELIUM_DEFAULT_CONNECTION_OPTIONS.outbox_maxlen.clone()),
                    timeout: opts
                        .timeout
                        .unwrap_or_else(|| HELIUM_DEFAULT_CONNECTION_OPTIONS.timeout.clone()),
                    idle_timeout: opts
                        .idle_timeout
                        .unwrap_or_else(|| HELIUM_DEFAULT_CONNECTION_OPTIONS.idle_timeout.clone()),
                    heartbeat: opts
                        .heartbeat
                        .unwrap_or_else(|| HELIUM_DEFAULT_CONNECTION_OPTIONS.heartbeat.clone()),
                    private_key_lifetime: opts.private_key_lifetime.unwrap_or_else(|| {
                        HELIUM_DEFAULT_CONNECTION_OPTIONS
                            .private_key_lifetime
                            .clone()
                    }),
                    num_neighbors: opts
                        .num_neighbors
                        .unwrap_or_else(|| HELIUM_DEFAULT_CONNECTION_OPTIONS.num_neighbors.clone()),
                    num_clients: opts
                        .num_clients
                        .unwrap_or_else(|| HELIUM_DEFAULT_CONNECTION_OPTIONS.num_clients.clone()),
                    soft_num_neighbors: opts.soft_num_neighbors.unwrap_or_else(|| {
                        HELIUM_DEFAULT_CONNECTION_OPTIONS.soft_num_neighbors.clone()
                    }),
                    soft_num_clients: opts.soft_num_clients.unwrap_or_else(|| {
                        HELIUM_DEFAULT_CONNECTION_OPTIONS.soft_num_clients.clone()
                    }),
                    max_neighbors_per_host: opts.max_neighbors_per_host.unwrap_or_else(|| {
                        HELIUM_DEFAULT_CONNECTION_OPTIONS
                            .max_neighbors_per_host
                            .clone()
                    }),
                    max_clients_per_host: opts.max_clients_per_host.unwrap_or_else(|| {
                        HELIUM_DEFAULT_CONNECTION_OPTIONS
                            .max_clients_per_host
                            .clone()
                    }),
                    soft_max_neighbors_per_host: opts.soft_max_neighbors_per_host.unwrap_or_else(
                        || {
                            HELIUM_DEFAULT_CONNECTION_OPTIONS
                                .soft_max_neighbors_per_host
                                .clone()
                        },
                    ),
                    soft_max_neighbors_per_org: opts.soft_max_neighbors_per_org.unwrap_or_else(
                        || {
                            HELIUM_DEFAULT_CONNECTION_OPTIONS
                                .soft_max_neighbors_per_org
                                .clone()
                        },
                    ),
                    soft_max_clients_per_host: opts.soft_max_clients_per_host.unwrap_or_else(
                        || {
                            HELIUM_DEFAULT_CONNECTION_OPTIONS
                                .soft_max_clients_per_host
                                .clone()
                        },
                    ),
                    walk_interval: opts
                        .walk_interval
                        .unwrap_or_else(|| HELIUM_DEFAULT_CONNECTION_OPTIONS.walk_interval.clone()),
                    dns_timeout: opts
                        .dns_timeout
                        .unwrap_or_else(|| HELIUM_DEFAULT_CONNECTION_OPTIONS.dns_timeout.clone()),
                    max_inflight_blocks: opts.max_inflight_blocks.unwrap_or_else(|| {
                        HELIUM_DEFAULT_CONNECTION_OPTIONS
                            .max_inflight_blocks
                            .clone()
                    }),
                    max_inflight_attachments: opts.max_inflight_attachments.unwrap_or_else(|| {
                        HELIUM_DEFAULT_CONNECTION_OPTIONS
                            .max_inflight_attachments
                            .clone()
                    }),
                    maximum_call_argument_size: opts.maximum_call_argument_size.unwrap_or_else(
                        || {
                            HELIUM_DEFAULT_CONNECTION_OPTIONS
                                .maximum_call_argument_size
                                .clone()
                        },
                    ),
                    download_interval: opts.download_interval.unwrap_or_else(|| {
                        HELIUM_DEFAULT_CONNECTION_OPTIONS.download_interval.clone()
                    }),
                    inv_sync_interval: opts.inv_sync_interval.unwrap_or_else(|| {
                        HELIUM_DEFAULT_CONNECTION_OPTIONS.inv_sync_interval.clone()
                    }),
                    public_ip_address: ip_addr,
                    disable_inbound_walks: opts.disable_inbound_walks.unwrap_or(false),
                    disable_inbound_handshakes: opts.disable_inbound_handshakes.unwrap_or(false),
                    force_disconnect_interval: opts.force_disconnect_interval,
                    ..ConnectionOptions::default()
                }
            }
            None => HELIUM_DEFAULT_CONNECTION_OPTIONS.clone(),
        };

        let block_limit = if burnchain.mode == "mainnet" || burnchain.mode == "xenon" {
            MAINNET_BLOCK_LIMIT.clone()
        } else {
            match config_file.block_limit {
                Some(opts) => ExecutionCost {
                    write_length: opts
                        .write_length
                        .unwrap_or(HELIUM_BLOCK_LIMIT.write_length.clone()),
                    write_count: opts
                        .write_count
                        .unwrap_or(HELIUM_BLOCK_LIMIT.write_count.clone()),
                    read_length: opts
                        .read_length
                        .unwrap_or(HELIUM_BLOCK_LIMIT.read_length.clone()),
                    read_count: opts
                        .read_count
                        .unwrap_or(HELIUM_BLOCK_LIMIT.read_count.clone()),
                    runtime: opts.runtime.unwrap_or(HELIUM_BLOCK_LIMIT.runtime.clone()),
                },
                None => HELIUM_BLOCK_LIMIT.clone(),
            }
        };

        Config {
            node,
            burnchain,
            initial_balances,
            events_observers,
            connection_options,
            block_limit,
        }
    }

    pub fn get_burnchain_path(&self) -> String {
        format!("{}/burnchain/", self.node.working_dir)
    }

    pub fn get_burn_db_path(&self) -> String {
        format!("{}/burnchain/db", self.node.working_dir)
    }

    pub fn get_burn_db_file_path(&self) -> String {
        let dir_name = if self.burnchain.mode.as_str() == "mocknet" {
            "mocknet".to_string()
        } else {
            let (network, _) = self.burnchain.get_bitcoin_network();
            network
        };
        format!(
            "{}/burnchain/db/{}/{}/sortition.db/",
            self.node.working_dir, self.burnchain.chain, dir_name
        )
    }

    pub fn get_chainstate_path(&self) -> String {
        format!("{}/chainstate/", self.node.working_dir)
    }

    pub fn get_peer_db_path(&self) -> String {
        format!("{}/peer_db.sqlite", self.node.working_dir)
    }

    pub fn get_atlas_db_path(&self) -> String {
        format!("{}/chainstate/atlas_db.sqlite", self.node.working_dir)
    }

    pub fn add_initial_balance(&mut self, address: String, amount: u64) {
        let new_balance = InitialBalance {
            address: PrincipalData::parse_standard_principal(&address)
                .unwrap()
                .into(),
            amount,
        };
        self.initial_balances.push(new_balance);
    }

    pub fn get_initial_liquid_ustx(&self) -> u128 {
        let mut total = 0;
        for ib in self.initial_balances.iter() {
            total += ib.amount as u128
        }
        total
    }

    pub fn is_mainnet(&self) -> bool {
        match self.burnchain.mode.as_str() {
            "mainnet" => true,
            _ => false,
        }
    }
}

impl std::default::Default for Config {
    fn default() -> Config {
        // Testnet's name
        let node = NodeConfig {
            ..NodeConfig::default()
        };

        let mut burnchain = BurnchainConfig {
            ..BurnchainConfig::default()
        };

        burnchain.spv_headers_path = node.get_default_spv_headers_path();

        let connection_options = HELIUM_DEFAULT_CONNECTION_OPTIONS.clone();
        let block_limit = HELIUM_BLOCK_LIMIT.clone();

        Config {
            burnchain,
            node,
            initial_balances: vec![],
            events_observers: vec![],
            connection_options,
            block_limit,
        }
    }
}

#[derive(Clone, Debug, Default)]
pub struct BurnchainConfig {
    pub chain: String,
    pub mode: String,
    pub chain_id: u32,
    pub peer_version: u32,
    pub commit_anchor_block_within: u64,
    pub burn_fee_cap: u64,
    pub peer_host: String,
    pub peer_port: u16,
    pub rpc_port: u16,
    pub rpc_ssl: bool,
    pub username: Option<String>,
    pub password: Option<String>,
    pub timeout: u32,
    pub spv_headers_path: String,
    pub magic_bytes: MagicBytes,
    pub local_mining_public_key: Option<String>,
    pub burnchain_op_tx_fee: u64,
    pub process_exit_at_block_height: Option<u64>,
    pub poll_time_secs: u64,
}

impl BurnchainConfig {
    fn default() -> BurnchainConfig {
        BurnchainConfig {
            chain: "bitcoin".to_string(),
            mode: "mocknet".to_string(),
            chain_id: TESTNET_CHAIN_ID,
            peer_version: TESTNET_PEER_VERSION,
            burn_fee_cap: 20000,
            commit_anchor_block_within: 5000,
            peer_host: "0.0.0.0".to_string(),
            peer_port: 8333,
            rpc_port: 8332,
            rpc_ssl: false,
            username: None,
            password: None,
            timeout: 300,
            spv_headers_path: "./spv-headers.dat".to_string(),
            magic_bytes: BLOCKSTACK_MAGIC_MAINNET.clone(),
            local_mining_public_key: None,
            burnchain_op_tx_fee: MINIMUM_DUST_FEE,
            process_exit_at_block_height: None,
            poll_time_secs: 10, // TODO: this is a testnet specific value.
        }
    }

    pub fn get_rpc_url(&self) -> String {
        let scheme = match self.rpc_ssl {
            true => "https://",
            false => "http://",
        };
        format!("{}{}:{}", scheme, self.peer_host, self.rpc_port)
    }

    pub fn get_rpc_socket_addr(&self) -> SocketAddr {
        let mut addrs_iter = format!("{}:{}", self.peer_host, self.rpc_port)
            .to_socket_addrs()
            .unwrap();
        let sock_addr = addrs_iter.next().unwrap();
        sock_addr
    }

    pub fn get_bitcoin_network(&self) -> (String, BitcoinNetworkType) {
        match self.mode.as_str() {
            "mainnet" => ("mainnet".to_string(), BitcoinNetworkType::Mainnet),
            "xenon" => ("testnet".to_string(), BitcoinNetworkType::Testnet),
            "helium" | "neon" | "argon" | "krypton" => {
                ("regtest".to_string(), BitcoinNetworkType::Regtest)
            }
            _ => panic!("Invalid bitcoin mode -- expected mainnet, testnet, or regtest"),
        }
    }
}

#[derive(Clone, Deserialize, Default)]
pub struct BurnchainConfigFile {
    pub chain: Option<String>,
    pub burn_fee_cap: Option<u64>,
    pub mode: Option<String>,
    pub commit_anchor_block_within: Option<u64>,
    pub peer_host: Option<String>,
    pub peer_port: Option<u16>,
    pub rpc_port: Option<u16>,
    pub rpc_ssl: Option<bool>,
    pub username: Option<String>,
    pub password: Option<String>,
    pub timeout: Option<u32>,
    pub spv_headers_path: Option<String>,
    pub magic_bytes: Option<String>,
    pub local_mining_public_key: Option<String>,
    pub burnchain_op_tx_fee: Option<u64>,
    pub process_exit_at_block_height: Option<u64>,
    pub poll_time_secs: Option<u64>,
}

#[derive(Clone, Debug, Default)]
pub struct NodeConfig {
    pub name: String,
    pub seed: Vec<u8>,
    pub working_dir: String,
    pub rpc_bind: String,
    pub p2p_bind: String,
    pub data_url: String,
    pub p2p_address: String,
    pub local_peer_seed: Vec<u8>,
    pub bootstrap_node: Option<Neighbor>,
    pub deny_nodes: Vec<Neighbor>,
    pub miner: bool,
    pub mine_microblocks: bool,
    pub microblock_frequency: u64,
    pub max_microblocks: u64,
    pub wait_time_for_microblocks: u64,
    pub prometheus_bind: Option<String>,
    pub pox_sync_sample_secs: u64,
    pub use_test_genesis_chainstate: Option<bool>,
}

impl NodeConfig {
    fn default() -> NodeConfig {
        let mut rng = rand::thread_rng();
        let mut buf = [0u8; 8];
        rng.fill_bytes(&mut buf);

        let testnet_id = format!("stacks-testnet-{}", to_hex(&buf));

        let rpc_port = 20443;
        let p2p_port = 20444;

        let mut local_peer_seed = [0u8; 32];
        rng.fill_bytes(&mut local_peer_seed);

        let mut seed = [0u8; 32];
        rng.fill_bytes(&mut seed);

        let name = "helium-node";
        NodeConfig {
            name: name.to_string(),
            seed: seed.to_vec(),
            working_dir: format!("/tmp/{}", testnet_id),
            rpc_bind: format!("0.0.0.0:{}", rpc_port),
            p2p_bind: format!("0.0.0.0:{}", p2p_port),
            data_url: format!("http://127.0.0.1:{}", rpc_port),
            p2p_address: format!("127.0.0.1:{}", rpc_port),
            bootstrap_node: None,
            deny_nodes: vec![],
            local_peer_seed: local_peer_seed.to_vec(),
            miner: false,
            mine_microblocks: false,
            microblock_frequency: 5000,
            max_microblocks: u16::MAX as u64,
            wait_time_for_microblocks: 5000,
            prometheus_bind: None,
            pox_sync_sample_secs: 30,
            use_test_genesis_chainstate: None,
        }
    }

    pub fn get_burnchain_path(&self) -> String {
        format!("{}/burnchain", self.working_dir)
    }

    pub fn get_default_spv_headers_path(&self) -> String {
        format!("{}/spv-headers.dat", self.get_burnchain_path())
    }

    fn default_neighbor(
        addr: SocketAddr,
        pubk: Secp256k1PublicKey,
        chain_id: u32,
        peer_version: u32,
    ) -> Neighbor {
        Neighbor {
            addr: NeighborKey {
                peer_version: peer_version,
                network_id: chain_id,
                addrbytes: PeerAddress::from_socketaddr(&addr),
                port: addr.port(),
            },
            public_key: pubk,
            expire_block: 9999999,
            last_contact_time: 0,
            allowed: 0,
            denied: 0,
            asn: 0,
            org: 0,
            in_degree: 0,
            out_degree: 0,
        }
    }

    pub fn set_bootstrap_node(
        &mut self,
        bootstrap_node: Option<String>,
        chain_id: u32,
        peer_version: u32,
    ) {
        if let Some(bootstrap_node) = bootstrap_node {
            let comps: Vec<&str> = bootstrap_node.split("@").collect();
            match comps[..] {
                [public_key, peer_addr] => {
                    let mut pubk = Secp256k1PublicKey::from_hex(public_key).unwrap();
                    pubk.set_compressed(true);

                    let mut addrs_iter = peer_addr.to_socket_addrs().unwrap();
                    let sock_addr = addrs_iter.next().unwrap();
                    let neighbor =
                        NodeConfig::default_neighbor(sock_addr, pubk, chain_id, peer_version);
                    self.bootstrap_node = Some(neighbor);
                }
                _ => {}
            }
        }
    }

    pub fn add_deny_node(&mut self, deny_node: &str, chain_id: u32, peer_version: u32) {
        let sockaddr = deny_node.to_socket_addrs().unwrap().next().unwrap();
        let neighbor = NodeConfig::default_neighbor(
            sockaddr,
            Secp256k1PublicKey::from_private(&Secp256k1PrivateKey::new()),
            chain_id,
            peer_version,
        );
        self.deny_nodes.push(neighbor);
    }

    pub fn set_deny_nodes(&mut self, deny_nodes: String, chain_id: u32, peer_version: u32) {
        let parts: Vec<&str> = deny_nodes.split(",").collect();
        for part in parts.into_iter() {
            if part.len() > 0 {
                self.add_deny_node(&part, chain_id, peer_version);
            }
        }
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
    pub max_inflight_attachments: Option<u64>,
    pub read_only_call_limit_write_length: Option<u64>,
    pub read_only_call_limit_read_length: Option<u64>,
    pub read_only_call_limit_write_count: Option<u64>,
    pub read_only_call_limit_read_count: Option<u64>,
    pub read_only_call_limit_runtime: Option<u64>,
    pub maximum_call_argument_size: Option<u32>,
    pub download_interval: Option<u64>,
    pub inv_sync_interval: Option<u64>,
    pub public_ip_address: Option<String>,
    pub disable_inbound_walks: Option<bool>,
    pub disable_inbound_handshakes: Option<bool>,
    pub force_disconnect_interval: Option<u64>,
}

#[derive(Clone, Default, Deserialize)]
pub struct BlockLimitFile {
    pub write_length: Option<u64>,
    pub read_length: Option<u64>,
    pub write_count: Option<u64>,
    pub read_count: Option<u64>,
    pub runtime: Option<u64>,
}

#[derive(Clone, Deserialize, Default)]
pub struct NodeConfigFile {
    pub name: Option<String>,
    pub seed: Option<String>,
    pub deny_nodes: Option<String>,
    pub working_dir: Option<String>,
    pub rpc_bind: Option<String>,
    pub p2p_bind: Option<String>,
    pub p2p_address: Option<String>,
    pub data_url: Option<String>,
    pub bootstrap_node: Option<String>,
    pub local_peer_seed: Option<String>,
    pub miner: Option<bool>,
    pub mine_microblocks: Option<bool>,
    pub microblock_frequency: Option<u64>,
    pub max_microblocks: Option<u64>,
    pub wait_time_for_microblocks: Option<u64>,
    pub prometheus_bind: Option<String>,
    pub pox_sync_sample_secs: Option<u64>,
    pub use_test_genesis_chainstate: Option<bool>,
}

#[derive(Clone, Deserialize, Default)]
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
    MemPoolTransactions,
    AnyEvent,
    BurnchainBlocks,
}

impl EventKeyType {
    fn from_string(raw_key: &str) -> Option<EventKeyType> {
        if raw_key == "*" {
            return Some(EventKeyType::AnyEvent);
        }

        if raw_key == "stx" {
            return Some(EventKeyType::STXEvent);
        }

        if raw_key == "memtx" {
            return Some(EventKeyType::MemPoolTransactions);
        }

        if raw_key == "burn_blocks" {
            return Some(EventKeyType::BurnchainBlocks);
        }

        let comps: Vec<_> = raw_key.split("::").collect();
        if comps.len() == 1 {
            let split: Vec<_> = comps[0].split(".").collect();
            if split.len() != 3 {
                return None;
            }
            let components = (
                PrincipalData::parse_standard_principal(split[0]),
                split[1].to_string().try_into(),
                split[2].to_string().try_into(),
            );
            match components {
                (Ok(address), Ok(name), Ok(asset_name)) => {
                    let contract_identifier = QualifiedContractIdentifier::new(address, name);
                    let asset_identifier = AssetIdentifier {
                        contract_identifier,
                        asset_name,
                    };
                    Some(EventKeyType::AssetEvent(asset_identifier))
                }
                (_, _, _) => None,
            }
        } else if comps.len() == 2 {
            if let Ok(contract_identifier) = QualifiedContractIdentifier::parse(comps[0]) {
                Some(EventKeyType::SmartContractEvent((
                    contract_identifier,
                    comps[1].to_string(),
                )))
            } else {
                None
            }
        } else {
            None
        }
    }
}

#[derive(Debug, Clone, Deserialize)]
pub struct InitialBalance {
    pub address: PrincipalData,
    pub amount: u64,
}

#[derive(Clone, Deserialize, Default)]
pub struct InitialBalanceFile {
    pub address: String,
    pub amount: u64,
}
