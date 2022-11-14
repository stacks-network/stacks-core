use std::convert::TryInto;
use std::fs;
use std::net::{SocketAddr, ToSocketAddrs};
use std::path::PathBuf;
use std::sync::Arc;
use std::sync::Mutex;

use rand::RngCore;

use stacks::burnchains::bitcoin::BitcoinNetworkType;
use stacks::burnchains::PoxConstants;
use stacks::burnchains::{MagicBytes, BLOCKSTACK_MAGIC_MAINNET};
use stacks::chainstate::stacks::index::marf::MARFOpenOpts;
use stacks::chainstate::stacks::index::storage::TrieHashCalculationMode;
use stacks::chainstate::stacks::miner::BlockBuilderSettings;
use stacks::chainstate::stacks::miner::MinerStatus;
use stacks::chainstate::stacks::MAX_BLOCK_LEN;
use stacks::core::mempool::MemPoolWalkSettings;
use stacks::core::StacksEpoch;
use stacks::core::StacksEpochId;
use stacks::core::{
    CHAIN_ID_MAINNET, CHAIN_ID_TESTNET, PEER_VERSION_MAINNET, PEER_VERSION_TESTNET,
};
use stacks::cost_estimates::fee_medians::WeightedMedianFeeRateEstimator;
use stacks::cost_estimates::fee_rate_fuzzer::FeeRateFuzzer;
use stacks::cost_estimates::fee_scalar::ScalarFeeRateEstimator;
use stacks::cost_estimates::metrics::CostMetric;
use stacks::cost_estimates::metrics::ProportionalDotProduct;
use stacks::cost_estimates::CostEstimator;
use stacks::cost_estimates::FeeEstimator;
use stacks::cost_estimates::PessimisticEstimator;
use stacks::net::connection::ConnectionOptions;
use stacks::net::{Neighbor, NeighborKey, PeerAddress};
use stacks::util::get_epoch_time_ms;
use stacks::util::hash::hex_bytes;
use stacks::util::secp256k1::Secp256k1PrivateKey;
use stacks::util::secp256k1::Secp256k1PublicKey;
use stacks::vm::costs::ExecutionCost;
use stacks::vm::types::{AssetIdentifier, PrincipalData, QualifiedContractIdentifier};

const DEFAULT_SATS_PER_VB: u64 = 50;
const DEFAULT_MAX_RBF_RATE: u64 = 150; // 1.5x
const DEFAULT_RBF_FEE_RATE_INCREMENT: u64 = 5;
const LEADER_KEY_TX_ESTIM_SIZE: u64 = 290;
const BLOCK_COMMIT_TX_ESTIM_SIZE: u64 = 350;
const INV_REWARD_CYCLES_TESTNET: u64 = 6;

#[derive(Clone, Deserialize, Default, Debug)]
pub struct ConfigFile {
    pub burnchain: Option<BurnchainConfigFile>,
    pub node: Option<NodeConfigFile>,
    pub ustx_balance: Option<Vec<InitialBalanceFile>>,
    pub events_observer: Option<Vec<EventObserverConfigFile>>,
    pub connection_options: Option<ConnectionOptionsFile>,
    pub fee_estimation: Option<FeeEstimationConfigFile>,
    pub miner: Option<MinerConfigFile>,
}

#[derive(Clone, Deserialize, Default)]
pub struct LegacyMstxConfigFile {
    pub mstx_balance: Option<Vec<InitialBalanceFile>>,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_config_file() {
        assert_eq!(
            format!("Invalid path: No such file or directory (os error 2)"),
            ConfigFile::from_path("some_path").unwrap_err()
        );
        assert_eq!(
            format!("Invalid toml: unexpected character found: `/` at line 1 column 1"),
            ConfigFile::from_str("//[node]").unwrap_err()
        );
        assert!(ConfigFile::from_str("").is_ok());
    }

    #[test]
    fn test_config() {
        assert_eq!(
            format!("node.seed should be a hex encoded string"),
            Config::from_config_file(
                ConfigFile::from_str(
                    r#"
                    [node]
                    seed = "invalid-hex-value"
                    "#,
                )
                .unwrap()
            )
            .unwrap_err()
        );

        assert_eq!(
            format!("node.local_peer_seed should be a hex encoded string"),
            Config::from_config_file(
                ConfigFile::from_str(
                    r#"
                    [node]
                    local_peer_seed = "invalid-hex-value"
                    "#,
                )
                .unwrap()
            )
            .unwrap_err()
        );

        let expected_err_prefix =
            "Invalid burnchain.peer_host: failed to lookup address information:";
        let actual_err_msg = Config::from_config_file(
            ConfigFile::from_str(
                r#"
                [burnchain]
                peer_host = "bitcoin2.blockstack.com"
                "#,
            )
            .unwrap(),
        )
        .unwrap_err();
        assert_eq!(
            expected_err_prefix,
            &actual_err_msg[..expected_err_prefix.len()]
        );

        assert!(Config::from_config_file(ConfigFile::from_str("").unwrap()).is_ok());
    }

    #[test]
    fn should_load_legacy_mstx_balances_toml() {
        let config = ConfigFile::from_str(
            r#"
            [[ustx_balance]]
            address = "ST2QKZ4FKHAH1NQKYKYAYZPY440FEPK7GZ1R5HBP2"
            amount = 10000000000000000

            [[ustx_balance]]
            address = "ST319CF5WV77KYR1H3GT0GZ7B8Q4AQPY42ETP1VPF"
            amount = 10000000000000000

            [[mstx_balance]] # legacy property name
            address = "ST221Z6TDTC5E0BYR2V624Q2ST6R0Q71T78WTAX6H"
            amount = 10000000000000000

            [[mstx_balance]] # legacy property name
            address = "ST2TFVBMRPS5SSNP98DQKQ5JNB2B6NZM91C4K3P7B"
            amount = 10000000000000000
            "#,
        );
        let config = config.unwrap();
        assert!(config.ustx_balance.is_some());
        let balances = config
            .ustx_balance
            .expect("Failed to parse stx balances from toml");
        assert_eq!(balances.len(), 4);
        assert_eq!(
            balances[0].address,
            "ST2QKZ4FKHAH1NQKYKYAYZPY440FEPK7GZ1R5HBP2"
        );
        assert_eq!(
            balances[1].address,
            "ST319CF5WV77KYR1H3GT0GZ7B8Q4AQPY42ETP1VPF"
        );
        assert_eq!(
            balances[2].address,
            "ST221Z6TDTC5E0BYR2V624Q2ST6R0Q71T78WTAX6H"
        );
        assert_eq!(
            balances[3].address,
            "ST2TFVBMRPS5SSNP98DQKQ5JNB2B6NZM91C4K3P7B"
        );
    }
}

impl ConfigFile {
    pub fn from_path(path: &str) -> Result<ConfigFile, String> {
        let content = fs::read_to_string(path).map_err(|e| format!("Invalid path: {}", &e))?;
        Self::from_str(&content)
    }

    pub fn from_str(content: &str) -> Result<ConfigFile, String> {
        let mut config: ConfigFile =
            toml::from_str(content).map_err(|e| format!("Invalid toml: {}", e))?;
        let legacy_config: LegacyMstxConfigFile = toml::from_str(content).unwrap();
        if let Some(mstx_balance) = legacy_config.mstx_balance {
            warn!("'mstx_balance' inside toml config is deprecated, replace with 'ustx_balance'");
            config.ustx_balance = match config.ustx_balance {
                Some(balance) => Some([balance, mstx_balance].concat()),
                None => Some(mstx_balance),
            };
        }
        Ok(config)
    }

    pub fn xenon() -> ConfigFile {
        let burnchain = BurnchainConfigFile {
            mode: Some("xenon".to_string()),
            rpc_port: Some(18332),
            peer_port: Some(18333),
            peer_host: Some("bitcoind.xenon.blockstack.org".to_string()),
            magic_bytes: Some("T2".into()),
            ..BurnchainConfigFile::default()
        };

        let node = NodeConfigFile {
            bootstrap_node: Some("047435c194e9b01b3d7f7a2802d6684a3af68d05bbf4ec8f17021980d777691f1d51651f7f1d566532c804da506c117bbf79ad62eea81213ba58f8808b4d9504ad@xenon.blockstack.org:20444".to_string()),
            miner: Some(false),
            ..NodeConfigFile::default()
        };

        let balances = vec![
            InitialBalanceFile {
                address: "ST2QKZ4FKHAH1NQKYKYAYZPY440FEPK7GZ1R5HBP2".to_string(),
                amount: 10000000000000000,
            },
            InitialBalanceFile {
                address: "ST319CF5WV77KYR1H3GT0GZ7B8Q4AQPY42ETP1VPF".to_string(),
                amount: 10000000000000000,
            },
            InitialBalanceFile {
                address: "ST221Z6TDTC5E0BYR2V624Q2ST6R0Q71T78WTAX6H".to_string(),
                amount: 10000000000000000,
            },
            InitialBalanceFile {
                address: "ST2TFVBMRPS5SSNP98DQKQ5JNB2B6NZM91C4K3P7B".to_string(),
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
            peer_host: Some("bitcoin.blockstack.com".to_string()),
            username: Some("blockstack".to_string()),
            password: Some("blockstacksystem".to_string()),
            magic_bytes: Some("X2".to_string()),
            ..BurnchainConfigFile::default()
        };

        let bootstrap_nodes = [
            "02da7a464ac770ae8337a343670778b93410f2f3fef6bea98dd1c3e9224459d36b@seed-0.mainnet.stacks.co:20444",
            "02afeae522aab5f8c99a00ddf75fbcb4a641e052dd48836408d9cf437344b63516@seed-1.mainnet.stacks.co:20444",
            "03652212ea76be0ed4cd83a25c06e57819993029a7b9999f7d63c36340b34a4e62@seed-2.mainnet.stacks.co:20444"].join(",");

        let node = NodeConfigFile {
            bootstrap_node: Some(bootstrap_nodes),
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

        let balances = vec![
            InitialBalanceFile {
                // "mnemonic": "point approve language letter cargo rough similar wrap focus edge polar task olympic tobacco cinnamon drop lawn boring sort trade senior screen tiger climb",
                // "privateKey": "539e35c740079b79f931036651ad01f76d8fe1496dbd840ba9e62c7e7b355db001",
                // "btcAddress": "n1htkoYKuLXzPbkn9avC2DJxt7X85qVNCK",
                address: "ST3EQ88S02BXXD0T5ZVT3KW947CRMQ1C6DMQY8H19".to_string(),
                amount: 10000000000000000,
            },
            InitialBalanceFile {
                // "mnemonic": "laugh capital express view pull vehicle cluster embark service clerk roast glance lumber glove purity project layer lyrics limb junior reduce apple method pear",
                // "privateKey": "075754fb099a55e351fe87c68a73951836343865cd52c78ae4c0f6f48e234f3601",
                // "btcAddress": "n2ZGZ7Zau2Ca8CLHGh11YRnLw93b4ufsDR",
                address: "ST3KCNDSWZSFZCC6BE4VA9AXWXC9KEB16FBTRK36T".to_string(),
                amount: 10000000000000000,
            },
            InitialBalanceFile {
                // "mnemonic": "level garlic bean design maximum inhale daring alert case worry gift frequent floor utility crowd twenty burger place time fashion slow produce column prepare",
                // "privateKey": "374b6734eaff979818c5f1367331c685459b03b1a2053310906d1408dc928a0001",
                // "btcAddress": "mhY4cbHAFoXNYvXdt82yobvVuvR6PHeghf",
                address: "STB2BWB0K5XZGS3FXVTG3TKS46CQVV66NAK3YVN8".to_string(),
                amount: 10000000000000000,
            },
            InitialBalanceFile {
                // "mnemonic": "drop guess similar uphold alarm remove fossil riot leaf badge lobster ability mesh parent lawn today student olympic model assault syrup end scorpion lab",
                // "privateKey": "26f235698d02803955b7418842affbee600fc308936a7ca48bf5778d1ceef9df01",
                // "btcAddress": "mkEDDqbELrKYGUmUbTAyQnmBAEz4V1MAro",
                address: "STSTW15D618BSZQB85R058DS46THH86YQQY6XCB7".to_string(),
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
}

#[derive(Clone, Debug)]
pub struct Config {
    pub burnchain: BurnchainConfig,
    pub node: NodeConfig,
    pub initial_balances: Vec<InitialBalance>,
    pub events_observers: Vec<EventObserverConfig>,
    pub connection_options: ConnectionOptions,
    pub miner: MinerConfig,
    pub estimation: FeeEstimationConfig,
}

lazy_static! {
    static ref HELIUM_DEFAULT_CONNECTION_OPTIONS: ConnectionOptions = ConnectionOptions {
        inbox_maxlen: 100,
        outbox_maxlen: 100,
        timeout: 15,
        idle_timeout: 15,               // how long a HTTP connection can be idle before it's closed
        heartbeat: 3600,
        // can't use u64::max, because sqlite stores as i64.
        private_key_lifetime: 9223372036854775807,
        num_neighbors: 16,              // number of neighbors whose inventories we track
        num_clients: 750,               // number of inbound p2p connections
        soft_num_neighbors: 16,         // soft-limit on the number of neighbors whose inventories we track
        soft_num_clients: 750,          // soft limit on the number of inbound p2p connections
        max_neighbors_per_host: 1,      // maximum number of neighbors per host we permit
        max_clients_per_host: 4,        // maximum number of inbound p2p connections per host we permit
        soft_max_neighbors_per_host: 1, // soft limit on the number of neighbors per host we permit
        soft_max_neighbors_per_org: 32, // soft limit on the number of neighbors per AS we permit (TODO: for now it must be greater than num_neighbors)
        soft_max_clients_per_host: 4,   // soft limit on how many inbound p2p connections per host we permit
        max_http_clients: 1000,         // maximum number of HTTP connections
        max_neighbors_of_neighbor: 10,  // maximum number of neighbors we'll handshake with when doing a neighbor walk (I/O for this can be expensive, so keep small-ish)
        walk_interval: 60,              // how often, in seconds, we do a neighbor walk
        inv_sync_interval: 45,          // how often, in seconds, we refresh block inventories
        inv_reward_cycles: 3,           // how many reward cycles to look back on, for mainnet
        download_interval: 10,          // how often, in seconds, we do a block download scan (should be less than inv_sync_interval)
        dns_timeout: 15_000,
        max_inflight_blocks: 6,
        max_inflight_attachments: 6,
        .. std::default::Default::default()
    };
}

impl Config {
    /// This method applies any of this Config's configured PoX constants to the supplied
    /// `PoxConstants` struct.
    pub fn update_pox_constants(&self, pox_consts: &mut PoxConstants) {
        if self.is_mainnet() {
            return;
        }
        if let Some(pox_2_activation_height) = self.burnchain.pox_2_activation {
            pox_consts.v1_unlock_height = pox_2_activation_height;
        }
    }

    fn make_epochs(
        conf_epochs: &[StacksEpochConfigFile],
        burn_mode: &str,
        bitcoin_network: BitcoinNetworkType,
        pox_2_activation: Option<u32>,
    ) -> Result<Vec<StacksEpoch>, String> {
        let default_epochs = match bitcoin_network {
            BitcoinNetworkType::Mainnet => {
                Err("Cannot configure epochs in mainnet mode".to_string())
            }
            BitcoinNetworkType::Testnet => Ok(stacks::core::STACKS_EPOCHS_TESTNET.to_vec()),
            BitcoinNetworkType::Regtest => Ok(stacks::core::STACKS_EPOCHS_REGTEST.to_vec()),
        }?;
        let mut matched_epochs = vec![];
        for configured_epoch in conf_epochs.iter() {
            let epoch_name = &configured_epoch.epoch_name;
            let epoch_id = if epoch_name == EPOCH_CONFIG_1_0_0 {
                Ok(StacksEpochId::Epoch10)
            } else if epoch_name == EPOCH_CONFIG_2_0_0 {
                Ok(StacksEpochId::Epoch20)
            } else if epoch_name == EPOCH_CONFIG_2_0_5 {
                Ok(StacksEpochId::Epoch2_05)
            } else if epoch_name == EPOCH_CONFIG_2_1_0 {
                Ok(StacksEpochId::Epoch21)
            } else {
                Err(format!("Unknown epoch name specified: {}", epoch_name))
            }?;
            matched_epochs.push((epoch_id, configured_epoch.start_height));
        }

        matched_epochs.sort_by_key(|(epoch_id, _)| *epoch_id);
        // epochs must be sorted the same both by start height and by epoch
        let mut check_sort = matched_epochs.clone();
        check_sort.sort_by_key(|(_, start)| *start);
        if matched_epochs != check_sort {
            return Err(
                "Configured epochs must have start heights in the correct epoch order".to_string(),
            );
        }

        // epochs must be a prefix of [1.0, 2.0, 2.05, 2.1]
        let expected_list = [
            StacksEpochId::Epoch10,
            StacksEpochId::Epoch20,
            StacksEpochId::Epoch2_05,
            StacksEpochId::Epoch21,
        ];
        for (expected_epoch, configured_epoch) in expected_list
            .iter()
            .zip(matched_epochs.iter().map(|(epoch_id, _)| epoch_id))
        {
            if expected_epoch != configured_epoch {
                return Err(format!(
                                "Configured epochs may not skip an epoch. Expected epoch = {}, Found epoch = {}",
                                expected_epoch, configured_epoch));
            }
        }

        // Stacks 1.0 must start at 0
        if matched_epochs[0].1 != 0 {
            return Err("Stacks 1.0 must start at height = 0".into());
        }

        if matched_epochs.len() > default_epochs.len() {
            return Err(format!(
                "Cannot configure more epochs than support by this node. Supported epoch count: {}",
                default_epochs.len()
            ));
        }
        let mut out_epochs = default_epochs[..matched_epochs.len()].to_vec();

        for (i, (epoch_id, start_height)) in matched_epochs.iter().enumerate() {
            if epoch_id != &out_epochs[i].epoch_id {
                return Err(
                                format!("Unmatched epochs in configuration and node implementation. Implemented = {}, Configured = {}",
                                   epoch_id, &out_epochs[i].epoch_id));
            }
            // end_height = next epoch's start height || i64::max if last epoch
            let end_height = if i + 1 < matched_epochs.len() {
                matched_epochs[i + 1].1
            } else {
                i64::MAX
            };
            out_epochs[i].start_height = u64::try_from(*start_height)
                .map_err(|_| "Start height must be a non-negative integer")?;
            out_epochs[i].end_height = u64::try_from(end_height)
                .map_err(|_| "End height must be a non-negative integer")?;
        }

        if burn_mode == "mocknet" {
            for epoch in out_epochs.iter_mut() {
                epoch.block_limit = ExecutionCost::max_value();
            }
        }

        if let Some(pox_2_activation) = pox_2_activation {
            let last_epoch = out_epochs
                .iter()
                .find(|&e| e.epoch_id == StacksEpochId::Epoch21)
                .ok_or("Cannot configure pox_2_activation if epoch 2.1 is not configured")?;
            if last_epoch.start_height > pox_2_activation as u64 {
                Err(format!("Cannot configure pox_2_activation at a lower height than the Epoch 2.1 start height. pox_2_activation = {}, epoch 2.1 start height = {}", pox_2_activation, last_epoch.start_height))?;
            }
        }

        Ok(out_epochs)
    }

    pub fn from_config_file(config_file: ConfigFile) -> Result<Config, String> {
        let default_node_config = NodeConfig::default();
        let (mut node, bootstrap_node, deny_nodes) = match config_file.node {
            Some(node) => {
                let rpc_bind = node.rpc_bind.unwrap_or(default_node_config.rpc_bind);
                let node_config = NodeConfig {
                    name: node.name.unwrap_or(default_node_config.name),
                    seed: match node.seed {
                        Some(seed) => hex_bytes(&seed)
                            .map_err(|_e| format!("node.seed should be a hex encoded string"))?,
                        None => default_node_config.seed,
                    },
                    working_dir: node.working_dir.unwrap_or(default_node_config.working_dir),
                    rpc_bind: rpc_bind.clone(),
                    p2p_bind: node.p2p_bind.unwrap_or(default_node_config.p2p_bind),
                    p2p_address: node.p2p_address.unwrap_or(rpc_bind.clone()),
                    bootstrap_node: vec![],
                    deny_nodes: vec![],
                    data_url: match node.data_url {
                        Some(data_url) => data_url,
                        None => format!("http://{}", rpc_bind),
                    },
                    local_peer_seed: match node.local_peer_seed {
                        Some(seed) => hex_bytes(&seed).map_err(|_e| {
                            format!("node.local_peer_seed should be a hex encoded string")
                        })?,
                        None => default_node_config.local_peer_seed,
                    },
                    miner: node.miner.unwrap_or(default_node_config.miner),
                    mock_mining: node.mock_mining.unwrap_or(default_node_config.mock_mining),
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
                    wait_time_for_blocks: node
                        .wait_time_for_blocks
                        .unwrap_or(default_node_config.wait_time_for_blocks),
                    prometheus_bind: node.prometheus_bind,
                    marf_cache_strategy: node.marf_cache_strategy,
                    marf_defer_hashing: node
                        .marf_defer_hashing
                        .unwrap_or(default_node_config.marf_defer_hashing),
                    pox_sync_sample_secs: node
                        .pox_sync_sample_secs
                        .unwrap_or(default_node_config.pox_sync_sample_secs),
                    use_test_genesis_chainstate: node.use_test_genesis_chainstate,
                    always_use_affirmation_maps: node.always_use_affirmation_maps.unwrap_or(false),
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

                if &burnchain_mode == "mainnet" {
                    // check magic bytes and set if not defined
                    let mainnet_magic = ConfigFile::mainnet().burnchain.unwrap().magic_bytes;
                    if burnchain.magic_bytes.is_none() {
                        burnchain.magic_bytes = mainnet_magic.clone();
                    }
                    if burnchain.magic_bytes != mainnet_magic {
                        return Err(format!(
                            "Attempted to run mainnet node with bad magic bytes '{}'",
                            burnchain.magic_bytes.as_ref().unwrap()
                        ));
                    }
                    if node.use_test_genesis_chainstate == Some(true) {
                        return Err(format!(
                            "Attempted to run mainnet node with `use_test_genesis_chainstate`"
                        ));
                    }
                    if let Some(ref balances) = config_file.ustx_balance {
                        if balances.len() > 0 {
                            return Err(format!(
                                "Attempted to run mainnet node with specified `initial_balances`"
                            ));
                        }
                    }
                }

                let mut result = BurnchainConfig {
                    chain: burnchain.chain.unwrap_or(default_burnchain_config.chain),
                    chain_id: if &burnchain_mode == "mainnet" {
                        CHAIN_ID_MAINNET
                    } else {
                        CHAIN_ID_TESTNET
                    },
                    peer_version: if &burnchain_mode == "mainnet" {
                        PEER_VERSION_MAINNET
                    } else {
                        PEER_VERSION_TESTNET
                    },
                    mode: burnchain_mode,
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
                            let mut sock_addrs = format!("{}:1", &peer_host)
                                .to_socket_addrs()
                                .map_err(|e| format!("Invalid burnchain.peer_host: {}", &e))?;
                            let sock_addr = match sock_addrs.next() {
                                Some(addr) => addr,
                                None => {
                                    return Err(format!(
                                        "No IP address could be queried for '{}'",
                                        &peer_host
                                    ));
                                }
                            };
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
                    magic_bytes: burnchain
                        .magic_bytes
                        .map(|magic_ascii| {
                            assert_eq!(magic_ascii.len(), 2, "Magic bytes must be length-2");
                            assert!(magic_ascii.is_ascii(), "Magic bytes must be ASCII");
                            MagicBytes::from(magic_ascii.as_bytes())
                        })
                        .unwrap_or(default_burnchain_config.magic_bytes),
                    local_mining_public_key: burnchain.local_mining_public_key,
                    process_exit_at_block_height: burnchain.process_exit_at_block_height,
                    poll_time_secs: burnchain
                        .poll_time_secs
                        .unwrap_or(default_burnchain_config.poll_time_secs),
                    satoshis_per_byte: burnchain
                        .satoshis_per_byte
                        .unwrap_or(default_burnchain_config.satoshis_per_byte),
                    max_rbf: burnchain
                        .max_rbf
                        .unwrap_or(default_burnchain_config.max_rbf),
                    leader_key_tx_estimated_size: burnchain
                        .leader_key_tx_estimated_size
                        .unwrap_or(default_burnchain_config.leader_key_tx_estimated_size),
                    block_commit_tx_estimated_size: burnchain
                        .block_commit_tx_estimated_size
                        .unwrap_or(default_burnchain_config.block_commit_tx_estimated_size),
                    rbf_fee_increment: burnchain
                        .rbf_fee_increment
                        .unwrap_or(default_burnchain_config.rbf_fee_increment),
                    // will be overwritten below
                    epochs: default_burnchain_config.epochs,
                    ast_precheck_size_height: burnchain.ast_precheck_size_height,
                    pox_2_activation: burnchain
                        .pox_2_activation
                        .or(default_burnchain_config.pox_2_activation),
                };

                // check that pox_2_activation hasn't been set in mainnet
                if result.pox_2_activation.is_some() {
                    if let BitcoinNetworkType::Mainnet = result.get_bitcoin_network().1 {
                        return Err("PoX-2 Activation height is not configurable in mainnet".into());
                    }
                }

                if let Some(ref conf_epochs) = burnchain.epochs {
                    result.epochs = Some(Self::make_epochs(
                        conf_epochs,
                        &result.mode,
                        result.get_bitcoin_network().1,
                        burnchain.pox_2_activation,
                    )?);
                }

                result
            }
            None => default_burnchain_config,
        };

        let miner_default_config = MinerConfig::default();
        let miner = match config_file.miner {
            Some(ref miner) => MinerConfig {
                min_tx_fee: miner.min_tx_fee.unwrap_or(miner_default_config.min_tx_fee),
                first_attempt_time_ms: miner
                    .first_attempt_time_ms
                    .unwrap_or(miner_default_config.first_attempt_time_ms),
                subsequent_attempt_time_ms: miner
                    .subsequent_attempt_time_ms
                    .unwrap_or(miner_default_config.subsequent_attempt_time_ms),
                microblock_attempt_time_ms: miner
                    .microblock_attempt_time_ms
                    .unwrap_or(miner_default_config.microblock_attempt_time_ms),
                probability_pick_no_estimate_tx: miner
                    .probability_pick_no_estimate_tx
                    .unwrap_or(miner_default_config.probability_pick_no_estimate_tx),
                block_reward_recipient: miner.block_reward_recipient.as_ref().map(|c| {
                    PrincipalData::parse(&c)
                        .expect(&format!("FATAL: not a valid principal identifier: {}", c))
                }),
                segwit: miner.segwit.unwrap_or(miner_default_config.segwit),
                wait_for_block_download: miner_default_config.wait_for_block_download,
                nonce_cache_size: miner
                    .nonce_cache_size
                    .unwrap_or(miner_default_config.nonce_cache_size),
                candidate_retry_cache_size: miner
                    .candidate_retry_cache_size
                    .unwrap_or(miner_default_config.candidate_retry_cache_size),
            },
            None => miner_default_config,
        };

        let supported_modes = vec![
            "mocknet", "helium", "neon", "argon", "krypton", "xenon", "mainnet",
        ];

        if !supported_modes.contains(&burnchain.mode.as_str()) {
            return Err(format!(
                "Setting burnchain.network not supported (should be: {})",
                supported_modes.join(", ")
            ));
        }

        if burnchain.mode == "helium" && burnchain.local_mining_public_key.is_none() {
            return Err(format!("Config is missing the setting `burnchain.local_mining_public_key` (mandatory for helium)"));
        }

        if let Some(bootstrap_node) = bootstrap_node {
            node.set_bootstrap_nodes(bootstrap_node, burnchain.chain_id, burnchain.peer_version);
        } else {
            if burnchain.mode == "mainnet" {
                let bootstrap_node = ConfigFile::mainnet().node.unwrap().bootstrap_node.unwrap();
                node.set_bootstrap_nodes(
                    bootstrap_node,
                    burnchain.chain_id,
                    burnchain.peer_version,
                );
            }
        }
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
                    dns_timeout: opts.dns_timeout.unwrap_or_else(|| {
                        HELIUM_DEFAULT_CONNECTION_OPTIONS.dns_timeout.clone() as u64
                    }) as u128,
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
                    inv_sync_interval: opts
                        .inv_sync_interval
                        .unwrap_or_else(|| HELIUM_DEFAULT_CONNECTION_OPTIONS.inv_sync_interval),
                    inv_reward_cycles: opts.inv_reward_cycles.unwrap_or_else(|| {
                        if burnchain.mode == "mainnet" {
                            HELIUM_DEFAULT_CONNECTION_OPTIONS.inv_reward_cycles
                        } else {
                            // testnet reward cycles are a bit smaller (and blocks can go by
                            // faster), so make our inventory
                            // reward cycle depth a bit longer to compensate
                            INV_REWARD_CYCLES_TESTNET
                        }
                    }),
                    public_ip_address: ip_addr,
                    disable_inbound_walks: opts.disable_inbound_walks.unwrap_or(false),
                    disable_inbound_handshakes: opts.disable_inbound_handshakes.unwrap_or(false),
                    disable_block_download: opts.disable_block_download.unwrap_or(false),
                    force_disconnect_interval: opts.force_disconnect_interval,
                    max_http_clients: opts.max_http_clients.unwrap_or_else(|| {
                        HELIUM_DEFAULT_CONNECTION_OPTIONS.max_http_clients.clone()
                    }),
                    connect_timeout: opts.connect_timeout.unwrap_or(10),
                    handshake_timeout: opts.connect_timeout.unwrap_or(5),
                    max_sockets: opts.max_sockets.unwrap_or(800) as usize,
                    antientropy_public: opts.antientropy_public.unwrap_or(true),
                    ..ConnectionOptions::default()
                }
            }
            None => HELIUM_DEFAULT_CONNECTION_OPTIONS.clone(),
        };

        let estimation = match config_file.fee_estimation {
            Some(f) => FeeEstimationConfig::from(f),
            None => FeeEstimationConfig::default(),
        };

        Ok(Config {
            node,
            burnchain,
            initial_balances,
            events_observers,
            connection_options,
            estimation,
            miner,
        })
    }

    fn get_burnchain_path(&self) -> PathBuf {
        let mut path = PathBuf::from(&self.node.working_dir);
        path.push(&self.burnchain.mode);
        path.push("burnchain");
        path
    }

    pub fn get_chainstate_path(&self) -> PathBuf {
        let mut path = PathBuf::from(&self.node.working_dir);
        path.push(&self.burnchain.mode);
        path.push("chainstate");
        path
    }

    /// Returns the path `{get_chainstate_path()}/estimates`, and ensures it exists.
    pub fn get_estimates_path(&self) -> PathBuf {
        let mut path = self.get_chainstate_path();
        path.push("estimates");
        fs::create_dir_all(&path).expect(&format!(
            "Failed to create `estimates` directory at {}",
            path.to_string_lossy()
        ));
        path
    }

    pub fn get_chainstate_path_str(&self) -> String {
        self.get_chainstate_path()
            .to_str()
            .expect("Unable to produce path")
            .to_string()
    }

    pub fn get_burnchain_path_str(&self) -> String {
        self.get_burnchain_path()
            .to_str()
            .expect("Unable to produce path")
            .to_string()
    }

    pub fn get_burn_db_path(&self) -> String {
        self.get_burnchain_path()
            .to_str()
            .expect("Unable to produce path")
            .to_string()
    }

    pub fn get_burn_db_file_path(&self) -> String {
        let mut path = self.get_burnchain_path();
        path.push("sortition");
        path.to_str().expect("Unable to produce path").to_string()
    }

    pub fn get_spv_headers_file_path(&self) -> String {
        let mut path = self.get_burnchain_path();
        path.set_file_name("headers.sqlite");
        path.to_str().expect("Unable to produce path").to_string()
    }

    pub fn get_peer_db_file_path(&self) -> String {
        let mut path = self.get_chainstate_path();
        path.set_file_name("peer.sqlite");
        path.to_str().expect("Unable to produce path").to_string()
    }

    pub fn get_atlas_db_file_path(&self) -> String {
        let mut path = self.get_chainstate_path();
        path.set_file_name("atlas.sqlite");
        path.to_str().expect("Unable to produce path").to_string()
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

    pub fn is_node_event_driven(&self) -> bool {
        self.events_observers.len() > 0
    }

    pub fn make_block_builder_settings(
        &self,
        attempt: u64,
        microblocks: bool,
        miner_status: Arc<Mutex<MinerStatus>>,
    ) -> BlockBuilderSettings {
        BlockBuilderSettings {
            max_miner_time_ms: if microblocks {
                self.miner.microblock_attempt_time_ms
            } else if attempt <= 1 {
                // first attempt to mine a block -- do so right away
                self.miner.first_attempt_time_ms
            } else {
                // second or later attempt to mine a block -- give it some time
                self.miner.subsequent_attempt_time_ms
            },
            mempool_settings: MemPoolWalkSettings {
                min_tx_fee: self.miner.min_tx_fee,
                max_walk_time_ms: if microblocks {
                    self.miner.microblock_attempt_time_ms
                } else if attempt <= 1 {
                    // first attempt to mine a block -- do so right away
                    self.miner.first_attempt_time_ms
                } else {
                    // second or later attempt to mine a block -- give it some time
                    self.miner.subsequent_attempt_time_ms
                },
                consider_no_estimate_tx_prob: self.miner.probability_pick_no_estimate_tx,
                nonce_cache_size: self.miner.nonce_cache_size,
                candidate_retry_cache_size: self.miner.candidate_retry_cache_size,
            },
            miner_status,
        }
    }
}

impl std::default::Default for Config {
    fn default() -> Config {
        // Testnet's name
        let node = NodeConfig {
            ..NodeConfig::default()
        };

        let burnchain = BurnchainConfig {
            ..BurnchainConfig::default()
        };

        let connection_options = HELIUM_DEFAULT_CONNECTION_OPTIONS.clone();
        let estimation = FeeEstimationConfig::default();

        Config {
            burnchain,
            node,
            initial_balances: vec![],
            events_observers: vec![],
            connection_options,
            estimation,
            miner: MinerConfig::default(),
        }
    }
}

#[derive(Clone, Debug, Default, Deserialize)]
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
    pub magic_bytes: MagicBytes,
    pub local_mining_public_key: Option<String>,
    pub process_exit_at_block_height: Option<u64>,
    pub poll_time_secs: u64,
    pub satoshis_per_byte: u64,
    pub max_rbf: u64,
    pub leader_key_tx_estimated_size: u64,
    pub block_commit_tx_estimated_size: u64,
    pub rbf_fee_increment: u64,
    /// Custom override for the definitions of the epochs. This will only be applied for testnet and
    /// regtest nodes.
    pub epochs: Option<Vec<StacksEpoch>>,
    pub pox_2_activation: Option<u32>,
    pub ast_precheck_size_height: Option<u64>,
}

impl BurnchainConfig {
    fn default() -> BurnchainConfig {
        BurnchainConfig {
            chain: "bitcoin".to_string(),
            mode: "mocknet".to_string(),
            chain_id: CHAIN_ID_TESTNET,
            peer_version: PEER_VERSION_TESTNET,
            burn_fee_cap: 20000,
            commit_anchor_block_within: 5000,
            peer_host: "0.0.0.0".to_string(),
            peer_port: 8333,
            rpc_port: 8332,
            rpc_ssl: false,
            username: None,
            password: None,
            timeout: 300,
            magic_bytes: BLOCKSTACK_MAGIC_MAINNET.clone(),
            local_mining_public_key: None,
            process_exit_at_block_height: None,
            poll_time_secs: 10, // TODO: this is a testnet specific value.
            satoshis_per_byte: DEFAULT_SATS_PER_VB,
            max_rbf: DEFAULT_MAX_RBF_RATE,
            leader_key_tx_estimated_size: LEADER_KEY_TX_ESTIM_SIZE,
            block_commit_tx_estimated_size: BLOCK_COMMIT_TX_ESTIM_SIZE,
            rbf_fee_increment: DEFAULT_RBF_FEE_RATE_INCREMENT,
            epochs: None,
            pox_2_activation: None,
            ast_precheck_size_height: None,
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
            "helium" | "neon" | "argon" | "krypton" | "mocknet" => {
                ("regtest".to_string(), BitcoinNetworkType::Regtest)
            }
            _ => panic!("Invalid bitcoin mode -- expected mainnet, testnet, or regtest"),
        }
    }
}

#[derive(Clone, Deserialize, Default, Debug)]
pub struct StacksEpochConfigFile {
    epoch_name: String,
    start_height: i64,
}

pub const EPOCH_CONFIG_1_0_0: &'static str = "1.0";
pub const EPOCH_CONFIG_2_0_0: &'static str = "2.0";
pub const EPOCH_CONFIG_2_0_5: &'static str = "2.05";
pub const EPOCH_CONFIG_2_1_0: &'static str = "2.1";

#[derive(Clone, Deserialize, Default, Debug)]
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
    pub magic_bytes: Option<String>,
    pub local_mining_public_key: Option<String>,
    pub process_exit_at_block_height: Option<u64>,
    pub poll_time_secs: Option<u64>,
    pub satoshis_per_byte: Option<u64>,
    pub leader_key_tx_estimated_size: Option<u64>,
    pub block_commit_tx_estimated_size: Option<u64>,
    pub rbf_fee_increment: Option<u64>,
    pub max_rbf: Option<u64>,
    pub epochs: Option<Vec<StacksEpochConfigFile>>,
    pub pox_2_activation: Option<u32>,
    pub ast_precheck_size_height: Option<u64>,
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
    pub bootstrap_node: Vec<Neighbor>,
    pub deny_nodes: Vec<Neighbor>,
    pub miner: bool,
    pub mock_mining: bool,
    pub mine_microblocks: bool,
    pub microblock_frequency: u64,
    pub max_microblocks: u64,
    pub wait_time_for_microblocks: u64,
    pub wait_time_for_blocks: u64,
    pub prometheus_bind: Option<String>,
    pub marf_cache_strategy: Option<String>,
    pub marf_defer_hashing: bool,
    pub pox_sync_sample_secs: u64,
    pub use_test_genesis_chainstate: Option<bool>,
    pub always_use_affirmation_maps: bool,
}

#[derive(Clone, Debug)]
pub enum CostEstimatorName {
    NaivePessimistic,
}

#[derive(Clone, Debug)]
pub enum FeeEstimatorName {
    ScalarFeeRate,
    FuzzedWeightedMedianFeeRate,
}

#[derive(Clone, Debug)]
pub enum CostMetricName {
    ProportionDotProduct,
}

impl Default for CostEstimatorName {
    fn default() -> Self {
        CostEstimatorName::NaivePessimistic
    }
}

impl Default for FeeEstimatorName {
    fn default() -> Self {
        FeeEstimatorName::ScalarFeeRate
    }
}

impl Default for CostMetricName {
    fn default() -> Self {
        CostMetricName::ProportionDotProduct
    }
}

impl CostEstimatorName {
    fn panic_parse(s: String) -> CostEstimatorName {
        if &s.to_lowercase() == "naive_pessimistic" {
            CostEstimatorName::NaivePessimistic
        } else {
            panic!(
                "Bad cost estimator name supplied in configuration file: {}",
                s
            );
        }
    }
}

impl FeeEstimatorName {
    fn panic_parse(s: String) -> FeeEstimatorName {
        if &s.to_lowercase() == "scalar_fee_rate" {
            FeeEstimatorName::ScalarFeeRate
        } else if &s.to_lowercase() == "fuzzed_weighted_median_fee_rate" {
            FeeEstimatorName::FuzzedWeightedMedianFeeRate
        } else {
            panic!(
                "Bad fee estimator name supplied in configuration file: {}",
                s
            );
        }
    }
}

impl CostMetricName {
    fn panic_parse(s: String) -> CostMetricName {
        if &s.to_lowercase() == "proportion_dot_product" {
            CostMetricName::ProportionDotProduct
        } else {
            panic!("Bad cost metric name supplied in configuration file: {}", s);
        }
    }
}

#[derive(Clone, Debug)]
pub struct FeeEstimationConfig {
    pub cost_estimator: Option<CostEstimatorName>,
    pub fee_estimator: Option<FeeEstimatorName>,
    pub cost_metric: Option<CostMetricName>,
    pub log_error: bool,
    /// If using FeeRateFuzzer, the amount of random noise, as a percentage of the base value (in
    /// [0, 1]) to add for fuzz. See comments on FeeRateFuzzer.
    pub fee_rate_fuzzer_fraction: f64,
    /// If using WeightedMedianFeeRateEstimator, the window size to use. See comments on
    /// WeightedMedianFeeRateEstimator.
    pub fee_rate_window_size: u64,
}

impl Default for FeeEstimationConfig {
    fn default() -> Self {
        Self {
            cost_estimator: Some(CostEstimatorName::default()),
            fee_estimator: Some(FeeEstimatorName::default()),
            cost_metric: Some(CostMetricName::default()),
            log_error: false,
            fee_rate_fuzzer_fraction: 0.1f64,
            fee_rate_window_size: 5u64,
        }
    }
}

impl From<FeeEstimationConfigFile> for FeeEstimationConfig {
    fn from(f: FeeEstimationConfigFile) -> Self {
        if let Some(true) = f.disabled {
            return Self {
                cost_estimator: None,
                fee_estimator: None,
                cost_metric: None,
                log_error: false,
                fee_rate_fuzzer_fraction: 0f64,
                fee_rate_window_size: 0u64,
            };
        }
        let cost_estimator = f
            .cost_estimator
            .map(CostEstimatorName::panic_parse)
            .unwrap_or_default();
        let fee_estimator = f
            .fee_estimator
            .map(FeeEstimatorName::panic_parse)
            .unwrap_or_default();
        let cost_metric = f
            .cost_metric
            .map(CostMetricName::panic_parse)
            .unwrap_or_default();
        let log_error = f.log_error.unwrap_or(false);
        Self {
            cost_estimator: Some(cost_estimator),
            fee_estimator: Some(fee_estimator),
            cost_metric: Some(cost_metric),
            log_error,
            fee_rate_fuzzer_fraction: f.fee_rate_fuzzer_fraction.unwrap_or(0.1f64),
            fee_rate_window_size: f.fee_rate_window_size.unwrap_or(5u64),
        }
    }
}

impl Config {
    pub fn make_cost_estimator(&self) -> Option<Box<dyn CostEstimator>> {
        let cost_estimator: Box<dyn CostEstimator> =
            match self.estimation.cost_estimator.as_ref()? {
                CostEstimatorName::NaivePessimistic => Box::new(
                    self.estimation
                        .make_pessimistic_cost_estimator(self.get_estimates_path()),
                ),
            };

        Some(cost_estimator)
    }

    pub fn make_cost_metric(&self) -> Option<Box<dyn CostMetric>> {
        let metric: Box<dyn CostMetric> = match self.estimation.cost_metric.as_ref()? {
            CostMetricName::ProportionDotProduct => {
                Box::new(ProportionalDotProduct::new(MAX_BLOCK_LEN as u64))
            }
        };

        Some(metric)
    }

    pub fn make_fee_estimator(&self) -> Option<Box<dyn FeeEstimator>> {
        let metric = self.make_cost_metric()?;
        let fee_estimator: Box<dyn FeeEstimator> = match self.estimation.fee_estimator.as_ref()? {
            FeeEstimatorName::ScalarFeeRate => self
                .estimation
                .make_scalar_fee_estimator(self.get_estimates_path(), metric),
            FeeEstimatorName::FuzzedWeightedMedianFeeRate => self
                .estimation
                .make_fuzzed_weighted_median_fee_estimator(self.get_estimates_path(), metric),
        };

        Some(fee_estimator)
    }
}

impl FeeEstimationConfig {
    pub fn make_pessimistic_cost_estimator(
        &self,
        mut estimates_path: PathBuf,
    ) -> PessimisticEstimator {
        if let Some(CostEstimatorName::NaivePessimistic) = self.cost_estimator.as_ref() {
            estimates_path.push("cost_estimator_pessimistic.sqlite");
            PessimisticEstimator::open(&estimates_path, self.log_error)
                .expect("Error opening cost estimator")
        } else {
            panic!("BUG: Expected to configure a naive pessimistic cost estimator");
        }
    }

    pub fn make_scalar_fee_estimator<CM: CostMetric + 'static>(
        &self,
        mut estimates_path: PathBuf,
        metric: CM,
    ) -> Box<dyn FeeEstimator> {
        if let Some(FeeEstimatorName::ScalarFeeRate) = self.fee_estimator.as_ref() {
            estimates_path.push("fee_estimator_scalar_rate.sqlite");
            Box::new(
                ScalarFeeRateEstimator::open(&estimates_path, metric)
                    .expect("Error opening fee estimator"),
            )
        } else {
            panic!("BUG: Expected to configure a scalar fee estimator");
        }
    }

    // Creates a fuzzed WeightedMedianFeeRateEstimator with window_size 5. The fuzz
    // is uniform with bounds [+/- 0.5].
    pub fn make_fuzzed_weighted_median_fee_estimator<CM: CostMetric + 'static>(
        &self,
        mut estimates_path: PathBuf,
        metric: CM,
    ) -> Box<dyn FeeEstimator> {
        if let Some(FeeEstimatorName::FuzzedWeightedMedianFeeRate) = self.fee_estimator.as_ref() {
            estimates_path.push("fee_fuzzed_weighted_median.sqlite");
            let underlying_estimator = WeightedMedianFeeRateEstimator::open(
                &estimates_path,
                metric,
                self.fee_rate_window_size
                    .try_into()
                    .expect("Configured fee rate window size out of bounds."),
            )
            .expect("Error opening fee estimator");
            Box::new(FeeRateFuzzer::new(
                underlying_estimator,
                self.fee_rate_fuzzer_fraction,
            ))
        } else {
            panic!("BUG: Expected to configure a weighted median fee estimator");
        }
    }
}

impl NodeConfig {
    fn default() -> NodeConfig {
        let mut rng = rand::thread_rng();
        let mut buf = [0u8; 8];
        rng.fill_bytes(&mut buf);

        let now = get_epoch_time_ms();
        let testnet_id = format!("stacks-node-{}", now);

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
            bootstrap_node: vec![],
            deny_nodes: vec![],
            local_peer_seed: local_peer_seed.to_vec(),
            miner: false,
            mock_mining: false,
            mine_microblocks: true,
            microblock_frequency: 30_000,
            max_microblocks: u16::MAX as u64,
            wait_time_for_microblocks: 30_000,
            wait_time_for_blocks: 30_000,
            prometheus_bind: None,
            marf_cache_strategy: None,
            marf_defer_hashing: true,
            pox_sync_sample_secs: 30,
            use_test_genesis_chainstate: None,
            always_use_affirmation_maps: false,
        }
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

    pub fn add_bootstrap_node(&mut self, bootstrap_node: &str, chain_id: u32, peer_version: u32) {
        let parts: Vec<&str> = bootstrap_node.split("@").collect();
        if parts.len() != 2 {
            panic!(
                "Invalid bootstrap node '{}': expected PUBKEY@IP:PORT",
                bootstrap_node
            );
        }
        let (pubkey_str, hostport) = (parts[0], parts[1]);
        let pubkey = Secp256k1PublicKey::from_hex(pubkey_str)
            .expect(&format!("Invalid public key '{}'", pubkey_str));
        debug!("Resolve '{}'", &hostport);
        let sockaddr = hostport.to_socket_addrs().unwrap().next().unwrap();
        let neighbor = NodeConfig::default_neighbor(sockaddr, pubkey, chain_id, peer_version);
        self.bootstrap_node.push(neighbor);
    }

    pub fn set_bootstrap_nodes(
        &mut self,
        bootstrap_nodes: String,
        chain_id: u32,
        peer_version: u32,
    ) {
        let parts: Vec<&str> = bootstrap_nodes.split(",").collect();
        for part in parts.into_iter() {
            if part.len() > 0 {
                self.add_bootstrap_node(&part, chain_id, peer_version);
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

    pub fn get_marf_opts(&self) -> MARFOpenOpts {
        let hash_mode = if self.marf_defer_hashing {
            TrieHashCalculationMode::Deferred
        } else {
            TrieHashCalculationMode::Immediate
        };

        MARFOpenOpts::new(
            hash_mode,
            &self
                .marf_cache_strategy
                .as_ref()
                .unwrap_or(&"noop".to_string()),
            false,
        )
    }
}

#[derive(Clone, Debug, Default)]
pub struct MinerConfig {
    pub min_tx_fee: u64,
    pub first_attempt_time_ms: u64,
    pub subsequent_attempt_time_ms: u64,
    pub microblock_attempt_time_ms: u64,
    pub probability_pick_no_estimate_tx: u8,
    pub block_reward_recipient: Option<PrincipalData>,
    /// If possible, mine with a p2wpkh address
    pub segwit: bool,
    /// Wait for a downloader pass before mining.
    /// This can only be disabled in testing; it can't be changed in the config file.
    pub wait_for_block_download: bool,
    pub nonce_cache_size: u64,
    pub candidate_retry_cache_size: u64,
}

impl MinerConfig {
    pub fn default() -> MinerConfig {
        MinerConfig {
            min_tx_fee: 1,
            first_attempt_time_ms: 5_000,
            subsequent_attempt_time_ms: 30_000,
            microblock_attempt_time_ms: 30_000,
            probability_pick_no_estimate_tx: 5,
            block_reward_recipient: None,
            segwit: false,
            wait_for_block_download: true,
            nonce_cache_size: 10_000,
            candidate_retry_cache_size: 10_000,
        }
    }
}

#[derive(Clone, Default, Deserialize, Debug)]
pub struct ConnectionOptionsFile {
    pub inbox_maxlen: Option<usize>,
    pub outbox_maxlen: Option<usize>,
    pub connect_timeout: Option<u64>,
    pub handshake_timeout: Option<u64>,
    pub timeout: Option<u64>,
    pub idle_timeout: Option<u64>,
    pub heartbeat: Option<u32>,
    pub private_key_lifetime: Option<u64>,
    pub num_neighbors: Option<u64>,
    pub num_clients: Option<u64>,
    pub max_http_clients: Option<u64>,
    pub soft_num_neighbors: Option<u64>,
    pub soft_num_clients: Option<u64>,
    pub max_neighbors_per_host: Option<u64>,
    pub max_clients_per_host: Option<u64>,
    pub soft_max_neighbors_per_host: Option<u64>,
    pub soft_max_neighbors_per_org: Option<u64>,
    pub soft_max_clients_per_host: Option<u64>,
    pub max_sockets: Option<u64>,
    pub walk_interval: Option<u64>,
    pub dns_timeout: Option<u64>,
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
    pub full_inv_sync_interval: Option<u64>,
    pub inv_reward_cycles: Option<u64>,
    pub public_ip_address: Option<String>,
    pub disable_inbound_walks: Option<bool>,
    pub disable_inbound_handshakes: Option<bool>,
    pub disable_block_download: Option<bool>,
    pub force_disconnect_interval: Option<u64>,
    pub antientropy_public: Option<bool>,
}

#[derive(Clone, Deserialize, Default, Debug)]
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
    pub mock_mining: Option<bool>,
    pub mine_microblocks: Option<bool>,
    pub microblock_frequency: Option<u64>,
    pub max_microblocks: Option<u64>,
    pub wait_time_for_microblocks: Option<u64>,
    pub wait_time_for_blocks: Option<u64>,
    pub prometheus_bind: Option<String>,
    pub marf_cache_strategy: Option<String>,
    pub marf_defer_hashing: Option<bool>,
    pub pox_sync_sample_secs: Option<u64>,
    pub use_test_genesis_chainstate: Option<bool>,
    pub always_use_affirmation_maps: Option<bool>,
}

#[derive(Clone, Deserialize, Debug)]
pub struct FeeEstimationConfigFile {
    pub cost_estimator: Option<String>,
    pub fee_estimator: Option<String>,
    pub cost_metric: Option<String>,
    pub disabled: Option<bool>,
    pub log_error: Option<bool>,
    pub fee_rate_fuzzer_fraction: Option<f64>,
    pub fee_rate_window_size: Option<u64>,
}

impl Default for FeeEstimationConfigFile {
    fn default() -> Self {
        Self {
            cost_estimator: None,
            fee_estimator: None,
            cost_metric: None,
            disabled: None,
            log_error: None,
            fee_rate_fuzzer_fraction: None,
            fee_rate_window_size: None,
        }
    }
}

#[derive(Clone, Deserialize, Default, Debug)]
pub struct MinerConfigFile {
    pub min_tx_fee: Option<u64>,
    pub first_attempt_time_ms: Option<u64>,
    pub subsequent_attempt_time_ms: Option<u64>,
    pub microblock_attempt_time_ms: Option<u64>,
    pub probability_pick_no_estimate_tx: Option<u8>,
    pub block_reward_recipient: Option<String>,
    pub segwit: Option<bool>,
    pub nonce_cache_size: Option<u64>,
    pub candidate_retry_cache_size: Option<u64>,
}

#[derive(Clone, Deserialize, Default, Debug)]
pub struct EventObserverConfigFile {
    pub endpoint: String,
    pub events_keys: Vec<String>,
}

#[derive(Clone, Default, Debug)]
pub struct EventObserverConfig {
    pub endpoint: String,
    pub events_keys: Vec<EventKeyType>,
}

#[derive(Clone, Debug)]
pub enum EventKeyType {
    SmartContractEvent((QualifiedContractIdentifier, String)),
    AssetEvent(AssetIdentifier),
    STXEvent,
    MemPoolTransactions,
    Microblocks,
    AnyEvent,
    BurnchainBlocks,
    MinedBlocks,
    MinedMicroblocks,
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

        if raw_key == "microblocks" {
            return Some(EventKeyType::Microblocks);
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

#[derive(Clone, Deserialize, Default, Debug)]
pub struct InitialBalanceFile {
    pub address: String,
    pub amount: u64,
}
