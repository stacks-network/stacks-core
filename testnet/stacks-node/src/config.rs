use std::collections::HashSet;
use std::convert::TryInto;
use std::fs;
use std::net::{SocketAddr, ToSocketAddrs};
use std::path::PathBuf;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use clarity::vm::costs::ExecutionCost;
use clarity::vm::types::{AssetIdentifier, PrincipalData, QualifiedContractIdentifier};
use lazy_static::lazy_static;
use rand::RngCore;
use stacks::burnchains::bitcoin::BitcoinNetworkType;
use stacks::burnchains::{Burnchain, MagicBytes, BLOCKSTACK_MAGIC_MAINNET};
use stacks::chainstate::stacks::boot::MINERS_NAME;
use stacks::chainstate::stacks::index::marf::MARFOpenOpts;
use stacks::chainstate::stacks::index::storage::TrieHashCalculationMode;
use stacks::chainstate::stacks::miner::{BlockBuilderSettings, MinerStatus};
use stacks::chainstate::stacks::MAX_BLOCK_LEN;
use stacks::core::mempool::MemPoolWalkSettings;
use stacks::core::{
    MemPoolDB, StacksEpoch, StacksEpochExtension, StacksEpochId, CHAIN_ID_MAINNET,
    CHAIN_ID_TESTNET, PEER_VERSION_MAINNET, PEER_VERSION_TESTNET,
};
use stacks::cost_estimates::fee_medians::WeightedMedianFeeRateEstimator;
use stacks::cost_estimates::fee_rate_fuzzer::FeeRateFuzzer;
use stacks::cost_estimates::fee_scalar::ScalarFeeRateEstimator;
use stacks::cost_estimates::metrics::{CostMetric, ProportionalDotProduct, UnitMetric};
use stacks::cost_estimates::{CostEstimator, FeeEstimator, PessimisticEstimator, UnitEstimator};
use stacks::net::atlas::AtlasConfig;
use stacks::net::connection::ConnectionOptions;
use stacks::net::{Neighbor, NeighborKey};
use stacks::util_lib::boot::boot_code_id;
use stacks::util_lib::db::Error as DBError;
use stacks_common::address::{AddressHashMode, C32_ADDRESS_VERSION_TESTNET_SINGLESIG};
use stacks_common::types::chainstate::StacksAddress;
use stacks_common::types::net::PeerAddress;
use stacks_common::util::get_epoch_time_ms;
use stacks_common::util::hash::hex_bytes;
use stacks_common::util::secp256k1::{Secp256k1PrivateKey, Secp256k1PublicKey};

use crate::mockamoto::signer::SelfSigner;

pub const DEFAULT_SATS_PER_VB: u64 = 50;
const DEFAULT_MAX_RBF_RATE: u64 = 150; // 1.5x
const DEFAULT_RBF_FEE_RATE_INCREMENT: u64 = 5;
const LEADER_KEY_TX_ESTIM_SIZE: u64 = 290;
const BLOCK_COMMIT_TX_ESTIM_SIZE: u64 = 350;
const INV_REWARD_CYCLES_TESTNET: u64 = 6;

#[derive(Clone, Deserialize, Default, Debug)]
pub struct ConfigFile {
    pub __path: Option<String>, // Only used for config file reloads
    pub burnchain: Option<BurnchainConfigFile>,
    pub node: Option<NodeConfigFile>,
    pub ustx_balance: Option<Vec<InitialBalanceFile>>,
    pub events_observer: Option<HashSet<EventObserverConfigFile>>,
    pub connection_options: Option<ConnectionOptionsFile>,
    pub fee_estimation: Option<FeeEstimationConfigFile>,
    pub miner: Option<MinerConfigFile>,
    pub atlas: Option<AtlasConfigFile>,
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
        let mut f = Self::from_str(&content)?;
        f.__path = Some(path.to_string());
        Ok(f)
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
            bootstrap_node: Some("029266faff4c8e0ca4f934f34996a96af481df94a89b0c9bd515f3536a95682ddc@seed.testnet.hiro.so:20444".to_string()),
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

        let node = NodeConfigFile {
            bootstrap_node: Some("02196f005965cebe6ddc3901b7b1cc1aa7a88f305bb8c5893456b8f9a605923893@seed.mainnet.hiro.so:20444,02539449ad94e6e6392d8c1deb2b4e61f80ae2a18964349bc14336d8b903c46a8c@cet.stacksnodes.org:20444,02ececc8ce79b8adf813f13a0255f8ae58d4357309ba0cedd523d9f1a306fcfb79@sgt.stacksnodes.org:20444,0303144ba518fe7a0fb56a8a7d488f950307a4330f146e1e1458fc63fb33defe96@est.stacksnodes.org:20444".to_string()),
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

    pub fn mockamoto() -> ConfigFile {
        let epochs = vec![
            StacksEpochConfigFile {
                epoch_name: "1.0".into(),
                start_height: 0,
            },
            StacksEpochConfigFile {
                epoch_name: "2.0".into(),
                start_height: 0,
            },
            StacksEpochConfigFile {
                epoch_name: "2.05".into(),
                start_height: 1,
            },
            StacksEpochConfigFile {
                epoch_name: "2.1".into(),
                start_height: 2,
            },
            StacksEpochConfigFile {
                epoch_name: "2.2".into(),
                start_height: 3,
            },
            StacksEpochConfigFile {
                epoch_name: "2.3".into(),
                start_height: 4,
            },
            StacksEpochConfigFile {
                epoch_name: "2.4".into(),
                start_height: 5,
            },
            StacksEpochConfigFile {
                epoch_name: "2.5".into(),
                start_height: 6,
            },
            StacksEpochConfigFile {
                epoch_name: "3.0".into(),
                start_height: 7,
            },
        ];

        let burnchain = BurnchainConfigFile {
            mode: Some("mockamoto".into()),
            rpc_port: Some(8332),
            peer_port: Some(8333),
            peer_host: Some("localhost".into()),
            username: Some("blockstack".into()),
            password: Some("blockstacksystem".into()),
            magic_bytes: Some("M3".into()),
            epochs: Some(epochs),
            pox_prepare_length: Some(3),
            pox_reward_length: Some(36),
            ..BurnchainConfigFile::default()
        };

        let node = NodeConfigFile {
            bootstrap_node: None,
            miner: Some(true),
            ..NodeConfigFile::default()
        };

        let mining_key = Secp256k1PrivateKey::new();
        let miner = MinerConfigFile {
            mining_key: Some(mining_key.to_hex()),
            ..MinerConfigFile::default()
        };

        let mock_private_key = Secp256k1PrivateKey::from_seed(&[0]);
        let mock_public_key = Secp256k1PublicKey::from_private(&mock_private_key);
        let mock_address = StacksAddress::from_public_keys(
            C32_ADDRESS_VERSION_TESTNET_SINGLESIG,
            &AddressHashMode::SerializeP2PKH,
            1,
            &vec![mock_public_key],
        )
        .unwrap();

        info!(
            "Mockamoto starting. Initial balance set to mock_private_key = {}",
            mock_private_key.to_hex()
        );

        let ustx_balance = vec![InitialBalanceFile {
            address: mock_address.to_string(),
            amount: 1_000_000_000_000,
        }];

        ConfigFile {
            burnchain: Some(burnchain),
            node: Some(node),
            miner: Some(miner),
            ustx_balance: Some(ustx_balance),
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
    pub config_path: Option<String>,
    pub burnchain: BurnchainConfig,
    pub node: NodeConfig,
    pub initial_balances: Vec<InitialBalance>,
    pub events_observers: HashSet<EventObserverConfig>,
    pub connection_options: ConnectionOptions,
    pub miner: MinerConfig,
    pub estimation: FeeEstimationConfig,
    pub atlas: AtlasConfig,
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
    pub fn self_signing(&self) -> Option<SelfSigner> {
        if !(self.burnchain.mode == "nakamoto-neon" || self.burnchain.mode == "mockamoto") {
            return None;
        }
        self.miner.self_signing_key.clone()
    }

    /// get the up-to-date burnchain from the config
    pub fn get_burnchain_config(&self) -> Result<BurnchainConfig, String> {
        if let Some(path) = &self.config_path {
            let config_file = ConfigFile::from_path(path.as_str())?;
            let config = Config::from_config_file(config_file)?;
            Ok(config.burnchain)
        } else {
            Ok(self.burnchain.clone())
        }
    }

    /// Connect to the MempoolDB using the configured cost estimation
    pub fn connect_mempool_db(&self) -> Result<MemPoolDB, DBError> {
        // create estimators, metric instances for RPC handler
        let cost_estimator = self
            .make_cost_estimator()
            .unwrap_or_else(|| Box::new(UnitEstimator));
        let metric = self
            .make_cost_metric()
            .unwrap_or_else(|| Box::new(UnitMetric));

        MemPoolDB::open(
            self.is_mainnet(),
            self.burnchain.chain_id,
            &self.get_chainstate_path_str(),
            cost_estimator,
            metric,
        )
    }

    /// Apply any test settings to this burnchain config struct
    fn apply_test_settings(&self, burnchain: &mut Burnchain) {
        if self.burnchain.get_bitcoin_network().1 == BitcoinNetworkType::Mainnet {
            return;
        }

        if let Some(pox_prepare_length) = self.burnchain.pox_prepare_length {
            debug!("Override pox_prepare_length to {pox_prepare_length}");
            burnchain.pox_constants.prepare_length = pox_prepare_length;
        }

        if let Some(pox_reward_length) = self.burnchain.pox_reward_length {
            debug!("Override pox_reward_length to {pox_reward_length}");
            burnchain.pox_constants.reward_cycle_length = pox_reward_length;
        }

        if let Some(v1_unlock_height) = self.burnchain.pox_2_activation {
            debug!(
                "Override v1_unlock_height from {} to {}",
                burnchain.pox_constants.v1_unlock_height, v1_unlock_height
            );
            burnchain.pox_constants.v1_unlock_height = v1_unlock_height;
        }

        if let Some(epochs) = &self.burnchain.epochs {
            // Iterate through the epochs vector and find the item where epoch_id == StacksEpochId::Epoch22
            if let Some(epoch) = epochs
                .iter()
                .find(|epoch| epoch.epoch_id == StacksEpochId::Epoch21)
            {
                // Override v1_unlock_height to the start_height of epoch2.1
                debug!(
                    "Override v2_unlock_height from {} to {}",
                    burnchain.pox_constants.v1_unlock_height,
                    epoch.start_height + 1
                );
                burnchain.pox_constants.v1_unlock_height = epoch.start_height as u32 + 1;
            }

            if let Some(epoch) = epochs
                .iter()
                .find(|epoch| epoch.epoch_id == StacksEpochId::Epoch22)
            {
                // Override v2_unlock_height to the start_height of epoch2.2
                debug!(
                    "Override v2_unlock_height from {} to {}",
                    burnchain.pox_constants.v2_unlock_height,
                    epoch.start_height + 1
                );
                burnchain.pox_constants.v2_unlock_height = epoch.start_height as u32 + 1;
            }

            if let Some(epoch) = epochs
                .iter()
                .find(|epoch| epoch.epoch_id == StacksEpochId::Epoch24)
            {
                // Override pox_3_activation_height to the start_height of epoch2.4
                debug!(
                    "Override pox_3_activation_height from {} to {}",
                    burnchain.pox_constants.pox_3_activation_height, epoch.start_height
                );
                burnchain.pox_constants.pox_3_activation_height = epoch.start_height as u32;
            }

            if let Some(epoch) = epochs
                .iter()
                .find(|epoch| epoch.epoch_id == StacksEpochId::Epoch25)
            {
                // Override pox_4_activation_height to the start_height of epoch2.5
                debug!(
                    "Override pox_4_activation_height from {} to {}",
                    burnchain.pox_constants.pox_4_activation_height, epoch.start_height
                );
                burnchain.pox_constants.pox_4_activation_height = epoch.start_height as u32;
                burnchain.pox_constants.v3_unlock_height = epoch.start_height as u32 + 1;
            }
        }

        if let Some(sunset_start) = self.burnchain.sunset_start {
            debug!(
                "Override sunset_start from {} to {}",
                burnchain.pox_constants.sunset_start, sunset_start
            );
            burnchain.pox_constants.sunset_start = sunset_start.into();
        }

        if let Some(sunset_end) = self.burnchain.sunset_end {
            debug!(
                "Override sunset_end from {} to {}",
                burnchain.pox_constants.sunset_end, sunset_end
            );
            burnchain.pox_constants.sunset_end = sunset_end.into();
        }

        // check if the Epoch 3.0 burnchain settings as configured are going to be valid.
        if self.burnchain.mode == "nakamoto-neon" || self.burnchain.mode == "mockamoto" {
            self.check_nakamoto_config(&burnchain);
        }
    }

    fn check_nakamoto_config(&self, burnchain: &Burnchain) {
        let epochs = StacksEpoch::get_epochs(
            self.burnchain.get_bitcoin_network().1,
            self.burnchain.epochs.as_ref(),
        );
        let Some(epoch_30) = StacksEpoch::find_epoch_by_id(&epochs, StacksEpochId::Epoch30)
            .map(|epoch_ix| epochs[epoch_ix].clone())
        else {
            // no Epoch 3.0, so just return
            return;
        };
        if burnchain.pox_constants.prepare_length < 3 {
            panic!(
                "FATAL: Nakamoto rules require a prepare length >= 3. Prepare length set to {}",
                burnchain.pox_constants.prepare_length
            );
        }
        if burnchain.is_in_prepare_phase(epoch_30.start_height) {
            panic!(
                "FATAL: Epoch 3.0 must start *during* a reward phase, not a prepare phase. Epoch 3.0 start set to: {}. PoX Parameters: {:?}",
                epoch_30.start_height,
                &burnchain.pox_constants
            );
        }
    }

    /// Load up a Burnchain and apply config settings to it.
    /// Use this over the Burnchain constructors.
    /// Panics if we are unable to instantiate a burnchain (e.g. becase we're using an unrecognized
    /// chain ID or something).
    pub fn get_burnchain(&self) -> Burnchain {
        let (network_name, _) = self.burnchain.get_bitcoin_network();
        let mut burnchain = {
            let working_dir = self.get_burn_db_path();
            match Burnchain::new(&working_dir, &self.burnchain.chain, &network_name) {
                Ok(burnchain) => burnchain,
                Err(e) => {
                    error!("Failed to instantiate burnchain: {}", e);
                    panic!()
                }
            }
        };
        self.apply_test_settings(&mut burnchain);
        burnchain
    }

    /// Assert that a burnchain's PoX constants are consistent with the list of epoch start and end
    /// heights.  Panics if this is not the case.
    pub fn assert_valid_epoch_settings(burnchain: &Burnchain, epochs: &[StacksEpoch]) {
        // sanity check: epochs must be contiguous and ordered
        // (this panics if it's not the case)
        test_debug!("Validate epochs: {:#?}", epochs);
        let _ = StacksEpoch::validate_epochs(epochs);

        // sanity check: v1_unlock_height must happen after pox-2 instantiation
        let epoch21_index = StacksEpoch::find_epoch_by_id(&epochs, StacksEpochId::Epoch21)
            .expect("FATAL: no epoch 2.1 defined");

        let epoch21 = &epochs[epoch21_index];
        let v1_unlock_height = burnchain.pox_constants.v1_unlock_height as u64;

        assert!(
            v1_unlock_height > epoch21.start_height,
            "FATAL: v1 unlock height occurs at or before pox-2 activation: {} <= {}\nburnchain: {:?}", v1_unlock_height, epoch21.start_height, burnchain
        );

        let epoch21_rc = burnchain
            .block_height_to_reward_cycle(epoch21.start_height)
            .expect("FATAL: epoch 21 starts before the first burnchain block");
        let v1_unlock_rc = burnchain
            .block_height_to_reward_cycle(v1_unlock_height)
            .expect("FATAL: v1 unlock height is before the first burnchain block");

        if epoch21_rc + 1 == v1_unlock_rc {
            // if v1_unlock_height is in the reward cycle after epoch_21, then it must not fall on
            // the reward cycle boundary.
            assert!(
                !burnchain.is_reward_cycle_start(v1_unlock_height),
                "FATAL: v1 unlock height is at a reward cycle boundary\nburnchain: {:?}",
                burnchain
            );
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
            } else if epoch_name == EPOCH_CONFIG_2_2_0 {
                Ok(StacksEpochId::Epoch22)
            } else if epoch_name == EPOCH_CONFIG_2_3_0 {
                Ok(StacksEpochId::Epoch23)
            } else if epoch_name == EPOCH_CONFIG_2_4_0 {
                Ok(StacksEpochId::Epoch24)
            } else if epoch_name == EPOCH_CONFIG_2_5_0 {
                Ok(StacksEpochId::Epoch25)
            } else if epoch_name == EPOCH_CONFIG_3_0_0 {
                Ok(StacksEpochId::Epoch30)
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

        // epochs must be a prefix of [1.0, 2.0, 2.05, 2.1, 2.2, 2.3, 2.4]
        let expected_list = [
            StacksEpochId::Epoch10,
            StacksEpochId::Epoch20,
            StacksEpochId::Epoch2_05,
            StacksEpochId::Epoch21,
            StacksEpochId::Epoch22,
            StacksEpochId::Epoch23,
            StacksEpochId::Epoch24,
            StacksEpochId::Epoch25,
            StacksEpochId::Epoch30,
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
        if config_file.burnchain.as_ref().map(|b| b.mode.clone()) == Some(Some("mockamoto".into()))
        {
            // in the case of mockamoto, use `ConfigFile::mockamoto()` as the default for
            //  processing a user-supplied config
            let default = Self::from_config_default(ConfigFile::mockamoto(), Config::default())?;
            Self::from_config_default(config_file, default)
        } else {
            Self::from_config_default(config_file, Config::default())
        }
    }

    fn from_config_default(config_file: ConfigFile, default: Config) -> Result<Config, String> {
        let Config {
            node: default_node_config,
            burnchain: default_burnchain_config,
            miner: miner_default_config,
            estimation: default_estimator,
            ..
        } = default;

        // First parse the burnchain config
        let burnchain = match config_file.burnchain {
            Some(burnchain) => burnchain.into_config_default(default_burnchain_config)?,
            None => default_burnchain_config,
        };

        let supported_modes = vec![
            "mocknet",
            "helium",
            "neon",
            "argon",
            "krypton",
            "xenon",
            "mainnet",
            "mockamoto",
            "nakamoto-neon",
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

        let is_mainnet = burnchain.mode == "mainnet";

        // Parse the node config
        let (mut node, bootstrap_node, deny_nodes) = match config_file.node {
            Some(node) => {
                let deny_nodes = node.deny_nodes.clone();
                let bootstrap_node = node.bootstrap_node.clone();
                let node_config = node.into_config_default(default_node_config)?;
                (node_config, bootstrap_node, deny_nodes)
            }
            None => (default_node_config, None, None),
        };

        if let Some(bootstrap_node) = bootstrap_node {
            node.set_bootstrap_nodes(bootstrap_node, burnchain.chain_id, burnchain.peer_version);
        } else {
            if is_mainnet {
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

        // Validate the node config
        if is_mainnet {
            if node.use_test_genesis_chainstate == Some(true) {
                return Err(format!(
                    "Attempted to run mainnet node with `use_test_genesis_chainstate`"
                ));
            }
        } else if node.require_affirmed_anchor_blocks {
            // testnet requires that we use the 2.05 rules for anchor block affirmations,
            // because reward cycle 360 (and possibly future ones) has a different anchor
            // block choice in 2.05 rules than in 2.1 rules.
            debug!("Set `require_affirmed_anchor_blocks` to `false` for non-mainnet config");
            node.require_affirmed_anchor_blocks = false;
        }

        let miners_contract_id = boot_code_id(MINERS_NAME, is_mainnet);
        if node.miner
            && burnchain.mode == "nakamoto-neon"
            && !node.stacker_dbs.contains(&miners_contract_id)
        {
            debug!("A miner must subscribe to the {miners_contract_id} stacker db contract. Forcibly subscribing...");
            node.stacker_dbs.push(miners_contract_id);
        }

        let miner = match config_file.miner {
            Some(miner) => miner.into_config_default(miner_default_config)?,
            None => miner_default_config,
        };

        let initial_balances: Vec<InitialBalance> = match config_file.ustx_balance {
            Some(balances) => {
                if is_mainnet && balances.len() > 0 {
                    return Err(format!(
                        "Attempted to run mainnet node with specified `initial_balances`"
                    ));
                }
                balances
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
                    .collect()
            }
            None => vec![],
        };

        let mut events_observers = match config_file.events_observer {
            Some(raw_observers) => {
                let mut observers = HashSet::new();
                for observer in raw_observers {
                    let events_keys: Vec<EventKeyType> = observer
                        .events_keys
                        .iter()
                        .map(|e| EventKeyType::from_string(e).unwrap())
                        .collect();

                    let endpoint = format!("{}", observer.endpoint);

                    let include_data_events = observer.include_data_events.unwrap_or(false);
                    observers.insert(EventObserverConfig {
                        endpoint,
                        events_keys,
                        include_data_events,
                    });
                }
                observers
            }
            None => HashSet::new(),
        };

        // check for observer config in env vars
        match std::env::var("STACKS_EVENT_OBSERVER") {
            Ok(val) => events_observers.insert(EventObserverConfig {
                endpoint: val,
                events_keys: vec![EventKeyType::AnyEvent],
                include_data_events: false,
            }),
            _ => false,
        };

        let connection_options = match config_file.connection_options {
            Some(opts) => opts.into_config(is_mainnet)?,
            None => HELIUM_DEFAULT_CONNECTION_OPTIONS.clone(),
        };

        let estimation = match config_file.fee_estimation {
            Some(f) => FeeEstimationConfig::from(f),
            None => default_estimator,
        };

        let atlas = match config_file.atlas {
            Some(f) => f.into_config(is_mainnet),
            None => AtlasConfig::new(is_mainnet),
        };

        atlas
            .validate()
            .map_err(|e| format!("Atlas config error: {e}"))?;

        Ok(Config {
            config_path: config_file.__path,
            node,
            burnchain,
            initial_balances,
            events_observers,
            connection_options,
            estimation,
            miner,
            atlas,
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

    pub fn get_stacker_db_file_path(&self) -> String {
        let mut path = self.get_chainstate_path();
        path.set_file_name("stacker_db.sqlite");
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
        let node = NodeConfig::default();
        let burnchain = BurnchainConfig::default();

        let connection_options = HELIUM_DEFAULT_CONNECTION_OPTIONS.clone();
        let estimation = FeeEstimationConfig::default();
        let mainnet = burnchain.mode == "mainnet";

        Config {
            config_path: None,
            burnchain,
            node,
            initial_balances: vec![],
            events_observers: HashSet::new(),
            connection_options,
            estimation,
            miner: MinerConfig::default(),
            atlas: AtlasConfig::new(mainnet),
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
    pub pox_reward_length: Option<u32>,
    pub pox_prepare_length: Option<u32>,
    pub sunset_start: Option<u32>,
    pub sunset_end: Option<u32>,
    pub wallet_name: String,
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
            pox_prepare_length: None,
            pox_reward_length: None,
            sunset_start: None,
            sunset_end: None,
            wallet_name: "".to_string(),
            ast_precheck_size_height: None,
        }
    }
    pub fn get_rpc_url(&self, wallet: Option<String>) -> String {
        let scheme = match self.rpc_ssl {
            true => "https://",
            false => "http://",
        };
        let wallet_path = if let Some(wallet_id) = wallet.as_ref() {
            format!("/wallet/{}", wallet_id)
        } else {
            "".to_string()
        };
        format!(
            "{}{}:{}{}",
            scheme, self.peer_host, self.rpc_port, wallet_path
        )
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
            "helium" | "neon" | "argon" | "krypton" | "mocknet" | "mockamoto" | "nakamoto-neon" => {
                ("regtest".to_string(), BitcoinNetworkType::Regtest)
            }
            other => panic!("Invalid stacks-node mode: {other}"),
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
pub const EPOCH_CONFIG_2_2_0: &'static str = "2.2";
pub const EPOCH_CONFIG_2_3_0: &'static str = "2.3";
pub const EPOCH_CONFIG_2_4_0: &'static str = "2.4";
pub const EPOCH_CONFIG_2_5_0: &'static str = "2.5";
pub const EPOCH_CONFIG_3_0_0: &'static str = "3.0";

#[derive(Clone, Deserialize, Default, Debug)]
pub struct BurnchainConfigFile {
    pub chain: Option<String>,
    pub chain_id: Option<u32>,
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
    pub pox_prepare_length: Option<u32>,
    pub pox_reward_length: Option<u32>,
    pub pox_2_activation: Option<u32>,
    pub sunset_start: Option<u32>,
    pub sunset_end: Option<u32>,
    pub wallet_name: Option<String>,
    pub ast_precheck_size_height: Option<u64>,
}

impl BurnchainConfigFile {
    fn into_config_default(
        mut self,
        default_burnchain_config: BurnchainConfig,
    ) -> Result<BurnchainConfig, String> {
        if self.mode.as_deref() == Some("xenon") {
            if self.magic_bytes.is_none() {
                self.magic_bytes = ConfigFile::xenon().burnchain.unwrap().magic_bytes;
            }
        }

        let mode = self.mode.unwrap_or(default_burnchain_config.mode);
        let is_mainnet = mode == "mainnet";
        if is_mainnet {
            // check magic bytes and set if not defined
            let mainnet_magic = ConfigFile::mainnet().burnchain.unwrap().magic_bytes;
            if self.magic_bytes.is_none() {
                self.magic_bytes = mainnet_magic.clone();
            }
            if self.magic_bytes != mainnet_magic {
                return Err(format!(
                    "Attempted to run mainnet node with bad magic bytes '{}'",
                    self.magic_bytes.as_ref().unwrap()
                ));
            }
        }

        let mut config = BurnchainConfig {
            chain: self.chain.unwrap_or(default_burnchain_config.chain),
            chain_id: if is_mainnet {
                CHAIN_ID_MAINNET
            } else {
                CHAIN_ID_TESTNET
            },
            peer_version: if is_mainnet {
                PEER_VERSION_MAINNET
            } else {
                PEER_VERSION_TESTNET
            },
            mode,
            burn_fee_cap: self
                .burn_fee_cap
                .unwrap_or(default_burnchain_config.burn_fee_cap),
            commit_anchor_block_within: self
                .commit_anchor_block_within
                .unwrap_or(default_burnchain_config.commit_anchor_block_within),
            peer_host: match self.peer_host.as_ref() {
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
            peer_port: self.peer_port.unwrap_or(default_burnchain_config.peer_port),
            rpc_port: self.rpc_port.unwrap_or(default_burnchain_config.rpc_port),
            rpc_ssl: self.rpc_ssl.unwrap_or(default_burnchain_config.rpc_ssl),
            username: self.username,
            password: self.password,
            timeout: self.timeout.unwrap_or(default_burnchain_config.timeout),
            magic_bytes: self
                .magic_bytes
                .map(|magic_ascii| {
                    assert_eq!(magic_ascii.len(), 2, "Magic bytes must be length-2");
                    assert!(magic_ascii.is_ascii(), "Magic bytes must be ASCII");
                    MagicBytes::from(magic_ascii.as_bytes())
                })
                .unwrap_or(default_burnchain_config.magic_bytes),
            local_mining_public_key: self.local_mining_public_key,
            process_exit_at_block_height: self.process_exit_at_block_height,
            poll_time_secs: self
                .poll_time_secs
                .unwrap_or(default_burnchain_config.poll_time_secs),
            satoshis_per_byte: self
                .satoshis_per_byte
                .unwrap_or(default_burnchain_config.satoshis_per_byte),
            max_rbf: self.max_rbf.unwrap_or(default_burnchain_config.max_rbf),
            leader_key_tx_estimated_size: self
                .leader_key_tx_estimated_size
                .unwrap_or(default_burnchain_config.leader_key_tx_estimated_size),
            block_commit_tx_estimated_size: self
                .block_commit_tx_estimated_size
                .unwrap_or(default_burnchain_config.block_commit_tx_estimated_size),
            rbf_fee_increment: self
                .rbf_fee_increment
                .unwrap_or(default_burnchain_config.rbf_fee_increment),
            // will be overwritten below
            epochs: default_burnchain_config.epochs,
            ast_precheck_size_height: self.ast_precheck_size_height,
            pox_2_activation: self
                .pox_2_activation
                .or(default_burnchain_config.pox_2_activation),
            sunset_start: self.sunset_start.or(default_burnchain_config.sunset_start),
            sunset_end: self.sunset_end.or(default_burnchain_config.sunset_end),
            wallet_name: self
                .wallet_name
                .unwrap_or(default_burnchain_config.wallet_name.clone()),
            pox_reward_length: self
                .pox_reward_length
                .or(default_burnchain_config.pox_reward_length),
            pox_prepare_length: self
                .pox_prepare_length
                .or(default_burnchain_config.pox_prepare_length),
        };

        if let BitcoinNetworkType::Mainnet = config.get_bitcoin_network().1 {
            // check that pox_2_activation hasn't been set in mainnet
            if config.pox_2_activation.is_some()
                || config.sunset_start.is_some()
                || config.sunset_end.is_some()
            {
                return Err("PoX-2 parameters are not configurable in mainnet".into());
            }
        }

        if let Some(ref conf_epochs) = self.epochs {
            config.epochs = Some(Config::make_epochs(
                conf_epochs,
                &config.mode,
                config.get_bitcoin_network().1,
                self.pox_2_activation,
            )?);
        }

        Ok(config)
    }
}
#[derive(Clone, Debug)]
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
    pub require_affirmed_anchor_blocks: bool,
    // fault injection for hiding blocks.
    // not part of the config file.
    pub fault_injection_hide_blocks: bool,
    /// At most, how often should the chain-liveness thread
    ///  wake up the chains-coordinator. Defaults to 300s (5 min).
    pub chain_liveness_poll_time_secs: u64,
    /// stacker DBs we replicate
    pub stacker_dbs: Vec<QualifiedContractIdentifier>,
    /// if running in mockamoto mode, how long to wait between each
    /// simulated bitcoin block
    pub mockamoto_time_ms: u64,
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

impl Default for NodeConfig {
    fn default() -> Self {
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
            require_affirmed_anchor_blocks: true,
            fault_injection_hide_blocks: false,
            chain_liveness_poll_time_secs: 300,
            stacker_dbs: vec![],
            mockamoto_time_ms: 3_000,
        }
    }
}

impl NodeConfig {
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
        info!("Resolve '{}'", &hostport);
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

#[derive(Clone, Debug)]
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
    pub unprocessed_block_deadline_secs: u64,
    pub mining_key: Option<Secp256k1PrivateKey>,
    pub self_signing_key: Option<SelfSigner>,
    /// Amount of time while mining in nakamoto to wait in between mining interim blocks
    pub wait_on_interim_blocks: Duration,
}

impl Default for MinerConfig {
    fn default() -> MinerConfig {
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
            unprocessed_block_deadline_secs: 30,
            mining_key: None,
            self_signing_key: None,
            wait_on_interim_blocks: Duration::from_millis(2_500),
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

impl ConnectionOptionsFile {
    fn into_config(self, is_mainnet: bool) -> Result<ConnectionOptions, String> {
        let ip_addr = self
            .public_ip_address
            .map(|public_ip_address| {
                public_ip_address
                    .parse::<SocketAddr>()
                    .map(|addr| (PeerAddress::from_socketaddr(&addr), addr.port()))
                    .map_err(|e| format!("Invalid connection_option.public_ip_address: {}", e))
            })
            .transpose()?;
        let mut read_only_call_limit = HELIUM_DEFAULT_CONNECTION_OPTIONS
            .read_only_call_limit
            .clone();
        self.read_only_call_limit_write_length.map(|x| {
            read_only_call_limit.write_length = x;
        });
        self.read_only_call_limit_write_count.map(|x| {
            read_only_call_limit.write_count = x;
        });
        self.read_only_call_limit_read_length.map(|x| {
            read_only_call_limit.read_length = x;
        });
        self.read_only_call_limit_read_count.map(|x| {
            read_only_call_limit.read_count = x;
        });
        self.read_only_call_limit_runtime.map(|x| {
            read_only_call_limit.runtime = x;
        });
        Ok(ConnectionOptions {
            read_only_call_limit,
            inbox_maxlen: self
                .inbox_maxlen
                .unwrap_or_else(|| HELIUM_DEFAULT_CONNECTION_OPTIONS.inbox_maxlen),
            outbox_maxlen: self
                .outbox_maxlen
                .unwrap_or_else(|| HELIUM_DEFAULT_CONNECTION_OPTIONS.outbox_maxlen),
            timeout: self
                .timeout
                .unwrap_or_else(|| HELIUM_DEFAULT_CONNECTION_OPTIONS.timeout),
            idle_timeout: self
                .idle_timeout
                .unwrap_or_else(|| HELIUM_DEFAULT_CONNECTION_OPTIONS.idle_timeout),
            heartbeat: self
                .heartbeat
                .unwrap_or_else(|| HELIUM_DEFAULT_CONNECTION_OPTIONS.heartbeat),
            private_key_lifetime: self
                .private_key_lifetime
                .unwrap_or_else(|| HELIUM_DEFAULT_CONNECTION_OPTIONS.private_key_lifetime),
            num_neighbors: self
                .num_neighbors
                .unwrap_or_else(|| HELIUM_DEFAULT_CONNECTION_OPTIONS.num_neighbors),
            num_clients: self
                .num_clients
                .unwrap_or_else(|| HELIUM_DEFAULT_CONNECTION_OPTIONS.num_clients),
            soft_num_neighbors: self
                .soft_num_neighbors
                .unwrap_or_else(|| HELIUM_DEFAULT_CONNECTION_OPTIONS.soft_num_neighbors),
            soft_num_clients: self
                .soft_num_clients
                .unwrap_or_else(|| HELIUM_DEFAULT_CONNECTION_OPTIONS.soft_num_clients),
            max_neighbors_per_host: self
                .max_neighbors_per_host
                .unwrap_or_else(|| HELIUM_DEFAULT_CONNECTION_OPTIONS.max_neighbors_per_host),
            max_clients_per_host: self
                .max_clients_per_host
                .unwrap_or_else(|| HELIUM_DEFAULT_CONNECTION_OPTIONS.max_clients_per_host),
            soft_max_neighbors_per_host: self
                .soft_max_neighbors_per_host
                .unwrap_or_else(|| HELIUM_DEFAULT_CONNECTION_OPTIONS.soft_max_neighbors_per_host),
            soft_max_neighbors_per_org: self
                .soft_max_neighbors_per_org
                .unwrap_or_else(|| HELIUM_DEFAULT_CONNECTION_OPTIONS.soft_max_neighbors_per_org),
            soft_max_clients_per_host: self
                .soft_max_clients_per_host
                .unwrap_or_else(|| HELIUM_DEFAULT_CONNECTION_OPTIONS.soft_max_clients_per_host),
            walk_interval: self
                .walk_interval
                .unwrap_or_else(|| HELIUM_DEFAULT_CONNECTION_OPTIONS.walk_interval.clone()),
            dns_timeout: self
                .dns_timeout
                .map(|dns_timeout| dns_timeout as u128)
                .unwrap_or_else(|| HELIUM_DEFAULT_CONNECTION_OPTIONS.dns_timeout),
            max_inflight_blocks: self
                .max_inflight_blocks
                .unwrap_or_else(|| HELIUM_DEFAULT_CONNECTION_OPTIONS.max_inflight_blocks),
            max_inflight_attachments: self
                .max_inflight_attachments
                .unwrap_or_else(|| HELIUM_DEFAULT_CONNECTION_OPTIONS.max_inflight_attachments),
            maximum_call_argument_size: self
                .maximum_call_argument_size
                .unwrap_or_else(|| HELIUM_DEFAULT_CONNECTION_OPTIONS.maximum_call_argument_size),
            download_interval: self
                .download_interval
                .unwrap_or_else(|| HELIUM_DEFAULT_CONNECTION_OPTIONS.download_interval.clone()),
            inv_sync_interval: self
                .inv_sync_interval
                .unwrap_or_else(|| HELIUM_DEFAULT_CONNECTION_OPTIONS.inv_sync_interval),
            inv_reward_cycles: self.inv_reward_cycles.unwrap_or_else(|| {
                if is_mainnet {
                    HELIUM_DEFAULT_CONNECTION_OPTIONS.inv_reward_cycles
                } else {
                    // testnet reward cycles are a bit smaller (and blocks can go by
                    // faster), so make our inventory
                    // reward cycle depth a bit longer to compensate
                    INV_REWARD_CYCLES_TESTNET
                }
            }),
            public_ip_address: ip_addr,
            disable_inbound_walks: self.disable_inbound_walks.unwrap_or(false),
            disable_inbound_handshakes: self.disable_inbound_handshakes.unwrap_or(false),
            disable_block_download: self.disable_block_download.unwrap_or(false),
            force_disconnect_interval: self.force_disconnect_interval,
            max_http_clients: self
                .max_http_clients
                .unwrap_or_else(|| HELIUM_DEFAULT_CONNECTION_OPTIONS.max_http_clients.clone()),
            connect_timeout: self.connect_timeout.unwrap_or(10),
            handshake_timeout: self.handshake_timeout.unwrap_or(5),
            max_sockets: self.max_sockets.unwrap_or(800) as usize,
            antientropy_public: self.antientropy_public.unwrap_or(true),
            ..ConnectionOptions::default()
        })
    }
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
    pub require_affirmed_anchor_blocks: Option<bool>,
    /// At most, how often should the chain-liveness thread
    ///  wake up the chains-coordinator. Defaults to 300s (5 min).
    pub chain_liveness_poll_time_secs: Option<u64>,
    /// Stacker DBs we replicate
    pub stacker_dbs: Option<Vec<String>>,
    /// if running in mockamoto mode, how long to wait between each
    /// simulated bitcoin block
    pub mockamoto_time_ms: Option<u64>,
}

impl NodeConfigFile {
    fn into_config_default(self, default_node_config: NodeConfig) -> Result<NodeConfig, String> {
        let rpc_bind = self.rpc_bind.unwrap_or(default_node_config.rpc_bind);
        let miner = self.miner.unwrap_or(default_node_config.miner);
        let node_config = NodeConfig {
            name: self.name.unwrap_or(default_node_config.name),
            seed: match self.seed {
                Some(seed) => hex_bytes(&seed)
                    .map_err(|_e| format!("node.seed should be a hex encoded string"))?,
                None => default_node_config.seed,
            },
            working_dir: std::env::var("STACKS_WORKING_DIR")
                .unwrap_or(self.working_dir.unwrap_or(default_node_config.working_dir)),
            rpc_bind: rpc_bind.clone(),
            p2p_bind: self.p2p_bind.unwrap_or(default_node_config.p2p_bind),
            p2p_address: self.p2p_address.unwrap_or(rpc_bind.clone()),
            bootstrap_node: vec![],
            deny_nodes: vec![],
            data_url: match self.data_url {
                Some(data_url) => data_url,
                None => format!("http://{}", rpc_bind),
            },
            local_peer_seed: match self.local_peer_seed {
                Some(seed) => hex_bytes(&seed)
                    .map_err(|_e| format!("node.local_peer_seed should be a hex encoded string"))?,
                None => default_node_config.local_peer_seed,
            },
            miner,
            mock_mining: self.mock_mining.unwrap_or(default_node_config.mock_mining),
            mine_microblocks: self
                .mine_microblocks
                .unwrap_or(default_node_config.mine_microblocks),
            microblock_frequency: self
                .microblock_frequency
                .unwrap_or(default_node_config.microblock_frequency),
            max_microblocks: self
                .max_microblocks
                .unwrap_or(default_node_config.max_microblocks),
            wait_time_for_microblocks: self
                .wait_time_for_microblocks
                .unwrap_or(default_node_config.wait_time_for_microblocks),
            wait_time_for_blocks: self
                .wait_time_for_blocks
                .unwrap_or(default_node_config.wait_time_for_blocks),
            prometheus_bind: self.prometheus_bind,
            marf_cache_strategy: self.marf_cache_strategy,
            marf_defer_hashing: self
                .marf_defer_hashing
                .unwrap_or(default_node_config.marf_defer_hashing),
            pox_sync_sample_secs: self
                .pox_sync_sample_secs
                .unwrap_or(default_node_config.pox_sync_sample_secs),
            use_test_genesis_chainstate: self.use_test_genesis_chainstate,
            always_use_affirmation_maps: self
                .always_use_affirmation_maps
                .unwrap_or(default_node_config.always_use_affirmation_maps),
            // miners should always try to mine, even if they don't have the anchored
            // blocks in the canonical affirmation map. Followers, however, can stall.
            require_affirmed_anchor_blocks: self.require_affirmed_anchor_blocks.unwrap_or(!miner),
            // chainstate fault_injection activation for hide_blocks.
            // you can't set this in the config file.
            fault_injection_hide_blocks: false,
            chain_liveness_poll_time_secs: self
                .chain_liveness_poll_time_secs
                .unwrap_or(default_node_config.chain_liveness_poll_time_secs),
            stacker_dbs: self
                .stacker_dbs
                .unwrap_or(vec![])
                .iter()
                .filter_map(|contract_id| QualifiedContractIdentifier::parse(contract_id).ok())
                .collect(),
            mockamoto_time_ms: self
                .mockamoto_time_ms
                .unwrap_or(default_node_config.mockamoto_time_ms),
        };
        Ok(node_config)
    }
}

#[derive(Clone, Deserialize, Default, Debug)]
pub struct FeeEstimationConfigFile {
    pub cost_estimator: Option<String>,
    pub fee_estimator: Option<String>,
    pub cost_metric: Option<String>,
    pub disabled: Option<bool>,
    pub log_error: Option<bool>,
    pub fee_rate_fuzzer_fraction: Option<f64>,
    pub fee_rate_window_size: Option<u64>,
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
    pub unprocessed_block_deadline_secs: Option<u64>,
    pub mining_key: Option<String>,
    pub self_signing_seed: Option<u64>,
    pub wait_on_interim_blocks_ms: Option<u64>,
}

impl MinerConfigFile {
    fn into_config_default(self, miner_default_config: MinerConfig) -> Result<MinerConfig, String> {
        Ok(MinerConfig {
            min_tx_fee: self.min_tx_fee.unwrap_or(miner_default_config.min_tx_fee),
            first_attempt_time_ms: self
                .first_attempt_time_ms
                .unwrap_or(miner_default_config.first_attempt_time_ms),
            subsequent_attempt_time_ms: self
                .subsequent_attempt_time_ms
                .unwrap_or(miner_default_config.subsequent_attempt_time_ms),
            microblock_attempt_time_ms: self
                .microblock_attempt_time_ms
                .unwrap_or(miner_default_config.microblock_attempt_time_ms),
            probability_pick_no_estimate_tx: self
                .probability_pick_no_estimate_tx
                .unwrap_or(miner_default_config.probability_pick_no_estimate_tx),
            block_reward_recipient: self
                .block_reward_recipient
                .map(|c| {
                    PrincipalData::parse(&c).map_err(|e| {
                        format!(
                            "miner.block_reward_recipient is not a valid principal identifier: {e}"
                        )
                    })
                })
                .transpose()?,
            segwit: self.segwit.unwrap_or(miner_default_config.segwit),
            wait_for_block_download: miner_default_config.wait_for_block_download,
            nonce_cache_size: self
                .nonce_cache_size
                .unwrap_or(miner_default_config.nonce_cache_size),
            candidate_retry_cache_size: self
                .candidate_retry_cache_size
                .unwrap_or(miner_default_config.candidate_retry_cache_size),
            unprocessed_block_deadline_secs: self
                .unprocessed_block_deadline_secs
                .unwrap_or(miner_default_config.unprocessed_block_deadline_secs),
            mining_key: self
                .mining_key
                .as_ref()
                .map(|x| Secp256k1PrivateKey::from_hex(x))
                .transpose()?,
            self_signing_key: self
                .self_signing_seed
                .as_ref()
                .map(|x| SelfSigner::from_seed(*x))
                .or(miner_default_config.self_signing_key),
            wait_on_interim_blocks: self
                .wait_on_interim_blocks_ms
                .map(Duration::from_millis)
                .unwrap_or(miner_default_config.wait_on_interim_blocks),
        })
    }
}
#[derive(Clone, Deserialize, Default, Debug)]
pub struct AtlasConfigFile {
    pub attachments_max_size: Option<u32>,
    pub max_uninstantiated_attachments: Option<u32>,
    pub uninstantiated_attachments_expire_after: Option<u32>,
    pub unresolved_attachment_instances_expire_after: Option<u32>,
}

impl AtlasConfigFile {
    // Can't inplement `Into` trait because this takes a parameter
    fn into_config(&self, mainnet: bool) -> AtlasConfig {
        let mut conf = AtlasConfig::new(mainnet);
        if let Some(val) = self.attachments_max_size {
            conf.attachments_max_size = val
        }
        if let Some(val) = self.max_uninstantiated_attachments {
            conf.max_uninstantiated_attachments = val
        }
        if let Some(val) = self.uninstantiated_attachments_expire_after {
            conf.uninstantiated_attachments_expire_after = val
        }
        if let Some(val) = self.unresolved_attachment_instances_expire_after {
            conf.unresolved_attachment_instances_expire_after = val
        }
        conf
    }
}

#[derive(Clone, Deserialize, Default, Debug, Hash, PartialEq, Eq, PartialOrd)]
pub struct EventObserverConfigFile {
    pub endpoint: String,
    pub events_keys: Vec<String>,
    pub include_data_events: Option<bool>,
}

#[derive(Clone, Default, Debug, Hash, PartialEq, Eq, PartialOrd)]
pub struct EventObserverConfig {
    pub endpoint: String,
    pub events_keys: Vec<EventKeyType>,
    pub include_data_events: bool,
}

#[derive(Clone, Debug, Hash, PartialEq, Eq, PartialOrd)]
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
    StackerDBChunks,
    BlockProposal,
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

        if raw_key == "stackerdb" {
            return Some(EventKeyType::StackerDBChunks);
        }

        if raw_key == "block_proposal" {
            return Some(EventKeyType::BlockProposal);
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
