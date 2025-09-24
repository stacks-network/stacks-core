// Copyright (C) 2013-2020 Blockstack PBC, a public benefit corporation
// Copyright (C) 2020-2024 Stacks Open Internet Foundation
//
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.
//
// This program is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
// GNU General Public License for more details.
//
// You should have received a copy of the GNU General Public License
// along with this program.  If not, see <http://www.gnu.org/licenses/>.

pub mod chain_data;

use std::collections::{HashMap, HashSet};
use std::net::{Ipv4Addr, SocketAddr, ToSocketAddrs};
use std::path::PathBuf;
use std::str::FromStr;
use std::sync::{Arc, LazyLock, Mutex};
use std::time::Duration;
use std::{cmp, fs, thread};

use clarity::vm::costs::ExecutionCost;
use clarity::vm::types::{AssetIdentifier, PrincipalData, QualifiedContractIdentifier};
use rand::RngCore;
use serde::Deserialize;
use stacks_common::consts::SIGNER_SLOTS_PER_USER;
use stacks_common::types::chainstate::StacksAddress;
use stacks_common::types::net::PeerAddress;
use stacks_common::types::Address;
use stacks_common::util::get_epoch_time_ms;
use stacks_common::util::hash::hex_bytes;
use stacks_common::util::secp256k1::{Secp256k1PrivateKey, Secp256k1PublicKey};

use crate::burnchains::bitcoin::BitcoinNetworkType;
use crate::burnchains::{Burnchain, MagicBytes, BLOCKSTACK_MAGIC_MAINNET};
use crate::chainstate::nakamoto::signer_set::NakamotoSigners;
use crate::chainstate::stacks::boot::MINERS_NAME;
use crate::chainstate::stacks::index::marf::MARFOpenOpts;
use crate::chainstate::stacks::index::storage::TrieHashCalculationMode;
use crate::chainstate::stacks::miner::{BlockBuilderSettings, MinerStatus};
use crate::chainstate::stacks::MAX_BLOCK_LEN;
use crate::config::chain_data::MinerStats;
use crate::core::mempool::{MemPoolWalkSettings, MemPoolWalkStrategy, MemPoolWalkTxTypes};
use crate::core::{
    MemPoolDB, StacksEpoch, StacksEpochExtension, StacksEpochId, CHAIN_ID_MAINNET,
    CHAIN_ID_TESTNET, PEER_VERSION_MAINNET, PEER_VERSION_TESTNET, STACKS_EPOCHS_REGTEST,
    STACKS_EPOCHS_TESTNET,
};
use crate::cost_estimates::fee_medians::WeightedMedianFeeRateEstimator;
use crate::cost_estimates::fee_rate_fuzzer::FeeRateFuzzer;
use crate::cost_estimates::fee_scalar::ScalarFeeRateEstimator;
use crate::cost_estimates::metrics::{CostMetric, ProportionalDotProduct, UnitMetric};
use crate::cost_estimates::{CostEstimator, FeeEstimator, PessimisticEstimator, UnitEstimator};
use crate::net::atlas::AtlasConfig;
use crate::net::connection::{ConnectionOptions, DEFAULT_BLOCK_PROPOSAL_MAX_AGE_SECS};
use crate::net::{Neighbor, NeighborAddress, NeighborKey};
use crate::types::chainstate::BurnchainHeaderHash;
use crate::types::EpochList;
use crate::util::hash::to_hex;
use crate::util_lib::boot::boot_code_id;
use crate::util_lib::db::Error as DBError;

pub const DEFAULT_SATS_PER_VB: u64 = 50;
pub const OP_TX_BLOCK_COMMIT_ESTIM_SIZE: u64 = 380;
pub const OP_TX_DELEGATE_STACKS_ESTIM_SIZE: u64 = 230;
pub const OP_TX_LEADER_KEY_ESTIM_SIZE: u64 = 290;
pub const OP_TX_PRE_STACKS_ESTIM_SIZE: u64 = 280;
pub const OP_TX_STACK_STX_ESTIM_SIZE: u64 = 250;
pub const OP_TX_TRANSFER_STACKS_ESTIM_SIZE: u64 = 230;
pub const OP_TX_VOTE_AGG_ESTIM_SIZE: u64 = 230;

pub const OP_TX_ANY_ESTIM_SIZE: u64 = fmax!(
    OP_TX_BLOCK_COMMIT_ESTIM_SIZE,
    OP_TX_DELEGATE_STACKS_ESTIM_SIZE,
    OP_TX_LEADER_KEY_ESTIM_SIZE,
    OP_TX_PRE_STACKS_ESTIM_SIZE,
    OP_TX_STACK_STX_ESTIM_SIZE,
    OP_TX_TRANSFER_STACKS_ESTIM_SIZE,
    OP_TX_VOTE_AGG_ESTIM_SIZE
);

/// Default maximum percentage of `satoshis_per_byte` that a Bitcoin fee rate
/// may be increased to when RBFing a transaction
const DEFAULT_MAX_RBF_RATE: u64 = 150; // 1.5x
/// Amount to increment the fee by, in Sats/vByte, when RBFing a Bitcoin
/// transaction
const DEFAULT_RBF_FEE_RATE_INCREMENT: u64 = 5;
/// Default number of reward cycles of blocks to sync in a non-full inventory
/// sync
const INV_REWARD_CYCLES_TESTNET: u64 = 6;
/// Default minimum time to wait between mining blocks in milliseconds. The
/// value must be greater than or equal to 1000 ms because if a block is mined
/// within the same second as its parent, it will be rejected by the signers.
const DEFAULT_MIN_TIME_BETWEEN_BLOCKS_MS: u64 = 1_000;
/// Default time in milliseconds to pause after receiving the first threshold
/// rejection, before proposing a new block.
const DEFAULT_FIRST_REJECTION_PAUSE_MS: u64 = 5_000;
/// Default time in milliseconds to pause after receiving subsequent threshold
/// rejections, before proposing a new block.
const DEFAULT_SUBSEQUENT_REJECTION_PAUSE_MS: u64 = 10_000;
/// Default time in milliseconds to wait for a Nakamoto block after seeing a
/// burnchain block before submitting a block commit.
const DEFAULT_BLOCK_COMMIT_DELAY_MS: u64 = 40_000;
/// Default percentage of the remaining tenure cost limit to consume each block
const DEFAULT_TENURE_COST_LIMIT_PER_BLOCK_PERCENTAGE: u8 = 25;
/// Default percentage of the block limit to consume by non-boot contract calls
pub const DEFAULT_CONTRACT_COST_LIMIT_PERCENTAGE: u8 = 95;
/// Default number of seconds to wait in-between polling the sortition DB to
/// see if we need to extend the ongoing tenure (e.g. because the current
/// sortition is empty or invalid).
const DEFAULT_TENURE_EXTEND_POLL_SECS: u64 = 1;
/// Default number of millis to wait before trying to continue a tenure because the next miner did not produce blocks
const DEFAULT_TENURE_EXTEND_WAIT_MS: u64 = 120_000;
/// Default duration to wait before attempting to issue a tenure extend.
/// This should be greater than the signers' timeout. This is used for issuing
/// fallback tenure extends
const DEFAULT_TENURE_TIMEOUT_SECS: u64 = 180;
/// Default percentage of block budget that must be used before attempting a
/// time-based tenure extend
const DEFAULT_TENURE_EXTEND_COST_THRESHOLD: u64 = 50;
/// Default number of milliseconds that the miner should sleep between mining
/// attempts when the mempool is empty.
const DEFAULT_EMPTY_MEMPOOL_SLEEP_MS: u64 = 2_500;
/// Default number of seconds that a miner should wait before timing out an HTTP request to StackerDB.
const DEFAULT_STACKERDB_TIMEOUT_SECS: u64 = 120;
/// Default maximum size for a tenure (note: the counter is reset on tenure extend).
pub const DEFAULT_MAX_TENURE_BYTES: u64 = 10 * 1024 * 1024; // 10 MB

static HELIUM_DEFAULT_CONNECTION_OPTIONS: LazyLock<ConnectionOptions> =
    LazyLock::new(|| ConnectionOptions {
        inbox_maxlen: 100,
        outbox_maxlen: 100,
        timeout: 15,
        idle_timeout: 15, // how long a HTTP connection can be idle before it's closed
        heartbeat: 3600,
        // can't use u64::max, because sqlite stores as i64.
        private_key_lifetime: 9223372036854775807,
        num_neighbors: 32,         // number of neighbors whose inventories we track
        num_clients: 750,          // number of inbound p2p connections
        soft_num_neighbors: 16, // soft-limit on the number of neighbors whose inventories we track
        soft_num_clients: 750,  // soft limit on the number of inbound p2p connections
        max_neighbors_per_host: 1, // maximum number of neighbors per host we permit
        max_clients_per_host: 4, // maximum number of inbound p2p connections per host we permit
        soft_max_neighbors_per_host: 1, // soft limit on the number of neighbors per host we permit
        soft_max_neighbors_per_org: 32, // soft limit on the number of neighbors per AS we permit (TODO: for now it must be greater than num_neighbors)
        soft_max_clients_per_host: 4, // soft limit on how many inbound p2p connections per host we permit
        max_http_clients: 1000,       // maximum number of HTTP connections
        max_neighbors_of_neighbor: 10, // maximum number of neighbors we'll handshake with when doing a neighbor walk (I/O for this can be expensive, so keep small-ish)
        walk_interval: 60,             // how often, in seconds, we do a neighbor walk
        walk_seed_probability: 0.1, // 10% of the time when not in IBD, walk to a non-seed node even if we aren't connected to a seed node
        log_neighbors_freq: 60_000, // every minute, log all peer connections
        inv_sync_interval: 45,      // how often, in seconds, we refresh block inventories
        inv_reward_cycles: 3,       // how many reward cycles to look back on, for mainnet
        download_interval: 10, // how often, in seconds, we do a block download scan (should be less than inv_sync_interval)
        dns_timeout: 15_000,
        max_inflight_blocks: 6,
        max_inflight_attachments: 6,
        ..std::default::Default::default()
    });

pub static DEFAULT_MAINNET_CONFIG: LazyLock<Config> = LazyLock::new(|| {
    Config::from_config_file(ConfigFile::mainnet(), false)
        .expect("Failed to create default mainnet config")
});

#[derive(Clone, Deserialize, Default, Debug)]
#[serde(deny_unknown_fields)]
pub struct ConfigFile {
    pub __path: Option<String>, // Only used for config file reloads
    pub burnchain: Option<BurnchainConfigFile>,
    pub node: Option<NodeConfigFile>,
    /// Represents an initial STX balance allocation for an address at genesis
    /// for testing purposes.
    ///
    /// This struct is used to define pre-allocated STX balances that are credited to
    /// specific addresses when the Stacks node first initializes its chainstate. These balances
    /// are included in the genesis block and are immediately available for spending.
    ///
    /// **Configuration:**
    /// Configured as a list `[[ustx_balance]]` in TOML.
    ///
    /// Example TOML entry:
    /// ```toml
    /// [[ustx_balance]]
    /// address = "ST2QKZ4FKHAH1NQKYKYAYZPY440FEPK7GZ1R5HBP2"
    /// amount = 10000000000000000
    /// ```
    ///
    /// This is intended strictly for testing purposes.
    /// Attempting to specify initial balances if [`BurnchainConfig::mode`] is "mainnet" will
    /// result in an invalid config error.
    ///
    /// Default: `None`
    pub ustx_balance: Option<Vec<InitialBalanceFile>>,
    /// Deprecated: use `ustx_balance` instead
    pub mstx_balance: Option<Vec<InitialBalanceFile>>,
    pub events_observer: Option<HashSet<EventObserverConfigFile>>,
    pub connection_options: Option<ConnectionOptionsFile>,
    pub fee_estimation: Option<FeeEstimationConfigFile>,
    pub miner: Option<MinerConfigFile>,
    pub atlas: Option<AtlasConfigFile>,
}

impl ConfigFile {
    pub fn from_path(path: &str) -> Result<ConfigFile, String> {
        let content = fs::read_to_string(path).map_err(|e| format!("Invalid path: {e}"))?;
        let mut f = Self::from_str(&content)?;
        f.__path = Some(path.to_string());
        Ok(f)
    }

    #[allow(clippy::should_implement_trait)]
    pub fn from_str(content: &str) -> Result<ConfigFile, String> {
        let mut config: ConfigFile =
            toml::from_str(content).map_err(|e| format!("Invalid toml: {e}"))?;
        if let Some(mstx_balance) = config.mstx_balance.take() {
            warn!("'mstx_balance' in the config is deprecated; please use 'ustx_balance' instead.");
            match config.ustx_balance {
                Some(ref mut ustx_balance) => {
                    ustx_balance.extend(mstx_balance);
                }
                None => {
                    config.ustx_balance = Some(mstx_balance);
                }
            }
        }
        Ok(config)
    }

    pub fn xenon() -> ConfigFile {
        let burnchain = BurnchainConfigFile {
            mode: Some("xenon".to_string()),
            rpc_port: Some(18332),
            peer_port: Some(18333),
            peer_host: Some("0.0.0.0".to_string()),
            magic_bytes: Some("T2".into()),
            ..BurnchainConfigFile::default()
        };

        let node = NodeConfigFile {
            bootstrap_node: Some("029266faff4c8e0ca4f934f34996a96af481df94a89b0c9bd515f3536a95682ddc@seed.testnet.hiro.so:30444".to_string()),
            miner: Some(false),
            stacker: Some(false),
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
            peer_host: Some("0.0.0.0".to_string()),
            username: Some("bitcoin".to_string()),
            password: Some("bitcoin".to_string()),
            magic_bytes: Some("X2".to_string()),
            ..BurnchainConfigFile::default()
        };

        let node = NodeConfigFile {
            bootstrap_node: Some("02196f005965cebe6ddc3901b7b1cc1aa7a88f305bb8c5893456b8f9a605923893@seed.mainnet.hiro.so:20444,02539449ad94e6e6392d8c1deb2b4e61f80ae2a18964349bc14336d8b903c46a8c@cet.stacksnodes.org:20444,02ececc8ce79b8adf813f13a0255f8ae58d4357309ba0cedd523d9f1a306fcfb79@sgt.stacksnodes.org:20444,0303144ba518fe7a0fb56a8a7d488f950307a4330f146e1e1458fc63fb33defe96@est.stacksnodes.org:20444".to_string()),
            miner: Some(false),
            stacker: Some(false),
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
            stacker: Some(false),
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
            stacker: Some(false),
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

impl Config {
    /// get the up-to-date burnchain options from the config.
    /// If the config file can't be loaded, then return the existing config
    pub fn get_burnchain_config(&self) -> BurnchainConfig {
        let Some(path) = &self.config_path else {
            return self.burnchain.clone();
        };
        let Ok(config_file) = ConfigFile::from_path(path.as_str()) else {
            return self.burnchain.clone();
        };
        let Ok(config) = Config::from_config_file(config_file, false) else {
            return self.burnchain.clone();
        };
        config.burnchain
    }

    /// get the up-to-date miner options from the config
    /// If the config can't be loaded for some reason, then return the existing config
    pub fn get_miner_config(&self) -> MinerConfig {
        let Some(path) = &self.config_path else {
            return self.miner.clone();
        };
        let Ok(config_file) = ConfigFile::from_path(path.as_str()) else {
            return self.miner.clone();
        };
        let Ok(config) = Config::from_config_file(config_file, false) else {
            return self.miner.clone();
        };
        config.miner
    }

    pub fn get_node_config(&self, resolve_bootstrap_nodes: bool) -> NodeConfig {
        let Some(path) = &self.config_path else {
            return self.node.clone();
        };
        let Ok(config_file) = ConfigFile::from_path(path.as_str()) else {
            return self.node.clone();
        };
        let Ok(config) = Config::from_config_file(config_file, resolve_bootstrap_nodes) else {
            return self.node.clone();
        };
        config.node
    }

    /// Apply any test settings to this burnchain config struct
    #[cfg_attr(test, mutants::skip)]
    fn apply_test_settings(&self, burnchain: &mut Burnchain) {
        if self.burnchain.get_bitcoin_network().1 == BitcoinNetworkType::Mainnet {
            return;
        }

        if let Some(first_burn_block_height) = self.burnchain.first_burn_block_height {
            debug!(
                "Override first_block_height from {} to {first_burn_block_height}",
                burnchain.first_block_height
            );
            burnchain.first_block_height = first_burn_block_height;
        }

        if let Some(first_burn_block_timestamp) = self.burnchain.first_burn_block_timestamp {
            debug!(
                "Override first_block_timestamp from {} to {first_burn_block_timestamp}",
                burnchain.first_block_timestamp
            );
            burnchain.first_block_timestamp = first_burn_block_timestamp;
        }

        if let Some(first_burn_block_hash) = &self.burnchain.first_burn_block_hash {
            debug!(
                "Override first_burn_block_hash from {} to {first_burn_block_hash}",
                burnchain.first_block_hash
            );
            burnchain.first_block_hash = BurnchainHeaderHash::from_hex(first_burn_block_hash)
                .expect("Invalid first_burn_block_hash");
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
                "Override v1_unlock_height from {} to {v1_unlock_height}",
                burnchain.pox_constants.v1_unlock_height
            );
            burnchain.pox_constants.v1_unlock_height = v1_unlock_height;
        }

        if let Some(epochs) = &self.burnchain.epochs {
            if let Some(epoch) = epochs.get(StacksEpochId::Epoch10) {
                // Epoch 1.0 start height can be equal to the first block height iff epoch 2.0
                // start height is also equal to the first block height.
                assert!(
                    epoch.start_height <= burnchain.first_block_height,
                    "FATAL: Epoch 1.0 start height must be at or before the first block height"
                );
            }

            if let Some(epoch) = epochs.get(StacksEpochId::Epoch20) {
                assert_eq!(
                    epoch.start_height, burnchain.first_block_height,
                    "FATAL: Epoch 2.0 start height must match the first block height"
                );
            }

            if let Some(epoch) = epochs.get(StacksEpochId::Epoch21) {
                // Override v1_unlock_height to the start_height of epoch2.1
                debug!(
                    "Override v2_unlock_height from {} to {}",
                    burnchain.pox_constants.v1_unlock_height,
                    epoch.start_height + 1
                );
                burnchain.pox_constants.v1_unlock_height = epoch.start_height as u32 + 1;
            }

            if let Some(epoch) = epochs.get(StacksEpochId::Epoch22) {
                // Override v2_unlock_height to the start_height of epoch2.2
                debug!(
                    "Override v2_unlock_height from {} to {}",
                    burnchain.pox_constants.v2_unlock_height,
                    epoch.start_height + 1
                );
                burnchain.pox_constants.v2_unlock_height = epoch.start_height as u32 + 1;
            }

            if let Some(epoch) = epochs.get(StacksEpochId::Epoch24) {
                // Override pox_3_activation_height to the start_height of epoch2.4
                debug!(
                    "Override pox_3_activation_height from {} to {}",
                    burnchain.pox_constants.pox_3_activation_height, epoch.start_height
                );
                burnchain.pox_constants.pox_3_activation_height = epoch.start_height as u32;
            }

            if let Some(epoch) = epochs.get(StacksEpochId::Epoch25) {
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
                "Override sunset_start from {} to {sunset_start}",
                burnchain.pox_constants.sunset_start
            );
            burnchain.pox_constants.sunset_start = sunset_start.into();
        }

        if let Some(sunset_end) = self.burnchain.sunset_end {
            debug!(
                "Override sunset_end from {} to {sunset_end}",
                burnchain.pox_constants.sunset_end
            );
            burnchain.pox_constants.sunset_end = sunset_end.into();
        }

        // check if the Epoch 3.0 burnchain settings as configured are going to be valid.
        self.check_nakamoto_config(burnchain);
    }

    fn check_nakamoto_config(&self, burnchain: &Burnchain) {
        let epochs = self.burnchain.get_epoch_list();
        let Some(epoch_30) = epochs.get(StacksEpochId::Epoch30) else {
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
        let activation_reward_cycle = burnchain
            .block_height_to_reward_cycle(epoch_30.start_height)
            .expect("FATAL: Epoch 3.0 starts before the first burnchain block");
        if activation_reward_cycle < 2 {
            panic!(
                "FATAL: Epoch 3.0 must start at or after the second reward cycle. Epoch 3.0 start set to: {}. PoX Parameters: {:?}",
                epoch_30.start_height,
                &burnchain.pox_constants
            );
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
                    error!("Failed to instantiate burnchain: {e}");
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
        let validated = StacksEpoch::validate_epochs(epochs);

        // sanity check: v1_unlock_height must happen after pox-2 instantiation
        let epoch21 = validated
            .get(StacksEpochId::Epoch21)
            .expect("FATAL: no epoch 2.1 defined");
        let v1_unlock_height = burnchain.pox_constants.v1_unlock_height as u64;

        assert!(
            v1_unlock_height > epoch21.start_height,
            "FATAL: v1 unlock height occurs at or before pox-2 activation: {v1_unlock_height} <= {}\nburnchain: {burnchain:?}", epoch21.start_height
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
                "FATAL: v1 unlock height is at a reward cycle boundary\nburnchain: {burnchain:?}"
            );
        }
    }

    // TODO: add tests from mutation testing results #4866
    #[cfg_attr(test, mutants::skip)]
    fn make_epochs(
        conf_epochs: &[StacksEpochConfigFile],
        burn_mode: &str,
        bitcoin_network: BitcoinNetworkType,
        pox_2_activation: Option<u32>,
    ) -> Result<EpochList<ExecutionCost>, String> {
        let default_epochs = match bitcoin_network {
            BitcoinNetworkType::Mainnet => {
                Err("Cannot configure epochs in mainnet mode".to_string())
            }
            BitcoinNetworkType::Testnet => Ok(STACKS_EPOCHS_TESTNET.clone().to_vec()),
            BitcoinNetworkType::Regtest => Ok(STACKS_EPOCHS_REGTEST.clone().to_vec()),
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
            } else if epoch_name == EPOCH_CONFIG_3_1_0 {
                Ok(StacksEpochId::Epoch31)
            } else if epoch_name == EPOCH_CONFIG_3_2_0 {
                Ok(StacksEpochId::Epoch32)
            } else {
                Err(format!("Unknown epoch name specified: {epoch_name}"))
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
            StacksEpochId::Epoch31,
            StacksEpochId::Epoch32,
        ];
        for (expected_epoch, configured_epoch) in expected_list
            .iter()
            .zip(matched_epochs.iter().map(|(epoch_id, _)| epoch_id))
        {
            if expected_epoch != configured_epoch {
                return Err(format!("Configured epochs may not skip an epoch. Expected epoch = {expected_epoch}, Found epoch = {configured_epoch}"));
            }
        }

        // Stacks 1.0 must start at 0
        if matched_epochs
            .first()
            .ok_or_else(|| "Must configure at least 1 epoch")?
            .1
            != 0
        {
            return Err("Stacks 1.0 must start at height = 0".into());
        }

        let mut out_epochs = default_epochs
            .get(..matched_epochs.len())
            .ok_or_else(|| {
                format!(
                "Cannot configure more epochs than support by this node. Supported epoch count: {}",
                default_epochs.len()
            )
            })?
            .to_vec();

        for (i, ((epoch_id, start_height), out_epoch)) in
            matched_epochs.iter().zip(out_epochs.iter_mut()).enumerate()
        {
            if epoch_id != &out_epoch.epoch_id {
                return Err(
                    format!("Unmatched epochs in configuration and node implementation. Implemented = {epoch_id}, Configured = {}",
                            &out_epoch.epoch_id));
            }
            // end_height = next epoch's start height || i64::max if last epoch
            let end_height = if let Some(next_epoch) = matched_epochs.get(i + 1) {
                next_epoch.1
            } else {
                i64::MAX
            };
            out_epoch.start_height = u64::try_from(*start_height)
                .map_err(|_| "Start height must be a non-negative integer")?;
            out_epoch.end_height = u64::try_from(end_height)
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
                Err(format!("Cannot configure pox_2_activation at a lower height than the Epoch 2.1 start height. pox_2_activation = {pox_2_activation}, epoch 2.1 start height = {}", last_epoch.start_height))?;
            }
        }

        Ok(EpochList::new(&out_epochs))
    }

    pub fn from_config_file(
        config_file: ConfigFile,
        resolve_bootstrap_nodes: bool,
    ) -> Result<Config, String> {
        Self::from_config_default(config_file, Config::default(), resolve_bootstrap_nodes)
    }

    fn from_config_default(
        config_file: ConfigFile,
        default: Config,
        resolve_bootstrap_nodes: bool,
    ) -> Result<Config, String> {
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

        let supported_modes = [
            "mocknet",
            "helium",
            "neon",
            "argon",
            "krypton",
            "xenon",
            "mainnet",
            "nakamoto-neon",
        ];

        if !supported_modes.contains(&burnchain.mode.as_str()) {
            return Err(format!(
                "Setting burnchain.network not supported (should be: {})",
                supported_modes.join(", ")
            ));
        }

        if burnchain.mode == "helium" && burnchain.local_mining_public_key.is_none() {
            return Err("Config is missing the setting `burnchain.local_mining_public_key` (mandatory for helium)".into());
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
            if resolve_bootstrap_nodes {
                node.set_bootstrap_nodes(
                    bootstrap_node,
                    burnchain.chain_id,
                    burnchain.peer_version,
                );
            }
        } else if is_mainnet && resolve_bootstrap_nodes {
            let bootstrap_node = ConfigFile::mainnet().node.unwrap().bootstrap_node.unwrap();
            node.set_bootstrap_nodes(bootstrap_node, burnchain.chain_id, burnchain.peer_version);
        }
        if let Some(deny_nodes) = deny_nodes {
            node.set_deny_nodes(deny_nodes, burnchain.chain_id, burnchain.peer_version);
        }

        // Validate the node config
        if is_mainnet && node.use_test_genesis_chainstate == Some(true) {
            return Err("Attempted to run mainnet node with `use_test_genesis_chainstate`".into());
        }

        if node.stacker || node.miner {
            node.add_miner_stackerdb(is_mainnet);
            node.add_signers_stackerdbs(is_mainnet);
        }

        let miner = match config_file.miner {
            Some(mut miner) => {
                if miner.mining_key.is_none() && !node.seed.is_empty() {
                    miner.mining_key = Some(to_hex(&node.seed));
                }
                miner.into_config_default(miner_default_config)?
            }
            None => miner_default_config,
        };

        if is_mainnet && miner.replay_transactions {
            return Err("Attempted to run mainnet node with `replay_transactions` set to true. This feature is still incomplete and may not be enabled on a mainnet node".into());
        }
        let initial_balances: Vec<InitialBalance> = match config_file.ustx_balance {
            Some(balances) => {
                if is_mainnet && !balances.is_empty() {
                    return Err(
                        "Attempted to run mainnet node with specified `initial_balances`".into(),
                    );
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

                    observers.insert(EventObserverConfig {
                        endpoint: observer.endpoint,
                        events_keys,
                        timeout_ms: observer.timeout_ms.unwrap_or(1_000),
                        disable_retries: observer.disable_retries.unwrap_or(false),
                    });
                }
                observers
            }
            None => HashSet::new(),
        };

        // check for observer config in env vars
        if let Ok(val) = std::env::var("STACKS_EVENT_OBSERVER") {
            events_observers.insert(EventObserverConfig {
                endpoint: val,
                events_keys: vec![EventKeyType::AnyEvent],
                timeout_ms: 1_000,
                disable_retries: false,
            });
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

        if miner.mining_key.is_none() && miner.pre_nakamoto_mock_signing {
            return Err("Cannot use pre_nakamoto_mock_signing without a mining_key".to_string());
        }

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

    /// Returns the path working directory path, and ensures it exists.
    pub fn get_working_dir(&self) -> PathBuf {
        let path = PathBuf::from(&self.node.working_dir);
        fs::create_dir_all(&path).unwrap_or_else(|_| {
            panic!(
                "Failed to create working directory at {}",
                path.to_string_lossy()
            )
        });
        path
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
        fs::create_dir_all(&path).unwrap_or_else(|_| {
            panic!(
                "Failed to create `estimates` directory at {}",
                path.to_string_lossy()
            )
        });
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
        matches!(self.burnchain.mode.as_str(), "mainnet")
    }

    pub fn is_node_event_driven(&self) -> bool {
        !self.events_observers.is_empty()
    }

    pub fn make_nakamoto_block_builder_settings(
        &self,
        miner_status: Arc<Mutex<MinerStatus>>,
    ) -> BlockBuilderSettings {
        let miner_config = self.get_miner_config();
        BlockBuilderSettings {
            max_miner_time_ms: miner_config.nakamoto_attempt_time_ms,
            mempool_settings: MemPoolWalkSettings {
                strategy: miner_config.mempool_walk_strategy,
                max_walk_time_ms: miner_config.nakamoto_attempt_time_ms,
                consider_no_estimate_tx_prob: miner_config.probability_pick_no_estimate_tx,
                nonce_cache_size: miner_config.nonce_cache_size,
                candidate_retry_cache_size: miner_config.candidate_retry_cache_size,
                txs_to_consider: miner_config.txs_to_consider,
                filter_origins: miner_config.filter_origins,
                tenure_cost_limit_per_block_percentage: miner_config
                    .tenure_cost_limit_per_block_percentage,
                contract_cost_limit_percentage: miner_config.contract_cost_limit_percentage,
                log_skipped_transactions: miner_config.log_skipped_transactions,
            },
            miner_status,
            confirm_microblocks: false,
            max_execution_time: miner_config
                .max_execution_time_secs
                .map(Duration::from_secs),
            max_tenure_bytes: miner_config.max_tenure_bytes,
        }
    }

    // TODO: add tests from mutation testing results #4867
    #[cfg_attr(test, mutants::skip)]
    pub fn make_block_builder_settings(
        &self,
        attempt: u64,
        microblocks: bool,
        miner_status: Arc<Mutex<MinerStatus>>,
    ) -> BlockBuilderSettings {
        let miner_config = self.get_miner_config();
        BlockBuilderSettings {
            max_miner_time_ms: if microblocks {
                miner_config.microblock_attempt_time_ms
            } else if attempt <= 1 {
                // first attempt to mine a block -- do so right away
                miner_config.first_attempt_time_ms
            } else {
                // second or later attempt to mine a block -- give it some time
                miner_config.subsequent_attempt_time_ms
            },
            mempool_settings: MemPoolWalkSettings {
                max_walk_time_ms: if microblocks {
                    miner_config.microblock_attempt_time_ms
                } else if attempt <= 1 {
                    // first attempt to mine a block -- do so right away
                    miner_config.first_attempt_time_ms
                } else {
                    // second or later attempt to mine a block -- give it some time
                    miner_config.subsequent_attempt_time_ms
                },
                strategy: miner_config.mempool_walk_strategy,
                consider_no_estimate_tx_prob: miner_config.probability_pick_no_estimate_tx,
                nonce_cache_size: miner_config.nonce_cache_size,
                candidate_retry_cache_size: miner_config.candidate_retry_cache_size,
                txs_to_consider: miner_config.txs_to_consider,
                filter_origins: miner_config.filter_origins,
                tenure_cost_limit_per_block_percentage: miner_config
                    .tenure_cost_limit_per_block_percentage,
                contract_cost_limit_percentage: miner_config.contract_cost_limit_percentage,
                log_skipped_transactions: miner_config.log_skipped_transactions,
            },
            miner_status,
            confirm_microblocks: true,
            max_execution_time: miner_config
                .max_execution_time_secs
                .map(Duration::from_secs),
            max_tenure_bytes: miner_config.max_tenure_bytes,
        }
    }

    pub fn get_miner_stats(&self) -> Option<MinerStats> {
        let miner_config = self.get_miner_config();
        if let Some(unconfirmed_commits_helper) = miner_config.unconfirmed_commits_helper.as_ref() {
            let miner_stats = MinerStats {
                unconfirmed_commits_helper: unconfirmed_commits_helper.clone(),
            };
            return Some(miner_stats);
        }
        None
    }

    /// Determine how long the p2p state machine should poll for.
    /// If the node is not mining, then use a default value.
    /// If the node is mining, however, then at the time of this writing, the miner's latency is in
    /// part dependent on the state machine getting block data back to the miner quickly, and thus
    /// the poll time is dependent on the first attempt time.
    pub fn get_poll_time(&self) -> u64 {
        if self.node.miner {
            cmp::min(1000, self.miner.first_attempt_time_ms / 2)
        } else {
            1000
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

#[derive(Clone, Debug, Default, Deserialize, PartialEq)]
pub struct BurnchainConfig {
    /// The underlying blockchain used for Proof-of-Transfer.
    /// ---
    /// @default: `"bitcoin"`
    /// @notes:
    ///   - Currently, only `"bitcoin"` is supported.
    pub chain: String,
    /// The operational mode or network profile for the Stacks node.
    /// This setting determines network parameters (like chain ID, peer version),
    /// default configurations, genesis block definitions, and overall node behavior.
    ///
    /// Supported values:
    /// - `"mainnet"`: mainnet
    /// - `"xenon"`: testnet
    /// - `"mocknet"`: regtest
    /// - `"helium"`: regtest
    /// - `"neon"`: regtest
    /// - `"argon"`: regtest
    /// - `"krypton"`: regtest
    /// - `"nakamoto-neon"`: regtest
    /// ---
    /// @default: `"mocknet"`
    pub mode: String,
    /// The network-specific identifier used in P2P communication and database initialization.
    /// ---
    /// @default: |
    ///   - if [`BurnchainConfig::mode`] is `"mainnet"`: [`CHAIN_ID_MAINNET`]
    ///   - else: [`CHAIN_ID_TESTNET`]
    /// @notes:
    ///   - **Warning:** Do not modify this unless you really know what you're doing.
    ///   - This is intended strictly for testing purposes.
    pub chain_id: u32,
    /// The peer protocol version number used in P2P communication.
    /// This parameter cannot be set via the configuration file.
    /// ---
    /// @default: |
    ///   - if [`BurnchainConfig::mode`] is `"mainnet"`: [`PEER_VERSION_MAINNET`]
    ///   - else: [`PEER_VERSION_TESTNET`]
    /// @notes:
    ///   - **Warning:** Do not modify this unless you really know what you're doing.
    pub peer_version: u32,
    /// Specifies a mandatory wait period (in milliseconds) after receiving a burnchain tip
    /// before the node attempts to build the anchored block for the new tenure.
    /// This duration effectively schedules the start of the block-building process
    /// relative to the tip's arrival time.
    /// ---
    /// @default: `5_000`
    /// @units: milliseconds
    /// @notes:
    ///   - This is intended strictly for testing purposes.
    pub commit_anchor_block_within: u64,
    /// The maximum amount (in sats) of "burn commitment" to broadcast for the next
    /// block's leader election. Acts as a safety cap to limit the maximum amount
    /// spent on mining. It serves as both the target fee and a fallback if dynamic
    /// fee calculations fail or cannot be performed.
    ///
    /// This setting can be hot-reloaded from the config file, allowing adjustment
    /// without restarting.
    /// ---
    /// @default: `20_000`
    /// @units: satoshis
    /// @notes:
    ///   - Only relevant if [`NodeConfig::miner`] is `true`.
    pub burn_fee_cap: u64,
    /// The hostname or IP address of the bitcoin node peer.
    ///
    /// This field is required for all node configurations as it specifies where to
    /// find the underlying bitcoin node to interact with for PoX operations,
    /// block validation, and mining.
    /// ---
    /// @default: `"0.0.0.0"`
    pub peer_host: String,
    /// The P2P network port of the bitcoin node specified by [`BurnchainConfig::peer_host`].
    /// ---
    /// @default: `8333`
    pub peer_port: u16,
    /// The RPC port of the bitcoin node specified by [`BurnchainConfig::peer_host`].
    /// ---
    /// @default: `8332`
    pub rpc_port: u16,
    /// Flag indicating whether to use SSL/TLS when connecting to the bitcoin node's
    /// RPC interface.
    /// ---
    /// @default: `false`
    pub rpc_ssl: bool,
    /// The username for authenticating with the bitcoin node's RPC interface.
    /// Required if the bitcoin node requires RPC authentication.
    /// ---
    /// @default: `None`
    /// @notes:
    ///   - Only relevant if [`NodeConfig::miner`] is `true`.
    pub username: Option<String>,
    /// The password for authenticating with the bitcoin node's RPC interface.
    /// Required if the bitcoin node requires RPC authentication.
    /// ---
    /// @default: `None`
    /// @notes:
    ///   - Only relevant if [`NodeConfig::miner`] is `true`.
    pub password: Option<String>,
    /// Timeout duration, in seconds, for RPC calls made to the bitcoin node.
    /// Configures the timeout on the underlying HTTP client.
    /// ---
    /// @default: `300`
    /// @units: seconds
    pub timeout: u64,
    /// Timeout duration, in seconds, for socket operations (read/write) with the bitcoin node.
    /// Controls how long the node will wait for socket operations to complete before timing out.
    /// ---
    /// @default: `30`
    /// @units: seconds
    pub socket_timeout: u64,
    /// The network "magic bytes" used to identify packets for the specific bitcoin
    /// network instance (e.g., mainnet, testnet, regtest). Must match the magic
    /// bytes of the connected bitcoin node.
    ///
    /// These two-byte identifiers help ensure that nodes only connect to peers on the
    /// same network type. Common values include:
    /// - "X2" for mainnet
    /// - "T2" for testnet (xenon)
    /// - Other values for specific test networks
    ///
    /// Configured as a 2-character ASCII string (e.g., "X2" for mainnet).
    /// ---
    /// @default: |
    ///   - if [`BurnchainConfig::mode`] is `"xenon"`: `"T2"`
    ///   - else: `"X2"`
    pub magic_bytes: MagicBytes,
    /// The public key associated with the local mining address for the underlying
    /// Bitcoin regtest node. Provided as a hex string representing an uncompressed
    /// public key.
    ///
    /// It is primarily used in modes that rely on a controlled Bitcoin regtest
    /// backend (e.g., "helium", "mocknet", "neon") where the Stacks node itself
    /// needs to instruct the Bitcoin node to generate blocks.
    ///
    /// The key is used to derive the Bitcoin address that receives the coinbase
    /// rewards when generating blocks on the regtest network.
    /// ---
    /// @default: `None`
    /// @notes:
    ///   - Mandatory if [`BurnchainConfig::mode`] is "helium".
    ///   - This is intended strictly for testing purposes.
    pub local_mining_public_key: Option<String>,
    /// Optional bitcoin block height at which the Stacks node process should
    /// gracefully exit. When bitcoin reaches this height, the node logs a message
    /// and initiates a graceful shutdown.
    /// ---
    /// @default: `None`
    /// @notes:
    ///   - Applied only if [`BurnchainConfig::mode`] is not "mainnet".
    ///   - This is intended strictly for testing purposes.
    pub process_exit_at_block_height: Option<u64>,
    /// The interval, in seconds, at which the node polls the bitcoin node for new
    /// blocks and state updates.
    ///
    /// The default value of 10 seconds is mainly intended for testing purposes.
    /// It's suggested to set this to a higher value for mainnet, e.g., 300 seconds
    /// (5 minutes).
    /// ---
    /// @default: `10`
    /// @units: seconds
    pub poll_time_secs: u64,
    /// The default fee rate in sats/vByte to use when estimating fees for miners
    /// to submit bitcoin transactions (like block commits or leader key registrations).
    /// ---
    /// @default: [`DEFAULT_SATS_PER_VB`]
    /// @units: sats/vByte
    /// @notes:
    ///   - Only relevant if [`NodeConfig::miner`] is `true`.
    pub satoshis_per_byte: u64,
    /// Maximum fee rate multiplier allowed when using Replace-By-Fee (RBF) for
    /// bitcoin transactions. Expressed as a percentage of the original
    /// [`BurnchainConfig::satoshis_per_byte`] rate (e.g., 150 means the fee rate
    /// can be increased up to 1.5x). Used in mining logic for RBF decisions to
    /// cap the replacement fee rate.
    /// ---
    /// @default: [`DEFAULT_MAX_RBF_RATE`]
    /// @units: percent
    /// @notes:
    ///   - Only relevant if [`NodeConfig::miner`] is `true`.
    pub max_rbf: u64,
    /// Estimated size (in virtual bytes) of a leader key registration transaction
    /// on bitcoin. Used for fee calculation in mining logic by multiplying with the
    /// fee rate [`BurnchainConfig::satoshis_per_byte`].
    /// ---
    /// @default: [`OP_TX_LEADER_KEY_ESTIM_SIZE`]
    /// @units: virtual bytes
    /// @notes:
    ///   - Only relevant if [`NodeConfig::miner`] is `true`.
    pub leader_key_tx_estimated_size: u64,
    /// Estimated size (in virtual bytes) of a block commit transaction on bitcoin.
    /// Used for fee calculation in mining logic by multiplying with the fee rate
    /// [`BurnchainConfig::satoshis_per_byte`].
    /// ---
    /// @default: [`OP_TX_BLOCK_COMMIT_ESTIM_SIZE`]
    /// @units: virtual bytes
    /// @notes:
    ///   - Only relevant if [`NodeConfig::miner`] is `true`.
    pub block_commit_tx_estimated_size: u64,
    /// The incremental amount (in sats/vByte) to add to the previous transaction's
    /// fee rate for RBF bitcoin transactions.
    /// ---
    /// @default: [`DEFAULT_RBF_FEE_RATE_INCREMENT`]
    /// @units: sats/vByte
    /// @notes:
    ///   - Only relevant if [`NodeConfig::miner`] is `true`.
    pub rbf_fee_increment: u64,
    /// Overrides the default starting bitcoin block height for the node.
    /// Allows starting synchronization from a specific historical point in test environments.
    /// ---
    /// @default: `None` (uses the burnchain's default starting height for the mode)
    /// @notes:
    ///   - Applied only if [`BurnchainConfig::mode`] is not "mainnet".
    ///   - This is intended strictly for testing purposes.
    ///   - Should be used together with [`BurnchainConfig::first_burn_block_timestamp`] and
    ///     [`BurnchainConfig::first_burn_block_hash`] for proper operation.
    pub first_burn_block_height: Option<u64>,
    /// Overrides the default starting block timestamp of the burnchain.
    /// ---
    /// @default: `None` (uses the burnchain's default starting timestamp)
    /// @notes:
    ///   - Applied only if [`BurnchainConfig::mode`] is not "mainnet".
    ///   - This is intended strictly for testing purposes.
    ///   - Should be used together with [`BurnchainConfig::first_burn_block_height`] and
    ///     [`BurnchainConfig::first_burn_block_hash`] for proper operation.
    pub first_burn_block_timestamp: Option<u32>,
    /// Overrides the default starting block hash of the burnchain.
    /// ---
    /// @default: `None` (uses the burnchain's default starting block hash)
    /// @notes:
    ///   - Applied only if [`BurnchainConfig::mode`] is not "mainnet".
    ///   - This is intended strictly for testing purposes.
    ///   - Should be used together with [`BurnchainConfig::first_burn_block_height`] and
    ///     [`BurnchainConfig::first_burn_block_timestamp`] for proper operation.
    pub first_burn_block_hash: Option<String>,
    /// Custom override for the definitions of Stacks epochs (start/end burnchain
    /// heights, consensus rules). This setting allows testing specific epoch
    /// transitions or custom consensus rules by defining exactly when each epoch
    /// starts on bitcoin.
    ///
    /// Epochs define distinct protocol rule sets (consensus rules, execution costs,
    /// capabilities). When configured, the list must include all epochs
    /// sequentially from "1.0" up to the highest desired epoch, without skipping
    /// any intermediate ones. Valid `epoch_name` values currently include:
    /// `"1.0"`, `"2.0"`, `"2.05"`, `"2.1"`, `"2.2"`, `"2.3"`, `"2.4"`, `"2.5"`, `"3.0"`, `"3.1"`.
    ///
    /// **Validation Rules:**
    /// - Epochs must be provided in strict chronological order (`1.0`, `2.0`, `2.05`...).
    /// - `start_height` values must be non-decreasing across the list.
    /// - Epoch `"1.0"` must have `start_height = 0`.
    /// - The number of defined epochs cannot exceed the maximum supported by the node software.
    /// ---
    /// @default: `None` (uses the standard epoch definitions for the selected [`BurnchainConfig::mode`])
    /// @notes:
    ///   - Applied only if [`BurnchainConfig::mode`] is not "mainnet".
    ///   - This is intended strictly for testing purposes.
    ///   - Configured as a list `[[burnchain.epochs]]` in TOML, each with `epoch_name` (string)
    ///     and `start_height` (integer Bitcoin block height).
    /// @toml_example: |
    ///   [[burnchain.epochs]]
    ///   epoch_name = "2.1"
    ///   start_height = 150
    ///
    ///   [[burnchain.epochs]]
    ///   epoch_name = "2.2"
    ///   start_height = 200
    pub epochs: Option<EpochList<ExecutionCost>>,
    /// Sets a custom burnchain height for PoX-2 activation (for testing).
    ///
    /// This affects two key transitions:
    /// 1. The block height at which PoX v1 lockups are automatically unlocked.
    /// 2. The block height from which PoX reward set calculations switch to PoX v2 rules.
    ///
    /// **Behavior:**
    /// - This value directly sets the auto unlock height for PoX v1 lockups before
    ///   transition to PoX v2. This also defines the burn height at which PoX reward
    ///   sets are calculated using PoX v2 rather than v1.
    /// - If custom [`BurnchainConfig::epochs`] are provided:
    ///   - This value is used to validate that Epoch 2.1's start height is ≤ this value.
    ///   - However, the height specified in `epochs` for Epoch 2.1 takes precedence.
    /// ---
    /// @default: `None`
    /// @notes:
    ///   - Applied only if [`BurnchainConfig::mode`] is not "mainnet".
    ///   - This is intended strictly for testing purposes.
    pub pox_2_activation: Option<u32>,
    /// Overrides the length (in bitcoin blocks) of the PoX reward cycle.
    /// ---
    /// @default: `None` (uses the standard reward cycle length for the mode)
    /// @units: bitcoin blocks
    /// @notes:
    ///   - Applied only if [`BurnchainConfig::mode`] is not "mainnet".
    ///   - This is intended strictly for testing purposes.
    pub pox_reward_length: Option<u32>,
    /// Overrides the length (in bitcoin blocks) of the PoX prepare phase.
    /// ---
    /// @default: `None` (uses the standard prepare phase length for the mode)
    /// @units: bitcoin blocks
    /// @notes:
    ///   - Applied only if [`BurnchainConfig::mode`] is not "mainnet".
    ///   - This is intended strictly for testing purposes.
    pub pox_prepare_length: Option<u32>,
    /// Overrides the bitcoin height at which the PoX sunset period begins in epochs
    /// before 2.1. The sunset period represents a planned phase-out of the PoX
    /// mechanism. During this period, stacking rewards gradually decrease,
    /// eventually ceasing entirely. This parameter allows testing the PoX sunset
    /// transition by explicitly setting its start height.
    /// ---
    /// @default: `None` (uses the standard sunset start height for the mode)
    /// @deprecated: The sunset phase was removed in Epoch 2.1.
    /// @notes:
    ///   - Applied only if [`BurnchainConfig::mode`] is not "mainnet".
    ///   - This is intended strictly for testing purposes for epochs before 2.1.
    pub sunset_start: Option<u32>,
    /// Overrides the bitcoin height, non-inclusive, at which the PoX sunset period
    /// ends in epochs before 2.1. After this height, Stacking rewards are disabled
    /// completely. This parameter works together with `sunset_start` to define the
    /// full sunset transition period for PoX.
    /// ---
    /// @default: `None` (uses the standard sunset end height for the mode)
    /// @deprecated: The sunset phase was removed in Epoch 2.1.
    /// @notes:
    ///   - Applied only if [`BurnchainConfig::mode`] is not "mainnet".
    ///   - This is intended strictly for testing purposes for epochs before 2.1.
    pub sunset_end: Option<u32>,
    /// Specifies the name of the Bitcoin wallet to use within the connected bitcoin
    /// node. Used to interact with a specific named wallet if the bitcoin node
    /// manages multiple wallets.
    ///
    /// If the specified wallet doesn't exist, the node will attempt to create it via
    /// the `createwallet` RPC call. This is particularly useful for miners who need
    /// to manage separate wallets.
    /// ---
    /// @default: `""` (empty string, implying the default wallet or no specific wallet needed)
    /// @notes:
    ///   - Primarily relevant for miners interacting with multi-wallet Bitcoin nodes.
    pub wallet_name: String,
    /// Fault injection setting for testing. Introduces an artificial delay (in
    /// milliseconds) before processing each burnchain block download. Simulates a
    /// slow burnchain connection.
    /// ---
    /// @default: `0` (no delay)
    /// @units: milliseconds
    /// @notes:
    ///   - This is intended strictly for testing purposes.
    pub fault_injection_burnchain_block_delay: u64,
    /// The maximum number of unspent transaction outputs (UTXOs) to request from
    /// the bitcoin node.
    ///
    /// This value is passed as the `maximumCount` parameter to the bitcoin node.
    /// It helps manage response size and processing load, particularly relevant
    /// for miners querying for available UTXOs to fund operations like block
    /// commits or leader key registrations.
    ///
    /// Setting this limit too high might lead to performance issues or timeouts when
    /// querying nodes with a very large number of UTXOs. Conversely, setting it too
    /// low might prevent the miner from finding enough UTXOs in a single query to
    /// meet the required funding amount for a transaction, even if sufficient funds
    /// exist across more UTXOs not returned by the limited query.
    /// ---
    /// @default: `1024`
    /// @notes:
    ///   - This value must be `<= 1024`.
    ///   - Only relevant if [`NodeConfig::miner`] is `true`.
    pub max_unspent_utxos: Option<u64>,
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
            socket_timeout: 30,
            magic_bytes: BLOCKSTACK_MAGIC_MAINNET,
            local_mining_public_key: None,
            process_exit_at_block_height: None,
            poll_time_secs: 10, // TODO: this is a testnet specific value.
            satoshis_per_byte: DEFAULT_SATS_PER_VB,
            max_rbf: DEFAULT_MAX_RBF_RATE,
            leader_key_tx_estimated_size: OP_TX_LEADER_KEY_ESTIM_SIZE,
            block_commit_tx_estimated_size: OP_TX_BLOCK_COMMIT_ESTIM_SIZE,
            rbf_fee_increment: DEFAULT_RBF_FEE_RATE_INCREMENT,
            first_burn_block_height: None,
            first_burn_block_timestamp: None,
            first_burn_block_hash: None,
            epochs: None,
            pox_2_activation: None,
            pox_prepare_length: None,
            pox_reward_length: None,
            sunset_start: None,
            sunset_end: None,
            wallet_name: "".to_string(),
            fault_injection_burnchain_block_delay: 0,
            max_unspent_utxos: Some(1024),
        }
    }
    pub fn get_rpc_url(&self, wallet: Option<String>) -> String {
        let scheme = match self.rpc_ssl {
            true => "https://",
            false => "http://",
        };
        let wallet_path = if let Some(wallet_id) = wallet.as_ref() {
            format!("/wallet/{wallet_id}")
        } else {
            "".to_string()
        };
        format!("{scheme}{}:{}{wallet_path}", self.peer_host, self.rpc_port)
    }

    pub fn get_rpc_socket_addr(&self) -> SocketAddr {
        let mut addrs_iter = format!("{}:{}", self.peer_host, self.rpc_port)
            .to_socket_addrs()
            .unwrap();
        addrs_iter.next().unwrap()
    }

    pub fn get_bitcoin_network(&self) -> (String, BitcoinNetworkType) {
        match self.mode.as_str() {
            "mainnet" => ("mainnet".to_string(), BitcoinNetworkType::Mainnet),
            "xenon" => ("testnet".to_string(), BitcoinNetworkType::Testnet),
            "helium" | "neon" | "argon" | "krypton" | "mocknet" | "nakamoto-neon" => {
                ("regtest".to_string(), BitcoinNetworkType::Regtest)
            }
            other => panic!("Invalid stacks-node mode: {other}"),
        }
    }

    pub fn get_epoch_list(&self) -> EpochList<ExecutionCost> {
        StacksEpoch::get_epochs(self.get_bitcoin_network().1, self.epochs.as_ref())
    }
}

#[derive(Clone, Deserialize, Default, Debug)]
pub struct StacksEpochConfigFile {
    epoch_name: String,
    start_height: i64,
}

pub const EPOCH_CONFIG_1_0_0: &str = "1.0";
pub const EPOCH_CONFIG_2_0_0: &str = "2.0";
pub const EPOCH_CONFIG_2_0_5: &str = "2.05";
pub const EPOCH_CONFIG_2_1_0: &str = "2.1";
pub const EPOCH_CONFIG_2_2_0: &str = "2.2";
pub const EPOCH_CONFIG_2_3_0: &str = "2.3";
pub const EPOCH_CONFIG_2_4_0: &str = "2.4";
pub const EPOCH_CONFIG_2_5_0: &str = "2.5";
pub const EPOCH_CONFIG_3_0_0: &str = "3.0";
pub const EPOCH_CONFIG_3_1_0: &str = "3.1";
pub const EPOCH_CONFIG_3_2_0: &str = "3.2";

#[derive(Clone, Deserialize, Default, Debug)]
#[serde(deny_unknown_fields)]
pub struct BurnchainConfigFile {
    pub chain: Option<String>,
    pub mode: Option<String>,
    pub chain_id: Option<u32>,
    pub burn_fee_cap: Option<u64>,
    pub commit_anchor_block_within: Option<u64>,
    pub peer_host: Option<String>,
    pub peer_port: Option<u16>,
    pub rpc_port: Option<u16>,
    pub rpc_ssl: Option<bool>,
    pub username: Option<String>,
    pub password: Option<String>,
    /// Timeout, in seconds, for communication with bitcoind
    pub timeout: Option<u64>,
    /// Socket timeout, in seconds, for socket operations with bitcoind
    pub socket_timeout: Option<u64>,
    pub magic_bytes: Option<String>,
    pub local_mining_public_key: Option<String>,
    pub process_exit_at_block_height: Option<u64>,
    pub poll_time_secs: Option<u64>,
    pub satoshis_per_byte: Option<u64>,
    pub leader_key_tx_estimated_size: Option<u64>,
    pub block_commit_tx_estimated_size: Option<u64>,
    pub rbf_fee_increment: Option<u64>,
    pub max_rbf: Option<u64>,
    pub first_burn_block_height: Option<u64>,
    pub first_burn_block_timestamp: Option<u32>,
    pub first_burn_block_hash: Option<String>,
    pub epochs: Option<Vec<StacksEpochConfigFile>>,
    pub pox_prepare_length: Option<u32>,
    pub pox_reward_length: Option<u32>,
    pub pox_2_activation: Option<u32>,
    pub sunset_start: Option<u32>,
    pub sunset_end: Option<u32>,
    pub wallet_name: Option<String>,
    pub fault_injection_burnchain_block_delay: Option<u64>,
    pub max_unspent_utxos: Option<u64>,
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
                self.magic_bytes.clone_from(&mainnet_magic);
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
            chain_id: match self.chain_id {
                Some(chain_id) => {
                    if is_mainnet && chain_id != CHAIN_ID_MAINNET {
                        return Err(format!(
                            "Attempted to run mainnet node with chain_id {chain_id}",
                        ));
                    }
                    chain_id
                }
                None => {
                    if is_mainnet {
                        CHAIN_ID_MAINNET
                    } else {
                        CHAIN_ID_TESTNET
                    }
                }
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
                    format!("{}:1", &peer_host)
                        .to_socket_addrs()
                        .map_err(|e| format!("Invalid burnchain.peer_host: {}", &e))?
                        .next()
                        .is_none()
                        .then(|| {
                            return format!("No IP address could be queried for '{}'", &peer_host);
                        });
                    peer_host.clone()
                }
                None => default_burnchain_config.peer_host,
            },
            peer_port: self.peer_port.unwrap_or(default_burnchain_config.peer_port),
            rpc_port: self.rpc_port.unwrap_or(default_burnchain_config.rpc_port),
            rpc_ssl: self.rpc_ssl.unwrap_or(default_burnchain_config.rpc_ssl),
            username: self.username,
            password: self.password,
            timeout: self.timeout.unwrap_or(default_burnchain_config.timeout),
            socket_timeout: self
                .socket_timeout
                .unwrap_or(default_burnchain_config.socket_timeout),
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
            first_burn_block_height: self
                .first_burn_block_height
                .or(default_burnchain_config.first_burn_block_height),
            first_burn_block_timestamp: self
                .first_burn_block_timestamp
                .or(default_burnchain_config.first_burn_block_timestamp),
            first_burn_block_hash: self
                .first_burn_block_hash
                .clone()
                .or(default_burnchain_config.first_burn_block_hash.clone()),
            // will be overwritten below
            epochs: default_burnchain_config.epochs,
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
            fault_injection_burnchain_block_delay: self
                .fault_injection_burnchain_block_delay
                .unwrap_or(default_burnchain_config.fault_injection_burnchain_block_delay),
            max_unspent_utxos: self
                .max_unspent_utxos
                .inspect(|&val| {
                    assert!(val <= 1024, "Value for max_unspent_utxos should be <= 1024");
                })
                .or(default_burnchain_config.max_unspent_utxos),
        };

        if let BitcoinNetworkType::Mainnet = config.get_bitcoin_network().1 {
            // check that pox_2_activation hasn't been set in mainnet
            if config.pox_2_activation.is_some()
                || config.sunset_start.is_some()
                || config.sunset_end.is_some()
            {
                return Err("PoX-2 parameters are not configurable in mainnet".into());
            }
            // Check that the first burn block options are not set in mainnet
            if config.first_burn_block_height.is_some()
                || config.first_burn_block_timestamp.is_some()
                || config.first_burn_block_hash.is_some()
            {
                return Err("First burn block parameters are not configurable in mainnet".into());
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
    /// Human-readable name for the node. Primarily used for identification in testing
    /// environments (e.g., deriving log file names, temporary directory names).
    /// ---
    /// @default: `"helium-node"`
    pub name: String,
    /// The node's Bitcoin wallet private key, provided as a hex string in the config file.
    /// Used to initialize the node's keychain for signing operations.
    /// If [`MinerConfig::mining_key`] is not set, this seed may also be used for
    /// mining-related signing.
    /// ---
    /// @default: Randomly generated 32 bytes
    /// @notes:
    ///   - Required if [`NodeConfig::miner`] is `true` and [`MinerConfig::mining_key`] is absent.
    pub seed: Vec<u8>,
    /// The file system absolute path to the node's working directory.
    /// All persistent data, including chainstate, burnchain databases, and potentially
    /// other stores, will be located within this directory. This path can be
    /// overridden by setting the `STACKS_WORKING_DIR` environment variable.
    /// ---
    /// @default: `/tmp/stacks-node-{current_timestamp}`
    /// @notes:
    ///   - For persistent mainnet or testnet nodes, this path must be explicitly
    ///     configured to a non-temporary location.
    pub working_dir: String,
    /// The IPv4 address and port (e.g., "0.0.0.0:20443") on which the node's HTTP RPC
    /// server should bind and listen for incoming API requests.
    /// ---
    /// @default: `"0.0.0.0:20443"`
    pub rpc_bind: String,
    /// The IPv4 address and port (e.g., "0.0.0.0:20444") on which the node's P2P
    /// networking service should bind and listen for incoming connections from other peers.
    /// ---
    /// @default: `"0.0.0.0:20444"`
    pub p2p_bind: String,
    /// The publicly accessible URL that this node advertises to peers during the P2P
    /// handshake as its HTTP RPC endpoint. Other nodes or services might use this URL
    /// to query the node's API.
    /// ---
    /// @default: Derived by adding "http://" prefix to [`NodeConfig::rpc_bind`] value.
    /// @notes:
    ///   - Example: For rpc_bind="0.0.0.0:20443", data_url becomes "http://0.0.0.0:20443".
    pub data_url: String,
    /// The publicly accessible IPv4 address and port that this node advertises to peers
    /// for P2P connections. This might differ from [`NodeConfig::p2p_bind`] if the
    /// node is behind NAT or a proxy.
    /// ---
    /// @default: Derived directly from [`NodeConfig::rpc_bind`] value.
    /// @notes:
    ///   - Example: For rpc_bind="0.0.0.0:20443", p2p_address becomes "0.0.0.0:20443".
    ///   - The default value derivation might be unexpected, potentially using the
    ///     [`NodeConfig::rpc_bind`] address; explicit configuration is recommended if needed.
    pub p2p_address: String,
    /// The private key seed, provided as a hex string in the config file, used
    /// specifically for the node's identity and message signing within the P2P
    /// networking layer. This is separate from the main [`NodeConfig::seed`].
    /// ---
    /// @default: Randomly generated 32 bytes
    pub local_peer_seed: Vec<u8>,
    /// A list of initial peer nodes used to bootstrap connections into the Stacks P2P
    /// network. Peers are specified in a configuration file as comma-separated
    /// strings in the format `"PUBKEY@IP:PORT"` or `"PUBKEY@HOSTNAME:PORT"`. DNS
    /// hostnames are resolved during configuration loading.
    /// ---
    /// @default: `[]` (empty vector)
    /// @toml_example: |
    ///   bootstrap_node = "pubkey1@example.com:30444,pubkey2@192.168.1.100:20444"
    pub bootstrap_node: Vec<Neighbor>,
    /// A list of peer addresses that this node should explicitly deny connections from.
    /// Peers are specified as comma-separated strings in the format "IP:PORT" or
    /// "HOSTNAME:PORT" in the configuration file. DNS hostnames are resolved during
    /// configuration loading.
    /// ---
    /// @default: `[]` (empty vector)
    /// @toml_example: |
    ///   deny_nodes = "192.168.1.100:20444,badhost.example.com:20444"
    pub deny_nodes: Vec<Neighbor>,
    /// Flag indicating whether this node should activate its mining logic and attempt to
    /// produce Stacks blocks. Setting this to `true` typically requires providing
    /// necessary private keys (either [`NodeConfig::seed`] or [`MinerConfig::mining_key`]).
    /// ---
    /// @default: `false`
    pub miner: bool,
    /// Setting this to `true` enables the node to replicate the miner and signer
    /// Stacker DBs required for signing, and is required if the node is connected to a
    /// signer.
    /// ---
    /// @default: `false`
    pub stacker: bool,
    /// Enables a simulated mining mode, primarily for local testing and development.
    /// When `true`, the node may generate blocks locally without participating in the
    /// real bitcoin consensus or P2P block production process.
    /// ---
    /// @default: `false`
    /// @notes:
    ///   - Only relevant if [`NodeConfig::miner`] is `true`.
    pub mock_mining: bool,
    /// If [`NodeConfig::mock_mining`] is enabled, this specifies an optional directory
    /// path where the generated mock Stacks blocks will be saved. (pre-Nakamoto)
    /// The path is canonicalized on load.
    /// ---
    /// @default: `None`
    /// @deprecated: This setting was only used in the neon node and is ignored in Epoch 3.0+.
    pub mock_mining_output_dir: Option<PathBuf>,
    /// Enable microblock mining.
    /// ---
    /// @default: `true`
    /// @deprecated: This setting is ignored in Epoch 2.5+.
    pub mine_microblocks: bool,
    /// How often to attempt producing microblocks, in milliseconds.
    /// ---
    /// @default: `30_000` (30 seconds)
    /// @deprecated: This setting is ignored in Epoch 2.5+.
    /// @notes:
    ///   - Only applies when [`NodeConfig::mine_microblocks`] is true and before Epoch 2.5.
    /// @units: milliseconds
    pub microblock_frequency: u64,
    /// The maximum number of microblocks allowed per Stacks block.
    /// ---
    /// @default: `65535` (u16::MAX)
    /// @deprecated: This setting is ignored in Epoch 2.5+.
    pub max_microblocks: u64,
    /// Cooldown period after a microblock is produced, in milliseconds.
    /// ---
    /// @default: `30_000` (30 seconds)
    /// @deprecated: This setting is ignored in Epoch 2.5+.
    /// @notes:
    ///   - Only applies when [`NodeConfig::mine_microblocks`] is true and before Epoch 2.5.
    /// @units: milliseconds
    pub wait_time_for_microblocks: u64,
    /// When operating as a miner, this specifies the maximum time (in milliseconds)
    /// the node waits after detecting a new burnchain block to synchronize corresponding
    /// Stacks block data from the network before resuming mining attempts.
    /// If synchronization doesn't complete within this duration, mining resumes anyway
    /// to prevent stalling. This setting is loaded by all nodes but primarily affects
    /// miner behavior within the relayer thread.
    /// ---
    /// @default: `30_000` (30 seconds)
    /// @units: milliseconds
    pub wait_time_for_blocks: u64,
    /// Controls how frequently, in milliseconds, the Nakamoto miner's relay thread
    /// polls for work or takes periodic actions when idle (e.g., checking for new
    /// burnchain blocks). A default value of 10 seconds is reasonable on mainnet
    /// (where bitcoin blocks are ~10 minutes). A lower value might be useful in
    /// other environments with faster burn blocks.
    /// ---
    /// @default: `10_000` (10 seconds)
    /// @units: milliseconds
    pub next_initiative_delay: u64,
    /// Optional network address and port (e.g., "127.0.0.1:9153") for binding the
    /// Prometheus metrics server. If set, the node will start an HTTP server on this
    /// address to expose internal metrics for scraping by a Prometheus instance.
    /// ---
    /// @default: `None` (Prometheus server disabled)
    pub prometheus_bind: Option<String>,
    /// The strategy to use for MARF trie node caching in memory.
    /// Controls the trade-off between memory usage and performance for state access.
    ///
    /// Possible values:
    /// - `"noop"`: No caching (least memory).
    /// - `"everything"`: Cache all nodes (most memory, potentially fastest).
    /// - `"node256"`: Cache only larger `TrieNode256` nodes.
    ///
    /// If the value is `None` or an unrecognized string, it defaults to `"noop"`.
    /// ---
    /// @default: `None` (effectively `"noop"`)
    pub marf_cache_strategy: Option<String>,
    /// Controls the timing of hash calculations for MARF trie nodes.
    /// - If `true`, hashes are calculated only when the MARF is flushed to disk
    ///   (deferred hashing).
    /// - If `false`, hashes are calculated immediately as leaf nodes are inserted or
    ///   updated (immediate hashing).
    /// Deferred hashing might improve write performance.
    /// ---
    /// @default: `true`
    pub marf_defer_hashing: bool,
    /// Sampling interval in seconds for the PoX synchronization watchdog thread
    /// (pre-Nakamoto). Determines how often the watchdog checked PoX state
    /// consistency in the Neon run loop.
    /// ---
    /// @default: `30`
    /// @units: seconds
    /// @deprecated: Unused after the Nakamoto upgrade. This setting is ignored in Epoch 3.0+.
    pub pox_sync_sample_secs: u64,
    /// If set to `true`, the node initializes its state using an alternative test
    /// genesis block definition, loading different initial balances, names, and
    /// lockups than the standard network genesis.
    /// ---
    /// @default: `None` (uses standard network genesis)
    /// @notes:
    ///   - This is intended strictly for testing purposes and is disallowed on mainnet.
    pub use_test_genesis_chainstate: Option<bool>,
    /// Fault injection setting for testing purposes. If set to `Some(p)`, where `p` is
    /// between 0 and 100, the node will have a `p` percent chance of intentionally
    /// *not* pushing a newly processed block to its peers.
    /// ---
    /// @default: `None` (no fault injection)
    /// @notes:
    ///   - Values: 0-100 (percentage).
    pub fault_injection_block_push_fail_probability: Option<u8>,
    /// Fault injection setting for testing purposes. If `true`, the node's chainstate
    /// database access layer may intentionally fail to retrieve block data, even if it
    /// exists, simulating block hiding or data unavailability.
    /// ---
    /// @default: `false`
    /// @notes:
    ///   - This parameter cannot be set via the configuration file; it must be modified
    ///     programmatically.
    pub fault_injection_hide_blocks: bool,
    /// The polling interval, in seconds, for the background thread that monitors
    /// chain liveness. This thread periodically wakes up the main coordinator to
    /// check for chain progress or other conditions requiring action.
    /// ---
    /// @default: `300` (5 minutes)
    /// @units: seconds
    pub chain_liveness_poll_time_secs: u64,
    /// A list of specific StackerDB contracts (identified by their qualified contract
    /// identifiers, e.g., "SP000000000000000000002Q6VF78.pox-3") that this node
    /// should actively replicate.
    /// ---
    /// @default: |
    ///   - if [`NodeConfig::miner`] is `true` or [`NodeConfig::stacker`] is `true`:
    ///     relevant system contracts (e.g., `.miners`, `.signers-*`) are
    ///     automatically added in addition to any contracts specified in the
    ///     configuration file.
    ///   - else: defaults to an empty list `[]`.
    /// @notes:
    ///   - Values are strings representing qualified contract identifiers.
    /// @toml_example: |
    ///   stacker_dbs = [
    ///     "SP000000000000000000002Q6VF78.pox-3",
    ///     "SP2C2YFP12AJZB4M4KUPSTMZQR0SNHNPH204SCQJM.stx-oracle-v1"
    ///   ]
    pub stacker_dbs: Vec<QualifiedContractIdentifier>,
    /// Enables the transaction index, which maps transaction IDs to the blocks
    /// containing them. Setting this to `true` allows the use of RPC endpoints
    /// that look up transactions by ID (e.g., `/extended/v1/tx/{txid}`), but
    /// requires substantial additional disk space for the index database.
    /// ---
    /// @default: `false`
    pub txindex: bool,
}

#[derive(Clone, Debug, Default)]
pub enum CostEstimatorName {
    #[default]
    NaivePessimistic,
}

#[derive(Clone, Debug, Default)]
pub enum FeeEstimatorName {
    #[default]
    ScalarFeeRate,
    FuzzedWeightedMedianFeeRate,
}

#[derive(Clone, Debug, Default)]
pub enum CostMetricName {
    #[default]
    ProportionDotProduct,
}

impl CostEstimatorName {
    fn panic_parse(s: String) -> CostEstimatorName {
        if &s.to_lowercase() == "naive_pessimistic" {
            CostEstimatorName::NaivePessimistic
        } else {
            panic!("Bad cost estimator name supplied in configuration file: {s}");
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
            panic!("Bad fee estimator name supplied in configuration file: {s}");
        }
    }
}

impl CostMetricName {
    fn panic_parse(s: String) -> CostMetricName {
        if &s.to_lowercase() == "proportion_dot_product" {
            CostMetricName::ProportionDotProduct
        } else {
            panic!("Bad cost metric name supplied in configuration file: {s}");
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
        let testnet_id = format!("stacks-node-{now}");

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
            working_dir: format!("/tmp/{testnet_id}"),
            rpc_bind: format!("0.0.0.0:{rpc_port}"),
            p2p_bind: format!("0.0.0.0:{p2p_port}"),
            data_url: format!("http://127.0.0.1:{rpc_port}"),
            p2p_address: format!("127.0.0.1:{rpc_port}"),
            bootstrap_node: vec![],
            deny_nodes: vec![],
            local_peer_seed: local_peer_seed.to_vec(),
            miner: false,
            stacker: false,
            mock_mining: false,
            mock_mining_output_dir: None,
            mine_microblocks: true,
            microblock_frequency: 30_000,
            max_microblocks: u16::MAX as u64,
            wait_time_for_microblocks: 30_000,
            wait_time_for_blocks: 30_000,
            next_initiative_delay: 10_000,
            prometheus_bind: None,
            marf_cache_strategy: None,
            marf_defer_hashing: true,
            pox_sync_sample_secs: 30,
            use_test_genesis_chainstate: None,
            fault_injection_block_push_fail_probability: None,
            fault_injection_hide_blocks: false,
            chain_liveness_poll_time_secs: 300,
            stacker_dbs: vec![],
            txindex: false,
        }
    }
}

impl NodeConfig {
    /// Get a SocketAddr for this node's RPC endpoint which uses the loopback address
    pub fn get_rpc_loopback(&self) -> Option<SocketAddr> {
        let rpc_port = self.rpc_bind_addr()?.port();
        Some(SocketAddr::new(Ipv4Addr::LOCALHOST.into(), rpc_port))
    }

    pub fn rpc_bind_addr(&self) -> Option<SocketAddr> {
        SocketAddr::from_str(&self.rpc_bind)
            .inspect_err(|e| {
                error!("Could not parse node.rpc_bind configuration setting as SocketAddr: {e}");
            })
            .ok()
    }

    pub fn p2p_bind_addr(&self) -> Option<SocketAddr> {
        SocketAddr::from_str(&self.p2p_bind)
            .inspect_err(|e| {
                error!("Could not parse node.rpc_bind configuration setting as SocketAddr: {e}");
            })
            .ok()
    }

    pub fn add_signers_stackerdbs(&mut self, is_mainnet: bool) {
        for signer_set in 0..2 {
            for message_id in 0..SIGNER_SLOTS_PER_USER {
                let contract_name = NakamotoSigners::make_signers_db_name(signer_set, message_id);
                let contract_id = boot_code_id(contract_name.as_str(), is_mainnet);
                if !self.stacker_dbs.contains(&contract_id) {
                    self.stacker_dbs.push(contract_id);
                }
            }
        }
    }

    pub fn add_miner_stackerdb(&mut self, is_mainnet: bool) {
        let miners_contract_id = boot_code_id(MINERS_NAME, is_mainnet);
        if !self.stacker_dbs.contains(&miners_contract_id) {
            self.stacker_dbs.push(miners_contract_id);
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
                peer_version,
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
        let parts: Vec<&str> = bootstrap_node.split('@').collect();
        let Ok(parts) = TryInto::<&[_; 2]>::try_into(parts.as_slice()) else {
            panic!("Invalid bootstrap node '{bootstrap_node}': expected PUBKEY@IP:PORT");
        };
        let (pubkey_str, hostport) = (parts[0], parts[1]);
        let pubkey = Secp256k1PublicKey::from_hex(pubkey_str)
            .unwrap_or_else(|_| panic!("Invalid public key '{pubkey_str}'"));
        debug!("Resolve '{hostport}'");

        let mut attempts = 0;
        let max_attempts = 5;
        let mut delay = Duration::from_secs(2);

        let sockaddr = loop {
            match hostport.to_socket_addrs() {
                Ok(mut addrs) => {
                    if let Some(addr) = addrs.next() {
                        break addr;
                    } else {
                        panic!("No addresses found for '{hostport}'");
                    }
                }
                Err(e) => {
                    if attempts >= max_attempts {
                        panic!("Failed to resolve '{hostport}' after {max_attempts} attempts: {e}");
                    } else {
                        error!(
                            "Attempt {} - Failed to resolve '{hostport}': {e}. Retrying in {delay:?}...",
                            attempts + 1,
                        );
                        thread::sleep(delay);
                        attempts += 1;
                        delay *= 2;
                    }
                }
            }
        };

        let neighbor = NodeConfig::default_neighbor(sockaddr, pubkey, chain_id, peer_version);
        self.bootstrap_node.push(neighbor);
    }

    pub fn set_bootstrap_nodes(
        &mut self,
        bootstrap_nodes: String,
        chain_id: u32,
        peer_version: u32,
    ) {
        for part in bootstrap_nodes.split(',') {
            if !part.is_empty() {
                self.add_bootstrap_node(part, chain_id, peer_version);
            }
        }
    }

    pub fn add_deny_node(&mut self, deny_node: &str, chain_id: u32, peer_version: u32) {
        let sockaddr = deny_node.to_socket_addrs().unwrap().next().unwrap();
        let neighbor = NodeConfig::default_neighbor(
            sockaddr,
            Secp256k1PublicKey::from_private(&Secp256k1PrivateKey::random()),
            chain_id,
            peer_version,
        );
        self.deny_nodes.push(neighbor);
    }

    pub fn set_deny_nodes(&mut self, deny_nodes: String, chain_id: u32, peer_version: u32) {
        for part in deny_nodes.split(',') {
            if !part.is_empty() {
                self.add_deny_node(part, chain_id, peer_version);
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
            self.marf_cache_strategy.as_deref().unwrap_or("noop"),
            false,
        )
    }
}

#[derive(Clone, Debug, PartialEq)]
pub struct MinerConfig {
    /// Time to wait (in milliseconds) before the first attempt to mine a block.
    /// ---
    /// @default: `10`
    /// @units: milliseconds
    /// @deprecated: This setting is ignored in Epoch 3.0+. Only used in the neon chain mode.
    pub first_attempt_time_ms: u64,
    /// Time to wait (in milliseconds) for subsequent attempts to mine a block,
    /// after the first attempt fails.
    /// ---
    /// @default: `120_000` (2 minutes)
    /// @units: milliseconds
    /// @deprecated: This setting is ignored in Epoch 3.0+. Only used in the neon chain mode.
    pub subsequent_attempt_time_ms: u64,
    /// Time to wait (in milliseconds) to mine a microblock.
    /// ---
    /// @default: `30_000` (30 seconds)
    /// @units: milliseconds
    /// @deprecated: This setting is ignored in Epoch 3.0+. Only used in the neon chain mode.
    pub microblock_attempt_time_ms: u64,
    /// Maximum time (in milliseconds) the miner spends selecting transactions from
    /// the mempool when assembling a Nakamoto block. Once this duration is exceeded,
    /// the miner stops adding transactions and finalizes the block with those
    /// already selected.
    /// ---
    /// @default: `5_000` (5 seconds)
    /// @units: milliseconds
    pub nakamoto_attempt_time_ms: u64,
    /// Strategy for selecting the next transaction candidate from the mempool.
    /// Controls prioritization between maximizing immediate fee capture vs. ensuring
    /// transaction nonce order for account progression and processing efficiency.
    ///
    /// See [`MemPoolWalkStrategy`] for variant details.
    ///
    /// Possible values (use variant names for configuration):
    /// - `"GlobalFeeRate"`: Selects the transaction with the highest fee rate globally.
    /// - `"NextNonceWithHighestFeeRate"`: Selects the highest-fee transaction among those
    ///   matching the next expected nonce for sender/sponsor accounts.
    /// ---
    /// @default: `"NextNonceWithHighestFeeRate"`
    pub mempool_walk_strategy: MemPoolWalkStrategy,
    /// Probability (percentage, 0-100) of prioritizing a transaction without a
    /// known fee rate during candidate selection.
    ///
    /// Only effective when `mempool_walk_strategy` is `GlobalFeeRate`. Helps ensure
    /// transactions lacking fee estimates are periodically considered alongside
    /// high-fee ones, preventing potential starvation. A value of 0 means never
    /// prioritize them first, 100 means always prioritize them first (if available).
    /// ---
    /// @default: `25` (25% chance)
    /// @units: percent
    /// @notes:
    ///   - Values: 0-100.
    pub probability_pick_no_estimate_tx: u8,
    /// Optional recipient for the coinbase block reward, overriding the default miner address.
    ///
    /// By default (`None`), the reward is sent to the miner's primary address
    /// ([`NodeConfig::seed`]). If set to some principal address *and* the current
    /// Stacks epoch is > 2.1, the reward will be directed to the specified
    /// address instead.
    /// ---
    /// @default: `None`
    pub block_reward_recipient: Option<PrincipalData>,
    /// If possible, mine with a p2wpkh address.
    /// ---
    /// @default: `false`
    pub segwit: bool,
    /// Wait for a downloader pass before mining.
    /// This can only be disabled in testing; it can't be changed in the config file.
    /// ---
    /// @default: `true`
    pub wait_for_block_download: bool,
    /// Max size (in bytes) of the in-memory cache for storing expected account nonces.
    ///
    /// This cache accelerates mempool processing (e.g., during block building) by
    /// storing the anticipated next nonce for accounts, reducing expensive lookups
    /// into the node's state (MARF trie). A larger cache can improve performance
    /// for workloads involving many unique accounts but increases memory consumption.
    /// ---
    /// @default: `1048576` (1 MiB)
    /// @units: bytes
    /// @notes:
    ///   - Must be configured to a value greater than 0.
    pub nonce_cache_size: usize,
    /// Max size (in *number* of items) of transaction candidates to hold in the in-memory
    /// retry cache.
    ///
    /// This cache stores transactions encountered during a `GlobalFeeRate` mempool
    /// walk whose nonces are currently too high for immediate processing. These
    /// candidates are prioritized for reconsideration later within the *same* walk,
    /// potentially becoming valid if other processed transactions update the
    /// expected nonces.
    ///
    /// A larger cache retains more potentially valid future candidates but uses more
    /// memory. This setting is primarily relevant for the `GlobalFeeRate` strategy.
    /// ---
    /// @default: `1048576`
    /// @units: items
    /// @notes:
    ///   - Each element [`crate::core::mempool::MemPoolTxInfoPartial`] is currently 112 bytes.
    pub candidate_retry_cache_size: usize,
    /// Amount of time (in seconds) to wait for unprocessed blocks before mining a new block.
    /// ---
    /// @default: `30`
    /// @units: seconds
    /// @deprecated: This setting is ignored in Epoch 3.0+. Only used in the neon chain mode.
    pub unprocessed_block_deadline_secs: u64,
    /// The private key (Secp256k1) used for signing blocks, provided as a hex string.
    ///
    /// This key must be present at runtime for mining operations to succeed.
    /// ---
    /// @default: |
    ///   - if the `[miner]` section *is present* in the config file: [`NodeConfig::seed`]
    ///   - else: `None`
    pub mining_key: Option<Secp256k1PrivateKey>,
    /// Amount of time while mining in nakamoto to wait in between mining interim blocks.
    /// ---
    /// @default: `None`
    /// @deprecated: Use `min_time_between_blocks_ms` instead.
    pub wait_on_interim_blocks: Option<Duration>,
    /// Minimum number of transactions that must be in a block if we're going to
    /// replace a pending block-commit with a new block-commit.
    /// ---
    /// @default: `0`
    /// @deprecated: This setting is ignored in Epoch 3.0+. Only used in the neon chain mode.
    pub min_tx_count: u64,
    /// If true, requires subsequent mining attempts for the same block height to have
    /// a transaction count >= the previous best attempt.
    /// ---
    /// @default: `false`
    /// @deprecated: This setting is ignored in Epoch 3.0+. Only used in the neon chain mode.
    pub only_increase_tx_count: bool,
    /// Optional path to an external helper script for fetching unconfirmed
    /// block-commits. Used to inform the miner's dynamic burn fee bidding strategy
    /// with off-chain data.
    ///
    /// If a path is provided, the target script must:
    /// - Be executable by the user running the Stacks node process.
    /// - Accept a list of active miner burnchain addresses as command-line arguments.
    /// - On successful execution, print a JSON array representing `Vec<UnconfirmedBlockCommit>`
    ///   (see [`stacks::config::chain_data::UnconfirmedBlockCommit`] struct) to stdout.
    /// - Exit with code 0 on success.
    ///
    /// Look at `test_get_unconfirmed_commits` in `stackslib/src/config/chain_data.rs`
    /// for an example script.
    /// ---
    /// @default: `None` (feature disabled).
    /// @deprecated: This setting is ignored in Epoch 3.0+. Only used in the neon chain mode
    ///   and by the `get-spend-amount` cli subcommand.
    pub unconfirmed_commits_helper: Option<String>,
    /// The minimum win probability this miner aims to achieve in block sortitions.
    ///
    /// This target is used to detect prolonged periods of underperformance. If the
    /// miner's calculated win probability consistently falls below this value for a
    /// duration specified by [`MinerConfig::underperform_stop_threshold`] (after
    /// an initial startup phase), the miner may cease spending in subsequent
    /// sortitions (returning a burn fee cap of 0) to conserve resources.
    ///
    /// Setting this value close to 0.0 effectively disables the underperformance check.
    /// ---
    /// @default: `0.0`
    /// @deprecated: This setting is ignored in Epoch 3.0+. Only used in the neon chain mode.
    pub target_win_probability: f64,
    /// Path to a file for storing and loading the currently active, registered VRF leader key.
    ///
    /// Loading: On startup or when needing to register a key, if this path is set,
    /// the relayer first attempts to load a serialized [`RegisteredKey`] from this
    /// file. If successful, it uses the loaded key and skips the on-chain VRF key
    /// registration transaction, saving time and fees.
    /// Saving: After a new VRF key registration transaction is confirmed and
    /// activated on the burnchain, if this path is set, the node saves the details
    /// of the newly activated [`RegisteredKey`] to this file. This allows the
    /// miner to persist its active VRF key across restarts.
    /// If the file doesn't exist during load, or the path is `None`, the node
    /// proceeds with a new registration.
    /// ---
    /// @default: `None`
    pub activated_vrf_key_path: Option<String>,
    /// Controls how the miner estimates its win probability when checking for underperformance.
    ///
    /// This estimation is used in conjunction with [`MinerConfig::target_win_probability`] and
    /// [`MinerConfig::underperform_stop_threshold`] to decide whether to pause
    /// mining due to low predicted success rate.
    ///
    /// - If `true`: The win probability estimation looks at projected spend
    ///   distributions ~6 blocks into the future. This might help the miner adjust
    ///   its spending more quickly based on anticipated competition changes.
    /// - If `false`: The win probability estimation uses the currently observed
    ///   spend distribution for the next block.
    /// ---
    /// @default: `false`
    /// @deprecated: This setting is ignored in Epoch 3.0+. Only used in the neon chain mode and by the
    ///   `get-spend-amount` cli subcommand.
    pub fast_rampup: bool,
    /// The maximum number of consecutive Bitcoin blocks the miner will tolerate
    /// underperforming (i.e., having a calculated win probability below
    /// [`MinerConfig::target_win_probability`]) before temporarily pausing mining efforts.
    ///
    /// This check is only active after an initial startup phase (6 blocks past the
    /// mining start height). If the miner underperforms for this number of
    /// consecutive blocks, the [`BlockMinerThread::get_mining_spend_amount`] function
    /// will return 0, effectively preventing the miner from submitting a block commit
    /// for the current sortition to conserve funds.
    /// ---
    /// @default: `None` (underperformance check is disabled).
    /// @deprecated: This setting is ignored in Epoch 3.0+. Only used in the neon chain mode.
    pub underperform_stop_threshold: Option<u64>,
    /// Specifies which types of transactions the miner should consider including in a
    /// block during the mempool walk process. Transactions of types not included in
    /// this set will be skipped.
    ///
    /// This allows miners to exclude specific transaction categories.
    /// Configured as a comma-separated string of transaction type names in the configuration file.
    ///
    /// Accepted values correspond to variants of [`MemPoolWalkTxTypes`]:
    /// - `"TokenTransfer"`
    /// - `"SmartContract"`
    /// - `"ContractCall"`
    /// ---
    /// @default: All transaction types are considered (equivalent to [`MemPoolWalkTxTypes::all()`]).
    /// @toml_example: |
    ///   txs_to_consider = "TokenTransfer,ContractCall"
    pub txs_to_consider: HashSet<MemPoolWalkTxTypes>,
    /// A comma separated list of Stacks addresses to whitelist so that only
    /// transactions from these addresses should be considered during the mempool walk
    /// for block building. If this list is non-empty, any transaction whose origin
    /// address is *not* in this set will be skipped.
    ///
    /// This allows miners to prioritize transactions originating from specific accounts that are
    /// important to them.
    /// Configured as a comma-separated string of standard Stacks addresses
    /// (e.g., "ST123...,ST456...") in the configuration file.
    /// ---
    /// @default: Empty set (all origins are considered).
    /// @toml_example: |
    ///   filter_origins = "ST2QKZ4FKHAH1NQKYKYAYZPY440FEPK7GZ1R5HBP2,ST319CF5WV77KYR1H3GT0GZ7B8Q4AQPY42ETP1VPF"
    pub filter_origins: HashSet<StacksAddress>,
    /// Defines the maximum depth (in Stacks blocks) the miner considers when
    /// evaluating potential chain tips when selecting the best tip to mine the next
    /// block on.
    ///
    /// The miner analyzes candidate tips within this depth from the highest known
    /// tip. It selects the "nicest" tip, often defined as the one that minimizes
    /// chain reorganizations or orphans within this lookback window. A lower value
    /// restricts the analysis to shallower forks, while a higher value considers
    /// deeper potential reorganizations.
    ///
    /// This setting influences which fork the miner chooses to build upon if multiple valid tips exist.
    /// ---
    /// @default: `3`
    /// @deprecated: This setting is ignored in Epoch 3.0+. Only used in the neon chain mode and the
    ///   `pick-best-tip` cli subcommand.
    pub max_reorg_depth: u64,
    /// Enables a mock signing process for testing purposes, specifically designed
    /// for use during Epoch 2.5 before the activation of Nakamoto consensus.
    ///
    /// When set to `true` and [`MinerConfig::mining_key`] is provided, the miner
    /// will interact with the `.miners` and `.signers` contracts via the stackerdb
    /// to send and receive mock proposals and signatures, simulating aspects of the
    /// Nakamoto leader election and block signing flow.
    /// ---
    /// @default: `false` (Should only default true if [`MinerConfig::mining_key`] is set).
    /// @deprecated: This setting is ignored in Epoch 3.0+.
    /// @notes:
    ///   - This is intended strictly for testing Epoch 2.5 conditions.
    pub pre_nakamoto_mock_signing: bool,
    /// The minimum time to wait between mining blocks in milliseconds. The value
    /// must be greater than or equal to 1000 ms because if a block is mined
    /// within the same second as its parent, it will be rejected by the signers.
    ///
    /// This check ensures compliance with signer rules that prevent blocks with
    /// identical timestamps (at second resolution) to their parents. If a lower
    /// value is configured, 1000 ms is used instead.
    /// ---
    /// @default: [`DEFAULT_MIN_TIME_BETWEEN_BLOCKS_MS`]
    /// @units: milliseconds
    pub min_time_between_blocks_ms: u64,
    /// The amount of time in milliseconds that the miner should sleep in between
    /// attempts to mine a block when the mempool is empty.
    ///
    /// This prevents the miner from busy-looping when there are no pending
    /// transactions, conserving CPU resources. During this sleep, the miner still
    /// checks burnchain tip changes.
    /// ---
    /// @default: [`DEFAULT_EMPTY_MEMPOOL_SLEEP_MS`]
    /// @units: milliseconds
    pub empty_mempool_sleep_time: Duration,
    /// Time in milliseconds to pause after receiving the first threshold rejection,
    /// before proposing a new block.
    ///
    /// When a miner's block proposal fails to gather enough signatures from the
    /// signers for the first time at a given height, the miner will pause for this
    /// duration before attempting to mine and propose again.
    /// ---
    /// @default: [`DEFAULT_FIRST_REJECTION_PAUSE_MS`]
    /// @units: milliseconds
    pub first_rejection_pause_ms: u64,
    /// Time in milliseconds to pause after receiving subsequent threshold rejections,
    /// before proposing a new block.
    ///
    /// If a miner's block proposal is rejected multiple times at the same height
    /// (after the first rejection), this potentially longer pause duration is used
    /// before retrying. This gives more significant time for network state changes
    /// or signer coordination.
    /// ---
    /// @default: [`DEFAULT_SUBSEQUENT_REJECTION_PAUSE_MS`]
    /// @units: milliseconds
    pub subsequent_rejection_pause_ms: u64,
    /// Time in milliseconds to wait for a Nakamoto block after seeing a burnchain
    /// block before submitting a block commit.
    ///
    /// After observing a new burnchain block, the miner's relayer waits for this
    /// duration before submitting its next block commit transaction to Bitcoin.
    /// This delay provides an opportunity for a new Nakamoto block (produced by the
    /// winner of the latest sortition) to arrive. Waiting helps avoid situations
    /// where the relayer immediately submits a commit that needs to be replaced
    /// via RBF if a new Stacks block appears shortly after. This delay is skipped
    /// if the new burnchain blocks leading to the tip contain no sortitions.
    /// ---
    /// @default: [`DEFAULT_BLOCK_COMMIT_DELAY_MS`]
    /// @units: milliseconds
    pub block_commit_delay: Duration,
    /// The percentage of the remaining tenure cost limit to consume each block.
    ///
    /// This setting limits the execution cost (Clarity cost) a single Nakamoto block
    /// can incur, expressed as a percentage of the *remaining* cost budget for the
    /// current mining tenure. For example, if set to 25, a block can use at most
    /// 25% of the tenure's currently available cost limit. This allows miners to
    /// spread the tenure's total execution budget across multiple blocks rather than
    /// potentially consuming it all in the first block.
    /// ---
    /// @default: [`DEFAULT_TENURE_COST_LIMIT_PER_BLOCK_PERCENTAGE`]
    /// @units: percent
    /// @notes:
    ///   - Values: 1-100.
    ///   - Setting to 100 effectively disables this per-block limit, allowing a block to use the
    ///     entire remaining tenure budget.
    pub tenure_cost_limit_per_block_percentage: Option<u8>,
    /// The percentage of a block’s execution cost limit at which the miner changes
    /// transaction selection behavior for non-boot contract calls.
    ///
    /// When the total cost of included transactions in the current block reaches this
    /// percentage of the block’s maximum execution cost (Clarity cost), and the next
    /// available **non-bootcode** contract call in the mempool would cause a
    /// `BlockTooBigError`, the miner will stop attempting to include additional
    /// non-boot contract calls. Instead, it will consider only STX transfers and
    /// boot contract calls for the remainder of the block budget.
    ///
    /// This allows miners to avoid repeatedly attempting to fit large non-boot
    /// contract calls late in block assembly when space is tight, improving block
    /// packing efficiency and ensuring other transaction types are not starved.
    ///
    /// ---
    /// @default: [`DEFAULT_CONTRACT_COST_LIMIT_PERCENTAGE`]
    /// @units: percent
    /// @notes:
    ///   - Values: 0–100.
    ///   - Setting to 100 effectively disables this behavior, allowing miners to
    ///     attempt non-boot contract calls until the block is full.
    ///   - This setting only affects **non-boot** contract calls; boot contract calls
    ///     and STX transfers are unaffected.
    pub contract_cost_limit_percentage: Option<u8>,
    /// Duration to wait in-between polling the sortition DB to see if we need to
    /// extend the ongoing tenure (e.g. because the current sortition is empty or invalid).
    ///
    /// After the relayer determines that a tenure extension might be needed but
    /// cannot proceed immediately (e.g., because a miner thread is already active
    /// for the current burn view), it will wait for this duration before
    /// re-checking the conditions for tenure extension.
    /// ---
    /// @default: [`DEFAULT_TENURE_EXTEND_POLL_SECS`]
    /// @units: seconds
    pub tenure_extend_poll_timeout: Duration,
    /// Duration to wait before trying to continue a tenure because the next miner
    /// did not produce blocks.
    ///
    /// If the node was the winner of the previous sortition but not the most recent
    /// one, the relayer waits for this duration before attempting to extend its own
    /// tenure. This gives the new winner of the most recent sortition a grace period
    /// to produce their first block. Also used in scenarios with empty sortitions
    /// to give the winner of the *last valid* sortition time to produce a block
    /// before the current miner attempts an extension.
    /// ---
    /// @default: [`DEFAULT_TENURE_EXTEND_WAIT_MS`]
    /// @units: milliseconds
    pub tenure_extend_wait_timeout: Duration,
    /// Duration to wait before attempting to issue a time-based tenure extend.
    ///
    /// A miner can proactively attempt to extend its tenure if a significant amount
    /// of time has passed since the last tenure change, even without an explicit
    /// trigger like an empty sortition. If the time elapsed since the last tenure
    /// change exceeds this value, and the signer coordinator indicates an extension
    /// is timely, and the cost usage threshold ([`MinerConfig::tenure_extend_cost_threshold`])
    /// is met, the miner will include a tenure extension transaction in its next block.
    /// ---
    /// @default: [`DEFAULT_TENURE_TIMEOUT_SECS`]
    /// @units: seconds
    pub tenure_timeout: Duration,
    /// Percentage of block budget that must be used before attempting a time-based tenure extend.
    ///
    /// This sets a minimum threshold for the accumulated execution cost within a
    /// tenure before a time-based tenure extension ([`MinerConfig::tenure_timeout`])
    /// can be initiated. The miner checks if the proportion of the total tenure
    /// budget consumed so far exceeds this percentage. If the cost usage is below
    /// this threshold, a time-based extension will not be attempted, even if the
    /// [`MinerConfig::tenure_timeout`] duration has elapsed. This prevents miners
    /// from extending tenures very early if they have produced only low-cost blocks.
    /// ---
    /// @default: [`DEFAULT_TENURE_EXTEND_COST_THRESHOLD`]
    /// @units: percent
    /// @notes:
    ///   - Values: 0-100.
    pub tenure_extend_cost_threshold: u64,
    /// Defines adaptive timeouts for waiting for signer responses, based on the
    /// accumulated weight of rejections.
    ///
    /// Configured as a map where keys represent rejection count thresholds in
    /// percentage, and values are the timeout durations (in seconds) to apply when
    /// the rejection count reaches or exceeds that key but is less than the next key.
    ///
    /// When a miner proposes a block, it waits for signer responses (approvals or
    /// rejections). The SignerCoordinator tracks the total weight of received
    /// rejections. It uses this map to determine the current timeout duration. It
    /// selects the timeout value associated with the largest key in the map that is
    /// less than or equal to the current accumulated rejection weight. If this
    /// timeout duration expires before a decision is reached, the coordinator
    /// signals a timeout. This prompts the miner to potentially retry proposing the
    /// block. As more rejections come in, the applicable timeout step might change
    /// (likely decrease), allowing the miner to abandon unviable proposals faster.
    ///
    /// A key for 0 (zero rejections) must be defined, representing the initial
    /// timeout when no rejections have been received.
    /// ---
    /// @default: `{ 0: 180, 10: 90, 20: 45, 30: 0 }` (times in seconds)
    /// @notes:
    ///   - Keys are rejection weight percentages (0-100).
    ///   - Values are timeout durations.
    /// @toml_example: |
    ///   # Keys are rejection counts (as strings), values are timeouts in seconds.
    ///   [miner.block_rejection_timeout_steps]
    ///   "0" = 180
    ///   "10" = 90
    ///   "20" = 45
    ///   "30" = 0
    pub block_rejection_timeout_steps: HashMap<u32, Duration>,
    /// Defines the maximum execution time (in seconds) allowed for a single contract call transaction.
    ///
    /// When processing a transaction (contract call or smart contract deployment),
    /// if this option is set, and the execution time exceeds this limit, the
    /// transaction processing fails with an `ExecutionTimeout` error, and the
    /// transaction is skipped. This prevents potentially long-running or
    /// infinite-loop transactions from blocking block production.
    /// ---
    /// @default: `None` (no execution time limit)
    /// @units: seconds
    pub max_execution_time_secs: Option<u64>,
    /// TODO: remove this option when its no longer a testing feature and it becomes default behaviour
    /// The miner will attempt to replay transactions that a threshold number of signers are expecting in the next block
    pub replay_transactions: bool,
    /// Defines the socket timeout (in seconds) for stackerdb communcation.
    /// ---
    /// @default: [`DEFAULT_STACKERDB_TIMEOUT_SECS`]
    /// @units: seconds.
    pub stackerdb_timeout: Duration,
    /// Defines them maximum numnber of bytes to allow in a tenure.
    /// The miner will stop mining if the limit is reached.
    pub max_tenure_bytes: u64,
    /// Enable logging of skipped transactions (generally used for tests)
    pub log_skipped_transactions: bool,
}

impl Default for MinerConfig {
    fn default() -> MinerConfig {
        MinerConfig {
            first_attempt_time_ms: 10,
            subsequent_attempt_time_ms: 120_000,
            microblock_attempt_time_ms: 30_000,
            nakamoto_attempt_time_ms: 5_000,
            probability_pick_no_estimate_tx: 25,
            block_reward_recipient: None,
            segwit: false,
            wait_for_block_download: true,
            nonce_cache_size: 1024 * 1024,
            candidate_retry_cache_size: 1024 * 1024,
            unprocessed_block_deadline_secs: 30,
            mining_key: None,
            wait_on_interim_blocks: None,
            min_tx_count: 0,
            only_increase_tx_count: false,
            unconfirmed_commits_helper: None,
            target_win_probability: 0.0,
            activated_vrf_key_path: None,
            fast_rampup: false,
            underperform_stop_threshold: None,
            mempool_walk_strategy: MemPoolWalkStrategy::NextNonceWithHighestFeeRate,
            txs_to_consider: MemPoolWalkTxTypes::all(),
            filter_origins: HashSet::new(),
            max_reorg_depth: 3,
            pre_nakamoto_mock_signing: false, // Should only default true if mining key is set
            min_time_between_blocks_ms: DEFAULT_MIN_TIME_BETWEEN_BLOCKS_MS,
            empty_mempool_sleep_time: Duration::from_millis(DEFAULT_EMPTY_MEMPOOL_SLEEP_MS),
            first_rejection_pause_ms: DEFAULT_FIRST_REJECTION_PAUSE_MS,
            subsequent_rejection_pause_ms: DEFAULT_SUBSEQUENT_REJECTION_PAUSE_MS,
            block_commit_delay: Duration::from_millis(DEFAULT_BLOCK_COMMIT_DELAY_MS),
            tenure_cost_limit_per_block_percentage: Some(
                DEFAULT_TENURE_COST_LIMIT_PER_BLOCK_PERCENTAGE,
            ),
            contract_cost_limit_percentage: Some(DEFAULT_CONTRACT_COST_LIMIT_PERCENTAGE),
            tenure_extend_poll_timeout: Duration::from_secs(DEFAULT_TENURE_EXTEND_POLL_SECS),
            tenure_extend_wait_timeout: Duration::from_millis(DEFAULT_TENURE_EXTEND_WAIT_MS),
            tenure_timeout: Duration::from_secs(DEFAULT_TENURE_TIMEOUT_SECS),
            tenure_extend_cost_threshold: DEFAULT_TENURE_EXTEND_COST_THRESHOLD,

            block_rejection_timeout_steps: {
                let mut rejections_timeouts_default_map = HashMap::<u32, Duration>::new();
                rejections_timeouts_default_map.insert(0, Duration::from_secs(180));
                rejections_timeouts_default_map.insert(10, Duration::from_secs(90));
                rejections_timeouts_default_map.insert(20, Duration::from_secs(45));
                rejections_timeouts_default_map.insert(30, Duration::from_secs(0));
                rejections_timeouts_default_map
            },
            max_execution_time_secs: None,
            replay_transactions: false,
            stackerdb_timeout: Duration::from_secs(DEFAULT_STACKERDB_TIMEOUT_SECS),
            max_tenure_bytes: DEFAULT_MAX_TENURE_BYTES,
            log_skipped_transactions: false,
        }
    }
}

#[derive(Clone, Default, Deserialize, Debug)]
#[serde(deny_unknown_fields)]
pub struct ConnectionOptionsFile {
    /// Maximum number of messages allowed in the per-connection incoming buffer.
    /// The limits apply individually to each established connection (both P2P and HTTP).
    /// ---
    /// @default: `100`
    pub inbox_maxlen: Option<usize>,
    /// Maximum number of messages allowed in the per-connection outgoing buffer.
    /// The limit applies individually to each established connection (both P2P and HTTP).
    /// ---
    /// @default: `100`
    pub outbox_maxlen: Option<usize>,
    /// Maximum duration (in seconds) a connection attempt is allowed to remain in
    /// the connecting state.
    ///
    /// This applies to both incoming P2P and HTTP connections. If a remote peer
    /// initiates a connection but does not complete the connection process
    /// (e.g., handshake for P2P) within this time, the node will consider it
    /// unresponsive and drop the connection attempt.
    /// ---
    /// @default: `10`
    /// @units: seconds
    pub connect_timeout: Option<u64>,
    /// Maximum duration (in seconds) a P2P peer is allowed after connecting before
    /// completing the handshake.
    ///
    /// If a P2P peer connects successfully but fails to send the necessary handshake
    /// messages within this time, the node will consider it unresponsive and drop the
    /// connection.
    /// ---
    /// @default: `5`
    /// @units: seconds
    pub handshake_timeout: Option<u64>,
    /// General communication timeout (in seconds).
    ///
    /// - For HTTP connections: Governs two timeout aspects:
    ///   - Server-side: Defines the maximum allowed time since the last request was
    ///     received from a client. An idle connection is dropped if both this
    ///     timeout and [`ConnectionOptionsFile::idle_timeout`] are exceeded.
    ///   - Client-side: Sets the timeout duration (TTL) for outgoing HTTP requests
    ///     initiated by the node itself.
    /// - For P2P connections: Used as the specific timeout for NAT punch-through requests.
    /// ---
    /// @default: `15`
    /// @units: seconds
    pub timeout: Option<u64>,
    /// Maximum idle time (in seconds) for HTTP connections.
    ///
    /// This applies only to HTTP connections. It defines the maximum allowed time
    /// since the last response was sent by the node to the client. An HTTP
    /// connection is dropped if both this `idle_timeout` and the general
    /// [`ConnectionOptionsFile::timeout`] (time since last request received) are exceeded.
    /// ---
    /// @default: `15`
    /// @units: seconds
    pub idle_timeout: Option<u64>,
    /// Interval (in seconds) at which this node expects to send or receive P2P
    /// keep-alive messages.
    ///
    /// During the P2P handshake, this node advertises this configured `heartbeat`
    /// value to its peers. Each peer uses the other's advertised heartbeat
    /// interval (plus a timeout margin) to monitor responsiveness and detect
    /// potential disconnections. This node also uses its own configured value to
    /// proactively send Ping messages if the connection would otherwise be idle,
    /// helping to keep it active.
    /// ---
    /// @default: `3_600` (1 hour)
    /// @units: seconds
    pub heartbeat: Option<u32>,
    /// Validity duration (in number of bitcoin blocks) for the node's P2P session
    /// private key.
    ///
    /// The node uses a temporary private key for signing P2P messages. This key has
    /// an associated expiry bitcoin block height stored in the peer database. When
    /// the current bitcoin height reaches or exceeds the key's expiry height, the
    /// node automatically generates a new random private key.
    /// The expiry block height for this new key is calculated by adding the
    /// configured [`ConnectionOptionsFile::private_key_lifetime`] (in blocks) to the
    /// previous key's expiry block height. The node then re-handshakes with peers
    /// to transition to the new key. This provides periodic key rotation for P2P communication.
    /// ---
    /// @default: `9223372036854775807` (i64::MAX, effectively infinite, disabling automatic re-keying).
    /// @units: bitcoin blocks
    pub private_key_lifetime: Option<u64>,
    /// Target number of peers for StackerDB replication.
    ///
    /// Sets the maximum number of potential replication target peers requested from
    /// the StackerDB control contract (`get-replication-targets`) when configuring a replica.
    ///
    /// Note: Formerly (pre-Epoch 3.0), this also controlled the target peer count for
    /// inventory synchronization.
    /// ---
    /// @default: `32`
    pub num_neighbors: Option<u64>,
    /// Maximum number of allowed concurrent inbound P2P connections.
    ///
    /// This acts as a hard limit. If the node already has this many active inbound
    /// P2P connections, any new incoming P2P connection attempts will be rejected.
    /// Outbound P2P connections initiated by this node are not counted against this limit.
    /// ---
    /// @default: `750`
    pub num_clients: Option<u64>,
    /// Maximum total number of allowed concurrent HTTP connections.
    ///
    /// This limits the total number of simultaneous connections the node's RPC/HTTP
    /// server will accept. If this limit is reached, new incoming HTTP connection
    /// attempts will be rejected.
    /// ---
    /// @default: `1000`
    pub max_http_clients: Option<u64>,
    /// Target number of outbound P2P connections the node aims to maintain.
    ///
    /// The connection pruning logic only activates if the current number of established
    /// outbound P2P connections exceeds this value. Pruning aims to reduce the
    /// connection count back down to this target, ensuring the node maintains a
    /// baseline number of outbound peers for network connectivity.
    /// ---
    /// @default: `16`
    pub soft_num_neighbors: Option<u64>,
    /// Soft limit threshold for triggering inbound P2P connection pruning.
    ///
    /// If the total number of currently active inbound P2P connections exceeds this
    /// value, the node will activate pruning logic to reduce the count, typically by
    /// applying per-host limits (see [`ConnectionOptionsFile::soft_max_clients_per_host`]).
    /// This helps manage the overall load from inbound peers.
    /// ---
    /// @default: `750`
    pub soft_num_clients: Option<u64>,
    /// Maximum number of neighbors per host we permit.
    /// ---
    /// @default: `1`
    /// @deprecated: It does not have any effect on the node's behavior.
    pub max_neighbors_per_host: Option<u64>,
    /// Maximum number of inbound p2p connections per host we permit.
    /// ---
    /// @default: `4`
    /// @deprecated: It does not have any effect on the node's behavior.
    pub max_clients_per_host: Option<u64>,
    /// Soft limit on the number of neighbors per host we permit.
    /// ---
    /// @default: `1`
    /// @deprecated: It does not have any effect on the node's behavior.
    pub soft_max_neighbors_per_host: Option<u64>,
    /// Soft limit on the number of outbound P2P connections per network organization (ASN).
    ///
    /// During connection pruning (when total outbound connections >
    /// [`ConnectionOptionsFile::soft_num_neighbors`]), the node checks if any single
    /// network organization (identified by ASN) has more outbound connections than
    /// this limit. If so, it preferentially prunes the least healthy/newest
    /// connections from that overrepresented organization until its count is
    /// reduced to this limit or the total outbound count reaches
    /// [`ConnectionOptionsFile::soft_num_neighbors`]. This encourages connection diversity
    /// across different network providers.
    /// ---
    /// @default: `32`
    pub soft_max_neighbors_per_org: Option<u64>,
    /// Soft limit on the number of inbound P2P connections allowed per host IP address.
    ///
    /// During inbound connection pruning (when total inbound connections >
    /// [`ConnectionOptionsFile::soft_num_clients`]), the node checks if any single
    /// IP address has more connections than this limit. If so, it preferentially
    /// prunes the newest connections originating from that specific IP address
    /// until its count is reduced to this limit. This prevents a single host from
    /// dominating the node's inbound connection capacity.
    /// ---
    /// @default: `4`
    pub soft_max_clients_per_host: Option<u64>,
    /// Maximum total number of concurrent network sockets the node is allowed to manage.
    ///
    /// This limit applies globally to all types of sockets handled by the node's
    /// networking layer, including listening sockets (P2P and RPC/HTTP),
    /// established P2P connections (inbound/outbound), and established HTTP connections.
    /// It serves as a hard limit to prevent the node from exhausting operating
    /// system resources related to socket descriptors.
    /// ---
    /// @default: `800`
    pub max_sockets: Option<u64>,
    /// Minimum interval (in seconds) between the start of consecutive neighbor discovery walks.
    ///
    /// The node periodically performs "neighbor walks" to discover new peers and
    /// maintain an up-to-date view of the P2P network topology. This setting
    /// controls how frequently these walks can be initiated, preventing excessive
    /// network traffic and processing.
    /// ---
    /// @default: `60`
    /// @units: seconds
    pub walk_interval: Option<u64>,
    /// Probability (0.0 to 1.0) of forcing a neighbor walk to start from a seed/bootstrap peer.
    ///
    /// This probability applies only when the node is not in Initial Block Download (IBD)
    /// and is already connected to at least one seed/bootstrap peer.
    /// Normally, in this situation, the walk would start from a random inbound or
    /// outbound peer. However, with this probability, the walk is forced to start
    /// from a seed peer instead. This helps ensure the node periodically
    /// re-establishes its network view from trusted entry points.
    /// ---
    /// @default: `0.1` (10%)
    pub walk_seed_probability: Option<f64>,
    /// Frequency (in milliseconds) for logging the current P2P neighbor list at the
    /// DEBUG level.
    ///
    /// If set to a non-zero value, the node will periodically log details about its
    /// currently established P2P connections (neighbors). Setting this to 0 disables
    /// this periodic logging.
    /// ---
    /// @default: `60_000` (1 minute)
    /// @units: milliseconds
    pub log_neighbors_freq: Option<u64>,
    /// Maximum time (in milliseconds) to wait for a DNS query to resolve.
    ///
    /// When the node needs to resolve a hostname (e.g., from a peer's advertised
    /// [`NodeConfig::data_url`] or an Atlas attachment URL) into an IP address, it
    /// initiates a DNS lookup. This setting defines the maximum duration the node will
    /// wait for the DNS server to respond before considering the lookup timed out.
    /// ---
    /// @default: `15_000` (15 seconds)
    /// @units: milliseconds
    pub dns_timeout: Option<u64>,
    /// Maximum number of concurrent Nakamoto block download requests allowed.
    ///
    /// This limits how many separate block download processes for Nakamoto tenures
    /// (both confirmed and unconfirmed) can be active simultaneously. Helps manage
    /// network bandwidth and processing load during chain synchronization.
    /// ---
    /// @default: `6`
    pub max_inflight_blocks: Option<u64>,
    /// Maximum number of concurrent Atlas data attachment download requests allowed.
    ///
    /// This limits how many separate download requests for Atlas data attachments
    /// can be active simultaneously. Helps manage network resources when fetching
    /// potentially large attachment data.
    /// ---
    /// @default: `6`
    pub max_inflight_attachments: Option<u64>,
    /// Maximum total size (in bytes) of data allowed to be written during a read-only call.
    /// ---
    /// @default: `0`
    /// @notes:
    ///   - This limit is effectively forced to 0 by the API handler, ensuring read-only behavior.
    ///   - Configuring a non-zero value has no effect on read-only call execution.
    /// @units: bytes
    pub read_only_call_limit_write_length: Option<u64>,
    /// Maximum total size (in bytes) of data allowed to be read from Clarity data
    /// space (variables, maps) during a read-only call.
    /// ---
    /// @default: `100_000` (100 KB).
    /// @units: bytes
    pub read_only_call_limit_read_length: Option<u64>,
    /// Maximum number of distinct write operations allowed during a read-only call.
    /// ---
    /// @default: `0`
    /// @notes:
    ///   - This limit is effectively forced to 0 by the API handler, ensuring read-only behavior.
    ///   - Configuring a non-zero value has no effect on read-only call execution.
    pub read_only_call_limit_write_count: Option<u64>,
    /// Maximum number of distinct read operations from Clarity data space allowed
    /// during a read-only call.
    /// ---
    /// @default: `30`
    pub read_only_call_limit_read_count: Option<u64>,
    /// Runtime cost limit for an individual read-only function call. This represents
    /// computation effort within the Clarity VM.
    /// (See SIP-006: https://github.com/stacksgov/sips/blob/main/sips/sip-006/sip-006-runtime-cost-assessment.md)
    /// ---
    /// @default: `1_000_000_000`
    /// @units: Clarity VM cost units
    pub read_only_call_limit_runtime: Option<u64>,
    /// Maximum size (in bytes) of the HTTP request body for read-only contract calls.
    ///
    /// This limit is enforced on the `Content-Length` of incoming requests to the
    /// `/v2/contracts/call-read-only/...` RPC endpoint. It prevents excessively large
    /// request bodies, which might contain numerous or very large hex-encoded
    /// function arguments, from overwhelming the node.
    /// ---
    /// @default: `83_886_080` (80 MiB)
    /// @units: bytes
    /// @notes:
    ///   - Calculated as 20 * [`clarity::vm::types::BOUND_VALUE_SERIALIZATION_HEX`].
    pub maximum_call_argument_size: Option<u32>,
    /// Minimum interval (in seconds) between consecutive block download scans in epoch 2.x.
    ///
    /// In the pre-Nakamoto block download logic, if a full scan for blocks completed
    /// without finding any new blocks to download, and if the known peer inventories
    /// had not changed, the node would wait at least this duration before
    /// initiating the next download scan. This throttled the downloader when the
    /// node was likely already synchronized.
    /// ---
    /// @default: `10`
    /// @units: seconds
    /// @deprecated: This setting is ignored in Epoch 3.0+.
    pub download_interval: Option<u64>,
    /// Minimum interval (in seconds) between initiating inventory synchronization
    /// attempts with the same peer.
    ///
    /// Acts as a per-peer cooldown to throttle sync requests. A new sync cycle with
    /// a peer generally starts only after this interval has passed since the previous
    /// attempt began *and* the previous cycle is considered complete.
    /// ---
    /// @default: `45`
    /// @units: seconds
    pub inv_sync_interval: Option<u64>,
    /// Deprecated: it does not have any effect on the node's behavior.
    /// ---
    /// @default: `None`
    /// @deprecated: It does not have any effect on the node's behavior.
    pub full_inv_sync_interval: Option<u64>,
    /// Lookback depth (in PoX reward cycles) for Nakamoto inventory synchronization requests.
    ///
    /// When initiating an inventory sync cycle with a peer, the node requests data
    /// starting from `inv_reward_cycles` cycles before the current target reward
    /// cycle. This determines how much historical inventory information is requested
    /// in each sync attempt.
    /// ---
    /// @default: |
    ///   - if [`BurnchainConfig::mode`] is `"mainnet"`: `3`
    ///   - else: [`INV_REWARD_CYCLES_TESTNET`]
    /// @units: PoX reward cycles
    pub inv_reward_cycles: Option<u64>,
    /// The Public IPv4 address and port (e.g. "203.0.113.42:20444") to advertise to other nodes.
    ///
    /// If this option is not set (`None`), the node will attempt to automatically
    /// discover its public IP address.
    /// ---
    /// @default: `None` (triggers automatic discovery attempt)
    pub public_ip_address: Option<String>,
    /// If true, disables the neighbor discovery mechanism from starting walks from
    /// inbound peers. Walks will only initiate from seed/bootstrap peers, outbound
    /// connections, or pingbacks.
    /// ---
    /// @default: `false`
    /// @notes:
    ///   - Primarily intended for testing or specific network debugging scenarios.
    pub disable_inbound_walks: Option<bool>,
    /// If true, prevents the node from processing initial handshake messages from new
    /// inbound P2P connections.
    ///
    /// This effectively stops the node from establishing new authenticated inbound
    /// P2P sessions. Outbound connections initiated by this node are unaffected.
    /// ---
    /// @default: `false`
    /// @notes:
    ///   - Primarily intended for testing purposes.
    pub disable_inbound_handshakes: Option<bool>,
    /// If true, completely disables the block download state machine.
    ///
    /// The node will not attempt to download Stacks blocks (neither Nakamoto
    /// tenures nor legacy blocks) from peers.
    /// ---
    /// @default: `false`
    /// @notes:
    ///   - Intended for testing or specialized node configurations.
    pub disable_block_download: Option<bool>,
    /// Fault injection setting for testing purposes. Interval (in seconds) for
    /// forced disconnection of all peers.
    ///
    /// If set to a positive value, the node will periodically disconnect all of its
    /// P2P peers at roughly this interval. This simulates network churn or
    /// partitioning for testing node resilience.
    /// ---
    /// @default: `None` (feature disabled)
    /// @notes:
    ///   - If set to a positive value, the node will periodically disconnect all of
    ///     its P2P peers at roughly this interval.
    ///   - This simulates network churn or partitioning for testing node resilience.
    ///   - The code enforcing this behavior is conditionally compiled using `cfg!(test)`
    ///     and is only active during test runs.
    ///   - This setting has no effect in standard production builds.
    /// @units: seconds
    pub force_disconnect_interval: Option<u64>,
    /// Controls whether a node with public inbound connections should still push
    /// blocks, even if not NAT'ed.
    ///
    /// In the Stacks 2.x anti-entropy logic, if a node detected it had inbound
    /// connections from public IPs (suggesting it wasn't behind NAT) and this flag
    /// was set to `false`, it would refrain from proactively pushing blocks and
    /// microblocks to peers. The assumption was that publicly reachable nodes should
    /// primarily serve downloads. If set to `true` (default), the node would push
    /// data regardless of its perceived reachability.
    /// ---
    /// @default: `true`
    /// @deprecated: This setting is ignored in Epoch 3.0+.
    pub antientropy_public: Option<bool>,
    /// Whether to allow connections and interactions with peers having private IP addresses.
    ///
    /// If `false` (default), the node will generally:
    /// - Reject incoming connection attempts from peers with private IPs.
    /// - Avoid initiating connections to peers known to have private IPs.
    /// - Ignore peers with private IPs during neighbor discovery (walks).
    /// - Skip querying peers with private IPs for mempool or StackerDB data.
    /// - Filter out peers with private IPs from API responses listing potential peers.
    ///
    /// Setting this to `true` disables these restrictions, which can be useful for
    /// local testing environments or fully private network deployments.
    /// ---
    /// @default: `false`
    pub private_neighbors: Option<bool>,
    /// HTTP auth password to use when communicating with stacks-signer binary.
    ///
    /// This token is used in the `Authorization` header for certain requests.
    /// Primarily, it secures the communication channel between this node and a
    /// connected `stacks-signer` instance.
    ///
    /// It is also used to authenticate requests to `/v2/blocks?broadcast=1`.
    /// ---
    /// @default: `None` (authentication disabled for relevant endpoints)
    /// @notes:
    ///   - This field **must** be configured if the node needs to receive
    ///     block proposals from a configured `stacks-signer` [[events_observer]]
    ///     via the `/v3/block_proposal` endpoint.
    ///   - The value must match the token configured on the signer.
    pub auth_token: Option<String>,
    /// Minimum interval (in seconds) between attempts to run the Epoch 2.x anti-entropy
    /// data push mechanism.
    ///
    /// The Stacks 2.x anti-entropy protocol involves the node proactively pushing its
    /// known Stacks blocks and microblocks to peers. This value specifies the
    /// cooldown period for this operation. This prevents the node from excessively
    /// attempting to push data to its peers.
    /// ---
    /// @default: `3_600` (1 hour)
    /// @deprecated: This setting is ignored in Epoch 3.0+.
    /// @units: seconds
    pub antientropy_retry: Option<u64>,
    /// Controls whether the node accepts Nakamoto blocks pushed proactively by peers.
    ///
    /// - If `true`: Pushed blocks are ignored (logged at DEBUG and discarded). The
    ///   node will still process blocks that it actively downloads.
    /// - If `false`: Both pushed blocks and actively downloaded blocks are processed.
    /// ---
    /// @default: `false`
    pub reject_blocks_pushed: Option<bool>,
    /// Static list of preferred replica peers for specific StackerDB contracts,
    /// provided as a JSON string.
    ///
    /// This allows manually specifying known peers to use for replicating particular
    /// StackerDBs, potentially overriding or supplementing the peers discovered via
    /// the StackerDB's control contract.
    ///
    /// Format: The configuration value must be a TOML string containing valid JSON.
    /// The JSON structure must be an array of tuples, where each tuple pairs a
    /// contract identifier with a list of preferred neighbor addresses:
    /// `[[ContractIdentifier, [NeighborAddress, ...]], ...]`
    ///
    /// 1.  `ContractIdentifier`: A JSON object representing the [`QualifiedContractIdentifier`].
    ///     It must have the specific structure:
    ///     `{"issuer": [version_byte, [byte_array_20]], "name": "contract-name"}`
    ///
    /// 2.  `NeighborAddress`: A JSON object specifying the peer details:
    ///     `{"ip": "...", "port": ..., "public_key_hash": "..."}`
    /// ---
    /// @default: `None` (no hints provided)
    /// @notes:
    ///   - Use this option with caution, primarily for advanced testing or bootstrapping.
    /// @toml_example: |
    ///   stackerdb_hint_replicas = '''
    ///   [
    ///     [
    ///       {
    ///         "issuer": [1, [1,2,3,4,5,6,7,8,9,10,11,12,13,14,15,16,17,18,19,20]],
    ///         "name": "my-contract"
    ///       },
    ///       [
    ///         {
    ///           "ip": "192.0.2.1",
    ///           "port": 20444,
    ///           "public_key_hash": "0102030405060708090a0b0c0d0e0f1011121314"
    ///         }
    ///       ]
    ///     ]
    ///   ]
    ///   '''
    pub stackerdb_hint_replicas: Option<String>,
    /// Maximum age (in seconds) allowed for a block proposal received via the
    /// `/v3/block_proposal` RPC endpoint.
    ///
    /// If a block proposal is received whose timestamp is older than the current
    /// time minus this configured value, the node will reject the proposal with an
    /// HTTP 422 (Unprocessable Entity) error, considering it too stale. This
    /// prevents the node from spending resources validating outdated proposals.
    /// ---
    /// @default: [`DEFAULT_BLOCK_PROPOSAL_MAX_AGE_SECS`]
    /// @units: seconds
    pub block_proposal_max_age_secs: Option<u64>,

    /// Maximum time (in seconds) that a readonly call in free cost tracking mode
    /// can run before being interrupted
    /// ---
    /// @default: 30
    /// @units: seconds
    pub read_only_max_execution_time_secs: Option<u64>,
}

impl ConnectionOptionsFile {
    fn into_config(self, is_mainnet: bool) -> Result<ConnectionOptions, String> {
        let ip_addr = self
            .public_ip_address
            .map(|public_ip_address| {
                public_ip_address
                    .parse::<SocketAddr>()
                    .map(|addr| (PeerAddress::from_socketaddr(&addr), addr.port()))
                    .map_err(|e| format!("Invalid connection_option.public_ip_address: {e}"))
            })
            .transpose()?;
        let mut read_only_call_limit = HELIUM_DEFAULT_CONNECTION_OPTIONS
            .read_only_call_limit
            .clone();
        if let Some(x) = self.read_only_call_limit_write_length {
            read_only_call_limit.write_length = x;
        }
        if let Some(x) = self.read_only_call_limit_write_count {
            read_only_call_limit.write_count = x;
        }
        if let Some(x) = self.read_only_call_limit_read_length {
            read_only_call_limit.read_length = x;
        }
        if let Some(x) = self.read_only_call_limit_read_count {
            read_only_call_limit.read_count = x;
        }
        if let Some(x) = self.read_only_call_limit_runtime {
            read_only_call_limit.runtime = x;
        };
        let default = ConnectionOptions::default();
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
                .unwrap_or_else(|| HELIUM_DEFAULT_CONNECTION_OPTIONS.walk_interval),
            walk_seed_probability: self
                .walk_seed_probability
                .unwrap_or_else(|| HELIUM_DEFAULT_CONNECTION_OPTIONS.walk_seed_probability),
            log_neighbors_freq: self
                .log_neighbors_freq
                .unwrap_or_else(|| HELIUM_DEFAULT_CONNECTION_OPTIONS.log_neighbors_freq),
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
                .unwrap_or_else(|| HELIUM_DEFAULT_CONNECTION_OPTIONS.download_interval),
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
                .unwrap_or_else(|| HELIUM_DEFAULT_CONNECTION_OPTIONS.max_http_clients),
            connect_timeout: self.connect_timeout.unwrap_or(10),
            handshake_timeout: self.handshake_timeout.unwrap_or(5),
            max_sockets: self.max_sockets.unwrap_or(800) as usize,
            antientropy_public: self.antientropy_public.unwrap_or(true),
            private_neighbors: self.private_neighbors.unwrap_or(false),
            auth_token: self.auth_token,
            antientropy_retry: self.antientropy_retry.unwrap_or(default.antientropy_retry),
            reject_blocks_pushed: self
                .reject_blocks_pushed
                .unwrap_or(default.reject_blocks_pushed),
            stackerdb_hint_replicas: self
                .stackerdb_hint_replicas
                .map(|stackerdb_hint_replicas_json| {
                    let hint_replicas_res: Result<
                        Vec<(QualifiedContractIdentifier, Vec<NeighborAddress>)>,
                        String,
                    > = serde_json::from_str(&stackerdb_hint_replicas_json)
                        .map_err(|e| format!("Failed to decode `stackerdb_hint_replicas`: {e:?}"));
                    hint_replicas_res
                })
                .transpose()?
                .map(HashMap::from_iter)
                .unwrap_or(default.stackerdb_hint_replicas),
            block_proposal_max_age_secs: self
                .block_proposal_max_age_secs
                .unwrap_or(DEFAULT_BLOCK_PROPOSAL_MAX_AGE_SECS),
            read_only_max_execution_time_secs: self
                .read_only_max_execution_time_secs
                .unwrap_or(default.read_only_max_execution_time_secs),
            ..default
        })
    }
}

#[derive(Clone, Deserialize, Default, Debug)]
#[serde(deny_unknown_fields)]
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
    pub stacker: Option<bool>,
    pub mock_mining: Option<bool>,
    pub mock_mining_output_dir: Option<String>,
    pub mine_microblocks: Option<bool>,
    pub microblock_frequency: Option<u64>,
    pub max_microblocks: Option<u64>,
    pub wait_time_for_microblocks: Option<u64>,
    pub wait_time_for_blocks: Option<u64>,
    pub next_initiative_delay: Option<u64>,
    pub prometheus_bind: Option<String>,
    pub marf_cache_strategy: Option<String>,
    pub marf_defer_hashing: Option<bool>,
    pub pox_sync_sample_secs: Option<u64>,
    pub use_test_genesis_chainstate: Option<bool>,
    /// At most, how often should the chain-liveness thread
    ///  wake up the chains-coordinator. Defaults to 300s (5 min).
    pub chain_liveness_poll_time_secs: Option<u64>,
    /// Stacker DBs we replicate
    pub stacker_dbs: Option<Vec<String>>,
    /// fault injection: fail to push blocks with this probability (0-100)
    pub fault_injection_block_push_fail_probability: Option<u8>,
    /// enable transactions indexing, note this will require additional storage (in the order of gigabytes)
    pub txindex: Option<bool>,
}

impl NodeConfigFile {
    fn into_config_default(self, default_node_config: NodeConfig) -> Result<NodeConfig, String> {
        let rpc_bind = self.rpc_bind.unwrap_or(default_node_config.rpc_bind);
        let miner = self.miner.unwrap_or(default_node_config.miner);
        let stacker = self.stacker.unwrap_or(default_node_config.stacker);
        let node_config = NodeConfig {
            name: self.name.unwrap_or(default_node_config.name),
            seed: match self.seed {
                Some(seed) => hex_bytes(&seed)
                    .map_err(|_e| "node.seed should be a hex encoded string".to_string())?,
                None => default_node_config.seed,
            },
            working_dir: std::env::var("STACKS_WORKING_DIR")
                .unwrap_or(self.working_dir.unwrap_or(default_node_config.working_dir)),
            rpc_bind: rpc_bind.clone(),
            p2p_bind: self.p2p_bind.unwrap_or(default_node_config.p2p_bind),
            p2p_address: self.p2p_address.unwrap_or(rpc_bind.clone()),
            bootstrap_node: vec![],
            deny_nodes: vec![],
            data_url: self
                .data_url
                .unwrap_or_else(|| format!("http://{rpc_bind}")),
            local_peer_seed: match self.local_peer_seed {
                Some(seed) => hex_bytes(&seed).map_err(|_e| {
                    "node.local_peer_seed should be a hex encoded string".to_string()
                })?,
                None => default_node_config.local_peer_seed,
            },
            miner,
            stacker,
            mock_mining: self.mock_mining.unwrap_or(default_node_config.mock_mining),
            mock_mining_output_dir: self
                .mock_mining_output_dir
                .map(PathBuf::from)
                .map(fs::canonicalize)
                .transpose()
                .unwrap_or_else(|e| {
                    panic!("Failed to construct PathBuf from node.mock_mining_output_dir: {e}")
                }),
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
            next_initiative_delay: self
                .next_initiative_delay
                .unwrap_or(default_node_config.next_initiative_delay),
            prometheus_bind: self.prometheus_bind,
            marf_cache_strategy: self.marf_cache_strategy,
            marf_defer_hashing: self
                .marf_defer_hashing
                .unwrap_or(default_node_config.marf_defer_hashing),
            pox_sync_sample_secs: self
                .pox_sync_sample_secs
                .unwrap_or(default_node_config.pox_sync_sample_secs),
            use_test_genesis_chainstate: self.use_test_genesis_chainstate,
            // chainstate fault_injection activation for hide_blocks.
            // you can't set this in the config file.
            fault_injection_hide_blocks: false,
            chain_liveness_poll_time_secs: self
                .chain_liveness_poll_time_secs
                .unwrap_or(default_node_config.chain_liveness_poll_time_secs),
            stacker_dbs: self
                .stacker_dbs
                .unwrap_or_default()
                .iter()
                .filter_map(|contract_id| QualifiedContractIdentifier::parse(contract_id).ok())
                .collect(),
            fault_injection_block_push_fail_probability: if self
                .fault_injection_block_push_fail_probability
                .is_some()
            {
                self.fault_injection_block_push_fail_probability
            } else {
                default_node_config.fault_injection_block_push_fail_probability
            },

            txindex: self.txindex.unwrap_or(default_node_config.txindex),
        };
        Ok(node_config)
    }
}

#[derive(Clone, Deserialize, Default, Debug)]
#[serde(deny_unknown_fields)]
pub struct FeeEstimationConfigFile {
    /// Specifies the name of the cost estimator to use.
    /// This controls how the node estimates computational costs for transactions.
    ///
    /// Accepted values:
    /// - `"NaivePessimistic"`: The only currently supported cost estimator. This estimator
    ///   tracks the highest observed costs for each operation type and uses the average
    ///   of the top 10 values as its estimate, providing a conservative approach to
    ///   cost estimation.
    /// ---
    /// @default: `"NaivePessimistic"`
    /// @notes:
    ///   - If [`FeeEstimationConfigFile::disabled`] is `true`, the node will
    ///     use the default unit cost estimator.
    pub cost_estimator: Option<String>,
    /// Specifies the name of the fee estimator to use.
    /// This controls how the node calculates appropriate transaction fees based on costs.
    ///
    /// Accepted values:
    /// - `"ScalarFeeRate"`: Simple multiplier-based fee estimation that uses percentiles
    ///   (5th, 50th, and 95th) of observed fee rates from recent blocks.
    /// - `"FuzzedWeightedMedianFeeRate"`: Fee estimation that adds controlled randomness
    ///   to a weighted median rate calculator. This helps prevent fee optimization attacks
    ///   by adding unpredictability to fee estimates while still maintaining accuracy.
    /// ---
    /// @default: `"ScalarFeeRate"`
    /// @notes:
    ///   - If [`FeeEstimationConfigFile::disabled`] is `true`, the node will
    ///     use the default unit fee estimator.
    pub fee_estimator: Option<String>,
    /// Specifies the name of the cost metric to use.
    /// This controls how the node measures and compares transaction costs.
    ///
    /// Accepted values:
    /// - `"ProportionDotProduct"`: The only currently supported cost metric. This metric
    ///   computes a weighted sum of cost dimensions (runtime, read/write counts, etc.)
    ///   proportional to how much of the block limit they consume.
    /// ---
    /// @default: `"ProportionDotProduct"`
    /// @notes:
    ///   - If [`FeeEstimationConfigFile::disabled`] is `true`, the node will
    ///     use the default unit cost metric.
    pub cost_metric: Option<String>,
    /// If `true`, all fee and cost estimation features are disabled.
    /// The node will use unit estimators and metrics, which effectively provide no
    /// actual estimation capabilities.
    ///
    /// When disabled, the node will:
    /// 1. Not track historical transaction costs or fee rates.
    /// 2. Return simple unit values for costs for any transaction, regardless of
    ///    its actual complexity.
    /// 3. Be unable to provide meaningful fee estimates for API requests (always
    ///    returns an error).
    /// 4. Consider only raw transaction fees (not fees per cost unit) when
    ///    assembling blocks.
    ///
    /// This setting takes precedence over individual estimator/metric configurations.
    /// ---
    /// @default: `false`
    /// @notes:
    ///   - When `true`, the values for [`FeeEstimationConfigFile::cost_estimator`],
    ///     [`FeeEstimationConfigFile::fee_estimator`], and
    ///     [`FeeEstimationConfigFile::cost_metric`] are ignored.
    pub disabled: Option<bool>,
    /// If `true`, errors encountered during cost or fee estimation will be logged.
    /// This can help diagnose issues with the fee estimation subsystem.
    /// ---
    /// @default: `false`
    pub log_error: Option<bool>,
    /// Specifies the fraction of random noise to add if using the
    /// `FuzzedWeightedMedianFeeRate` fee estimator. This value should be in the
    /// range [0, 1], representing a percentage of the base fee rate.
    ///
    /// For example, with a value of 0.1 (10%), fee rate estimates will have random
    /// noise added within the range of ±10% of the original estimate. This
    /// randomization makes it difficult for users to precisely optimize their fees
    /// while still providing reasonable estimates.
    /// ---
    /// @default: `0.1` (10%)
    /// @notes:
    ///   - This setting is only relevant when [`FeeEstimationConfigFile::fee_estimator`] is set to
    ///     `"FuzzedWeightedMedianFeeRate"`.
    pub fee_rate_fuzzer_fraction: Option<f64>,
    /// Specifies the window size for the `WeightedMedianFeeRateEstimator`.
    /// This determines how many historical fee rate data points are considered
    /// when calculating the median fee rate.
    ///
    // The window size controls how quickly the fee estimator responds to changing
    // network conditions. A smaller window size (e.g., 5) makes the estimator more
    // responsive to recent fee rate changes but potentially more volatile. A larger
    // window size (e.g., 10) produces more stable estimates but may be slower to
    // adapt to rapid network changes.
    /// ---
    /// @default: `5`
    /// @notes:
    ///   - This setting is primarily relevant when [`FeeEstimationConfigFile::fee_estimator`] is set
    ///     to `"FuzzedWeightedMedianFeeRate"`.
    pub fee_rate_window_size: Option<u64>,
}

#[derive(Clone, Deserialize, Default, Debug)]
#[serde(deny_unknown_fields)]
pub struct MinerConfigFile {
    pub first_attempt_time_ms: Option<u64>,
    pub subsequent_attempt_time_ms: Option<u64>,
    pub microblock_attempt_time_ms: Option<u64>,
    pub nakamoto_attempt_time_ms: Option<u64>,
    pub mempool_walk_strategy: Option<String>,
    pub probability_pick_no_estimate_tx: Option<u8>,
    pub block_reward_recipient: Option<String>,
    pub segwit: Option<bool>,
    pub nonce_cache_size: Option<usize>,
    pub candidate_retry_cache_size: Option<usize>,
    pub unprocessed_block_deadline_secs: Option<u64>,
    pub mining_key: Option<String>,
    pub wait_on_interim_blocks_ms: Option<u64>,
    pub min_tx_count: Option<u64>,
    pub only_increase_tx_count: Option<bool>,
    pub unconfirmed_commits_helper: Option<String>,
    pub target_win_probability: Option<f64>,
    pub activated_vrf_key_path: Option<String>,
    pub fast_rampup: Option<bool>,
    pub underperform_stop_threshold: Option<u64>,
    pub txs_to_consider: Option<String>,
    pub filter_origins: Option<String>,
    pub max_reorg_depth: Option<u64>,
    pub pre_nakamoto_mock_signing: Option<bool>,
    pub min_time_between_blocks_ms: Option<u64>,
    pub empty_mempool_sleep_ms: Option<u64>,
    pub first_rejection_pause_ms: Option<u64>,
    pub subsequent_rejection_pause_ms: Option<u64>,
    pub block_commit_delay_ms: Option<u64>,
    pub tenure_cost_limit_per_block_percentage: Option<u8>,
    pub contract_cost_limit_percentage: Option<u8>,
    pub tenure_extend_poll_secs: Option<u64>,
    pub tenure_extend_wait_timeout_ms: Option<u64>,
    pub tenure_timeout_secs: Option<u64>,
    pub tenure_extend_cost_threshold: Option<u64>,
    pub block_rejection_timeout_steps: Option<HashMap<String, u64>>,
    pub max_execution_time_secs: Option<u64>,
    /// TODO: remove this config option once its no longer a testing feature
    pub replay_transactions: Option<bool>,
    pub stackerdb_timeout_secs: Option<u64>,
    pub max_tenure_bytes: Option<u64>,
}

impl MinerConfigFile {
    fn into_config_default(self, miner_default_config: MinerConfig) -> Result<MinerConfig, String> {
        match &self.mining_key {
            Some(_) => {}
            None => {
                panic!("mining key not set");
            }
        }

        let mining_key = self
            .mining_key
            .as_ref()
            .map(|x| Secp256k1PrivateKey::from_hex(x))
            .transpose()?;
        let pre_nakamoto_mock_signing = mining_key.is_some();

        let tenure_cost_limit_per_block_percentage =
            if let Some(percentage) = self.tenure_cost_limit_per_block_percentage {
                if percentage == 100 {
                    None
                } else if percentage > 0 && percentage < 100 {
                    Some(percentage)
                } else {
                    return Err(
                        "miner.tenure_cost_limit_per_block_percentage must be between 1 and 100"
                            .to_string(),
                    );
                }
            } else {
                miner_default_config.tenure_cost_limit_per_block_percentage
            };

        let contract_cost_limit_percentage = if let Some(percentage) =
            self.contract_cost_limit_percentage
        {
            if percentage <= 100 {
                Some(percentage)
            } else {
                return Err(
                    "miner.contract_cost_limit_percentage must be between 0 and 100".to_string(),
                );
            }
        } else {
            miner_default_config.contract_cost_limit_percentage
        };

        let nonce_cache_size = self
            .nonce_cache_size
            .unwrap_or(miner_default_config.nonce_cache_size);
        if nonce_cache_size == 0 {
            return Err("miner.nonce_cache_size must be greater than 0".to_string());
        }

        Ok(MinerConfig {
            first_attempt_time_ms: self
                .first_attempt_time_ms
                .unwrap_or(miner_default_config.first_attempt_time_ms),
            subsequent_attempt_time_ms: self
                .subsequent_attempt_time_ms
                .unwrap_or(miner_default_config.subsequent_attempt_time_ms),
            microblock_attempt_time_ms: self
                .microblock_attempt_time_ms
                .unwrap_or(miner_default_config.microblock_attempt_time_ms),
            nakamoto_attempt_time_ms: self
                .nakamoto_attempt_time_ms
                .unwrap_or(miner_default_config.nakamoto_attempt_time_ms),
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
            wait_on_interim_blocks: self
                .wait_on_interim_blocks_ms
                .map(Duration::from_millis),
            min_tx_count: self
                .min_tx_count
                .unwrap_or(miner_default_config.min_tx_count),
            only_increase_tx_count: self
                .only_increase_tx_count
                .unwrap_or(miner_default_config.only_increase_tx_count),
            unconfirmed_commits_helper: self.unconfirmed_commits_helper.clone(),
            target_win_probability: self
                .target_win_probability
                .unwrap_or(miner_default_config.target_win_probability),
            activated_vrf_key_path: self.activated_vrf_key_path.clone(),
            fast_rampup: self.fast_rampup.unwrap_or(miner_default_config.fast_rampup),
            underperform_stop_threshold: self.underperform_stop_threshold,
            mempool_walk_strategy: self.mempool_walk_strategy
                .map(|s| str::parse(&s).unwrap_or_else(|e| panic!("Could not parse '{s}': {e}")))
                .unwrap_or(MemPoolWalkStrategy::NextNonceWithHighestFeeRate),
            txs_to_consider: {
                if let Some(txs_to_consider) = &self.txs_to_consider {
                    txs_to_consider
                        .split(',')
                        .map(
                            |txs_to_consider_str| match str::parse(txs_to_consider_str) {
                                Ok(txtype) => txtype,
                                Err(e) => {
                                    panic!("could not parse '{txs_to_consider_str}': {e}");
                                }
                            },
                        )
                        .collect()
                } else {
                    MemPoolWalkTxTypes::all()
                }
            },
            filter_origins: {
                if let Some(filter_origins) = &self.filter_origins {
                    filter_origins
                        .split(',')
                        .map(|origin_str| match StacksAddress::from_string(origin_str) {
                            Some(addr) => addr,
                            None => {
                                panic!("could not parse '{origin_str}' into a Stacks address");
                            }
                        })
                        .collect()
                } else {
                    HashSet::new()
                }
            },
            max_reorg_depth: self
                .max_reorg_depth
                .unwrap_or(miner_default_config.max_reorg_depth),
            pre_nakamoto_mock_signing: self
                .pre_nakamoto_mock_signing
                .unwrap_or(pre_nakamoto_mock_signing), // Should only default true if mining key is set
            min_time_between_blocks_ms: self.min_time_between_blocks_ms.map(|ms| if ms < DEFAULT_MIN_TIME_BETWEEN_BLOCKS_MS {
                warn!("miner.min_time_between_blocks_ms is less than the minimum allowed value of {DEFAULT_MIN_TIME_BETWEEN_BLOCKS_MS} ms. Using the default value instead.");
                DEFAULT_MIN_TIME_BETWEEN_BLOCKS_MS
            } else {
                ms
            }).unwrap_or(miner_default_config.min_time_between_blocks_ms),
            empty_mempool_sleep_time: self.empty_mempool_sleep_ms.map(Duration::from_millis).unwrap_or(miner_default_config.empty_mempool_sleep_time),
            first_rejection_pause_ms: self.first_rejection_pause_ms.unwrap_or(miner_default_config.first_rejection_pause_ms),
            subsequent_rejection_pause_ms: self.subsequent_rejection_pause_ms.unwrap_or(miner_default_config.subsequent_rejection_pause_ms),
            block_commit_delay: self.block_commit_delay_ms.map(Duration::from_millis).unwrap_or(miner_default_config.block_commit_delay),
            tenure_cost_limit_per_block_percentage,
            contract_cost_limit_percentage,
            tenure_extend_poll_timeout: self.tenure_extend_poll_secs.map(Duration::from_secs).unwrap_or(miner_default_config.tenure_extend_poll_timeout),
            tenure_extend_wait_timeout: self.tenure_extend_wait_timeout_ms.map(Duration::from_millis).unwrap_or(miner_default_config.tenure_extend_wait_timeout),
            tenure_timeout: self.tenure_timeout_secs.map(Duration::from_secs).unwrap_or(miner_default_config.tenure_timeout),
            tenure_extend_cost_threshold: self.tenure_extend_cost_threshold.unwrap_or(miner_default_config.tenure_extend_cost_threshold),

            block_rejection_timeout_steps: {
                if let Some(block_rejection_timeout_items) = self.block_rejection_timeout_steps {
                    let mut rejection_timeout_durations = HashMap::<u32, Duration>::new();
                    for (slice, seconds) in block_rejection_timeout_items.iter() {
                        match slice.parse::<u32>() {
                            Ok(slice_slot) => rejection_timeout_durations.insert(slice_slot, Duration::from_secs(*seconds)),
                            Err(e) => panic!("block_rejection_timeout_steps keys must be unsigned integers: {}", e)
                        };
                    }
                    if !rejection_timeout_durations.contains_key(&0) {
                        panic!("block_rejection_timeout_steps requires a definition for the '0' key/step");
                    }
                    rejection_timeout_durations
                } else{
                    miner_default_config.block_rejection_timeout_steps
                }
            },

            max_execution_time_secs: self.max_execution_time_secs,
            replay_transactions: self.replay_transactions.unwrap_or_default(),
            stackerdb_timeout: self.stackerdb_timeout_secs.map(Duration::from_secs).unwrap_or(miner_default_config.stackerdb_timeout),
            max_tenure_bytes: self.max_tenure_bytes.unwrap_or(miner_default_config.max_tenure_bytes),
            log_skipped_transactions: false
        })
    }
}

#[derive(Clone, Deserialize, Default, Debug)]
#[serde(deny_unknown_fields)]
pub struct AtlasConfigFile {
    pub attachments_max_size: Option<u32>,
    pub max_uninstantiated_attachments: Option<u32>,
    pub uninstantiated_attachments_expire_after: Option<u32>,
    pub unresolved_attachment_instances_expire_after: Option<u32>,
}

impl AtlasConfigFile {
    // Can't inplement `Into` trait because this takes a parameter
    #[allow(clippy::wrong_self_convention)]
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
#[serde(deny_unknown_fields)]
pub struct EventObserverConfigFile {
    /// URL endpoint (hostname and port) where event notifications will be sent via
    /// HTTP POST requests.
    ///
    /// The node will automatically prepend `http://` to this endpoint and append the
    /// specific event path (e.g., `/new_block`, `/new_mempool_tx`). Therefore, this
    /// value should be specified as `hostname:port` (e.g., "localhost:3700").
    ///
    /// This should point to a service capable of receiving and processing Stacks event data.
    /// ---
    /// @default: No default.
    /// @required: true
    /// @notes:
    ///   - **Do NOT include the `http://` scheme in this configuration value.**
    /// @toml_example: |
    ///   endpoint = "localhost:3700"
    pub endpoint: String,
    /// List of event types that this observer is configured to receive.
    ///
    /// Each string in the list specifies an event category or a specific event to
    /// subscribe to. For an observer to receive any notifications, this list must
    /// contain at least one valid key. Providing an invalid string that doesn't match
    /// any of the valid formats below will cause the node to panic on startup when
    /// parsing the configuration.
    ///
    /// All observers, regardless of their `events_keys` configuration, implicitly
    /// receive payloads on the `/attachments/new` endpoint.
    ///
    /// Valid Event Keys:
    /// - `"*"`: Subscribes to a broad set of common events.
    ///   - Events delivered to:
    ///     - `/new_block`: For blocks containing transactions that generate STX, FT,
    ///       NFT, or smart contract events.
    ///     - `/new_microblocks`: For all new microblock streams. Note: Only until epoch 2.5.
    ///     - `/new_mempool_tx`: For new mempool transactions.
    ///     - `/drop_mempool_tx`: For dropped mempool transactions.
    ///     - `/new_burn_block`: For new burnchain blocks.
    ///   - Note: This key does NOT by itself subscribe to `/stackerdb_chunks` or `/proposal_response`.
    ///
    /// - `"stx"`: Subscribes to STX token operation events (transfer, mint, burn, lock).
    ///   - Events delivered to: `/new_block`, `/new_microblocks`.
    ///   - Payload details: The "events" array in the delivered payloads will be
    ///     filtered to include only STX-related events.
    ///
    /// - `"memtx"`: Subscribes to new and dropped mempool transaction events.
    ///   - Events delivered to: `/new_mempool_tx`, `/drop_mempool_tx`.
    ///
    /// - `"burn_blocks"`: Subscribes to new burnchain block events.
    ///   - Events delivered to: `/new_burn_block`.
    ///
    /// - `"microblocks"`: Subscribes to new microblock stream events.
    ///   - Events delivered to: `/new_microblocks`.
    ///   - Payload details:
    ///     - The "transactions" field will contain all transactions from the microblocks.
    ///     - The "events" field will contain STX, FT, NFT, or specific smart contract
    ///       events *only if* this observer is also subscribed to those more specific
    ///       event types (e.g., via `"stx"`, `"*"`, a specific contract event key,
    ///       or a specific asset identifier key).
    ///   - Note: Only until epoch 2.5.
    ///
    /// - `"stackerdb"`: Subscribes to StackerDB chunk update events.
    ///   - Events delivered to: `/stackerdb_chunks`.
    ///
    /// - `"block_proposal"`: Subscribes to block proposal response events (for Nakamoto consensus).
    ///   - Events delivered to: `/proposal_response`.
    ///
    /// - Smart Contract Event: Subscribes to a specific smart contract event.
    ///   - Format: `"{contract_address}.{contract_name}::{event_name}"`
    ///     (e.g., `ST0000000000000000000000000000000000000000.my-contract::my-custom-event`)
    ///   - Events delivered to: `/new_block`, `/new_microblocks`.
    ///   - Payload details: The "events" array in the delivered payloads will be
    ///     filtered for this specific event.
    ///
    /// - Asset Identifier for FT/NFT Events: Subscribes to events (mint, burn,
    ///   transfer) for a specific Fungible Token (FT) or Non-Fungible Token (NFT).
    ///   - Format: `"{contract_address}.{contract_name}.{asset_name}"`
    ///     (e.g., for an FT: `ST0000000000000000000000000000000000000000.contract.token`)
    ///   - Events delivered to: `/new_block`, `/new_microblocks`.
    ///   - Payload details: The "events" array in the delivered payloads will be
    ///     filtered for events related to the specified asset.
    /// ---
    /// @default: No default.
    /// @required: true
    /// @notes:
    ///   - For a more detailed documentation check the event-dispatcher docs in the `/docs` folder.
    /// @toml_example: |
    ///   events_keys = [
    ///     "burn_blocks",
    ///     "memtx",
    ///     "ST0000000000000000000000000000000000000000.my-contract::my-custom-event",
    ///     "ST0000000000000000000000000000000000000000.token-contract.my-ft"
    ///   ]
    pub events_keys: Vec<String>,
    /// Maximum duration (in milliseconds) to wait for the observer endpoint to respond.
    ///
    /// When the node sends an event notification to this observer, it will wait at
    /// most this long for a successful HTTP response (status code 200) before
    /// considering the request timed out. If a timeout occurs and retries are enabled
    /// (see [`EventObserverConfigFile::disable_retries`]), the request will be attempted
    /// again according to the retry strategy.
    /// ---
    /// @default: `1_000`
    /// @units: milliseconds
    pub timeout_ms: Option<u64>,
    /// Controls whether the node should retry sending event notifications if delivery
    /// fails or times out.
    ///
    /// If `false` (default): The node will attempt to deliver event notifications
    ///   persistently. If an attempt fails (due to network error, timeout, or a
    ///   non-200 HTTP response), the event payload is saved and retried indefinitely.
    ///   This ensures that all events will eventually be delivered. However, this can
    ///   cause the node's block processing to stall if an observer is down, or
    ///   indefinitely fails to process the event.
    ///
    /// - If `true`: The node will make only a single attempt to deliver each event
    ///   notification. If this single attempt fails for any reason, the event is
    ///   discarded, and no further retries will be made for that specific event.
    /// ---
    /// @default: `false` (retries are enabled)
    /// @notes:
    ///   - **Warning:** Setting this to `true` can lead to missed events if the
    ///     observer endpoint is temporarily unavailable or experiences issues.
    pub disable_retries: Option<bool>,
}

#[derive(Clone, Default, Debug, Hash, PartialEq, Eq, PartialOrd)]
pub struct EventObserverConfig {
    pub endpoint: String,
    pub events_keys: Vec<EventKeyType>,
    pub timeout_ms: u64,
    pub disable_retries: bool,
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
        if let Ok(comps) = TryInto::<&[_; 1]>::try_into(comps.as_slice()) {
            let split_vec: Vec<_> = comps[0].split('.').collect();
            let Ok(split) = TryInto::<&[_; 3]>::try_into(split_vec.as_slice()) else {
                return None;
            };
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
        } else if let Ok(comps) = TryInto::<&[_; 2]>::try_into(comps.as_slice()) {
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
#[serde(deny_unknown_fields)]
pub struct InitialBalanceFile {
    /// The Stacks address to receive the initial STX balance.
    /// Must be a valid "non-mainnet" Stacks address (e.g., "ST2QKZ4FKHAH1NQKYKYAYZPY440FEPK7GZ1R5HBP2").
    /// ---
    /// @default: No default.
    /// @required: true
    pub address: String,
    /// The amount of microSTX to allocate to the address at node startup.
    /// 1 STX = 1,000,000 microSTX.
    /// ---
    /// @default: No default.
    /// @required: true
    /// @units: microSTX
    pub amount: u64,
}

#[cfg(test)]
mod tests {
    use std::path::Path;

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
                .unwrap(),
                false
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
                .unwrap(),
                false
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
            false,
        )
        .unwrap_err();
        assert_eq!(
            expected_err_prefix,
            &actual_err_msg[..expected_err_prefix.len()]
        );

        assert!(Config::from_config_file(ConfigFile::from_str("").unwrap(), false).is_ok());
    }

    #[test]
    fn test_deny_unknown_fields() {
        {
            let err = ConfigFile::from_str(
                r#"
            [node]
            name = "test"
            unknown_field = "test"
            "#,
            )
            .unwrap_err();
            assert!(err.starts_with("Invalid toml: unknown field `unknown_field`"));
        }

        {
            let err = ConfigFile::from_str(
                r#"
            [burnchain]
            chain_id = 0x00000500
            unknown_field = "test"
            chain = "bitcoin"
            "#,
            )
            .unwrap_err();
            assert!(err.starts_with("Invalid toml: unknown field `unknown_field`"));
        }

        {
            let err = ConfigFile::from_str(
                r#"
            [node]
            rpc_bind = "0.0.0.0:20443"
            unknown_field = "test"
            p2p_bind = "0.0.0.0:20444"
            "#,
            )
            .unwrap_err();
            assert!(err.starts_with("Invalid toml: unknown field `unknown_field`"));
        }

        {
            let err = ConfigFile::from_str(
                r#"
            [[ustx_balance]]
            address = "ST3AM1A56AK2C1XAFJ4115ZSV26EB49BVQ10MGCS0"
            amount = 10000000000000000
            unknown_field = "test"
            "#,
            )
            .unwrap_err();
            assert!(err.starts_with("Invalid toml: unknown field `unknown_field`"));
        }

        {
            let err = ConfigFile::from_str(
                r#"
            [[events_observer]]
            endpoint = "localhost:30000"
            unknown_field = "test"
            events_keys = ["stackerdb", "block_proposal", "burn_blocks"]
            "#,
            )
            .unwrap_err();
            assert!(err.starts_with("Invalid toml: unknown field `unknown_field`"));
        }

        {
            let err = ConfigFile::from_str(
                r#"
            [connection_options]
            inbox_maxlen = 100
            outbox_maxlen = 200
            unknown_field = "test"
            "#,
            )
            .unwrap_err();
            assert!(err.starts_with("Invalid toml: unknown field `unknown_field`"));
        }

        {
            let err = ConfigFile::from_str(
                r#"
            [fee_estimation]
            cost_estimator = "foo"
            unknown_field = "test"
            "#,
            )
            .unwrap_err();
            assert!(err.starts_with("Invalid toml: unknown field `unknown_field`"));
        }

        {
            let err = ConfigFile::from_str(
                r#"
            [miner]
            first_attempt_time_ms = 180_000
            unknown_field = "test"
            subsequent_attempt_time_ms = 360_000
            "#,
            )
            .unwrap_err();
            println!("{err}");
            assert!(err.starts_with("Invalid toml: unknown field `unknown_field`"));
        }

        {
            let err = ConfigFile::from_str(
                r#"
                [atlas]
                attachments_max_size = 100
                unknown_field = "test"
                "#,
            )
            .unwrap_err();
            assert!(err.starts_with("Invalid toml: unknown field `unknown_field`"));
        }
    }

    #[test]
    fn test_example_confs() {
        // For each config file in the ../conf/ directory, we should be able to parse it
        let conf_dir = Path::new(env!("CARGO_MANIFEST_DIR")).join("conf");
        println!("Reading config files from: {conf_dir:?}");
        let conf_files = fs::read_dir(conf_dir).unwrap();

        for entry in conf_files {
            let entry = entry.unwrap();
            let path = entry.path();
            if path.is_file() {
                let file_name = path.file_name().unwrap().to_str().unwrap();
                if file_name.ends_with(".toml") {
                    debug!("Parsing config file: {file_name}");
                    let _config = ConfigFile::from_path(path.to_str().unwrap()).unwrap();
                    debug!("Parsed config file: {file_name}");
                }
            }
        }
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

    #[test]
    fn should_load_auth_token() {
        let config = Config::from_config_file(
            ConfigFile::from_str(
                r#"
                [connection_options]
                auth_token = "password"
                "#,
            )
            .unwrap(),
            false,
        )
        .expect("Expected to be able to parse block proposal token from file");

        assert_eq!(
            config.connection_options.auth_token,
            Some("password".to_string())
        );
    }

    #[test]
    fn test_into_config_default_chain_id() {
        // Helper function to create BurnchainConfigFile with mode and optional chain_id
        fn make_burnchain_config_file(mainnet: bool, chain_id: Option<u32>) -> BurnchainConfigFile {
            let mut config = BurnchainConfigFile::default();
            if mainnet {
                config.mode = Some("mainnet".to_string());
            }
            config.chain_id = chain_id;
            config
        }
        let default_burnchain_config = BurnchainConfig::default();

        // **Case 1a:** Should panic when `is_mainnet` is true and `chain_id` != `CHAIN_ID_MAINNET`
        {
            let config_file = make_burnchain_config_file(true, Some(CHAIN_ID_TESTNET));

            let result = config_file.into_config_default(default_burnchain_config.clone());

            assert!(
                result.is_err(),
                "Expected error when chain_id != CHAIN_ID_MAINNET on mainnet"
            );
        }

        // **Case 1b:** Should not panic when `is_mainnet` is true and `chain_id` == `CHAIN_ID_MAINNET`
        {
            let config_file = make_burnchain_config_file(true, Some(CHAIN_ID_MAINNET));

            let config = config_file
                .into_config_default(default_burnchain_config.clone())
                .expect("Should not panic");
            assert_eq!(config.chain_id, CHAIN_ID_MAINNET);
        }

        // **Case 1c:** Should not panic when `is_mainnet` is false; chain_id should be as provided
        {
            let chain_id = 123456;
            let config_file = make_burnchain_config_file(false, Some(chain_id));

            let config = config_file
                .into_config_default(default_burnchain_config.clone())
                .expect("Should not panic");
            assert_eq!(config.chain_id, chain_id);
        }

        // **Case 2a:** Should not panic when `chain_id` is None and `is_mainnet` is true
        {
            let config_file = make_burnchain_config_file(true, None);

            let config = config_file
                .into_config_default(default_burnchain_config.clone())
                .expect("Should not panic");
            assert_eq!(config.chain_id, CHAIN_ID_MAINNET);
        }

        // **Case 2b:** Should not panic when `chain_id` is None and `is_mainnet` is false
        {
            let config_file = make_burnchain_config_file(false, None);

            let config = config_file
                .into_config_default(default_burnchain_config)
                .expect("Should not panic");
            assert_eq!(config.chain_id, CHAIN_ID_TESTNET);
        }
    }
}
