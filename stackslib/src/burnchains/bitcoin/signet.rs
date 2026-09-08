// Copyright (C) 2026 Stacks Open Internet Foundation
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

//! BIP 325 parameters shared by public and custom signets.

use stacks_common::deps_common::bitcoin::blockdata::block::Block;
use stacks_common::deps_common::bitcoin::blockdata::constants::genesis_block;
use stacks_common::deps_common::bitcoin::network::constants::Network;
use stacks_common::deps_common::bitcoin::network::serialize;
use stacks_common::deps_common::bitcoin::util::hash::Sha256dHash;
use stacks_common::util::hash::hex_bytes;

use crate::core::{EpochList, STACKS_EPOCHS_REGTEST, STACKS_EPOCH_MAX};

/// Bitcoin Core's default public signet challenge, as hexadecimal script bytes.
pub const DEFAULT_CHALLENGE: &str = "512103ad5e0edad18cb1f0fc0d28a3d4f1f3e445640337489abb10404f2d1e086be430210359ef5021964fe22d6f8e05b2463c9540ce96883fe3b278760f048f5189f2e6c452ae";
/// Genesis hash shared by all signets.
pub const GENESIS_HASH: &str = "00000008819873e925422c1ff0f99f7cc9bbb232af63a077a480a3633bee1ef6";
/// Unix timestamp of the signet genesis block.
pub const GENESIS_TIMESTAMP: u32 = 1598918400;
/// Compact encoding of the signet proof-of-work limit.
pub const POW_LIMIT_BITS: u32 = 0x1e0377ae;
/// Default Bitcoin Core signet P2P port.
pub const P2P_PORT: u16 = 38333;
/// Default Bitcoin Core signet RPC port.
pub const RPC_PORT: u16 = 38332;

/// Decode a nonempty challenge script, bounded by Bitcoin's maximum script size.
pub fn parse_challenge(challenge: &str) -> Result<Vec<u8>, String> {
    if challenge.is_empty() || challenge.len() > 20_000 {
        return Err("signet_challenge must contain 1 to 10000 bytes of hexadecimal script".into());
    }
    hex_bytes(challenge).map_err(|e| format!("Invalid signet_challenge: {e}"))
}

/// Decode the fixed public signet challenge.
pub fn default_challenge() -> Vec<u8> {
    parse_challenge(DEFAULT_CHALLENGE).expect("Valid public signet challenge")
}

/// Hash the CompactSize-prefixed challenge, matching Bitcoin Core's HashWriter.
pub fn challenge_hash(challenge: &[u8]) -> Sha256dHash {
    let serialized = serialize::serialize(&challenge.to_vec())
        .expect("Serializing a bounded script to memory cannot fail");
    Sha256dHash::from_data(&serialized)
}

/// Return the network magic as the little-endian integer used by the wire codec.
pub fn network_magic(challenge: &[u8]) -> u32 {
    let hash = challenge_hash(challenge);
    u32::from_le_bytes([hash.0[0], hash.0[1], hash.0[2], hash.0[3]])
}

/// Construct the BIP 325 genesis block using Bitcoin's shared genesis transaction.
pub fn genesis() -> Block {
    let mut block = genesis_block(Network::Bitcoin);
    block.header.time = GENESIS_TIMESTAMP;
    block.header.bits = POW_LIMIT_BITS;
    block.header.nonce = 52613770;
    block
}

/// Development epoch schedule for a fresh signet-backed Stacks chain.
/// Operators launching at a later burn height must agree on an explicit schedule.
pub fn default_epochs() -> EpochList {
    let mut epochs = (*STACKS_EPOCHS_REGTEST).clone();
    // Leave time for coinbase maturity, legacy mining, and PoX-4 registration.
    // Epoch 4.0 starts outside the prepare phase; Epoch 4.1 remains inactive.
    let starts = [
        0,
        0,
        1,
        2,
        3,
        4,
        5,
        201,
        231,
        241,
        251,
        252,
        253,
        262,
        STACKS_EPOCH_MAX,
    ];
    assert_eq!(
        epochs.len(),
        starts.len(),
        "Update the signet development epoch schedule"
    );
    for (i, epoch) in epochs.iter_mut().enumerate() {
        epoch.start_height = starts[i];
        if let Some(next) = starts.get(i + 1) {
            epoch.end_height = *next;
        }
    }
    epochs
}

#[cfg(test)]
mod tests {
    use std::{env, fs};

    use stacks_common::deps_common::bitcoin::network::message::NetworkMessage;
    use stacks_common::deps_common::bitcoin::network::serialize::BitcoinHash;
    use tempfile::tempdir;

    use super::*;
    use crate::burnchains::bitcoin::address::BitcoinAddress;
    use crate::burnchains::bitcoin::indexer::{
        BitcoinIndexer, BitcoinIndexerConfig, BitcoinIndexerRuntime, BITCOIN_SIGNET,
    };
    use crate::burnchains::bitcoin::messages::BitcoinMessageHandler;
    use crate::burnchains::bitcoin::spv::SpvClient;
    use crate::burnchains::bitcoin::{BitcoinNetworkType, Error as BitcoinError};
    use crate::burnchains::indexer::BurnchainIndexer;
    use crate::burnchains::BITCOIN_NETWORK_ID_MAINNET;
    use crate::chainstate::burn::db::sortdb::SortitionDB;
    use crate::config::{Config, ConfigFile};
    use crate::core::StacksEpochId;
    use crate::util_lib::db::Error as DBError;

    /// Check public and custom message magic against Bitcoin Core and BIP 325 vectors.
    #[test]
    fn signet_network_magic_vectors() {
        assert_eq!(network_magic(&default_challenge()), BITCOIN_SIGNET);
        let challenge = parse_challenge(
            "512103ad5e0edad18cb1f0fc0d28a3d4f1f3e445640337489abb10404f2d1e086be43051ae",
        )
        .unwrap();
        assert_eq!(
            network_magic(&challenge).to_le_bytes(),
            [0x7e, 0xc6, 0x53, 0xa5]
        );
        assert_eq!(
            network_magic(&[0x51]).to_le_bytes(),
            [0x54, 0xd2, 0x6f, 0xbd]
        );
        // Core serializes vectors with CompactSize, including scripts >= 253 bytes.
        let long = vec![0x51; 253];
        let mut encoded = vec![0xfd, 0xfd, 0x00];
        encoded.extend_from_slice(&long);
        assert_eq!(challenge_hash(&long), Sha256dHash::from_data(&encoded));
    }

    /// Reject malformed scripts before starting network I/O.
    #[test]
    fn signet_challenge_validation() {
        for invalid in ["", "0", "zz", " 51", "0x51"] {
            assert!(parse_challenge(invalid).is_err(), "{invalid}");
        }
        assert!(parse_challenge(&"51".repeat(10000)).is_ok());
        assert!(parse_challenge(&"51".repeat(10001)).is_err());
    }

    /// Verify the complete genesis header hash and its PoW target.
    #[test]
    fn signet_genesis_vector() {
        let header = genesis().header;
        assert_eq!(
            header.bitcoin_hash(),
            Sha256dHash::from_hex(GENESIS_HASH).unwrap()
        );
        assert!(header.bitcoin_hash().into_le() <= header.target());
    }

    /// Signet uses testnet address encodings for legacy, SegWit, and Taproot outputs.
    #[test]
    fn signet_address_encodings() {
        let scripts = [
            format!("76a914{}88ac", "11".repeat(20)),
            format!("a914{}87", "11".repeat(20)),
            format!("0014{}", "11".repeat(20)),
            format!("0020{}", "11".repeat(32)),
            format!("5120{}", "11".repeat(32)),
        ];
        for script in scripts {
            let bytes = hex_bytes(&script).unwrap();
            let signet =
                BitcoinAddress::from_scriptpubkey(BitcoinNetworkType::Signet, &bytes).unwrap();
            let testnet =
                BitcoinAddress::from_scriptpubkey(BitcoinNetworkType::Testnet, &bytes).unwrap();
            let mainnet =
                BitcoinAddress::from_scriptpubkey(BitcoinNetworkType::Mainnet, &bytes).unwrap();
            assert_eq!(signet.to_string(), testnet.to_string());
            assert_ne!(signet.to_string(), mainnet.to_string());
        }
    }

    /// Parse a follower config without resolving any external bootstrap peers.
    fn config(extra: &str) -> Config {
        let contents = format!("[node]\nworking_dir = '/tmp/stacks-signet-config-test'\n[burnchain]\nmode = 'signet'\n{extra}");
        Config::from_config_file(ConfigFile::from_str(&contents).unwrap(), false).unwrap()
    }

    /// Defaults, epoch configuration, and every chain database must agree on network identity.
    #[test]
    fn signet_config_defaults_and_isolation() {
        let public = config("");
        assert_eq!(
            public.burnchain.get_bitcoin_network().1,
            BitcoinNetworkType::Signet
        );
        assert_eq!(public.burnchain.peer_host, "127.0.0.1");
        assert_eq!(public.burnchain.peer_port, P2P_PORT);
        assert_eq!(public.burnchain.rpc_port, RPC_PORT);
        assert_eq!(public.burnchain.magic_bytes.as_bytes(), b"S2");
        assert!(!public.is_mainnet());
        let burnchain = public.get_burnchain();
        assert_eq!(burnchain.pox_constants.reward_cycle_length, 20);
        assert_eq!(burnchain.pox_constants.prepare_length, 5);
        assert!(
            burnchain.pox_constants.anchor_threshold > burnchain.pox_constants.prepare_length / 2
        );
        let epochs = public.burnchain.get_epoch_list();
        assert_eq!(
            epochs.get(StacksEpochId::Epoch30).unwrap().start_height,
            231
        );
        assert_eq!(
            epochs.get(StacksEpochId::Epoch40).unwrap().start_height,
            262
        );
        assert_eq!(
            epochs.get(StacksEpochId::Epoch40).unwrap().end_height,
            STACKS_EPOCH_MAX
        );
        assert_eq!(
            epochs.get(StacksEpochId::Epoch41).unwrap().start_height,
            STACKS_EPOCH_MAX
        );
        assert_eq!(burnchain.first_block_hash.to_hex(), GENESIS_HASH);
        Config::assert_valid_epoch_settings(&burnchain, &public.burnchain.get_epoch_list());
        let explicit_public = config(&format!("signet_challenge = '{DEFAULT_CHALLENGE}'"));
        assert_eq!(
            public.get_chainstate_path(),
            explicit_public.get_chainstate_path()
        );
        let custom = config(
            "signet_challenge = '51'\npeer_port = 39333\nrpc_port = 39332\nmagic_bytes = 'Q2'",
        );
        assert_eq!(custom.burnchain.peer_port, 39333);
        assert_eq!(custom.burnchain.rpc_port, 39332);
        for (public_path, custom_path) in [
            (
                public.get_chainstate_path_str(),
                custom.get_chainstate_path_str(),
            ),
            (public.get_burn_db_path(), custom.get_burn_db_path()),
            (
                public.get_spv_headers_file_path(),
                custom.get_spv_headers_file_path(),
            ),
            (
                public.get_peer_db_file_path(),
                custom.get_peer_db_file_path(),
            ),
            (
                public.get_atlas_db_file_path(),
                custom.get_atlas_db_file_path(),
            ),
            (
                public.get_stacker_db_file_path(),
                custom.get_stacker_db_file_path(),
            ),
        ] {
            assert_ne!(public_path, custom_path);
        }
    }

    /// Queued observer events survive switching away and back without crossing challenges.
    #[test]
    fn signet_event_queue_directory_isolation() {
        let dir = tempdir().unwrap();
        let mut public = config("");
        public.node.working_dir = dir.path().to_str().unwrap().to_owned();
        let mut custom = public.clone();
        custom.burnchain.signet_challenge = Some(vec![0x51]);
        let public_path = public
            .get_event_observer_dir()
            .join("event_observers.sqlite");
        fs::write(&public_path, b"public pending events").unwrap();
        let custom_path = custom
            .get_event_observer_dir()
            .join("event_observers.sqlite");
        assert_ne!(public_path, custom_path);
        assert!(!custom_path.exists());
        fs::write(&custom_path, b"private pending events").unwrap();
        assert_eq!(fs::read(&public_path).unwrap(), b"public pending events");
        public.burnchain.signet_challenge = Some(default_challenge());
        assert_eq!(
            public
                .get_event_observer_dir()
                .join("event_observers.sqlite"),
            public_path
        );
        public.burnchain.mode = "neon".into();
        public.burnchain.signet_challenge = None;
        assert_eq!(public.get_event_observer_dir(), dir.path());
    }

    /// Keep the shipped follower template parseable with the runtime configuration schema.
    #[test]
    fn signet_sample_config() {
        let file = ConfigFile::from_str(include_str!(
            "../../../../sample/conf/signet-follower-conf.toml"
        ))
        .unwrap();
        let parsed = Config::from_config_file(file, false).unwrap();
        assert_eq!(
            parsed.burnchain.get_bitcoin_network().1,
            BitcoinNetworkType::Signet
        );
        assert_eq!(parsed.burnchain.peer_port, P2P_PORT);
    }

    /// A signet-only setting must not silently alter another network.
    #[test]
    fn signet_config_rejects_other_modes() {
        for mode in ["mainnet", "xenon", "neon", "mocknet"] {
            let text = format!("[burnchain]\nmode = '{mode}'\nsignet_challenge = '51'");
            assert!(Config::from_config_file(ConfigFile::from_str(&text).unwrap(), false).is_err());
        }
    }

    /// A fresh signet's stable view stays at genesis until seven confirmations exist.
    #[test]
    fn signet_fresh_chain_stable_view() {
        let dir = tempdir().unwrap();
        let conf = config("signet_challenge = '51'");
        let mut burnchain = conf.get_burnchain();
        let db = SortitionDB::connect(
            dir.path().join("sortition").to_str().unwrap(),
            burnchain.first_block_height,
            &burnchain.first_block_hash,
            u64::from(burnchain.first_block_timestamp),
            &conf.burnchain.get_epoch_list(),
            burnchain.pox_constants.clone(),
            None,
            true,
            None,
        )
        .unwrap();
        let tip = SortitionDB::get_canonical_burn_chain_tip(db.conn()).unwrap();
        let view = SortitionDB::get_burnchain_view(&db.index_conn(), &burnchain, &tip).unwrap();
        assert_eq!(view.burn_block_height, 0);
        assert_eq!(view.burn_stable_block_height, 0);
        assert_eq!(view.burn_stable_block_hash, burnchain.first_block_hash);
        assert_eq!(burnchain.stable_confirmations, 7);
        burnchain.network_id = BITCOIN_NETWORK_ID_MAINNET;
        std::assert_matches!(
            SortitionDB::get_burnchain_view(&db.index_conn(), &burnchain, &tip),
            Err(DBError::Corruption)
        );
    }

    /// A Core peer still syncing must leave an empty local chain retryable.
    #[test]
    fn signet_initial_sync_waits_for_core() {
        let dir = tempdir().unwrap();
        let path = dir
            .path()
            .join("headers.sqlite")
            .to_str()
            .unwrap()
            .to_owned();
        let mut client =
            SpvClient::new(&path, 0, Some(1), BitcoinNetworkType::Signet, true, false).unwrap();
        let mut indexer = BitcoinIndexer::new(
            BitcoinIndexerConfig::default_regtest(path),
            BitcoinIndexerRuntime::new(BitcoinNetworkType::Signet, 30),
            None,
        );
        std::assert_matches!(
            client.handle_message(&mut indexer, NetworkMessage::Headers(vec![])),
            Err(BitcoinError::TimedOut)
        );
        assert_eq!(client.get_highest_header_height().unwrap(), 0);
    }

    /// Exercise real P2P handshake, header validation, persistence, and restart against Core.
    /// Set STACKS_SIGNET_PORT, STACKS_SIGNET_HEIGHT, and optional STACKS_SIGNET_CHALLENGE.
    #[test]
    #[ignore = "requires an explicitly configured local, fully validating Bitcoin Core signet"]
    fn signet_live_header_sync() {
        let dir = tempdir().unwrap();
        let path = dir
            .path()
            .join("headers.sqlite")
            .to_str()
            .unwrap()
            .to_owned();
        let height = env::var("STACKS_SIGNET_HEIGHT")
            .expect("Set STACKS_SIGNET_HEIGHT")
            .parse::<u64>()
            .unwrap();
        assert!(height > 0);
        let mut config = BitcoinIndexerConfig::default_regtest(path.clone());
        config.peer_host = "127.0.0.1".into();
        config.peer_port = env::var("STACKS_SIGNET_PORT")
            .expect("Set STACKS_SIGNET_PORT")
            .parse()
            .unwrap();
        config.signet_challenge = env::var("STACKS_SIGNET_CHALLENGE")
            .ok()
            .map(|s| parse_challenge(&s).unwrap());
        config.socket_timeout = 10;
        config.timeout = 30;
        let mut indexer = BitcoinIndexer::new(
            config.clone(),
            BitcoinIndexerRuntime::new(BitcoinNetworkType::Signet, 30),
            None,
        );
        assert_eq!(indexer.dup().network_magic(), indexer.network_magic());
        assert!(indexer.sync_headers(0, Some(height)).unwrap() >= height);
        drop(indexer);
        let client =
            SpvClient::new(&path, 0, None, BitcoinNetworkType::Signet, false, false).unwrap();
        assert_eq!(
            client
                .read_block_header(0)
                .unwrap()
                .unwrap()
                .header
                .bitcoin_hash(),
            Sha256dHash::from_hex(GENESIS_HASH).unwrap()
        );
        let tip = client.read_block_header(height).unwrap().unwrap().header;
        if let Ok(expected_hash) = env::var("STACKS_SIGNET_TIP_HASH") {
            assert_eq!(
                tip.bitcoin_hash(),
                Sha256dHash::from_hex(&expected_hash).unwrap()
            );
        }
        drop(client);
        let mut restarted = BitcoinIndexer::new(
            config,
            BitcoinIndexerRuntime::new(BitcoinNetworkType::Signet, 30),
            None,
        );
        assert!(
            restarted
                .sync_headers(height.saturating_sub(1), Some(height))
                .unwrap()
                >= height
        );
        let reopened =
            SpvClient::new(&path, 0, None, BitcoinNetworkType::Signet, false, false).unwrap();
        assert_eq!(
            reopened.read_block_header(height).unwrap().unwrap().header,
            tip
        );
    }
}
