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
        return Err("challenge must contain 1 to 10000 bytes of hexadecimal script".into());
    }
    hex_bytes(challenge).map_err(|e| format!("invalid hexadecimal script: {e}"))
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
    for (i, (epoch, start)) in epochs.iter_mut().zip(starts).enumerate() {
        epoch.start_height = start;
        if let Some(next) = starts.get(i + 1) {
            epoch.end_height = *next;
        }
    }
    epochs
}

#[cfg(test)]
mod tests {
    use std::env;

    use stacks_common::deps_common::bitcoin::network::serialize::BitcoinHash;
    use tempfile::tempdir;

    use super::*;
    use crate::burnchains::bitcoin::address::BitcoinAddress;
    use crate::burnchains::bitcoin::indexer::{
        BitcoinIndexer, BitcoinIndexerConfig, BitcoinIndexerRuntime, BITCOIN_SIGNET,
    };
    use crate::burnchains::bitcoin::spv::SpvClient;
    use crate::burnchains::bitcoin::BitcoinNetworkType;
    use crate::burnchains::indexer::BurnchainIndexer;
    use crate::burnchains::{Burnchain, BITCOIN_NETWORK_ID_MAINNET};
    use crate::chainstate::burn::db::sortdb::SortitionDB;
    use crate::config::DEFAULT_SIGNET_CHALLENGE;
    use crate::util_lib::db::Error as DBError;

    /// Check public and custom message magic against Bitcoin Core and BIP 325 vectors.
    #[test]
    fn signet_network_magic_vectors() {
        assert_eq!(
            network_magic(&parse_challenge(DEFAULT_SIGNET_CHALLENGE).unwrap()),
            BITCOIN_SIGNET
        );
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

    /// The indexer and its duplicate use the configured public or custom challenge.
    #[test]
    fn signet_indexer_uses_configured_challenge() {
        for (challenge, expected_magic) in [
            (None, BITCOIN_SIGNET),
            (
                Some(parse_challenge(DEFAULT_SIGNET_CHALLENGE).unwrap()),
                BITCOIN_SIGNET,
            ),
            (Some(vec![0x51]), 0xbd6fd254),
        ] {
            let mut indexer_config = BitcoinIndexerConfig::default_signet(String::new());
            if let Some(challenge) = challenge {
                indexer_config.signet_challenge = Some(challenge);
            }
            assert!(indexer_config.signet_challenge.is_some());
            let indexer = BitcoinIndexer::new(
                indexer_config,
                BitcoinIndexerRuntime::new(BitcoinNetworkType::Signet, 30),
                None,
            );
            assert_eq!(indexer.network_magic(), expected_magic);
            assert_eq!(indexer.dup().network_magic(), expected_magic);
        }
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

    /// A fresh signet's stable view stays at genesis until seven confirmations exist.
    #[test]
    fn signet_fresh_chain_stable_view() {
        let dir = tempdir().unwrap();
        let mut burnchain =
            Burnchain::new(dir.path().to_str().unwrap(), "bitcoin", "signet", None).unwrap();
        let db = SortitionDB::connect(
            dir.path().join("sortition").to_str().unwrap(),
            burnchain.first_block_height,
            &burnchain.first_block_hash,
            u64::from(burnchain.first_block_timestamp),
            &default_epochs(),
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
        let mut config = BitcoinIndexerConfig::default_signet(path.clone());
        config.peer_port = env::var("STACKS_SIGNET_PORT")
            .expect("Set STACKS_SIGNET_PORT")
            .parse()
            .unwrap();
        if let Ok(challenge) = env::var("STACKS_SIGNET_CHALLENGE") {
            config.signet_challenge = Some(parse_challenge(&challenge).unwrap());
        }
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
