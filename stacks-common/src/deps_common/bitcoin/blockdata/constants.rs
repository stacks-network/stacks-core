// Rust Bitcoin Library
// Written in 2014 by
//     Andrew Poelstra <apoelstra@wpsoftware.net>
//
// To the extent possible under law, the author(s) have dedicated all
// copyright and related and neighboring rights to this software to
// the public domain worldwide. This software is distributed without
// any warranty.
//
// You should have received a copy of the CC0 Public Domain Dedication
// along with this software.
// If not, see <http://creativecommons.org/publicdomain/zero/1.0/>.
//

//! Blockdata constants
//!
//! This module provides various constants relating to the blockchain and
//! consensus code. In particular, it defines the genesis block and its
//! single transaction
//!

use std::default::Default;

use crate::deps_common::bitcoin::blockdata::block::{Block, BlockHeader};
use crate::deps_common::bitcoin::blockdata::opcodes;
use crate::deps_common::bitcoin::blockdata::script;
use crate::deps_common::bitcoin::blockdata::transaction::{OutPoint, Transaction, TxIn, TxOut};
use crate::deps_common::bitcoin::network::constants::Network;
use crate::deps_common::bitcoin::util::hash::MerkleRoot;
use crate::util::hash::hex_bytes;
use crate::util::uint::Uint256;

/// The maximum allowable sequence number
pub static MAX_SEQUENCE: u32 = 0xFFFFFFFF;
/// How many satoshis are in "one bitcoin"
pub static COIN_VALUE: u64 = 100_000_000;
/// How many seconds between blocks we expect on average
pub static TARGET_BLOCK_SPACING: u32 = 600;
/// How many blocks between diffchanges
pub static DIFFCHANGE_INTERVAL: u32 = 2016;
/// How much time on average should occur between diffchanges
pub static DIFFCHANGE_TIMESPAN: u32 = 14 * 24 * 3600;

/// In Bitcoind this is insanely described as ~((u256)0 >> 32)
pub fn max_target(_: Network) -> Uint256 {
    Uint256::from_u64(0xFFFF) << 208
}

/// The maximum value allowed in an output (useful for sanity checking,
/// since keeping everything below this value should prevent overflows
/// if you are doing anything remotely sane with monetary values).
pub fn max_money(_: Network) -> u64 {
    21_000_000 * COIN_VALUE
}

/// Constructs and returns the coinbase (and only) transaction of the Bitcoin genesis block
fn bitcoin_genesis_tx() -> Transaction {
    // Base
    let mut ret = Transaction {
        version: 1,
        lock_time: 0,
        input: vec![],
        output: vec![],
    };

    // Inputs
    let in_script = script::Builder::new()
        .push_scriptint(486604799)
        .push_scriptint(4)
        .push_slice(b"The Times 03/Jan/2009 Chancellor on brink of second bailout for banks")
        .into_script();
    ret.input.push(TxIn {
        previous_output: OutPoint::null(),
        script_sig: in_script,
        sequence: MAX_SEQUENCE,
        witness: vec![],
    });

    // Outputs
    let out_script = script::Builder::new()
        .push_slice(&hex_bytes("04678afdb0fe5548271967f1a67130b7105cd6a828e03909a67962e0ea1f61deb649f6bc3f4cef38c4f35504e51ec112de5c384df7ba0b8d578a4c702b6bf11d5f").unwrap())
        .push_opcode(opcodes::All::OP_CHECKSIG)
        .into_script();
    ret.output.push(TxOut {
        value: 50 * COIN_VALUE,
        script_pubkey: out_script,
    });

    // end
    ret
}

/// Constructs and returns the genesis block
pub fn genesis_block(network: Network) -> Block {
    match network {
        Network::Bitcoin => {
            let txdata = vec![bitcoin_genesis_tx()];
            Block {
                header: BlockHeader {
                    version: 1,
                    prev_blockhash: Default::default(),
                    merkle_root: txdata.merkle_root(),
                    time: 1231006505,
                    bits: 0x1d00ffff,
                    nonce: 2083236893,
                },
                txdata: txdata,
            }
        }
        Network::Testnet => {
            let txdata = vec![bitcoin_genesis_tx()];
            Block {
                header: BlockHeader {
                    version: 1,
                    prev_blockhash: Default::default(),
                    merkle_root: txdata.merkle_root(),
                    time: 1296688602,
                    bits: 0x1d00ffff,
                    nonce: 414098458,
                },
                txdata: txdata,
            }
        }
        Network::Regtest => {
            let txdata = vec![bitcoin_genesis_tx()];
            Block {
                header: BlockHeader {
                    version: 1,
                    prev_blockhash: Default::default(),
                    merkle_root: txdata.merkle_root(),
                    time: 1296688602,
                    bits: 0x207fffff,
                    nonce: 2,
                },
                txdata: txdata,
            }
        }
    }
}

#[cfg(test)]
mod test {
    use crate::util::hash::hex_bytes as hex_decode;
    use std::default::Default;

    use crate::deps_common::bitcoin::blockdata::constants::{bitcoin_genesis_tx, genesis_block};
    use crate::deps_common::bitcoin::blockdata::constants::{COIN_VALUE, MAX_SEQUENCE};
    use crate::deps_common::bitcoin::network::constants::Network;
    use crate::deps_common::bitcoin::network::serialize::{serialize, BitcoinHash};

    #[test]
    fn bitcoin_genesis_first_transaction() {
        let gen = bitcoin_genesis_tx();

        assert_eq!(gen.version, 1);
        assert_eq!(gen.input.len(), 1);
        assert_eq!(gen.input[0].previous_output.txid, Default::default());
        assert_eq!(gen.input[0].previous_output.vout, 0xFFFFFFFF);
        assert_eq!(serialize(&gen.input[0].script_sig).ok(),
                   Some(hex_decode("4d04ffff001d0104455468652054696d65732030332f4a616e2f32303039204368616e63656c6c6f72206f6e206272696e6b206f66207365636f6e64206261696c6f757420666f722062616e6b73").unwrap()));

        assert_eq!(gen.input[0].sequence, MAX_SEQUENCE);
        assert_eq!(gen.output.len(), 1);
        assert_eq!(serialize(&gen.output[0].script_pubkey).ok(),
                   Some(hex_decode("434104678afdb0fe5548271967f1a67130b7105cd6a828e03909a67962e0ea1f61deb649f6bc3f4cef38c4f35504e51ec112de5c384df7ba0b8d578a4c702b6bf11d5fac").unwrap()));
        assert_eq!(gen.output[0].value, 50 * COIN_VALUE);
        assert_eq!(gen.lock_time, 0);

        assert_eq!(
            gen.bitcoin_hash().be_hex_string(),
            "4a5e1e4baab89f3a32518a88c31bc87f618f76673e2cc77ab2127b7afdeda33b".to_string()
        );
    }

    #[test]
    fn bitcoin_genesis_full_block() {
        let gen = genesis_block(Network::Bitcoin);

        assert_eq!(gen.header.version, 1);
        assert_eq!(gen.header.prev_blockhash, Default::default());
        assert_eq!(
            gen.header.merkle_root.be_hex_string(),
            "4a5e1e4baab89f3a32518a88c31bc87f618f76673e2cc77ab2127b7afdeda33b".to_string()
        );
        assert_eq!(gen.header.time, 1231006505);
        assert_eq!(gen.header.bits, 0x1d00ffff);
        assert_eq!(gen.header.nonce, 2083236893);
        assert_eq!(
            gen.header.bitcoin_hash().be_hex_string(),
            "000000000019d6689c085ae165831e934ff763ae46a2a6c172b3f1b60a8ce26f".to_string()
        );
    }

    #[test]
    fn testnet_genesis_full_block() {
        let gen = genesis_block(Network::Testnet);
        assert_eq!(gen.header.version, 1);
        assert_eq!(gen.header.prev_blockhash, Default::default());
        assert_eq!(
            gen.header.merkle_root.be_hex_string(),
            "4a5e1e4baab89f3a32518a88c31bc87f618f76673e2cc77ab2127b7afdeda33b".to_string()
        );
        assert_eq!(gen.header.time, 1296688602);
        assert_eq!(gen.header.bits, 0x1d00ffff);
        assert_eq!(gen.header.nonce, 414098458);
        assert_eq!(
            gen.header.bitcoin_hash().be_hex_string(),
            "000000000933ea01ad0ee984209779baaec3ced90fa3f408719526f8d77f4943".to_string()
        );
    }
}
