#![no_main]

use blockstack_lib::burnchains::bitcoin::blocks::BitcoinBlockParser;
use blockstack_lib::burnchains::bitcoin::BitcoinNetworkType;
use blockstack_lib::burnchains::MagicBytes;
use blockstack_lib::core::StacksEpochId;
use libfuzzer_sys::fuzz_target;
use stacks_common::deps_common::bitcoin::blockdata::transaction::Transaction;
use stacks_common::deps_common::bitcoin::network::serialize::deserialize;

const MIN_DATA_LENGTH: usize = 8;
const BLOCK_HEIGHT: usize = 0;

fuzz_target!(|data: &[u8]| {
    if data.is_empty() || data.len() < MIN_DATA_LENGTH {
        return;
    }

    let tx = match deserialize::<Transaction>(&data) {
        Ok(tx) => tx,
        Err(_) => return,
    };

    if !is_valid_transaction(&tx) {
        return;
    }

    let parser = create_bitcoin_parser();
    let _ = parser.parse_tx(&tx, BLOCK_HEIGHT, StacksEpochId::Epoch31);
});

fn is_valid_transaction(tx: &Transaction) -> bool {
    !tx.output.is_empty()
}

fn create_bitcoin_parser() -> BitcoinBlockParser {
    let magic_bytes = MagicBytes::default();
    BitcoinBlockParser::new(BitcoinNetworkType::Mainnet, magic_bytes)
}
