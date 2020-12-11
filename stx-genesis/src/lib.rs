use std::io::prelude::*;
use std::io::{self, BufReader};

use libflate::deflate;

pub struct GenesisAccountBalance {
    /// A STX or BTC address (BTC addresses should be converted to STX when used).
    pub address: String,
    /// Balance in microSTX.
    pub amount: u64,
}

pub struct GenesisAccountLockup {
    /// A STX or BTC address (BTC addresses should be converted to STX when used).
    pub address: String,
    /// Locked amount in microSTX.
    pub amount: u64,
    /// The number of blocks after the genesis block at which the tokens unlock.
    pub block_height: u64,
}

pub static GENESIS_CHAINSTATE_HASH: &str =
    include_str!(concat!(env!("OUT_DIR"), "/chainstate.txt.sha256"));

pub fn read_balances() -> Box<dyn Iterator<Item = GenesisAccountBalance>> {
    let account_balances_bytes = include_bytes!(concat!(env!("OUT_DIR"), "/account_balances.gz"));
    let cursor = io::Cursor::new(account_balances_bytes);
    let balances_encoder = deflate::Decoder::new(cursor);
    let buff_reader = BufReader::new(balances_encoder);
    let balances = buff_reader.lines().map(|line| line.unwrap()).map(|line| {
        let mut parts = line.split(",");
        let addr = parts.next().unwrap();
        let balance = parts.next().unwrap().parse::<u64>().unwrap();
        GenesisAccountBalance {
            address: addr.to_string(),
            amount: balance,
        }
    });
    return Box::new(balances);
}

pub fn read_lockups() -> Box<dyn Iterator<Item = GenesisAccountLockup>> {
    let account_balances_bytes = include_bytes!(concat!(env!("OUT_DIR"), "/account_lockups.gz"));
    let cursor = io::Cursor::new(account_balances_bytes);
    let balances_encoder = deflate::Decoder::new(cursor);
    let buff_reader = BufReader::new(balances_encoder);
    let balances = buff_reader.lines().map(|line| line.unwrap()).map(|line| {
        let mut parts = line.split(",");
        let addr = parts.next().unwrap();
        let amount = parts.next().unwrap().parse::<u64>().unwrap();
        let block_height = parts.next().unwrap().parse::<u64>().unwrap();
        GenesisAccountLockup {
            address: addr.to_string(),
            amount: amount,
            block_height: block_height,
        }
    });
    return Box::new(balances);
}
