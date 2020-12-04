use std::fs::File;
use std::io::prelude::*;
use std::io::LineWriter;
use std::io::Write;
use std::{
    convert::TryFrom,
    io::{self, BufReader, Cursor},
    time::SystemTime,
};

use libflate::deflate;

use stacks::{
    burnchains::{bitcoin::address::BitcoinAddress, Address},
    chainstate::stacks::db::{AccountBalance, VestingSchedule},
    chainstate::stacks::StacksAddress,
    util::hash::Sha256Sum,
    vm::types::StandardPrincipalData,
};

pub fn read_balances() -> Box<dyn Iterator<Item = AccountBalance>> {
    let account_balances_bytes = include_bytes!(concat!(env!("OUT_DIR"), "/account_balances.gz"));
    let cursor = io::Cursor::new(account_balances_bytes);
    let balances_encoder = deflate::Decoder::new(cursor);
    let buff_reader = BufReader::new(balances_encoder);
    let balances = buff_reader.lines().map(|line| line.unwrap()).map(|line| {
        let mut parts = line.split(",");
        let addr = parts.next().unwrap();
        let stx_address = parse_genesis_address(&addr).expect(&format!(
            "Failed to parsed genesis balance address {}",
            addr
        ));
        let balance = parts.next().unwrap().parse::<u64>().unwrap();
        AccountBalance {
            address: stx_address,
            amount: balance,
        }
    });
    return Box::new(balances);
}

pub fn read_vesting() -> Box<dyn Iterator<Item = VestingSchedule>> {
    let account_balances_bytes = include_bytes!(concat!(env!("OUT_DIR"), "/account_vesting.gz"));
    let cursor = io::Cursor::new(account_balances_bytes);
    let balances_encoder = deflate::Decoder::new(cursor);
    let buff_reader = BufReader::new(balances_encoder);
    let balances = buff_reader.lines().map(|line| line.unwrap()).map(|line| {
        let mut parts = line.split(",");
        let addr = parts.next().unwrap();
        let stx_address = parse_genesis_address(&addr).expect(&format!(
            "Failed to parsed genesis vesting address {}",
            addr
        ));
        let amount = parts.next().unwrap().parse::<u64>().unwrap();
        let block_height = parts.next().unwrap().parse::<u64>().unwrap();
        VestingSchedule {
            address: stx_address,
            amount: amount,
            block_height: block_height,
        }
    });
    return Box::new(balances);
}

fn parse_genesis_address(addr: &str) -> Option<StacksAddress> {
    // Typical entries are b58 bitcoin addresses that need converted to c32
    match BitcoinAddress::from_b58(&addr) {
        Ok(addr) => return Some(StacksAddress::from_bitcoin_address(&addr)),
        _ => {}
    };
    // A few addresses (from legacy placeholder accounts) are already c32
    match StacksAddress::from_string(addr) {
        Some(addr) => return Some(addr),
        None => return None,
    };
}
