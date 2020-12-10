use std::io::prelude::*;
use std::io::{self, BufReader};

use libflate::deflate;

pub struct GenesisAccountBalance {
    /// A STX or BTC address (BTC addresses should be converted to STX when used).
    pub address: String,
    /// Balance in microSTX.
    pub amount: u64,
}

pub struct GenesisAccountVesting {
    /// A STX or BTC address (BTC addresses should be converted to STX when used).
    pub address: String,
    /// Vesting amount in microSTX.
    pub amount: u64,
    /// The number of blocks after the genesis block at which the tokens unlock.
    pub block_height: u64,
}

pub struct GenesisNamespace {
    pub namespace_id: String,
    pub address: String,
    pub reveal_block: i64,
    pub ready_block: i64,
    pub buckets: String,
    pub base: String,
    pub coeff: String,
    pub nonalpha_discount: String,
    pub no_vowel_discount: String,
    pub lifetime: String,
}

pub struct GenesisName {
    pub name: String,
    pub address: String,
    pub registered_at: i64,
    pub expire_block: i64,
    pub zonefile_hash: String,
}

pub static GENESIS_CHAINSTATE_HASH: &str =
    include_str!(concat!(env!("OUT_DIR"), "/chainstate.txt.sha256"));

fn iter_deflated_csv(deflate_bytes: &'static [u8]) -> Box<dyn Iterator<Item = Vec<String>>> {
    let cursor = io::Cursor::new(deflate_bytes);
    let deflate_decoder = deflate::Decoder::new(cursor);
    let buff_reader = BufReader::new(deflate_decoder);
    let line_iter = buff_reader
        .lines()
        .map(|line| line.unwrap())
        .map(|line| line.split(",").map(String::from).collect());
    return Box::new(line_iter);
}

pub fn read_balances() -> Box<dyn Iterator<Item = GenesisAccountBalance>> {
    let account_balances_bytes = include_bytes!(concat!(env!("OUT_DIR"), "/account_balances.gz"));
    let balances = iter_deflated_csv(account_balances_bytes).map(|cols| GenesisAccountBalance {
        address: cols[0].to_string(),
        amount: cols[1].parse::<u64>().unwrap(),
    });
    return Box::new(balances);
}

pub fn read_vesting() -> Box<dyn Iterator<Item = GenesisAccountVesting>> {
    let account_balances_bytes = include_bytes!(concat!(env!("OUT_DIR"), "/account_vesting.gz"));
    let vesting = iter_deflated_csv(account_balances_bytes).map(|cols| GenesisAccountVesting {
        address: cols[0].to_string(),
        amount: cols[1].parse::<u64>().unwrap(),
        block_height: cols[2].parse::<u64>().unwrap(),
    });
    return Box::new(vesting);
}

pub fn read_namespaces() -> Box<dyn Iterator<Item = GenesisNamespace>> {
    let namespaces_bytes = include_bytes!(concat!(env!("OUT_DIR"), "/namespaces.gz"));
    let namespaces = iter_deflated_csv(namespaces_bytes).map(|cols| GenesisNamespace {
        namespace_id: cols[0].to_string(),
        address: cols[1].to_string(),
        reveal_block: cols[2].parse::<i64>().unwrap(),
        ready_block: cols[3].parse::<i64>().unwrap(),
        buckets: cols[4].to_string(),
        base: cols[5].to_string(),
        coeff: cols[6].to_string(),
        nonalpha_discount: cols[7].to_string(),
        no_vowel_discount: cols[8].to_string(),
        lifetime: cols[9].to_string(),
    });
    return Box::new(namespaces);
}

pub fn read_names() -> Box<dyn Iterator<Item = GenesisName>> {
    let names_bytes = include_bytes!(concat!(env!("OUT_DIR"), "/names.gz"));
    let names = iter_deflated_csv(names_bytes).map(|cols| GenesisName {
        name: cols[0].to_string(),
        address: cols[1].to_string(),
        registered_at: cols[2].parse::<i64>().unwrap(),
        expire_block: cols[3].parse::<i64>().unwrap(),
        zonefile_hash: cols[4].to_string(),
    });
    return Box::new(names);
}

#[cfg(test)]
mod tests {
    use super::*;

    // Test the decompression and line parsing

    #[test]
    fn test_balances_read() {
        for balance in read_balances() {
            assert!(balance.amount > 0);
        }
    }

    #[test]
    fn test_vestings_read() {
        for vesting in read_vesting() {
            assert!(vesting.amount > 0);
        }
    }

    #[test]
    fn test_namespaces_read() {
        for namespace in read_namespaces() {
            assert!(namespace.ready_block > 0);
        }
    }

    #[test]
    fn test_names_read() {
        for name in read_names() {
            assert!(name.registered_at > 0);
        }
    }
}
