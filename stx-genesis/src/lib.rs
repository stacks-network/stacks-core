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

pub struct GenesisNamespace {
    pub namespace_id: String,
    pub importer: String,
    pub reveal_block: i64,
    pub ready_block: i64,
    pub buckets: String,
    pub base: i64,
    pub coeff: i64,
    pub nonalpha_discount: i64,
    pub no_vowel_discount: i64,
    pub lifetime: i64,
}

pub struct GenesisName {
    pub fully_qualified_name: String,
    pub owner: String,
    pub registered_at: i64,
    pub expire_block: i64,
    pub zonefile_hash: String,
}

pub static GENESIS_CHAINSTATE_HASH: &str =
    include_str!(concat!(env!("OUT_DIR"), "/chainstate.txt.sha256"));

pub struct GenesisData {
    use_test_chainstate_data: bool,
}

impl GenesisData {
    pub fn new(use_test_chainstate_data: bool) -> GenesisData {
        GenesisData {
            use_test_chainstate_data,
        }
    }
    pub fn read_balances(&self) -> Box<dyn Iterator<Item = GenesisAccountBalance>> {
        read_balances(if self.use_test_chainstate_data {
            include_bytes!(concat!(env!("OUT_DIR"), "/account_balances-test.gz"))
        } else {
            include_bytes!(concat!(env!("OUT_DIR"), "/account_balances.gz"))
        })
    }
    pub fn read_lockups(&self) -> Box<dyn Iterator<Item = GenesisAccountLockup>> {
        read_lockups(if self.use_test_chainstate_data {
            include_bytes!(concat!(env!("OUT_DIR"), "/account_lockups-test.gz"))
        } else {
            include_bytes!(concat!(env!("OUT_DIR"), "/account_lockups.gz"))
        })
    }
    pub fn read_namespaces(&self) -> Box<dyn Iterator<Item = GenesisNamespace>> {
        read_namespaces(if self.use_test_chainstate_data {
            include_bytes!(concat!(env!("OUT_DIR"), "/namespaces-test.gz"))
        } else {
            include_bytes!(concat!(env!("OUT_DIR"), "/namespaces.gz"))
        })
    }
    pub fn read_names(&self) -> Box<dyn Iterator<Item = GenesisName>> {
        read_names(if self.use_test_chainstate_data {
            include_bytes!(concat!(env!("OUT_DIR"), "/names-test.gz"))
        } else {
            include_bytes!(concat!(env!("OUT_DIR"), "/names.gz"))
        })
    }
}

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

fn read_balances(deflate_bytes: &'static [u8]) -> Box<dyn Iterator<Item = GenesisAccountBalance>> {
    let balances = iter_deflated_csv(deflate_bytes).map(|cols| GenesisAccountBalance {
        address: cols[0].to_string(),
        amount: cols[1].parse::<u64>().unwrap(),
    });
    return Box::new(balances);
}

fn read_lockups(deflate_bytes: &'static [u8]) -> Box<dyn Iterator<Item = GenesisAccountLockup>> {
    let lockups = iter_deflated_csv(deflate_bytes).map(|cols| GenesisAccountLockup {
        address: cols[0].to_string(),
        amount: cols[1].parse::<u64>().unwrap(),
        block_height: cols[2].parse::<u64>().unwrap(),
    });
    return Box::new(lockups);
}

fn read_namespaces(deflate_bytes: &'static [u8]) -> Box<dyn Iterator<Item = GenesisNamespace>> {
    let namespaces = iter_deflated_csv(deflate_bytes).map(|cols| GenesisNamespace {
        namespace_id: cols[0].to_string(),
        importer: cols[1].to_string(),
        reveal_block: cols[2].parse::<i64>().unwrap(),
        ready_block: cols[3].parse::<i64>().unwrap(),
        buckets: cols[4].to_string(),
        base: cols[5].parse::<i64>().unwrap(),
        coeff: cols[6].parse::<i64>().unwrap(),
        nonalpha_discount: cols[7].parse::<i64>().unwrap(),
        no_vowel_discount: cols[8].parse::<i64>().unwrap(),
        lifetime: cols[9].parse::<i64>().unwrap(),
    });
    return Box::new(namespaces);
}

fn read_names(deflate_bytes: &'static [u8]) -> Box<dyn Iterator<Item = GenesisName>> {
    let names = iter_deflated_csv(deflate_bytes).map(|cols| GenesisName {
        fully_qualified_name: cols[0].to_string(),
        owner: cols[1].to_string(),
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
        for balance in GenesisData::new(false).read_balances() {
            assert!(balance.amount > 0);
        }
        for balance in GenesisData::new(true).read_balances() {
            assert!(balance.amount > 0);
        }
    }

    #[test]
    fn test_lockups_read() {
        for lockup in GenesisData::new(false).read_lockups() {
            assert!(lockup.amount > 0);
        }
        for lockup in GenesisData::new(true).read_lockups() {
            assert!(lockup.amount > 0);
        }
    }

    #[test]
    fn test_namespaces_read() {
        for namespace in GenesisData::new(false).read_namespaces() {
            assert!(namespace.ready_block > 0);
        }
        for namespace in GenesisData::new(true).read_namespaces() {
            assert!(namespace.ready_block > 0);
        }
    }

    #[test]
    fn test_names_read() {
        for name in GenesisData::new(false).read_names() {
            assert!(name.registered_at > 0);
        }
        for name in GenesisData::new(true).read_names() {
            assert!(name.registered_at > 0);
        }
    }
}
