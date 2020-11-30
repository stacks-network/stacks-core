use stacks::{burnchains::bitcoin::address::BitcoinAddress, util::hash::Sha256Sum, chainstate::stacks::db::VestingSchedule};
use stacks::chainstate::stacks::StacksAddress;

use super::config::{InitialBalance};

pub const GENESIS_DATA_BYTES: &str = include_str!("../chainstate.txt");
pub const GENESIS_DATA_SHA_BYTES: &str = include_str!("../chainstate.txt.sha256");

fn verify_genesis_integrity() {
    // TODO: This digest & check should be done in a build script or const fn rather than runtime.
    let genesis_data_sha = Sha256Sum::from_data(GENESIS_DATA_BYTES.as_bytes());
    let expected_genesis_sha = Sha256Sum::from_hex(GENESIS_DATA_SHA_BYTES).unwrap();
    if !genesis_data_sha.eq(&expected_genesis_sha) {
        panic!("FATAL ERROR: genesis data hash mismatch, expected {}, got {}", expected_genesis_sha, genesis_data_sha);
    }
}

pub struct EmbeddedGenesisData {
    // pub vesting_schedules: Vec<InitialVestingSchedule>,
    pub vesting_schedules: Vec<VestingSchedule>,
    pub stx_balances: Vec<InitialBalance>,
}

lazy_static! {
    pub static ref EMBEDDED_GENESIS_DATA: EmbeddedGenesisData = {
        verify_genesis_integrity();
        // TODO: This takes several seconds, ideally should be performed in a const fn or build script.
        let vesting_schedules = EmbeddedGenesisData::parse_vesting_schedules(GENESIS_DATA_BYTES);
        let stx_balances = EmbeddedGenesisData::parse_balances(GENESIS_DATA_BYTES);
        EmbeddedGenesisData {
            vesting_schedules,
            stx_balances
        }
    };
}

impl EmbeddedGenesisData {

    pub fn parse_vesting_schedules2(genesis_str: &'static str) -> impl Iterator<Item = VestingSchedule> {
        let lines = genesis_str
            .lines()
            .into_iter()
            .skip_while(|line| !line.eq(&"-----BEGIN STX VESTING-----"))
            // skip table header line "address,value,blocks"
            .skip(2)
            .take_while(|line| !line.eq(&"-----END STX VESTING-----"))
            .filter_map(|line| {
                let mut parts = line.split(",");
                let addr = parts.next().unwrap();
                let stx_address = match BitcoinAddress::from_b58(&addr) {
                    Ok(addr) => StacksAddress::from_bitcoin_address(&addr),
                    _ => {
                        warn!("Skipping invalid vesting address: {}", addr);
                        return None;
                    },
                };
                let amount = parts.next().unwrap().parse::<u64>().unwrap();
                let block_height = parts.next().unwrap().parse::<u64>().unwrap();
                Some(VestingSchedule {
                    address: stx_address.into(),
                    amount: amount,
                    block_height: block_height,
                })
            });
        return lines;
    }

    pub fn parse_vesting_schedules(genesis_str: &'static str) -> Vec<VestingSchedule> {
        let mut schedules = vec![];
        let lines = genesis_str
            .lines()
            .into_iter()
            .skip_while(|l| !l.eq(&"-----BEGIN STX VESTING-----"))
            // skip table header line "address,value,blocks"
            .skip(2)
            .take_while(|l| !l.eq(&"-----END STX VESTING-----"));
        
        for line in lines {
            let mut parts = line.split(",");
            let addr = parts.next().unwrap();
            let stx_address = match BitcoinAddress::from_b58(&addr) {
                Ok(addr) => StacksAddress::from_bitcoin_address(&addr),
                _ => {
                    warn!("Skipping invalid vesting address: {}", addr);
                    continue;
                },
            };
            let amount = parts.next().unwrap().parse::<u64>().unwrap();
            let block_height = parts.next().unwrap().parse::<u64>().unwrap();
            schedules.push(VestingSchedule {
                address: stx_address.into(),
                amount: amount,
                block_height: block_height,
            });
        }
        schedules
    }

    pub fn parse_balances(genesis_str: &'static str) -> Vec<InitialBalance> {
        let mut balances = vec![];
        let lines = genesis_str
            .lines()
            .into_iter()
            .skip_while(|l| !l.eq(&"-----BEGIN STX BALANCES-----"))
            // skip table header line "address,balance"
            .skip(2)
            .take_while(|l| !l.eq(&"-----END STX BALANCES-----"));
        for line in lines {
            let mut parts = line.split(",");
            let addr = parts.next().unwrap();
            let stx_address = match BitcoinAddress::from_b58(&addr) {
                Ok(addr) => StacksAddress::from_bitcoin_address(&addr),
                _ => {
                    warn!("Skipping invalid stx balance address: {}", addr);
                    continue;
                },
            };
            let balance = parts.next().unwrap().parse::<u64>().unwrap();
            balances.push(InitialBalance {
                address: stx_address.into(),
                amount: balance
            });
        }
        balances
    }
}
