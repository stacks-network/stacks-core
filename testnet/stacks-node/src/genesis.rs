use stacks::chainstate::stacks::StacksAddress;
use stacks::{
    burnchains::bitcoin::address::BitcoinAddress,
    chainstate::stacks::db::{AccountBalance, VestingSchedule},
    util::hash::Sha256Sum,
};

pub const GENESIS_DATA_BYTES: &str = include_str!("../chainstate.txt");
pub const GENESIS_DATA_SHA_BYTES: &str = include_str!("../chainstate.txt.sha256");

fn verify_genesis_integrity() -> GenesisIntegrity {
    // TODO: This digest & check should be done in a build script or const fn rather than runtime.
    let genesis_data_sha = Sha256Sum::from_data(GENESIS_DATA_BYTES.as_bytes());
    let expected_genesis_sha = Sha256Sum::from_hex(GENESIS_DATA_SHA_BYTES).unwrap();
    GenesisIntegrity {
        is_valid: genesis_data_sha.eq(&expected_genesis_sha),
        expected: expected_genesis_sha,
        actual: genesis_data_sha,
    }
}

pub struct GenesisIntegrity {
    pub is_valid: bool,
    pub expected: Sha256Sum,
    pub actual: Sha256Sum,
}

lazy_static! {
    pub static ref EMBEDDED_GENESIS_DATA_VALIDATION: GenesisIntegrity = verify_genesis_integrity();
}

fn check_genesis_data_integrity() {
    let genesis_data_validation = &EMBEDDED_GENESIS_DATA_VALIDATION;
    if !genesis_data_validation.is_valid {
        panic!(
            "FATAL ERROR: genesis data hash mismatch, expected {}, got {}",
            genesis_data_validation.expected, genesis_data_validation.actual
        );
    }
}

pub fn parse_vesting_schedules() -> Box<dyn Iterator<Item = VestingSchedule>> {
    check_genesis_data_integrity();
    let schedules = GENESIS_DATA_BYTES
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
                }
            };
            let amount = parts.next().unwrap().parse::<u64>().unwrap();
            let block_height = parts.next().unwrap().parse::<u64>().unwrap();
            Some(VestingSchedule {
                address: stx_address.into(),
                amount: amount,
                block_height: block_height,
            })
        });
    return Box::new(schedules);
}

pub fn parse_balances() -> Box<dyn Iterator<Item = AccountBalance>> {
    check_genesis_data_integrity();
    let balances = GENESIS_DATA_BYTES
        .lines()
        .into_iter()
        .skip_while(|l| !l.eq(&"-----BEGIN STX BALANCES-----"))
        // skip table header line "address,balance"
        .skip(2)
        .take_while(|l| !l.eq(&"-----END STX BALANCES-----"))
        .filter_map(|line| {
            let mut parts = line.split(",");
            let addr = parts.next().unwrap();
            let stx_address = match BitcoinAddress::from_b58(&addr) {
                Ok(addr) => StacksAddress::from_bitcoin_address(&addr),
                _ => {
                    warn!("Skipping invalid stx balance address: {}", addr);
                    return None;
                }
            };
            let balance = parts.next().unwrap().parse::<u64>().unwrap();
            Some(AccountBalance {
                address: stx_address.into(),
                amount: balance,
            })
        });
    return Box::new(balances);
}
