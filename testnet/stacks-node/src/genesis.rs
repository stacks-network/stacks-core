use stacks::burnchains::bitcoin::address::BitcoinAddress;
use stacks::chainstate::stacks::StacksAddress;
use stacks::util;
use std::fs::File;
use std::io::Read;
use sha2::{Digest, Sha256};
use std::fs;

use super::config::{InitialBalance, InitialVestingSchedule};

#[derive(Debug, Clone, Deserialize)]
pub struct SerializedInitialBalance {
    pub address: String,
    #[serde(rename = "balance")]
    pub amount: String,
}

#[derive(Debug, Clone, Deserialize)]
pub struct SerializedInitialVestingSchedule {
    pub address: String,
    #[serde(rename = "value")]
    pub amount: String,
    #[serde(rename = "blocks")]
    pub block_height: u64,
}

#[derive(Debug, Deserialize)]
pub struct GenesisData {
    #[serde(rename = "balances")]
    initial_balances: Vec<SerializedInitialBalance>,
    #[serde(rename = "vesting")]
    initial_vesting_schedules: Vec<SerializedInitialVestingSchedule>,
}

impl GenesisData {
    pub fn from_file(file_path: &str, expected_sha2sum: &str) -> Result<GenesisData, String> {

        let mut f = File::open(&file_path).expect("no file found");
        let metadata = fs::metadata(&file_path).expect("unable to read metadata");
        let mut file_content: Vec<u8> = vec![0; metadata.len() as usize];
        f.read(&mut file_content).expect("buffer overflow");

        // Check file integrity using the sha2sum provided in the config
        let mut sha2 = Sha256::new();
        sha2.input(&file_content[..]);
        let mut sha2sum = [0u8; 32];
        sha2sum.copy_from_slice(&sha2.result()[..]);
        
        assert_eq!(&util::hash::to_hex(&sha2sum), expected_sha2sum);

        match serde_json::from_slice(&file_content[..]) {
            Ok(genesis_data) => Ok(genesis_data),
            Err(err) => {
                Err(format!("Failed parsing GenesisData: {}", err))
            }
        }
    }

    pub fn get_initial_balances(&self) -> Vec<InitialBalance> {
        let mut balances = vec![];
        for ser_bal in self.initial_balances.iter() {

            let btc_address = BitcoinAddress::from_b58(&ser_bal.address).unwrap();
            let stx_address = StacksAddress::from_bitcoin_address(&btc_address);

            balances.push(InitialBalance {
                address: stx_address.into(),
                amount: ser_bal.amount.parse::<u64>().unwrap(),
            });
        }
        balances
    }

    pub fn get_initial_vesting_schedules(&self) -> Vec<InitialVestingSchedule> {
        let mut schedules = vec![];
        for ser_schedule in self.initial_vesting_schedules.iter() {

            let btc_address = BitcoinAddress::from_b58(&ser_schedule.address).unwrap();
            let stx_address = StacksAddress::from_bitcoin_address(&btc_address);

            schedules.push(InitialVestingSchedule {
                address: stx_address.into(),
                amount: ser_schedule.amount.parse::<u64>().unwrap(),
                block_height: ser_schedule.block_height,
            });
        }
        schedules
    }
}
