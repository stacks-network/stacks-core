// Copyright (C) 2013-2020 Blockstack PBC, a public benefit corporation
// Copyright (C) 2020 Stacks Open Internet Foundation
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

use crate::burnchains::Burnchain;
use crate::burnchains::Error as burnchain_error;
use crate::chainstate::burn::ConsensusHash;
use clarity::vm::costs::ExecutionCost;
use stacks_common::util::log;
use std::convert::TryFrom;

pub use self::mempool::MemPoolDB;
use crate::types::chainstate::StacksBlockId;
use crate::types::chainstate::{BlockHeaderHash, BurnchainHeaderHash};
use stacks_common::types::StacksEpoch as GenericStacksEpoch;
pub use stacks_common::types::StacksEpochId;
pub mod mempool;

#[cfg(test)]
pub mod tests;

use std::cmp::Ord;
use std::cmp::Ordering;
use std::cmp::PartialOrd;

pub type StacksEpoch = GenericStacksEpoch<ExecutionCost>;

// fork set identifier -- to be mixed with the consensus hash (encodes the version)
pub const SYSTEM_FORK_SET_VERSION: [u8; 4] = [23u8, 0u8, 0u8, 0u8];

// chain id
pub use stacks_common::consts::{CHAIN_ID_MAINNET, CHAIN_ID_TESTNET};

// peer version (big-endian)
// first byte == major network protocol version (currently 0x18)
// second and third bytes are unused
// fourth byte == highest epoch supported by this node (0x05 for 2.05)
pub const PEER_VERSION_MAINNET: u32 = 0x18000005;
pub const PEER_VERSION_TESTNET: u32 = 0xfacade05;

pub const PEER_VERSION_EPOCH_1_0: u8 = 0x00;
pub const PEER_VERSION_EPOCH_2_0: u8 = 0x00;
pub const PEER_VERSION_EPOCH_2_05: u8 = 0x05;
pub const PEER_VERSION_EPOCH_2_1: u8 = 0x06;

// network identifiers
pub const NETWORK_ID_MAINNET: u32 = 0x17000000;
pub const NETWORK_ID_TESTNET: u32 = 0xff000000;

// default port
pub const NETWORK_P2P_PORT: u16 = 6265;

// sliding burnchain window over which a miner's past block-commit payouts will be used to weight
// its current block-commit in a sortition
pub const MINING_COMMITMENT_WINDOW: u8 = 6;

// Number of previous burnchain blocks to search to find burnchain-hosted Stacks operations
pub const BURNCHAIN_TX_SEARCH_WINDOW: u8 = 6;

// This controls a miner heuristic for dropping a transaction from repeated consideration
//  in the mempool. If the transaction caused the block limit to be reached when the block
//  was previously `TX_BLOCK_LIMIT_PROPORTION_HEURISTIC`% full, the transaction will be dropped
//  from the mempool. 20% is chosen as a heuristic here to allow for large transactions to be
//  attempted, but if they cannot be included in an otherwise mostly empty block, not to consider
//  them again.
pub const TX_BLOCK_LIMIT_PROPORTION_HEURISTIC: u64 = 20;

pub const GENESIS_EPOCH: StacksEpochId = StacksEpochId::Epoch20;

/// The number of blocks which will share the block bonus
///   from burn blocks that occurred without a sortition.
///   (See: https://forum.stacks.org/t/pox-consensus-and-stx-future-supply)
#[cfg(test)]
pub const INITIAL_MINING_BONUS_WINDOW: u16 = 10;
#[cfg(not(test))]
pub const INITIAL_MINING_BONUS_WINDOW: u16 = 10_000;

pub const STACKS_2_0_LAST_BLOCK_TO_PROCESS: u64 = 700_000;
pub const MAINNET_2_0_GENESIS_ROOT_HASH: &str =
    "9653c92b1ad726e2dc17862a3786f7438ab9239c16dd8e7aaba8b0b5c34b52af";

pub const STACKS_EPOCH_MAX: u64 = i64::MAX as u64;

/// This is the "dummy" parent to the actual first burnchain block that we process.
pub const FIRST_BURNCHAIN_CONSENSUS_HASH: ConsensusHash = ConsensusHash([0u8; 20]);

// TODO: TO BE SET BY STACKS_V1_MINER_THRESHOLD
pub const BITCOIN_MAINNET_FIRST_BLOCK_HEIGHT: u64 = 666050;
pub const BITCOIN_MAINNET_FIRST_BLOCK_TIMESTAMP: u32 = 1610643248;
pub const BITCOIN_MAINNET_FIRST_BLOCK_HASH: &str =
    "0000000000000000000ab248c8e35c574514d052a83dbc12669e19bc43df486e";
pub const BITCOIN_MAINNET_INITIAL_REWARD_START_BLOCK: u64 = 651389;
pub const BITCOIN_MAINNET_STACKS_2_05_BURN_HEIGHT: u64 = 713_000;

// TODO: Pick a real height for Stacks 2.1.
pub const BITCOIN_MAINNET_STACKS_21_BURN_HEIGHT: u64 = 2_000_000;

pub const BITCOIN_TESTNET_FIRST_BLOCK_HEIGHT: u64 = 2000000;
pub const BITCOIN_TESTNET_FIRST_BLOCK_TIMESTAMP: u32 = 1622691840;
pub const BITCOIN_TESTNET_FIRST_BLOCK_HASH: &str =
    "000000000000010dd0863ec3d7a0bae17c1957ae1de9cbcdae8e77aad33e3b8c";
pub const BITCOIN_TESTNET_STACKS_2_05_BURN_HEIGHT: u64 = 2_104_380;

// TODO: Pick a real height for Stacks 2.1.
pub const BITCOIN_TESTNET_STACKS_21_BURN_HEIGHT: u64 = 4_000_000;

pub const BITCOIN_REGTEST_FIRST_BLOCK_HEIGHT: u64 = 0;
pub const BITCOIN_REGTEST_FIRST_BLOCK_TIMESTAMP: u32 = 0;
pub const BITCOIN_REGTEST_FIRST_BLOCK_HASH: &str =
    "0000000000000000000000000000000000000000000000000000000000000000";

pub const FIRST_STACKS_BLOCK_HASH: BlockHeaderHash = BlockHeaderHash([0u8; 32]);
pub const EMPTY_MICROBLOCK_PARENT_HASH: BlockHeaderHash = BlockHeaderHash([0u8; 32]);

lazy_static! {
    pub static ref FIRST_STACKS_BLOCK_ID: StacksBlockId =
        StacksBlockId::new(&FIRST_BURNCHAIN_CONSENSUS_HASH, &FIRST_STACKS_BLOCK_HASH);
}

pub const BOOT_BLOCK_HASH: BlockHeaderHash = BlockHeaderHash([0xff; 32]);
pub const BURNCHAIN_BOOT_CONSENSUS_HASH: ConsensusHash = ConsensusHash([0xff; 20]);

pub const MICROSTACKS_PER_STACKS: u32 = 1_000_000;

pub const POX_SUNSET_START: u64 = 100_000;
pub const POX_SUNSET_END: u64 = POX_SUNSET_START + 400_000;

pub const POX_PREPARE_WINDOW_LENGTH: u32 = 100;
pub const POX_REWARD_CYCLE_LENGTH: u32 = 2100;
/// The maximum amount that PoX rewards can be scaled by.
///  That is, if participation is very low, rewards are:
///      POX_MAXIMAL_SCALING x (rewards with 100% participation)
///  Set a 4x, this implies the lower bound of participation for scaling
///   is 25%
pub const POX_MAXIMAL_SCALING: u128 = 4;
/// This is the amount that PoX threshold adjustments are stepped by.
pub const POX_THRESHOLD_STEPS_USTX: u128 = 10_000 * (MICROSTACKS_PER_STACKS as u128);

pub const POX_MAX_NUM_CYCLES: u8 = 12;

// These values are taken from the corresponding variables in `pox-tesnet.clar`.
pub const POX_TESTNET_STACKING_THRESHOLD_25: u128 = 8000;
pub const POX_TESTNET_CYCLE_LENGTH: u128 = 1050;

pub const POX_V1_MAINNET_EARLY_UNLOCK_HEIGHT: u32 = 1_000_000;
pub const POX_V1_TESTNET_EARLY_UNLOCK_HEIGHT: u32 = 2_000_000;

/// Burn block height at which the ASTRules::PrecheckSize becomes the default behavior on mainnet
pub const AST_RULES_PRECHECK_SIZE: u64 = 752000; // on or about Aug 30 2022

// Stacks 1.0 did not allow smart contracts so all limits are 0.
pub const BLOCK_LIMIT_MAINNET_10: ExecutionCost = ExecutionCost {
    write_length: 0,
    write_count: 0,
    read_length: 0,
    read_count: 0,
    runtime: 0,
};

// Block limit in Stacks 2.0.
pub const BLOCK_LIMIT_MAINNET_20: ExecutionCost = ExecutionCost {
    write_length: 15_000_000, // roughly 15 mb
    write_count: 7_750,
    read_length: 100_000_000,
    read_count: 7_750,
    runtime: 5_000_000_000,
};

// Block limit in Stacks 2.05.
pub const BLOCK_LIMIT_MAINNET_205: ExecutionCost = ExecutionCost {
    write_length: 15_000_000,
    write_count: 15_000,
    read_length: 100_000_000,
    read_count: 15_000,
    runtime: 5_000_000_000,
};

// Block limit for the testnet in Stacks 2.0.
pub const HELIUM_BLOCK_LIMIT_20: ExecutionCost = ExecutionCost {
    write_length: 15_0_000_000,
    write_count: 5_0_000,
    read_length: 1_000_000_000,
    read_count: 5_0_000,
    // allow much more runtime in helium blocks than mainnet
    runtime: 100_000_000_000,
};

pub const FAULT_DISABLE_MICROBLOCKS_COST_CHECK: &str = "MICROBLOCKS_DISABLE_COST_CHECK";
pub const FAULT_DISABLE_MICROBLOCKS_BYTES_CHECK: &str = "MICROBLOCKS_DISABLE_BYTES_CHECK";

pub fn check_fault_injection(fault_name: &str) -> bool {
    use std::env;

    // only activates if we're testing
    if env::var("BITCOIND_TEST") != Ok("1".to_string()) {
        return false;
    }

    env::var(fault_name) == Ok("1".to_string())
}

lazy_static! {
    pub static ref STACKS_EPOCHS_MAINNET: [StacksEpoch; 4] = [
        StacksEpoch {
            epoch_id: StacksEpochId::Epoch10,
            start_height: 0,
            end_height: BITCOIN_MAINNET_FIRST_BLOCK_HEIGHT,
            block_limit: BLOCK_LIMIT_MAINNET_10.clone(),
            network_epoch: PEER_VERSION_EPOCH_1_0
        },
        StacksEpoch {
            epoch_id: StacksEpochId::Epoch20,
            start_height: BITCOIN_MAINNET_FIRST_BLOCK_HEIGHT,
            end_height: BITCOIN_MAINNET_STACKS_2_05_BURN_HEIGHT,
            block_limit: BLOCK_LIMIT_MAINNET_20.clone(),
            network_epoch: PEER_VERSION_EPOCH_2_0
        },
        StacksEpoch {
            epoch_id: StacksEpochId::Epoch2_05,
            start_height: BITCOIN_MAINNET_STACKS_2_05_BURN_HEIGHT,
            end_height: BITCOIN_MAINNET_STACKS_21_BURN_HEIGHT,
            block_limit: BLOCK_LIMIT_MAINNET_205.clone(),
            network_epoch: PEER_VERSION_EPOCH_2_05
        },
        StacksEpoch {
            epoch_id: StacksEpochId::Epoch21,
            start_height: BITCOIN_MAINNET_STACKS_21_BURN_HEIGHT,
            end_height: STACKS_EPOCH_MAX,
            block_limit: BLOCK_LIMIT_MAINNET_205.clone(),
            network_epoch: PEER_VERSION_EPOCH_2_05
        },
    ];
}

lazy_static! {
    pub static ref STACKS_EPOCHS_TESTNET: [StacksEpoch; 4] = [
        StacksEpoch {
            epoch_id: StacksEpochId::Epoch10,
            start_height: 0,
            end_height: BITCOIN_TESTNET_FIRST_BLOCK_HEIGHT,
            block_limit: BLOCK_LIMIT_MAINNET_10.clone(),
            network_epoch: PEER_VERSION_EPOCH_1_0
        },
        StacksEpoch {
            epoch_id: StacksEpochId::Epoch20,
            start_height: BITCOIN_TESTNET_FIRST_BLOCK_HEIGHT,
            end_height: BITCOIN_TESTNET_STACKS_2_05_BURN_HEIGHT,
            block_limit: BLOCK_LIMIT_MAINNET_20.clone(),
            network_epoch: PEER_VERSION_EPOCH_2_0
        },
        StacksEpoch {
            epoch_id: StacksEpochId::Epoch2_05,
            start_height: BITCOIN_TESTNET_STACKS_2_05_BURN_HEIGHT,
            end_height: BITCOIN_TESTNET_STACKS_21_BURN_HEIGHT,
            block_limit: BLOCK_LIMIT_MAINNET_205.clone(),
            network_epoch: PEER_VERSION_EPOCH_2_05
        },
        StacksEpoch {
            epoch_id: StacksEpochId::Epoch21,
            start_height: BITCOIN_TESTNET_STACKS_21_BURN_HEIGHT,
            end_height: STACKS_EPOCH_MAX,
            block_limit: BLOCK_LIMIT_MAINNET_205.clone(),
            network_epoch: PEER_VERSION_EPOCH_2_05
        },
    ];
}

lazy_static! {
    pub static ref STACKS_EPOCHS_REGTEST: [StacksEpoch; 4] = [
        StacksEpoch {
            epoch_id: StacksEpochId::Epoch10,
            start_height: 0,
            end_height: 0,
            block_limit: BLOCK_LIMIT_MAINNET_10.clone(),
            network_epoch: PEER_VERSION_EPOCH_1_0
        },
        StacksEpoch {
            epoch_id: StacksEpochId::Epoch20,
            start_height: 0,
            end_height: 100,
            block_limit: HELIUM_BLOCK_LIMIT_20.clone(),
            network_epoch: PEER_VERSION_EPOCH_2_0
        },
        StacksEpoch {
            epoch_id: StacksEpochId::Epoch2_05,
            start_height: 100,
            end_height: 110,
            block_limit: HELIUM_BLOCK_LIMIT_20.clone(),
            network_epoch: PEER_VERSION_EPOCH_2_05
        },
        StacksEpoch {
            epoch_id: StacksEpochId::Epoch21,
            start_height: 110,
            end_height: STACKS_EPOCH_MAX,
            block_limit: HELIUM_BLOCK_LIMIT_20.clone(),
            network_epoch: PEER_VERSION_EPOCH_2_05
        },
    ];
}

/// Stacks 2.05 epoch marker.  All block-commits in 2.05 must have a memo bitfield with this value
/// *or greater*.
pub static STACKS_EPOCH_2_05_MARKER: u8 = 0x05;

/// Stacks 2.1 epoch marker.  All block-commits in 2.1 must have a memo bitfield with this value
/// *or greater*.
pub static STACKS_EPOCH_2_1_MARKER: u8 = 0x06;

#[test]
fn test_ord_for_stacks_epoch() {
    let epochs = STACKS_EPOCHS_MAINNET.clone();
    assert_eq!(epochs[0].cmp(&epochs[1]), Ordering::Less);
    assert_eq!(epochs[1].cmp(&epochs[2]), Ordering::Less);
    assert_eq!(epochs[0].cmp(&epochs[2]), Ordering::Less);
    assert_eq!(epochs[0].cmp(&epochs[0]), Ordering::Equal);
    assert_eq!(epochs[1].cmp(&epochs[1]), Ordering::Equal);
    assert_eq!(epochs[2].cmp(&epochs[2]), Ordering::Equal);
    assert_eq!(epochs[2].cmp(&epochs[0]), Ordering::Greater);
    assert_eq!(epochs[2].cmp(&epochs[1]), Ordering::Greater);
    assert_eq!(epochs[1].cmp(&epochs[0]), Ordering::Greater);
}

#[test]
fn test_ord_for_stacks_epoch_id() {
    assert_eq!(
        StacksEpochId::Epoch10.cmp(&StacksEpochId::Epoch20),
        Ordering::Less
    );
    assert_eq!(
        StacksEpochId::Epoch20.cmp(&StacksEpochId::Epoch2_05),
        Ordering::Less
    );
    assert_eq!(
        StacksEpochId::Epoch10.cmp(&StacksEpochId::Epoch2_05),
        Ordering::Less
    );
    assert_eq!(
        StacksEpochId::Epoch10.cmp(&StacksEpochId::Epoch10),
        Ordering::Equal
    );
    assert_eq!(
        StacksEpochId::Epoch20.cmp(&StacksEpochId::Epoch20),
        Ordering::Equal
    );
    assert_eq!(
        StacksEpochId::Epoch2_05.cmp(&StacksEpochId::Epoch2_05),
        Ordering::Equal
    );
    assert_eq!(
        StacksEpochId::Epoch2_05.cmp(&StacksEpochId::Epoch20),
        Ordering::Greater
    );
    assert_eq!(
        StacksEpochId::Epoch2_05.cmp(&StacksEpochId::Epoch10),
        Ordering::Greater
    );
    assert_eq!(
        StacksEpochId::Epoch20.cmp(&StacksEpochId::Epoch10),
        Ordering::Greater
    );
}
pub trait StacksEpochExtension {
    #[cfg(test)]
    fn unit_test(stacks_epoch_id: StacksEpochId, epoch_2_0_block_height: u64) -> Vec<StacksEpoch>;
    #[cfg(test)]
    fn unit_test_2_05(epoch_2_0_block_height: u64) -> Vec<StacksEpoch>;
    #[cfg(test)]
    fn unit_test_pre_2_05(epoch_2_0_block_height: u64) -> Vec<StacksEpoch>;
    #[cfg(test)]
    fn unit_test_2_1(epoch_2_0_block_height: u64) -> Vec<StacksEpoch>;
    fn all(
        epoch_2_0_block_height: u64,
        epoch_2_05_block_height: u64,
        epoch_2_1_block_height: u64,
    ) -> Vec<StacksEpoch>;
}

impl StacksEpochExtension for StacksEpoch {
    #[cfg(test)]
    fn unit_test_pre_2_05(first_burnchain_height: u64) -> Vec<StacksEpoch> {
        info!(
            "StacksEpoch unit_test first_burn_height = {}",
            first_burnchain_height
        );

        vec![
            StacksEpoch {
                epoch_id: StacksEpochId::Epoch10,
                start_height: 0,
                end_height: first_burnchain_height,
                block_limit: ExecutionCost::max_value(),
                network_epoch: PEER_VERSION_EPOCH_1_0,
            },
            StacksEpoch {
                epoch_id: StacksEpochId::Epoch20,
                start_height: first_burnchain_height,
                end_height: STACKS_EPOCH_MAX,
                block_limit: ExecutionCost::max_value(),
                network_epoch: PEER_VERSION_EPOCH_2_0,
            },
        ]
    }

    #[cfg(test)]
    fn unit_test_2_05(first_burnchain_height: u64) -> Vec<StacksEpoch> {
        info!(
            "StacksEpoch unit_test first_burn_height = {}",
            first_burnchain_height
        );

        vec![
            StacksEpoch {
                epoch_id: StacksEpochId::Epoch10,
                start_height: 0,
                end_height: first_burnchain_height,
                block_limit: ExecutionCost::max_value(),
                network_epoch: PEER_VERSION_EPOCH_1_0,
            },
            StacksEpoch {
                epoch_id: StacksEpochId::Epoch20,
                start_height: first_burnchain_height,
                end_height: first_burnchain_height + 4,
                block_limit: ExecutionCost::max_value(),
                network_epoch: PEER_VERSION_EPOCH_2_0,
            },
            StacksEpoch {
                epoch_id: StacksEpochId::Epoch2_05,
                start_height: first_burnchain_height + 4,
                end_height: STACKS_EPOCH_MAX,
                block_limit: ExecutionCost {
                    write_length: 205205,
                    write_count: 205205,
                    read_length: 205205,
                    read_count: 205205,
                    runtime: 205205,
                },
                network_epoch: PEER_VERSION_EPOCH_2_05,
            },
        ]
    }

    #[cfg(test)]
    fn unit_test_2_1(first_burnchain_height: u64) -> Vec<StacksEpoch> {
        info!(
            "StacksEpoch unit_test first_burn_height = {}",
            first_burnchain_height
        );

        vec![
            StacksEpoch {
                epoch_id: StacksEpochId::Epoch10,
                start_height: 0,
                end_height: first_burnchain_height,
                block_limit: ExecutionCost::max_value(),
                network_epoch: PEER_VERSION_EPOCH_1_0,
            },
            StacksEpoch {
                epoch_id: StacksEpochId::Epoch20,
                start_height: first_burnchain_height,
                end_height: first_burnchain_height + 4,
                block_limit: ExecutionCost::max_value(),
                network_epoch: PEER_VERSION_EPOCH_2_0,
            },
            StacksEpoch {
                epoch_id: StacksEpochId::Epoch2_05,
                start_height: first_burnchain_height + 4,
                end_height: first_burnchain_height + 8,
                block_limit: ExecutionCost {
                    write_length: 205205,
                    write_count: 205205,
                    read_length: 205205,
                    read_count: 205205,
                    runtime: 205205,
                },
                network_epoch: PEER_VERSION_EPOCH_2_05,
            },
            StacksEpoch {
                epoch_id: StacksEpochId::Epoch21,
                start_height: first_burnchain_height + 8,
                end_height: STACKS_EPOCH_MAX,
                block_limit: ExecutionCost {
                    write_length: 210210,
                    write_count: 210210,
                    read_length: 210210,
                    read_count: 210210,
                    runtime: 210210,
                },
                network_epoch: PEER_VERSION_EPOCH_2_1,
            },
        ]
    }

    #[cfg(test)]
    fn unit_test(stacks_epoch_id: StacksEpochId, first_burnchain_height: u64) -> Vec<StacksEpoch> {
        match stacks_epoch_id {
            StacksEpochId::Epoch10 | StacksEpochId::Epoch20 => {
                StacksEpoch::unit_test_pre_2_05(first_burnchain_height)
            }
            StacksEpochId::Epoch2_05 => StacksEpoch::unit_test_2_05(first_burnchain_height),
            StacksEpochId::Epoch21 => StacksEpoch::unit_test_2_1(first_burnchain_height),
        }
    }

    fn all(
        epoch_2_0_block_height: u64,
        epoch_2_05_block_height: u64,
        epoch_2_1_block_height: u64,
    ) -> Vec<StacksEpoch> {
        vec![
            StacksEpoch {
                epoch_id: StacksEpochId::Epoch10,
                start_height: 0,
                end_height: epoch_2_0_block_height,
                block_limit: ExecutionCost::max_value(),
                network_epoch: PEER_VERSION_EPOCH_1_0,
            },
            StacksEpoch {
                epoch_id: StacksEpochId::Epoch20,
                start_height: epoch_2_0_block_height,
                end_height: epoch_2_05_block_height,
                block_limit: ExecutionCost::max_value(),
                network_epoch: PEER_VERSION_EPOCH_1_0,
            },
            StacksEpoch {
                epoch_id: StacksEpochId::Epoch2_05,
                start_height: epoch_2_05_block_height,
                end_height: epoch_2_1_block_height,
                block_limit: ExecutionCost::max_value(),
                network_epoch: PEER_VERSION_EPOCH_1_0,
            },
            StacksEpoch {
                epoch_id: StacksEpochId::Epoch21,
                start_height: epoch_2_1_block_height,
                end_height: STACKS_EPOCH_MAX,
                block_limit: ExecutionCost::max_value(),
                network_epoch: PEER_VERSION_EPOCH_1_0,
            },
        ]
    }
}
