use crate::vm::costs::ExecutionCost;
use crate::vm::database::{BurnStateDB, HeadersDB};
use crate::vm::execute as vm_execute;
use crate::vm::execute_on_network as vm_execute_on_network;
use crate::vm::representations::SymbolicExpression;
use crate::vm::types::StandardPrincipalData;
use crate::vm::types::{PrincipalData, ResponseData, Value};
use crate::vm::StacksEpoch;
use stacks_common::address::{AddressHashMode, C32_ADDRESS_VERSION_TESTNET_SINGLESIG};
use stacks_common::consts::{
    BITCOIN_REGTEST_FIRST_BLOCK_HASH, BITCOIN_REGTEST_FIRST_BLOCK_HEIGHT,
    BITCOIN_REGTEST_FIRST_BLOCK_TIMESTAMP, FIRST_BURNCHAIN_CONSENSUS_HASH, FIRST_STACKS_BLOCK_HASH,
};
use stacks_common::types::chainstate::{
    BlockHeaderHash, BurnchainHeaderHash, SortitionId, StacksAddress, StacksBlockId, VRFSeed,
};
use stacks_common::types::chainstate::{StacksPrivateKey, StacksPublicKey};
use stacks_common::types::{StacksEpochId, PEER_VERSION_EPOCH_2_0};

pub struct UnitTestBurnStateDB {
    pub epoch_id: StacksEpochId,
}
pub struct UnitTestHeaderDB {}

pub const TEST_HEADER_DB: UnitTestHeaderDB = UnitTestHeaderDB {};
pub const TEST_BURN_STATE_DB: UnitTestBurnStateDB = UnitTestBurnStateDB {
    epoch_id: StacksEpochId::Epoch20,
};

pub fn execute(s: &str) -> Value {
    vm_execute(s).unwrap().unwrap()
}

pub fn execute_on_network(s: &str, use_mainnet: bool) -> Value {
    vm_execute_on_network(s, use_mainnet).unwrap().unwrap()
}

pub fn symbols_from_values(vec: Vec<Value>) -> Vec<SymbolicExpression> {
    vec.into_iter()
        .map(|value| SymbolicExpression::atom_value(value))
        .collect()
}

pub fn is_committed(v: &Value) -> bool {
    eprintln!("is_committed?: {}", v);

    match v {
        Value::Response(ref data) => data.committed,
        _ => false,
    }
}

pub fn is_err_code(v: &Value, e: u128) -> bool {
    eprintln!("is_err_code?: {}", v);
    match v {
        Value::Response(ref data) => !data.committed && *data.data == Value::UInt(e),
        _ => false,
    }
}

pub fn is_err_code_i128(v: &Value, e: i128) -> bool {
    eprintln!("is_err_code?: {}", v);
    match v {
        Value::Response(ref data) => !data.committed && *data.data == Value::Int(e),
        _ => false,
    }
}

impl From<&StacksPrivateKey> for StandardPrincipalData {
    fn from(o: &StacksPrivateKey) -> StandardPrincipalData {
        let stacks_addr = StacksAddress::from_public_keys(
            C32_ADDRESS_VERSION_TESTNET_SINGLESIG,
            &AddressHashMode::SerializeP2PKH,
            1,
            &vec![StacksPublicKey::from_private(o)],
        )
        .unwrap();
        StandardPrincipalData::from(stacks_addr)
    }
}

impl From<&StacksPrivateKey> for PrincipalData {
    fn from(o: &StacksPrivateKey) -> PrincipalData {
        PrincipalData::Standard(StandardPrincipalData::from(o))
    }
}

impl From<&StacksPrivateKey> for Value {
    fn from(o: &StacksPrivateKey) -> Value {
        Value::from(StandardPrincipalData::from(o))
    }
}

impl HeadersDB for UnitTestHeaderDB {
    fn get_burn_header_hash_for_block(
        &self,
        id_bhh: &StacksBlockId,
    ) -> Option<BurnchainHeaderHash> {
        if *id_bhh == StacksBlockId::new(&FIRST_BURNCHAIN_CONSENSUS_HASH, &FIRST_STACKS_BLOCK_HASH)
        {
            let first_block_hash =
                BurnchainHeaderHash::from_hex(BITCOIN_REGTEST_FIRST_BLOCK_HASH).unwrap();
            Some(first_block_hash)
        } else {
            None
        }
    }
    fn get_vrf_seed_for_block(&self, _bhh: &StacksBlockId) -> Option<VRFSeed> {
        None
    }
    fn get_stacks_block_header_hash_for_block(
        &self,
        id_bhh: &StacksBlockId,
    ) -> Option<BlockHeaderHash> {
        if *id_bhh == StacksBlockId::new(&FIRST_BURNCHAIN_CONSENSUS_HASH, &FIRST_STACKS_BLOCK_HASH)
        {
            Some(FIRST_STACKS_BLOCK_HASH)
        } else {
            None
        }
    }
    fn get_burn_block_time_for_block(&self, id_bhh: &StacksBlockId) -> Option<u64> {
        if *id_bhh == StacksBlockId::new(&FIRST_BURNCHAIN_CONSENSUS_HASH, &FIRST_STACKS_BLOCK_HASH)
        {
            Some(BITCOIN_REGTEST_FIRST_BLOCK_TIMESTAMP as u64)
        } else {
            // for non-genesis blocks, just pick a u64 value that will increment in most
            // unit tests as blocks are built (most unit tests construct blocks using
            // incrementing high order bytes)
            Some(1 + 10 * (id_bhh.as_bytes()[0] as u64))
        }
    }
    fn get_burn_block_height_for_block(&self, id_bhh: &StacksBlockId) -> Option<u32> {
        if *id_bhh == StacksBlockId::new(&FIRST_BURNCHAIN_CONSENSUS_HASH, &FIRST_STACKS_BLOCK_HASH)
        {
            Some(BITCOIN_REGTEST_FIRST_BLOCK_HEIGHT as u32)
        } else {
            Some(1 + id_bhh.as_bytes()[0] as u32)
        }
    }
    fn get_miner_address(&self, _id_bhh: &StacksBlockId) -> Option<StacksAddress> {
        None
    }
}

impl BurnStateDB for UnitTestBurnStateDB {
    fn get_burn_block_height(&self, _sortition_id: &SortitionId) -> Option<u32> {
        None
    }

    fn get_burn_header_hash(
        &self,
        _height: u32,
        _sortition_id: &SortitionId,
    ) -> Option<BurnchainHeaderHash> {
        None
    }

    fn get_stacks_epoch(&self, _height: u32) -> Option<StacksEpoch> {
        Some(StacksEpoch {
            epoch_id: self.epoch_id,
            start_height: 0,
            end_height: u64::MAX,
            block_limit: ExecutionCost::max_value(),
            network_epoch: PEER_VERSION_EPOCH_2_0,
        })
    }

    fn get_stacks_epoch_by_epoch_id(&self, _epoch_id: &StacksEpochId) -> Option<StacksEpoch> {
        self.get_stacks_epoch(0)
    }

    fn get_v1_unlock_height(&self) -> u32 {
        u32::max_value()
    }

    fn get_pox_prepare_length(&self) -> u32 {
        1
    }

    fn get_pox_reward_cycle_length(&self) -> u32 {
        1
    }

    fn get_pox_rejection_fraction(&self) -> u64 {
        1
    }
    fn get_burn_start_height(&self) -> u32 {
        0
    }
}
