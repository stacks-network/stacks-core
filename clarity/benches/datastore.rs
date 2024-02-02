//! The `datastore` module contains simple in-memory imnplementations of the
//! various data storage traits used during program execution.
//! It is intended for use in tooling and tests, but not intended to be used
//! in production. The `datastore` module is only available when the
//! `developer-mode` feature is enabled. Many of these methods are just
//! mock implementations that do nothing.
#![allow(clippy::expect_used, clippy::unwrap_used)]

use std::collections::HashMap;

use clarity::types::chainstate::{
    BlockHeaderHash, BurnchainHeaderHash, ConsensusHash, SortitionId, StacksAddress, StacksBlockId,
    VRFSeed,
};
use clarity::types::StacksEpochId;
use clarity::util::hash::Sha512Trunc256Sum;
use clarity::vm::analysis::AnalysisDatabase;
use clarity::vm::database::{BurnStateDB, ClarityBackingStore, HeadersDB};
use clarity::vm::errors::InterpreterResult as Result;
use clarity::vm::types::{QualifiedContractIdentifier, TupleData};
use clarity::vm::{StacksEpoch, Value};
use rusqlite::Connection;
use sha2::{Digest, Sha512_256};

#[derive(Clone, Debug)]
pub struct Datastore {
    store: HashMap<StacksBlockId, HashMap<String, String>>,
    block_id_lookup: HashMap<StacksBlockId, StacksBlockId>,
    metadata: HashMap<(String, String), String>,
    open_chain_tip: StacksBlockId,
    current_chain_tip: StacksBlockId,
    chain_height: u32,
    height_at_chain_tip: HashMap<StacksBlockId, u32>,
}

#[derive(Clone, Debug)]
pub struct BlockInfo {
    block_header_hash: BlockHeaderHash,
    burn_block_header_hash: BurnchainHeaderHash,
    consensus_hash: ConsensusHash,
    vrf_seed: VRFSeed,
    burn_block_time: u64,
    burn_block_height: u32,
    miner: StacksAddress,
    burnchain_tokens_spent_for_block: u128,
    get_burnchain_tokens_spent_for_winning_block: u128,
    tokens_earned_for_block: u128,
    pox_payout_addrs: (Vec<TupleData>, u128),
}

#[derive(Clone, Debug, Default)]
pub struct StacksConstants {
    pub burn_start_height: u32,
    pub pox_prepare_length: u32,
    pub pox_reward_cycle_length: u32,
    pub pox_rejection_fraction: u64,
    pub epoch_21_start_height: u32,
}

#[derive(Clone, Debug)]
pub struct BurnDatastore {
    store: HashMap<StacksBlockId, BlockInfo>,
    sortition_lookup: HashMap<SortitionId, StacksBlockId>,
    consensus_hash_lookup: HashMap<ConsensusHash, SortitionId>,
    block_id_lookup: HashMap<StacksBlockId, StacksBlockId>,
    open_chain_tip: StacksBlockId,
    current_chain_tip: StacksBlockId,
    chain_height: u32,
    height_at_chain_tip: HashMap<StacksBlockId, u32>,
    constants: StacksConstants,
    genesis_time: u64,
}

fn height_to_hashed_bytes(height: u32) -> [u8; 32] {
    let input_bytes = height.to_be_bytes();
    let mut hasher = Sha512_256::new();
    hasher.update(input_bytes);
    let hash = Sha512Trunc256Sum::from_hasher(hasher);
    hash.0
}

fn height_to_id(height: u32) -> StacksBlockId {
    StacksBlockId(height_to_hashed_bytes(height))
}

fn height_to_block(height: u32, genesis_time: Option<u64>) -> BlockInfo {
    let bytes = height_to_hashed_bytes(height);
    let genesis_time = genesis_time.unwrap_or(0);

    let block_header_hash = {
        let mut buffer = bytes;
        buffer[0] = 1;
        BlockHeaderHash(buffer)
    };
    let burn_block_header_hash = {
        let mut buffer = bytes;
        buffer[0] = 2;
        BurnchainHeaderHash(buffer)
    };
    let consensus_hash = {
        let mut buffer = bytes;
        buffer[0] = 3;
        ConsensusHash::from_bytes(&buffer[0..20]).unwrap()
    };
    let vrf_seed = {
        let mut buffer = bytes;
        buffer[0] = 4;
        VRFSeed(buffer)
    };
    let time_since_genesis: u64 = (height * 1800).into();
    let burn_block_time: u64 = genesis_time + time_since_genesis;
    let burn_block_height = height;
    let miner = StacksAddress::burn_address(true);
    let burnchain_tokens_spent_for_block = 2000;
    let get_burnchain_tokens_spent_for_winning_block = 2000;
    let tokens_earned_for_block = 5000;
    let pox_payout_addrs = (
        vec![TupleData::from_data(vec![
            (
                "hashbytes".into(),
                Value::buff_from([0; 32].to_vec()).unwrap(),
            ),
            ("version".into(), Value::buff_from_byte(0)),
        ])
        .unwrap()],
        0_u128,
    );

    BlockInfo {
        block_header_hash,
        burn_block_header_hash,
        consensus_hash,
        vrf_seed,
        burn_block_time,
        burn_block_height,
        miner,
        burnchain_tokens_spent_for_block,
        get_burnchain_tokens_spent_for_winning_block,
        tokens_earned_for_block,
        pox_payout_addrs,
    }
}

impl Datastore {
    pub fn new() -> Datastore {
        let id = height_to_id(0);

        let mut store = HashMap::new();
        store.insert(id, HashMap::new());

        let mut block_id_lookup = HashMap::new();
        block_id_lookup.insert(id, id);

        let mut id_height_map = HashMap::new();
        id_height_map.insert(id, 0);

        Datastore {
            store,
            block_id_lookup,
            metadata: HashMap::new(),
            open_chain_tip: id,
            current_chain_tip: id,
            chain_height: 0,
            height_at_chain_tip: id_height_map,
        }
    }

    pub fn advance_chain_tip(&mut self, count: u32) -> u32 {
        let cur_height = self.chain_height;
        let current_lookup_id = *self
            .block_id_lookup
            .get(&self.open_chain_tip)
            .expect("Open chain tip missing in block id lookup table");

        for i in 1..=count {
            let height = cur_height + i;
            let id = height_to_id(height);

            self.block_id_lookup.insert(id, current_lookup_id);
            self.height_at_chain_tip.insert(id, height);
        }

        self.chain_height += count;
        self.open_chain_tip = height_to_id(self.chain_height);
        self.current_chain_tip = self.open_chain_tip;
        self.chain_height
    }
}

impl Default for Datastore {
    fn default() -> Self {
        Self::new()
    }
}

impl ClarityBackingStore for Datastore {
    fn put_all(&mut self, items: Vec<(String, String)>) {
        for (key, value) in items {
            self.put(&key, &value);
        }
    }

    /// fetch K-V out of the committed datastore
    fn get(&mut self, key: &str) -> Option<String> {
        let lookup_id = self
            .block_id_lookup
            .get(&self.current_chain_tip)
            .expect("Could not find current chain tip in block_id_lookup map");

        if let Some(map) = self.store.get(lookup_id) {
            map.get(key).cloned()
        } else {
            panic!("Block does not exist for current chain tip");
        }
    }

    fn has_entry(&mut self, key: &str) -> bool {
        self.get(key).is_some()
    }

    /// change the current MARF context to service reads from a different chain_tip
    ///   used to implement time-shifted evaluation.
    /// returns the previous block header hash on success
    fn set_block_hash(&mut self, bhh: StacksBlockId) -> Result<StacksBlockId> {
        let prior_tip = self.open_chain_tip;
        self.current_chain_tip = bhh;
        Ok(prior_tip)
    }

    fn get_block_at_height(&mut self, height: u32) -> Option<StacksBlockId> {
        Some(height_to_id(height))
    }

    /// this function returns the current block height, as viewed by this marfed-kv structure,
    ///  i.e., it changes on time-shifted evaluation. the open_chain_tip functions always
    ///   return data about the chain tip that is currently open for writing.
    fn get_current_block_height(&mut self) -> u32 {
        *self
            .height_at_chain_tip
            .get(self.get_chain_tip())
            .unwrap_or(&u32::MAX)
    }

    fn get_open_chain_tip_height(&mut self) -> u32 {
        self.chain_height
    }

    fn get_open_chain_tip(&mut self) -> StacksBlockId {
        self.open_chain_tip
    }

    /// The contract commitment is the hash of the contract, plus the block height in
    ///   which the contract was initialized.
    fn make_contract_commitment(&mut self, _contract_hash: Sha512Trunc256Sum) -> String {
        "".to_string()
    }

    fn insert_metadata(&mut self, contract: &QualifiedContractIdentifier, key: &str, value: &str) {
        // let bhh = self.get_open_chain_tip();
        // self.get_side_store().insert_metadata(&bhh, &contract.to_string(), key, value)
        self.metadata
            .insert((contract.to_string(), key.to_string()), value.to_string());
    }

    fn get_metadata(
        &mut self,
        contract: &QualifiedContractIdentifier,
        key: &str,
    ) -> Result<Option<String>> {
        // let (bhh, _) = self.get_contract_hash(contract)?;
        // Ok(self.get_side_store().get_metadata(&bhh, &contract.to_string(), key))
        let key = &(contract.to_string(), key.to_string());

        match self.metadata.get(key) {
            Some(result) => Ok(Some(result.to_string())),
            None => Ok(None),
        }
    }

    fn get_with_proof(&mut self, _key: &str) -> Option<(String, Vec<u8>)> {
        None
    }

    fn get_contract_hash(
        &mut self,
        _contract: &QualifiedContractIdentifier,
    ) -> Result<(StacksBlockId, Sha512Trunc256Sum)> {
        panic!("Datastore cannot get_contract_hash")
    }

    fn get_metadata_manual(
        &mut self,
        _at_height: u32,
        _contract: &QualifiedContractIdentifier,
        _key: &str,
    ) -> Result<Option<String>> {
        panic!("Datastore cannot get_metadata_manual")
    }

    #[cfg(not(feature = "wasm"))]
    fn get_side_store(&mut self) -> &Connection {
        panic!("Datastore cannot get_side_store")
    }
}

impl BurnDatastore {
    pub fn new(constants: StacksConstants) -> BurnDatastore {
        let bytes = height_to_hashed_bytes(0);
        let id = StacksBlockId(bytes);
        let sortition_id = SortitionId(bytes);
        let genesis_time = chrono::Utc::now().timestamp() as u64;

        let genesis_block = BlockInfo {
            block_header_hash: BlockHeaderHash([0x00; 32]),
            burn_block_header_hash: BurnchainHeaderHash([0x00; 32]),
            consensus_hash: ConsensusHash([0x00; 20]),
            vrf_seed: VRFSeed([0x00; 32]),
            burn_block_time: genesis_time,
            burn_block_height: 0,
            miner: StacksAddress::burn_address(false),
            burnchain_tokens_spent_for_block: 0,
            get_burnchain_tokens_spent_for_winning_block: 0,
            tokens_earned_for_block: 0,
            pox_payout_addrs: (
                vec![TupleData::from_data(vec![
                    (
                        "hashbytes".into(),
                        Value::buff_from([0; 32].to_vec()).unwrap(),
                    ),
                    ("version".into(), Value::buff_from_byte(0)),
                ])
                .unwrap()],
                0_u128,
            ),
        };

        let mut height_at_chain_tip = HashMap::new();
        height_at_chain_tip.insert(id, 0);

        let mut sortition_lookup = HashMap::new();
        sortition_lookup.insert(sortition_id, id);

        let mut consensus_hash_lookup = HashMap::new();
        consensus_hash_lookup.insert(genesis_block.consensus_hash, sortition_id);

        let mut store = HashMap::new();
        store.insert(id, genesis_block);

        let mut block_id_lookup = HashMap::new();
        block_id_lookup.insert(id, id);

        let mut id_height_map = HashMap::new();
        id_height_map.insert(id, 0);

        BurnDatastore {
            store,
            sortition_lookup,
            consensus_hash_lookup,
            block_id_lookup,
            open_chain_tip: id,
            current_chain_tip: id,
            chain_height: 0,
            height_at_chain_tip,
            constants,
            genesis_time,
        }
    }

    pub fn advance_chain_tip(&mut self, count: u32) {
        let cur_height = self.chain_height;
        let current_lookup_id = *self
            .block_id_lookup
            .get(&self.open_chain_tip)
            .expect("Open chain tip missing in block id lookup table");
        let genesis_time = self.genesis_time;

        for i in 1..=count {
            let height = cur_height + i;
            let bytes = height_to_hashed_bytes(height);
            let id = StacksBlockId(bytes);
            let sortition_id = SortitionId(bytes);
            let block_info = height_to_block(height, Some(genesis_time));
            self.block_id_lookup.insert(id, current_lookup_id);
            self.height_at_chain_tip.insert(id, height);
            self.sortition_lookup.insert(sortition_id, id);
            self.consensus_hash_lookup
                .insert(block_info.consensus_hash, sortition_id);
            self.store.insert(id, block_info);
        }

        self.chain_height += count;
        self.open_chain_tip = height_to_id(self.chain_height);
        self.current_chain_tip = self.open_chain_tip;
    }
}

impl HeadersDB for BurnDatastore {
    fn get_stacks_block_header_hash_for_block(
        &self,
        id_bhh: &StacksBlockId,
    ) -> Option<BlockHeaderHash> {
        self.store.get(id_bhh).map(|id| id.block_header_hash)
    }

    fn get_burn_header_hash_for_block(
        &self,
        id_bhh: &StacksBlockId,
    ) -> Option<BurnchainHeaderHash> {
        self.store.get(id_bhh).map(|id| id.burn_block_header_hash)
    }

    fn get_consensus_hash_for_block(&self, id_bhh: &StacksBlockId) -> Option<ConsensusHash> {
        self.store.get(id_bhh).map(|id| id.consensus_hash)
    }
    fn get_vrf_seed_for_block(&self, id_bhh: &StacksBlockId) -> Option<VRFSeed> {
        self.store.get(id_bhh).map(|id| id.vrf_seed)
    }
    fn get_burn_block_time_for_block(&self, id_bhh: &StacksBlockId) -> Option<u64> {
        self.store.get(id_bhh).map(|id| id.burn_block_time)
    }
    fn get_burn_block_height_for_block(&self, id_bhh: &StacksBlockId) -> Option<u32> {
        self.store.get(id_bhh).map(|id| id.burn_block_height)
    }
    fn get_miner_address(&self, id_bhh: &StacksBlockId) -> Option<StacksAddress> {
        self.store.get(id_bhh).map(|id| id.miner)
    }
    fn get_burnchain_tokens_spent_for_block(&self, id_bhh: &StacksBlockId) -> Option<u128> {
        self.store
            .get(id_bhh)
            .map(|id| id.burnchain_tokens_spent_for_block)
    }
    fn get_burnchain_tokens_spent_for_winning_block(&self, id_bhh: &StacksBlockId) -> Option<u128> {
        self.store
            .get(id_bhh)
            .map(|id| id.get_burnchain_tokens_spent_for_winning_block)
    }
    fn get_tokens_earned_for_block(&self, id_bhh: &StacksBlockId) -> Option<u128> {
        self.store.get(id_bhh).map(|id| id.tokens_earned_for_block)
    }
}

impl BurnStateDB for BurnDatastore {
    fn get_v1_unlock_height(&self) -> u32 {
        0
    }

    fn get_v2_unlock_height(&self) -> u32 {
        0
    }

    fn get_pox_3_activation_height(&self) -> u32 {
        0
    }

    /// Returns the *burnchain block height* for the `sortition_id` is associated with.
    fn get_burn_block_height(&self, sortition_id: &SortitionId) -> Option<u32> {
        self.sortition_lookup
            .get(sortition_id)
            .and_then(|id| self.store.get(id))
            .map(|block_info| block_info.burn_block_height)
    }

    /// Returns the height of the burnchain when the Stacks chain started running.
    fn get_burn_start_height(&self) -> u32 {
        0
    }

    fn get_v3_unlock_height(&self) -> u32 {
        0
    }

    fn get_pox_4_activation_height(&self) -> u32 {
        0
    }

    fn get_pox_prepare_length(&self) -> u32 {
        self.constants.pox_prepare_length
    }

    fn get_pox_reward_cycle_length(&self) -> u32 {
        self.constants.pox_reward_cycle_length
    }

    fn get_pox_rejection_fraction(&self) -> u64 {
        self.constants.pox_rejection_fraction
    }

    /// Returns the burnchain header hash for the given burn block height, as queried from the given SortitionId.
    ///
    /// Returns Some if `self.get_burn_start_height() <= height < self.get_burn_block_height(sorition_id)`, and None otherwise.
    fn get_burn_header_hash(
        &self,
        _height: u32,
        sortition_id: &SortitionId,
    ) -> Option<BurnchainHeaderHash> {
        self.sortition_lookup
            .get(sortition_id)
            .and_then(|id| self.store.get(id))
            .map(|block_info| block_info.burn_block_header_hash)
    }

    /// Lookup a `SortitionId` keyed to a `ConsensusHash`.
    ///
    /// Returns None if no block found.
    fn get_sortition_id_from_consensus_hash(
        &self,
        consensus_hash: &ConsensusHash,
    ) -> Option<SortitionId> {
        self.consensus_hash_lookup.get(consensus_hash).copied()
    }

    /// The epoch is defined as by a start and end height. This returns
    /// the epoch enclosing `height`.
    fn get_stacks_epoch(&self, _height: u32) -> Option<StacksEpoch> {
        None
    }

    fn get_stacks_epoch_by_epoch_id(&self, _epoch_id: &StacksEpochId) -> Option<StacksEpoch> {
        None
    }

    /// Get the PoX payout addresses for a given burnchain block
    fn get_pox_payout_addrs(
        &self,
        _height: u32,
        sortition_id: &SortitionId,
    ) -> Option<(Vec<TupleData>, u128)> {
        self.sortition_lookup
            .get(sortition_id)
            .and_then(|id| self.store.get(id))
            .map(|block_info| block_info.pox_payout_addrs.clone())
    }

    fn get_ast_rules(&self, _height: u32) -> clarity::vm::ast::ASTRules {
        clarity::vm::ast::ASTRules::PrecheckSize
    }
}

impl Datastore {
    pub fn open(_path_str: &str, _miner_tip: Option<&StacksBlockId>) -> Result<Datastore> {
        Ok(Datastore::new())
    }

    pub fn as_analysis_db(&mut self) -> AnalysisDatabase<'_> {
        AnalysisDatabase::new(self)
    }

    /// begin, commit, rollback a save point identified by key
    ///    this is used to clean up any data from aborted blocks
    ///     (NOT aborted transactions that is handled by the clarity vm directly).
    /// The block header hash is used for identifying savepoints.
    ///     this _cannot_ be used to rollback to arbitrary prior block hash, because that
    ///     blockhash would already have committed and no longer exist in the save point stack.
    /// this is a "lower-level" rollback than the roll backs performed in
    ///   ClarityDatabase or AnalysisDatabase -- this is done at the backing store level.

    pub fn begin(&mut self, _current: &StacksBlockId, _next: &StacksBlockId) {}
    pub fn rollback(&mut self) {}
    pub fn commit_mined_block(&mut self, _will_move_to: &StacksBlockId) {}
    pub fn commit_to(&mut self, _final_bhh: &StacksBlockId) {}

    pub fn get_chain_tip(&self) -> &StacksBlockId {
        &self.current_chain_tip
    }

    pub fn set_chain_tip(&mut self, bhh: &StacksBlockId) {
        self.current_chain_tip = *bhh;
    }

    pub fn put(&mut self, key: &str, value: &str) {
        let lookup_id = self
            .block_id_lookup
            .get(&self.open_chain_tip)
            .expect("Could not find current chain tip in block_id_lookup map");

        // if there isn't a store for the open chain_tip, make one and update the
        // entry for the block id in the lookup table
        if *lookup_id != self.open_chain_tip {
            self.store.insert(
                self.open_chain_tip,
                self.store
                    .get(lookup_id)
                    .unwrap_or_else(|| panic!("Block with ID {:?} does not exist", lookup_id))
                    .clone(),
            );

            self.block_id_lookup
                .insert(self.open_chain_tip, self.current_chain_tip);
        }

        if let Some(map) = self.store.get_mut(&self.open_chain_tip) {
            map.insert(key.to_string(), value.to_string());
        } else {
            panic!("Block does not exist for current chain tip");
        }
    }

    pub fn make_contract_hash_key(contract: &QualifiedContractIdentifier) -> String {
        format!("clarity-contract::{}", contract)
    }
}
