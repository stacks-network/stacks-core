// Copyright (C) 2013-2020 Blocstack PBC, a public benefit corporation
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

use std::path::PathBuf;

use burnchains::BurnchainHeaderHash;
use chainstate::burn::{BlockHeaderHash, VRFSeed};
use chainstate::stacks::index::marf::{MarfConnection, MARF};
use chainstate::stacks::index::proofs::TrieMerkleProof;
use chainstate::stacks::index::storage::TrieFileStorage;
use chainstate::stacks::index::{Error as MarfError, MARFValue, MarfTrieId, TrieHash};
use chainstate::stacks::StacksBlockId;
use std::convert::TryInto;
use util::hash::{hex_bytes, to_hex, Sha512Trunc256Sum};
use vm::analysis::AnalysisDatabase;
use vm::database::{
    BurnStateDB, ClarityDatabase, ClarityDeserializable, ClaritySerializable, HeadersDB,
    SqliteConnection, NULL_BURN_STATE_DB, NULL_HEADER_DB,
};
use vm::errors::{
    CheckErrors, IncomparableError, InterpreterError, InterpreterResult as Result, RuntimeErrorType,
};
use vm::types::QualifiedContractIdentifier;

/// The MarfedKV struct is used to wrap a MARF data structure and side-storage
///   for use as a K/V store for ClarityDB or the AnalysisDB.
/// The Clarity VM and type checker do not "know" to begin/commit the block they are currently processing:
///   each instantiation of the VM simply executes one transaction. So the block handling
///   loop will need to invoke these two methods (begin + commit) outside of the context of the VM.
///   NOTE: Clarity will panic if you try to execute it from a non-initialized MarfedKV context.
///   (See: vm::tests::with_marfed_environment())
pub struct MarfedKV {
    chain_tip: StacksBlockId,
    marf: MARF<StacksBlockId>,
    // Since the MARF only stores 32 bytes of value,
    //   we need another storage
    side_store: SqliteConnection,
}

pub struct MemoryBackingStore {
    side_store: SqliteConnection,
}

// These functions generally _do not_ return errors, rather, any errors in the underlying storage
//    will _panic_. The rationale for this is that under no condition should the interpreter
//    attempt to continue processing in the event of an unexpected storage error.
pub trait ClarityBackingStore {
    /// put K-V data into the committed datastore
    fn put_all(&mut self, items: Vec<(String, String)>);
    /// fetch K-V out of the committed datastore
    fn get(&mut self, key: &str) -> Option<String>;
    fn get_with_proof(&mut self, key: &str) -> Option<(String, TrieMerkleProof<StacksBlockId>)>;
    fn has_entry(&mut self, key: &str) -> bool {
        self.get(key).is_some()
    }

    /// change the current MARF context to service reads from a different chain_tip
    ///   used to implement time-shifted evaluation.
    /// returns the previous block header hash on success
    fn set_block_hash(&mut self, bhh: StacksBlockId) -> Result<StacksBlockId>;

    fn get_block_at_height(&mut self, height: u32) -> Option<StacksBlockId>;

    /// this function returns the current block height, as viewed by this marfed-kv structure,
    ///  i.e., it changes on time-shifted evaluation. the open_chain_tip functions always
    ///   return data about the chain tip that is currently open for writing.
    fn get_current_block_height(&mut self) -> u32;

    fn get_open_chain_tip_height(&mut self) -> u32;
    fn get_open_chain_tip(&mut self) -> StacksBlockId;
    fn get_side_store(&mut self) -> &mut SqliteConnection;

    /// The contract commitment is the hash of the contract, plus the block height in
    ///   which the contract was initialized.
    fn make_contract_commitment(&mut self, contract_hash: Sha512Trunc256Sum) -> String {
        let block_height = self.get_open_chain_tip_height();
        let cc = ContractCommitment {
            hash: contract_hash,
            block_height,
        };
        cc.serialize()
    }

    /// This function is used to obtain a committed contract hash, and the block header hash of the block
    ///   in which the contract was initialized. This data is used to store contract metadata in the side
    ///   store.
    fn get_contract_hash(
        &mut self,
        contract: &QualifiedContractIdentifier,
    ) -> Result<(StacksBlockId, Sha512Trunc256Sum)> {
        let key = MarfedKV::make_contract_hash_key(contract);
        let contract_commitment = self
            .get(&key)
            .map(|x| ContractCommitment::deserialize(&x))
            .ok_or_else(|| CheckErrors::NoSuchContract(contract.to_string()))?;
        let ContractCommitment {
            block_height,
            hash: contract_hash,
        } = contract_commitment;
        let bhh = self.get_block_at_height(block_height)
            .expect("Should always be able to map from height to block hash when looking up contract information.");
        Ok((bhh, contract_hash))
    }

    fn insert_metadata(&mut self, contract: &QualifiedContractIdentifier, key: &str, value: &str) {
        let bhh = self.get_open_chain_tip();
        self.get_side_store()
            .insert_metadata(&bhh, &contract.to_string(), key, value)
    }

    fn get_metadata(
        &mut self,
        contract: &QualifiedContractIdentifier,
        key: &str,
    ) -> Result<Option<String>> {
        let (bhh, _) = self.get_contract_hash(contract)?;
        Ok(self
            .get_side_store()
            .get_metadata(&bhh, &contract.to_string(), key))
    }

    fn put_all_metadata(
        &mut self,
        mut items: Vec<((QualifiedContractIdentifier, String), String)>,
    ) {
        for ((contract, key), value) in items.drain(..) {
            self.insert_metadata(&contract, &key, &value);
        }
    }
}

pub struct ContractCommitment {
    pub hash: Sha512Trunc256Sum,
    pub block_height: u32,
}

impl ClaritySerializable for ContractCommitment {
    fn serialize(&self) -> String {
        format!("{}{}", self.hash, to_hex(&self.block_height.to_be_bytes()))
    }
}

impl ClarityDeserializable<ContractCommitment> for ContractCommitment {
    fn deserialize(input: &str) -> ContractCommitment {
        assert_eq!(input.len(), 72);
        let hash = Sha512Trunc256Sum::from_hex(&input[0..64]).expect("Hex decode fail.");
        let height_bytes = hex_bytes(&input[64..72]).expect("Hex decode fail.");
        let block_height = u32::from_be_bytes(height_bytes.as_slice().try_into().unwrap());
        ContractCommitment { hash, block_height }
    }
}

impl MarfedKV {
    fn setup_db(
        path_str: &str,
        unconfirmed: bool,
    ) -> Result<(SqliteConnection, MARF<StacksBlockId>)> {
        let mut path = PathBuf::from(path_str);

        std::fs::create_dir_all(&path)
            .map_err(|_| InterpreterError::FailedToCreateDataDirectory)?;

        path.push("marf");
        let marf_path = path
            .to_str()
            .ok_or_else(|| InterpreterError::BadFileName)?
            .to_string();

        path.pop();
        path.push("data.sqlite");
        let data_path = path
            .to_str()
            .ok_or_else(|| InterpreterError::BadFileName)?
            .to_string();

        let side_store = SqliteConnection::initialize(&data_path)?;
        let marf = if unconfirmed {
            MARF::from_path_unconfirmed(&marf_path)
                .map_err(|err| InterpreterError::MarfFailure(IncomparableError { err }))?
        } else {
            MARF::from_path(&marf_path)
                .map_err(|err| InterpreterError::MarfFailure(IncomparableError { err }))?
        };

        Ok((side_store, marf))
    }

    pub fn open(path_str: &str, miner_tip: Option<&StacksBlockId>) -> Result<MarfedKV> {
        let (side_store, marf) = MarfedKV::setup_db(path_str, false)?;
        let chain_tip = match miner_tip {
            Some(ref miner_tip) => *miner_tip.clone(),
            None => StacksBlockId::sentinel(),
        };

        Ok(MarfedKV {
            marf,
            chain_tip,
            side_store,
        })
    }

    pub fn open_unconfirmed(path_str: &str, miner_tip: Option<&StacksBlockId>) -> Result<MarfedKV> {
        let (side_store, marf) = MarfedKV::setup_db(path_str, true)?;
        let chain_tip = match miner_tip {
            Some(ref miner_tip) => *miner_tip.clone(),
            None => StacksBlockId::sentinel(),
        };

        Ok(MarfedKV {
            marf,
            chain_tip,
            side_store,
        })
    }

    // used by benchmarks
    pub fn temporary() -> MarfedKV {
        use rand::Rng;
        use std::env;

        let mut path = env::temp_dir();
        let random_bytes = rand::thread_rng().gen::<[u8; 32]>();
        path.push(to_hex(&random_bytes));

        let marf = MARF::from_path(
            path.to_str()
                .expect("Inexplicably non-UTF-8 character in filename"),
        )
        .unwrap();
        let side_store = SqliteConnection::memory().unwrap();

        let chain_tip = StacksBlockId::sentinel();

        MarfedKV {
            marf,
            chain_tip,
            side_store,
        }
    }

    pub fn as_clarity_db<'a>(
        &'a mut self,
        headers_db: &'a dyn HeadersDB,
        burn_state_db: &'a dyn BurnStateDB,
    ) -> ClarityDatabase<'a> {
        ClarityDatabase::new(self, headers_db, burn_state_db)
    }

    pub fn as_analysis_db<'a>(&'a mut self) -> AnalysisDatabase<'a> {
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

    pub fn begin(&mut self, current: &StacksBlockId, next: &StacksBlockId) {
        {
            let mut tx = self.marf.begin_tx().expect(&format!(
                "ERROR: Failed to begin new MARF block {} - {})",
                current, next
            ));
            tx.begin(current, next).expect(&format!(
                "ERROR: Failed to begin new MARF block {} - {})",
                current, next
            ));
            tx.commit_tx();
        }
        self.chain_tip = self
            .marf
            .get_open_chain_tip()
            .expect("ERROR: Failed to get open MARF")
            .clone();
        self.side_store.begin(&self.chain_tip);
    }

    pub fn begin_unconfirmed(&mut self, current: &StacksBlockId) {
        {
            let mut tx = self.marf.begin_tx().expect(&format!(
                "ERROR: Failed to begin new unconfirmed MARF block for {})",
                current
            ));
            tx.begin_unconfirmed(current).expect(&format!(
                "ERROR: Failed to begin new unconfirmed MARF block for {})",
                current
            ));
            tx.commit_tx();
        }
        self.chain_tip = self
            .marf
            .get_open_chain_tip()
            .expect("ERROR: Failed to get open MARF")
            .clone();
        self.side_store.begin(&self.chain_tip);
    }

    pub fn rollback(&mut self) {
        self.marf.drop_current();
        self.side_store.rollback(&self.chain_tip);
        self.chain_tip = StacksBlockId::sentinel();
    }

    pub fn rollback_unconfirmed(&mut self) {
        self.marf.drop_unconfirmed();
        self.side_store.rollback_unconfirmed(&self.chain_tip);
        self.chain_tip = StacksBlockId::sentinel();
    }

    #[cfg(test)]
    pub fn test_commit(&mut self) {
        let bhh = self.chain_tip.clone();
        self.commit_to(&bhh);
    }

    // This is used by miners
    //   so that the block validation and processing logic doesn't
    //   reprocess the same data as if it were already loaded
    pub fn commit_mined_block(&mut self, will_move_to: &StacksBlockId) {
        debug!(
            "commit_mined_block: ({}->{})",
            &self.chain_tip, will_move_to
        );
        // rollback the side_store
        //    the side_store shouldn't commit data for blocks that won't be
        //    included in the processed chainstate (like a block constructed during mining)
        //    _if_ for some reason, we do want to be able to access that mined chain state in the future,
        //    we should probably commit the data to a different table which does not have uniqueness constraints.
        self.side_store.rollback(&self.chain_tip);
        let _ = self.marf.commit_mined(will_move_to).map_err(|e| {
            error!(
                "Failed to commit to mined MARF block {}: {:?}",
                &will_move_to, &e
            );
            panic!();
        });
    }

    pub fn commit_to(&mut self, final_bhh: &StacksBlockId) {
        debug!("commit_to({})", final_bhh);
        self.side_store
            .commit_metadata_to(&self.chain_tip, final_bhh);
        self.side_store.commit(&self.chain_tip);
        let _ = self.marf.commit_to(final_bhh).map_err(|e| {
            error!("Failed to commit to MARF block {}: {:?}", &final_bhh, &e);
            panic!();
        });
    }

    pub fn commit_unconfirmed(&mut self) {
        debug!("commit_unconfirmed()");
        // NOTE: Can omit commit_metadata_to, since the block header hash won't change
        // self.side_store.commit_metadata_to(&self.chain_tip, final_bhh);
        self.side_store.commit(&self.chain_tip);
        self.marf
            .commit()
            .expect("ERROR: Failed to commit MARF block");
    }

    pub fn get_chain_tip(&self) -> &StacksBlockId {
        &self.chain_tip
    }

    pub fn set_chain_tip(&mut self, bhh: &StacksBlockId) {
        self.chain_tip = bhh.clone();
    }

    // This function *should not* be called by
    //   a smart-contract, rather it should only be used by the VM
    pub fn get_root_hash(&mut self) -> TrieHash {
        self.marf
            .get_root_hash_at(&self.chain_tip)
            .expect("FATAL: Failed to read MARF root hash")
    }

    pub fn get_marf(&mut self) -> &mut MARF<StacksBlockId> {
        &mut self.marf
    }

    pub fn put(&mut self, key: &str, value: &str) {
        let marf_value = MARFValue::from_value(value);
        self.side_store.put(&marf_value.to_hex(), value);

        self.marf
            .insert(key, marf_value)
            .expect("ERROR: Unexpected MARF Failure")
    }

    pub fn make_contract_hash_key(contract: &QualifiedContractIdentifier) -> String {
        format!("clarity-contract::{}", contract)
    }
}

impl ClarityBackingStore for MarfedKV {
    fn get_side_store(&mut self) -> &mut SqliteConnection {
        &mut self.side_store
    }

    fn set_block_hash(&mut self, bhh: StacksBlockId) -> Result<StacksBlockId> {
        self.marf
            .check_ancestor_block_hash(&bhh)
            .map_err(|e| match e {
                MarfError::NotFoundError => {
                    test_debug!("No such block {:?} (NotFoundError)", &bhh);
                    RuntimeErrorType::UnknownBlockHeaderHash(BlockHeaderHash(bhh.0))
                }
                MarfError::NonMatchingForks(_bh1, _bh2) => {
                    test_debug!(
                        "No such block {:?} (NonMatchingForks({}, {}))",
                        &bhh,
                        BlockHeaderHash(_bh1),
                        BlockHeaderHash(_bh2)
                    );
                    RuntimeErrorType::UnknownBlockHeaderHash(BlockHeaderHash(bhh.0))
                }
                _ => panic!("ERROR: Unexpected MARF failure: {}", e),
            })?;

        let result = Ok(self.chain_tip);
        self.chain_tip = bhh;

        result
    }

    fn get_current_block_height(&mut self) -> u32 {
        self.marf
            .get_block_height_of(&self.chain_tip, &self.chain_tip)
            .expect("Unexpected MARF failure.")
            .expect("Failed to obtain current block height.")
    }

    fn get_block_at_height(&mut self, block_height: u32) -> Option<StacksBlockId> {
        self.marf
            .get_bhh_at_height(&self.chain_tip, block_height)
            .expect("Unexpected MARF failure.")
            .map(|x| StacksBlockId(x.to_bytes()))
    }

    fn get_open_chain_tip(&mut self) -> StacksBlockId {
        StacksBlockId(
            self.marf
                .get_open_chain_tip()
                .expect("Attempted to get the open chain tip from an unopened context.")
                .clone()
                .to_bytes(),
        )
    }

    fn get_open_chain_tip_height(&mut self) -> u32 {
        self.marf
            .get_open_chain_tip_height()
            .expect("Attempted to get the open chain tip from an unopened context.")
    }

    fn get_with_proof(&mut self, key: &str) -> Option<(String, TrieMerkleProof<StacksBlockId>)> {
        self.marf
            .get_with_proof(&self.chain_tip, key)
            .or_else(|e| match e {
                MarfError::NotFoundError => Ok(None),
                _ => Err(e),
            })
            .expect("ERROR: Unexpected MARF Failure on GET")
            .map(|(marf_value, proof)| {
                let side_key = marf_value.to_hex();
                let data = self.side_store.get(&side_key).expect(&format!(
                    "ERROR: MARF contained value_hash not found in side storage: {}",
                    side_key
                ));
                (data, proof)
            })
    }

    fn get(&mut self, key: &str) -> Option<String> {
        trace!("MarfedKV get: {:?} tip={}", key, &self.chain_tip);
        self.marf
            .get(&self.chain_tip, key)
            .or_else(|e| match e {
                MarfError::NotFoundError => {
                    trace!(
                        "MarfedKV get {:?} off of {:?}: not found",
                        key,
                        &self.chain_tip
                    );
                    Ok(None)
                }
                _ => Err(e),
            })
            .expect("ERROR: Unexpected MARF Failure on GET")
            .map(|marf_value| {
                let side_key = marf_value.to_hex();
                trace!("MarfedKV get side-key for {:?}: {:?}", key, &side_key);
                self.side_store.get(&side_key).expect(&format!(
                    "ERROR: MARF contained value_hash not found in side storage: {}",
                    side_key
                ))
            })
    }

    fn put_all(&mut self, mut items: Vec<(String, String)>) {
        let mut keys = Vec::new();
        let mut values = Vec::new();
        for (key, value) in items.drain(..) {
            trace!("MarfedKV put '{}' = '{}'", &key, &value);
            let marf_value = MARFValue::from_value(&value);
            self.side_store.put(&marf_value.to_hex(), &value);
            keys.push(key);
            values.push(marf_value);
        }
        self.marf
            .insert_batch(&keys, values)
            .expect("ERROR: Unexpected MARF Failure");
    }
}

impl MemoryBackingStore {
    pub fn new() -> MemoryBackingStore {
        let side_store = SqliteConnection::memory().unwrap();

        let mut memory_marf = MemoryBackingStore { side_store };

        memory_marf.as_clarity_db().initialize();

        memory_marf
    }

    pub fn as_clarity_db<'a>(&'a mut self) -> ClarityDatabase<'a> {
        ClarityDatabase::new(self, &NULL_HEADER_DB, &NULL_BURN_STATE_DB)
    }

    pub fn as_analysis_db<'a>(&'a mut self) -> AnalysisDatabase<'a> {
        AnalysisDatabase::new(self)
    }
}

impl ClarityBackingStore for MemoryBackingStore {
    fn set_block_hash(&mut self, bhh: StacksBlockId) -> Result<StacksBlockId> {
        Err(RuntimeErrorType::UnknownBlockHeaderHash(BlockHeaderHash(bhh.0)).into())
    }

    fn get(&mut self, key: &str) -> Option<String> {
        self.side_store.get(key)
    }

    fn get_with_proof(&mut self, key: &str) -> Option<(String, TrieMerkleProof<StacksBlockId>)> {
        self.side_store
            .get(key)
            .map(|x| (x, TrieMerkleProof(vec![])))
    }

    fn get_side_store(&mut self) -> &mut SqliteConnection {
        &mut self.side_store
    }

    fn get_block_at_height(&mut self, height: u32) -> Option<StacksBlockId> {
        if height == 0 {
            Some(StacksBlockId::sentinel())
        } else {
            None
        }
    }

    fn get_open_chain_tip(&mut self) -> StacksBlockId {
        StacksBlockId::sentinel()
    }

    fn get_open_chain_tip_height(&mut self) -> u32 {
        0
    }

    fn get_current_block_height(&mut self) -> u32 {
        0
    }

    fn put_all(&mut self, mut items: Vec<(String, String)>) {
        for (key, value) in items.drain(..) {
            self.side_store.put(&key, &value);
        }
    }
}
