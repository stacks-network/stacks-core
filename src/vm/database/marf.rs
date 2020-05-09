use std::path::PathBuf;

use vm::types::{QualifiedContractIdentifier};
use vm::errors::{InterpreterError, CheckErrors, InterpreterResult as Result, IncomparableError, RuntimeErrorType};
use vm::database::{SqliteConnection, ClarityDatabase, HeadersDB, NULL_HEADER_DB,
                   ClaritySerializable, ClarityDeserializable};
use vm::analysis::{AnalysisDatabase};
use chainstate::stacks::index::marf::MARF;
use chainstate::stacks::index::{MARFValue, Error as MarfError, TrieHash};
use chainstate::stacks::index::storage::{TrieFileStorage};
use chainstate::stacks::index::proofs::{TrieMerkleProof};
use chainstate::burn::{VRFSeed, BlockHeaderHash};
use burnchains::BurnchainHeaderHash;
use std::convert::TryInto;
use util::hash::{to_hex, hex_bytes, Sha512Trunc256Sum};

/// The MarfedKV struct is used to wrap a MARF data structure and side-storage
///   for use as a K/V store for ClarityDB or the AnalysisDB.
/// The Clarity VM and type checker do not "know" to begin/commit the block they are currently processing:
///   each instantiation of the VM simply executes one transaction. So the block handling
///   loop will need to invoke these two methods (begin + commit) outside of the context of the VM.
///   NOTE: Clarity will panic if you try to execute it from a non-initialized MarfedKV context.
///   (See: vm::tests::with_marfed_environment()) 
pub struct MarfedKV {
    chain_tip: BlockHeaderHash,
    marf: MARF,
    // Since the MARF only stores 32 bytes of value,
    //   we need another storage
    side_store: SqliteConnection
}

pub struct MemoryBackingStore {
    side_store: SqliteConnection
}

// These functions generally _do not_ return errors, rather, any errors in the underlying storage
//    will _panic_. The rationale for this is that under no condition should the interpreter
//    attempt to continue processing in the event of an unexpected storage error.
pub trait ClarityBackingStore {
    /// put K-V data into the committed datastore
    fn put_all(&mut self, items: Vec<(String, String)>);
    /// fetch K-V out of the committed datastore
    fn get(&mut self, key: &str) -> Option<String>;
    fn get_with_proof(&mut self, key: &str) -> Option<(String, TrieMerkleProof)>;
    fn has_entry(&mut self, key: &str) -> bool {
        self.get(key).is_some()
    }

    /// change the current MARF context to service reads from a different chain_tip
    ///   used to implement time-shifted evaluation.
    /// returns the previous block header hash on success
    fn set_block_hash(&mut self, bhh: BlockHeaderHash) -> Result<BlockHeaderHash>;

    fn get_block_at_height(&mut self, height: u32) -> Option<BlockHeaderHash>;

    /// this function returns the current block height, as viewed by this marfed-kv structure,
    ///  i.e., it changes on time-shifted evaluation. the open_chain_tip functions always
    ///   return data about the chain tip that is currently open for writing.
    fn get_current_block_height(&mut self) -> u32;

    fn get_open_chain_tip_height(&mut self) -> u32;
    fn get_open_chain_tip(&mut self) -> BlockHeaderHash;
    fn get_side_store(&mut self) -> &mut SqliteConnection;

    /// The contract commitment is the hash of the contract, plus the block height in
    ///   which the contract was initialized.
    fn make_contract_commitment(&mut self, contract_hash: Sha512Trunc256Sum) -> String {
        let block_height = self.get_open_chain_tip_height();
        let cc = ContractCommitment { hash: contract_hash, block_height };
        cc.serialize()
    }

    /// This function is used to obtain a committed contract hash, and the block header hash of the block
    ///   in which the contract was initialized. This data is used to store contract metadata in the side
    ///   store.
    fn get_contract_hash(&mut self, contract: &QualifiedContractIdentifier) -> Result<(BlockHeaderHash, Sha512Trunc256Sum)> {
        let key = MarfedKV::make_contract_hash_key(contract);
        let contract_commitment = self.get(&key).map(|x| ContractCommitment::deserialize(&x))
            .ok_or_else(|| { CheckErrors::NoSuchContract(contract.to_string()) })?;
        let ContractCommitment { block_height, hash: contract_hash } = contract_commitment;
        let bhh = self.get_block_at_height(block_height)
            .expect("Should always be able to map from height to block hash when looking up contract information.");
        Ok((bhh, contract_hash))
    }

    fn insert_metadata(&mut self, contract: &QualifiedContractIdentifier, key: &str, value: &str) {
        let bhh = self.get_open_chain_tip();
        self.get_side_store().insert_metadata(&bhh, &contract.to_string(), key, value)
    }

    fn get_metadata(&mut self, contract: &QualifiedContractIdentifier, key: &str) -> Result<Option<String>> {
        let (bhh, _) = self.get_contract_hash(contract)?;
        Ok(self.get_side_store().get_metadata(&bhh, &contract.to_string(), key))
    }

    fn put_all_metadata(&mut self, mut items: Vec<((QualifiedContractIdentifier, String), String)>) {
        for ((contract, key), value) in items.drain(..) {
            self.insert_metadata(&contract, &key, &value);
        }
    }
}

pub struct ContractCommitment {
    pub hash: Sha512Trunc256Sum,
    pub block_height: u32
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
    pub fn open(path_str: &str, miner_tip: Option<&BlockHeaderHash>) -> Result<MarfedKV> {
        let mut path = PathBuf::from(path_str);

        std::fs::create_dir_all(&path)
            .map_err(|_| InterpreterError::FailedToCreateDataDirectory)?;

        path.push("marf");
        let marf_path = path.to_str()
            .ok_or_else(|| InterpreterError::BadFileName)?
            .to_string();

        path.pop();
        path.push("data.sqlite");
        let data_path = path.to_str()
            .ok_or_else(|| InterpreterError::BadFileName)?
            .to_string();

        let side_store = SqliteConnection::initialize(&data_path)?;
        let marf = MARF::from_path(&marf_path, miner_tip)
            .map_err(|err| InterpreterError::MarfFailure(IncomparableError{ err }))?;

        let chain_tip = match miner_tip {
            Some(ref miner_tip) => *miner_tip.clone(),
            None => TrieFileStorage::block_sentinel()
        };

        Ok( MarfedKV { marf, chain_tip, side_store } )
    }

    // used by benchmarks
    pub fn temporary() -> MarfedKV {
        use std::env;
        use rand::Rng;

        let mut path = env::temp_dir();
        let random_bytes = rand::thread_rng().gen::<[u8; 32]>();
        path.push(to_hex(&random_bytes));

        let marf = MARF::from_path(path.to_str().expect("Inexplicably non-UTF-8 character in filename"), None)
            .unwrap();
        let side_store = SqliteConnection::memory().unwrap();

        let chain_tip = TrieFileStorage::block_sentinel();

        MarfedKV { marf, chain_tip, side_store }
    }

    pub fn as_clarity_db<'a>(&'a mut self, headers_db: &'a dyn HeadersDB) -> ClarityDatabase<'a> {
        ClarityDatabase::new(self, headers_db)
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

    pub fn begin(&mut self, current: &BlockHeaderHash, next: &BlockHeaderHash) {
        self.marf.begin(current, next)
            .expect(&format!("ERROR: Failed to begin new MARF block {} - {})", current, next));
        self.chain_tip = self.marf.get_open_chain_tip()
            .expect("ERROR: Failed to get open MARF")
            .clone();
        self.side_store.begin(&self.chain_tip);
    }
    pub fn rollback(&mut self) {
        self.marf.drop_current();
        self.side_store.rollback(&self.chain_tip);
        self.chain_tip = TrieFileStorage::block_sentinel();
    }
    #[cfg(test)]
    pub fn test_commit(&mut self) {
        let bhh = self.chain_tip.clone();
        self.commit_to(&bhh);
    }
    // This is used by miners
    //   so that the block validation and processing logic doesn't
    //   reprocess the same data as if it were already loaded
    pub fn commit_mined_block(&mut self, will_move_to: &BlockHeaderHash) {
        debug!("commit_mined_block: ({}->{})", &self.chain_tip, will_move_to); 
        // rollback the side_store
        //    the side_store shouldn't commit data for blocks that won't be
        //    included in the processed chainstate (like a block constructed during mining)
        //    _if_ for some reason, we do want to be able to access that mined chain state in the future,
        //    we should probably commit the data to a different table which does not have uniqueness constraints.
        self.side_store.rollback(&self.chain_tip);
        self.marf.commit_mined(will_move_to)
            .expect("ERROR: Failed to commit MARF block");
    }
    pub fn commit_to(&mut self, final_bhh: &BlockHeaderHash) {
        debug!("commit_to({})", final_bhh); 
        self.side_store.commit_metadata_to(&self.chain_tip, final_bhh);
        self.side_store.commit(&self.chain_tip);
        self.marf.commit_to(final_bhh)
            .expect("ERROR: Failed to commit MARF block");
    }
    pub fn get_chain_tip(&self) -> &BlockHeaderHash {
        &self.chain_tip
    }

    pub fn set_chain_tip(&mut self, bhh: &BlockHeaderHash) {
        self.chain_tip = bhh.clone();
    }

    // This function *should not* be called by
    //   a smart-contract, rather it should only be used by the VM
    pub fn get_root_hash(&mut self) -> TrieHash {
        self.marf
            .get_root_hash_at(&self.chain_tip)
            .expect("FATAL: Failed to read MARF root hash")
    }

    pub fn get_marf(&mut self) -> &mut MARF {
        &mut self.marf
    }

    pub fn put(&mut self, key: &str, value: &str) {
        let marf_value = MARFValue::from_value(value);
        self.side_store.put(&marf_value.to_hex(), value);

        self.marf.insert(key, marf_value)
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

    fn set_block_hash(&mut self, bhh: BlockHeaderHash) -> Result<BlockHeaderHash> {
        self.marf.check_ancestor_block_hash(&bhh).map_err(|e| {
            match e {
                MarfError::NotFoundError => RuntimeErrorType::UnknownBlockHeaderHash(bhh),
                MarfError::NonMatchingForks(_,_) => RuntimeErrorType::UnknownBlockHeaderHash(bhh),
                _ => panic!("ERROR: Unexpected MARF failure: {}", e)
            }
        })?;

        let result = Ok(self.chain_tip);
        self.chain_tip = bhh;

        result
    }

    fn get_current_block_height(&mut self) -> u32 {
        self.marf.get_block_height_of(&self.chain_tip, &self.chain_tip)
            .expect("Unexpected MARF failure.")
            .expect("Failed to obtain current block height.")
    }

    fn get_block_at_height(&mut self, block_height: u32) -> Option<BlockHeaderHash> {
        self.marf.get_bhh_at_height(&self.chain_tip, block_height)
            .expect("Unexpected MARF failure.")
    }

    fn get_open_chain_tip(&mut self) -> BlockHeaderHash {
        self.marf.get_open_chain_tip()
            .expect("Attempted to get the open chain tip from an unopened context.")
            .clone()
    }

    fn get_open_chain_tip_height(&mut self) -> u32 {
        self.marf.get_open_chain_tip_height()
            .expect("Attempted to get the open chain tip from an unopened context.")
    }

    fn get_with_proof(&mut self, key: &str) -> Option<(String, TrieMerkleProof)> {
        self.marf.get_with_proof(&self.chain_tip, key)
            .or_else(|e| {
                match e {
                    MarfError::NotFoundError => Ok(None),
                    _ => Err(e)
                }
            })
            .expect("ERROR: Unexpected MARF Failure on GET")
            .map(|(marf_value, proof)| {
                let side_key = marf_value.to_hex();
                let data = self.side_store.get(&side_key)
                    .expect(&format!("ERROR: MARF contained value_hash not found in side storage: {}",
                                     side_key));
                (data, proof)
            })
    }

    fn get(&mut self, key: &str) -> Option<String> {
        self.marf.get(&self.chain_tip, key)
            .or_else(|e| {
                match e {
                    MarfError::NotFoundError => Ok(None),
                    _ => Err(e)
                }
            })
            .expect("ERROR: Unexpected MARF Failure on GET")
            .map(|marf_value| {
                let side_key = marf_value.to_hex();
                self.side_store.get(&side_key)
                    .expect(&format!("ERROR: MARF contained value_hash not found in side storage: {}",
                                     side_key))
            })
    }

    fn put_all(&mut self, mut items: Vec<(String, String)>) {
        let mut keys = Vec::new();
        let mut values = Vec::new();
        for (key, value) in items.drain(..) {
            let marf_value = MARFValue::from_value(&value);
            self.side_store.put(&marf_value.to_hex(), &value);
            keys.push(key);
            values.push(marf_value);
        }
        self.marf.insert_batch(&keys, values)
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
        ClarityDatabase::new(self, &NULL_HEADER_DB)
    }

    pub fn as_analysis_db<'a>(&'a mut self) -> AnalysisDatabase<'a> {
        AnalysisDatabase::new(self)
    }
}

impl ClarityBackingStore for MemoryBackingStore {
    fn set_block_hash(&mut self, bhh: BlockHeaderHash) -> Result<BlockHeaderHash> {
        Err(RuntimeErrorType::UnknownBlockHeaderHash(bhh).into())
    }

    fn get(&mut self, key: &str) -> Option<String> {
        self.side_store.get(key)
    }

    fn get_with_proof(&mut self, key: &str) -> Option<(String, TrieMerkleProof)> {
        self.side_store.get(key)
            .map(|x| {
                (x, TrieMerkleProof(vec![]))
            })
    }

    fn get_side_store(&mut self) -> &mut SqliteConnection {
        &mut self.side_store
    }

    fn get_block_at_height(&mut self, height: u32) -> Option<BlockHeaderHash> {
        if height == 0 {
            Some(TrieFileStorage::block_sentinel())
        } else {
            None
        }
    }

    fn get_open_chain_tip(&mut self) -> BlockHeaderHash {
        TrieFileStorage::block_sentinel()
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
