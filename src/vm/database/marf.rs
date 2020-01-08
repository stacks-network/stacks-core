use std::path::PathBuf;

use vm::types::{QualifiedContractIdentifier};
use vm::errors::{InterpreterError, CheckErrors, InterpreterResult as Result, IncomparableError, RuntimeErrorType};
use vm::database::{SqliteConnection, ClarityDatabase};
use vm::analysis::{AnalysisDatabase};
use chainstate::stacks::index::marf::MARF;
use chainstate::stacks::index::{MARFValue, Error as MarfError, TrieHash};
use chainstate::stacks::index::storage::{TrieFileStorage};
use chainstate::burn::BlockHeaderHash;

/// The MarfedKV struct is used to wrap a MARF data structure and side-storage
///   for use as a K/V store for ClarityDB or the AnalysisDB.
/// The Clarity VM and type checker do not "know" to begin/commit the block they are currently processing:
///   each instantiation of the VM simply executes one transaction. So the block handling
///   loop will need to invoke these two methods (begin + commit) outside of the context of the VM.
///   NOTE: Clarity will panic if you try to execute it from a non-initialized MarfedKV context.
///   (See: vm::tests::with_marfed_environment()) 
pub struct MarfedKV {
    chain_tip: BlockHeaderHash,
    // the MARF is option'ed, if None, then this KV is "marfless".
    //    this is used for raw evals, testing --- use cases formerly that used a generic datastore.
    // functions which _assume_ a MARF present will panic if the MARF is None.
    marf: Option<MARF>,
    // Since the MARF only stores 32 bytes of value,
    //   we need another storage
    side_store: SqliteConnection
}

pub fn temporary_marf() -> MarfedKV {
    use std::env;
    use rand::Rng;
    use util::hash::to_hex;

    let mut path = env::temp_dir();
    let random_bytes = rand::thread_rng().gen::<[u8; 32]>();
    path.push(to_hex(&random_bytes));

    let marf = MARF::from_path(path.to_str().expect("Inexplicably non-UTF-8 character in filename"), None)
        .unwrap();
    let side_store = SqliteConnection::memory().unwrap();

    let chain_tip = TrieFileStorage::block_sentinel();

    MarfedKV { marf: Some(marf), chain_tip, side_store }
}

pub fn in_memory_marf() -> MarfedKV {
    let side_store = SqliteConnection::memory().unwrap();
    let chain_tip = TrieFileStorage::block_sentinel();

    let mut memory_marf = MarfedKV { marf: None, chain_tip, side_store };

    memory_marf.as_clarity_db().initialize();

    memory_marf
}

pub fn sqlite_marf(path_str: &str, miner_tip: Option<&BlockHeaderHash>) -> Result<MarfedKV> {
    let mut path = PathBuf::from(path_str);
    std::fs::create_dir_all(&path)
        .map_err(|err| InterpreterError::FailedToCreateDataDirectory)?;

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

    Ok( MarfedKV { marf: Some(marf), chain_tip, side_store } )
}

impl MarfedKV {
    pub fn as_clarity_db<'a>(&'a mut self) -> ClarityDatabase<'a> {
        ClarityDatabase::new(self)
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
        let marf = self.marf.as_mut().unwrap();
        marf.begin(current, next)
            .expect(&format!("ERROR: Failed to begin new MARF block {} - {})", current.to_hex(), next.to_hex()));
        self.chain_tip = marf.get_open_chain_tip()
            .expect("ERROR: Failed to get open MARF")
            .clone();
        self.side_store.begin(&self.chain_tip);
    }
    pub fn rollback(&mut self) {
        self.marf.as_mut().unwrap().drop_current();
        self.side_store.rollback(&self.chain_tip);
        self.chain_tip = TrieFileStorage::block_sentinel();
    }
    pub fn commit(&mut self) {
        // AARON: I'm not sure this path should be considered 'legal' anymore,
        //     and may want to delete or panic.
        self.side_store.commit(&self.chain_tip);
        self.marf.as_mut().unwrap().commit()
            .expect("ERROR: Failed to commit MARF block");
    }
    pub fn commit_to(&mut self, final_bhh: &BlockHeaderHash) {
        self.side_store.commit_metadata_to(&self.chain_tip, final_bhh);
        self.side_store.commit(&self.chain_tip);
        self.marf.as_mut().unwrap().commit_to(final_bhh)
            .expect("ERROR: Failed to commit MARF block");
    }
    pub fn get_chain_tip(&self) -> &BlockHeaderHash {
        &self.chain_tip
    }

    // This function *should not* be called by
    //   a smart-contract, rather it should only be used by the VM
    pub fn get_root_hash(&mut self) -> TrieHash {
        self.marf.as_mut().unwrap()
            .get_root_hash_at(&self.chain_tip)
            .expect("FATAL: Failed to read MARF root hash")
    }

    pub fn get_marf(&mut self) -> &mut MARF {
        self.marf.as_mut().unwrap()
    }

    #[cfg(test)]
    pub fn get_side_store(&mut self) -> &mut SqliteConnection {
        &mut self.side_store
    }
}

// These functions _do not_ return errors, rather, any errors in the underlying storage
//    will _panic_. The rationale for this is that under no condition should the interpreter
//    attempt to continue processing in the event of an unexpected storage error.
impl MarfedKV {
    /// returns the previous block header hash on success
    pub fn set_block_hash(&mut self, bhh: BlockHeaderHash) -> Result<BlockHeaderHash> {
        let marf = self.marf.as_mut().ok_or_else(|| RuntimeErrorType::UnknownBlockHeaderHash(bhh))?;

        marf.check_ancestor_block_hash(&bhh).map_err(|e| {
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

    pub fn put(&mut self, key: &str, value: &str) {
        match self.marf {
            Some(ref mut marf) => {
                let marf_value = MARFValue::from_value(value);

                self.side_store.put(&marf_value.to_hex(), value);

                marf.insert(key, marf_value)
                    .expect("ERROR: Unexpected MARF Failure")
            },
            None => {
                self.side_store.put(key, value);
            }
        }
    }

    pub fn get_with_bhh(&mut self, key: &str) -> Option<(BlockHeaderHash, String)> {
        match self.marf {
            Some(ref mut marf) => {
                marf.get_with_bhh(&self.chain_tip, key)
                    .or_else(|e| {
                        match e {
                            MarfError::NotFoundError => Ok(None),
                            _ => Err(e)
                        }
                    })
                    .expect("ERROR: Unexpected MARF Failure on GET")
                    .map(|(marf_value, bhh)| {
                        let side_key = marf_value.to_hex();
                        (bhh, 
                         self.side_store.get(&side_key)
                         .expect(&format!("ERROR: MARF contained value_hash not found in side storage: {}",
                                          side_key)))
                    })
            },
            None => {
                self.get(key).map(|x| {
                    (TrieFileStorage::block_sentinel(), x)
                })
            }
        }
    }


    pub fn make_contract_hash_key(contract: &QualifiedContractIdentifier) -> String {
        format!("clarity-contract::{}", contract)
    }

    pub fn get_contract_hash(&mut self, contract: &QualifiedContractIdentifier) -> Result<(BlockHeaderHash, String)> {
        let key = MarfedKV::make_contract_hash_key(contract);
        self.get_with_bhh(&key)
            .ok_or_else(|| { CheckErrors::NoSuchContract(contract.to_string()).into() })
    }

    pub fn get_metadata(&mut self, contract: &QualifiedContractIdentifier, key: &str) -> Result<Option<String>> {
        let (bhh, _) = self.get_contract_hash(contract)?;
        Ok(self.side_store.get_metadata(&bhh, &contract.to_string(), key))
    }

    pub fn insert_metadata(&mut self, contract: &QualifiedContractIdentifier, key: &str, value: &str) -> bool {
        match self.marf {
            Some(ref marf) => {
                let bhh = marf.get_open_chain_tip().expect("Metadata write attempted on unopened MARF");
                self.side_store.insert_metadata(bhh, &contract.to_string(), key, value)
            },
            None => {
                let bhh = TrieFileStorage::block_sentinel();
                self.side_store.insert_metadata(&bhh, &contract.to_string(), key, value)
            }
        }
    }

    pub fn put_all_metadata(&mut self, mut items: Vec<((QualifiedContractIdentifier, String), String)>) {
        for ((contract, key), value) in items.drain(..) {
            self.insert_metadata(&contract, &key, &value);
        }
    }

    pub fn get(&mut self, key: &str) -> Option<String> {
        match self.marf {
            Some(ref mut marf) => {
                marf.get(&self.chain_tip, key)
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
            },
            None => {
                self.side_store.get(key)
            }
        }
    }

    pub fn has_entry(&mut self, key: &str) -> bool {
        self.get(key).is_some()
    }

    pub fn put_all(&mut self, mut items: Vec<(String, String)>) {
        match self.marf {
            None => {
                for (key, value) in items.drain(..) {
                    self.side_store.put(&key, &value);
                }
            },
            Some(ref mut marf) => {
                let mut keys = Vec::new();
                let mut values = Vec::new();
                for (key, value) in items.drain(..) {
                    let marf_value = MARFValue::from_value(&value);
                    self.side_store.put(&marf_value.to_hex(), &value);
                    keys.push(key);
                    values.push(marf_value);
                }
                marf.insert_batch(&keys, values)
                    .expect("ERROR: Unexpected MARF Failure");
            }
        }
    }

}
