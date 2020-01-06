use std::path::PathBuf;

use vm::errors::{ InterpreterError, InterpreterResult as Result, IncomparableError, RuntimeErrorType };
use vm::database::{KeyValueStorage, SqliteConnection, ClarityDatabase};
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
    marf: MARF,
    // Since the MARF only stores 32 bytes of value,
    //   we need another storage
    side_store: SqliteConnection
}

#[cfg(test)]
pub fn temporary_marf() -> MarfedKV {
    in_memory_marf()
}

pub fn in_memory_marf() -> MarfedKV {
    use std::env;
    use rand::Rng;
    use util::hash::to_hex;
    use std::collections::HashMap;

    let mut path = env::temp_dir();
    let random_bytes = rand::thread_rng().gen::<[u8; 32]>();
    path.push(to_hex(&random_bytes));

    let marf = MARF::from_path(path.to_str().expect("Inexplicably non-UTF-8 character in filename"), None)
        .unwrap();
    let side_store = SqliteConnection::memory().unwrap();

    let chain_tip = TrieFileStorage::block_sentinel();

    MarfedKV { chain_tip, marf, side_store }
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

    Ok( MarfedKV { chain_tip, marf, side_store } )
}

impl MarfedKV {
    pub fn as_clarity_db<'a>(&'a mut self) -> ClarityDatabase<'a> {
        ClarityDatabase::new(self)
    }

    pub fn as_analysis_db<'a>(&'a mut self) -> AnalysisDatabase<'a> {
        AnalysisDatabase::new(self)
    }

    pub fn begin(&mut self, current: &BlockHeaderHash, next: &BlockHeaderHash) {
        self.marf.begin(current, next)
            .expect(&format!("ERROR: Failed to begin new MARF block {} - {})", current.to_hex(), next.to_hex()));
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
    pub fn commit(&mut self) {
        self.side_store.commit(&self.chain_tip);
        self.marf.commit()
            .expect("ERROR: Failed to commit MARF block");
    }
    pub fn commit_to(&mut self, final_bhh: &BlockHeaderHash) {
        self.side_store.commit(&self.chain_tip);
        self.marf.commit_to(final_bhh)
            .expect("ERROR: Failed to commit MARF block");
    }
    pub fn get_chain_tip(&self) -> &BlockHeaderHash {
        &self.chain_tip
    }
    pub fn get_root_hash(&mut self) -> TrieHash {
        self.marf.get_root_hash_at(&self.chain_tip)
            .expect("FATAL: Failed to read MARF root hash")
    }
    pub fn get_marf(&mut self) -> &mut MARF {
        &mut self.marf
    }

    #[cfg(test)]
    pub fn get_side_store(&mut self) -> &mut SqliteConnection {
        &mut self.side_store
    }
}

impl MarfedKV {
    /// returns the previous block header hash
    pub fn set_block_hash(&mut self, bhh: BlockHeaderHash) -> Result<BlockHeaderHash> {
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

    pub fn put(&mut self, key: &str, value: &str) {
        let marf_value = MARFValue::from_value(value);

        self.side_store.put(&marf_value.to_hex(), value);

        self.marf.insert(key, marf_value)
            .expect("ERROR: Unexpected MARF Failure")
    }

    pub fn put_non_consensus(&mut self, key: &str, value: &str) {
        panic!("Not implemented");
    }

    pub fn put_all_non_consensus(&mut self, mut items: Vec<(String, String)>) {
        for (key, value) in items.drain(..) {
            self.put_non_consensus(&key, &value);
        }
    }

    pub fn get_non_consensus(&mut self, key: &str) -> Option<String> {
        panic!("Not implemented");
    }

    pub fn get(&mut self, key: &str) -> Option<String> {
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

    pub fn has_entry(&mut self, key: &str) -> bool {
        self.get(key).is_some()
    }

    pub fn put_all(&mut self, mut items: Vec<(String, String)>) {
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
