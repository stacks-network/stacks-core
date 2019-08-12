use std::path::PathBuf;

use vm::errors::{ InterpreterError, InterpreterResult as Result, IncomparableError };
use vm::database::{KeyValueStorage, SqliteConnection};
use chainstate::stacks::index::marf::MARF;
use chainstate::stacks::index::{MARFValue, Error as MarfError};
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
    side_store: Box<KeyValueStorage>
}

#[cfg(test)]
pub fn temporary_marf() -> MarfedKV {
    use std::env;
    use rand::Rng;
    use util::hash::to_hex;
    use std::collections::HashMap;

    let mut path = env::temp_dir();
    let random_bytes = rand::thread_rng().gen::<[u8; 32]>();
    path.push(to_hex(&random_bytes));

    let mut marf = MARF::from_path(path.to_str().expect("Inexplicably non-UTF-8 character in filename"))
        .unwrap();
    let side_store = Box::new(HashMap::new());

    let chain_tip = marf.chain_tips().get(0).cloned()
        .unwrap_or_else(|| TrieFileStorage::block_sentinel());

    MarfedKV { chain_tip, marf, side_store }
}

/// If chain_tip is None, this will try to figure out a reasonable value for a starting
///   chain_tip. If the MARF already has some chain_tips, then it selects ordinal 0.
///   Otherwise, it uses the block_sentinel.
pub fn sqlite_marf(path_str: &str, chain_tip: Option<BlockHeaderHash>) -> Result<MarfedKV> {
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

    let side_store = Box::new(SqliteConnection::initialize(&data_path)?);
    let mut marf = MARF::from_path(&marf_path)
        .map_err(|err| InterpreterError::MarfFailure(IncomparableError{ err }))?;

    let chain_tip = chain_tip
        .or_else(|| marf.chain_tips().get(0).cloned())
        .unwrap_or_else(|| TrieFileStorage::block_sentinel());


    Ok( MarfedKV { chain_tip, marf, side_store } )
}

impl MarfedKV {
    pub fn begin(&mut self, current: &BlockHeaderHash, next: &BlockHeaderHash) {
        self.marf.begin(current, next)
            .unwrap();
        self.chain_tip = next.clone();
    }
    pub fn commit(&mut self) {
        self.marf.commit()
            .unwrap()
    }
    pub fn chain_tips(&mut self) -> Vec<BlockHeaderHash> {
        self.marf.chain_tips()
    }
    pub fn get_chain_tip(&self) -> &BlockHeaderHash {
        &self.chain_tip
    }
}

impl KeyValueStorage for &mut MarfedKV {
    fn put(&mut self, key: &str, value: &str) {
        let marf_value = MARFValue::from_value(value);

        self.side_store.put(&marf_value.to_hex(), value);

        self.marf.insert(key, marf_value)
            .expect("ERROR: Unexpected MARF Failure")
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

    fn has_entry(&mut self, key: &str) -> bool {
        self.get(key).is_some()
    }
}
