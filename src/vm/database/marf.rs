use vm::database::{KeyValueStorage};
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

    let marf = MARF::from_path(path.to_str().expect("Inexplicably non-UTF-8 character in filename"))
        .unwrap();
    let side_store = Box::new(HashMap::new());
    MarfedKV { marf, side_store }
}

impl MarfedKV {
    pub fn begin(&mut self, current: &BlockHeaderHash, next: &BlockHeaderHash) {
        self.marf.begin(current, next)
            .unwrap();
    }
    pub fn commit(&mut self) {
        self.marf.commit()
            .unwrap()
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
        let chain_tip = self.marf.get_open_chain_tip()
            .expect("ERROR: Clarity VM attempted to use unopened MARF")
            .clone();
        self.marf.get(&chain_tip, key)
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
