use vm::database::{KeyValueStorage, KeyType};
use chainstate::stacks::index::marf::MARF;
use chainstate::stacks::index::{MARFValue, Error as MarfError};
use chainstate::stacks::index::storage::{TrieFileStorage};
use chainstate::burn::BlockHeaderHash;
use util::hash::{to_hex, Sha256Sum};

pub struct MarfedKV {
    marf: MARF,
    // Since the MARF only stores 32 bytes of value,
    //   we need another storage
    side_store: Box<KeyValueStorage>
}

fn value_hash(value: &str) -> KeyType {
    let Sha256Sum(hash_data) = Sha256Sum::from_data(value.as_bytes());
    hash_data
}

#[cfg(test)]
pub fn temporary_marf() -> MarfedKV {
    use std::env;
    use rand::Rng;
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
    fn put(&mut self, key: &KeyType, value: &str) {
        let value_hash = value_hash(value);
        self.side_store.put(&value_hash, value);

        let string = to_hex(key);
        let marf_value = MARFValue::from_value_hash_bytes(&value_hash);

        self.marf.insert(&string, marf_value)
            .expect("ERROR: Unexpected MARF Failure")
    }

    fn get(&mut self, key: &KeyType) -> Option<String> {
        let chain_tip = self.marf.get_open_chain_tip()
            .expect("ERROR: Clarity VM attempted to use unopened MARF")
            .clone();
        let string = to_hex(key);
        self.marf.get(&chain_tip, &string)
            .or_else(|e| {
                match e {
                    MarfError::NotFoundError => Ok(None),
                    _ => Err(e)
                }
            })
            .expect("ERROR: Unexpected MARF Failure on GET")
            .map(|marf_value| {
                let side_key = marf_value.to_value_hash();
                self.side_store.get(&side_key.0)
                    .expect(&format!("ERROR: MARF contained value_hash not found in side storage: {}",
                                     side_key.to_hex()))
            })
    }

    fn has_entry(&mut self, key: &KeyType) -> bool {
        self.get(key).is_some()
    }
}
