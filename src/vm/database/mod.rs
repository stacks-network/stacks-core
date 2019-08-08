pub mod marf;
mod sqlite;
mod structures;
mod clarity_db;
mod key_value_wrapper;

use std::collections::HashMap;

pub use self::key_value_wrapper::{
    KeyType, KeyValueStorage, RollbackWrapper };
pub use self::clarity_db::{ClarityDatabase};
pub use self::structures::{ClaritySerializable, ClarityDeserializable };
pub use self::sqlite::{SqliteStore, SqliteConnection};

impl KeyValueStorage for HashMap<KeyType, String> {
    fn put(&mut self, key: &KeyType, value: &str) {
        self.insert(key.clone(), value.to_string());
    }
    fn get(&mut self, key: &KeyType) -> Option<String> {
        (&*self).get(key).cloned()
    }
    fn has_entry(&mut self, key: &KeyType) -> bool {
        self.contains_key(key)
    }
}

pub fn memory_db<'a>() -> ClarityDatabase<'a> {
    let store: HashMap<KeyType, String> = HashMap::new();
    let mut db = ClarityDatabase::new(Box::new(store));
    db.initialize();
    db
}
