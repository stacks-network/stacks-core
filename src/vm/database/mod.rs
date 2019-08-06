mod sqlite;
mod structures;
pub mod key_value_wrapper;

use std::collections::HashMap;
pub use self::key_value_wrapper::{KeyType, KeyValueStorage, ClarityDatabase};

pub use self::sqlite::{SqliteStore, SqliteConnection};

impl KeyValueStorage for HashMap<KeyType, String> {
    fn put(&mut self, key: &KeyType, value: &str) {
        self.insert(key.clone(), value.to_string());
    }
    fn get(&self, key: &KeyType) -> Option<String> {
        self.get(key).cloned()
    }
    fn has_entry(&self, key: &KeyType) -> bool {
        self.contains_key(key)
    }
}


pub fn memory_db<'a>() -> ClarityDatabase<'a> {
    let store: HashMap<KeyType, String> = HashMap::new();
    let mut db = ClarityDatabase::new(Box::new(store));
    db.initialize();
    db
}
