pub mod marf;
mod sqlite;
mod structures;
mod clarity_db;
mod key_value_wrapper;

use std::collections::HashMap;

pub use self::key_value_wrapper::{
    KeyValueStorage, RollbackWrapper };
pub use self::clarity_db::{ClarityDatabase};
pub use self::structures::{ClaritySerializable, ClarityDeserializable };
pub use self::sqlite::{SqliteConnection};
pub use self::marf::{sqlite_marf, MarfedKV};

impl KeyValueStorage for HashMap<String, String> {
    fn put(&mut self, key: &str, value: &str) {
        self.insert(key.to_string(), value.to_string());
    }
    fn get(&mut self, key: &str) -> Option<String> {
        (&*self).get(key).cloned()
    }
    fn has_entry(&mut self, key: &str) -> bool {
        self.contains_key(key)
    }
}

pub fn memory_db<'a>() -> ClarityDatabase<'a> {
    let store: HashMap<String, String> = HashMap::new();
    let mut db = ClarityDatabase::new(Box::new(store));
    db.initialize();
    db
}
