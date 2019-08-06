use std::convert::TryFrom;
use std::collections::{VecDeque, HashMap};

use rusqlite::{Connection, OptionalExtension, NO_PARAMS, Row, Savepoint};
use rusqlite::types::{ToSql, FromSql};

use vm::contracts::Contract;
use vm::errors::{Error, InterpreterError, RuntimeErrorType, UncheckedError, InterpreterResult as Result, IncomparableError};
use vm::types::{Value, OptionalData, TypeSignature, TupleTypeSignature, AtomTypeIdentifier, PrincipalData, NONE};

use chainstate::burn::{VRFSeed, BlockHeaderHash};
use burnchains::BurnchainHeaderHash;

use vm::database::structures::*;

pub type KeyType = [u8; 32];

pub enum DataType {
    DataMap, Variable, FungibleToken, NonFungibleToken
}

pub enum MetaDataType {
    DataMap, Variable, FungibleToken, NonFungibleToken
}

pub enum StoreType {
    Data(DataType),
    MetaData(MetaDataType)
}

pub trait KeyValueStorage {
    fn put(&mut self, key: &KeyType, value: &str);
    fn get(&self, key: &KeyType) -> Option<String>;
    fn has_entry(&self, key: &KeyType) -> bool;
}

trait Rollback <'a, 'b> {
    fn reap_child(&mut self, edits: Vec<(KeyType, String)>,
                  lookup_map: &'b mut HashMap<KeyType, VecDeque<String>>,
                  store: &'a mut KeyValueStorage);
}

pub struct RollbackContext {
    edits: Vec<(KeyType, String)>
}

pub struct RollbackWrapper {
    store: Box<KeyValueStorage>,
    lookup_map: HashMap<KeyType, VecDeque<String>>,
    stack: VecDeque<RollbackContext>
}

impl RollbackWrapper {
    pub fn new(store: Box<KeyValueStorage>) -> RollbackWrapper {
        RollbackWrapper {
            store: store,
            lookup_map: HashMap::new(),
            stack: VecDeque::new()
        }
    }

    pub fn nest(&mut self) {
        self.stack.push_back(RollbackContext { edits: Vec::new() });
    }

    // Rollback the child's edits.
    //   this clears all edits from the child's edit queue,
    //     and removes any of those edits from the lookup map.
    pub fn rollback(&mut self) {
        let mut last_item = self.stack.pop_back()
            .expect("ERROR: Clarity VM attempted to commit past the stack.");

        last_item.edits.reverse();

        for (key, value) in last_item.edits.drain(..) {
                let remove_edit_deque = {
                    let key_edit_history = self.lookup_map.get_mut(&key)
                        .expect("ERROR: Clarity VM had edit log entry, but not lookup_map entry");
                    let popped_value = key_edit_history.pop_back();
                    assert!(popped_value.as_ref() == Some(&value));
                    key_edit_history.len() == 0
                };
                if remove_edit_deque {
                    self.lookup_map.remove(&key);
                }
        }
    }

    pub fn commit(&mut self) {
        let mut last_item = self.stack.pop_back()
            .expect("ERROR: Clarity VM attempted to commit past the stack.");

        if self.stack.len() == 0 {
            // committing to the backing store
            for (key, value) in last_item.edits.drain(..) {
                let remove_edit_deque = {
                    let key_edit_history = self.lookup_map.get_mut(&key)
                        .expect("ERROR: Clarity VM had edit log entry, but not lookup_map entry");
                    let popped_value = key_edit_history.pop_back();
                    assert!(popped_value.as_ref() == Some(&value));
                    self.store.put(&key, &value);
                    key_edit_history.len() == 0
                };
                if remove_edit_deque {
                    self.lookup_map.remove(&key);
                }
            }
            assert!(self.lookup_map.len() == 0);
        } else {
            // bubble up to the next item in the stack
            let next_up = self.stack.back_mut().unwrap();
            for (key, value) in last_item.edits.drain(..) {
                next_up.edits.push((key, value));
            }
        }
    }

}

impl KeyValueStorage for RollbackWrapper {
    fn put(&mut self, key: &KeyType, value: &str) {
        let current = self.stack.back_mut()
            .expect("ERROR: Clarity VM attempted PUT on non-nested context.");

        if !self.lookup_map.contains_key(key) {
            self.lookup_map.insert(key.clone(), VecDeque::new());
        }
        let key_edit_deque = self.lookup_map.get_mut(key).unwrap();
        key_edit_deque.push_back(value.to_string());

        current.edits.push((key.clone(), value.to_string()));
    }

    fn get(&self, key: &KeyType) -> Option<String> {
        let current = self.stack.back()
            .expect("ERROR: Clarity VM attempted GET on non-nested context.");

        let lookup_result = match self.lookup_map.get(key) {
            None => None,
            Some(key_edit_history) => {
                key_edit_history.back().cloned()
            },
        };
        if lookup_result.is_some() {
            lookup_result
        } else {
            self.store.get(key)
        }
    }

    fn has_entry(&self, key: &KeyType) -> bool {
        let current = self.stack.back()
            .expect("ERROR: Clarity VM attempted GET on non-nested context.");
        if self.lookup_map.contains_key(key) {
            true
        } else {
            self.store.has_entry(key)
        }
    }
}

pub struct ClarityDatabase {
    store: RollbackWrapper
}

impl ClarityDatabase {
    fn new(store: Box<KeyValueStorage>) -> ClarityDatabase {
        panic!()
    }

    pub fn begin(&mut self) {
        self.store.nest();
    }

    pub fn commit(&mut self) {
        self.store.commit();
    }

    pub fn make_key(contract_name: &str, data: StoreType, var_name: &str) -> KeyType {
        [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0]
    }

    pub fn make_key4(contract_name: &str, data: StoreType, var_name: &str, key_value: &Value) -> KeyType {
        [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0]
    }

    pub fn create_fungible_token(&mut self, contract_name: &str, token_name: &str, total_supply: &Option<i128>) {
    }
    pub fn create_non_fungible_token(&mut self, contract_name: &str, asset_name: &str, key_type: &TypeSignature) {
    }
}

// Variable Functions...
impl ClarityDatabase {
    pub fn create_variable(&mut self, contract_name: &str, variable_name: &str, value_type: TypeSignature) {
        let variable_data = DataVariableMetadata { value_type };

        let key = ClarityDatabase::make_key(contract_name, StoreType::MetaData(MetaDataType::Variable), variable_name);

        assert!(!self.store.has_entry(&key), "Clarity VM attempted to initialize existing variable");

        self.store.put(&key, &variable_data.serialize());
    }

    fn load_variable(&self, contract_name: &str, variable_name: &str) -> Result<DataVariableMetadata> {
        let key = ClarityDatabase::make_key(contract_name, StoreType::MetaData(MetaDataType::Variable), variable_name);

        let serialized = self.store.get(&key)
            .ok_or(UncheckedError::UndefinedVariable(variable_name.to_string()))?;

        Ok(DataVariableMetadata::deserialize(&serialized))
    }

    pub fn set_variable(&mut self, contract_name: &str, variable_name: &str, value: Value) -> Result<Value> {
        let variable_descriptor = self.load_variable(contract_name, variable_name)?;
        if !variable_descriptor.value_type.admits(&value) {
            return Err(UncheckedError::TypeError(format!("{:?}", variable_descriptor.value_type), value).into())
        }

        let key = ClarityDatabase::make_key(contract_name, StoreType::Data(DataType::Variable), variable_name);

        self.store.put(&key, &value.serialize());

        return Ok(Value::Bool(true))
    }

    pub fn lookup_variable(&self, contract_name: &str, variable_name: &str) -> Result<Value>  {
        let variable_descriptor = self.load_variable(contract_name, variable_name)?;

        let key = ClarityDatabase::make_key(contract_name, StoreType::Data(DataType::Variable), variable_name);

        let result = self.store.get(&key);

        match result {
            None => Ok(Value::none()),
            Some(serialized) => Ok(Value::deserialize(&serialized))
        }
    }
}

// Data Map Functions
impl ClarityDatabase {
    pub fn create_map(&mut self, contract_name: &str, map_name: &str, key_type: TupleTypeSignature, value_type: TupleTypeSignature) {
        let key_type = TypeSignature::new_atom(AtomTypeIdentifier::TupleType(key_type));
        let value_type = TypeSignature::new_atom(AtomTypeIdentifier::TupleType(value_type));

        let data = DataMapMetadata { key_type, value_type };

        let key = ClarityDatabase::make_key(contract_name, StoreType::MetaData(MetaDataType::DataMap), map_name);

        assert!(!self.store.has_entry(&key), "Clarity VM attempted to initialize existing data map");

        self.store.put(&key, &data.serialize());
    }

    fn load_map(&self, contract_name: &str, map_name: &str) -> Result<DataMapMetadata> {
        let key = ClarityDatabase::make_key(contract_name, StoreType::MetaData(MetaDataType::DataMap), map_name);

        let serialized = self.store.get(&key)
            .ok_or(UncheckedError::UndefinedVariable(map_name.to_string()))?;

        Ok(DataMapMetadata::deserialize(&serialized))
    }

    pub fn fetch_entry(&self, contract_name: &str, map_name: &str, key_value: &Value) -> Result<Value> {
        let map_descriptor = self.load_map(contract_name, map_name)?;
        if !map_descriptor.key_type.admits(key_value) {
            return Err(UncheckedError::TypeError(format!("{:?}", map_descriptor.key_type), (*key_value).clone()).into())
        }

        let key = ClarityDatabase::make_key4(contract_name, StoreType::Data(DataType::DataMap), map_name, &key_value);

        let result = self.store.get(&key);

        match result {
            None => Ok(Value::none()),
            Some(serialized) => Ok(Value::deserialize(&serialized))
        }
    }

    pub fn set_entry(&mut self, contract_name: &str, map_name: &str, key: Value, value: Value) -> Result<Value> {
        self.inner_set_entry(contract_name, map_name, key, value, false)
    }

    pub fn insert_entry(&mut self, contract_name: &str, map_name: &str, key: Value, value: Value) -> Result<Value> {
        self.inner_set_entry(contract_name, map_name, key, value, true)
    }

    fn data_map_entry_exists(&self, key: &[u8; 32]) -> Result<bool> {
        match self.store.get(&key) {
            None => Ok(false),
            Some(serialized) =>
                Ok(Value::deserialize(&serialized) != Value::none())
        }
    }
    
    fn inner_set_entry(&mut self, contract_name: &str, map_name: &str, key_value: Value, value: Value, return_if_exists: bool) -> Result<Value> {
        let map_descriptor = self.load_map(contract_name, map_name)?;
        if !map_descriptor.key_type.admits(&key_value) {
            return Err(UncheckedError::TypeError(format!("{:?}", map_descriptor.key_type), key_value).into())
        }
        if !map_descriptor.value_type.admits(&value) {
            return Err(UncheckedError::TypeError(format!("{:?}", map_descriptor.value_type), value).into())
        }

        let key = ClarityDatabase::make_key4(contract_name, StoreType::Data(DataType::DataMap), map_name, &key_value);

        if return_if_exists && self.data_map_entry_exists(&key)? {
            return Ok(Value::Bool(false))
        }

        self.store.put(&key, &(Value::some(value).serialize()));

        return Ok(Value::Bool(true))
    }

    pub fn delete_entry(&mut self, contract_name: &str, map_name: &str, key_value: &Value) -> Result<Value> {
        let key = ClarityDatabase::make_key4(contract_name, StoreType::Data(DataType::DataMap), map_name, &key_value);
        if !self.data_map_entry_exists(&key)? {
            return Ok(Value::Bool(false))
        }

        let map_descriptor = self.load_map(contract_name, map_name)?;
        if !map_descriptor.key_type.admits(key_value) {
            return Err(UncheckedError::TypeError(format!("{:?}", map_descriptor.key_type), (*key_value).clone()).into())
        }

        self.store.put(&key, &(Value::none().serialize()));

        return Ok(Value::Bool(true))
    }
}
