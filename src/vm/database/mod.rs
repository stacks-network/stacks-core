use std::collections::HashMap;

use vm::contracts::Contract;
use vm::errors::{Error, ErrType, InterpreterResult as Result};
use vm::types::{Value, TypeSignature, TupleTypeSignature, AtomTypeIdentifier};

mod sqlite;

pub use self::sqlite::SqliteContractDatabase;

pub trait ContractDatabase {
    fn create_map(&mut self,   contract_name: &str, map_name: &str, key_type: TupleTypeSignature, value_type: TupleTypeSignature);
    fn fetch_entry(&self,      contract_name: &str, map_name: &str, key: &Value) -> Result<Value>;
    fn set_entry(&mut self,    contract_name: &str, map_name: &str, key: Value, value: Value) -> Result<Value>;
    fn insert_entry(&mut self, contract_name: &str, map_name: &str, key: Value, value: Value) -> Result<Value>;
    fn delete_entry(&mut self, contract_name: &str, map_name: &str, key: &Value) -> Result<Value>;

    fn take_contract(&mut self, contract_name: &str) -> Result<Contract>;
    fn replace_contract(&mut self, contract_name: &str, contract: Contract) -> Result<()>;
    fn insert_contract(&mut self, contract_name: &str, contract: Contract) -> Result<()>;

    fn begin_save_point(&mut self) -> Result<()>;
    fn roll_back(&mut self) -> Result<()>;
    fn commit(&mut self) -> Result<()>;
}

#[derive(Serialize, Deserialize)]
pub struct MemoryDataMap {
    map: HashMap<Value, Value>,
    key_type: TypeSignature,
    value_type: TypeSignature
}

#[derive(Serialize, Deserialize)]
pub struct MemoryContractDatabase {
    maps: HashMap<(String, String), MemoryDataMap>,
    contracts: HashMap<String, Option<Contract>>
}

impl MemoryContractDatabase {
    pub fn new() -> MemoryContractDatabase {
        MemoryContractDatabase { maps: HashMap::new(),
                                 contracts: HashMap::new() }
    }

    fn get_mut_data_map(&mut self, contract_name: &str, map_name: &str) -> Result<&mut MemoryDataMap> {
        if let Some(data_map) = self.maps.get_mut(&(contract_name.to_string(), map_name.to_string())) {
            Ok(data_map)
        } else {
            Err(Error::new(ErrType::UndefinedVariable(map_name.to_string())))
        }
    }

    fn get_data_map(&self, contract_name: &str, map_name: &str) -> Result<&MemoryDataMap> {
        if let Some(data_map) = self.maps.get(&(contract_name.to_string(), map_name.to_string())) {
            Ok(data_map)
        } else {
            Err(Error::new(ErrType::UndefinedVariable(map_name.to_string())))
        }
    }
}

impl ContractDatabase for MemoryContractDatabase {

    fn create_map(&mut self, contract_name: &str, map_name: &str, key_type: TupleTypeSignature, value_type: TupleTypeSignature) {
        let new_map = MemoryDataMap::new(key_type, value_type);
        self.maps.insert((contract_name.to_string(), map_name.to_string()),
                         new_map);
    }

    fn fetch_entry(&self, contract_name: &str, map_name: &str, key: &Value) -> Result<Value> {
        let data_map = self.get_data_map(contract_name, map_name)?;
        data_map.fetch_entry(key)
    }

    fn set_entry(&mut self, contract_name: &str, map_name: &str, key: Value, value: Value) -> Result<Value> {
        let data_map = self.get_mut_data_map(contract_name, map_name)?;
        data_map.set_entry(key, value)
    }

    fn insert_entry(&mut self, contract_name: &str, map_name: &str, key: Value, value: Value) -> Result<Value> {
        let data_map = self.get_mut_data_map(contract_name, map_name)?;
        data_map.insert_entry(key, value)
    }

    fn delete_entry(&mut self, contract_name: &str, map_name: &str, key: &Value) -> Result<Value> {
        let data_map = self.get_mut_data_map(contract_name, map_name)?;
        data_map.delete_entry(key)
    }

    fn take_contract(&mut self, contract_name: &str) -> Result<Contract> {
        let contract = self.contracts.get_mut(contract_name)
            .ok_or_else(|| { Error::new(ErrType::UndefinedContract(contract_name.to_string())) })?;
        contract.take().ok_or(Error::new(ErrType::ContractAlreadyInvoked))
    }

    fn replace_contract(&mut self, contract_name: &str, contract: Contract) -> Result<()> {
        let contract_holder = self.contracts.get_mut(contract_name)
            .ok_or_else(|| { Error::new(ErrType::UndefinedContract(contract_name.to_string())) })?;
        match contract_holder.replace(contract) {
            Some(_) => Err(Error::new(ErrType::InterpreterError(
                format!("Attempted to close invocation on a non-open contract {}", contract_name)))),
            None => Ok(())
        }
    }

    fn insert_contract(&mut self, contract_name: &str, contract: Contract) -> Result<()> {
        if self.contracts.contains_key(contract_name) {
            Err(Error::new(ErrType::ContractAlreadyExists(contract_name.to_string())))
        } else {
            self.contracts.insert(contract_name.to_string(), Some(contract));
            Ok(())
        }
    }

    fn begin_save_point(&mut self) -> Result<()> {
        Ok(())
    }
    fn roll_back(&mut self) -> Result<()> {
        Ok(())
    }
    fn commit(&mut self) -> Result<()> {
        Ok(())
    }

}

impl MemoryDataMap {
    // TODO: currently, the return types and behavior of these functions are defined here,
    //   however, they should really be specified in the functions/database.rs file, whereas
    //   this file should really just be speccing out the database connection/requirement.
    pub fn new(key_type: TupleTypeSignature,
               value_type: TupleTypeSignature) -> MemoryDataMap {
        MemoryDataMap {
            map: HashMap::new(),
            key_type: TypeSignature::new_atom(AtomTypeIdentifier::TupleType(key_type)),
            value_type: TypeSignature::new_atom(AtomTypeIdentifier::TupleType(value_type))
        }
    }

    fn fetch_entry(&self, key: &Value) -> Result<Value> {
        if !self.key_type.admits(key) {
            return Err(Error::new(ErrType::TypeError(format!("{:?}", self.key_type), (*key).clone())))
        }
        if let Some(value) = self.map.get(key) {
            return Ok((*value).clone())
        } else {
            return Ok(Value::Void)
        }
    }

    fn set_entry(&mut self, key: Value, value: Value) -> Result<Value> {
        if !self.key_type.admits(&key) {
            return Err(Error::new(ErrType::TypeError(format!("{:?}", self.key_type), key)))
        }
        if !self.value_type.admits(&value) {
            return Err(Error::new(ErrType::TypeError(format!("{:?}", self.value_type), value)))
        }
        self.map.insert(key, value);
        Ok(Value::Void)
    }

    fn insert_entry(&mut self, key: Value, value: Value) -> Result<Value> {
        if !self.key_type.admits(&key) {
            return Err(Error::new(ErrType::TypeError(format!("{:?}", self.key_type), key)))
        }
        if !self.value_type.admits(&value) {
            return Err(Error::new(ErrType::TypeError(format!("{:?}", self.value_type), value)))
        }
        if self.map.contains_key(&key) {
            Ok(Value::Bool(false))
        } else {
            self.map.insert(key, value);
            Ok(Value::Bool(true))
        }
    }

    fn delete_entry(&mut self, key: &Value) -> Result<Value> {
        if !self.key_type.admits(key) {
            return Err(Error::new(ErrType::TypeError(format!("{:?}", self.key_type), (*key).clone())))
        }
        if let Some(_value) = self.map.remove(key) {
            Ok(Value::Bool(true))
        } else {
            Ok(Value::Bool(false))
        }
    }
}

