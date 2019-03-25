use vm::contracts::Contract;
use vm::errors::{InterpreterResult as Result};
use vm::types::{Value, TupleTypeSignature};

mod sqlite;

pub use self::sqlite::SqliteContractDatabase;

pub trait ContractDatabase {
    fn create_map(&mut self,   contract_name: &str, map_name: &str, key_type: TupleTypeSignature, value_type: TupleTypeSignature) -> Result<()>;
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

pub struct MemoryContractDatabase {
    db: SqliteContractDatabase
}

impl MemoryContractDatabase {
    pub fn new() -> Result<MemoryContractDatabase> {
        Ok(
            MemoryContractDatabase { db: SqliteContractDatabase::initialize(":memory:")? })
    }
}

impl ContractDatabase for MemoryContractDatabase {

    fn create_map(&mut self, contract_name: &str, map_name: &str, key_type: TupleTypeSignature, value_type: TupleTypeSignature) -> Result<()> {
        self.db.create_map(contract_name, map_name, key_type, value_type)
    }

    fn fetch_entry(&self, contract_name: &str, map_name: &str, key: &Value) -> Result<Value> {
        self.db.fetch_entry(contract_name, map_name, key)
    }

    fn set_entry(&mut self, contract_name: &str, map_name: &str, key: Value, value: Value) -> Result<Value> {
        self.db.set_entry(contract_name, map_name, key, value)
    }

    fn insert_entry(&mut self, contract_name: &str, map_name: &str, key: Value, value: Value) -> Result<Value> {
        self.db.insert_entry(contract_name, map_name, key, value)
    }

    fn delete_entry(&mut self, contract_name: &str, map_name: &str, key: &Value) -> Result<Value> {
        self.db.delete_entry(contract_name, map_name, key)
    }

    fn take_contract(&mut self, contract_name: &str) -> Result<Contract> {
        self.db.take_contract(contract_name)
    }

    fn replace_contract(&mut self, contract_name: &str, contract: Contract) -> Result<()> {
        self.db.replace_contract(contract_name, contract)
    }

    fn insert_contract(&mut self, contract_name: &str, contract: Contract) -> Result<()> {
        self.db.insert_contract(contract_name, contract)
    }

    fn begin_save_point(&mut self) -> Result<()> {
        self.db.begin_save_point()
    }
    fn roll_back(&mut self) -> Result<()> {
        self.db.roll_back()
    }
    fn commit(&mut self) -> Result<()> {
        self.db.commit()
    }

}
