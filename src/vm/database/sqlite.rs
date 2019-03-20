use std::collections::HashMap;

use rusqlite::{Connection, Result as SqliteResult, NO_PARAMS};
use rusqlite::types::ToSql;

use vm::database::{ContractDatabase};
use vm::contexts::{GlobalContext};
use vm::errors::{Error, ErrType, InterpreterResult as Result, IncomparableError};
use vm::types::{Value, TypeSignature, TupleTypeSignature, AtomTypeIdentifier};


pub struct SqliteContractDatabase {
    conn: Connection
}

pub struct SqliteDataMap {
    map_identifier: i64,
    key_type: TypeSignature,
    value_type: TypeSignature
}

impl SqliteContractDatabase {
    pub fn initialize(filename: &str) -> Result<SqliteContractDatabase> {
        let contract_db = SqliteContractDatabase::open(filename)?;
        contract_db.conn.execute("CREATE TABLE IF NOT EXISTS maps_table
                      (map_identifier INTEGER PRIMARY KEY AUTOINCREMENT,
                       contract_name TEXT,
                       map_name TEXT,
                       key_type TEXT,
                       value_type TEXT)",
                                 NO_PARAMS)
            .map_err(|x| Error::new(ErrType::SqliteError(IncomparableError{ err: x })))?;
        contract_db.conn.execute("CREATE TABLE IF NOT EXISTS data_table
                      (data_identifier INTEGER PRIMARY KEY AUTOINCREMENT,
                       map_identifier INTEGER,
                       key TEXT,
                       value TEXT)",
                                 NO_PARAMS)
            .map_err(|x| Error::new(ErrType::SqliteError(IncomparableError{ err: x })))?;
        Ok(contract_db)
    }

    pub fn open(filename: &str) -> Result<SqliteContractDatabase> {
        let conn = Connection::open(filename)
            .map_err(|x| Error::new(ErrType::SqliteError(IncomparableError{ err: x })))?;
        Ok(SqliteContractDatabase {
            conn: conn })
    }

    fn load_map(&self, contract_name: &str, map_name: &str) -> Result<SqliteDataMap> {
        let (map_identifier, key_type, value_type): (_, String, String) = self.conn.query_row(
            "SELECT map_identifier, key_type, value_type FROM maps_table WHERE contract_name = ? AND map_name = ?",
            &[contract_name, map_name],
            |row| {
                (row.get(0), row.get(1), row.get(2))
            })
            .map_err(|x| Error::new(ErrType::SqliteError(IncomparableError{ err: x })))?;

        Ok(SqliteDataMap {
            map_identifier: map_identifier,
            key_type: TypeSignature::deserialize(&key_type)?,
            value_type: TypeSignature::deserialize(&value_type)?
        })
    }
}

impl ContractDatabase for SqliteContractDatabase {
    fn create_map(&mut self, contract_name: &str, map_name: &str, key_type: TupleTypeSignature, value_type: TupleTypeSignature) {
        let key_type = TypeSignature::new_atom(AtomTypeIdentifier::TupleType(key_type));
        let value_type = TypeSignature::new_atom(AtomTypeIdentifier::TupleType(value_type));

        self.conn.execute("INSERT INTO maps_table (contract_name, map_name, key_type, value_type) VALUES (?, ?, ?, ?)",
                          &[contract_name, map_name, &key_type.serialize().unwrap(), &value_type.serialize().unwrap()])
            .unwrap();
    }

    fn fetch_entry(&self, contract_name: &str, map_name: &str, key: &Value) -> Result<Value> {
        let map_descriptor = self.load_map(contract_name, map_name)?;
        if !map_descriptor.key_type.admits(key) {
            return Err(Error::new(ErrType::TypeError(format!("{:?}", map_descriptor.key_type), (*key).clone())))
        }

        let params: [&ToSql; 2] = [&map_descriptor.map_identifier,
                                   &key.serialize()?];

        let sql_result: SqliteResult<Option<String>> = 
            self.conn.query_row(
                "SELECT value FROM data_table WHERE map_identifier = ? AND key = ? ORDER BY data_identifier DESC",
                &params,
                |row| {
                    row.get(0)
                });
        match sql_result {
            Err(QueryReturnedNoRows) => {
                Ok(Value::Void)
            },
            Err(x) => {
                Err(Error::new(ErrType::SqliteError(IncomparableError{ err: x })))
            },
            Ok(sql_result) => {
                match sql_result {
                    None => {
                        Ok(Value::Void)
                    },
                    Some(value_data) => {
                        Value::deserialize(&value_data)
                    }
                }
            }
        }
    }

    fn set_entry(&mut self, contract_name: &str, map_name: &str, key: Value, value: Value) -> Result<Value> {
        let map_descriptor = self.load_map(contract_name, map_name)?;
        if !map_descriptor.key_type.admits(&key) {
            return Err(Error::new(ErrType::TypeError(format!("{:?}", map_descriptor.key_type), key)))
        }
        if !map_descriptor.value_type.admits(&value) {
            return Err(Error::new(ErrType::TypeError(format!("{:?}", map_descriptor.value_type), value)))
        }

        let params: [&ToSql; 3] = [&map_descriptor.map_identifier,
                                   &key.serialize()?,
                                   &Some(value.serialize()?)];

        self.conn.execute(
            "INSERT INTO data_table (map_identifier, key, value) VALUES (?, ?, ?)",
            &params)
            .map_err(|x| Error::new(ErrType::SqliteError(IncomparableError{ err: x })))?;

        return Ok(Value::Void)
    }

    fn insert_entry(&mut self, contract_name: &str, map_name: &str, key: Value, value: Value) -> Result<Value> {
        let exists = self.fetch_entry(contract_name, map_name, &key)? != Value::Void;
        if exists {
            return Ok(Value::Bool(false))
        }

        let map_descriptor = self.load_map(contract_name, map_name)?;
        if !map_descriptor.key_type.admits(&key) {
            return Err(Error::new(ErrType::TypeError(format!("{:?}", map_descriptor.key_type), key)))
        }
        if !map_descriptor.value_type.admits(&value) {
            return Err(Error::new(ErrType::TypeError(format!("{:?}", map_descriptor.value_type), value)))
        }
        let params: [&ToSql; 3] = [&map_descriptor.map_identifier,
                                   &key.serialize()?,
                                   &Some(value.serialize()?)];

        self.conn.execute(
            "INSERT INTO data_table (map_identifier, key, value) VALUES (?, ?, ?)",
            &params)
            .map_err(|x| Error::new(ErrType::SqliteError(IncomparableError{ err: x })))?;

        return Ok(Value::Bool(true))
    }

    fn delete_entry(&mut self, contract_name: &str, map_name: &str, key: &Value) -> Result<Value> {
        let exists = self.fetch_entry(contract_name, map_name, &key)? != Value::Void;
        if !exists {
            return Ok(Value::Bool(false))
        }

        let map_descriptor = self.load_map(contract_name, map_name)?;
        if !map_descriptor.key_type.admits(key) {
            return Err(Error::new(ErrType::TypeError(format!("{:?}", map_descriptor.key_type), (*key).clone())))
        }

        let none: Option<String> = None;
        let params: [&ToSql; 3] = [&map_descriptor.map_identifier,
                                   &key.serialize()?,
                                   &none];

        self.conn.execute(
            "INSERT INTO data_table (map_identifier, key, value) VALUES (?, ?, ?)",
            &params)
            .map_err(|x| Error::new(ErrType::SqliteError(IncomparableError{ err: x })))?;

        return Ok(Value::Bool(exists))
    }
}
