use rusqlite::{Connection, OptionalExtension, NO_PARAMS, Result as SqlResult, Row};
use rusqlite::types::ToSql;

use vm::contracts::Contract;
use vm::database::{ContractDatabase};
use vm::errors::{Error, ErrType, InterpreterResult as Result, IncomparableError};
use vm::types::{Value, TypeSignature, TupleTypeSignature, AtomTypeIdentifier};


pub struct SqliteContractDatabase {
    conn: Option<Connection>,
    save_point: u16
}

pub struct SqliteDataMap {
    map_identifier: i64,
    key_type: TypeSignature,
    value_type: TypeSignature
}

impl SqliteContractDatabase {
    pub fn initialize(filename: &str) -> Result<SqliteContractDatabase> {
        let mut contract_db = SqliteContractDatabase::open(filename)?;
        contract_db.execute("CREATE TABLE IF NOT EXISTS maps_table
                      (map_identifier INTEGER PRIMARY KEY AUTOINCREMENT,
                       contract_name TEXT,
                       map_name TEXT,
                       key_type TEXT,
                       value_type TEXT)",
                            NO_PARAMS)?;
        contract_db.execute("CREATE TABLE IF NOT EXISTS data_table
                      (data_identifier INTEGER PRIMARY KEY AUTOINCREMENT,
                       map_identifier INTEGER,
                       key TEXT,
                       value TEXT)",
                            NO_PARAMS)?;
        contract_db.execute("CREATE TABLE IF NOT EXISTS contracts
                      (contract_identifier INTEGER PRIMARY KEY AUTOINCREMENT,
                       contract_name TEXT,
                       contract_data TEXT)",
                            NO_PARAMS)?;
        Ok(contract_db)
    }

    pub fn open(filename: &str) -> Result<SqliteContractDatabase> {
        let conn = Connection::open(filename)
            .map_err(|x| Error::new(ErrType::SqliteError(IncomparableError{ err: x })))?;
        Ok(SqliteContractDatabase {
            conn: Some(conn),
            save_point: 0
        })
    }

    fn load_map(&self, contract_name: &str, map_name: &str) -> Result<SqliteDataMap> {
        let (map_identifier, key_type, value_type): (_, String, String) =
            self.query_row(
                "SELECT map_identifier, key_type, value_type FROM maps_table WHERE contract_name = ? AND map_name = ?",
                &[contract_name, map_name],
                |row| {
                    (row.get(0), row.get(1), row.get(2))
                })?
            .ok_or(Error::new(ErrType::UndefinedMap(map_name.to_string())))?;

        Ok(SqliteDataMap {
            map_identifier: map_identifier,
            key_type: TypeSignature::deserialize(&key_type)?,
            value_type: TypeSignature::deserialize(&value_type)?
        })
    }

    fn load_contract(&self, contract_name: &str) -> Result<Option<Contract>> {
        let contract: Option<String> =
            self.query_row(
                "SELECT contract_data FROM contracts WHERE contract_name = ?",
                &[contract_name],
                |row| {
                    row.get(0)
                })?;
        match contract {
            None => Ok(None),
            Some(ref contract) => Ok(Some(Contract::deserialize(contract)?))
        }
    }

    fn execute<P>(&mut self, sql: &str, params: P) -> Result<usize>
    where
        P: IntoIterator,
        P::Item: ToSql {
        if self.conn.is_some() {
            let conn = self.conn.take().unwrap();
            let result = conn.execute(sql, params)
                .map_err(|x| {
                    eprintln!("SQL Execution Error: {:?}", x);
                    Error::new(ErrType::SqliteError(IncomparableError{ err: x }))
                })?;
            // if execution error'ed, return _without_ replacing connection!
            //    this closes the connection.
            self.conn.replace(conn);
            Ok(result)
        } else {
            Err(Error::new(ErrType::SqlConnectionClosed))
        }
    }

    fn query_row<T, P, F>(&self, sql: &str, params: P, f: F) -> Result<Option<T>>
    where
        P: IntoIterator,
        P::Item: ToSql,
        F: FnOnce(&Row) -> T {
        if let Some(ref conn) = self.conn {
            conn.query_row(sql, params, f)
                .optional()
                .map_err(|x| Error::new(ErrType::SqliteError(IncomparableError{ err: x })))
        } else {
            Err(Error::new(ErrType::SqlConnectionClosed))
        }
    }
}

impl ContractDatabase for SqliteContractDatabase {
    fn create_map(&mut self, contract_name: &str, map_name: &str, key_type: TupleTypeSignature, value_type: TupleTypeSignature) {
        let key_type = TypeSignature::new_atom(AtomTypeIdentifier::TupleType(key_type));
        let value_type = TypeSignature::new_atom(AtomTypeIdentifier::TupleType(value_type));

        self.execute("INSERT INTO maps_table (contract_name, map_name, key_type, value_type) VALUES (?, ?, ?, ?)",
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

        let sql_result: Option<Option<String>> = 
            self.query_row(
                "SELECT value FROM data_table WHERE map_identifier = ? AND key = ? ORDER BY data_identifier DESC",
                &params,
                |row| {
                    row.get(0)
                })?;
        match sql_result {
            None => {
                Ok(Value::Void)
            },
            Some(sql_result) => {
                match sql_result {
                    None => Ok(Value::Void),
                    Some(value_data) => Value::deserialize(&value_data)
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

        self.execute(
            "INSERT INTO data_table (map_identifier, key, value) VALUES (?, ?, ?)",
            &params)?;

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

        self.execute(
            "INSERT INTO data_table (map_identifier, key, value) VALUES (?, ?, ?)",
            &params)?;

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

        self.execute(
            "INSERT INTO data_table (map_identifier, key, value) VALUES (?, ?, ?)",
            &params)?;

        return Ok(Value::Bool(exists))
    }


    fn take_contract(&mut self, contract_name: &str) -> Result<Contract> {
        self.load_contract(contract_name)?
            .ok_or_else(|| { Error::new(ErrType::UndefinedContract(contract_name.to_string())) })
    }

    fn replace_contract(&mut self, _contract_name: &str, _contract: Contract) -> Result<()> {
        Ok(())
    }

    fn insert_contract(&mut self, contract_name: &str, contract: Contract) -> Result<()> {
        if self.load_contract(contract_name)?.is_some() {
            Err(Error::new(ErrType::ContractAlreadyExists(contract_name.to_string())))
        } else {
            self.execute("INSERT INTO contracts (contract_name, contract_data) VALUES (?, ?)",
                         &[contract_name, &contract.serialize()?])?;
            Ok(())
        }
    }

    fn begin_save_point(&mut self) -> Result<()> {
        self.save_point = self.save_point.checked_add(1)
            .ok_or(Error::new(ErrType::MaxContextDepthReached))?;
        let sql = format!("SAVEPOINT \"{}\"", self.save_point);
        self.execute(&sql, NO_PARAMS)?;
        Ok(())
    }

    fn roll_back(&mut self) -> Result<()> {
        if self.save_point == 0 {
            return Err(Error::new(ErrType::InterpreterError("Attempted to roll back non-existent savepoint.".to_string())))
        }
        let sql = format!("ROLLBACK TRANSACTION TO SAVEPOINT \"{}\"", self.save_point);
        self.execute(&sql, NO_PARAMS)?;
        self.save_point = self.save_point - 1;
        Ok(())
    }

    fn commit(&mut self) -> Result<()> {
        if self.save_point == 0 {
            return Err(Error::new(ErrType::InterpreterError("Attempted to commit non-existent savepoint.".to_string())))
        }
        let sql = format!("RELEASE SAVEPOINT \"{}\"", self.save_point);
        self.execute(&sql, NO_PARAMS)?;
        self.save_point = self.save_point - 1;
        Ok(())
    }

}
