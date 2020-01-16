/*
 copyright: (c) 2013-2019 by Blockstack PBC, a public benefit corporation.

 This file is part of Blockstack.

 Blockstack is free software. You may redistribute or modify
 it under the terms of the GNU General Public License as published by
 the Free Software Foundation, either version 3 of the License or
 (at your option) any later version.

 Blockstack is distributed in the hope that it will be useful,
 but WITHOUT ANY WARRANTY, including without the implied warranty of
 MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
 GNU General Public License for more details.

 You should have received a copy of the GNU General Public License
 along with Blockstack. If not, see <http://www.gnu.org/licenses/>.
*/

use std::fmt;
use std::error;
use std::fs;
use std::io;
use std::io::Error as IOError;
use std::path::PathBuf;
use std::ops::Deref;
use std::ops::DerefMut;

use util::hash::to_hex;

use chainstate::burn::BlockHeaderHash;

use rusqlite::NO_PARAMS;
use rusqlite::Error as sqlite_error;
use rusqlite::Connection;
use rusqlite::Row;
use rusqlite::types::ToSql;

use chainstate::stacks::index::marf::MARF;
use chainstate::stacks::index::TrieHash;
use chainstate::stacks::index::MARFValue;
use chainstate::stacks::index::Error as MARFError;

use serde_json::Error as serde_error;

pub type DBConn = rusqlite::Connection;
pub type DBTx<'a> = rusqlite::Transaction<'a>;

#[derive(Debug)]
pub enum Error {
    /// Not implemented 
    NotImplemented,
    /// Database doesn't exist
    NoDBError,
    /// Read-only and tried to write
    ReadOnly,
    /// Type error -- can't represent the given data in the database 
    TypeError,
    /// Database is corrupt -- we got data that shouldn't be there, or didn't get data when we
    /// should have 
    Corruption,
    /// Serialization error -- can't serialize data
    SerializationError(serde_error),
    /// Parse error -- failed to load data we stored directly 
    ParseError,
    /// Operation would overflow 
    Overflow,
    /// Data not found
    NotFoundError,
    /// Data already exists
    ExistsError,
    /// Sqlite3 error
    SqliteError(sqlite_error),
    /// I/O error
    IOError(IOError),
    /// MARF index error
    IndexError(MARFError)
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match *self {
            Error::NotImplemented => f.write_str(error::Error::description(self)),
            Error::NoDBError => f.write_str(error::Error::description(self)),
            Error::ReadOnly => f.write_str(error::Error::description(self)),
            Error::TypeError => f.write_str(error::Error::description(self)),
            Error::Corruption => f.write_str(error::Error::description(self)),
            Error::SerializationError(ref e) => fmt::Display::fmt(e, f),
            Error::ParseError => f.write_str(error::Error::description(self)),
            Error::Overflow => f.write_str(error::Error::description(self)),
            Error::NotFoundError => f.write_str(error::Error::description(self)),
            Error::ExistsError => f.write_str(error::Error::description(self)),
            Error::IOError(ref e) => fmt::Display::fmt(e, f),
            Error::SqliteError(ref e) => fmt::Display::fmt(e, f),
            Error::IndexError(ref e) => fmt::Display::fmt(e, f),
        }
    }
}

impl error::Error for Error {
    fn cause(&self) -> Option<&dyn error::Error> {
        match *self {
            Error::NotImplemented => None,
            Error::NoDBError => None,
            Error::ReadOnly => None,
            Error::TypeError => None,
            Error::Corruption => None,
            Error::SerializationError(ref e) => Some(e),
            Error::ParseError => None,
            Error::Overflow => None,
            Error::NotFoundError => None,
            Error::ExistsError => None,
            Error::SqliteError(ref e) => Some(e),
            Error::IOError(ref e) => Some(e),
            Error::IndexError(ref e) => Some(e),
        }
    }

    fn description(&self) -> &str {
        match *self {
            Error::NotImplemented => "Not implemented",
            Error::NoDBError => "Database does not exist",
            Error::ReadOnly => "Database is opened read-only",
            Error::TypeError => "Invalid or unrepresentable database type",
            Error::Corruption => "Database is corrupt",
            Error::SerializationError(ref e) => e.description(),
            Error::ParseError => "Parse error",
            Error::Overflow => "Numeric overflow",
            Error::NotFoundError => "Not found",
            Error::ExistsError => "Already exists",
            Error::SqliteError(ref e) => e.description(),
            Error::IOError(ref e) => e.description(),
            Error::IndexError(ref e) => e.description()
        }
    }
}

pub trait FromRow<T> {
    fn from_row<'a>(row: &'a Row) -> Result<T, Error>;
}

pub trait FromColumn<T> {
    fn from_column<'a>(row: &'a Row, column_name: &str) -> Result<T, Error>;
}

macro_rules! impl_byte_array_from_column {
    ($thing:ident) => {
        impl FromColumn<$thing> for $thing {
            fn from_column<'a>(row: &'a Row, column_name: &str) -> Result<$thing, ::util::db::Error> {
                let hex_str : String = row.get(column_name);
                let byte_str = hex_bytes(&hex_str)
                    .map_err(|_e| ::util::db::Error::ParseError)?;
                let inst = $thing::from_bytes(&byte_str)
                    .ok_or(::util::db::Error::ParseError)?;
                Ok(inst)
            }
        }
    }
}

/// boilerplate code for querying rows 
pub fn query_rows<T, P>(conn: &Connection, sql_query: &String, sql_args: P) -> Result<Vec<T>, Error>
where
    P: IntoIterator,
    P::Item: ToSql,
    T: FromRow<T>
{
    let mut stmt = conn.prepare(sql_query)
        .map_err(Error::SqliteError)?;

    let mut rows = stmt.query(sql_args)
        .map_err(Error::SqliteError)?;

    // gather 
    let mut row_data = vec![];
    while let Some(row_res) = rows.next() {
        match row_res {
            Ok(row) => {
                let next_row = T::from_row(&row)?;
                row_data.push(next_row);
            },
            Err(e) => {
                return Err(Error::SqliteError(e));
            }
        };
    }

    Ok(row_data)
}

/// boilerplate code for querying a column out of a sequence of rows
pub fn query_row_columns<T, P>(conn: &Connection, sql_query: &String, sql_args: P, column_name: &str) -> Result<Vec<T>, Error>
where
    P: IntoIterator,
    P::Item: ToSql,
    T: FromColumn<T>
{
    let mut stmt = conn.prepare(sql_query)
        .map_err(Error::SqliteError)?;

    let mut rows = stmt.query(sql_args)
        .map_err(Error::SqliteError)?;

    // gather 
    let mut row_data = vec![];
    while let Some(row_res) = rows.next() {
        match row_res {
            Ok(row) => {
                let next_row = T::from_column(&row, column_name)?;
                row_data.push(next_row);
            },
            Err(e) => {
                return Err(Error::SqliteError(e));
            }
        };
    }

    Ok(row_data)
}

/// Boilerplate for querying a single integer (first and only item of the query must be an int)
pub fn query_int<P>(conn: &Connection, sql_query: &String, sql_args: P) -> Result<i64, Error>
where
    P: IntoIterator,
    P::Item: ToSql
{
    let mut stmt = conn.prepare(sql_query)
        .map_err(Error::SqliteError)?;

    let mut rows = stmt.query(sql_args)
        .map_err(Error::SqliteError)?;

    let mut row_data = vec![];
    while let Some(row_res) = rows.next() {
        match row_res {
            Ok(row) => {
                if row_data.len() > 0 {
                    return Err(Error::Overflow);
                }
                let i : i64 = row.get(0);
                row_data.push(i);
            },
            Err(e) => {
                return Err(Error::SqliteError(e));
            }
        };
    }

    if row_data.len() == 0 {
        return Err(Error::NotFoundError);
    }

    Ok(row_data[0])
}

pub fn query_count<P>(conn: &Connection, sql_query: &String, sql_args: P) -> Result<i64, Error>
where
    P: IntoIterator,
    P::Item: ToSql
{
    query_int(conn, sql_query, sql_args)
}

/// Set up an on-disk database with a MARF index if they don't exist yet.
/// Either way, returns (db path, MARF path)
pub fn db_mkdirs(path_str: &str) -> Result<(String, String), Error> {
    let mut path = PathBuf::from(path_str);
    match fs::metadata(path_str) {
        Ok(md) => {
            if !md.is_dir() {
                error!("Not a directory: {:?}", path);
                return Err(Error::ExistsError);
            }
        },
        Err(e) => {
            if e.kind() != io::ErrorKind::NotFound {
                return Err(Error::IOError(e));
            }
            fs::create_dir_all(path_str).map_err(Error::IOError)?;
        }
    }

    path.push("marf");
    let marf_path = path.to_str()
        .ok_or_else(|| Error::ParseError)?
        .to_string();

    path.pop();
    path.push("data.db");
    let data_path = path.to_str()
        .ok_or_else(|| Error::ParseError)?
        .to_string();
   
    Ok((data_path, marf_path))
}

pub struct IndexDBTx<'a, C> {
    pub tx: DBTx<'a>,
    pub index: &'a mut MARF,
    pub context: C,
    block_linkage: Option<(BlockHeaderHash, BlockHeaderHash)>
}

impl<'a, C> Deref for IndexDBTx<'a, C> {
    type Target = DBTx<'a>;
    fn deref(&self) -> &DBTx<'a> {
        &self.tx
    }
}

impl<'a, C> DerefMut for IndexDBTx<'a, C> {
    fn deref_mut(&mut self) -> &mut DBTx<'a> {
        &mut self.tx
    }
}

impl<'a, C> IndexDBTx<'a, C> {
    pub fn new(tx: DBTx<'a>, index: &'a mut MARF, context: C) -> IndexDBTx<'a, C> {
        IndexDBTx {
            tx: tx,
            index: index,
            block_linkage: None,
            context: context
        }
    }

    pub fn instantiate_index(&mut self) -> Result<(), Error> {
        self.tx.execute(r#"
        -- fork-specific key/value storage, indexed via a MARF.
        -- each row is guaranteed to be unique
        CREATE TABLE IF NOT EXISTS __fork_storage(
            value_hash TEXT NOT NULL,
            value TEXT NOT NULL,

            PRIMARY KEY(value_hash)
        );
        "#, NO_PARAMS).map_err(Error::SqliteError)?;
        Ok(())
    }

    /// Get the ancestor block hash of a block of a given height, given a descendent block hash.
    pub fn get_ancestor_block_hash(&mut self, block_height: u64, tip_block_hash: &BlockHeaderHash) -> Result<Option<BlockHeaderHash>, Error> {
        assert!(block_height < u32::max_value() as u64);
        MARF::get_block_at_height(self.index.borrow_storage_backend(), block_height as u32, tip_block_hash).map_err(Error::IndexError)
    }

    /// Get the height of an ancestor block, if it is indeed the ancestor.
    pub fn get_ancestor_block_height(&mut self, ancestor_block_hash: &BlockHeaderHash, tip_block_hash: &BlockHeaderHash) -> Result<Option<u64>, Error> {
        match MARF::get_block_height(self.index.borrow_storage_backend(), ancestor_block_hash, tip_block_hash).map_err(Error::IndexError)? {
            Some(height_u32) => {
                Ok(Some(height_u32 as u64))
            }
            None => {
                Ok(None)
            }
        }
    }

    /// Store some data to the index storage.
    /// key must be globally-unique
    fn store_indexed(&mut self, key: &String, value: &String) -> Result<MARFValue, Error> {
        let marf_value = MARFValue::from_value(value);
        self.tx.execute("INSERT OR REPLACE INTO __fork_storage (value_hash, value) VALUES (?1, ?2)", &[&to_hex(&marf_value.to_vec()), value]).map_err(Error::SqliteError)?;
        Ok(marf_value)
    }

    /// Load some index data
    fn load_indexed(&self, key: &String, marf_value: &MARFValue) -> Result<Option<String>, Error> {
        let mut stmt = self.tx.prepare("SELECT value FROM __fork_storage WHERE value_hash = ?1 LIMIT 2").map_err(Error::SqliteError)?;
        let mut rows = stmt.query(&[&to_hex(&marf_value.to_vec())]).map_err(Error::SqliteError)?;
        let mut all_values = vec![];
        while let Some(row_res) = rows.next() {
            match row_res {
                Ok(row) => {
                    let value_str : String = row.get(0);
                    all_values.push(value_str);
                },
                Err(e) => {
                    panic!("FATAL: Failed to read row from Sqlite");
                }
            };
        }

        match all_values.len() {
            0 => {
                return Ok(None);
            }
            1 => {
                return Ok(Some(all_values[0].clone()));
            }
            _ => {
                // should be impossible
                panic!("FATAL: two or more values for {}", &to_hex(&marf_value.to_vec()));
            }
        }
    }

    /// Get a value from the fork index
    pub fn get_indexed(&mut self, header_hash: &BlockHeaderHash, key: &String) -> Result<Option<String>, Error> {
        let parent_index_root = match self.index.get_root_hash_at(header_hash) {
            Ok(root) => {
                root
            },
            Err(e) => {
                match e {
                    MARFError::NotFoundError => {
                        test_debug!("Not found: Get '{}' off of {} (parent index root not found)", key, header_hash.to_hex());
                        return Ok(None);
                    },
                    _ => {
                        error!("Failed to get root hash of {}: {:?}", &header_hash.to_hex(), &e);
                        return Err(Error::Corruption);
                    }
                }
            }
        };

        match self.index.get(header_hash, key) {
            Ok(marf_value_opt) => { 
                match marf_value_opt {
                    Some(marf_value) => {
                        let value = self.load_indexed(key, &marf_value)?
                            .expect(&format!("FATAL: corrupt index: key '{}' from {} (root index {}) is present in the index but missing a value in the DB", &key, &header_hash.to_hex(), &parent_index_root.to_hex()));

                        return Ok(Some(value));
                    },
                    None => {
                        return Ok(None);
                    }
                }
            },
            Err(e) => {
                match e {
                    MARFError::NotFoundError => {
                        return Ok(None);
                    },
                    _ => {
                        error!("Failed to fetch '{}' off of {}: {:?}", key, &header_hash.to_hex(), &e);
                        return Err(Error::Corruption);
                    }
                }
            }
        }
    }

    pub fn put_indexed_begin(&mut self, parent_header_hash: &BlockHeaderHash, header_hash: &BlockHeaderHash) -> Result<(), Error> {
        match self.block_linkage {
            None => {
                self.index.begin(parent_header_hash, header_hash).map_err(Error::IndexError)?;
                self.block_linkage = Some((parent_header_hash.clone(), header_hash.clone()));
                Ok(())
            },
            Some(_) => {
                panic!("Tried to put_indexed_begin twice!")
            }
        }
    }

    /// Put all keys and values in a single MARF transaction.
    /// No other MARF transactions will be permitted in the lifetime of this transaction.
    pub fn put_indexed_all(&mut self, keys: &Vec<String>, values: &Vec<String>) -> Result<TrieHash, Error> {
        assert_eq!(keys.len(), values.len());
        assert!(self.block_linkage.is_some());

        let mut marf_values = Vec::with_capacity(values.len());
        for i in 0..values.len() {
            let marf_value = self.store_indexed(&keys[i], &values[i])?;
            marf_values.push(marf_value);
        }

        self.index.insert_batch(&keys, marf_values).map_err(Error::IndexError)?;
        let root_hash = self.index.get_root_hash().map_err(Error::IndexError)?;
        Ok(root_hash)
    }

    /// Commit the indexed data
    pub fn indexed_commit(&mut self) -> Result<(), Error> {
        if self.block_linkage.is_some() {
            self.index.commit().map_err(Error::IndexError)?;
            self.block_linkage = None;
        }
        Ok(())
    }

    /// Commit the tx
    pub fn commit(self) -> Result<(), Error> {
        self.tx.commit().map_err(Error::SqliteError)?;

        if self.block_linkage.is_some() {
            self.index.commit().map_err(Error::IndexError)?;
        }
        Ok(())
    }

    /// Get the root hash
    pub fn get_root_hash_at(&mut self, bhh: &BlockHeaderHash) -> Result<TrieHash, Error> {
        let root_hash = self.index.get_root_hash_at(bhh).map_err(Error::IndexError)?;
        Ok(root_hash)
    }
}
