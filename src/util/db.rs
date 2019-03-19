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

use rusqlite::Error as sqlite_error;
use rusqlite::Connection;
use rusqlite::Row;

use serde_json::Error as serde_error;

pub type DBConn = rusqlite::Connection;

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
    /// Sqlite3 error
    SqliteError(sqlite_error)
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
            Error::SqliteError(ref e) => fmt::Display::fmt(e, f)
        }
    }
}

impl error::Error for Error {
    fn cause(&self) -> Option<&error::Error> {
        match *self {
            Error::NotImplemented => None,
            Error::NoDBError => None,
            Error::ReadOnly => None,
            Error::TypeError => None,
            Error::Corruption => None,
            Error::SerializationError(ref e) => Some(e),
            Error::ParseError => None,
            Error::Overflow => None,
            Error::SqliteError(ref e) => Some(e)
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
            Error::SqliteError(ref e) => e.description()
        }
    }
}

pub trait RowOrder {
    fn row_order() -> Vec<&'static str>;
}

pub trait FromRow<T> {
    fn from_row<'a>(row: &'a Row, index: usize) -> Result<T, Error>;
}

macro_rules! impl_byte_array_from_row {
    ($thing:ident) => {
        impl FromRow<$thing> for $thing {
            fn from_row<'a>(row: &'a Row, index: usize) -> Result<$thing, ::util::db::Error> {
                let hex_str : String = row.get(index);
                let byte_str = hex_bytes(&hex_str)
                    .map_err(|_e| ::util::db::Error::ParseError)?;
                let inst = $thing::from_bytes(&byte_str)
                    .ok_or(::util::db::Error::ParseError)?;
                Ok(inst)
            }
        }
    }
}
