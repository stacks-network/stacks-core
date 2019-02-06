/*
 copyright: (c) 2013-2018 by Blockstack PBC, a public benefit corporation.

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

pub mod burndb;

use std::fmt;
use std::error;

use rusqlite::Error as sqlite_error;
use rusqlite::Row;

use rusqlite::Connection;
pub type DBConn = Connection;

use serde_json::Error as serde_error;

use burnchains::{Txid, BurnchainHeaderHash, Address};

use burnchains::bitcoin::address::BitcoinAddress;

use util::vrf::ECVRF_check_public_key;
use util::hash::{hex_bytes, Hash160};

use chainstate::burn::{ConsensusHash, VRFSeed, BlockHeaderHash, OpsHash};

use ed25519_dalek::PublicKey as VRFPublicKey;

#[derive(Debug)]
pub enum Error {
    /// Not implemented 
    NotImplemented,
    /// Database doesn't exist
    NoDBError,
    /// DB connection error 
    ConnectionError,
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
    /// Overflow 
    Overflow,
    /// Sqlite3 error
    SqliteError(sqlite_error)
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match *self {
            Error::NotImplemented => f.write_str(error::Error::description(self)),
            Error::NoDBError => f.write_str(error::Error::description(self)),
            Error::ConnectionError => f.write_str(error::Error::description(self)),
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
            Error::ConnectionError => None,
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
            Error::ConnectionError => "Failed to connect to database",
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

pub trait ChainstateDB {
    fn backup(backup_path: &String) -> Result<(), Error>;
}

pub trait RowOrder {
    fn row_order() -> Vec<&'static str>;
}

pub trait FromRow<T> {
    fn from_row<'a>(row: &'a Row, index: usize) -> Result<T, db_error>;
}

use self::Error as db_error;

macro_rules! impl_byte_array_from_row {
    ($thing:ident) => {
        impl FromRow<$thing> for $thing {
            fn from_row<'a>(row: &'a Row, index: usize) -> Result<$thing, db_error> {
                let hex_str : String = row.get(index);
                let byte_str = hex_bytes(&hex_str)
                    .map_err(|_e| db_error::ParseError)?;
                let inst = $thing::from_bytes(&byte_str)
                    .ok_or(db_error::ParseError)?;
                Ok(inst)
            }
        }
    }
}

impl_byte_array_from_row!(Txid);
impl_byte_array_from_row!(ConsensusHash);
impl_byte_array_from_row!(Hash160);
impl_byte_array_from_row!(BlockHeaderHash);
impl_byte_array_from_row!(VRFSeed);
impl_byte_array_from_row!(OpsHash);
impl_byte_array_from_row!(BurnchainHeaderHash);

pub fn VRFPublicKey_from_row<'a>(row: &'a Row, index: usize) -> Result<VRFPublicKey, db_error> {
    let public_key_hex : String = row.get(index);
    let public_key_bytes = hex_bytes(&public_key_hex)
        .map_err(|_e| db_error::ParseError)?;

    ECVRF_check_public_key(&public_key_bytes.to_vec())
        .ok_or(db_error::ParseError)?;

    let public_key = VRFPublicKey::from_bytes(&public_key_bytes)
        .map_err(|_e| db_error::ParseError)?;
    Ok(public_key)
}

impl FromRow<BitcoinAddress> for BitcoinAddress {
    fn from_row<'a>(row: &'a Row, index: usize) -> Result<BitcoinAddress, db_error> {
        let address_b58 : String = row.get(index);
        match BitcoinAddress::from_string(&address_b58) {
            Some(a) => Ok(a),
            None => Err(db_error::ParseError)
        }
    }
}
