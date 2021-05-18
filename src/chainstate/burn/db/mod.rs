// Copyright (C) 2013-2020 Blockstack PBC, a public benefit corporation
// Copyright (C) 2020 Stacks Open Internet Foundation
//
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.
//
// This program is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
// GNU General Public License for more details.
//
// You should have received a copy of the GNU General Public License
// along with this program.  If not, see <http://www.gnu.org/licenses/>.

use std::error;
use std::fmt;

use rusqlite::Connection;
use rusqlite::Error as sqlite_error;
use rusqlite::Row;
use serde_json::Error as serde_error;

use crate::types::proof::TrieHash;
use burnchains::{Address, Txid};
use chainstate::burn::{ConsensusHash, OpsHash, SortitionHash};
use chainstate::stacks::StacksPublicKey;
use util::db;
use util::db::Error as db_error;
use util::db::FromColumn;
use util::hash::{hex_bytes, Hash160, Sha512Trunc256Sum};
use util::secp256k1::MessageSignature;
use util::vrf::*;

use crate::types::chainstate::{BlockHeaderHash, BurnchainHeaderHash, VRFSeed};

pub mod processing;
pub mod sortdb;

pub type DBConn = Connection;

impl_byte_array_from_column!(Txid);
impl_byte_array_from_column!(ConsensusHash);
impl_byte_array_from_column!(Hash160);
impl_byte_array_from_column!(BlockHeaderHash);
impl_byte_array_from_column!(VRFSeed);
impl_byte_array_from_column!(OpsHash);
impl_byte_array_from_column!(BurnchainHeaderHash);
impl_byte_array_from_column!(SortitionHash);
impl_byte_array_from_column!(Sha512Trunc256Sum);
impl_byte_array_from_column!(VRFProof);
impl_byte_array_from_column!(TrieHash);
impl_byte_array_from_column!(MessageSignature);

impl FromColumn<VRFPublicKey> for VRFPublicKey {
    fn from_column<'a>(row: &'a Row, column_name: &str) -> Result<VRFPublicKey, db_error> {
        let pubkey_hex: String = row.get_unwrap(column_name);
        match VRFPublicKey::from_hex(&pubkey_hex) {
            Some(pubk) => Ok(pubk),
            None => Err(db_error::ParseError),
        }
    }
}

impl<A: Address> FromColumn<A> for A {
    fn from_column<'a>(row: &'a Row, column_name: &str) -> Result<A, db_error> {
        let address_str: String = row.get_unwrap(column_name);
        match A::from_string(&address_str) {
            Some(a) => Ok(a),
            None => Err(db_error::ParseError),
        }
    }
}
