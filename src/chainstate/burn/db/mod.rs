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

use util::vrf::ECVRF_check_public_key;
use util::hash::{hex_bytes, Hash160};

use chainstate::burn::{ConsensusHash, VRFSeed, BlockHeaderHash, OpsHash, SortitionHash};

use ed25519_dalek::PublicKey as VRFPublicKey;

use util::db;
use util::db::FromRow;
use util::db::Error as db_error;

impl_byte_array_from_row!(Txid);
impl_byte_array_from_row!(ConsensusHash);
impl_byte_array_from_row!(Hash160);
impl_byte_array_from_row!(BlockHeaderHash);
impl_byte_array_from_row!(VRFSeed);
impl_byte_array_from_row!(OpsHash);
impl_byte_array_from_row!(BurnchainHeaderHash);
impl_byte_array_from_row!(SortitionHash);

#[allow(non_snake_case)]
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

impl<A: Address> FromRow<A> for A {
    fn from_row<'a>(row: &'a Row, index: usize) -> Result<A, db_error> {
        let address_str : String = row.get(index);
        match A::from_string(&address_str) {
            Some(a) => Ok(a),
            None => Err(db_error::ParseError)
        }
    }
}

