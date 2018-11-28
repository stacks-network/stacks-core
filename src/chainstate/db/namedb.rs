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

use chainstate::db::ChainstateDB;
use chainstate::db::Error as db_error;

pub struct NameDB {

}

impl NameDB {
    pub fn connect(path: &String) -> Result<NameDB, db_error> {
        return Err(db_error::NotImplemented);
    }
}

impl ChainstateDB for NameDB {
    fn backup(backup_path: &String) -> Result<(), db_error> {
        return Err(db_error::NotImplemented);
    }
}
