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

use net::StacksMessageCodec;
use net::Error as net_error;
use net::codec::{read_next, write_next};

use chainstate::stacks::StacksAddress;

use util::hash::Hash160;

impl StacksMessageCodec for StacksAddress {
    fn serialize(&self) -> Vec<u8> {
        let mut res = vec![];
        write_next(&mut res, &self.version);
        write_next(&mut res, &self.bytes.as_bytes().to_vec());
        res
    }

    fn deserialize(buf: &Vec<u8>, index: &mut u32, max_size: u32) -> Result<StacksAddress, net_error> {
        let version : u8    = read_next(buf, index, max_size)?;
        let bytes : Hash160 = read_next(buf, index, max_size)?;
        Ok(StacksAddress {
            version: version,
            bytes: bytes
        })
    }
}
