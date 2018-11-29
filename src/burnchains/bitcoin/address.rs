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

use burnchains::Address;
use burnchains::Hash160;
use burnchains::bitcoin::Error as btc_error;

#[derive(Debug, PartialEq)]
pub enum BitcoinAddressType {
    PublicKeyHash,
    ScriptHash
}

#[derive(Debug, PartialEq)]
pub struct BitcoinAddress {
    addrtype: BitcoinAddressType,
    bytes: Hash160
}

impl BitcoinAddress {
    pub fn from_bytes(addrtype: BitcoinAddressType, bytes: &Vec<u8>) -> Result<BitcoinAddress, btc_error> {
        if bytes.len() != 20 {
            return Err(btc_error::InvalidByteSequence);
        }

        let mut my_bytes = [0; 20];
        let b = &bytes[..bytes.len()];
        my_bytes.copy_from_slice(b);

        Ok(BitcoinAddress {
            addrtype: addrtype,
            bytes: Hash160(my_bytes)
        })
    }
}

impl Address for BitcoinAddress {
    fn to_bytes(&self) -> Vec<u8> {
        self.bytes.as_bytes().to_vec()
    }
}
