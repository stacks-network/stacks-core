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

use std::ops::Deref;
use std::ops::DerefMut;

use net::StacksMessageCodec;
use net::codec::{read_next, write_next};
use net::Error as net_error;

/// printable-ASCII-only string, but encodable.
/// Note that it cannot be longer than ARRAY_MAX_LEN (4.1 billion bytes)
#[derive(Clone, PartialEq)]
pub struct StacksString(Vec<u8>);

impl fmt::Display for StacksString {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        f.write_str(String::from_utf8_lossy(&self).into_owned().as_str())
    }
}

impl fmt::Debug for StacksString {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(String::from_utf8_lossy(&self).into_owned().as_str())
    }
}

impl Deref for StacksString {
    type Target = Vec<u8>;
    fn deref(&self) -> &Vec<u8> {
        &self.0
    }
}

impl DerefMut for StacksString {
    fn deref_mut(&mut self) -> &mut Vec<u8> {
        &mut self.0
    }
}

impl StacksMessageCodec for StacksString {
    fn serialize(&self) -> Vec<u8> {
        let mut res = vec![];
        write_next(&mut res, &self.0);
        res
    }

    fn deserialize(buf: &Vec<u8>, index: &mut u32, max_size: u32) -> Result<StacksString, net_error> {
        let bytes : Vec<u8> = read_next(buf, index, max_size)?;

        // must encode a valid string
        let s = String::from_utf8(bytes.clone())
            .map_err(|_e| net_error::DeserializeError)?;
        
        if !StacksString::is_valid_string(&s) {
            // non-printable ASCII or not ASCII
            return Err(net_error::DeserializeError);
        }

        Ok(StacksString(bytes))
    }
}

impl StacksString {
    /// Is the given string a valid Clarity string?
    pub fn is_valid_string(s: &String) -> bool {
        s.is_ascii() && StacksString::is_printable(s)
    }

    /// Is the given string a well-formed name for a Clarity smart contract?
    pub fn is_valid_contract_name(s: &String) -> bool {
        StacksString::is_valid_string(s) && s.find('.').is_none()
    }
    
    /// Is the given string a well-formed name for a Clarity asset?
    pub fn is_valid_asset_name(s: &String) -> bool {
        // TODO: verify that we don't want periods in asset names
        StacksString::is_valid_string(s) && s.find('.').is_none()
    }

    /// Is the given string a well-formed name for a non-fungible token?
    pub fn is_valid_nft_name(s: &String) -> bool {
        // TODO: verify that this is sufficient
        StacksString::is_valid_string(s)
    }

    pub fn is_printable(s: &String) -> bool {
        if !s.is_ascii() {
            return false;
        }
        // all characters must be ASCII "printable" characters, excluding "delete".
        // This is 0x20 through 0x7e, inclusive
        for c in s.as_bytes().iter() {
            if (*c as u8) < 0x20 || (*c as u8) > 0x7e {
                return false;
            }
        }
        true
    }

    pub fn from_string(s: &String) -> Option<StacksString> {
        if !StacksString::is_valid_string(s) {
            return None;
        }
        Some(StacksString(s.as_bytes().to_vec()))
    }

    pub fn from_contract_name(s: &String) -> Option<StacksString> {
        if !StacksString::is_valid_contract_name(s) {
            return None;
        }
        Some(StacksString(s.as_bytes().to_vec()))
    }

    pub fn from_asset_name(s: &String) -> Option<StacksString> {
        if !StacksString::is_valid_asset_name(s) {
            return None;
        }
        Some(StacksString(s.as_bytes().to_vec()))
    }

    pub fn from_nft_name(s: &String) -> Option<StacksString> {
        if !StacksString::is_valid_nft_name(s) {
            return None;
        }
        Some(StacksString(s.as_bytes().to_vec()))
    }

    pub fn from_str(s: &str) -> Option<StacksString> {
        if !StacksString::is_valid_string(&String::from(s)) {
            return None;
        }
        Some(StacksString(s.as_bytes().to_vec()))
    }

    pub fn to_string(&self) -> String {
        // guaranteed to always succeed because the string is ASCII
        String::from_utf8(self.0.clone()).unwrap()
    }
}

#[cfg(test)]
mod test {
    use super::*;

    use net::*;
    use net::codec::*;
    use net::codec::test::check_codec_and_corruption;

    #[test]
    fn tx_stacks_string() {
        let s = "hello world";
        let stacks_str = StacksString::from_str(&s).unwrap();

        assert_eq!(stacks_str[..], s.as_bytes().to_vec()[..]);
        let s2 = stacks_str.to_string();
        assert_eq!(s2.to_string(), s.to_string());

        let b = stacks_str.serialize();
        let mut bytes = vec![0x00, 0x00, 0x00, s.len() as u8];
        bytes.extend_from_slice(s.as_bytes());

        check_codec_and_corruption::<StacksString>(&stacks_str, &bytes);
    }
}

