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
use std::convert::TryFrom;

use net::StacksMessageCodec;
use net::codec::{read_next, write_next};
use net::Error as net_error;

use vm::representations::{ClarityName, ContractName, SymbolicExpression, MAX_STRING_LEN as CLARITY_MAX_STRING_LENGTH};
use vm::ast::errors::ParseResult;
use vm::ast::parser::{lex, LexItem};

use vm::types::{
    Value,
    PrincipalData,
    StandardPrincipalData,
    QualifiedContractIdentifier
};

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

    fn deserialize(buf: &Vec<u8>, index_ptr: &mut u32, max_size: u32) -> Result<StacksString, net_error> {
        let mut index = *index_ptr;
        let bytes : Vec<u8> = read_next(buf, &mut index, max_size)?;

        // must encode a valid string
        let s = String::from_utf8(bytes.clone())
            .map_err(|_e| net_error::DeserializeError)?;
        
        if !StacksString::is_valid_string(&s) {
            // non-printable ASCII or not ASCII
            return Err(net_error::DeserializeError);
        }

        *index_ptr = index;

        Ok(StacksString(bytes))
    }
}

fn read_clarity_string_bytes(buf: &Vec<u8>, index_ptr: &mut u32, max_size: u32) -> Result<Vec<u8>, net_error> {
    let mut index = *index_ptr;
    let len_byte : u8 = read_next(buf, &mut index, max_size)?;
    if len_byte as usize > CLARITY_MAX_STRING_LENGTH as usize {
        return Err(net_error::DeserializeError);
    }

    if index.checked_add(len_byte as u32).is_none() {
        return Err(net_error::OverflowError);
    }
    if index + (len_byte as u32) > max_size {
        return Err(net_error::OverflowError);
    }
    if (buf.len() as u32) < index + (len_byte as u32) {
        return Err(net_error::UnderflowError);
    }

    let bytes : Vec<u8> = buf[(index as usize)..((index as usize) + (len_byte as usize))].to_vec();
    *index_ptr = index;
    Ok(bytes)
}

impl StacksMessageCodec for ClarityName {
    fn serialize(&self) -> Vec<u8> {
        let mut res = vec![];
        // ClarityName can't be longer than vm::representations::MAX_STRING_LEN, which itself is
        // a u8, so we should be good here.
        assert!(self.as_bytes().len() <= CLARITY_MAX_STRING_LENGTH as usize);
        res.push(self.as_bytes().len() as u8);
        res.extend_from_slice(self.as_bytes());
        res
    }

    fn deserialize(buf: &Vec<u8>, index_ptr: &mut u32, max_size: u32) -> Result<ClarityName, net_error> {
        let mut index = *index_ptr;
        let bytes = read_clarity_string_bytes(buf, &mut index, max_size)?;

        // must encode a valid string
        let s = String::from_utf8(bytes.clone())
            .map_err(|_e| net_error::DeserializeError)?;

        // must decode to a clarity name
        let name = ClarityName::try_from(s).map_err(|_e| net_error::DeserializeError)?;

        index = *index_ptr;
        Ok(name)
    }
}

impl StacksMessageCodec for ContractName {
    fn serialize(&self) -> Vec<u8> {
        let mut res = vec![];
        // ContractName can't be longer than vm::representations::MAX_STRING_LEN, which itself is
        // a u8, so we should be good here.
        assert!(self.as_bytes().len() <= CLARITY_MAX_STRING_LENGTH as usize);
        res.push(self.as_bytes().len() as u8);
        res.extend_from_slice(self.as_bytes());
        res
    }

    fn deserialize(buf: &Vec<u8>, index_ptr: &mut u32, max_size: u32) -> Result<ContractName, net_error> {
        let mut index = *index_ptr;
        let bytes = read_clarity_string_bytes(buf, &mut index, max_size)?;
        
        // must encode a valid string
        let s = String::from_utf8(bytes.clone())
            .map_err(|_e| net_error::DeserializeError)?;

        let name = ContractName::try_from(s).map_err(|_e| net_error::DeserializeError)?;
        *index_ptr = index;
        Ok(name)
    }
}

impl From<ClarityName> for StacksString {
    fn from(clarity_name: ClarityName) -> StacksString {
        // .unwrap() is safe since StacksString is less strict
        StacksString::from_str(&clarity_name).unwrap()
    }
}

impl From<ContractName> for StacksString {
    fn from(contract_name: ContractName) -> StacksString {
        // .unwrap() is safe since StacksString is less strict
        StacksString::from_str(&contract_name).unwrap()
    }
}

impl StacksString {
    /// Is the given string a valid Clarity string?
    pub fn is_valid_string(s: &String) -> bool {
        s.is_ascii() && StacksString::is_printable(s)
    }

    pub fn is_printable(s: &String) -> bool {
        if !s.is_ascii() {
            return false;
        }
        // all characters must be ASCII "printable" characters, excluding "delete".
        // This is 0x20 through 0x7e, inclusive, as well as '\t' and '\n'
        // TODO: DRY up with vm::representations
        for c in s.as_bytes().iter() {
            if (*c < 0x20 && *c != ('\t' as u8) && *c != ('\n' as u8)) || (*c > 0x7e) {
                return false;
            }
        }
        true
    }

    pub fn try_as_clarity_literal(&self) -> Option<Value> {
        // must parse to a single Clarity literal
        match lex(&self.to_string()) {
            Ok(lexed) => {
                if lexed.len() != 1 {
                    return None;
                }
                match lexed[0].0 {
                    LexItem::LiteralValue(_, ref value) => {
                        return Some((*value).clone());
                    }
                    _ => {
                        return None;
                    }
                }
            },
            Err(_) => {
                return None;
            }
        }
    }

    pub fn is_clarity_literal(&self) -> bool {
        self.try_as_clarity_literal().is_some()
    }
    
    pub fn from_string(s: &String) -> Option<StacksString> {
        if !StacksString::is_valid_string(s) {
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

    // TODO: ClarityName and ContractName
}

