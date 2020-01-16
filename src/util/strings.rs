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
    fn consensus_serialize(&self) -> Vec<u8> {
        let mut res = vec![];
        write_next(&mut res, &self.0);
        res
    }

    fn consensus_deserialize(buf: &[u8], index_ptr: &mut u32, max_size: u32) -> Result<StacksString, net_error> {
        let mut index = *index_ptr;
        let bytes : Vec<u8> = read_next(buf, &mut index, max_size)?;

        // must encode a valid string
        let s = String::from_utf8(bytes.clone())
            .map_err(|_e| {
                warn!("Invalid StacksString -- could not build from utf8");
                net_error::DeserializeError("Invalid Stacks string: could not build from utf8".to_string())
            })?;
        
        if !StacksString::is_valid_string(&s) {
            // non-printable ASCII or not ASCII
            warn!("Invalid StacksString -- non-printable ASCII or non-ASCII");
            return Err(net_error::DeserializeError("Invalid Stacks string: non-printable or non-ASCII string".to_string()));
        }

        *index_ptr = index;
        Ok(StacksString(bytes))
    }
}

fn read_clarity_string_bytes(buf: &[u8], index_ptr: &mut u32, max_size: u32) -> Result<Vec<u8>, net_error> {
    let mut index = *index_ptr;
    let len_byte : u8 = read_next(buf, &mut index, max_size)?;
    let len = len_byte as u32;

    if index > u32::max_value() - len {
        return Err(net_error::OverflowError(format!("Would overflow u32 to read string of {} bytes", len)));
    }
    if index + len > max_size {
        return Err(net_error::OverflowError(format!("Would read beyond end of buffer to read string of {} bytes", len)));
    }
    if (buf.len() as u32) < index + len {
        return Err(net_error::UnderflowError(format!("Not enough bytes to read string (have {}, need {})", buf.len(), index + len)));
    }

    let bytes : Vec<u8> = buf[(index as usize)..((index + len) as usize)].to_vec();
    index += len;

    *index_ptr = index;
    Ok(bytes)
}

impl StacksMessageCodec for ClarityName {
    fn consensus_serialize(&self) -> Vec<u8> {
        let mut res = vec![];
        // ClarityName can't be longer than vm::representations::MAX_STRING_LEN, which itself is
        // a u8, so we should be good here.
        assert!(self.as_bytes().len() <= CLARITY_MAX_STRING_LENGTH as usize);
        res.push(self.as_bytes().len() as u8);
        res.extend_from_slice(self.as_bytes());
        res
    }

    fn consensus_deserialize(buf: &[u8], index_ptr: &mut u32, max_size: u32) -> Result<ClarityName, net_error> {
        let mut index = *index_ptr;
        let bytes = read_clarity_string_bytes(buf, &mut index, max_size)?;

        // must encode a valid string
        let s = String::from_utf8(bytes)
            .map_err(|_e| net_error::DeserializeError("Failed to parse Clarity name: could not contruct from utf8".to_string()))?;

        // must decode to a clarity name
        let name = ClarityName::try_from(s).map_err(|e| net_error::DeserializeError(format!("Failed to parse Clarity name: {:?}", e)))?;
        *index_ptr = index;
        Ok(name)
    }
}

impl StacksMessageCodec for ContractName {
    fn consensus_serialize(&self) -> Vec<u8> {
        let mut res = vec![];
        // ContractName can't be longer than vm::representations::MAX_STRING_LEN, which itself is
        // a u8, so we should be good here.
        assert!(self.as_bytes().len() <= CLARITY_MAX_STRING_LENGTH as usize);
        res.push(self.as_bytes().len() as u8);
        res.extend_from_slice(self.as_bytes());
        res
    }

    fn consensus_deserialize(buf: &[u8], index_ptr: &mut u32, max_size: u32) -> Result<ContractName, net_error> {
        let mut index = *index_ptr;
        let bytes = read_clarity_string_bytes(buf, &mut index, max_size)?;
        
        // must encode a valid string
        let s = String::from_utf8(bytes)
            .map_err(|_e| net_error::DeserializeError("Failed to parse Contract name: could not construct from utf8".to_string()))?;

        let name = ContractName::try_from(s).map_err(|e| net_error::DeserializeError(format!("Failed to parse Contract name: {:?}", e)))?;
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

    pub fn is_clarity_variable(&self) -> bool {
        // must parse to a single Clarity variable
        match lex(&self.to_string()) {
            Ok(lexed) => {
                if lexed.len() != 1 {
                    return false;
                }
                match lexed[0].0 {
                    LexItem::Variable(_) => {
                        true
                    },
                    _ => {
                        false
                    }
                }
            },
            Err(_) => {
                false
            }
        }
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
    fn tx_stacks_strings_codec() {
        let s = "hello-world";
        let stacks_str = StacksString::from_str(&s).unwrap();
        let clarity_str = ClarityName::try_from(s.clone()).unwrap();
        let contract_str = ContractName::try_from(s.clone()).unwrap();

        assert_eq!(stacks_str[..], s.as_bytes().to_vec()[..]);
        let s2 = stacks_str.to_string();
        assert_eq!(s2.to_string(), s.to_string());

        // stacks strings have a 4-byte length prefix
        let b = stacks_str.consensus_serialize();
        let mut bytes = vec![0x00, 0x00, 0x00, s.len() as u8];
        bytes.extend_from_slice(s.as_bytes());

        check_codec_and_corruption::<StacksString>(&stacks_str, &bytes);

        // clarity names and contract names have a 1-byte length prefix
        let mut clarity_bytes = vec![s.len() as u8];
        clarity_bytes.extend_from_slice(clarity_str.as_bytes());
        check_codec_and_corruption::<ClarityName>(&clarity_str, &clarity_bytes);

        let mut contract_bytes = vec![s.len() as u8];
        contract_bytes.extend_from_slice(contract_str.as_bytes());
        check_codec_and_corruption::<ContractName>(&contract_str, &clarity_bytes);
    }

    #[test]
    fn tx_stacks_string_invalid() {
        let s = "hello\rworld";
        assert!(StacksString::from_str(&s).is_none());

        let s = "hello\x01world";
        assert!(StacksString::from_str(&s).is_none());
    }
}

