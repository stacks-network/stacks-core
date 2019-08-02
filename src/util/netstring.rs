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

use address::c32::{
    c32_address,
    c32_address_decode
};

use util::log;
use util::hash::to_hex;
use util::hash::hex_bytes;

use std::fmt;
use std::str;

use vm::types::{
    Value,
    BuffData,
    ListData,
    PrincipalData,
    TupleData,
    OptionalData,
    ResponseData,
    TypeSignature,
    AtomTypeIdentifier,
};

mod NetstringTypeID {
    pub const Int : u8 = 'i' as u8;
    pub const Bool : u8 = 'b' as u8;
    pub const Buffer : u8 = 's' as u8;
    pub const List : u8 = 'l' as u8;
    pub const StandardPrincipal : u8 = 'p' as u8;
    pub const ContractPrincipal : u8 = 'c' as u8;
    pub const Tuple : u8 = 't' as u8;
    pub const Optional : u8 = 'o' as u8;
    pub const Response : u8 = 'r' as u8;
    pub const Name : u8 = 'n' as u8;
    pub const Void : u8 = 'v' as u8;
}


/// Helper method to convert a Value into a typed netstring
fn to_typed_netstring_helper(value: &Value, so_far: &String) -> String {
    let next_str = match value {
        Value::Int(ref i) => {
            let i_str = format!("{}", i);
            let ni_str = format!("{}{}:{},", NetstringTypeID::Int as char, i_str.len(), i_str);
            ni_str
        },
        Value::Bool(ref b) => {
            if *b {
                format!("{}1:1,", NetstringTypeID::Bool as char)
            }
            else {
                format!("{}1:0,", NetstringTypeID::Bool as char)
            }
        },
        Value::Buffer(ref s) => {
            format!("{}{}:{},", NetstringTypeID::Buffer as char, s.data.len() * 2, to_hex(&s.data))
        },
        Value::List(ref l) => {
            let mut list_strs = Vec::with_capacity(l.data.len());
            for list_value in l.data.iter() {
                let list_value_str = to_typed_netstring_helper(list_value, &"".to_string());
                list_strs.push(list_value_str);
            }
            let list_str = list_strs.join("");
            format!("{}{}:{},", NetstringTypeID::List as char, list_str.len(), list_str)
        },
        Value::Principal(ref p) => {
            match p {
                PrincipalData::StandardPrincipal(ref version, ref data) => {
                    let addr = c32_address(*version, data)
                        .map_err(|_| panic!("Invalid standard principal data: {} {:?}", version, &data.to_vec()))
                        .unwrap();

                    format!("{}{}:{},", NetstringTypeID::StandardPrincipal as char, addr.len(), addr)
                },
                PrincipalData::ContractPrincipal(ref s) => {
                    format!("{}{}:{},", NetstringTypeID::ContractPrincipal as char, s.len(), s.clone())
                }
            }
        },
        Value::Tuple(ref t) => {
            let tuple_data_map = t.get_all();
            let mut tuple_strs = Vec::with_capacity(tuple_data_map.len());
            for (ref tuple_name, ref tuple_value) in tuple_data_map.iter() {
                let tuple_name_str = format!("{}{}:{},", NetstringTypeID::Name as char, tuple_name.len(), tuple_name);
                let tuple_value_str = to_typed_netstring_helper(tuple_value, &"".to_string());
                let tuple_body_str = format!("{}{}", &tuple_name_str, &tuple_value_str);
                tuple_strs.push(tuple_body_str);
            }
            let tuple_str = tuple_strs.join("");
            format!("{}{}:{},", NetstringTypeID::Tuple as char, tuple_str.len(), tuple_str)
        },
        Value::Optional(ref o) => {
            match o.data {
                Some(ref some_value) => {
                    let some_value_str = to_typed_netstring_helper(some_value, &"".to_string());
                    format!("{}{}:{},", NetstringTypeID::Optional as char, some_value_str.len(), &some_value_str)
                },
                None => {
                    format!("{}4:{}0:,,", NetstringTypeID::Optional as char, NetstringTypeID::Void as char)
                }
            }
        },
        Value::Response(ref r) => {
            if r.committed {
                // OK response
                let ok_value_str = to_typed_netstring_helper(&r.data, &"".to_string());
                format!("{}{}:o{},", NetstringTypeID::Response as char, ok_value_str.len() + 1, &ok_value_str)
            }
            else {
                // ERR response
                let err_value_str = to_typed_netstring_helper(&r.data, &"".to_string());
                format!("{}{}:e{},", NetstringTypeID::Response as char, err_value_str.len() + 1, &err_value_str)
            }
        }
    };

    format!("{}{}", so_far, next_str)
}

/// Convert a Clarity Value into a typed netstring
pub fn to_typed_netstring(value: &Value) -> String {
    to_typed_netstring_helper(value, &"".to_string())
}

/// Read the length of a netstring fragment.
/// Return the length, and the index into the netstring where the fragment begins.
fn scan_typed_netstring_length(netstr_bytes: &[u8]) -> Option<(usize, usize)> {
    let mut i = 1;
    if netstr_bytes.len() < 3 {
        test_debug!("Invalid typed netstring: less than 3 bytes");
        return None;
    }
    while i < netstr_bytes.len() && netstr_bytes[i] != (':' as u8) {
        i += 1;
    }
    if i >= netstr_bytes.len() {
        test_debug!("Invalid typed netstring: no ':' in '{}'", &str::from_utf8(netstr_bytes).unwrap());
        return None;
    }

    let sz = match str::from_utf8(&netstr_bytes[1..i]).unwrap().parse::<usize>() {
        Ok(res) => {
            res
        },
        Err(_) => {
            test_debug!("Invalid typed netstring: unparseable length '{}'", &str::from_utf8(&netstr_bytes[1..i]).unwrap());
            return None;
        }
    };

    i += 1;
    if i + sz >= netstr_bytes.len() {
        test_debug!("Invalid typed netstring: i + sz = {}, len is {}.  String is '{}'", i + sz, netstr_bytes.len(), &str::from_utf8(netstr_bytes).unwrap());
        return None;
    }
    
    if netstr_bytes[i + sz] != (',' as u8) {
        test_debug!("Invalid typed netstring: no ',' found at {} + {} = {} in '{}'", i, sz, i + sz, &str::from_utf8(netstr_bytes).unwrap());
        return None;
    }
    
    return Some((sz, i))
}

/// chomp the next netstring fragment.
/// Return the type, fragment, and remainder
/// NOTE: netstr _must_ be ASCII, or this method panics
fn chomp_typed_netstring(netstr: &String) -> Option<(u8, String, String)> {
    let netstr_bytes = netstr.as_bytes();
    let type_byte = netstr_bytes[0];
    let (sz, i) = match scan_typed_netstring_length(&netstr_bytes) {
        Some(res) => {
            res
        },
        None => {
            test_debug!("Failed to scan typed netstring for size and fragment offset: '{}'", &str::from_utf8(&netstr_bytes[1..]).unwrap());
            return None;
        }
    };

    let fragment = str::from_utf8(&netstr_bytes[i..(i+sz)]).unwrap().to_string();
    let remainder = str::from_utf8(&netstr_bytes[(i+sz+1)..]).unwrap().to_string();
    return Some((type_byte, fragment, remainder));
}

/// Parse a netstring fragment into a Clarity value
fn parse_typed_netstring(netstr: &String) -> Option<(Value, String)> {
    let (type_byte, fragment, remainder) = match chomp_typed_netstring(netstr) {
        Some(res) => {
            res
        },
        None => {
            test_debug!("Failed to chomp next fragment from typed netstring '{}'", netstr);
            return None;
        }
    };

    let value = match type_byte {
        NetstringTypeID::Int => {
            let int_value = match fragment.parse::<i128>() {
                Ok(i) => {
                    i
                },
                Err(_) => {
                    test_debug!("Failed to parse '{}' to an integer", &fragment);
                    return None;
                }
            };
            Value::Int(int_value)
        },
        NetstringTypeID::Bool => {
            if fragment == "1" {
                Value::Bool(true)
            }
            else if fragment == "0" {
                Value::Bool(false)
            }
            else {
                test_debug!("Invalid boolean fragment '{}'", &fragment);
                return None;
            }
        },
        NetstringTypeID::Buffer => {
            if fragment.len() % 2 != 0 {
                test_debug!("Buffer fragment must have even length: '{}'", &fragment);
                return None;
            }

            let fragment_bytes = fragment.as_bytes();
            for i in 0..fragment_bytes.len() {
                if !(fragment_bytes[i] >= ('0' as u8) && fragment_bytes[i] <= ('9' as u8)) &&
                   !(fragment_bytes[i] >= ('a' as u8) && fragment_bytes[i] <= ('f' as u8)) {
                   test_debug!("Buffer fragment must be lower-case hex: '{}'", &fragment);
                   return None;
                }
            }

            let bytes = match hex_bytes(&fragment) {
                Ok(bytes) => {
                    bytes
                },
                Err(_) => {
                    test_debug!("Buffer fragment is not hex: '{}'", &fragment);
                    return None;
                }
            };

            match Value::buff_from(bytes) {
                Ok(buffer_value) => {
                    buffer_value
                },
                Err(_) => {
                    test_debug!("Buffer fragment does not encode a valid buffer: '{}'", &fragment);
                    return None;
                }
            }
        },
        NetstringTypeID::List => {
            let mut values = vec![];
            let mut next_fragment = fragment.clone();
            while next_fragment.len() > 0 {
                let (next_value, next_remainder) = match parse_typed_netstring(&next_fragment) {
                    Some(res) => {
                        res
                    },
                    None => {
                        test_debug!("Failed to parse list fragment '{}'", &next_fragment);
                        return None;
                    }
                };
                values.push(next_value);
                next_fragment = next_remainder;
            }

            match Value::list_from(values) {
                Ok(list_value) => {
                    list_value
                },
                Err(_) => {
                    test_debug!("List fragment does not encode a valid list: '{}'", &fragment);
                    return None;
                }
            }
        },
        NetstringTypeID::StandardPrincipal => {
            let principal_data = match c32_address_decode(&fragment) {
                Ok((version, bytes)) => {
                    if bytes.len() == 20 {
                        let mut hash160_bytes = [0u8; 20];
                        hash160_bytes.copy_from_slice(&bytes[..]);
                        PrincipalData::StandardPrincipal(version, hash160_bytes)
                    }
                    else {
                        test_debug!("Invalid standard principal fragment '{}'", &fragment);
                        return None;
                    }
                },
                Err(_) => {
                    test_debug!("Unparseable standard principal fragment '{}'", &fragment);
                    return None;
                }
            };
            Value::Principal(principal_data)
        },
        NetstringTypeID::ContractPrincipal => {
            Value::Principal(PrincipalData::ContractPrincipal(fragment))
        },
        NetstringTypeID::Tuple => {
            let mut next_fragment = fragment.clone();
            let mut tuple_parts = vec![];
            while next_fragment.len() > 0 {
                let (name_type_byte, name_string, name_remainder) = match chomp_typed_netstring(&fragment) {
                    Some(res) => {
                        res
                    },
                    None => {
                        test_debug!("Failed to chomp next fragment from typle typed netstring '{}'", &fragment);
                        return None;
                    }
                };
                if name_type_byte != NetstringTypeID::Name {
                    test_debug!("Tuple fragment does not start with a name: '{}'", &fragment);
                    return None;
                }
                
                let (tuple_value, tuple_remainder) = match parse_typed_netstring(&name_remainder) {
                    Some(res) => {
                        res
                    },
                    None => {
                        test_debug!("Failed to parse tuple value fragment '{}'", &name_remainder);
                        return None;
                    }
                };
                tuple_parts.push((name_string, tuple_value));
                next_fragment = tuple_remainder.clone();
            }
            match Value::tuple_from_data(tuple_parts.clone()) {
                Ok(tuple) => {
                    tuple
                },
                Err(_) => {
                    test_debug!("Failed to construct tuple from '{:?}'", &tuple_parts);
                    return None;
                }
            }
        },
        NetstringTypeID::Optional => {
            if fragment == format!("{}0:,", NetstringTypeID::Void as char) {
                Value::Optional(OptionalData { data: None })
            }
            else {
                match parse_typed_netstring(&fragment) {
                    Some((value, rest)) => {
                        if rest.len() > 0 {
                            test_debug!("Failed to parse inner option fragment: '{}'", &fragment);
                            return None;
                        }
                        Value::Optional(OptionalData { data: Some(Box::new(value)) })
                    },
                    None => {
                        test_debug!("Failed to parse optional value fragment '{}'", &fragment);
                        return None;
                    }
                }
            }
        },
        NetstringTypeID::Response => {
            let fragment_bytes = fragment.as_bytes();
            if fragment_bytes.len() < 3 {
                test_debug!("Invalid response fragment '{}'", &fragment);
                return None;
            }
            
            let response_byte = fragment_bytes[0];
            if response_byte != ('o' as u8) && response_byte != ('e' as u8) {
                test_debug!("Invalid response fragment '{}': not an OK or ERR", &fragment);
                return None;
            }

            let response_fragment = str::from_utf8(&fragment_bytes[1..]).unwrap().to_string();
            let (response_value, response_value_remainder) = match parse_typed_netstring(&response_fragment) {
                Some(res) => {
                    res
                },
                None => {
                    test_debug!("Failed to parse inner response fragment '{}'", &response_fragment);
                    return None;
                }
            };
            if response_value_remainder.len() > 0 {
                test_debug!("Invalid inner response fragment '{}': got remainder '{}'", &response_fragment, &response_value_remainder);
                return None;
            }
            Value::Response(ResponseData { committed: (response_byte == 'o' as u8), data: Box::new(response_value) })
        }
        _ => {
            test_debug!("Invalid type byte '{}'", type_byte as char);
            return None;
        }
    };

    Some((value, remainder))
}


/// Parse a netstring into a Clarity Value
pub fn from_typed_netstring(netstr: &String) -> Option<Value> {
    if !netstr.is_ascii() {
        return None;
    }
    let (value, remainder) = match parse_typed_netstring(netstr) {
        Some(res) => {
            res
        },
        None => {
            test_debug!("Failed to parse netstring '{}'", netstr);
            return None;
        }
    };

    if remainder.len() > 0 {
        test_debug!("Invalid netstring '{}': got remainder '{}'", netstr, &remainder);
        return None;
    }
    Some(value)
}

#[cfg(test)]
mod test {

    use super::*;
    use vm::types::*;
    use util::hash::*;

    #[test]
    fn test_parse_sip_netstrings() {
        let netstrings = [
            "i3:123,",
            "s8:deadbeef,",
            "b1:1,",
            "b1:0,",
            "p40:SPEDP913HD52QSTK7H2EFBANGXMVF8E2EVHEVQJS,",
            "t23:n4:word,s10:68656c6c6f,,",
            "l23:i1:1,i1:2,i2:34,i3:567,,",
            "o5:i1:3,,",
            "o4:v0:,,",
            "r6:ob1:1,,",
            "r8:ei3:123,,"
        ];
        let values = [
            Value::Int(123),
            Value::buff_from(vec![0xde, 0xad, 0xbe, 0xef]).unwrap(),
            Value::Bool(true),
            Value::Bool(false),
            Value::Principal(PrincipalData::StandardPrincipal(22, [0x1c, 0xdb, 0x24, 0x23, 0x8b, 0x4a, 0x2b, 0xe7, 0x53, 0x3c, 0x44, 0xe7, 0xad, 0x55, 0x87, 0x69, 0xb7, 0xa1, 0xc2, 0x76])),
            Value::tuple_from_data(vec![("word".to_string(), Value::buff_from(vec![0x68, 0x65, 0x6c, 0x6c, 0x6f]).unwrap())]).unwrap(),
            Value::list_from(vec![Value::Int(1), Value::Int(2), Value::Int(34), Value::Int(567)]).unwrap(),
            Value::some(Value::Int(3)),
            Value::none(),
            Value::Response(ResponseData { committed: true, data: Box::new(Value::Bool(true)) }),
            Value::Response(ResponseData { committed: false, data: Box::new(Value::Int(123)) })
        ];

        for i in 0..netstrings.len() {
            test_debug!("{} <--> {:?}", &netstrings[i], &values[i]);
            let value = from_typed_netstring(&netstrings[i].to_string()).unwrap();
            let netstr = to_typed_netstring(&values[i]);

            assert_eq!(value, values[i]);
            assert_eq!(netstr, netstrings[i].to_string());
        }
    }

    #[test]
    fn test_parse_int_error() {
        let netstrings_invalid = [
            "i2:0,",        // overflow length
            "i1:10,",       // underflow length
            "i3:100",       // no comma
            "d39:170141183460469231731687303715884105727,", // unrecognized type
            "i2:,",         // no data
            "i3:-10,,",     // too much data
            "i40:-170141183460469231731687303715884105729,",        // doesn't fit into type
            "i39:170141183460469231731687303715884105728,",        // doesn't fit into type
            "i0:,",          // no data
            "i-1:,",        // negative length
        ];
        for i in 0..netstrings_invalid.len() {
            test_debug!("Invalid: {}", &netstrings_invalid[i]);
            assert!(from_typed_netstring(&netstrings_invalid[i].to_string()).is_none());
        }
    }

    #[test]
    fn test_parse_int() {
        let netstrings_valid = [
            "i1:0,",
            "i2:10,",
            "i3:100,",
            "i39:170141183460469231731687303715884105727,",
            "i2:-1,",
            "i3:-10,",
            "i4:-100,",
            "i40:-170141183460469231731687303715884105728,",
        ];
        let values_valid = [
            Value::Int(0),
            Value::Int(10),
            Value::Int(100),
            Value::Int(170141183460469231731687303715884105727i128),
            Value::Int(-1),
            Value::Int(-10),
            Value::Int(-100),
            Value::Int(-170141183460469231731687303715884105728i128)
        ];

        for i in 0..netstrings_valid.len() {
            test_debug!("{} <--> {:?}", &netstrings_valid[i], &values_valid[i]);
            let value = from_typed_netstring(&netstrings_valid[i].to_string()).unwrap();
            let netstr = to_typed_netstring(&values_valid[i]);

            assert_eq!(value, values_valid[i]);
            assert_eq!(netstr, netstrings_valid[i].to_string());
        }
    }

    #[test]
    fn test_parse_error_bool() {
        let netstrings_invalid = [
            "b0:0,",
            "b2:0,",
            "b1:2,",
            "b1:a,",
        ];

        for i in 0..netstrings_invalid.len() {
            test_debug!("Invalid: {}", &netstrings_invalid[i]);
            assert!(from_typed_netstring(&netstrings_invalid[i].to_string()).is_none());
        }
    }

    #[test]
    fn test_parse_bool() {
        let netstrings_valid = [
            "b1:0,",
            "b1:1,",
        ];
        let values_valid = [
            Value::Bool(false),
            Value::Bool(true)
        ];

        for i in 0..netstrings_valid.len() {
            test_debug!("{} <--> {:?}", &netstrings_valid[i], &values_valid[i]);
            let value = from_typed_netstring(&netstrings_valid[i].to_string()).unwrap();
            let netstr = to_typed_netstring(&values_valid[i]);

            assert_eq!(value, values_valid[i]);
            assert_eq!(netstr, netstrings_valid[i].to_string());
        }
    }

    #[test]
    fn test_parse_principal_error() {
        let netstrings_invalid = [
            "p41:SP25CN0FJJJN513DK4SVWG29XNCGFA9Y212FA078V,",    // bad checksum
            "p39:SP8NJM1YAAAMM4DPCK7FJ097PNJ1X97RBFJ4T8W",       // invalid length
            "p41:SP25CN0FJJJN513DK4SVWG29XNCGFA9Y212FA078v,",    // bad alphabet
            "c4:hello,",
            "c5:hello,,",
            "c0:,,",
            "p0:,,",
            "c-1:,,",
        ];

        for i in 0..netstrings_invalid.len() {
            test_debug!("Invalid: {}", &netstrings_invalid[i]);
            assert!(from_typed_netstring(&netstrings_invalid[i].to_string()).is_none());
        }
    }

    #[test]
    fn test_parse_principal() {
        let netstrings_valid = [
            "p41:SP25CN0FJJJN513DK4SVWG29XNCGFA9Y212FA078Y,",
            "c5:hello,",
            "c41:SP2X8XE7PVAN001ERWT2QD1GYX8MG38MES7HCRGHT,",
        ];
        let values_valid = [
            Value::Principal(PrincipalData::StandardPrincipal(22, [0x8a, 0xca, 0x81, 0xf2, 0x94, 0xaa, 0x50, 0x8d, 0xb3, 0x26, 0x77, 0xc8, 0x09, 0x3d, 0xab, 0x20, 0xf5, 0x27, 0xc2, 0x08])),
            Value::Principal(PrincipalData::ContractPrincipal("hello".to_string())),
            Value::Principal(PrincipalData::ContractPrincipal("SP2X8XE7PVAN001ERWT2QD1GYX8MG38MES7HCRGHT".to_string()))
        ];

        for i in 0..netstrings_valid.len() {
            test_debug!("{} <--> {:?}", &netstrings_valid[i], &values_valid[i]);
            let value = from_typed_netstring(&netstrings_valid[i].to_string()).unwrap();
            let netstr = to_typed_netstring(&values_valid[i]);

            assert_eq!(value, values_valid[i]);
            assert_eq!(netstr, netstrings_valid[i].to_string());
        }
    }

    #[test]
    fn test_parse_buffer_error() {
        let netstrings_invalid = [
            "s2:0g,",       // invalid character
            "s2:0A,",       // upper-case
            "s3:000,",      // odd number
            "s2:00,,",
            "s2:00",
            "s-1:,"
        ];

        for i in 0..netstrings_invalid.len() {
            test_debug!("Invalid: {}", &netstrings_invalid[i]);
            assert!(from_typed_netstring(&netstrings_invalid[i].to_string()).is_none());
        }
    }

    #[test]
    fn test_parse_buffer() {
        let netstrings_valid = [
            "s0:,",
            "s2:00,",
            "s10:0011223344,",
            "s100:000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f202122232425262728292a2b2c2d2e2f3031,",
        ];
        let values_valid = [
            Value::buff_from(vec![]).unwrap(),
            Value::buff_from(vec![0x00]).unwrap(),
            Value::buff_from(vec![0x00, 0x11, 0x22, 0x33, 0x44]).unwrap(),
            Value::buff_from(hex_bytes("000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f202122232425262728292a2b2c2d2e2f3031").unwrap()).unwrap()
        ];

        for i in 0..netstrings_valid.len() {
            test_debug!("{} <--> {:?}", &netstrings_valid[i], &values_valid[i]);
            let value = from_typed_netstring(&netstrings_valid[i].to_string()).unwrap();
            let netstr = to_typed_netstring(&values_valid[i]);

            assert_eq!(value, values_valid[i]);
            assert_eq!(netstr, netstrings_valid[i].to_string());
        }
    }

    #[test]
    fn test_parse_list() {
        let netstrings_valid = [
            "l0:,",

            "l5:i1:1,,",
            "l6:s2:00,,",
            "l46:p41:SP25CN0FJJJN513DK4SVWG29XNCGFA9Y212FA078Y,,",
            "l29:t23:n4:word,s10:68656c6c6f,,,",
            "l5:b1:0,,",
            "l9:o5:i1:3,,,",
            "l10:r6:ob1:1,,,",
            "l12:r8:ei3:123,,,",

            "l10:i1:1,i1:2,,",
            "l12:s2:00,s2:11,,",
            "l92:p41:SP25CN0FJJJN513DK4SVWG29XNCGFA9Y212FA078Y,p41:SP25CN0FJJJN513DK4SVWG29XNCGFA9Y212FA078Y,,",
            "l55:p41:SP25CN0FJJJN513DK4SVWG29XNCGFA9Y212FA078Y,c5:hello,,",
            "l58:t23:n4:word,s10:68656c6c6f,,t23:n4:dupe,s10:0011223344,,,",
            "l10:b1:0,b1:1,,",
            "l18:o5:i1:3,,o4:v0:,,,",
            "l20:r6:ob1:1,,r6:ob1:0,,,",
            "l24:r8:ei3:123,,r8:ei3:456,,,"
        ];
        let values_valid = [
            Value::list_from(vec![]).unwrap(),

            Value::list_from(vec![Value::Int(1)]).unwrap(),
            Value::list_from(vec![Value::buff_from(vec![0x00]).unwrap()]).unwrap(),
            Value::list_from(vec![Value::Principal(PrincipalData::StandardPrincipal(22, [0x8a, 0xca, 0x81, 0xf2, 0x94, 0xaa, 0x50, 0x8d, 0xb3, 0x26, 0x77, 0xc8, 0x09, 0x3d, 0xab, 0x20, 0xf5, 0x27, 0xc2, 0x08]))]).unwrap(),
            Value::list_from(vec![Value::tuple_from_data(vec![("word".to_string(), Value::buff_from(vec![0x68, 0x65, 0x6c, 0x6c, 0x6f]).unwrap())]).unwrap()]).unwrap(),
            Value::list_from(vec![Value::Bool(false)]).unwrap(),
            Value::list_from(vec![Value::some(Value::Int(3))]).unwrap(),
            Value::list_from(vec![Value::Response(ResponseData { committed: true, data: Box::new(Value::Bool(true)) })]).unwrap(),
            Value::list_from(vec![Value::Response(ResponseData { committed: false, data: Box::new(Value::Int(123)) })]).unwrap(),

            Value::list_from(vec![Value::Int(1), Value::Int(2)]).unwrap(),
            Value::list_from(vec![Value::buff_from(vec![0x00]).unwrap(), Value::buff_from(vec![0x11]).unwrap()]).unwrap(),
            Value::list_from(vec![Value::Principal(PrincipalData::StandardPrincipal(22, [0x8a, 0xca, 0x81, 0xf2, 0x94, 0xaa, 0x50, 0x8d, 0xb3, 0x26, 0x77, 0xc8, 0x09, 0x3d, 0xab, 0x20, 0xf5, 0x27, 0xc2, 0x08])),
                                  Value::Principal(PrincipalData::StandardPrincipal(22, [0x8a, 0xca, 0x81, 0xf2, 0x94, 0xaa, 0x50, 0x8d, 0xb3, 0x26, 0x77, 0xc8, 0x09, 0x3d, 0xab, 0x20, 0xf5, 0x27, 0xc2, 0x08]))]).unwrap(),
            Value::list_from(vec![Value::Principal(PrincipalData::StandardPrincipal(22, [0x8a, 0xca, 0x81, 0xf2, 0x94, 0xaa, 0x50, 0x8d, 0xb3, 0x26, 0x77, 0xc8, 0x09, 0x3d, 0xab, 0x20, 0xf5, 0x27, 0xc2, 0x08])),
                                  Value::Principal(PrincipalData::ContractPrincipal("hello".to_string()))]).unwrap(),
            Value::list_from(vec![Value::tuple_from_data(vec![("word".to_string(), Value::buff_from(vec![0x68, 0x65, 0x6c, 0x6c, 0x6f]).unwrap())]).unwrap(),
                                  Value::tuple_from_data(vec![("word".to_string(), Value::buff_from(vec![0x68, 0x65, 0x6c, 0x6c, 0x6f]).unwrap())]).unwrap()]).unwrap(),
            Value::list_from(vec![Value::Bool(false), Value::Bool(true)]).unwrap(),
            Value::list_from(vec![Value::some(Value::Int(3)), Value::none()]).unwrap(),
            Value::list_from(vec![Value::Response(ResponseData { committed: true, data: Box::new(Value::Bool(true)) }),
                                  Value::Response(ResponseData { committed: true, data: Box::new(Value::Bool(false)) })]).unwrap(),
            Value::list_from(vec![Value::Response(ResponseData { committed: false, data: Box::new(Value::Int(123)) }),
                                  Value::Response(ResponseData { committed: false, data: Box::new(Value::Int(456)) })]).unwrap(),
        ];

        for i in 0..netstrings_valid.len() {
            test_debug!("{} <--> {:?}", &netstrings_valid[i], &values_valid[i]);
            let value = from_typed_netstring(&netstrings_valid[i].to_string()).unwrap();
            let netstr = to_typed_netstring(&values_valid[i]);

            assert_eq!(value, values_valid[i]);
            assert_eq!(netstr, netstrings_valid[i].to_string());
        }
    }
}
