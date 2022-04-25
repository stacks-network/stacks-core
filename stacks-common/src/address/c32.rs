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

use super::Error;

use sha2::Digest;
use sha2::Sha256;
use std::convert::TryFrom;

const C32_CHARACTERS: &[u8; 32] = b"0123456789ABCDEFGHJKMNPQRSTVWXYZ";

/// C32 chars as an array, indexed by their ASCII code for O(1) lookups.
/// Supports lookups by uppercase and lowercase.
///
/// The table also encodes the special characters `O, L, I`:
///   * `O` and `o` as `0`
///   * `L` and `l` as `1`
///   * `I` and `i` as `1`
///
/// Table can be generated with:
/// ```
/// let mut table: [Option<u8>; 128] = [None; 128];
/// let alphabet = "0123456789ABCDEFGHJKMNPQRSTVWXYZ";
/// for (i, x) in alphabet.as_bytes().iter().enumerate() {
///     table[*x as usize] = Some(i as u8);
/// }
/// let alphabet_lower = alphabet.to_lowercase();
/// for (i, x) in alphabet_lower.as_bytes().iter().enumerate() {
///     table[*x as usize] = Some(i as u8);
/// }
/// let specials = [('O', '0'), ('L', '1'), ('I', '1')];
/// for pair in specials {
///     let i = alphabet.find(|a| a == pair.1).unwrap() as isize;
///     table[pair.0 as usize] = Some(i as u8);
///     table[pair.0.to_ascii_lowercase() as usize] = Some(i as u8);
/// }
/// ```
const C32_CHARACTERS_MAP: [Option<u8>; 128] = [
    None,
    None,
    None,
    None,
    None,
    None,
    None,
    None,
    None,
    None,
    None,
    None,
    None,
    None,
    None,
    None,
    None,
    None,
    None,
    None,
    None,
    None,
    None,
    None,
    None,
    None,
    None,
    None,
    None,
    None,
    None,
    None,
    None,
    None,
    None,
    None,
    None,
    None,
    None,
    None,
    None,
    None,
    None,
    None,
    None,
    None,
    None,
    None,
    Some(0),
    Some(1),
    Some(2),
    Some(3),
    Some(4),
    Some(5),
    Some(6),
    Some(7),
    Some(8),
    Some(9),
    None,
    None,
    None,
    None,
    None,
    None,
    None,
    Some(10),
    Some(11),
    Some(12),
    Some(13),
    Some(14),
    Some(15),
    Some(16),
    Some(17),
    Some(1),
    Some(18),
    Some(19),
    Some(1),
    Some(20),
    Some(21),
    Some(0),
    Some(22),
    Some(23),
    Some(24),
    Some(25),
    Some(26),
    None,
    Some(27),
    Some(28),
    Some(29),
    Some(30),
    Some(31),
    None,
    None,
    None,
    None,
    None,
    None,
    Some(10),
    Some(11),
    Some(12),
    Some(13),
    Some(14),
    Some(15),
    Some(16),
    Some(17),
    Some(1),
    Some(18),
    Some(19),
    Some(1),
    Some(20),
    Some(21),
    Some(0),
    Some(22),
    Some(23),
    Some(24),
    Some(25),
    Some(26),
    None,
    Some(27),
    Some(28),
    Some(29),
    Some(30),
    Some(31),
    None,
    None,
    None,
    None,
    None,
];

fn c32_encode(input_bytes: &[u8]) -> String {
    let mut result = vec![];
    let mut carry = 0;
    let mut carry_bits = 0;

    for current_value in input_bytes.iter().rev() {
        let low_bits_to_take = 5 - carry_bits;
        let low_bits = current_value & ((1 << low_bits_to_take) - 1);
        let c32_value = (low_bits << carry_bits) + carry;
        result.push(C32_CHARACTERS[c32_value as usize]);
        carry_bits = (8 + carry_bits) - 5;
        carry = current_value >> (8 - carry_bits);

        if carry_bits >= 5 {
            let c32_value = carry & ((1 << 5) - 1);
            result.push(C32_CHARACTERS[c32_value as usize]);
            carry_bits = carry_bits - 5;
            carry = carry >> 5;
        }
    }

    if carry_bits > 0 {
        result.push(C32_CHARACTERS[carry as usize]);
    }

    // remove leading zeros from c32 encoding
    while let Some(v) = result.pop() {
        if v != C32_CHARACTERS[0] {
            result.push(v);
            break;
        }
    }

    // add leading zeros from input.
    for current_value in input_bytes.iter() {
        if *current_value == 0 {
            result.push(C32_CHARACTERS[0]);
        } else {
            break;
        }
    }

    let result: Vec<u8> = result.drain(..).rev().collect();
    String::from_utf8(result).unwrap()
}

fn c32_decode(input_str: &str) -> Result<Vec<u8>, Error> {
    // must be ASCII
    if !input_str.is_ascii() {
        return Err(Error::InvalidCrockford32);
    }
    c32_decode_ascii(input_str)
}

fn c32_decode_ascii(input_str: &str) -> Result<Vec<u8>, Error> {
    let mut result = vec![];
    let mut carry: u16 = 0;
    let mut carry_bits = 0; // can be up to 5

    let mut iter_c32_digits = Vec::<u8>::with_capacity(input_str.len());

    for x in input_str.as_bytes().iter().rev() {
        match C32_CHARACTERS_MAP.get(*x as usize) {
            Some(&Some(x)) => iter_c32_digits.push(x),
            _ => {}
        }
    }

    if input_str.len() != iter_c32_digits.len() {
        // at least one char was None
        return Err(Error::InvalidCrockford32);
    }

    for current_5bit in &iter_c32_digits {
        carry += (*current_5bit as u16) << carry_bits;
        carry_bits += 5;

        if carry_bits >= 8 {
            result.push((carry & ((1 << 8) - 1)) as u8);
            carry_bits -= 8;
            carry = carry >> 8;
        }
    }

    if carry_bits > 0 {
        result.push(carry as u8);
    }

    // remove leading zeros from Vec<u8> encoding
    while let Some(v) = result.pop() {
        if v != 0 {
            result.push(v);
            break;
        }
    }

    // add leading zeros from input.
    for current_value in iter_c32_digits.iter().rev() {
        if *current_value == 0 {
            result.push(0);
        } else {
            break;
        }
    }

    result.reverse();
    Ok(result)
}

fn double_sha256_checksum(data: &[u8]) -> Vec<u8> {
    let tmp = Sha256::digest(Sha256::digest(data));
    tmp[0..4].to_vec()
}

fn c32_check_encode(version: u8, data: &[u8]) -> Result<String, Error> {
    if version >= 32 {
        return Err(Error::InvalidVersion(version));
    }

    let mut check_data = vec![version];
    check_data.extend_from_slice(data);
    let checksum = double_sha256_checksum(&check_data);

    let mut encoding_data = data.to_vec();
    encoding_data.extend_from_slice(&checksum);

    // working with ascii strings is awful.
    let mut c32_string = c32_encode(&encoding_data).into_bytes();
    let version_char = C32_CHARACTERS[version as usize];
    c32_string.insert(0, version_char);

    Ok(String::from_utf8(c32_string).unwrap())
}

fn c32_check_decode(check_data_unsanitized: &str) -> Result<(u8, Vec<u8>), Error> {
    // must be ASCII
    if !check_data_unsanitized.is_ascii() {
        return Err(Error::InvalidCrockford32);
    }

    if check_data_unsanitized.len() < 2 {
        return Err(Error::InvalidCrockford32);
    }

    let (version, data) = check_data_unsanitized.split_at(1);

    let data_sum_bytes = c32_decode_ascii(data)?;
    if data_sum_bytes.len() < 5 {
        return Err(Error::InvalidCrockford32);
    }

    let (data_bytes, expected_sum) = data_sum_bytes.split_at(data_sum_bytes.len() - 4);

    let mut check_data = c32_decode_ascii(version)?;
    check_data.extend_from_slice(data_bytes);

    let computed_sum = double_sha256_checksum(&check_data);
    if computed_sum != expected_sum {
        let computed_sum_u32 = (computed_sum[0] as u32)
            | ((computed_sum[1] as u32) << 8)
            | ((computed_sum[2] as u32) << 16)
            | ((computed_sum[3] as u32) << 24);

        let expected_sum_u32 = (expected_sum[0] as u32)
            | ((expected_sum[1] as u32) << 8)
            | ((expected_sum[2] as u32) << 16)
            | ((expected_sum[3] as u32) << 24);

        return Err(Error::BadChecksum(computed_sum_u32, expected_sum_u32));
    }

    let version = check_data[0];
    let data = data_bytes.to_vec();
    Ok((version, data))
}

pub fn c32_address_decode(c32_address_str: &str) -> Result<(u8, Vec<u8>), Error> {
    if c32_address_str.len() <= 5 {
        Err(Error::InvalidCrockford32)
    } else {
        c32_check_decode(&c32_address_str[1..])
    }
}

pub fn c32_address(version: u8, data: &[u8]) -> Result<String, Error> {
    let c32_string = c32_check_encode(version, data)?;
    Ok(format!("S{}", c32_string))
}

#[cfg(test)]
mod test {
    use super::super::c32_old::{
        c32_address as c32_address_old, c32_address_decode as c32_address_decode_old,
    };
    use super::*;
    use crate::util::hash::hex_bytes;
    use rand::Rng;

    #[test]
    fn old_c32_validation() {
        for n in 0..5000 {
            // random version
            let random_version: u8 = rand::thread_rng().gen_range(0, 31);

            // random 20 bytes
            let random_bytes = rand::thread_rng().gen::<[u8; 20]>();

            let addr_new = c32_address(random_version, &random_bytes).unwrap();
            let addr_old = c32_address_old(random_version, &random_bytes).unwrap();

            assert_eq!(&addr_new, &addr_old);

            let decoded_addrs = vec![
                c32_address_decode(&addr_new).unwrap(),
                c32_address_decode(&addr_old).unwrap(),
                c32_address_decode_old(&addr_new).unwrap(),
                c32_address_decode_old(&addr_new).unwrap(),
            ];

            for decoded_addr in decoded_addrs {
                assert_eq!(decoded_addr.0, random_version);
                assert_eq!(decoded_addr.1, random_bytes);
            }
        }
    }

    #[test]
    fn test_addresses() {
        let hex_strs = [
            "a46ff88886c2ef9762d970b4d2c63678835bd39d",
            "0000000000000000000000000000000000000000",
            "0000000000000000000000000000000000000001",
            "1000000000000000000000000000000000000001",
            "1000000000000000000000000000000000000000",
        ];

        let versions = [22, 0, 31, 20, 26, 21];

        let c32_addrs = [
            [
                "SP2J6ZY48GV1EZ5V2V5RB9MP66SW86PYKKNRV9EJ7",
                "SP000000000000000000002Q6VF78",
                "SP00000000000000000005JA84HQ",
                "SP80000000000000000000000000000004R0CMNV",
                "SP800000000000000000000000000000033H8YKK",
            ],
            [
                "S02J6ZY48GV1EZ5V2V5RB9MP66SW86PYKKPVKG2CE",
                "S0000000000000000000002AA028H",
                "S000000000000000000006EKBDDS",
                "S080000000000000000000000000000007R1QC00",
                "S080000000000000000000000000000003ENTGCQ",
            ],
            [
                "SZ2J6ZY48GV1EZ5V2V5RB9MP66SW86PYKKQ9H6DPR",
                "SZ000000000000000000002ZE1VMN",
                "SZ00000000000000000005HZ3DVN",
                "SZ80000000000000000000000000000004XBV6MS",
                "SZ800000000000000000000000000000007VF5G0",
            ],
            [
                "SM2J6ZY48GV1EZ5V2V5RB9MP66SW86PYKKQVX8X0G",
                "SM0000000000000000000062QV6X",
                "SM00000000000000000005VR75B2",
                "SM80000000000000000000000000000004WBEWKC",
                "SM80000000000000000000000000000000JGSYGV",
            ],
            [
                "ST2J6ZY48GV1EZ5V2V5RB9MP66SW86PYKKQYAC0RQ",
                "ST000000000000000000002AMW42H",
                "ST000000000000000000042DB08Y",
                "ST80000000000000000000000000000006BYJ4R4",
                "ST80000000000000000000000000000002YBNPV3",
            ],
            [
                "SN2J6ZY48GV1EZ5V2V5RB9MP66SW86PYKKP6D2ZK9",
                "SN000000000000000000003YDHWKJ",
                "SN00000000000000000005341MC8",
                "SN800000000000000000000000000000066KZWY0",
                "SN800000000000000000000000000000006H75AK",
            ],
        ];

        for i in 0..hex_strs.len() {
            for j in 0..versions.len() {
                let h = hex_strs[i];
                let v = versions[j];
                let b = hex_bytes(h).unwrap();
                let z = c32_address(v, &b).unwrap();

                assert_eq!(z, c32_addrs[j][i]);

                let (decoded_version, decoded_bytes) = c32_address_decode(&z).unwrap();
                assert_eq!(decoded_version, v);
                assert_eq!(decoded_bytes, b);
            }
        }
    }

    #[test]
    fn test_simple() {
        let hex_strings = &[
            "a46ff88886c2ef9762d970b4d2c63678835bd39d",
            "",
            "0000000000000000000000000000000000000000",
            "0000000000000000000000000000000000000001",
            "1000000000000000000000000000000000000001",
            "1000000000000000000000000000000000000000",
            "01",
            "22",
            "0001",
            "000001",
            "00000001",
            "10",
            "0100",
            "1000",
            "010000",
            "100000",
            "01000000",
            "10000000",
            "0100000000",
        ];
        let c32_strs = [
            "MHQZH246RBQSERPSE2TD5HHPF21NQMWX",
            "",
            "00000000000000000000",
            "00000000000000000001",
            "20000000000000000000000000000001",
            "20000000000000000000000000000000",
            "1",
            "12",
            "01",
            "001",
            "0001",
            "G",
            "80",
            "400",
            "2000",
            "10000",
            "G0000",
            "800000",
            "4000000",
        ];

        let results: Vec<_> = hex_strings
            .iter()
            .zip(c32_strs.iter())
            .map(|(hex_str, expected)| {
                let bytes = hex_bytes(hex_str).unwrap();
                let c32_encoded = c32_encode(&bytes);
                let decoded_bytes = c32_decode(&c32_encoded).unwrap();
                let result = (bytes, c32_encoded, decoded_bytes, expected);
                println!("{:?}", result);
                result
            })
            .collect();
        for (bytes, c32_encoded, decoded_bytes, expected_c32) in results.iter() {
            assert_eq!(bytes, decoded_bytes);
            assert_eq!(c32_encoded, *expected_c32);
        }
    }

    #[test]
    fn test_normalize() {
        let addrs = [
            "S02J6ZY48GV1EZ5V2V5RB9MP66SW86PYKKPVKG2CE",
            "SO2J6ZY48GV1EZ5V2V5RB9MP66SW86PYKKPVKG2CE",
            "S02J6ZY48GVLEZ5V2V5RB9MP66SW86PYKKPVKG2CE",
            "SO2J6ZY48GVLEZ5V2V5RB9MP66SW86PYKKPVKG2CE",
            "s02j6zy48gv1ez5v2v5rb9mp66sw86pykkpvkg2ce",
            "sO2j6zy48gv1ez5v2v5rb9mp66sw86pykkpvkg2ce",
            "s02j6zy48gvlez5v2v5rb9mp66sw86pykkpvkg2ce",
            "sO2j6zy48gvlez5v2v5rb9mp66sw86pykkpvkg2ce",
        ];

        let expected_bytes = hex_bytes("a46ff88886c2ef9762d970b4d2c63678835bd39d").unwrap();
        let expected_version = 0;

        for addr in addrs.iter() {
            let (decoded_version, decoded_bytes) = c32_address_decode(addr).unwrap();
            assert_eq!(decoded_version, expected_version);
            assert_eq!(decoded_bytes, expected_bytes);
        }
    }

    #[test]
    fn test_ascii_only() {
        match c32_address_decode("S\u{1D7D8}2J6ZY48GV1EZ5V2V5RB9MP66SW86PYKKPVKG2CE") {
            Err(Error::InvalidCrockford32) => {}
            _ => {
                assert!(false);
            }
        }
    }
}
