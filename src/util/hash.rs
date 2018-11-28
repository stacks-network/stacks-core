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

use util::pair::*;

// borrowed from Andrew Poelstra's rust-bitcoin library
/// Convert a hexadecimal-encoded string to its corresponding bytes
pub fn hex_bytes(s: &str) -> Result<Vec<u8>, &'static str> {
    let mut v = vec![];
    let mut iter = s.chars().pair();
    // Do the parsing
    iter.by_ref().fold(Ok(()), |e, (f, s)| 
        if e.is_err() { e }
        else {
            match (f.to_digit(16), s.to_digit(16)) {
                (None, _) => Err("unexpected hex digit"),
                (_, None) => Err("unexpected hex digit"),
                (Some(f), Some(s)) => { v.push((f * 0x10 + s) as u8); Ok(()) }
            }
        }
    )?;
    // Check that there was no remainder
    match iter.remainder() {
        Some(_) => Err("hexstring of odd length"),
        None => Ok(v)
    }
}

/// Convert a slice of u8 to a hex string
pub fn to_hex(s: &[u8]) -> String {
    let r : Vec<String> = s.to_vec().iter().map(|b| format!("{:02x}", b)).collect();
    return r.connect("");
}
