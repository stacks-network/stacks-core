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

#![allow(unused_imports)]
#![allow(unused_assignments)]
#![allow(dead_code)]
#![allow(non_camel_case_types)]
#![allow(non_snake_case)]
#![allow(non_upper_case_globals)]

extern crate rand;
extern crate ini;
extern crate secp256k1;
extern crate serde;
extern crate rusqlite;
extern crate curve25519_dalek;
extern crate ed25519_dalek;
extern crate httparse;
#[macro_use] extern crate lazy_static;
extern crate sha2;
extern crate sha3;
extern crate ripemd160;
extern crate regex;
extern crate time;
extern crate byteorder;
extern crate mio;

#[macro_use] extern crate serde_derive;
#[macro_use] extern crate serde_json;

#[cfg(test)]
#[macro_use]
extern crate assert_json_diff;

#[macro_use]
pub mod util;

#[macro_use]
pub mod net;

#[macro_use]
pub mod chainstate;

pub mod address;
pub mod burnchains;
pub mod core;
pub mod deps;
pub mod vm;

pub mod clarity;
