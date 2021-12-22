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

#[macro_use]
pub mod log;
#[macro_use]
pub mod macros;
pub mod hash;
pub mod pair;
pub mod pipe;
pub mod retry;
pub mod secp256k1;
pub mod uint;
pub mod vrf;

use std::error;
use std::fmt;
use std::thread;
use std::time;
use std::time::{SystemTime, UNIX_EPOCH};

pub fn get_epoch_time_secs() -> u64 {
    let start = SystemTime::now();
    let since_the_epoch = start
        .duration_since(UNIX_EPOCH)
        .expect("Time went backwards");
    return since_the_epoch.as_secs();
}

pub fn get_epoch_time_ms() -> u128 {
    let start = SystemTime::now();
    let since_the_epoch = start
        .duration_since(UNIX_EPOCH)
        .expect("Time went backwards");
    return since_the_epoch.as_millis();
}

pub fn sleep_ms(millis: u64) -> () {
    let t = time::Duration::from_millis(millis);
    thread::sleep(t);
}

/// Hex deserialization error
#[derive(Copy, Clone, PartialEq, Eq, Debug)]
pub enum HexError {
    /// Length was not 64 characters
    BadLength(usize),
    /// Non-hex character in string
    BadCharacter(char),
}

impl fmt::Display for HexError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match *self {
            HexError::BadLength(n) => write!(f, "bad length {} for sha256d hex string", n),
            HexError::BadCharacter(c) => write!(f, "bad character {} in sha256d hex string", c),
        }
    }
}

impl error::Error for HexError {
    fn cause(&self) -> Option<&dyn error::Error> {
        None
    }
    fn description(&self) -> &str {
        match *self {
            HexError::BadLength(_) => "sha256d hex string non-64 length",
            HexError::BadCharacter(_) => "sha256d bad hex character",
        }
    }
}

/// PartialEq helper method for slices of arbitrary length.
pub fn slice_partialeq<T: PartialEq>(s1: &[T], s2: &[T]) -> bool {
    if s1.len() != s2.len() {
        return false;
    }
    for i in 0..s1.len() {
        if s1[i] != s2[i] {
            return false;
        }
    }
    true
}

pub mod db_common {
    use rand::{thread_rng, Rng};
    use std::thread;
    use std::time;

    pub fn tx_busy_handler(run_count: i32) -> bool {
        let mut sleep_count = 10;
        if run_count > 0 {
            sleep_count = 2u64.saturating_pow(run_count as u32);
        }
        sleep_count = sleep_count.saturating_add(thread_rng().gen::<u64>() % sleep_count);

        if sleep_count > 5000 {
            sleep_count = 5000;
        }

        debug!(
            "Database is locked; sleeping {}ms and trying again",
            &sleep_count
        );

        thread::sleep(time::Duration::from_millis(sleep_count));
        true
    }
}
