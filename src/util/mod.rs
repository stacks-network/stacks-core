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
#[macro_use]
pub mod db;

pub mod bloom;
pub mod boot;
pub mod hash;
pub mod pair;
pub mod pipe;
pub mod retry;
pub mod secp256k1;
pub mod strings;
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

#[cfg(test)]
pub mod test {
    use super::*;
    use std::panic;
    use std::process;
    use std::sync::mpsc::sync_channel;

    pub fn with_timeout<F>(timeout_secs: u64, test_func: F)
    where
        F: FnOnce() -> () + std::marker::Send + 'static + panic::UnwindSafe,
    {
        let (sx, rx) = sync_channel(1);

        let t = thread::spawn(move || {
            let result = panic::catch_unwind(|| {
                test_func();
            });
            let _ = sx.send(result.is_ok());
        });

        // wait for test to finish
        let deadline = timeout_secs + get_epoch_time_secs();
        let mut done = false;
        while get_epoch_time_secs() <= deadline {
            sleep_ms(1000);
            match rx.try_recv() {
                Ok(success) => {
                    assert!(success);
                    done = true;
                    break;
                }
                Err(_) => {}
            }
        }

        if !done {
            panic!("Test timed out after {} seconds", timeout_secs);
        }
        t.join().unwrap();
    }

    #[test]
    fn test_test_timeout() {
        with_timeout(2000000, || {
            eprintln!("timeout test start...");
            sleep_ms(1000);
            eprintln!("timeout test end");
        })
    }

    #[test]
    #[should_panic]
    fn test_test_timeout_timeout() {
        with_timeout(1, || {
            eprintln!("timeout panic test start...");
            sleep_ms(1000 * 1000);
        })
    }

    #[test]
    #[should_panic]
    fn test_test_timeout_panic() {
        with_timeout(1000, || {
            panic!("force a panic");
        })
    }
}
