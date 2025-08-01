// Copyright (C) 2025 Stacks Open Internet Foundation
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

use std::time::Duration;
use std::{panic, thread};

use proptest::prelude::*;

use crate::burnchains::bitcoin::Error as bitcoin_error;
use crate::burnchains::{Burnchain, Error as burnchain_error};

// Run more cases than default with PROPTEST_CASES.
// Example:
//     PROPTEST_CASES=500 cargo test -p stackslib -- \
//     burnchains::tests::thread_join

#[test]
fn join_success() {
    proptest!(|(v in any::<u32>(), s in "[ -~]{1,20}")| {
        let h = thread::spawn(move || Ok(v));
        let r = Burnchain::handle_thread_join::<u32>(h, &s);
        prop_assert!(r.is_ok());
        prop_assert_eq!(r.unwrap(), v);
    });
}

#[test]
fn join_with_name() {
    proptest!(|(v in any::<u32>(), s in "[ -~]{1,20}")| {
        let h = thread::spawn(move || Ok(v));
        let r = Burnchain::handle_thread_join::<u32>(h, &s);
        prop_assert!(r.is_ok());
        prop_assert_eq!(r.unwrap(), v);
    });
}

#[test]
fn join_delay() {
    proptest!(|(d in 10u64..100, v in any::<u32>(), s in "[ -~]{1,20}")| {
        let h = thread::spawn(move || {
            thread::sleep(Duration::from_millis(d));
            Ok(v)
        });
        let r = Burnchain::handle_thread_join::<u32>(h, &s);
        prop_assert!(r.is_ok());
        prop_assert_eq!(r.unwrap(), v);
    });
}

#[test]
fn join_download_error() {
    let h = thread::spawn(move || {
        Err(burnchain_error::DownloadError(
            bitcoin_error::ConnectionError,
        ))
    });
    let r = Burnchain::handle_thread_join::<u32>(h, "test");
    assert!(r.is_err());
    match r {
        Err(burnchain_error::DownloadError(_)) => {}
        _ => panic!("Expected DownloadError"),
    }
}

#[test]
fn join_parse_error() {
    let h = thread::spawn(move || Err(burnchain_error::ParseError));
    let r = Burnchain::handle_thread_join::<u32>(h, "test");
    assert!(r.is_err());
    match r {
        Err(burnchain_error::ParseError) => {}
        _ => panic!("Expected ParseError"),
    }
}

#[test]
fn join_panics() {
    let h = thread::spawn(|| {
        panic!("boom");
        #[allow(unreachable_code)]
        Ok(42)
    });
    let r = Burnchain::handle_thread_join::<u32>(h, "test");
    assert!(r.is_err());
    match r {
        Err(burnchain_error::ThreadChannelError) => {}
        _ => panic!("Expected ThreadChannelError"),
    }
}
