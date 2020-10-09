// Copyright (C) 2013-2020 Blocstack PBC, a public benefit corporation
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

use std::cell::RefCell;
use std::env;

// Message Priorities/Levels
// Apache Conventions defined here: https://commons.apache.org/proper/commons-logging/guide.html#Message_PrioritiesLevels
//
// Severe errors that cause premature termination.
// Expect these to be immediately visible on a status console.
pub const LOG_FATAL: u8 = 6;
// Other runtime errors or unexpected conditions.
// Expect these to be immediately visible on a status console.
pub const LOG_ERROR: u8 = 5;
// Use of deprecated APIs, poor use of API, 'almost' errors, other runtime situations that are undesirable or unexpected, but not necessarily "wrong".
// Expect these to be immediately visible on a status console.
pub const LOG_WARN: u8 = 4;
// Interesting runtime events (startup/shutdown).
// Expect these to be immediately visible on a console, so be conservative and keep to a minimum
pub const LOG_INFO: u8 = 3;
// Detailed information on the flow through the system.
// Expect these to be written to logs only.
pub const LOG_DEBUG: u8 = 2;
// More detailed information.
// Expect these to be written to logs only.
pub const LOG_TRACE: u8 = 1;

// per-thread log level and log format
thread_local!(static loglevel: RefCell<u8> = RefCell::new(LOG_INFO));

pub fn set_loglevel(ll: u8) -> Result<(), String> {
    loglevel.with(move |level| match ll {
        LOG_TRACE..=LOG_FATAL => {
            *level.borrow_mut() = ll;
            Ok(())
        }
        _ => Err("Invalid log level".to_string()),
    })
}

pub fn get_loglevel() -> u8 {
    let mut res = 0;
    loglevel.with(|lvl| {
        res = *lvl.borrow();
    });

    if env::var("BLOCKSTACK_DEBUG") == Ok("1".into()) && res > LOG_DEBUG {
        set_loglevel(LOG_DEBUG).unwrap();
        LOG_DEBUG
    } else if env::var("BLOCKSTACK_TRACE") == Ok("1".into()) && res > LOG_TRACE {
        set_loglevel(LOG_TRACE).unwrap();
        LOG_TRACE
    } else {
        res
    }
}

#[macro_export]
macro_rules! trace {
    ($($arg:tt)*) => ({
        if ::util::log::get_loglevel() <= ::util::log::LOG_TRACE {
            use std::time::SystemTime;
            use std::thread;
            let (ts_sec, ts_msec) = match SystemTime::now().duration_since(SystemTime::UNIX_EPOCH) {
                Ok(n) => (n.as_secs(), n.subsec_nanos() / 1_000_000),
                Err(_) => (0, 0)
            };
            eprintln!("TRACE [{}.{:03}] [{}:{}] [{:?}] {}", ts_sec, ts_msec, file!(), line!(), thread::current().id(), format!($($arg)*));
        }
    })
}

#[macro_export]
macro_rules! debug {
    ($($arg:tt)*) => ({
        if ::util::log::get_loglevel() <= ::util::log::LOG_DEBUG {
            use std::time::SystemTime;
            use std::thread;
            let (ts_sec, ts_msec) = match SystemTime::now().duration_since(SystemTime::UNIX_EPOCH) {
                Ok(n) => (n.as_secs(), n.subsec_nanos() / 1_000_000),
                Err(_) => (0, 0)
            };
            eprintln!("DEBUG [{}.{:03}] [{}:{}] [{:?}] {}", ts_sec, ts_msec, file!(), line!(), thread::current().id(), format!($($arg)*));
        }
    })
}

#[macro_export]
macro_rules! info {
    ($($arg:tt)*) => ({
        if ::util::log::get_loglevel() <= ::util::log::LOG_INFO {
            use std::time::SystemTime;
            use std::thread;
            let (ts_sec, ts_msec) = match SystemTime::now().duration_since(SystemTime::UNIX_EPOCH) {
                Ok(n) => (n.as_secs(), n.subsec_nanos() / 1_000_000),
                Err(_) => (0, 0)
            };
            eprintln!("INFO [{}.{:03}] [{}:{}] [{:?}] {}", ts_sec, ts_msec, file!(), line!(), thread::current().id(), format!($($arg)*));
        }
    })
}

#[macro_export]
macro_rules! warn {
    ($($arg:tt)*) => ({
        if ::util::log::get_loglevel() <= ::util::log::LOG_WARN {
            use std::time::SystemTime;
            use std::thread;
            use crate::monitoring::increment_warning_emitted_counter;
            let (ts_sec, ts_msec) = match SystemTime::now().duration_since(SystemTime::UNIX_EPOCH) {
                Ok(n) => (n.as_secs(), n.subsec_nanos() / 1_000_000),
                Err(_) => (0, 0)
            };
            eprintln!("WARN [{}.{:03}] [{}:{}] [{:?}] {}", ts_sec, ts_msec, file!(), line!(), thread::current().id(), format!($($arg)*));

            increment_warning_emitted_counter();
        }
    })
}

#[macro_export]
macro_rules! error {
    ($($arg:tt)*) => ({
        if ::util::log::get_loglevel() <= ::util::log::LOG_ERROR {
            use std::time::SystemTime;
            use std::thread;
            use crate::monitoring::increment_errors_emitted_counter;
            let (ts_sec, ts_msec) = match SystemTime::now().duration_since(SystemTime::UNIX_EPOCH) {
                Ok(n) => (n.as_secs(), n.subsec_nanos() / 1_000_000),
                Err(_) => (0, 0)
            };
            eprintln!("ERROR [{}.{:03}] [{}:{}] [{:?}] {}", ts_sec, ts_msec, file!(), line!(), thread::current().id(), format!($($arg)*));

            increment_errors_emitted_counter();
        }
    })
}

#[macro_export]
macro_rules! fatal {
    ($($arg:tt)*) => ({
        if ::util::log::get_loglevel() <= ::util::log::LOG_FATAL {
            use std::time::SystemTime;
            use std::thread;
            let (ts_sec, ts_msec) = match SystemTime::now().duration_since(SystemTime::UNIX_EPOCH) {
                Ok(n) => (n.as_secs(), n.subsec_nanos() / 1_000_000),
                Err(_) => (0, 0)
            };
            eprintln!("FATAL [{}.{:03}] [{}:{}] [{:?}] {}", ts_sec, ts_msec, file!(), line!(), thread::current().id(), format!($($arg)*));
        }
    })
}
