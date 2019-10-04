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

use std::cell::RefCell;

pub const LOG_DEBUG : u8 = 1;
pub const LOG_INFO : u8 = 2;
pub const LOG_WARN : u8 = 3;
pub const LOG_ERROR : u8 = 4;

// per-thread log level and log format
thread_local!(static loglevel: RefCell<u8> = RefCell::new(LOG_DEBUG));

pub fn set_loglevel(ll: u8) -> Result<(), String> {
    loglevel.with(move |level| {
        match ll {
            LOG_DEBUG..=LOG_ERROR => {
                *level.borrow_mut() = ll;
                Ok(())
            },
            _ => {
                Err("Invalid log level".to_string())
            }
        }
    })
}

pub fn get_loglevel() -> u8 {
    let mut res = 0;
    loglevel.with(|lvl| {
        res = *lvl.borrow();
    });
    res
}

macro_rules! debug {
    ($($arg:tt)*) => ({
        if log::get_loglevel() <= log::LOG_DEBUG {
            use std::time::SystemTime;
            let (ts_sec, ts_msec) = match SystemTime::now().duration_since(SystemTime::UNIX_EPOCH) {
                Ok(n) => (n.as_secs(), n.subsec_nanos() / 1_000_000),
                Err(_) => (0, 0)
            };
            eprintln!("DEBUG [{}.{:03}] [{}:{}] {}", ts_sec, ts_msec, file!(), line!(), format!($($arg)*));
        }
    })
}

macro_rules! info {
    ($($arg:tt)*) => ({
        if log::get_loglevel() <= log::LOG_INFO {
            use std::time::SystemTime;
            let (ts_sec, ts_msec) = match SystemTime::now().duration_since(SystemTime::UNIX_EPOCH) {
                Ok(n) => (n.as_secs(), n.subsec_nanos() / 1_000_000),
                Err(_) => (0, 0)
            };
            eprintln!("INFO [{}.{:03}] [{}:{}] {}", ts_sec, ts_msec, file!(), line!(), format!($($arg)*));
        }
    })
}

macro_rules! warn {
    ($($arg:tt)*) => ({
        if log::get_loglevel() <= log::LOG_WARN {
            use std::time::SystemTime;
            let (ts_sec, ts_msec) = match SystemTime::now().duration_since(SystemTime::UNIX_EPOCH) {
                Ok(n) => (n.as_secs(), n.subsec_nanos() / 1_000_000),
                Err(_) => (0, 0)
            };
            eprintln!("WARN [{}.{:03}] [{}:{}] {}", ts_sec, ts_msec, file!(), line!(), format!($($arg)*));
        }
    })
}

macro_rules! error {
    ($($arg:tt)*) => ({
        if log::get_loglevel() <= log::LOG_ERROR {
            use std::time::SystemTime;
            let (ts_sec, ts_msec) = match SystemTime::now().duration_since(SystemTime::UNIX_EPOCH) {
                Ok(n) => (n.as_secs(), n.subsec_nanos() / 1_000_000),
                Err(_) => (0, 0)
            };
            eprintln!("ERROR [{}.{:03}] [{}:{}] {}", ts_sec, ts_msec, file!(), line!(), format!($($arg)*));
        }
    })
}

