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

use slog::{Drain, Logger};
use std::env;
use std::sync::Mutex;

lazy_static! {
    pub static ref LOGGER: Logger = make_logger();
}

fn make_logger() -> Logger {
    if env::var("BLOCKSTACK_LOG_JSON") == Ok("1".into()) {
        let drain = Mutex::new(slog_json::Json::default(std::io::stderr())).map(slog::Fuse);
        let filtered_drain = slog::LevelFilter::new(drain, get_loglevel()).fuse();
        slog::Logger::root(filtered_drain, o!())
    } else {
        let decorator = slog_term::TermDecorator::new().build();
        let drain = slog_term::CompactFormat::new(decorator).build().fuse();
        let drain = slog_async::Async::new(drain).build().fuse();
        let filtered_drain = slog::LevelFilter::new(drain, get_loglevel()).fuse();
        slog::Logger::root(filtered_drain, o!())
    }
}

fn get_loglevel() -> slog::Level {
    if env::var("BLOCKSTACK_TRACE") == Ok("1".into()) {
        slog::Level::Trace
    } else if env::var("BLOCKSTACK_DEBUG") == Ok("1".into()) {
        slog::Level::Debug
    } else {
        slog::Level::Info
    }
}

#[macro_export]
macro_rules! trace {
    ($($arg:tt)*) => ({
        slog_trace!($crate::util::log::LOGGER, $($arg)*)
    })
}

#[macro_export]
macro_rules! error {
    ($($arg:tt)*) => ({
        slog_error!($crate::util::log::LOGGER, $($arg)*)
    })
}

#[macro_export]
macro_rules! warn {
    ($($arg:tt)*) => ({
        slog_warn!($crate::util::log::LOGGER, $($arg)*)
    })
}

#[macro_export]
macro_rules! info {
    ($($arg:tt)*) => ({
        slog_info!($crate::util::log::LOGGER, $($arg)*)
    })
}

#[macro_export]
macro_rules! debug {
    ($($arg:tt)*) => ({
        slog_debug!($crate::util::log::LOGGER, $($arg)*)
    })
}

#[macro_export]
macro_rules! fatal {
    ($($arg:tt)*) => ({
        slog_crit!($crate::util::log::LOGGER, $($arg)*)
    })
}
