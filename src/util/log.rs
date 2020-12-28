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

use slog::{BorrowedKV, Drain, FnValue, Logger, OwnedKVList, Record, KV};
use slog_term::{CountingWriter, Decorator, RecordDecorator, Serializer};
use std::env;
use std::io;
use std::io::Write;
use std::sync::Mutex;
use std::thread;
use std::time::{Duration, SystemTime};

lazy_static! {
    pub static ref LOGGER: Logger = make_logger();
}

struct TermFormat<D: Decorator> {
    decorator: D,
}

fn print_msg_header(mut rd: &mut dyn RecordDecorator, record: &Record) -> io::Result<bool> {
    rd.start_level()?;
    write!(rd, "{}", record.level().as_short_str())?;
    rd.start_whitespace()?;
    write!(rd, " ")?;

    rd.start_timestamp()?;
    let elapsed = SystemTime::now()
        .duration_since(SystemTime::UNIX_EPOCH)
        .unwrap_or(Duration::from_secs(0));
    write!(
        rd,
        "[{:5}.{:06}]",
        elapsed.as_secs(),
        elapsed.subsec_nanos() / 1000
    )?;
    write!(rd, " ")?;
    write!(rd, "[{}:{}]", record.file(), record.line())?;
    write!(rd, " ")?;
    write!(rd, "[{:?}]", thread::current().id())?;

    rd.start_whitespace()?;
    write!(rd, " ")?;

    rd.start_msg()?;
    let mut count_rd = CountingWriter::new(&mut rd);
    write!(count_rd, "{}", record.msg())?;
    Ok(count_rd.count() != 0)
}

impl<D: Decorator> Drain for TermFormat<D> {
    type Ok = ();
    type Err = io::Error;

    fn log(&self, record: &Record, values: &OwnedKVList) -> Result<Self::Ok, Self::Err> {
        self.format_full(record, values)
    }
}

impl<D: Decorator> TermFormat<D> {
    pub fn new(decorator: D) -> TermFormat<D> {
        TermFormat { decorator }
    }

    fn format_full(&self, record: &Record, values: &OwnedKVList) -> io::Result<()> {
        self.decorator.with_record(record, values, |decorator| {
            let comma_needed = print_msg_header(decorator, record)?;
            {
                let mut serializer = Serializer::new(decorator, comma_needed, true);

                record.kv().serialize(record, &mut serializer)?;

                values.serialize(record, &mut serializer)?;

                serializer.finish()?;
            }

            decorator.start_whitespace()?;
            writeln!(decorator)?;

            decorator.flush()?;

            Ok(())
        })
    }
}

#[cfg(feature = "slog_json")]
fn make_json_logger() -> Logger {
    let def_keys = o!("file" => FnValue(move |info| {
                          info.file()
                      }),
                      "line" => FnValue(move |info| {
                          info.line()
                      }),
                      "thread" => FnValue(move |_| {
                          format!("{:?}", thread::current().id())
                      }),
    );

    let drain = Mutex::new(slog_json::Json::default(std::io::stderr())).map(slog::Fuse);
    let filtered_drain = slog::LevelFilter::new(drain, get_loglevel()).fuse();
    slog::Logger::root(filtered_drain, def_keys)
}

#[cfg(not(feature = "slog_json"))]
fn make_json_logger() -> Logger {
    panic!("Tried to construct JSON logger, but stacks-blockchain built without slog_json feature enabled.")
}

#[cfg(not(test))]
fn make_logger() -> Logger {
    if env::var("BLOCKSTACK_LOG_JSON") == Ok("1".into()) {
        make_json_logger()
    } else {
        let plain = slog_term::PlainSyncDecorator::new(std::io::stderr());
        let drain = TermFormat::new(plain);

        let logger = Logger::root(drain.fuse(), o!());
        logger
    }
}

#[cfg(test)]
fn make_logger() -> Logger {
    if env::var("BLOCKSTACK_LOG_JSON") == Ok("1".into()) {
        make_json_logger()
    } else {
        let plain = slog_term::PlainSyncDecorator::new(slog_term::TestStdoutWriter);
        let drain = TermFormat::new(plain);

        let logger = Logger::root(drain.fuse(), o!());
        logger
    }
}

pub fn get_loglevel() -> slog::Level {
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
        let cur_level = ::util::log::get_loglevel();
        if slog::Level::Trace.is_at_least(cur_level) {
            slog_trace!($crate::util::log::LOGGER, $($arg)*)
        }
    })
}

#[macro_export]
macro_rules! error {
    ($($arg:tt)*) => ({
        let cur_level = ::util::log::get_loglevel();
        if slog::Level::Error.is_at_least(cur_level) {
            slog_error!($crate::util::log::LOGGER, $($arg)*)
        }
    })
}

#[macro_export]
macro_rules! warn {
    ($($arg:tt)*) => ({
        let cur_level = ::util::log::get_loglevel();
        if slog::Level::Warning.is_at_least(cur_level) {
            slog_warn!($crate::util::log::LOGGER, $($arg)*)
        }
    })
}

#[macro_export]
macro_rules! info {
    ($($arg:tt)*) => ({
        let cur_level = ::util::log::get_loglevel();
        if slog::Level::Info.is_at_least(cur_level) {
            slog_info!($crate::util::log::LOGGER, $($arg)*)
        }
    })
}

#[macro_export]
macro_rules! debug {
    ($($arg:tt)*) => ({
        let cur_level = ::util::log::get_loglevel();
        if slog::Level::Debug.is_at_least(cur_level) {
            slog_debug!($crate::util::log::LOGGER, $($arg)*)
        }
    })
}

#[macro_export]
macro_rules! fatal {
    ($($arg:tt)*) => ({
        let cur_level = ::util::log::get_loglevel();
        if slog::Level::Critical.is_at_least(cur_level) {
            slog_crit!($crate::util::log::LOGGER, $($arg)*)
        }
    })
}
