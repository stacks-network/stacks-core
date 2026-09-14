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

use std::backtrace::Backtrace;
use std::path::Path;
use std::sync::{LazyLock, Mutex};
use std::thread;
use std::time::Instant;

use hashbrown::HashMap;
use rand::{thread_rng, Rng};
use rusqlite::types::ToSql;
use rusqlite::{
    Connection, Error as SqliteError, OpenFlags, OptionalExtension, Transaction,
    TransactionBehavior,
};

use crate::types::sqlite::NO_PARAMS;
use crate::util::sleep_ms;

// 256MB
pub const SQLITE_MMAP_SIZE: i64 = 256 * 1024 * 1024;

// 32K
pub const SQLITE_MARF_PAGE_SIZE: i64 = 32768;

/// Statement-cache capacity for `sqlite_open` connections. The widest observed
/// working set is ~120 distinct statements (the sortition MARF);
/// rusqlite's default of 16 would LRU-thrash.
pub const SQLITE_STATEMENT_CACHE_CAPACITY: usize = 200;

/// Keep track of DB locks, for deadlock debugging
///  - **key:** `rusqlite::Connection` debug print
///  - **value:** Lock holder (thread name + timestamp)
///
/// This uses a `Mutex` inside of `LazyLock` because:
///  - Using `Mutex` alone, it can't be statically initialized because `HashMap::new()` isn't `const`
///  - Using `LazyLock` alone doesn't allow interior mutability
static LOCK_TABLE: LazyLock<Mutex<HashMap<String, String>>> =
    LazyLock::new(|| Mutex::new(HashMap::new()));
/// Generate timestanps for use in `LOCK_TABLE`
/// `Instant` is preferable to `SystemTime` because it uses `CLOCK_MONOTONIC` and is not affected by NTP adjustments
static LOCK_TABLE_TIMER: LazyLock<Instant> = LazyLock::new(Instant::now);

/// Call when using an operation which locks a database
/// Updates `LOCK_TABLE`
pub fn update_lock_table(conn: &Connection) {
    let timestamp = LOCK_TABLE_TIMER.elapsed().as_millis();
    // The debug format for `Connection` includes the path
    let k = format!("{conn:?}");
    let v = format!("{:?}@{timestamp}", thread::current().name());
    LOCK_TABLE.lock().unwrap().insert(k, v);
}

/// Called by `rusqlite` if we are waiting too long on a database lock
/// If called too many times, will assume a deadlock and panic
pub fn tx_busy_handler(run_count: i32) -> bool {
    const AVG_SLEEP_TIME_MS: u64 = 100;

    // Every ~5min, report an error with a backtrace
    //   5min * 60s/min * 1_000ms/s / 100ms
    const ERROR_COUNT: u32 = 3_000;

    // First, check if this is taking unreasonably long. If so, it's probably a deadlock
    let run_count = run_count.unsigned_abs();
    if run_count > 0 && run_count.is_multiple_of(ERROR_COUNT) {
        error!("Deadlock detected. Waited 5 minutes (estimated) for database lock.";
            "run_count" => run_count,
            "backtrace" => ?Backtrace::capture()
        );
        for (k, v) in LOCK_TABLE.lock().unwrap().iter() {
            error!("Database '{k}' last locked by {v}");
        }
    }

    let mut sleep_time_ms = 2u64.saturating_pow(run_count);
    sleep_time_ms = sleep_time_ms.saturating_add(thread_rng().gen_range(0..sleep_time_ms));

    if sleep_time_ms > AVG_SLEEP_TIME_MS {
        let jitter = 10;
        sleep_time_ms =
            thread_rng().gen_range((AVG_SLEEP_TIME_MS - jitter)..(AVG_SLEEP_TIME_MS + jitter));
    }

    let msg = format!("Database is locked; sleeping {sleep_time_ms}ms and trying again");
    if run_count > 10 && run_count.is_multiple_of(10) {
        warn!("{msg}";
            "run_count" => run_count,
            "backtrace" => ?Backtrace::capture()
        );
    } else {
        debug!("{msg}");
    }

    sleep_ms(sleep_time_ms);
    true
}

/// Run a PRAGMA statement.  This can't always be done via execute(), because it may return a result (and
/// rusqlite does not like this).
pub fn sql_pragma(
    conn: &Connection,
    pragma_name: &str,
    pragma_value: &dyn ToSql,
) -> Result<(), SqliteError> {
    conn.pragma_update(None, pragma_name, pragma_value)
}

/// Run a VACUUM command
pub fn sql_vacuum(conn: &Connection) -> Result<(), SqliteError> {
    conn.execute("VACUUM", NO_PARAMS).map(|_| ())
}

/// Returns true if the database table `table_name` exists in the active
///  database of the provided SQLite connection.
pub fn table_exists(conn: &Connection, table_name: &str) -> Result<bool, SqliteError> {
    let sql = "SELECT name FROM sqlite_master WHERE type='table' AND name=?";
    conn.query_row(sql, &[table_name], |row| row.get::<_, String>(0))
        .optional()
        .map(|r| r.is_some())
}

/// Begin an immediate-mode transaction, and handle busy errors with exponential backoff.
/// Handling busy errors when the tx begins is preferable to doing it when the tx commits, since
/// then we don't have to worry about any extra rollback logic.
pub fn tx_begin_immediate(conn: &mut Connection) -> Result<Transaction<'_>, SqliteError> {
    conn.busy_handler(Some(tx_busy_handler))?;
    let tx = Transaction::new(conn, TransactionBehavior::Immediate)?;
    update_lock_table(&tx);
    Ok(tx)
}

#[cfg(feature = "profile-sqlite")]
fn trace_profile(query: &str, duration: std::time::Duration) {
    use serde_json::json;
    let obj = json!({"millis":duration.as_millis(), "query":query});
    debug!(
        "sqlite trace profile {}",
        serde_json::to_string(&obj).unwrap()
    );
}

#[cfg(feature = "profile-sqlite")]
fn inner_connection_open<P: AsRef<Path>>(
    path: P,
    flags: OpenFlags,
) -> Result<Connection, SqliteError> {
    let mut db = Connection::open_with_flags(path, flags)?;
    db.profile(Some(trace_profile));
    Ok(db)
}

#[cfg(not(feature = "profile-sqlite"))]
fn inner_connection_open<P: AsRef<Path>>(
    path: P,
    flags: OpenFlags,
) -> Result<Connection, SqliteError> {
    Connection::open_with_flags(path, flags)
}

/// Open a database connection and set some typically-used pragmas.
/// Connections are always opened in SQLite multi-thread (`NO_MUTEX`) mode;
/// passing `FULL_MUTEX` panics.
pub fn sqlite_open<P: AsRef<Path>>(
    path: P,
    mut flags: OpenFlags,
    foreign_keys: bool,
) -> Result<Connection, SqliteError> {
    // Without an explicit mutex flag the bundled SQLite defaults to serialized
    // mode, whose per-connection mutex is pure overhead here: `Connection` is
    // `!Sync`, so no thread can ever contend on it.
    assert!(
        !flags.contains(OpenFlags::SQLITE_OPEN_FULL_MUTEX),
        "sqlite_open always opens in multi-thread mode; FULL_MUTEX is not supported"
    );
    flags.insert(OpenFlags::SQLITE_OPEN_NO_MUTEX);
    let db = inner_connection_open(path, flags)?;
    db.busy_handler(Some(tx_busy_handler))?;
    db.set_prepared_statement_cache_capacity(SQLITE_STATEMENT_CACHE_CAPACITY);
    if !flags.contains(OpenFlags::SQLITE_OPEN_READ_ONLY) {
        sql_pragma(&db, "journal_mode", &"WAL")?;
    }
    sql_pragma(&db, "synchronous", &"NORMAL")?;
    if foreign_keys {
        sql_pragma(&db, "foreign_keys", &true)?;
    }
    Ok(db)
}
