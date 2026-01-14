// Copyright (C) 2013-2020 Blockstack PBC, a public benefit corporation
// Copyright (C) 2020-2026 Stacks Open Internet Foundation
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

use std::fmt::Debug;
use std::path::PathBuf;
use std::sync::Arc;
use std::thread::sleep;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use rusqlite::{params, Connection, Row};
use stacks::util_lib::db::{table_exists, Error as db_error};

use crate::event_dispatcher::EventRequestData;

pub struct PendingPayload {
    pub request_data: EventRequestData,
    #[allow(dead_code)] // will be used in a follow-up commit
    pub timestamp: SystemTime,
    pub id: i64,
}

/// Wraps a SQlite connection to the database in which pending event payloads are stored
#[derive(Debug)]
pub struct EventDispatcherDbConnection {
    connection: Connection,
}

impl EventDispatcherDbConnection {
    pub fn new_without_init(db_path: &PathBuf) -> Result<EventDispatcherDbConnection, db_error> {
        let connection = Connection::open(db_path.to_str().unwrap())?;
        Ok(EventDispatcherDbConnection { connection })
    }

    pub fn new(db_path: &PathBuf) -> Result<EventDispatcherDbConnection, db_error> {
        let connection = Connection::open(db_path.to_str().unwrap())?;
        connection.execute(
            "CREATE TABLE IF NOT EXISTS pending_payloads (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                url TEXT NOT NULL,
                payload BLOB NOT NULL,
                timeout INTEGER NOT NULL,
                timestamp INTEGER NOT NULL
            )",
            [],
        )?;
        let mut connection = EventDispatcherDbConnection { connection };

        connection.run_necessary_migrations()?;

        Ok(connection)
    }

    #[cfg(test)]
    pub fn new_from_exisiting_connection(connection: Connection) -> EventDispatcherDbConnection {
        EventDispatcherDbConnection { connection }
    }

    /// Insert a payload into the database, retrying on failure. Returns the id of of the inserted record.
    pub fn insert_payload_with_retry(&self, data: &EventRequestData, timestamp: SystemTime) -> i64 {
        with_retry(
            || self.insert_payload(data, timestamp),
            "Failed to insert payload into event observer database".to_string(),
        )
    }

    pub fn get_payload_with_retry(&self, id: i64) -> PendingPayload {
        with_retry(
            || self.get_payload(id),
            "Failed to retrieve payload {id} from event observer database".to_string(),
        )
    }

    pub fn insert_payload(
        &self,
        data: &EventRequestData,
        timestamp: SystemTime,
    ) -> Result<i64, db_error> {
        let timeout_ms: u64 = data
            .timeout
            .as_millis()
            .try_into()
            .expect("Timeout too large");

        let timestamp_s = timestamp
            .duration_since(UNIX_EPOCH)
            .expect("system clock is multiple decades slow")
            .as_secs();

        let id: i64 = self.connection.query_row(
            "INSERT INTO pending_payloads (url, payload, timeout, timestamp) VALUES (?1, ?2, ?3, ?4) RETURNING id",
            params![data.url, data.payload_bytes, timeout_ms, timestamp_s],
            |row| row.get(0),
        )?;
        Ok(id)
    }

    pub fn get_payload(&self, id: i64) -> Result<PendingPayload, db_error> {
        self.connection.query_row_and_then(
            &format!("SELECT {PAYLOAD_FIELDS} FROM pending_payloads WHERE id = ?1"),
            [id],
            row_to_pending_payload,
        )
    }

    pub fn get_pending_payloads(&self) -> Result<Vec<PendingPayload>, db_error> {
        let mut stmt = self.connection.prepare(&format!(
            "SELECT {PAYLOAD_FIELDS} FROM pending_payloads ORDER BY id"
        ))?;
        let payload_iter = stmt.query_and_then([], row_to_pending_payload)?;
        payload_iter.collect()
    }

    pub fn delete_payload(&self, id: i64) -> Result<(), db_error> {
        self.connection
            .execute("DELETE FROM pending_payloads WHERE id = ?1", params![id])?;
        Ok(())
    }

    /// The initial schema of the database when this code was first created
    const INITIAL_SCHEMA: u32 = 0;
    /// The `payload`` column type changed from TEXT to BLOB
    const PAYLOAD_IS_BLOB: u32 = 1;
    /// Column `timestamp` and table `db_config` added
    const VERSIONING_AND_TIMESTAMP_COLUMN: u32 = 2;

    fn run_necessary_migrations(&mut self) -> Result<(), db_error> {
        let current_schema = self.get_schema_version()?;

        if current_schema < Self::PAYLOAD_IS_BLOB {
            info!("Event observer: migrating pending_payloads.payload from TEXT to BLOB");
            self.migrate_payload_column_to_blob()?;
        }

        if current_schema < Self::VERSIONING_AND_TIMESTAMP_COLUMN {
            info!("Event observer: adding timestamp to pending_payloads");
            self.add_versioning_and_timestamp_column()?;
        }

        Ok(())
    }

    fn get_schema_version(&self) -> Result<u32, db_error> {
        let has_db_config = table_exists(&self.connection, "db_config")?;

        if has_db_config {
            let version =
                self.connection
                    .query_row("SELECT MAX(version) FROM db_config", [], |r| {
                        r.get::<_, u32>(0)
                    })?;
            return Ok(version);
        }

        let payload_type = self.connection.query_row(
            "SELECT type FROM pragma_table_info('pending_payloads') WHERE name='payload'",
            [],
            |r| r.get::<_, String>(0),
        )?;

        let payload_is_blob = payload_type.eq_ignore_ascii_case("BLOB");

        if payload_is_blob {
            Ok(Self::PAYLOAD_IS_BLOB)
        } else {
            Ok(Self::INITIAL_SCHEMA)
        }
    }

    fn migrate_payload_column_to_blob(&mut self) -> Result<(), db_error> {
        let tx = self.connection.transaction()?;
        tx.execute(
            "ALTER TABLE pending_payloads RENAME TO pending_payloads_old",
            [],
        )?;
        tx.execute(
            "CREATE TABLE pending_payloads (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                url TEXT NOT NULL,
                payload BLOB NOT NULL,
                timeout INTEGER NOT NULL
            )",
            [],
        )?;
        tx.execute(
            "INSERT INTO pending_payloads (id, url, payload, timeout)
                SELECT id, url, CAST(payload AS BLOB), timeout FROM pending_payloads_old",
            [],
        )?;
        tx.execute("DROP TABLE pending_payloads_old", [])?;
        tx.commit()?;
        Ok(())
    }

    fn add_versioning_and_timestamp_column(&mut self) -> Result<(), db_error> {
        let tx = self.connection.transaction()?;
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("time travel to pre-1970 is not supported")
            .as_secs();

        tx.execute(
            "ALTER TABLE pending_payloads RENAME TO pending_payloads_old",
            [],
        )?;
        tx.execute(
            "CREATE TABLE pending_payloads (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                url TEXT NOT NULL,
                payload BLOB NOT NULL,
                timeout INTEGER NOT NULL,
                timestamp INTEGER NOT NULL
            )",
            [],
        )?;
        tx.execute(
            "INSERT INTO pending_payloads (id, url, payload, timeout, timestamp)
                SELECT id, url, CAST(payload AS BLOB), timeout, ?1 FROM pending_payloads_old",
            [now],
        )?;
        tx.execute("DROP TABLE pending_payloads_old", [])?;

        tx.execute("CREATE TABLE db_config (version INTEGER)", [])?;
        tx.execute(
            "INSERT INTO db_config (version) VALUES (?1)",
            params![Self::VERSIONING_AND_TIMESTAMP_COLUMN],
        )?;

        tx.commit()?;
        Ok(())
    }
}

// If you change this, make sure to change `row_to_pending_payload` in sync.
const PAYLOAD_FIELDS: &str = "id, url, payload, timeout, timestamp";

/// This function should only be used with rows that were SELECTed using the
/// `PAYLOAD_FIELDS` constant.
fn row_to_pending_payload(row: &Row) -> Result<PendingPayload, db_error> {
    let id: i64 = row.get(0)?;
    let url: String = row.get(1)?;
    let payload_bytes: Vec<u8> = row.get(2)?;
    let payload_bytes = Arc::<[u8]>::from(payload_bytes);
    let timeout_ms: u64 = row.get(3)?;
    let timestamp_s: u64 = row.get(4)?;
    let request_data = EventRequestData {
        url,
        payload_bytes,
        timeout: Duration::from_millis(timeout_ms),
    };

    Ok(PendingPayload {
        id,
        request_data,
        timestamp: UNIX_EPOCH + Duration::from_secs(timestamp_s),
    })
}

/// Calls the given function, repeatedly if necessary, until it doesn't fail, and then
/// returns the result from the successful call. Initially backs off for 0.1s and increases
/// backoff exponentially up to a max of five seconds. If the function never returns a
/// success result, `with_retry` will block forever.
///
/// # Example
///
///     let response = with_retry(|| perform_db_op(42), "database operation 42 failed");
fn with_retry<T, E, F>(f: F, error_log_text: String) -> T
where
    F: Fn() -> Result<T, E>,
    E: Debug,
{
    let mut attempts = 0i64;
    let mut backoff = Duration::from_millis(100); // Initial backoff duration
    let max_backoff = Duration::from_secs(5); // Cap the backoff duration

    loop {
        match f() {
            Ok(thing) => {
                // Successful operation, break the loop
                return thing;
            }
            Err(err) => {
                // Log the error, then retry after a delay
                warn!("{error_log_text}: {err:?}";
                    "backoff" => ?backoff,
                    "attempts" => attempts
                );

                // Wait for the backoff duration
                sleep(backoff);

                // Increase the backoff duration (with exponential backoff)
                backoff = std::cmp::min(backoff.saturating_mul(2), max_backoff);

                attempts = attempts.saturating_add(1);
            }
        }
    }
}

#[cfg(test)]
mod test {
    use std::cell::RefCell;
    use std::time::Instant;

    use serde_json::json;
    use tempfile::tempdir;

    use super::*;

    #[test]
    fn test_init_db() {
        let dir = tempdir().unwrap();
        let db_path = dir.path().join("test_init_db.sqlite");

        // Call init_db
        let conn_result = EventDispatcherDbConnection::new(&db_path);
        assert!(conn_result.is_ok(), "Failed to initialize the database");

        // Check that the database file exists
        assert!(db_path.exists(), "Database file was not created");

        // Check that the table exists
        let conn = conn_result.unwrap();
        let mut stmt = conn
            .connection
            .prepare(
                "SELECT name FROM sqlite_master WHERE type='table' AND name='pending_payloads'",
            )
            .unwrap();
        let table_exists = stmt.exists([]).unwrap();
        assert!(table_exists, "Table 'pending_payloads' does not exist");
    }

    #[test]
    fn test_migration() {
        let dir = tempdir().unwrap();
        let db_path = dir.path().join("test_payload_migration.sqlite");

        // Simulate old schema with TEXT payloads.
        let conn = Connection::open(&db_path).unwrap();
        conn.execute(
            "CREATE TABLE pending_payloads (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                url TEXT NOT NULL,
                payload TEXT NOT NULL,
                timeout INTEGER NOT NULL
            )",
            [],
        )
        .unwrap();
        let payload_str = "{\"key\":\"value\"}";
        conn.execute(
            "INSERT INTO pending_payloads (url, payload, timeout) VALUES (?1, ?2, ?3)",
            params!["http://example.com/api", payload_str, 5000i64],
        )
        .unwrap();
        drop(conn);

        let conn =
            EventDispatcherDbConnection::new(&db_path).expect("Failed to initialize the database");

        let col_type: String = conn
            .connection
            .query_row(
                "SELECT type FROM pragma_table_info('pending_payloads') WHERE name = 'payload'",
                [],
                |row| row.get(0),
            )
            .unwrap();
        assert!(
            col_type.eq_ignore_ascii_case("BLOB"),
            "Payload column was not migrated to BLOB"
        );

        let insertion_info_col_count: i64 = conn
            .connection
            .query_row(
                "SELECT COUNT(*) FROM pragma_table_info('pending_payloads') WHERE name = 'timestamp'",
                [],
                |row| row.get(0),
            )
            .unwrap();
        assert!(
            insertion_info_col_count == 1,
            "timestamp column was not added"
        );

        let version: u32 = conn
            .connection
            .query_row("SELECT MAX(version) FROM db_config", [], |r| r.get(0))
            .expect("db_config was not added");
        assert_eq!(
            version,
            EventDispatcherDbConnection::VERSIONING_AND_TIMESTAMP_COLUMN,
            "Unexpected version number. Did you add a migration? Update this test."
        );

        let pending_payloads = conn
            .get_pending_payloads()
            .expect("Failed to get pending payloads");
        assert_eq!(pending_payloads.len(), 1, "Expected one pending payload");
        assert_eq!(
            pending_payloads[0].request_data.payload_bytes.as_ref(),
            payload_str.as_bytes(),
            "Payload contents did not survive migration"
        );
    }

    #[test]
    fn test_insert_and_get_pending_payloads() {
        let dir = tempdir().unwrap();
        let db_path = dir.path().join("test_payloads.sqlite");

        let conn =
            EventDispatcherDbConnection::new(&db_path).expect("Failed to initialize the database");

        let url = "http://example.com/api".to_string();
        let payload = json!({"key": "value"});
        let timeout = Duration::from_secs(5);
        let timestamp_sentinel = UNIX_EPOCH + Duration::from_hours(24 * 20000);
        let payload_bytes = serde_json::to_vec(&payload).expect("Failed to serialize payload");

        let data = EventRequestData {
            url,
            payload_bytes: payload_bytes.into(),
            timeout,
        };

        // Insert payload
        let id = conn.insert_payload_with_retry(&data, timestamp_sentinel);

        // Get pending payloads
        let pending_payloads = conn
            .get_pending_payloads()
            .expect("Failed to get pending payloads");
        assert_eq!(pending_payloads.len(), 1, "Expected one pending payload");

        let PendingPayload {
            id: retrieved_id,
            timestamp: retrieved_timestamp,
            request_data: retrieved_data,
        } = &pending_payloads[0];

        assert_eq!(*retrieved_id, id, "ID does not match");
        assert_eq!(retrieved_data.url, data.url, "URL does not match");
        assert_eq!(
            retrieved_data.payload_bytes.as_ref(),
            data.payload_bytes.as_ref(),
            "Serialized payload does not match"
        );
        assert_eq!(retrieved_data.timeout, timeout, "Timeout does not match");
        assert_eq!(
            *retrieved_timestamp, timestamp_sentinel,
            "Time stamp does not match"
        );
    }

    #[test]
    fn test_delete_payload() {
        let dir = tempdir().unwrap();
        let db_path = dir.path().join("test_delete_payload.sqlite");

        let conn =
            EventDispatcherDbConnection::new(&db_path).expect("Failed to initialize the database");

        let url = "http://example.com/api".to_string();
        let payload = json!({"key": "value"});
        let timeout = Duration::from_secs(5);
        let payload_bytes = serde_json::to_vec(&payload).expect("Failed to serialize payload");

        let data = EventRequestData {
            url,
            payload_bytes: payload_bytes.into(),
            timeout,
        };

        // Insert payload
        conn.insert_payload(&data, SystemTime::now())
            .expect("Failed to insert payload");

        // Get pending payloads
        let pending_payloads = conn
            .get_pending_payloads()
            .expect("Failed to get pending payloads");
        assert_eq!(pending_payloads.len(), 1, "Expected one pending payload");

        let PendingPayload { id, .. } = pending_payloads[0];

        // Delete payload
        let delete_result = conn.delete_payload(id);
        assert!(delete_result.is_ok(), "Failed to delete payload");

        // Verify that the pending payloads list is empty
        let pending_payloads = conn
            .get_pending_payloads()
            .expect("Failed to get pending payloads");
        assert_eq!(pending_payloads.len(), 0, "Expected no pending payloads");
    }

    #[test]
    fn test_with_retry_returns_original_result() {
        let f = || Result::<i32, String>::Ok(6_7);
        let result = with_retry(f, "failed".to_string());
        assert_eq!(result, 67);
    }

    #[test]
    fn test_with_retry_retries_as_often_as_necessary() {
        let call_count = RefCell::new(0);
        let f = || {
            *call_count.borrow_mut() += 1;
            if *call_count.borrow() < 5 {
                return Err("keep trying");
            } else {
                return Ok("you did it");
            }
        };
        let now = Instant::now();
        let result = with_retry(f, "failed".to_string());
        let elapsed_millis = now.elapsed().as_millis();
        assert_eq!(result, "you did it");
        let count = *call_count.borrow();
        assert_eq!(
            count, 5,
            "inner function was not called the expected number of times"
        );
        // We retry 4 times, with delays of 100, 200, 400, and 800 ms, respectively,
        // for a total of 1,500.
        assert!(1_450 < elapsed_millis && elapsed_millis < 1_550);
    }
}
