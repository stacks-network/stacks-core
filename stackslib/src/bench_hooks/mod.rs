// Copyright (C) 2026 Stacks Open Internet Foundation
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

//! Runtime controls for benchmarking builds.
//!
//! This module only exists when the node is built with the `bench-hooks` feature. It holds
//! process-wide, in-memory state that benchmark tooling changes through the `/bench/v1/...`
//! RPC endpoints and that node subsystems read. Nothing here is persisted: a restart always
//! brings the node back to its normal behavior.

use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Mutex, PoisonError};
use std::thread;
use std::time::Duration;

pub mod miner;

/// What a pausable activity is doing.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum RunState {
    /// No pause is requested.
    Running,
    /// A pause is requested, but the activity has not reached its checkpoint yet: work that
    /// started before the request may still be in progress.
    Pausing,
    /// The activity waits at its checkpoint: nothing is in progress until it is resumed.
    Paused,
}

/// Wire representation of a [`RunControl`].
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct RunStatus {
    pub state: RunState,
    /// Unix time (seconds) at which the current pause was requested; absent while running.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub since: Option<u64>,
}

/// Run control of one pausable activity. Tooling requests a pause or a resume; the activity
/// calls [`RunControl::hold_while_paused`] at its checkpoint, a point where none of its work is
/// in progress, so the control can tell a requested pause ([`RunState::Pausing`]) from one in
/// effect ([`RunState::Paused`]).
pub struct RunControl {
    /// Name of the activity, for the logs.
    name: &'static str,
    /// Unix time (seconds) at which the current pause was requested; `None` while running.
    since: Mutex<Option<u64>>,
    /// Threads currently waiting at the checkpoint.
    held: AtomicUsize,
}

/// Counts a thread as held at the checkpoint for as long as it lives, also if the thread unwinds.
struct HeldGuard<'a>(&'a AtomicUsize);

impl<'a> HeldGuard<'a> {
    fn new(held: &'a AtomicUsize) -> Self {
        held.fetch_add(1, Ordering::SeqCst);
        Self(held)
    }
}

impl Drop for HeldGuard<'_> {
    fn drop(&mut self) {
        self.0.fetch_sub(1, Ordering::SeqCst);
    }
}

impl RunControl {
    pub const fn new(name: &'static str) -> Self {
        Self {
            name,
            since: Mutex::new(None),
            held: AtomicUsize::new(0),
        }
    }

    fn with_since<R>(&self, f: impl FnOnce(&mut Option<u64>) -> R) -> R {
        // The state is plain data and always valid, so a poisoned lock is still usable.
        let mut since = self.since.lock().unwrap_or_else(PoisonError::into_inner);
        f(&mut since)
    }

    fn is_pause_requested(&self) -> bool {
        self.with_since(|since| since.is_some())
    }

    /// Request a pause at `now`. Pausing again keeps the original request time.
    pub fn pause(&self, now: u64) {
        self.with_since(|since| {
            since.get_or_insert(now);
        });
    }

    /// End the current pause, if any.
    pub fn resume(&self) {
        self.with_since(|since| *since = None);
    }

    pub fn status(&self) -> RunStatus {
        let since = self.with_since(|since| *since);
        let state = match since {
            None => RunState::Running,
            Some(_) if self.held.load(Ordering::SeqCst) > 0 => RunState::Paused,
            Some(_) => RunState::Pausing,
        };
        RunStatus { state, since }
    }

    /// The activity's checkpoint: while a pause is requested, wait (checking every `poll`) with
    /// the activity reported as [`RunState::Paused`], until it is resumed or `stop` returns
    /// `true` (e.g. the activity is aborted or the node shuts down). Returns at once when no
    /// pause is requested.
    pub fn hold_while_paused(&self, poll: Duration, stop: impl Fn() -> bool) {
        if !self.is_pause_requested() {
            return;
        }
        let _held = HeldGuard::new(&self.held);
        warn!("Bench hooks: {} paused at its checkpoint", self.name);
        while self.is_pause_requested() && !stop() {
            thread::sleep(poll);
        }
        warn!("Bench hooks: {} leaving its checkpoint", self.name;
            "stopped" => stop(),
            "still_pause_requested" => self.is_pause_requested(),
        );
    }
}

#[cfg(test)]
mod tests {
    use std::sync::atomic::AtomicBool;
    use std::time::Instant;

    use super::*;

    const POLL: Duration = Duration::from_millis(1);

    fn wait_for(what: &str, condition: impl Fn() -> bool) {
        let deadline = Instant::now() + Duration::from_secs(10);
        while !condition() {
            assert!(Instant::now() < deadline, "timed out waiting for {what}");
            thread::sleep(POLL);
        }
    }

    #[test]
    fn pause_resume() {
        let control = RunControl::new("test");
        let running = RunStatus {
            state: RunState::Running,
            since: None,
        };
        assert_eq!(control.status(), running);

        // no thread at the checkpoint: the pause is only requested
        control.pause(100);
        assert_eq!(
            control.status(),
            RunStatus {
                state: RunState::Pausing,
                since: Some(100)
            }
        );

        // a second pause keeps the original request time
        control.pause(200);
        assert_eq!(control.status().since, Some(100));

        control.resume();
        assert_eq!(control.status(), running);

        // resuming when running is a no-op
        control.resume();
        assert_eq!(control.status(), running);
    }

    #[test]
    fn status_wire_format() {
        let running = RunStatus {
            state: RunState::Running,
            since: None,
        };
        assert_eq!(
            serde_json::to_value(running).unwrap(),
            serde_json::json!({"state": "running"})
        );
        let paused = RunStatus {
            state: RunState::Paused,
            since: Some(100),
        };
        assert_eq!(
            serde_json::to_value(paused).unwrap(),
            serde_json::json!({"state": "paused", "since": 100})
        );
        let pausing: RunStatus =
            serde_json::from_str(r#"{"state": "pausing", "since": 100}"#).unwrap();
        assert_eq!(pausing.state, RunState::Pausing);
    }

    /// A pause requested while the activity is mid-work stays `pausing` until the activity
    /// reaches its checkpoint, and only then is `paused`.
    #[test]
    fn paused_only_while_the_activity_waits() {
        let control = RunControl::new("test");

        // not paused: the checkpoint returns at once
        control.hold_while_paused(POLL, || false);
        assert_eq!(control.status().state, RunState::Running);

        // the pause is requested while the activity is past its checkpoint
        control.pause(100);
        assert_eq!(control.status().state, RunState::Pausing);

        thread::scope(|s| {
            // the activity finishes its work and reaches the checkpoint
            let activity = s.spawn(|| control.hold_while_paused(POLL, || false));
            wait_for("the activity to be paused", || {
                control.status().state == RunState::Paused
            });
            assert!(!activity.is_finished());

            control.resume();
            assert_eq!(control.status().state, RunState::Running);
            activity.join().unwrap();
        });
        assert_eq!(control.status().state, RunState::Running);
    }

    /// A stopped activity (e.g. an aborted miner) leaves the checkpoint while the pause stays
    /// requested.
    #[test]
    fn stop_releases_the_checkpoint() {
        let control = RunControl::new("test");
        control.pause(100);
        let stop = AtomicBool::new(false);

        thread::scope(|s| {
            let activity =
                s.spawn(|| control.hold_while_paused(POLL, || stop.load(Ordering::SeqCst)));
            wait_for("the activity to be paused", || {
                control.status().state == RunState::Paused
            });

            stop.store(true, Ordering::SeqCst);
            activity.join().unwrap();
        });
        assert_eq!(
            control.status(),
            RunStatus {
                state: RunState::Pausing,
                since: Some(100)
            }
        );
    }
}
