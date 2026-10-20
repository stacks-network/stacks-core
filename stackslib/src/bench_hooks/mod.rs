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

pub mod miner;

/// Pause state of one activity. The activity is paused iff `since` is set.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct PauseState {
    /// Unix time (seconds) at which the current pause started.
    since: Option<u64>,
}

impl PauseState {
    pub fn is_paused(&self) -> bool {
        self.since.is_some()
    }

    /// Start a pause at `now`. Pausing an already paused activity keeps the original start.
    pub fn pause(&mut self, now: u64) {
        if self.since.is_none() {
            self.since = Some(now);
        }
    }

    /// End the current pause, if any.
    pub fn resume(&mut self) {
        self.since = None;
    }

    pub fn status(&self) -> PauseStatus {
        PauseStatus {
            paused: self.is_paused(),
            since: self.since,
        }
    }
}

/// Wire representation of a [`PauseState`].
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct PauseStatus {
    pub paused: bool,
    /// Unix time (seconds) at which the current pause started, if paused.
    pub since: Option<u64>,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn pause_resume() {
        let mut state = PauseState::default();
        assert!(!state.is_paused());

        state.pause(100);
        assert_eq!(
            state.status(),
            PauseStatus {
                paused: true,
                since: Some(100)
            }
        );

        // a second pause keeps the original start time
        state.pause(200);
        assert_eq!(state.status().since, Some(100));

        state.resume();
        assert_eq!(
            state.status(),
            PauseStatus {
                paused: false,
                since: None
            }
        );

        // resuming when not paused is a no-op
        state.resume();
        assert!(!state.is_paused());
    }
}
