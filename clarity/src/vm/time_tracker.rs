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

use std::time::{Duration, Instant};

/// Tracks wall-clock time spent in a single execution phase of one transaction
/// (Clarity evaluation *or* contract analysis) and signals when a configured
/// deadline has elapsed.
///
/// [`TimeTracker::NoTracking`] is the deterministic-replay / no-limit case (it must be used on
/// the commit/replay path so consensus stays deterministic).
///
/// [`TimeTracker::MaxTime`] is used only on the non-consensus voting paths:
/// block assembly (mining) and block-proposal validation (signers) to bound the time
/// a single transaction can spend.
#[derive(Clone, Copy)]
pub enum TimeTracker {
    NoTracking,
    MaxTime {
        start_time: Instant,
        max_duration: Duration,
    },
}

impl TimeTracker {
    /// Creates a [`TimeTracker`] from an optional maximum duration.
    ///
    /// If `Some(duration)` is provided, tracking starts immediately and the
    /// tracker will consider the phase bounded by `duration`.
    ///
    /// If `None` is provided, no time tracking is performed and the tracker
    /// behaves as an unlimited timer.
    pub fn from_opt_max_duration(duration: Option<Duration>) -> Self {
        match duration {
            Some(max_duration) => Self::from_max_duration(max_duration),
            None => Self::unlimited(),
        }
    }

    /// Creates a [`Self::MaxTime`] and starts tracking time immediately.
    ///
    /// The elapsed time is measured from the moment this function is called,
    /// and the tracker is configured with the provided maximum duration.
    pub fn from_max_duration(duration: Duration) -> Self {
        Self::MaxTime {
            start_time: Instant::now(),
            max_duration: duration,
        }
    }

    /// Creates a [`Self::NoTracking`] instance.
    ///
    /// In this mode, no elapsed time is recorded and no time limit is enforced.
    /// This can be used when timing is irrelevant or intentionally disabled.
    pub fn unlimited() -> Self {
        Self::NoTracking
    }

    /// Returns `true` if a deadline is configured and has elapsed. Always
    /// `false` for `NoTracking`.
    pub fn is_expired(&self) -> bool {
        match self {
            Self::NoTracking => false,
            Self::MaxTime {
                start_time,
                max_duration,
            } => start_time.elapsed() >= *max_duration,
        }
    }
}

#[cfg(test)]
mod test {
    use std::thread::sleep;

    use super::*;

    #[test]
    fn test_free_is_no_tracking_and_never_expires() {
        let tracker = TimeTracker::unlimited();
        assert!(matches!(tracker, TimeTracker::NoTracking));
        assert!(!tracker.is_expired());
    }

    #[test]
    fn test_zero_duration_is_immediately_expired() {
        let tracker = TimeTracker::from_max_duration(Duration::ZERO);
        assert!(matches!(tracker, TimeTracker::MaxTime { .. }));
        assert!(tracker.is_expired());
    }

    #[test]
    fn test_with_duration_expiring() {
        let tracker = TimeTracker::from_max_duration(Duration::from_millis(100));
        assert!(!tracker.is_expired());

        sleep(Duration::from_millis(200));
        assert!(tracker.is_expired());
    }

    #[test]
    fn test_from_opt_max_duration_creates_proper_instance() {
        let tracker = TimeTracker::from_opt_max_duration(None);
        assert!(matches!(tracker, TimeTracker::NoTracking));

        let tracker = TimeTracker::from_opt_max_duration(Some(Duration::ZERO));
        assert!(matches!(tracker, TimeTracker::MaxTime { .. }));
    }
}
