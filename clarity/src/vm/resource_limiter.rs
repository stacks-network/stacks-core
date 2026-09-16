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

use stacks_common::alloc_tracker::{
    AllocationCounter, thread_allocated, tracking_allocator_installed,
};

use crate::vm::resource_limiter::MemoryTracker::{MaxAllocated, NoTracking};

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
enum TimeTracker {
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
    #[cfg(test)]
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

    /// Returns and error if a deadline is configured and has elapsed. Always
    /// Ok(()) for `NoTracking`.
    pub fn check_not_expired(&self) -> Result<(), String> {
        match self {
            Self::NoTracking => Ok(()),
            Self::MaxTime {
                start_time,
                max_duration,
            } => {
                let elapsed = start_time.elapsed();
                // semantically `>` would be more correct than `>=`, but there
                // are a few tests that assume "zero always expires", and since
                // it makes not practical difference otherwise, we use `>=`.
                if elapsed >= *max_duration {
                    Err(format!(
                        "Elapsed time of {} ms exceeds budget of {} ms.",
                        elapsed.as_millis(),
                        max_duration.as_millis()
                    ))
                } else {
                    Ok(())
                }
            }
        }
    }
}

#[derive(Clone, Copy)]
enum MemoryTracker {
    NoTracking,
    MaxAllocated {
        baseline: AllocationCounter,
        limit_bytes: u64,
    },
}

impl MemoryTracker {
    pub fn unlimited() -> Self {
        Self::NoTracking
    }

    pub fn from_max_allocation(limit_bytes: u64) -> Self {
        if !tracking_allocator_installed() {
            error!(
                "TrackingAllocator is not installed as the global allocator; any configured memory limits will never trigger"
            );
        }

        Self::MaxAllocated {
            baseline: thread_allocated(),
            limit_bytes,
        }
    }

    pub fn check_not_exceeded(&self) -> Result<(), String> {
        match self {
            NoTracking => Ok(()),
            MaxAllocated {
                baseline,
                limit_bytes,
            } => {
                let allocated = thread_allocated().net_allocated(baseline);
                if allocated > *limit_bytes {
                    Err(format!(
                        "Net memory allocation of {} bytes exceeds budget of {} bytes.",
                        allocated, *limit_bytes
                    ))
                } else {
                    Ok(())
                }
            }
        }
    }

    /// Reject an upcoming allocation of `bytes` that would exceed the limit,
    /// so a known size can be refused before it is allocated.
    pub fn check_can_allocate(&self, bytes: u64) -> Result<(), String> {
        match self {
            NoTracking => Ok(()),
            MaxAllocated {
                baseline,
                limit_bytes,
            } => {
                let allocated = thread_allocated().net_allocated(baseline);
                if allocated.saturating_add(bytes) > *limit_bytes {
                    Err(format!(
                        "Net memory allocation of {allocated} bytes plus {bytes} upcoming bytes exceeds budget of {limit_bytes} bytes."
                    ))
                } else {
                    Ok(())
                }
            }
        }
    }

    /// Net bytes allocated since the baseline. `None` for `NoTracking`.
    pub fn net_allocated_bytes(&self) -> Option<u64> {
        match self {
            Self::NoTracking => None,
            Self::MaxAllocated { baseline, .. } => Some(thread_allocated().net_allocated(baseline)),
        }
    }
}

/// Specifies the maximum wallclock time and the maximum heap allocation
/// that can be used by an operation. The two relevant operations are
/// contract analysis and execution, each of which have separate budgets
/// (see `TransactionResourceBudgets`).
///
/// Call [`ResourceBudget::start_tracking`] to receive a [`ResourceLimiter`] that
/// fixes the baseline (current time and memory allocation) and that can be polled
/// to ensure usage stays within limits.
///
/// Memory tracking requires that the [`TrackingAllocator`] has been installed.
///
/// This is NOT related to cost tracking. The latter is consensus-critical and therefore
/// deterministic. The purpose of the [`ResourceBudget`] is defense-in-depth: If
/// a bug in clarity evaluation or analysis causes a long runtime or a huge amount
/// of memory being used, the miner will not include it in a block, and the signer
/// will reject the block as problematic.
///
/// During consensus-critical work, the budget MUST be [`ResourceBudget::unlimited`]
/// to ensure determinism.
pub struct ResourceBudget {
    max_duration: Option<Duration>,
    max_allocated_bytes: Option<u64>,
}

impl ResourceBudget {
    pub fn new() -> Self {
        Self {
            max_duration: None,
            max_allocated_bytes: None,
        }
    }

    pub fn unlimited() -> Self {
        // identical to Self::new(), but also provided under the name `unlimited`
        // to make intentions obvious at the call site
        Self::new()
    }

    pub fn with_max_duration(mut self, duration: Option<Duration>) -> Self {
        self.max_duration = duration;
        self
    }

    pub fn with_max_memory_use(mut self, bytes: Option<u64>) -> Self {
        self.max_allocated_bytes = bytes;
        self
    }

    /// Returns a resource limiter that can be polled to ensure that the budget
    /// is not exceeded (relative to the baseline that is taken at call time).
    pub fn start_tracking(&self) -> ResourceLimiter {
        ResourceLimiter::from_budget(self)
    }
}

impl Default for ResourceBudget {
    fn default() -> Self {
        Self::new()
    }
}

pub enum ResourceLimitExceeded {
    MaxDurationExceeded(String),
    MaxAllocationExceeded(String),
}

#[derive(Clone, Copy)]
pub struct ResourceLimiter {
    time_tracker: TimeTracker,
    mem_tracker: MemoryTracker,
}

impl ResourceLimiter {
    pub fn unlimited() -> ResourceLimiter {
        Self {
            time_tracker: TimeTracker::unlimited(),
            mem_tracker: MemoryTracker::unlimited(),
        }
    }

    pub fn from_budget(budget: &ResourceBudget) -> Self {
        let time_tracker = if let Some(duration) = budget.max_duration {
            TimeTracker::from_max_duration(duration)
        } else {
            TimeTracker::unlimited()
        };

        let mem_tracker = if let Some(bytes) = budget.max_allocated_bytes {
            MemoryTracker::from_max_allocation(bytes)
        } else {
            MemoryTracker::unlimited()
        };

        Self {
            time_tracker,
            mem_tracker,
        }
    }

    pub fn check_not_exceeded(&self) -> Result<(), ResourceLimitExceeded> {
        self.time_tracker
            .check_not_expired()
            .map_err(ResourceLimitExceeded::MaxDurationExceeded)?;

        self.mem_tracker
            .check_not_exceeded()
            .map_err(ResourceLimitExceeded::MaxAllocationExceeded)
    }

    /// Reject an upcoming allocation of `bytes` that would exceed the memory
    /// limit. Prospective, unlike [`Self::check_not_exceeded`].
    pub fn check_can_allocate(&self, bytes: u64) -> Result<(), ResourceLimitExceeded> {
        self.mem_tracker
            .check_can_allocate(bytes)
            .map_err(ResourceLimitExceeded::MaxAllocationExceeded)
    }

    /// Net bytes allocated since the baseline. `None` if memory is untracked.
    pub fn net_allocated_bytes(&self) -> Option<u64> {
        self.mem_tracker.net_allocated_bytes()
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
        assert!(tracker.check_not_expired().is_ok());
    }

    #[test]
    fn test_zero_duration_is_immediately_expired() {
        let tracker = TimeTracker::from_max_duration(Duration::ZERO);
        assert!(matches!(tracker, TimeTracker::MaxTime { .. }));
        assert!(tracker.check_not_expired().is_err());
    }

    #[test]
    fn test_with_duration_expiring() {
        let tracker = TimeTracker::from_max_duration(Duration::from_millis(100));
        assert!(tracker.check_not_expired().is_ok());

        sleep(Duration::from_millis(200));
        assert!(tracker.check_not_expired().is_err());
    }

    #[test]
    fn test_from_opt_max_duration_creates_proper_instance() {
        let tracker = TimeTracker::from_opt_max_duration(None);
        assert!(matches!(tracker, TimeTracker::NoTracking));

        let tracker = TimeTracker::from_opt_max_duration(Some(Duration::ZERO));
        assert!(matches!(tracker, TimeTracker::MaxTime { .. }));
    }
}
