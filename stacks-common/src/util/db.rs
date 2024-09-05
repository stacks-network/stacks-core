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
use std::time::Duration;

use rand::{thread_rng, Rng};

use crate::util::sleep_ms;

/// Called by `rusqlite` if we are waiting too long on a database lock
/// If called too many times, will fail to avoid deadlocks
pub fn tx_busy_handler(run_count: i32) -> bool {
    const TIMEOUT: Duration = Duration::from_secs(60);
    const AVG_SLEEP_TIME_MS: u64 = 100;

    // First, check if this is taking unreasonably long. If so, it's probably a deadlock
    let run_count = run_count.unsigned_abs();
    let approx_time_elapsed =
        Duration::from_millis(AVG_SLEEP_TIME_MS.saturating_mul(u64::from(run_count)));
    if approx_time_elapsed > TIMEOUT {
        error!("Probable deadlock detected. Waited {} seconds (estimated) for database lock. Giving up", approx_time_elapsed.as_secs();
            "run_count" => run_count,
            "backtrace" => ?Backtrace::capture()
        );
        return false;
    }

    let mut sleep_time_ms = 2u64.saturating_pow(run_count);

    sleep_time_ms = sleep_time_ms.saturating_add(thread_rng().gen_range(0..sleep_time_ms));

    if sleep_time_ms > AVG_SLEEP_TIME_MS {
        let jitter = 10;
        sleep_time_ms =
            thread_rng().gen_range((AVG_SLEEP_TIME_MS - jitter)..(AVG_SLEEP_TIME_MS + jitter));
    }

    let msg = format!("Database is locked; sleeping {sleep_time_ms}ms and trying again");
    if run_count > 10 && run_count % 10 == 0 {
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
