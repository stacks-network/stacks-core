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

//! Miner controls, exposed through `/bench/v1/miner`.

use std::time::Duration;

use stacks_common::util::get_epoch_time_secs;

use super::{RunControl, RunStatus};

/// Commands accepted by `POST /bench/v1/miner`, as `{"command": "<name>"}`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "command", rename_all = "kebab-case")]
pub enum MinerBenchCommand {
    /// Stop building and proposing Stacks blocks. RPC, mempool and p2p keep running, so
    /// submitted transactions keep accumulating in the mempool.
    PauseMining,
    /// Resume building and proposing Stacks blocks.
    ResumeMining,
}

/// Response of `GET` and `POST /bench/v1/miner`: the miner controls after the request.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct MinerBenchStatus {
    /// Block mining. A pause takes effect at the miner's next block attempt: while one that
    /// started before the request is in flight, the state is `pausing`, and it becomes `paused`
    /// once the miner waits at its checkpoint. Tooling that needs the miner idle (e.g. to fill
    /// the mempool) should wait for `paused`. A node that is not mining stays `pausing`.
    pub mining: RunStatus,
}

/// Everything controllable under `/bench/v1/miner`.
struct MinerBenchState {
    mining: RunControl,
}

impl MinerBenchState {
    const fn new() -> Self {
        Self {
            mining: RunControl::new("mining"),
        }
    }

    fn status(&self) -> MinerBenchStatus {
        MinerBenchStatus {
            mining: self.mining.status(),
        }
    }

    fn apply(&self, command: MinerBenchCommand) -> MinerBenchStatus {
        match command {
            MinerBenchCommand::PauseMining => {
                self.mining.pause(get_epoch_time_secs());
                info!("Bench hooks: mining pause requested");
            }
            MinerBenchCommand::ResumeMining => {
                self.mining.resume();
                info!("Bench hooks: mining resumed");
            }
        }
        self.status()
    }
}

static MINER: MinerBenchState = MinerBenchState::new();

/// Current state of the miner controls.
pub fn status() -> MinerBenchStatus {
    MINER.status()
}

/// Apply a command and return the resulting state. Commands are idempotent.
pub fn apply(command: MinerBenchCommand) -> MinerBenchStatus {
    MINER.apply(command)
}

/// The miner's pause checkpoint, called before each block attempt (see
/// [`RunControl::hold_while_paused`]).
pub fn hold_while_paused(poll: Duration, stop: impl Fn() -> bool) {
    MINER.mining.hold_while_paused(poll, stop)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::bench_hooks::RunState;

    #[test]
    fn command_wire_format() {
        let pause: MinerBenchCommand =
            serde_json::from_str(r#"{"command":"pause-mining"}"#).unwrap();
        assert_eq!(pause, MinerBenchCommand::PauseMining);

        let resume: MinerBenchCommand =
            serde_json::from_str(r#"{"command":"resume-mining"}"#).unwrap();
        assert_eq!(resume, MinerBenchCommand::ResumeMining);

        let unknown = serde_json::from_str::<MinerBenchCommand>(r#"{"command":"pause"}"#)
            .unwrap_err()
            .to_string();
        assert!(unknown.contains("pause-mining"), "{unknown}");

        // commands without arguments ignore extra fields
        let extra: MinerBenchCommand =
            serde_json::from_str(r#"{"command":"pause-mining","args":{}}"#).unwrap();
        assert_eq!(extra, MinerBenchCommand::PauseMining);

        assert!(serde_json::from_str::<MinerBenchCommand>(r#"{}"#).is_err());
    }

    #[test]
    fn status_wire_format() {
        let status = MinerBenchStatus {
            mining: RunStatus {
                state: RunState::Paused,
                since: Some(100),
            },
        };
        assert_eq!(
            serde_json::to_value(status).unwrap(),
            serde_json::json!({"mining": {"state": "paused", "since": 100}})
        );
    }

    /// Commands change the mining control; with no miner at the checkpoint a pause stays
    /// `pausing`.
    #[test]
    fn apply_commands() {
        let state = MinerBenchState::new();
        assert_eq!(state.status().mining.state, RunState::Running);

        let paused = state.apply(MinerBenchCommand::PauseMining);
        assert_eq!(paused.mining.state, RunState::Pausing);
        assert!(paused.mining.since.is_some());

        let resumed = state.apply(MinerBenchCommand::ResumeMining);
        assert_eq!(resumed.mining.state, RunState::Running);
        assert_eq!(resumed.mining.since, None);
    }
}
