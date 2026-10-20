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

use std::sync::{Mutex, PoisonError};

use stacks_common::util::get_epoch_time_secs;

use super::{PauseState, PauseStatus};

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

/// Everything controllable under `/bench/v1/miner`.
struct MinerBenchState {
    mining: Mutex<PauseState>,
}

static MINER: MinerBenchState = MinerBenchState {
    mining: Mutex::new(PauseState { since: None }),
};

/// Response of `GET` and `POST /bench/v1/miner`: the miner controls after the request.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct MinerBenchStatus {
    pub mining: PauseStatus,
}

fn with_mining<R>(f: impl FnOnce(&mut PauseState) -> R) -> R {
    // The state is plain data and always valid, so a poisoned lock is still usable.
    let mut state = MINER.mining.lock().unwrap_or_else(PoisonError::into_inner);
    f(&mut state)
}

/// Whether the miner should hold before its next block attempt.
pub fn is_mining_paused() -> bool {
    with_mining(|state| state.is_paused())
}

/// Current state of the miner controls.
pub fn status() -> MinerBenchStatus {
    MinerBenchStatus {
        mining: with_mining(|state| state.status()),
    }
}

/// Apply a command and return the resulting state. Commands are idempotent.
pub fn apply(command: MinerBenchCommand) -> MinerBenchStatus {
    match command {
        MinerBenchCommand::PauseMining => {
            with_mining(|state| state.pause(get_epoch_time_secs()));
            info!("Bench hooks: mining paused");
        }
        MinerBenchCommand::ResumeMining => {
            with_mining(|state| state.resume());
            info!("Bench hooks: mining resumed");
        }
    }
    status()
}

#[cfg(test)]
mod tests {
    use super::*;

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
}
