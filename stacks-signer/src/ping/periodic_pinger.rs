// Copyright (C) 2013-2020 Blockstack PBC, a public benefit corporation
// Copyright (C) 2020-2024 Stacks Open Internet Foundation
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

use slog::{slog_info, slog_trace};
use stacks_common::{info, trace};
use std::{
    collections::HashMap,
    sync::{
        atomic::{AtomicBool, Ordering},
        mpsc::{Receiver, Sender, TryRecvError},
        Arc,
    },
    thread::{self, JoinHandle},
    time::{Duration, Instant},
};

use crate::runloop::RunLoopCommand;

/// Stop the pinger thread
pub struct PingStopHandle {
    keep_running: Arc<AtomicBool>,
    handle: JoinHandle<RTTSummary>,
}

type RTTSummary = HashMap<u64, Vec<Duration>>;

/// Send a ping command periodically
pub struct PeriodicPinger {
    keep_running: Arc<AtomicBool>,
    wait_for: Duration,
    sender: Sender<RunLoopCommand>,
    payload_size: u32,
    ping_recv: Receiver<(u64, Duration)>,
    rtt_store: RTTSummary,
}

impl PeriodicPinger {
    /// Spawn a new pinger thread
    pub fn spawn(
        tx: Sender<RunLoopCommand>,
        wait_for: Duration,
        payload_size: u32,
        ping_recv: Receiver<(u64, Duration)>,
    ) -> PingStopHandle {
        let runner = Self {
            keep_running: Arc::new(AtomicBool::new(true)),
            wait_for,
            sender: tx,
            payload_size,
            ping_recv,
            rtt_store: HashMap::new(),
        };

        PingStopHandle {
            keep_running: Arc::clone(&runner.keep_running),
            handle: thread::Builder::new()
                .name("periodic-pinger".into())
                .spawn(move || runner.run())
                .unwrap(),
        }
    }

    fn run(mut self) -> RTTSummary {
        'outer: while self.keep_running() {
            if let Err(e) = self.sender.send(RunLoopCommand::Ping {
                payload_size: self.payload_size,
            }) {
                info!("Exit: Send channel closed: {e}");
                break;
            }
            trace!("Sent ping cmd");

            let now = Instant::now();
            while self.wait_for.saturating_sub(now.elapsed()) > Duration::ZERO {
                match self.ping_recv.try_recv() {
                    Ok((id, rtt)) => {
                        self.rtt_store.entry(id).or_default().push(rtt);
                    }
                    Err(TryRecvError::Empty) => {
                        thread::sleep(self.wait_for.saturating_sub(now.elapsed()));
                        break;
                    }
                    Err(_) => break 'outer,
                }
            }
        }
        self.rtt_store
    }

    fn keep_running(&self) -> bool {
        self.keep_running.load(Ordering::Relaxed)
    }
}

impl PingStopHandle {
    /// Stop the open loop and join the thread handle
    pub fn stop(self) -> Result<RTTSummary, ()> {
        self.keep_running.store(false, Ordering::SeqCst);
        self.handle
            .join()
            .map_err(|e| info!("Failed to join thread: {e:?}"))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::{sync::mpsc::channel, time::Instant};

    #[test]
    fn pinger_sends() {
        let (tx, rx) = channel();
        let payload_size = 8;
        let (_tx, ping_rx) = channel();
        let handle = PeriodicPinger::spawn(tx, Duration::from_millis(50), 8, ping_rx);
        thread::sleep(Duration::from_millis(200));

        assert!(rx.recv().unwrap() == RunLoopCommand::Ping { payload_size });
        assert!(rx.recv().unwrap() == RunLoopCommand::Ping { payload_size });

        let _ = handle.stop();
    }

    #[test]
    fn pinger_receives() {
        let (tx, _rx) = channel();
        let (ping_tx, ping_rx) = channel();
        ping_tx.send((0, Instant::now().elapsed())).unwrap();

        let handle = PeriodicPinger::spawn(tx, Duration::from_millis(50), 8, ping_rx);
        thread::sleep(Duration::from_millis(200));

        let map = handle.stop().unwrap();
        assert!(map.get(&0).unwrap().len() == 1);
    }
}
