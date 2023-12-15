use slog::{slog_info, slog_trace};
use stacks_common::{info, trace};
use std::{
    sync::{
        atomic::{AtomicBool, Ordering},
        mpsc::Sender,
        Arc,
    },
    thread::{self, JoinHandle},
    time::Duration,
};

use crate::runloop::RunLoopCommand;

/// Stop the pinger thread
pub struct PingStopHandle {
    keep_running: Arc<AtomicBool>,
    handle: JoinHandle<()>,
}

/// Send a ping command periodically
pub struct PeriodicPinger {
    keep_running: Arc<AtomicBool>,
    wait_for: Duration,
    sender: Sender<RunLoopCommand>,
}

impl PeriodicPinger {
    /// Spawn a new pinger thread
    pub fn spawn(tx: Sender<RunLoopCommand>, wait_for: Duration) -> PingStopHandle {
        let runner = Self {
            keep_running: Arc::new(AtomicBool::new(true)),
            wait_for,
            sender: tx,
        };

        PingStopHandle {
            keep_running: Arc::clone(&runner.keep_running),
            handle: thread::Builder::new()
                .name("periodic-pinger".into())
                .spawn(move || runner.run())
                .unwrap(),
        }
    }

    fn run(self) {
        while self.keep_running() {
            if let Err(e) = self.sender.send(RunLoopCommand::Ping) {
                info!("Exit: Send channel closed: {e}");
                break;
            }
            trace!("Sent ping cmd");
            thread::sleep(self.wait_for);
        }
    }

    fn keep_running(&self) -> bool {
        self.keep_running.load(Ordering::Relaxed)
    }
}

impl PingStopHandle {
    /// Stop the open loop and join the thread handle
    pub fn stop(self) {
        self.keep_running.store(false, Ordering::SeqCst);
        let _ = self
            .handle
            .join()
            .map_err(|e| info!("Failed to join thread: {e:?}"));
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::mpsc::channel;

    #[test]
    fn pinger_sends() {
        let (tx, rx) = channel();
        let handle = PeriodicPinger::spawn(tx, Duration::from_millis(50));
        thread::sleep(Duration::from_millis(200));

        assert!(rx.recv().unwrap() == RunLoopCommand::Ping);
        assert!(rx.recv().unwrap() == RunLoopCommand::Ping);

        handle.stop();
    }
}
