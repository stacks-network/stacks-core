#[macro_use]
pub mod db;
pub mod bloom;
pub mod boot;
pub mod signed_structured_data;
pub mod strings;

#[cfg(test)]
pub mod test {
    use std::sync::mpsc::{sync_channel, RecvTimeoutError};
    use std::time::Duration;
    use std::{panic, thread};

    use stacks_common::util::sleep_ms;

    pub fn with_timeout<F>(timeout_secs: u64, test_func: F)
    where
        F: FnOnce() + std::marker::Send + 'static + panic::UnwindSafe,
    {
        let (sx, rx) = sync_channel(1);

        let t = thread::spawn(move || {
            let result = panic::catch_unwind(|| {
                test_func();
            });
            let _ = sx.send(result.is_ok());
        });

        // Return as soon as the worker reports completion, while preserving the
        // caller's timeout bound.
        match rx.recv_timeout(Duration::from_secs(timeout_secs)) {
            Ok(success) => assert!(success),
            Err(RecvTimeoutError::Timeout) => {
                panic!("Test timed out after {} seconds", timeout_secs)
            }
            Err(RecvTimeoutError::Disconnected) => {
                panic!("Test thread disconnected before reporting result")
            }
        }
        t.join().unwrap();
    }

    #[test]
    fn test_test_timeout() {
        with_timeout(2000000, || {
            eprintln!("timeout test start...");
            sleep_ms(1000);
            eprintln!("timeout test end");
        })
    }

    #[test]
    #[should_panic]
    fn test_test_timeout_timeout() {
        with_timeout(1, || {
            eprintln!("timeout panic test start...");
            sleep_ms(1000 * 1000);
        })
    }

    #[test]
    #[should_panic]
    fn test_test_timeout_panic() {
        with_timeout(1000, || {
            panic!("force a panic");
        })
    }
}
