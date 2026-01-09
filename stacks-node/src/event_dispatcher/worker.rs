// Copyright (C) 2013-2020 Blockstack PBC, a public benefit corporation
// Copyright (C) 2020-2026 Stacks Open Internet Foundation
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

use std::path::PathBuf;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::mpsc::{channel, sync_channel, Receiver, Sender, SyncSender};
use std::sync::Arc;
use std::thread::{self, sleep};
use std::time::{Duration, SystemTime};

use rand::Rng;
use stacks::net::http::HttpRequestContents;
use stacks::net::httpcore::{send_http_request, StacksHttpRequest};
use stacks::types::net::PeerHost;
use url::Url;

use crate::event_dispatcher::db::EventDispatcherDbConnection;
#[cfg(test)]
use crate::event_dispatcher::TEST_EVENT_OBSERVER_SKIP_RETRY;
use crate::event_dispatcher::{EventDispatcherError, EventRequestData};

#[allow(dead_code)] // NoOp is only used in test configurations
enum WorkerTask {
    Payload {
        /// The id of the payload data in the event observer DB. It must exist.
        id: i64,
        /// If true, the HTTP request is only attempted once.
        disable_retries: bool,
        /// A value for the HTTP timeout is stored in the DB, but can optionally be overridden.
        timeout_override: Option<Duration>,
    },
    NoOp,
}
struct WorkerMessage {
    task: WorkerTask,
    /// The worker thread will send a message on this channel once it's done with this request.
    completion: Sender<()>,
}

/// The return type of `initiate_send()`. If the caller of that method just wishes to move
/// on, they can happily drop this result. This is the behavior for most event deliveries.
///
/// On the other hand, if they wish to block until the HTTP request was successfully sent
/// (or, in the case of `disable_retries`, at least attempted), they can call
/// `.wait_until_complete()`. This is what happens during `process_pending_payloads()` at
/// startup. Note that it's possible that other requests are in the queue, so the blocking
/// may take longer than only the handling of this very request.
pub struct EventDispatcherResult {
    /// The worker thread will send a one-time message to this channel to notify of completion.
    /// Afterwards, it will drop the sender and thus close the channel.
    receiver: Receiver<()>,
}

impl EventDispatcherResult {
    pub fn wait_until_complete(self) {
        // There is no codepath that would drop the sender without sending the acknowledgenent
        // first. And this method consumes `self`, so it can only be called once.
        // So if despite all that, `recv()` returns an error, that means the worker thread panicked.
        self.receiver
            .recv()
            .expect("EventDispatcherWorker thread has terminated mid-operation");
    }
}

/// This worker is responsible for making the actual HTTP requests that ultimately result
/// from dispatching events to observers. It makes those requests on a dedicated separate
/// thread so that e.g. a slow event observer doesn't block a node from continuing its work.
///
/// Call `EventDispatcherWorker::new()` to create.
///
/// Call `initiate_send()` with the id of the payload (in the event oberserver DB) to enqueue.
///
/// Cloning the `EventDispatcherWorker` does *not* create a new thread -- both the original and
/// the clone will share a single queue and worker thread.
///
/// Once the `EventDispatcherWorker` (including any clones) is dropped, the worker thread will
/// finish any enqueued work and then shut down.
#[derive(Clone)]
pub struct EventDispatcherWorker {
    sender: SyncSender<WorkerMessage>,
}

static NEXT_THREAD_NUM: AtomicU64 = AtomicU64::new(1);

impl EventDispatcherWorker {
    pub fn new(db_path: PathBuf) -> Result<EventDispatcherWorker, EventDispatcherError> {
        Self::new_with_custom_queue_size(db_path, 1_000)
    }

    pub fn new_with_custom_queue_size(
        db_path: PathBuf,
        queue_size: usize,
    ) -> Result<EventDispatcherWorker, EventDispatcherError> {
        let (message_tx, message_rx) = sync_channel(queue_size);
        let (ready_tx, ready_rx) = channel();

        let thread_num = NEXT_THREAD_NUM.fetch_add(1, Ordering::SeqCst);

        thread::Builder::new()
            .name(format!("event-dispatcher-{thread_num}").to_string())
            .spawn(move || {
                let conn = match EventDispatcherDbConnection::new(&db_path) {
                    Ok(conn) => conn,
                    Err(err) => {
                        error!("Event Dispatcher Worker: Unable to open DB, terminating worker thread: {err}");
                        ready_tx.send(Err(err)).unwrap();
                        return;
                    }
                };

                if let Err(err) = ready_tx.send(Ok(())) {
                    // If the sending fails (i.e. the receiver has been dropped), that means a logic bug
                    // has been introduced to the code -- at time of writing, the main function is waiting
                    // for this message a few lines down, outside the thread closure.
                    // We log this, but we still start the loop.
                    error!(
                        "Event Dispatcher Worker: Unable to send ready state. This is a bug. {err}"
                    );
                }

                // this will run forever until the messaging channel is closed
                Self::main_thread_loop(conn, message_rx);
            })
            .unwrap();

        // note double question mark, deals with both the channel RecvError and whatever error
        // might be sent across that channel
        ready_rx.recv()??;

        Ok(EventDispatcherWorker { sender: message_tx })
    }

    /// Let the worker know that it should send the request that is stored in the DB under the given
    /// ID, and delete that DB entry once it's done.
    ///
    /// A successful result only means that the request was successfully enqueued, not that it was
    /// actually made. If you need to wait until the latter has happened, call `wait_until_complete()`
    /// on the returned `EventDispatcherResult`.
    ///
    /// The worker has a limited queue size (1000 by default). If the queue is already full, the
    /// call to `initiate_send()` will block until space has become available.
    pub fn initiate_send(
        &self,
        id: i64,
        disable_retries: bool,
        timeout_override: Option<Duration>,
    ) -> Result<EventDispatcherResult, EventDispatcherError> {
        let (sender, receiver) = channel();
        debug!("Event Dispatcher Worker: sending payload {id}");

        self.sender.send(WorkerMessage {
            task: WorkerTask::Payload {
                id,
                disable_retries,
                timeout_override,
            },
            completion: sender,
        })?;

        Ok(EventDispatcherResult { receiver })
    }

    #[cfg(test)]
    pub fn noop(&self) -> Result<EventDispatcherResult, EventDispatcherError> {
        let (sender, receiver) = channel();
        debug!("Event Dispatcher Worker: sending no-op");

        self.sender.send(WorkerMessage {
            task: WorkerTask::NoOp,
            completion: sender,
        })?;

        Ok(EventDispatcherResult { receiver })
    }

    fn main_thread_loop(conn: EventDispatcherDbConnection, message_rx: Receiver<WorkerMessage>) {
        // main loop of the thread -- get message from channel, grab data from DB, send request,
        // delete from DB, acknowledge
        loop {
            let Ok(WorkerMessage { task, completion }) = message_rx.recv() else {
                info!("Event Dispatcher Worker: channel closed, terminating worker thread.");
                return;
            };

            let WorkerTask::Payload {
                id,
                disable_retries,
                timeout_override,
            } = task
            else {
                // no-op -- just ack and move on
                debug!("Event Dispatcher Worker: doing no-op");
                let _ = completion.send(());
                continue;
            };

            debug!("Event Dispatcher Worker: doing payload {id}");

            // This will block forever if we were passed a non-existing ID. Don't do that.
            let mut payload = conn.get_payload_with_retry(id);

            // Deliberately not handling the error case of `duration_since()` -- if the `timestamp`
            // is *after* `now` (which should be extremely rare), the most likely reason is a *slight*
            // adjustment to the the system clock (e.g. NTP sync) that happened between storing the
            // entity and retrieving it, and that should be fine.
            // If there was a *major* adjustment, all bets are off anyway. You shouldn't mess with your
            // clock on a server running a node.
            if let Ok(age) = SystemTime::now().duration_since(payload.timestamp) {
                if age.as_secs() > 5 * 60 {
                    warn!(
                        "Event Dispatcher Worker: Event payload transmitting more than 5 minutes after event";
                        "age_ms" => age.as_millis(),
                        "id"=> id
                    );
                }
            }

            if let Some(timeout_override) = timeout_override {
                payload.request_data.timeout = timeout_override;
            }

            Self::make_http_request_and_delete_from_db(
                &payload.request_data,
                disable_retries,
                id,
                &conn,
            );

            // We're ignoring the result of this call -- if the requester has dropped the receiver
            // in the meantime, that's fine. That is the usual case of fire-and-forget calls.
            let _ = completion.send(());
        }
    }

    fn make_http_request_and_delete_from_db(
        data: &EventRequestData,
        disable_retries: bool,
        id: i64,
        conn: &EventDispatcherDbConnection,
    ) {
        let http_result = Self::make_http_request(data, disable_retries);

        if let Err(err) = http_result {
            // log but continue
            error!("EventDispatcher: dispatching failed"; "url" => data.url.clone(), "error" => ?err);
        }

        #[cfg(test)]
        if TEST_EVENT_OBSERVER_SKIP_RETRY.get() {
            warn!("Fault injection: skipping deletion of payload");
            return;
        }

        // We're deleting regardless of result -- if retries are disabled, that means
        // we're supposed to forget about it in case of failure. If they're not disabled,
        // then we wouldn't be here in case of failue, because `make_http_request` retries
        // until it's successful (with the exception of the above fault injection which
        // simulates a shutdown).
        let deletion_result = conn.delete_payload(id);

        if let Err(e) = deletion_result {
            error!(
                "Event observer: failed to delete pending payload from database";
                "error" => ?e
            );
        }
    }

    fn make_http_request(
        data: &EventRequestData,
        disable_retries: bool,
    ) -> Result<(), EventDispatcherError> {
        debug!(
            "Event dispatcher: Sending payload"; "url" => &data.url, "bytes" => data.payload_bytes.len()
        );

        let url = Url::parse(&data.url)
            .unwrap_or_else(|_| panic!("Event dispatcher: unable to parse {} as a URL", data.url));

        let host = url.host_str().expect("Invalid URL: missing host");
        let port = url.port_or_known_default().unwrap_or(80);
        let peerhost: PeerHost = format!("{host}:{port}")
            .parse()
            .unwrap_or(PeerHost::DNS(host.to_string(), port));

        let mut backoff = Duration::from_millis(100);
        let mut attempts: i32 = 0;
        // Cap the backoff at 3x the timeout
        let max_backoff = data.timeout.saturating_mul(3);

        loop {
            let mut request = StacksHttpRequest::new_for_peer(
                peerhost.clone(),
                "POST".into(),
                url.path().into(),
                HttpRequestContents::new().payload_json_bytes(Arc::clone(&data.payload_bytes)),
            )
            .unwrap_or_else(|_| panic!("FATAL: failed to encode infallible data as HTTP request"));
            request.add_header("Connection".into(), "close".into());
            match send_http_request(host, port, request, data.timeout) {
                Ok(response) => {
                    if response.preamble().status_code == 200 {
                        debug!(
                            "Event dispatcher: Successful POST"; "url" => %url
                        );
                        break;
                    } else {
                        error!(
                            "Event dispatcher: Failed POST"; "url" => %url, "response" => ?response.preamble()
                        );
                    }
                }
                Err(err) => {
                    warn!(
                        "Event dispatcher: connection or request failed to {host}:{port} - {err:?}";
                        "backoff" => ?backoff,
                        "attempts" => attempts
                    );
                    if disable_retries {
                        warn!("Observer is configured in disable_retries mode: skipping retry of payload");
                        return Err(err.into());
                    }
                    #[cfg(test)]
                    if TEST_EVENT_OBSERVER_SKIP_RETRY.get() {
                        warn!("Fault injection: skipping retry of payload");
                        return Err(err.into());
                    }
                }
            }

            sleep(backoff);
            let jitter: u64 = rand::thread_rng().gen_range(0..100);
            backoff = std::cmp::min(
                backoff.saturating_mul(2) + Duration::from_millis(jitter),
                max_backoff,
            );
            attempts = attempts.saturating_add(1);
        }

        Ok(())
    }
}
