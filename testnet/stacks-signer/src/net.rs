use std::fmt::Debug;

use serde::{Deserialize, Serialize};
use slog::{slog_debug, slog_info, slog_warn};

use stacks_common::{debug, info, warn};

use crate::signing_round;

// Message is the format over the wire
#[derive(Serialize, Deserialize, Debug)]
pub struct Message {
    pub msg: signing_round::MessageTypes,
    pub sig: [u8; 32],
}

// Http listen/poll with queue (requires mutable access, is configured by passing in HttpNet)
pub struct HttpNetListen {
    pub net: HttpNet,
    in_queue: Vec<Message>,
}

impl HttpNetListen {
    pub fn new(net: HttpNet, in_queue: Vec<Message>) -> Self {
        HttpNetListen { net, in_queue }
    }
}

// Http send (does not require mutable access, can be cloned to pass to threads)
#[derive(Clone)]
pub struct HttpNet {
    pub stacks_node_url: String,
}

impl HttpNet {
    pub fn new(stacks_node_url: String) -> Self {
        HttpNet { stacks_node_url }
    }
}

// these functions manipulate the inbound message queue
pub trait NetListen {
    type Error: Debug;

    fn listen(&self);
    fn poll(&mut self, id: u64);
    fn next_message(&mut self) -> Option<Message>;
    fn send_message(&self, msg: Message) -> Result<(), Self::Error>;
}

impl NetListen for HttpNetListen {
    type Error = HttpNetError;

    fn listen(&self) {}

    fn poll(&mut self, id: u64) {
        let url = url_with_id(&self.net.stacks_node_url, id);
        debug!("poll {}", url);
        match ureq::get(&url).call() {
            Ok(response) => {
                match response.status() {
                    200 => {
                        match bincode::deserialize_from::<_, Message>(response.into_reader()) {
                            Ok(msg) => {
                                debug!("received {:?}", msg);
                                self.in_queue.push(msg);
                            }
                            Err(_e) => {}
                        };
                    }
                    _ => {}
                };
            }
            Err(e) => {
                warn!("{} U: {}", e, url)
            }
        };
    }
    fn next_message(&mut self) -> Option<Message> {
        self.in_queue.pop()
    }

    // pass-thru to immutable net function
    fn send_message(&self, msg: Message) -> Result<(), Self::Error> {
        self.net.send_message(msg)
    }
}

// for threads that only send data, use immutable Net
pub trait Net {
    type Error: Debug;

    fn send_message(&self, msg: Message) -> Result<(), Self::Error>;
}

impl Net for HttpNet {
    type Error = HttpNetError;

    fn send_message(&self, msg: Message) -> Result<(), Self::Error> {
        let req = ureq::post(&self.stacks_node_url);
        let bytes = bincode::serialize(&msg)?;
        let result = req.send_bytes(&bytes[..]);

        match result {
            Ok(response) => {
                debug!(
                    "sent {:?} {} bytes {:?} to {}",
                    &msg.msg,
                    bytes.len(),
                    &response,
                    self.stacks_node_url
                )
            }
            Err(e) => {
                info!("post failed to {} {}", self.stacks_node_url, e);
                return Err(e.into());
            }
        };

        Ok(())
    }
}

#[derive(thiserror::Error, Debug)]
pub enum HttpNetError {
    #[error("Serialization failed: {0}")]
    SerializationError(#[from] bincode::Error),

    #[error("Network error: {0}")]
    NetworkError(#[from] ureq::Error),
}

fn url_with_id(base: &str, id: u64) -> String {
    let mut url = base.to_owned();
    url.push_str(&format!("?id={}", id));
    url
}
