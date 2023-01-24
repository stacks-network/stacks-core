use std::fmt::Debug;

use serde::{Deserialize, Serialize};
use slog::{slog_debug, slog_info, slog_warn};

use stacks_common::{debug, info, warn};

use crate::config::Config;
use crate::signing_round;
use crate::signing_round::MessageTypes;

// Message is the format over the wire and a place for future metadata such as sender_id
#[derive(Serialize, Deserialize, Debug)]
pub struct Message {
    pub msg: signing_round::MessageTypes,
}

impl From<MessageTypes> for Message {
    fn from(value: MessageTypes) -> Self {
        Message { msg: value }
    }
}

pub struct HttpNet {
    pub stacks_node_url: String,
    in_queue: Vec<Message>,
}

impl HttpNet {
    pub fn new(config: &Config, in_q: Vec<Message>) -> Self {
        HttpNet {
            stacks_node_url: config.common.stacks_node_url.to_owned(),
            in_queue: in_q,
        }
    }
}

pub trait Net {
    fn listen(&self);
    fn poll(&mut self, id: usize);
    fn next_message(&mut self) -> Option<Message>;
}

impl Net for HttpNet {
    fn listen(&self) {}

    fn poll(&mut self, id: usize) {
        let url = url_with_id(&self.stacks_node_url, id);
        match ureq::get(&url).call() {
            Ok(response) => {
                match response.status() {
                    200 => {
                        match bincode::deserialize_from::<_, Message>(response.into_reader()) {
                            Ok(msg) => {
                                info!("received {:?}", &msg);
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
}

pub fn send_message(url: &str, msg: Message) {
    let req = ureq::post(url);
    let bytes = bincode::serialize(&msg).unwrap();
    match req.send_bytes(&bytes[..]) {
        Ok(response) => {
            info!("sent {} bytes {:?} to {}", bytes.len(), &response, url)
        }
        Err(e) => {
            info!("post failed to {} {}", url, e)
        }
    }
}

fn url_with_id(base: &str, id: usize) -> String {
    let mut url = base.to_owned();
    url.push_str(&format!("?id={}", id));
    url
}
