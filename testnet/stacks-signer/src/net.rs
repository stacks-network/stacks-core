use crate::config::Config;
use crate::signing_round;
use crate::signing_round::MessageTypes;
use serde::{Deserialize, Serialize};
use slog::{slog_debug, slog_info, slog_warn};
use stacks_common::{debug, info, warn};
use std::fmt::Debug;

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
    fn poll(&mut self);
    fn next_message(&mut self) -> Option<Message>;
}

impl Net for HttpNet {
    fn listen(&self) {}

    fn poll(&mut self) {
        match ureq::get(&self.stacks_node_url).call() {
            Ok(response) => {
                match response.status() {
                    200 => {
                        debug!("get/poll returned {:?}", response);
                        match bincode::deserialize_from::<_, Message>(response.into_reader()) {
                            Ok(msg) => {
                                info!("{:?}", &msg);
                            }
                            Err(_e) => {}
                        };
                    }
                    _ => {}
                };
                //self.msg_queue.push(msg);
            }
            Err(e) => {
                warn!("{} U: {}", e, self.stacks_node_url)
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
            debug!("sent {} bytes {:?}", bytes.len(), &response)
        }
        Err(e) => {
            info!("post failed to {} {}", url, e)
        }
    }
}
