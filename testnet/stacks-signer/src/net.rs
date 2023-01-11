use crate::config::Config;
use crate::signer;
use slog::slog_info;
use stacks_common::info;
use std::fmt::{Debug, Formatter};
use ureq::Response;

pub struct HttpNet {
    _highwater_msg_idx: usize,
    stacks_node_url: String,
}
pub trait Net {
    fn listen(&self);
    fn poll(&self) -> Result<Response, ureq::Error>;
    fn next_message(&self) -> Message;
    fn send_message(&self, _msg: Message);
}

#[derive(Debug)]
pub struct Message {
    pub r#type: signer::MessageTypes,
}

impl Debug for signer::MessageTypes {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        write!(f, "Message Type: {:?}", self)
    }
}

impl HttpNet {
    pub fn new(config: &Config) -> Self {
        HttpNet {
            _highwater_msg_idx: 0,
            stacks_node_url: config.stacks_node_url.to_owned(),
        }
    }
}

impl Net for HttpNet {
    fn listen(&self) {}

    fn poll(&self) -> Result<Response, ureq::Error> {
        ureq::get(&self.stacks_node_url).call()
    }

    fn next_message(&self) -> Message {
        match self.poll() {
            Ok(_msg) => {
                // TODO: deserialize msg
                Message {
                    r#type: signer::MessageTypes::Join,
                }
            }
            Err(e) => {
                panic!("E: {} U: {}", e, self.stacks_node_url)
            }
        }
    }

    fn send_message(&self, _msg: Message) {
        let req = ureq::post(&self.stacks_node_url);
        match req.call() {
            Ok(_) => {}
            Err(_) => {
                info!("post failed to {}", self.stacks_node_url)
            }
        }
    }
}
