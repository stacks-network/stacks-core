use crate::config::Config;
use crate::signer;
use serde::Serialize;
use ureq::{request, Error, Response};

pub struct Net {
    _highwater_msg_idx: usize,
    stacks_node_url: String,
}

pub struct Message {
    pub r#type: signer::MessageTypes,
}

impl Net {
    pub fn new(config: &Config) -> Net {
        Net {
            _highwater_msg_idx: 0,
            stacks_node_url: config.stacks_node_url.to_owned(),
        }
    }

    pub fn listen(&self) {}

    pub fn poll(&self) -> Result<Response, ureq::Error> {
        ureq::get(&self.stacks_node_url).call()
    }

    pub fn next_message(&self) -> Message {
        match self.poll() {
            Ok(_msg) => {
                // TODO: deserialize msg
                Message {
                    r#type: signer::MessageTypes::Join,
                }
            }
            Err(_) => { panic!()}
        }
    }

    pub fn send_message<S: Serialize>(&self, _msg: S) {}
}
