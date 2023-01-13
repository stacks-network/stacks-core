use crate::config::Config;
use crate::signer;
use slog::{slog_info, slog_warn};
use stacks_common::{info, warn};
use std::fmt::Debug;

pub struct HttpNet {
    pub stacks_node_url: String,
    msg_queue: Vec<Message>,
}

pub trait Net {
    fn listen(&self);
    fn poll(&mut self);
    fn next_message(&mut self) -> Option<Message>;
    fn send_message(&self, _msg: Message);
}

#[derive(Debug)]
pub struct Message {
    pub msg: signer::MessageTypes,
}

impl HttpNet {
    pub fn new(config: &Config, new_q: Vec<Message>) -> Self {
        HttpNet {
            stacks_node_url: config.stacks_node_url.to_owned(),
            msg_queue: new_q,
        }
    }
}

impl Net for HttpNet {
    fn listen(&self) {}

    fn poll(&mut self) {
        match ureq::get(&self.stacks_node_url).call() {
            Ok(_msg) => {
                // TODO: deserialize msg
                let msg = Message {
                    msg: signer::MessageTypes::Join,
                };
                self.msg_queue.push(msg);
            }
            Err(e) => {
                warn!("{} U: {}", e, self.stacks_node_url)
            }
        };
    }

    fn next_message(&mut self) -> Option<Message> {
        self.msg_queue.pop()
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
