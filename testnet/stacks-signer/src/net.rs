use crate::config::Config;
use crate::signer;
use slog::{slog_info, slog_warn, slog_debug};
use stacks_common::{info, warn, debug};
use std::fmt::Debug;

pub struct HttpNet {
    pub stacks_node_url: String,
    in_queue: Vec<Message>,
    out_queue: Vec<Message>,
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
    pub fn new(config: &Config, in_q: Vec<Message>, out_q: Vec<Message>) -> Self {
        HttpNet {
            stacks_node_url: config.stacks_node_url.to_owned(),
            in_queue: in_q,
            out_queue: out_q,
        }
    }
}

impl Net for HttpNet {
    fn listen(&self) {}

    fn poll(&mut self) {
        match ureq::get(&self.stacks_node_url).call() {
            Ok(response) => {
                match response.status() {
                    200 => {
                        debug!("{:?}", response);
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
