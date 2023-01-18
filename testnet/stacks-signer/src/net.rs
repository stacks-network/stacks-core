use crate::config::Config;
use crate::signer;
use serde::{Deserialize, Serialize};
use slog::{slog_debug, slog_info, slog_warn};
use stacks_common::{debug, info, warn};
use std::fmt::Debug;

pub struct HttpNet {
    pub stacks_node_url: String,
    in_queue: Vec<Message>,
    _out_queue: Vec<Message>,
}

pub trait Net {
    fn listen(&self);
    fn poll(&mut self);
    fn next_message(&mut self) -> Option<Message>;
    fn send_message(&self, _msg: Message);
}

#[derive(Serialize, Deserialize, Debug)]
pub struct Message {
    pub msg: signer::MessageTypes,
}

impl HttpNet {
    pub fn new(config: &Config, in_q: Vec<Message>, out_q: Vec<Message>) -> Self {
        HttpNet {
            stacks_node_url: config.stacks_node_url.to_owned(),
            in_queue: in_q,
            _out_queue: out_q,
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

    fn send_message(&self, msg: Message) {
        let req = ureq::post(&self.stacks_node_url);
        let bytes = bincode::serialize(&msg).unwrap();
        match req.send_bytes(&bytes[..]) {
            Ok(response) => {
                debug!("sent {} bytes {:?}", bytes.len(), &response)
            }
            Err(e) => {
                info!("post failed to {} {}", self.stacks_node_url, e)
            }
        }
    }
}
