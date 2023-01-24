use std::fmt::Debug;

use serde::{Deserialize, Serialize};
use slog::{slog_info, slog_warn};

use stacks_common::{info, warn};

use crate::signing_round;

// Message is the format over the wire and a place for future metadata such as sender_id
#[derive(Serialize, Deserialize, Debug)]
pub struct Message {
    pub msg: signing_round::MessageTypes,
    pub sig: [u8; 32],
}

pub struct HttpNet {
    pub stacks_node_url: String,
    in_queue: Vec<Message>,
}

impl HttpNet {
    pub fn new(stacks_node_url: String, in_q: Vec<Message>) -> Self {
        HttpNet {
            stacks_node_url,
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
        info!("poll {}", url);
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

pub fn id_to_sig_bytes(id: usize) -> [u8; 32] {
    let mut bytes = id.to_le_bytes().to_vec();
    bytes.extend_from_slice(&[0; 32 - 8]);
    bytes.try_into().unwrap()
}
