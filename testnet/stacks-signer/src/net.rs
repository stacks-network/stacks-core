use crate::signer;
use serde::Serialize;
use std::error::Error;
use tracing::info;
use warp::Filter;

pub struct Net {
    _highwater_msg_idx: usize,
    pub socket: usize,
}

pub struct Message {
    pub r#type: signer::MessageTypes,
}

impl Net {
    pub async fn new() -> Result<Net, Box<dyn Error>> {
        // GET /hello/warp => 200 OK with body "Hello, warp!"
        let hello = warp::path!("hello" / String).map(|name| format!("Hello, {}!", name));
        warp::serve(hello).run(([127, 0, 0, 1], 3030));
        Ok(Net {
            _highwater_msg_idx: 0,
            socket: 0,
        })
    }

    pub fn next_message(&self) -> Message {
        Message {
            r#type: signer::MessageTypes::Join,
        }
    }

    pub fn send_message<S: Serialize>(&self, _msg: S) {}
}
