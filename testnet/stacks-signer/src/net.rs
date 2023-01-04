use crate::signer;
use serde::Serialize;
use std::error::Error;
use std::iter::Map;
use tracing::info;
use warp::{Filter, Future, Server};

pub struct Net {
    _highwater_msg_idx: usize,
}

pub struct Message {
    pub r#type: signer::MessageTypes,
}

impl Net {
    pub fn new() -> Net {
        Net {
            _highwater_msg_idx: 0,
        }
    }

    pub async fn listen(&self) {
        let routes = warp::path("p2p")
            .and(warp::path::param::<String>())
            .map(|name| {
                info!("{}", name);
                format!("OK")
            });
        warp::serve(routes).run(([127, 0, 0, 1], 3030)).await
    }

    pub fn next_message(&self) -> Message {
        Message {
            r#type: signer::MessageTypes::Join,
        }
    }

    pub fn send_message<S: Serialize>(&self, _msg: S) {}
}
