use crate::signer;
use serde::Serialize;

pub struct Net {}
pub struct Message {
    pub r#type: signer::MessageTypes,
}

impl Net {
    pub fn new() -> Net {
        Net {}
    }

    pub fn next_message(&self) -> Message {
        Message {
            r#type: signer::MessageTypes::Join,
        }
    }

    pub fn send_message<S: Serialize>(&self, _msg: S) {}
}
