use crate::signer;

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
}
