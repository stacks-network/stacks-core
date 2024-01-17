use rand_core::{OsRng, RngCore};
use serde_derive::{Deserialize, Serialize};

/// What is written to the ping slot.
#[derive(Serialize, Deserialize, Clone, Debug, PartialEq)]
pub enum Packet {
    /// Outgoing
    Ping(Ping),
    /// Incoming
    Pong(Pong),
}

#[derive(Serialize, Deserialize, PartialEq, Debug, Clone)]
/// A ping in a slot means someone has requested you to push a Pong into your slot.
pub struct Ping {
    id: u64,
}
#[derive(Serialize, Deserialize, PartialEq, Debug, Clone)]
/// A pong in a slot means someone has responded to an RTT request.
pub struct Pong {
    id: u64,
}

impl From<Pong> for Packet {
    fn from(value: Pong) -> Self {
        Self::Pong(value)
    }
}

impl From<Ping> for Packet {
    fn from(value: Ping) -> Self {
        Self::Ping(value)
    }
}

impl Ping {
    /// Uniquely identify the RTT request
    pub fn new() -> Self {
        Ping {
            id: OsRng.next_u64(),
        }
    }

    /// Pongs receive their id from a ping.
    pub fn pong(&self) -> Pong {
        Pong { id: self.id }
    }

    ///
    pub fn id(&self) -> u64 {
        self.id
    }
}

impl Pong {
    ///
    pub fn id(&self) -> u64 {
        self.id
    }
}

#[cfg(test)]
mod tests {

    use super::*;
    use crate::SignerMessage;

    #[test]
    fn same_slot_for_ping_pong() {
        let ping_packet: SignerMessage = Ping::new().into();
        assert_eq!(
            ping_packet.slot_id(1),
            SignerMessage::from(Pong { id: 2 }).slot_id(1)
        );
    }
}
