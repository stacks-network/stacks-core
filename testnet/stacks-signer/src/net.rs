use crate::signer;
use async_std::io::Error;
use libp2p;
use serde::Serialize;
use tracing::info;

type Transport =
    libp2p::core::transport::Boxed<(libp2p::PeerId, libp2p::core::muxing::StreamMuxerBox)>;

pub struct Net {
    _local_key: libp2p::identity::Keypair,
    _transport: Transport,
}

pub struct Message {
    pub r#type: signer::MessageTypes,
}

impl Net {
    pub async fn new() -> Result<Net, Error> {
        let local_key = libp2p::identity::Keypair::generate_ed25519();
        let local_peer_id = libp2p::PeerId::from(local_key.public());
        info!("Local peer id: {local_peer_id:?}");
        let transport = libp2p::development_transport(local_key.clone()).await?;
        Ok(Net {
            _local_key: local_key,
            _transport: transport,
        })
    }

    pub fn next_message(&self) -> Message {
        Message {
            r#type: signer::MessageTypes::Join,
        }
    }

    pub fn send_message<S: Serialize>(&self, _msg: S) {}
}
