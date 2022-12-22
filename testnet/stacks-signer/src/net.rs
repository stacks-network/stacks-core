use crate::signer;
use async_std::io::Error;
use libp2p;
use serde::Serialize;
use tracing::info;

type Transport =
    libp2p::core::transport::Boxed<(libp2p::PeerId, libp2p::core::muxing::StreamMuxerBox)>;

pub struct Net {
    _local_key: libp2p::identity::Keypair,
    pub swarm: libp2p::Swarm<libp2p::floodsub::Floodsub>,
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
        let floodsub_topic = libp2p::floodsub::Topic::new("chat");
        let mut floodsub = libp2p::floodsub::Floodsub::new(local_peer_id);
        floodsub.subscribe(floodsub_topic);
        let mut swarm = libp2p::Swarm::with_threadpool_executor(transport, floodsub, local_peer_id);
        swarm
            .listen_on("/ip4/0.0.0.0/tcp/0".parse().unwrap())
            .unwrap();
        Ok(Net {
            _local_key: local_key,
            swarm: swarm,
        })
    }

    pub fn next_message(&self) -> Message {
        Message {
            r#type: signer::MessageTypes::Join,
        }
    }

    pub fn send_message<S: Serialize>(&self, _msg: S) {}
}
