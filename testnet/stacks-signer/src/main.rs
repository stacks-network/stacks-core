use async_std;
use libp2p::futures::StreamExt;
use stacks_signer::config::Config;
use stacks_signer::signer::Signer;
use stacks_signer::{logger, net, signer};
use tracing::info;

#[async_std::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    logger::setup();
    let _config = Config::from_file("conf/stacker.toml").unwrap();
    info!("{}", stacks_signer::version());

    let net = net::Net::new().await?;

    // start p2p sync
    let signer = signer::Signer::new();
    mainloop(signer, Box::new(net)).await;

    Ok(())
}

async fn mainloop(_signer: Signer, mut net: Box<net::Net>) {
    info!("mainloop");
    loop {
        libp2p::futures::select! {
        event = net.swarm.select_next_some() => {
                info!("{:?}", event);
                match event {
                    libp2p::swarm::SwarmEvent::NewListenAddr { address, .. } => {
                        println!("Listening on {address:?}");
                    },
                    libp2p::swarm::SwarmEvent::Behaviour(libp2p::floodsub::FloodsubEvent::Message(message)) => {
                        info!(
                        "Received: '{:?}' from {:?}",
                        String::from_utf8_lossy(&message.data),
                        message.source
                        );
                        //signer.process(&message.data);
                    },
                    _ => ()
                }
            }
        }
    }
}
