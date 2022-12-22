use async_std;
use libp2p::futures::StreamExt;
use stacks_signer::config::Config;
use stacks_signer::signer::Signer;
use stacks_signer::{logger, net, signer};
use std::thread;
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

async fn mainloop(mut signer: Signer, mut net: Box<net::Net>) {
    info!("mainloop");
    loop {
        libp2p::futures::select! {
                    event = net.swarm.select_next_some() => match event {
                _ => todo!()
            }
        }
        let message = net.next_message().r#type;
        signer.process(message);
    }
}
