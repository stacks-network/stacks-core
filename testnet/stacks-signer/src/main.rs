use stacks_signer::config::Config;
use stacks_signer::signer::Signer;
use stacks_signer::{logger, net, signer};
use tokio::signal;
use tracing::info;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    logger::setup();
    let _config = Config::from_file("conf/stacker.toml").unwrap();
    info!("{}", stacks_signer::version());

    let net = net::Net::new().await?;

    // start p2p sync
    let signer = signer::Signer::new();
    mainloop(signer, net).await;

    Ok(())
}

async fn mainloop(_signer: Signer, net: net::Net) {
    info!("mainloop");
    tokio::select! {
    _ = signal::ctrl_c() => {info!("stop!")},
    }
    info!("after signal");
}
