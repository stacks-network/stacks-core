use async_std;
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
    let handle = thread::spawn(|| {
        let signer = signer::Signer::new();
        mainloop(signer, net);
    });

    // let thread finish
    handle.join().unwrap();
    Ok(())
}

fn mainloop(mut signer: Signer, net: net::Net) {
    info!("mainloop");
    loop {
        let message = net.next_message().r#type;
        signer.process(message);
    }
}
