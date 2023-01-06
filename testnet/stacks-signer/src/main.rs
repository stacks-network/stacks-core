use stacks_signer::config::Config;
use stacks_signer::net::{Message, Net};
use stacks_signer::signer::{MessageTypes, Signer};
use stacks_signer::{logger, net, signer};
use std::thread::spawn;
use tracing::info;

fn main() {
    logger::setup();
    let config = Config::from_file("conf/stacker.toml").unwrap();
    info!("{}", stacks_signer::version());

    let net = net::Net::new(&config);

    // start p2p sync
    spawn(|| loop {
        let message = net.next_message();
        match message.r#type{
            MessageTypes::Join => {
                // TODO: process Join msg
            }
        }
    });

    mainloop(&config, net);
}

fn mainloop(config: &Config, net: net::Net) {
    info!("mainloop");
    let signer = signer::Signer::new();

    net.listen();
}
