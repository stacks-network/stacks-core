use stacks_signer::config::Config;
use stacks_signer::net::{Message};
use stacks_signer::signer::{MessageTypes};
use stacks_signer::{logger, net, signer};
use std::thread::spawn;
use tracing::info;

fn main() {
    logger::setup();
    let config = Config::from_file("conf/stacker.toml").unwrap();
    info!("{}", stacks_signer::version());

    let net = net::Net::new(&config);

    // start p2p sync
    let tx = net.tx.clone();
    spawn(move || loop {
        let message = Message { r#type: MessageTypes::Join {}};
            // net.next_message();
        tx.send(message).unwrap();
    });

    mainloop(&config, net);
}

fn mainloop(_config: &Config, net: net::Net) {
    info!("mainloop");
    let _signer = signer::Signer::new();

    for message in net.rx.iter() {
        info!("received message {:?}", message);
    }
}
