use stacks_signer::config::Config;
use stacks_signer::net::{HttpNet, Message, Net};
use stacks_signer::signer::MessageTypes;
use stacks_signer::{logger, net, signer};
use std::sync::mpsc;
use std::sync::mpsc::{Receiver, Sender};
use std::thread::spawn;
use tracing::info;

fn main() {
    logger::setup();
    let config = Config::from_file("conf/stacker.toml").unwrap();
    info!("{}", stacks_signer::version());

    let net: HttpNet = HttpNet::new(&config);

    // start p2p sync
    let (tx, rx): (Sender<Message>, Receiver<Message>) = mpsc::channel();
    spawn(move || loop {
        let message = Message {
            r#type: MessageTypes::Join {},
        };
        let _m = net.next_message();
        tx.send(message).unwrap();
    });

    mainloop(&config, rx);
}

fn mainloop(_config: &Config, rx: Receiver<Message>) {
    info!("mainloop");
    let _signer = signer::Signer::new();

    for message in rx.iter() {
        info!("received message {:?}", message);
    }
}
