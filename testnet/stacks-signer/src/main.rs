use slog::slog_info;
use stacks_common::info;
use stacks_signer::config::Config;
use stacks_signer::net::{HttpNet, Message, Net};
use stacks_signer::signer::{MessageTypes, Signer};
use std::sync::mpsc;
use std::sync::mpsc::{Receiver, Sender};
use std::thread::spawn;

fn main() {
    let config = Config::from_file("conf/stacker.toml").unwrap();
    info!("{}", stacks_signer::version());

    let mut net: HttpNet = HttpNet::new(&config, vec![]);

    // start p2p sync
    let (tx, rx): (Sender<Message>, Receiver<Message>) = mpsc::channel();
    spawn(move || loop {
        let message = Message {
            msg: MessageTypes::Join {},
        };
        tx.send(message).unwrap();
        let _m = net.next_message();
    });

    mainloop(&config, rx);
}

fn mainloop(_config: &Config, rx: Receiver<Message>) {
    info!("mainloop");
    let _signer = Signer::new();

    for message in rx.iter() {
        info!("received message {:?}", message);
    }
}
