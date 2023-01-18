use clap::Parser;
use slog::slog_info;
use stacks_common::info;
use stacks_signer::config::{Cli, Config};
use stacks_signer::net::{HttpNet, Message, Net};
use stacks_signer::signer::Signer;
use std::sync::mpsc;
use std::sync::mpsc::{Receiver, Sender};
use std::thread::spawn;
use std::{thread, time};

fn main() {
    let mut config = Config::from_file("conf/stacker.toml").unwrap();
    config.merge(Cli::parse());
    info!("{}", stacks_signer::version());

    let net: HttpNet = HttpNet::new(&config, vec![], vec![]);

    // thread coordination
    let (tx, rx): (Sender<Message>, Receiver<Message>) = mpsc::channel();

    // start p2p sync
    spawn(move || poll_loop(net, tx));
    main_loop(&config, rx);
}

fn poll_loop(mut net: HttpNet, tx: Sender<Message>) {
    loop {
        info!("polling {}", net.stacks_node_url);
        net.poll();
        match net.next_message() {
            None => {}
            Some(m) => {
                info!("{:?}", m);
                tx.send(m).unwrap();
            }
        };
        thread::sleep(time::Duration::from_millis(1000));
    }
}

fn main_loop(config: &Config, rx: Receiver<Message>) {
    let mut signer = Signer::new();
    signer.reset(config.common.minimum_signers, config.common.total_signers);

    loop {
        let message = rx.recv().unwrap();
        info!("received message {:?}", message);
        signer.process(message.msg);
    }
}
