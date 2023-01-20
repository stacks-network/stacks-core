use clap::Parser;
use slog::slog_info;
use stacks_common::info;
use stacks_signer::config::{Cli, Config};
use stacks_signer::net::{HttpNet, Message, Net};
use stacks_signer::signing_round::SigningRound;
use std::sync::mpsc;
use std::sync::mpsc::{Receiver, Sender};
use std::thread::spawn;
use std::{thread, time};
use stacks_signer::net;

fn main() {
    let mut config = Config::from_file("conf/stacker.toml").unwrap();
    config.merge(Cli::parse()); // merge command line options
    info!("{}", stacks_signer::version()); // sign-on message

    let net: HttpNet = HttpNet::new(&config, vec![]);

    // thread coordination
    let (tx, rx): (Sender<Message>, Receiver<Message>) = mpsc::channel();

    // start p2p sync
    spawn(move || poll_loop(net, tx));

    // listen to p2p messages
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
    let mut signer = SigningRound::new(
        config.signer.frost_id,
        config.common.minimum_signers,
        config.common.total_signers,
    );
    signer.reset();

    loop {
        let inbound = rx.recv().unwrap(); // blocking
        info!("received message {:?}", inbound);
        let outbounds = signer.process(inbound.msg).unwrap();
        for out in outbounds {
            net::send_message(&config.common.stacks_node_url, out.into())
        }
    }
}
