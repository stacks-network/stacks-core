use std::sync::mpsc;
use std::sync::mpsc::{Receiver, Sender};
use std::thread::spawn;
use std::{thread, time};

use clap::Parser;
use slog::slog_info;

use stacks_common::info;
use stacks_signer::config::{Cli, Config};
use stacks_signer::net;
use stacks_signer::net::{HttpNet, Message, Net};
use stacks_signer::signing_round::{DkgBegin, MessageTypes, SigningRound};

fn main() {
    let mut config = Config::from_file("conf/stacker.toml").unwrap();
    let cli = Cli::parse();
    config.merge(&cli); // merge command line options
    info!(
        "{} signer id #{}",
        stacks_signer::version(),
        config.signer.frost_id
    ); // sign-on message

    let net: HttpNet = HttpNet::new(&config, vec![]);

    // thread coordination
    let (tx, rx): (Sender<Message>, Receiver<Message>) = mpsc::channel();

    // start p2p sync
    let id = config.signer.frost_id;
    spawn(move || poll_loop(net, tx, id));

    // temporary fill-in for a coordinator
    if cli.start {
        let config2 = config.clone();
        spawn(move || start_round(&config2));
    }

    // listen to p2p messages
    main_loop(&config, rx);
}

fn poll_loop(mut net: HttpNet, tx: Sender<Message>, id: usize) {
    loop {
        net.poll(id);
        match net.next_message() {
            None => {}
            Some(m) => {
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
        info!("received {:?}", inbound);
        let outbounds = signer.process(inbound.msg).unwrap();
        for out in outbounds {
            net::send_message(&config.common.stacks_node_url, out.into())
        }
    }
}

fn start_round(config: &Config) {
    info!("Starting signature round (--start)");
    let dkg_start = MessageTypes::DkgBegin(DkgBegin { id: [0; 32] });
    net::send_message(&config.common.stacks_node_url, dkg_start.into());
}
