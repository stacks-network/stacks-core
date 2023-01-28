use std::sync::mpsc;
use std::sync::mpsc::{Receiver, Sender};
use std::thread::spawn;
use std::{thread, time};

use clap::Parser;
use slog::slog_info;

use stacks_common::info;
use stacks_signer::config::{Cli, Config};
use stacks_signer::net::{HttpNet, HttpNetListen, Message, Net, NetListen};
use stacks_signer::signing_round::SigningRound;

fn main() {
    let mut config = Config::from_file("conf/stacker.toml").unwrap();
    let cli = Cli::parse();
    config.merge(&cli); // merge command line options
    info!(
        "{} signer id #{}",
        stacks_signer::version(),
        config.signer.frost_id
    ); // sign-on message

    let net: HttpNet = HttpNet::new(config.common.stacks_node_url.clone());

    // thread coordination
    let (tx, rx): (Sender<Message>, Receiver<Message>) = mpsc::channel();

    // start p2p sync
    let id = config.signer.frost_id;
    let net_queue = HttpNetListen::new(net.clone(), vec![]);
    spawn(move || poll_loop(net_queue, tx, id));

    // listen to p2p messages
    main_loop(&config, &net, rx);
}

fn poll_loop(mut net: HttpNetListen, tx: Sender<Message>, id: u64) {
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

fn main_loop(config: &Config, net: &HttpNet, rx: Receiver<Message>) {
    let signer_id = config.signer.frost_id;
    let party_ids = vec![(signer_id * 2 - 1) as usize, (signer_id * 2) as usize]; // take two party/reward slots based on id
    let mut round = SigningRound::new(
        config.common.minimum_parties,
        config.common.total_parties,
        signer_id,
        party_ids,
    );

    loop {
        let inbound = rx.recv().unwrap(); // blocking
        let outbounds = round.process(inbound.msg).unwrap();
        for out in outbounds {
            let msg = Message {
                msg: out,
                sig: [0; 32],
            };
            net.send_message(msg).unwrap();
        }
    }
}
