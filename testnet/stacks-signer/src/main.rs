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

fn main() {
    let mut config = Config::from_file("conf/stacker.toml").unwrap();
    config.merge(Cli::parse());
    info!("{}", stacks_signer::version());

    let net: HttpNet = HttpNet::new(&config, vec![], vec![]);

    // thread coordination
    let (tx, rx): (Sender<Message>, Receiver<Message>) = mpsc::channel();

    // start p2p sync
    spawn(move || poll_loop(net, tx));
    main_loop(&config, net, rx);
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

fn main_loop(config: &Config, net: HttpNet, rx: Receiver<Message>) {
    let mut signer = SigningRound::new(
        config.signer.frost_id,
        config.common.minimum_signers,
        config.common.total_signers,
    );
    signer.reset();

    loop {
        let inbound = rx.recv().unwrap();
        info!("received message {:?}", inbound);
        let outbounds = signer.process(inbound.msg).unwrap();
        for out in outbounds {
            net.send_message(out.into())
        }
    }
}
