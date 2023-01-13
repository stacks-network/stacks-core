use slog::slog_info;
use stacks_common::info;
use stacks_signer::config::Config;
use stacks_signer::net::{HttpNet, Message, Net};
use stacks_signer::signer::{Signer};
use std::sync::mpsc;
use std::sync::mpsc::{Receiver, Sender};
use std::thread::spawn;
use std::{thread, time};

fn main() {
    let config = Config::from_file("conf/stacker.toml").unwrap();
    info!("{}", stacks_signer::version());

    let net: HttpNet = HttpNet::new(&config, vec![]);

    // start p2p sync
    let (tx, rx): (Sender<Message>, Receiver<Message>) = mpsc::channel();
    poll_loop(net, tx);
    main_loop(&config, rx);
}

fn poll_loop(mut net: HttpNet, tx: Sender<Message>) {
    spawn(move || loop {
        info!("polling {}", net.stacks_node_url);
        net.poll();
        match net.next_message() {
            None => {}
            Some(m) => { tx.send(m).unwrap(); }
        };
        thread::sleep(time::Duration::from_millis(1000));
    });
}

fn main_loop(_config: &Config, rx: Receiver<Message>) {
    info!("mainloop");
    let _signer = Signer::new();

    //for message in rx.iter() {
    loop {
        let message = rx.recv().unwrap();
        info!("received message {:?}", message);
    }
}
