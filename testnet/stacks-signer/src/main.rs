use tracing::info;
use stacks_signer::config::Config;
use stacks_signer::{logger, signer, net};
use std::thread;

fn main() {
    logger::setup();
    let _config = Config::from_file("conf/stacker.toml").unwrap();
    info!("{}", stacks_signer::version());

    let net = net::Net::new();

    // start p2p sync
    let handle = thread::spawn(|| {
        let signer = signer::Signer::new();
        signer.mainloop(net)
    });

    // let thread finish
    handle.join().unwrap();
}
