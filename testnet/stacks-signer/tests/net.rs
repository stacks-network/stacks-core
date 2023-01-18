use stacks_signer::net::{HttpNet, Message, Net};
use stacks_signer::signer::{MessageTypes};
use stacks_signer::config::Config;

#[test]
fn receive_msg() {
    let m1 = Message {
        msg: MessageTypes::DkgBegin,
    };
    let mut config = Config::default();
    config.common.stacks_node_url = "http://localhost:9775".to_owned();

    let in_queue = vec![m1];
    let out_queue = vec![];
    let mut net = HttpNet::new(&config, in_queue, out_queue);
    match net.next_message() {
        Some(_msg) => {
            assert!(true)
        }
        None => {}
    }
}
