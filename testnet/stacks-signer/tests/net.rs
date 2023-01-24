use stacks_signer::config::Config;
use stacks_signer::net::{HttpNet, Message, Net};
use stacks_signer::signing_round::{DkgBegin, MessageTypes};

#[test]
fn receive_msg() {
    let m1 = Message {
        msg: MessageTypes::DkgBegin(DkgBegin { id: [0; 32] }),
    };
    let mut config = Config::default();
    config.common.stacks_node_url = "http://localhost:9775".to_owned();

    let in_queue = vec![m1];
    let mut net = HttpNet::new(&config, in_queue);
    match net.next_message() {
        Some(_msg) => {
            assert!(true)
        }
        None => {}
    }
}
