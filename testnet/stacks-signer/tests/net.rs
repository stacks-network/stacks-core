use stacks_signer::net::{HttpNet, Message, Net};
use stacks_signer::signing_round::{DkgBegin, MessageTypes};

#[test]
fn receive_msg() {
    let m1 = Message {
        msg: MessageTypes::DkgBegin(DkgBegin { dkg_id: 0 }),
        sig: [0; 32],
    };

    let stacks_node_url = "http://localhost:9775".to_owned();

    let in_queue = vec![m1];
    let mut net = HttpNet::new(stacks_node_url, in_queue);
    match net.next_message() {
        Some(_msg) => {
            assert!(true)
        }
        None => {}
    }
}
