use secp256k1_math::scalar::Scalar;
use stacks_signer::config::Config;
use stacks_signer::net::{HttpNet, Message, Net};
use stacks_signer::signer::{MessageTypes, SignatureShare, Signer};

fn setup(in_queue: Vec<Message>, out_queue: Vec<Message>) -> (Signer, Box<dyn Net>) {
    let mut signer = Signer::new();
    signer.reset(1, 2);
    let mut config = Config::default();
    config.common.stacks_node_url = "http://localhost:9775".to_owned();

    // prepopulate network receive queue
    (signer, Box::new(HttpNet::new(&config, in_queue, out_queue)))
}

#[test]
fn receive_join() {
    let m1 = Message {
        msg: MessageTypes::DkgBegin
    };
    let in_queue = vec![m1];
    let out_queue = vec![];
    let (mut signer, _net) = setup(in_queue, out_queue);

    let join = MessageTypes::DkgBegin;
    assert!(signer.process(join));
}

#[test]
fn receive_share() {
    let share = frost::common::SignatureShare {
        id: 0,
        z_i: Scalar::new(),
        public_key: Default::default(),
    };

    let m1 = Message {
        msg: MessageTypes::SignatureShare(SignatureShare {
            signature_share: share,
        }),
    };
    let in_queue = vec![m1];
    let out_queue = vec![];
    let (_signer, mut net) = setup(in_queue, out_queue);

    let next = net.next_message();
    match next {
        Some(msg) => match msg.msg {
            MessageTypes::SignatureShare(share) => {
                assert_eq!(share.signature_share.id, 0)
            }
            _ => {
                panic!("wrong msg received")
            }
        },
        None => {
            panic!("net.next_message() failed")
        }
    }
}
