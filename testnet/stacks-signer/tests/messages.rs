use stacks_signer::signer::{Signer, MessageTypes};

#[test]
fn receive_message() {
    let signer = Signer::new();
    let join = MessageTypes::Join;
    assert!(signer.process(join));
}
