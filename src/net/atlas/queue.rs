use std::collections::BinaryHeap;

struct AttachmentPriorityQueue {
    storage: BinaryHeap<u16>,
}

impl AttachmentPriorityQueue {

    pub fn new() -> AttachmentPriorityQueue {
        let storage = BinaryHeap::new();
        AttachmentPriorityQueue {
            storage
        }
    }

    pub fn build(&mut self, peers: Vec<Peer>) {


    }


}