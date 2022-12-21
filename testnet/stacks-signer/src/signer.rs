use crate::net;
use frost::frost;
use rand_core::OsRng;
use tracing::info;

pub struct Signer {
    parties: Vec<frost::Party>,
}

pub enum MessageTypes {
    Join,
}

impl Signer {
    pub fn new() -> Signer {
        Signer { parties: vec![] }
    }
    pub fn reset(threshold: usize, total: usize) -> Signer {
        assert!(threshold <= total);
        let mut rng = OsRng::default();

        // Initial set-up
        let parties: Vec<frost::Party> = (0..total)
            .map(|i| frost::Party::new(i, total, threshold, &mut rng))
            .collect();
        return Signer { parties };
    }

    pub fn process(&self, message: MessageTypes) -> bool{
        match message {
            MessageTypes::Join => {
                Signer::reset(1, 2);
            }
        };
        true
    }
}
