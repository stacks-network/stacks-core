pub use frost::frost;
use rand_core::OsRng;
use secp256k1_math::scalar::Scalar;
use hashbrown::HashMap;

type KeyShare = HashMap<usize, Scalar>;

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

    pub fn reset(&mut self, threshold: usize, total: usize) {
        assert!(threshold <= total);
        let mut rng = OsRng::default();

        // Initial set-up
        let parties: Vec<frost::Party> = (0..total)
            .map(|i| frost::Party::new(i, total, threshold, &mut rng))
            .collect();
        self.parties = parties;
    }

    pub fn process(&mut self, message: MessageTypes) -> bool {
        match message {
            MessageTypes::Join => {
                self.reset(1, 2);
            }
        };
        true
    }

    pub fn key_share(&self, party_id: usize) -> KeyShare {
        self.parties[party_id].get_shares()
    }
}
