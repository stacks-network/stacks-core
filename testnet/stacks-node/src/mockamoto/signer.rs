use rand::{CryptoRng, RngCore, SeedableRng};
use stacks::chainstate::nakamoto::NakamotoBlock;
use stacks::chainstate::stacks::ThresholdSignature;
use wsts::curve::point::Point;
use wsts::traits::Aggregator;

/// This struct encapsulates a FROST signer that is capable of
///  signing its own aggregate public key.
/// This is used in `mockamoto` and `nakamoto-neon` operation
///  by the miner in order to self-sign blocks.
#[derive(Debug, Clone)]
pub struct SelfSigner {
    /// The parties that will sign the blocks
    pub signer_parties: Vec<wsts::v2::Party>,
    /// The commitments to the polynomials for the aggregate public key
    pub poly_commitments: Vec<wsts::common::PolyCommitment>,
    /// The aggregate public key
    pub aggregate_public_key: Point,
    /// The total number of key ids distributed among signer_parties
    pub num_keys: u32,
    /// The number of vote shares required to sign a block
    pub threshold: u32,
}

impl SelfSigner {
    pub fn from_seed(seed: u64) -> Self {
        let rng = rand::rngs::StdRng::seed_from_u64(seed);
        Self::from_rng::<rand::rngs::StdRng>(rng)
    }

    pub fn single_signer() -> Self {
        let rng = rand::rngs::OsRng::default();
        Self::from_rng::<rand::rngs::OsRng>(rng)
    }

    fn from_rng<RNG: RngCore + CryptoRng>(mut rng: RNG) -> Self {
        // Create the parties
        let mut signer_parties = [wsts::v2::Party::new(0, &[0], 1, 1, 1, &mut rng)];

        // Generate an aggregate public key
        let poly_commitments = match wsts::v2::test_helpers::dkg(&mut signer_parties, &mut rng) {
            Ok(poly_commitments) => poly_commitments,
            Err(secret_errors) => {
                panic!("Got secret errors from DKG: {:?}", secret_errors);
            }
        };

        assert_eq!(poly_commitments.len(), 1);
        assert_eq!(signer_parties.len(), 1);

        let aggregate_public_key = poly_commitments.iter().fold(
            Point::default(),
            |s, poly_commitment: &wsts::common::PolyCommitment| s + poly_commitment.poly[0],
        );

        Self {
            signer_parties: signer_parties.to_vec(),
            aggregate_public_key,
            poly_commitments,
            num_keys: 1,
            threshold: 1,
        }
    }

    pub fn sign_nakamoto_block(&mut self, block: &mut NakamotoBlock) {
        let mut rng = rand::rngs::OsRng::default();
        let msg = block
            .header
            .signer_signature_hash()
            .expect("Failed to determine the block header signature hash for signers.")
            .0;
        let (nonces, sig_shares, key_ids) =
            wsts::v2::test_helpers::sign(msg.as_slice(), &mut self.signer_parties, &mut rng);

        let mut sig_aggregator = wsts::v2::Aggregator::new(self.num_keys, self.threshold);
        sig_aggregator
            .init(self.poly_commitments.clone())
            .expect("aggregator init failed");
        let signature = sig_aggregator
            .sign(msg.as_slice(), &nonces, &sig_shares, &key_ids)
            .expect("aggregator sig failed");
        block.header.signer_signature = ThresholdSignature(signature);
    }
}
