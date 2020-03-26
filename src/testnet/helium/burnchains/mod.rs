pub mod burnchain_simulator_engine;
pub mod bitcoin_regtest_engine;

pub use self::burnchain_simulator_engine::{BurnchainSimulatorEngine};
pub use self::bitcoin_regtest_engine::{BitcoinRegtestEngine};

use super::Config;
use super::operations::BurnchainOperationType;

use burnchains::BurnchainSigner;
use chainstate::burn::db::burndb::{BurnDB};
use chainstate::burn::{BlockSnapshot};
use chainstate::burn::operations::{BlockstackOperationType};

use util::secp256k1::{MessageSignature, Secp256k1PublicKey};

pub struct BurnchainState {
    pub chain_tip: BlockSnapshot,
    pub ops: Vec<BlockstackOperationType>,
}

pub trait BurnchainOperationSigningDelegate {
    fn create_session(&mut self) -> [u8; 16];
    fn get_public_key(&mut self, session_id: &[u8]) -> Option<Secp256k1PublicKey>;
    fn sign_message(&mut self, session_id: &[u8], hash: &[u8]) -> Option<MessageSignature>;
    fn close_session(&mut self, session_id: &[u8]);
}

pub trait BurnchainEngine {
    fn new(config: Config) -> Self;
    fn start(&mut self) -> BurnchainState;
    fn submit_operation<T: BurnchainOperationSigningDelegate>(&mut self, operation: BurnchainOperationType, signer_delegate: &mut T);
    fn sync(&mut self) -> BurnchainState;
    fn burndb_mut(&mut self) -> &mut BurnDB;
    fn get_chain_tip(&mut self) -> BlockSnapshot;
}