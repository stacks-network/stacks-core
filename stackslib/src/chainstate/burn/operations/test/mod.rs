use rand::rngs::StdRng;
use rand::SeedableRng;
use stacks_common::util::hash::Hash160;

use crate::burnchains::bitcoin::address::{
    BitcoinAddress, LegacyBitcoinAddress, LegacyBitcoinAddressType, SegwitBitcoinAddress,
};
use crate::burnchains::bitcoin::{
    BitcoinInputType, BitcoinNetworkType, BitcoinTransaction, BitcoinTxInputStructured,
    BitcoinTxOutput,
};
use crate::burnchains::{BurnchainBlockHeader, BurnchainTransaction, Txid};
use crate::chainstate::burn::Opcodes;

mod serialization;

pub(crate) fn seeded_rng() -> StdRng {
    SeedableRng::from_seed([0; 32])
}

pub(crate) fn random_bytes<Rng: rand::Rng, const N: usize>(rng: &mut Rng) -> [u8; N] {
    [rng.gen(); N]
}

pub(crate) fn burnchain_block_header() -> BurnchainBlockHeader {
    BurnchainBlockHeader {
        block_height: 0,
        block_hash: [0; 32].into(),
        parent_block_hash: [0; 32].into(),
        num_txs: 0,
        timestamp: 0,
    }
}

pub(crate) fn burnchain_transaction(
    data: Vec<u8>,
    outputs: impl IntoIterator<Item = Output>,
    opcode: Opcodes,
) -> BurnchainTransaction {
    BurnchainTransaction::Bitcoin(bitcoin_transaction(data, outputs, opcode))
}

fn bitcoin_transaction(
    data: Vec<u8>,
    outputs: impl IntoIterator<Item = Output>,
    opcode: Opcodes,
) -> BitcoinTransaction {
    BitcoinTransaction {
        txid: Txid([0; 32]),
        vtxindex: 0,
        opcode: opcode as u8,
        data,
        data_amt: 0,
        inputs: vec![BitcoinTxInputStructured {
            keys: vec![],
            num_required: 0,
            in_type: BitcoinInputType::Standard,
            tx_ref: (Txid([0; 32]), 2),
        }
        .into()],
        outputs: outputs
            .into_iter()
            .map(|output2data| output2data.as_bitcoin_tx_output())
            .collect(),
    }
}

#[derive(Debug, Clone)]
pub(crate) struct Output {
    amount: u64,
    address: [u8; 32],
}

impl Output {
    pub(crate) fn new(amount: u64, peg_wallet_address: [u8; 32]) -> Self {
        Self {
            amount,
            address: peg_wallet_address,
        }
    }
    pub(crate) fn as_bitcoin_tx_output(&self) -> BitcoinTxOutput {
        BitcoinTxOutput {
            units: self.amount,
            address: BitcoinAddress::Segwit(SegwitBitcoinAddress::P2TR(true, self.address)),
        }
    }
}
