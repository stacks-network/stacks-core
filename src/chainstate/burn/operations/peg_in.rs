use crate::burnchains::BurnchainBlockHeader;
use crate::burnchains::BurnchainTransaction;
use crate::chainstate::burn::Opcodes;
use crate::types::chainstate::StacksAddress;
use crate::types::Address;

use crate::chainstate::burn::operations::Error as OpError;
use crate::chainstate::burn::operations::PegInOp;

impl PegInOp {
    pub fn from_tx(
        block_header: &BurnchainBlockHeader,
        tx: &BurnchainTransaction,
    ) -> Result<Self, OpError> {
        if tx.opcode() != Opcodes::PegIn as u8 {
            warn!("Invalid tx: invalid opcode {}", tx.opcode());
            return Err(OpError::InvalidInput);
        }

        let (amount, peg_wallet_address) = if let Some(Some(recepient)) = tx.get_recipients().get(1)
        {
            (recepient.amount, recepient.address.clone())
        } else {
            warn!("Invalid tx: Output 2 not provided");
            return Err(OpError::InvalidInput);
        };

        let address = Self::parse_data(tx.data())?;

        let txid = tx.txid();
        let vtxindex = tx.vtxindex();
        let block_height = block_header.block_height;
        let burn_header_hash = block_header.block_hash;

        Ok(Self {
            address,
            peg_wallet_address,
            amount,
            txid,
            vtxindex,
            block_height,
            burn_header_hash,
        })
    }

    fn parse_data(data: &[u8]) -> Result<StacksAddress, ParseError> {
        /*
            Wire format:

            0      2  3                                          80
            |------|--|------------------------------------------|
             magic  op       c32-encoded Stacks address

             Note that `data` is missing the first 3 bytes -- the magic and op must
             be stripped before this method is called. At the time of writing,
             this is done in `burnchains::bitcoin::blocks::BitcoinBlockParser::parse_data`.

             The c32-encoded Stacks address may be padded with trailing ascii whitespace
        */
        StacksAddress::from_str(std::str::from_utf8(data)?.trim()).ok_or(ParseError::AddressParsing)
    }

    pub fn check(&self) -> Result<(), OpError> {
        // TODO(sbtc): Check peg wallet address
        if self.amount == 0 {
            warn!("Invalid PegInOp: Peg amount must be positive");
            return Err(OpError::PegInAmountMustBePositive);
        }

        Ok(())
    }
}

enum ParseError {
    Utf8(std::str::Utf8Error),
    AddressParsing,
}

impl From<std::str::Utf8Error> for ParseError {
    fn from(err: std::str::Utf8Error) -> Self {
        Self::Utf8(err)
    }
}

impl From<ParseError> for OpError {
    fn from(_: ParseError) -> Self {
        Self::ParseError
    }
}

#[cfg(test)]
mod tests {
    use clarity::util::hash::Hash160;
    use rand::rngs::StdRng;
    use rand::SeedableRng;

    use crate::burnchains::{
        bitcoin::{
            address::{
                BitcoinAddress, LegacyBitcoinAddress, LegacyBitcoinAddressType,
                SegwitBitcoinAddress,
            },
            BitcoinInputType, BitcoinNetworkType, BitcoinTransaction, BitcoinTxInputStructured,
            BitcoinTxOutput,
        },
        Txid,
    };

    use super::*;

    #[test]
    fn test_parse_peg_in_should_succeed_given_a_conforming_transaction() {
        let mut rng = seeded_rng();
        let wallet_address = random_bytes(&mut rng);
        let stx_address_str = "ST000000000000000000002AMW42H";
        let data = stx_address_str.as_bytes().to_vec();

        let tx = burnchain_transaction(data, 10, wallet_address);
        let header = burnchain_block_header();

        let op = PegInOp::from_tx(&header, &tx).expect("Failed to construct peg-in operation");

        let stx_address = StacksAddress::from_str(stx_address_str).unwrap();
        assert_eq!(op.address, stx_address);
    }

    fn burnchain_block_header() -> BurnchainBlockHeader {
        BurnchainBlockHeader {
            block_height: 0,
            block_hash: [0; 32].into(),
            parent_block_hash: [0; 32].into(),
            num_txs: 0,
            timestamp: 0,
        }
    }

    fn seeded_rng() -> StdRng {
        SeedableRng::from_seed([0; 32])
    }

    fn random_bytes<Rng: rand::Rng, const N: usize>(rng: &mut Rng) -> [u8; N] {
        [rng.gen(); N]
    }

    fn burnchain_transaction(
        data: Vec<u8>,
        amount: u64,
        peg_in_wallet_address: [u8; 32],
    ) -> BurnchainTransaction {
        BurnchainTransaction::Bitcoin(bitcoin_transaction(data, amount, peg_in_wallet_address))
    }

    fn bitcoin_transaction(
        data: Vec<u8>,
        amount: u64,
        peg_in_wallet_address: [u8; 32],
    ) -> BitcoinTransaction {
        BitcoinTransaction {
            txid: Txid([0; 32]),
            vtxindex: 0,
            opcode: Opcodes::PegIn as u8,
            data,
            data_amt: 0,
            inputs: vec![BitcoinTxInputStructured {
                keys: vec![],
                num_required: 0,
                in_type: BitcoinInputType::Standard,
                tx_ref: (Txid([0; 32]), 0),
            }
            .into()],
            outputs: vec![
                BitcoinTxOutput {
                    units: 10,
                    address: BitcoinAddress::Legacy(LegacyBitcoinAddress {
                        addrtype: LegacyBitcoinAddressType::PublicKeyHash,
                        network_id: BitcoinNetworkType::Mainnet,
                        bytes: Hash160([1; 20]),
                    }),
                },
                BitcoinTxOutput {
                    units: amount,
                    address: BitcoinAddress::Segwit(SegwitBitcoinAddress::P2TR(
                        true,
                        peg_in_wallet_address,
                    )),
                },
            ],
        }
    }
}
