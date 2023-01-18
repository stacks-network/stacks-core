use clarity::codec::StacksMessageCodec;

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

        let (amount, peg_wallet_address) =
            if let Some(Some(recepient)) = tx.get_recipients().first() {
                (recepient.amount, recepient.address.clone())
            } else {
                warn!("Invalid tx: Output 2 not provided");
                return Err(OpError::InvalidInput);
            };

        let recipient = Self::parse_data(&tx.data())?;

        let txid = tx.txid();
        let vtxindex = tx.vtxindex();
        let block_height = block_header.block_height;
        let burn_header_hash = block_header.block_hash;

        Ok(Self {
            recipient,
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

            0      2  3                     24
            |------|--|---------------------|
             magic  op   Stacks address

             Note that `data` is missing the first 3 bytes -- the magic and op must
             be stripped before this method is called. At the time of writing,
             this is done in `burnchains::bitcoin::blocks::BitcoinBlockParser::parse_data`.
        */
        StacksAddress::consensus_deserialize(&mut &data[..]).map_err(|e| {
            warn!("PEG_IN Address parsing error: {}", e);
            ParseError::AddressParsing
        })
    }

    pub fn check(&self) -> Result<(), OpError> {
        if self.amount == 0 {
            warn!("PEG_IN Invalid: Peg amount must be positive");
            return Err(OpError::PegInAmountMustBePositive);
        }

        Ok(())
    }
}

enum ParseError {
    AddressParsing,
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
        let opcode = Opcodes::PegIn;

        let peg_wallet_address = random_bytes(&mut rng);
        let amount = 10;
        let output2 = Output2Data::new_as_option(amount, peg_wallet_address);

        let mut data = vec![1];
        let addr_bytes = random_bytes(&mut rng);
        let stx_address = StacksAddress::new(1, addr_bytes.into());
        data.extend_from_slice(&addr_bytes);

        let tx = burnchain_transaction(data, output2, opcode);
        let header = burnchain_block_header();

        let op = PegInOp::from_tx(&header, &tx).expect("Failed to construct peg-in operation");

        assert_eq!(op.recipient, stx_address);
        assert_eq!(op.amount, amount);
        assert_eq!(op.peg_wallet_address.bytes(), peg_wallet_address);
    }

    #[test]
    fn test_parse_peg_in_should_return_error_given_wrong_opcode() {
        let mut rng = seeded_rng();
        let opcode = Opcodes::StackStx;

        let peg_wallet_address = random_bytes(&mut rng);
        let amount = 10;
        let output2 = Output2Data::new_as_option(amount, peg_wallet_address);

        let mut data = vec![1];
        let addr_bytes: [u8; 20] = random_bytes(&mut rng);
        data.extend_from_slice(&addr_bytes);

        let tx = burnchain_transaction(data, output2, opcode);
        let header = burnchain_block_header();

        let op = PegInOp::from_tx(&header, &tx);

        match op {
            Err(OpError::InvalidInput) => (),
            result => panic!("Expected OpError::InvalidInput, got {:?}", result),
        }
    }

    #[test]
    fn test_parse_peg_in_should_return_error_given_no_second_output() {
        let mut rng = seeded_rng();
        let opcode = Opcodes::PegIn;

        let mut data = vec![1];
        let addr_bytes: [u8; 20] = random_bytes(&mut rng);
        data.extend_from_slice(&addr_bytes);

        let tx = burnchain_transaction(data, None, opcode);
        let header = burnchain_block_header();

        let op = PegInOp::from_tx(&header, &tx);

        match op {
            Err(OpError::InvalidInput) => (),
            result => panic!("Expected OpError::InvalidInput, got {:?}", result),
        }
    }

    #[test]
    fn test_parse_peg_in_should_return_error_given_too_short_data_array() {
        let mut rng = seeded_rng();
        let opcode = Opcodes::PegIn;

        let peg_wallet_address = random_bytes(&mut rng);
        let amount = 10;
        let output2 = Output2Data::new_as_option(amount, peg_wallet_address);

        let mut data = vec![1];
        let addr_bytes: [u8; 19] = random_bytes(&mut rng);
        data.extend_from_slice(&addr_bytes);

        let tx = burnchain_transaction(data, output2, opcode);
        let header = burnchain_block_header();

        let op = PegInOp::from_tx(&header, &tx);

        match op {
            Err(OpError::ParseError) => (),
            result => panic!("Expected OpError::InvalidInput, got {:?}", result),
        }
    }

    #[test]
    fn test_check_should_return_error_on_zero_amount_and_ok_on_any_other_values() {
        let mut rng = seeded_rng();

        let peg_wallet_address = random_bytes(&mut rng);

        let mut data = vec![1];
        let addr_bytes = random_bytes(&mut rng);
        let stx_address = StacksAddress::new(1, addr_bytes.into());
        data.extend_from_slice(&addr_bytes);

        let create_op = move |amount| {
            let opcode = Opcodes::PegIn;
            let output2 = Output2Data::new_as_option(amount, peg_wallet_address.clone());

            let tx = burnchain_transaction(data.clone(), output2, opcode);
            let header = burnchain_block_header();

            PegInOp::from_tx(&header, &tx).expect("Failed to construct peg-in operation")
        };

        match create_op(0).check() {
            Err(OpError::PegInAmountMustBePositive) => (),
            result => panic!(
                "Expected OpError::PegInAmountMustBePositive, got {:?}",
                result
            ),
        };

        create_op(1)
            .check()
            .expect("Any strictly positive amounts should be ok");

        create_op(u64::MAX)
            .check()
            .expect("Any strictly positive amounts should be ok");
    }

    fn seeded_rng() -> StdRng {
        SeedableRng::from_seed([0; 32])
    }

    fn random_bytes<Rng: rand::Rng, const N: usize>(rng: &mut Rng) -> [u8; N] {
        [rng.gen(); N]
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

    fn burnchain_transaction(
        data: Vec<u8>,
        output2: Option<Output2Data>,
        opcode: Opcodes,
    ) -> BurnchainTransaction {
        BurnchainTransaction::Bitcoin(bitcoin_transaction(data, output2, opcode))
    }

    fn bitcoin_transaction(
        data: Vec<u8>,
        output2: Option<Output2Data>,
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
                tx_ref: (Txid([0; 32]), 0),
            }
            .into()],
            outputs: output2
                .into_iter()
                .map(|output2data| output2data.as_bitcoin_tx_output())
                .collect(),
        }
    }

    struct Output2Data {
        amount: u64,
        peg_wallet_address: [u8; 32],
    }

    impl Output2Data {
        fn new_as_option(amount: u64, peg_wallet_address: [u8; 32]) -> Option<Self> {
            Some(Self {
                amount,
                peg_wallet_address,
            })
        }
        fn as_bitcoin_tx_output(&self) -> BitcoinTxOutput {
            BitcoinTxOutput {
                units: self.amount,
                address: BitcoinAddress::Segwit(SegwitBitcoinAddress::P2TR(
                    true,
                    self.peg_wallet_address,
                )),
            }
        }
    }
}
