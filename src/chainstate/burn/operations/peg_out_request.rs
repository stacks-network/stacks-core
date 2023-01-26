use stacks_common::codec::StacksMessageCodec;
use stacks_common::util::secp256k1::MessageSignature;

use crate::burnchains::BurnchainBlockHeader;
use crate::burnchains::BurnchainTransaction;
use crate::chainstate::burn::Opcodes;
use crate::types::chainstate::StacksAddress;
use crate::types::Address;

use crate::chainstate::burn::operations::Error as OpError;
use crate::chainstate::burn::operations::PegOutRequestOp;

impl PegOutRequestOp {
    pub fn from_tx(
        block_header: &BurnchainBlockHeader,
        tx: &BurnchainTransaction,
    ) -> Result<Self, OpError> {
        if tx.opcode() != Opcodes::PegOutRequest as u8 {
            warn!("Invalid tx: invalid opcode {}", tx.opcode());
            return Err(OpError::InvalidInput);
        }

        let recipient = if let Some(Some(recipient)) = tx.get_recipients().first() {
            recipient.address.clone()
        } else {
            warn!("Invalid tx: Output 2 not provided");
            return Err(OpError::InvalidInput);
        };

        let parsed_data = Self::parse_data(&tx.data())?;

        let txid = tx.txid();
        let vtxindex = tx.vtxindex();
        let block_height = block_header.block_height;
        let burn_header_hash = block_header.block_hash;

        Ok(Self {
            amount: parsed_data.amount,
            signature: parsed_data.signature,
            recipient,
            memo: parsed_data.memo,
            txid,
            vtxindex,
            block_height,
            burn_header_hash,
        })
    }

    fn parse_data(data: &[u8]) -> Result<ParsedData, ParseError> {
        /*
            Wire format:

            0      2  3         11                76   80
            |------|--|---------|-----------------|----|
             magic  op   amount      signature     memo

             Note that `data` is missing the first 3 bytes -- the magic and op must
             be stripped before this method is called. At the time of writing,
             this is done in `burnchains::bitcoin::blocks::BitcoinBlockParser::parse_data`.
        */

        if data.len() < 73 {
            // too short
            warn!(
                "PegOutRequestOp payload is malformed ({} bytes, expected {})",
                data.len(),
                73
            );
            return Err(ParseError::MalformedPayload);
        }

        let amount = u64::from_be_bytes(data[0..8].try_into().unwrap());
        let signature = MessageSignature::from_bytes(&data[8..73]).unwrap();
        let memo = data.get(73..).unwrap_or(&[]).to_vec();

        Ok(ParsedData {
            amount,
            signature,
            memo,
        })
    }

    pub fn check(&self) -> Result<(), OpError> {
        if self.amount == 0 {
            warn!("PEG_OUT_REQUEST Invalid: Requested BTC amount must be positive");
            return Err(OpError::AmountMustBePositive);
        }

        Ok(())
    }
}

struct ParsedData {
    amount: u64,
    signature: MessageSignature,
    memo: Vec<u8>,
}

enum ParseError {
    MalformedPayload,
    SliceConversion,
}

impl From<ParseError> for OpError {
    fn from(_: ParseError) -> Self {
        Self::ParseError
    }
}

impl From<std::array::TryFromSliceError> for ParseError {
    fn from(_: std::array::TryFromSliceError) -> Self {
        Self::SliceConversion
    }
}

#[cfg(test)]
mod tests {
    use crate::chainstate::burn::operations::test;

    use super::*;

    #[test]
    fn test_parse_peg_out_request_should_succeed_given_a_conforming_transaction() {
        let mut rng = test::seeded_rng();
        let opcode = Opcodes::PegOutRequest;

        let dust_amount = 1;
        let recipient_address_bytes = test::random_bytes(&mut rng);
        let output2 = test::Output::new_as_option(dust_amount, recipient_address_bytes);

        let mut data = vec![];
        let amount: u64 = 10;
        let signature: [u8; 65] = test::random_bytes(&mut rng);
        data.extend_from_slice(&amount.to_be_bytes());
        data.extend_from_slice(&signature);

        let tx = test::burnchain_transaction(data, output2, opcode);
        let header = test::burnchain_block_header();

        let op =
            PegOutRequestOp::from_tx(&header, &tx).expect("Failed to construct peg-out operation");

        assert_eq!(op.recipient.bytes(), recipient_address_bytes);
        assert_eq!(op.signature.as_bytes(), &signature);
        assert_eq!(op.amount, amount);
    }

    #[test]
    fn test_parse_peg_out_request_should_succeed_given_a_conforming_transaction_with_extra_memo_bytes(
    ) {
        let mut rng = test::seeded_rng();
        let opcode = Opcodes::PegOutRequest;

        let dust_amount = 1;
        let recipient_address_bytes = test::random_bytes(&mut rng);
        let output2 = test::Output::new_as_option(dust_amount, recipient_address_bytes);

        let mut data = vec![];
        let amount: u64 = 10;
        let signature: [u8; 65] = test::random_bytes(&mut rng);
        data.extend_from_slice(&amount.to_be_bytes());
        data.extend_from_slice(&signature);
        let memo_bytes: [u8; 4] = test::random_bytes(&mut rng);
        data.extend_from_slice(&memo_bytes);

        let tx = test::burnchain_transaction(data, output2, opcode);
        let header = test::burnchain_block_header();

        let op =
            PegOutRequestOp::from_tx(&header, &tx).expect("Failed to construct peg-out operation");

        assert_eq!(op.recipient.bytes(), recipient_address_bytes);
        assert_eq!(op.signature.as_bytes(), &signature);
        assert_eq!(&op.memo, &memo_bytes);
        assert_eq!(op.amount, amount);
    }

    #[test]
    fn test_parse_peg_out_request_should_return_error_given_wrong_opcode() {
        let mut rng = test::seeded_rng();
        let opcode = Opcodes::LeaderKeyRegister;

        let dust_amount = 1;
        let recipient_address_bytes = test::random_bytes(&mut rng);
        let output2 = test::Output::new_as_option(dust_amount, recipient_address_bytes);

        let mut data = vec![];
        let amount: u64 = 10;
        let signature: [u8; 65] = test::random_bytes(&mut rng);
        data.extend_from_slice(&amount.to_be_bytes());
        data.extend_from_slice(&signature);

        let tx = test::burnchain_transaction(data, output2, opcode);
        let header = test::burnchain_block_header();

        let op = PegOutRequestOp::from_tx(&header, &tx);

        match op {
            Err(OpError::InvalidInput) => (),
            result => panic!("Expected OpError::InvalidInput, got {:?}", result),
        }
    }

    #[test]
    fn test_parse_peg_out_request_should_return_error_given_no_second_output() {
        let mut rng = test::seeded_rng();
        let opcode = Opcodes::PegOutRequest;

        let output2 = None;

        let mut data = vec![];
        let amount: u64 = 10;
        let signature: [u8; 65] = test::random_bytes(&mut rng);
        data.extend_from_slice(&amount.to_be_bytes());
        data.extend_from_slice(&signature);

        let tx = test::burnchain_transaction(data, output2, opcode);
        let header = test::burnchain_block_header();

        let op = PegOutRequestOp::from_tx(&header, &tx);

        match op {
            Err(OpError::InvalidInput) => (),
            result => panic!("Expected OpError::InvalidInput, got {:?}", result),
        }
    }

    #[test]
    fn test_parse_peg_out_request_should_return_error_given_no_signature() {
        let mut rng = test::seeded_rng();
        let opcode = Opcodes::PegOutRequest;

        let dust_amount = 1;
        let recipient_address_bytes = test::random_bytes(&mut rng);
        let output2 = test::Output::new_as_option(dust_amount, recipient_address_bytes);

        let mut data = vec![];
        let amount: u64 = 10;
        let signature: [u8; 0] = test::random_bytes(&mut rng);
        data.extend_from_slice(&amount.to_be_bytes());
        data.extend_from_slice(&signature);

        let tx = test::burnchain_transaction(data, output2, opcode);
        let header = test::burnchain_block_header();

        let op = PegOutRequestOp::from_tx(&header, &tx);

        match op {
            Err(OpError::ParseError) => (),
            result => panic!("Expected OpError::ParseError, got {:?}", result),
        }
    }

    #[test]
    fn test_parse_peg_out_request_should_return_error_on_zero_amount_and_ok_on_any_other_values() {
        let mut rng = test::seeded_rng();

        let dust_amount = 1;
        let recipient_address_bytes = test::random_bytes(&mut rng);
        let output2 = test::Output::new_as_option(dust_amount, recipient_address_bytes);

        let mut create_op = move |amount: u64| {
            let opcode = Opcodes::PegOutRequest;

            let mut data = vec![];
            let signature: [u8; 65] = test::random_bytes(&mut rng);
            data.extend_from_slice(&amount.to_be_bytes());
            data.extend_from_slice(&signature);

            let tx = test::burnchain_transaction(data, output2.clone(), opcode);
            let header = test::burnchain_block_header();

            PegOutRequestOp::from_tx(&header, &tx)
                .expect("Failed to construct peg-out request operation")
        };

        match create_op(0).check() {
            Err(OpError::AmountMustBePositive) => (),
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
}
