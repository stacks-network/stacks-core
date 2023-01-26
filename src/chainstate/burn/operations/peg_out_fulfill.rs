use stacks_common::codec::StacksMessageCodec;
use stacks_common::types::chainstate::StacksBlockId;

use crate::burnchains::BurnchainBlockHeader;
use crate::burnchains::BurnchainTransaction;
use crate::chainstate::burn::Opcodes;
use crate::types::chainstate::StacksAddress;
use crate::types::Address;

use crate::chainstate::burn::operations::Error as OpError;
use crate::chainstate::burn::operations::PegOutFulfillOp;

impl PegOutFulfillOp {
    pub fn from_tx(
        block_header: &BurnchainBlockHeader,
        tx: &BurnchainTransaction,
    ) -> Result<Self, OpError> {
        if tx.opcode() != Opcodes::PegOutFulfill as u8 {
            warn!("Invalid tx: invalid opcode {}", tx.opcode());
            return Err(OpError::InvalidInput);
        }

        let (amount, recipient) = if let Some(Some(recipient)) = tx.get_recipients().first() {
            (recipient.amount, recipient.address.clone())
        } else {
            warn!("Invalid tx: Output 2 not provided");
            return Err(OpError::InvalidInput);
        };

        let ParsedData { chain_tip, memo } = Self::parse_data(&tx.data())?;

        let txid = tx.txid();
        let vtxindex = tx.vtxindex();
        let block_height = block_header.block_height;
        let burn_header_hash = block_header.block_hash;

        Ok(Self {
            chain_tip,
            amount,
            recipient,
            memo,
            txid,
            vtxindex,
            block_height,
            burn_header_hash,
        })
    }

    fn parse_data(data: &[u8]) -> Result<ParsedData, ParseError> {
        /*
            Wire format:

            0      2  3                     35                       80
            |------|--|---------------------|------------------------|
             magic  op       Chain tip                  Memo

             Note that `data` is missing the first 3 bytes -- the magic and op must
             be stripped before this method is called. At the time of writing,
             this is done in `burnchains::bitcoin::blocks::BitcoinBlockParser::parse_data`.
        */

        if data.len() < 32 {
            warn!(
                "PegInOp payload is malformed ({} bytes, expected at least {})",
                data.len(),
                32
            );
            return Err(ParseError::MalformedData);
        }

        let chain_tip = StacksBlockId::from_bytes(&data[..32]).unwrap();
        let memo = data.get(32..).unwrap_or(&[]).to_vec();

        Ok(ParsedData { chain_tip, memo })
    }

    pub fn check(&self) -> Result<(), OpError> {
        if self.amount == 0 {
            warn!("PEG_OUT_FULFILLMENT Invalid: Transferred amount must be positive");
            return Err(OpError::AmountMustBePositive);
        }

        Ok(())
    }
}

struct ParsedData {
    chain_tip: StacksBlockId,
    memo: Vec<u8>,
}

enum ParseError {
    MalformedData,
}

impl From<ParseError> for OpError {
    fn from(_: ParseError) -> Self {
        Self::ParseError
    }
}

#[cfg(test)]
mod tests {
    use crate::chainstate::burn::operations::test;

    use super::*;

    #[test]
    fn test_parse_peg_out_fulfill_should_succeed_given_a_conforming_transaction() {
        let mut rng = test::seeded_rng();
        let opcode = Opcodes::PegOutFulfill;

        let amount = 1;
        let recipient_address_bytes = test::random_bytes(&mut rng);
        let output2 = test::Output::new_as_option(amount, recipient_address_bytes);

        let mut data = vec![];
        let chain_tip_bytes: [u8; 32] = test::random_bytes(&mut rng);
        data.extend_from_slice(&chain_tip_bytes);

        let tx = test::burnchain_transaction(data, output2, opcode);
        let header = test::burnchain_block_header();

        let op =
            PegOutFulfillOp::from_tx(&header, &tx).expect("Failed to construct peg-out operation");

        assert_eq!(op.recipient.bytes(), recipient_address_bytes);
        assert_eq!(op.chain_tip.as_bytes(), &chain_tip_bytes);
        assert_eq!(op.amount, amount);
    }

    #[test]
    fn test_parse_peg_out_fulfill_should_return_error_given_wrong_opcode() {
        let mut rng = test::seeded_rng();
        let opcode = Opcodes::LeaderKeyRegister;

        let amount = 1;
        let recipient_address_bytes = test::random_bytes(&mut rng);
        let output2 = test::Output::new_as_option(amount, recipient_address_bytes);

        let mut data = vec![];
        let chain_tip_bytes: [u8; 32] = test::random_bytes(&mut rng);
        data.extend_from_slice(&chain_tip_bytes);

        let tx = test::burnchain_transaction(data, output2, opcode);
        let header = test::burnchain_block_header();

        let op = PegOutFulfillOp::from_tx(&header, &tx);

        match op {
            Err(OpError::InvalidInput) => (),
            result => panic!("Expected OpError::InvalidInput, got {:?}", result),
        }
    }

    #[test]
    fn test_parse_peg_out_fulfill_should_return_error_given_no_second_output() {
        let mut rng = test::seeded_rng();
        let opcode = Opcodes::PegOutFulfill;

        let output2 = None;

        let mut data = vec![];
        let chain_tip_bytes: [u8; 32] = test::random_bytes(&mut rng);
        data.extend_from_slice(&chain_tip_bytes);

        let tx = test::burnchain_transaction(data, output2, opcode);
        let header = test::burnchain_block_header();

        let op = PegOutFulfillOp::from_tx(&header, &tx);

        match op {
            Err(OpError::InvalidInput) => (),
            result => panic!("Expected OpError::InvalidInput, got {:?}", result),
        }
    }

    #[test]
    fn test_parse_peg_out_fulfill_should_return_error_given_too_small_header_hash() {
        let mut rng = test::seeded_rng();
        let opcode = Opcodes::PegOutFulfill;

        let amount = 1;
        let recipient_address_bytes = test::random_bytes(&mut rng);
        let output2 = test::Output::new_as_option(amount, recipient_address_bytes);

        let mut data = vec![];
        let chain_tip_bytes: [u8; 31] = test::random_bytes(&mut rng);
        data.extend_from_slice(&chain_tip_bytes);

        let tx = test::burnchain_transaction(data, output2, opcode);
        let header = test::burnchain_block_header();

        let op = PegOutFulfillOp::from_tx(&header, &tx);

        match op {
            Err(OpError::ParseError) => (),
            result => panic!("Expected OpError::ParseError, got {:?}", result),
        }
    }

    #[test]
    fn test_parse_peg_out_fulfill_should_return_error_on_zero_amount_and_ok_on_any_other_values() {
        let mut rng = test::seeded_rng();

        let mut data = vec![];
        let chain_tip_bytes: [u8; 32] = test::random_bytes(&mut rng);
        data.extend_from_slice(&chain_tip_bytes);

        let mut create_op = move |amount| {
            let opcode = Opcodes::PegOutFulfill;
            let recipient_address_bytes = test::random_bytes(&mut rng);
            let output2 = test::Output::new_as_option(amount, recipient_address_bytes);

            let tx = test::burnchain_transaction(data.clone(), output2, opcode);
            let header = test::burnchain_block_header();

            PegOutFulfillOp::from_tx(&header, &tx).expect("Failed to construct peg-in operation")
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
