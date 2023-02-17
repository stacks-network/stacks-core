// Copyright (C) 2013-2020 Blockstack PBC, a public benefit corporation
// Copyright (C) 2020 Stacks Open Internet Foundation
//
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.
//
// This program is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
// GNU General Public License for more details.
//
// You should have received a copy of the GNU General Public License
// along with this program.  If not, see <http://www.gnu.org/licenses/>.

use stacks_common::codec::StacksMessageCodec;
use stacks_common::types::chainstate::StacksBlockId;

use crate::burnchains::BurnchainBlockHeader;
use crate::burnchains::BurnchainTransaction;
use crate::burnchains::Txid;
use crate::chainstate::burn::Opcodes;
use crate::types::chainstate::StacksAddress;
use crate::types::Address;

use crate::chainstate::burn::operations::Error as OpError;
use crate::chainstate::burn::operations::PegOutFulfillOp;

/// Transaction structure:
///
/// Input 0: The 2nd output of a PegOutRequestOp, spent by the peg wallet (to pay the tx fee)
///
/// Output 0: data output (see PegOutFulfillOp::parse_data())
/// Output 1: Bitcoin address to send the BTC to
///
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
            warn!("Invalid tx: First output not recognized");
            return Err(OpError::InvalidInput);
        };

        let ParsedData { chain_tip, memo } = Self::parse_data(&tx.data())?;

        let txid = tx.txid();
        let vtxindex = tx.vtxindex();
        let block_height = block_header.block_height;
        let burn_header_hash = block_header.block_hash;

        let request_ref = Self::get_sender_txid(tx)?;

        Ok(Self {
            chain_tip,
            amount,
            recipient,
            memo,
            request_ref,
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

        let chain_tip = StacksBlockId::from_bytes(&data[..32])
            .expect("PegOutFulfillment chain tip data failed to convert to block ID");
        let memo = data.get(32..).unwrap_or(&[]).to_vec();

        Ok(ParsedData { chain_tip, memo })
    }

    fn get_sender_txid(tx: &BurnchainTransaction) -> Result<Txid, ParseError> {
        match tx.get_input_tx_ref(0) {
            Some(&(tx_ref, vout)) => {
                if vout != 2 {
                    warn!(
                        "Invalid tx: PegOutFulfillOp must spend the third output of the PegOutRequestOp"
                    );
                    Err(ParseError::InvalidInput)
                } else {
                    Ok(tx_ref)
                }
            }
            None => {
                warn!("Invalid tx: PegOutFulfillOp must have at least one input");
                Err(ParseError::InvalidInput)
            }
        }
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
    InvalidInput,
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
        let output2 = test::Output::new(amount, recipient_address_bytes);

        let mut data = vec![];
        let chain_tip_bytes: [u8; 32] = test::random_bytes(&mut rng);
        data.extend_from_slice(&chain_tip_bytes);

        let tx = test::burnchain_transaction(data, Some(output2), opcode);
        let header = test::burnchain_block_header();

        let op =
            PegOutFulfillOp::from_tx(&header, &tx).expect("Failed to construct peg-out operation");

        assert_eq!(op.recipient.bytes(), recipient_address_bytes);
        assert_eq!(op.chain_tip.as_bytes(), &chain_tip_bytes);
        assert_eq!(op.amount, amount);
    }

    #[test]
    fn test_parse_peg_out_fulfill_should_succeed_given_a_conforming_transaction_with_extra_memo_bytes(
    ) {
        let mut rng = test::seeded_rng();
        let opcode = Opcodes::PegOutFulfill;

        let amount = 1;
        let recipient_address_bytes = test::random_bytes(&mut rng);
        let output2 = test::Output::new(amount, recipient_address_bytes);

        let mut data = vec![];
        let chain_tip_bytes: [u8; 32] = test::random_bytes(&mut rng);
        data.extend_from_slice(&chain_tip_bytes);
        let memo_bytes: [u8; 17] = test::random_bytes(&mut rng);
        data.extend_from_slice(&memo_bytes);

        let tx = test::burnchain_transaction(data, Some(output2), opcode);
        let header = test::burnchain_block_header();

        let op =
            PegOutFulfillOp::from_tx(&header, &tx).expect("Failed to construct peg-out operation");

        assert_eq!(op.recipient.bytes(), recipient_address_bytes);
        assert_eq!(op.chain_tip.as_bytes(), &chain_tip_bytes);
        assert_eq!(&op.memo, &memo_bytes);
        assert_eq!(op.amount, amount);
    }

    #[test]
    fn test_parse_peg_out_fulfill_should_return_error_given_wrong_opcode() {
        let mut rng = test::seeded_rng();
        let opcode = Opcodes::LeaderKeyRegister;

        let amount = 1;
        let recipient_address_bytes = test::random_bytes(&mut rng);
        let output2 = test::Output::new(amount, recipient_address_bytes);

        let mut data = vec![];
        let chain_tip_bytes: [u8; 32] = test::random_bytes(&mut rng);
        data.extend_from_slice(&chain_tip_bytes);

        let tx = test::burnchain_transaction(data, Some(output2), opcode);
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
        let output2 = test::Output::new(amount, recipient_address_bytes);

        let mut data = vec![];
        let chain_tip_bytes: [u8; 31] = test::random_bytes(&mut rng);
        data.extend_from_slice(&chain_tip_bytes);

        let tx = test::burnchain_transaction(data, Some(output2), opcode);
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
            let output2 = test::Output::new(amount, recipient_address_bytes);

            let tx = test::burnchain_transaction(data.clone(), Some(output2), opcode);
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
