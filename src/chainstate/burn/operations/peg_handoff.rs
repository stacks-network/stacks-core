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

use crate::burnchains::BurnchainBlockHeader;
use crate::burnchains::BurnchainTransaction;
use crate::chainstate::burn::operations::Error as OpError;
use crate::chainstate::burn::operations::PegHandoffOp;
use crate::chainstate::burn::Opcodes;

/// Transaction structure:
///
/// Output 0: data output (see PegHandoffOp::parse_data())
/// Output 1: payment to peg wallet of next reward cycle
///
impl PegHandoffOp {
    pub fn from_tx(
        block_header: &BurnchainBlockHeader,
        tx: &BurnchainTransaction,
    ) -> Result<Self, OpError> {
        if tx.opcode() != Opcodes::PegHandoff as u8 {
            warn!("Invalid tx: invalid opcode {}", tx.opcode());
            return Err(OpError::InvalidInput);
        }

        let (amount, next_peg_wallet) = if let Some(Some(recipient)) = tx.get_recipients().first() {
            (recipient.amount, recipient.address.clone())
        } else {
            warn!("Invalid tx: First output not recognized");
            return Err(OpError::InvalidInput);
        };

        let parsed_data = Self::parse_data(&tx.data())?;

        let txid = tx.txid();
        let vtxindex = tx.vtxindex();
        let block_height = block_header.block_height;
        let burn_header_hash = block_header.block_hash;

        Ok(Self {
            next_peg_wallet,
            amount,
            reward_cycle: parsed_data.reward_cycle,
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

            0      2  3                  11                                     80
            |------|--|------------------|--------------------------------------|
             magic  op   Reward cycle                     memo

             Note that `data` is missing the first 3 bytes -- the magic and op must
             be stripped before this method is called. At the time of writing,
             this is done in `burnchains::bitcoin::blocks::BitcoinBlockParser::parse_data`.
        */

        if data.len() < 8 {
            warn!(
                "PegHandoffOp payload is malformed ({} bytes, expected at least {})",
                data.len(),
                8
            );
            return Err(ParseError::MalformedData);
        }

        let reward_cycle = u64::from_be_bytes(data[0..8].try_into().unwrap());
        let memo = data.get(8..).unwrap_or(&[]).to_vec();

        Ok(ParsedData { reward_cycle, memo })
    }

    pub fn check(&self) -> Result<(), OpError> {
        if self.amount == 0 {
            warn!("PEG_HANDOFF Invalid: Handoff amount must be positive");
            return Err(OpError::AmountMustBePositive);
        }

        Ok(())
    }
}

struct ParsedData {
    reward_cycle: u64,
    memo: Vec<u8>,
}

#[derive(Debug, PartialEq)]
enum ParseError {
    MalformedData,
    SliceConversion,
}

impl From<std::array::TryFromSliceError> for ParseError {
    fn from(_: std::array::TryFromSliceError) -> Self {
        Self::SliceConversion
    }
}

impl From<ParseError> for OpError {
    fn from(_: ParseError) -> Self {
        Self::ParseError
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::chainstate::burn::operations::test;

    #[test]
    fn test_parse_peg_handoff_should_succeed_given_a_conforming_transaction_without_memo() {
        let mut rng = test::seeded_rng();
        let opcode = Opcodes::PegHandoff;

        let next_peg_wallet = test::random_bytes(&mut rng);
        let amount = 1337;
        let reward_cycle: u64 = 42;

        let output2 = test::Output::new(amount, next_peg_wallet);

        let data = reward_cycle.to_be_bytes().to_vec();

        let tx = test::burnchain_transaction(data, Some(output2), opcode);
        let header = test::burnchain_block_header();

        let op = PegHandoffOp::from_tx(&header, &tx).expect("Failed to construct peg-in operation");

        assert_eq!(op.amount, amount);
        assert_eq!(op.reward_cycle, reward_cycle);
        assert_eq!(op.next_peg_wallet.bytes(), next_peg_wallet);
    }

    #[test]
    fn test_parse_peg_handoff_should_succeed_given_a_conforming_transaction_with_memo() {
        let mut rng = test::seeded_rng();
        let opcode = Opcodes::PegHandoff;

        let next_peg_wallet = test::random_bytes(&mut rng);
        let amount = 1337;
        let reward_cycle: u64 = 42;
        let memo: [u8; 69] = test::random_bytes(&mut rng);

        let output2 = test::Output::new(amount, next_peg_wallet);

        let mut data = reward_cycle.to_be_bytes().to_vec();
        data.extend_from_slice(&memo);

        let tx = test::burnchain_transaction(data, Some(output2), opcode);
        let header = test::burnchain_block_header();

        let op = PegHandoffOp::from_tx(&header, &tx).expect("Failed to construct peg-in operation");

        assert_eq!(op.amount, amount);
        assert_eq!(op.reward_cycle, reward_cycle);
        assert_eq!(op.next_peg_wallet.bytes(), next_peg_wallet);
        assert_eq!(op.memo.as_slice(), memo)
    }

    #[test]
    fn test_parse_peg_handoff_should_return_error_given_wrong_opcode() {
        let mut rng = test::seeded_rng();
        let opcode = Opcodes::PegOutRequest;

        let next_peg_wallet = test::random_bytes(&mut rng);
        let amount = 1337;
        let reward_cycle: u64 = 42;
        let memo: [u8; 69] = test::random_bytes(&mut rng);

        let output2 = test::Output::new(amount, next_peg_wallet);

        let mut data = reward_cycle.to_be_bytes().to_vec();
        data.extend_from_slice(&memo);

        let tx = test::burnchain_transaction(data, Some(output2), opcode);
        let header = test::burnchain_block_header();

        let op = PegHandoffOp::from_tx(&header, &tx);

        match op {
            Err(OpError::InvalidInput) => (),
            result => panic!("Expected OpError::InvalidInput, got {:?}", result),
        }
    }

    #[test]
    fn test_parse_peg_in_should_return_error_given_no_second_output() {
        let mut rng = test::seeded_rng();
        let opcode = Opcodes::PegHandoff;

        let reward_cycle: u64 = 42;
        let memo: [u8; 69] = test::random_bytes(&mut rng);

        let mut data = reward_cycle.to_be_bytes().to_vec();
        data.extend_from_slice(&memo);

        let tx = test::burnchain_transaction(data, None, opcode);
        let header = test::burnchain_block_header();

        let op = PegHandoffOp::from_tx(&header, &tx);

        match op {
            Err(OpError::InvalidInput) => (),
            result => panic!("Expected OpError::InvalidInput, got {:?}", result),
        }
    }

    #[test]
    fn test_check_should_return_error_on_zero_amount_and_ok_on_any_other_values() {
        let mut rng = test::seeded_rng();
        let opcode = Opcodes::PegHandoff;

        let next_peg_wallet = test::random_bytes(&mut rng);
        let reward_cycle: u64 = 42;
        let memo: [u8; 69] = test::random_bytes(&mut rng);

        let mut data = reward_cycle.to_be_bytes().to_vec();
        data.extend_from_slice(&memo);

        let header = test::burnchain_block_header();

        let create_op = move |amount| {
            let opcode = Opcodes::PegHandoff;
            let output2 = test::Output::new(amount, next_peg_wallet.clone());

            let tx = test::burnchain_transaction(data.clone(), Some(output2), opcode);
            let header = test::burnchain_block_header();

            PegHandoffOp::from_tx(&header, &tx).expect("Failed to construct peg-in operation")
        };

        match create_op(0).check() {
            Err(OpError::AmountMustBePositive) => (),
            result => panic!("Expected OpError::AmountMustBePositive, got {:?}", result),
        };

        create_op(1)
            .check()
            .expect("Any strictly positive amounts should be ok");

        create_op(u64::MAX)
            .check()
            .expect("Any strictly positive amounts should be ok");
    }
}
