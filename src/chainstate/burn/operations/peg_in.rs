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

use crate::burnchains::BurnchainBlockHeader;
use crate::burnchains::BurnchainTransaction;
use crate::chainstate::burn::Opcodes;
use crate::types::chainstate::StacksAddress;
use crate::types::Address;

use crate::chainstate::burn::operations::Error as OpError;
use crate::chainstate::burn::operations::PegInOp;

use crate::vm::errors::RuntimeErrorType as ClarityRuntimeError;
use crate::vm::types::PrincipalData;
use crate::vm::types::QualifiedContractIdentifier;
use crate::vm::types::StandardPrincipalData;
use crate::vm::ContractName;

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
            if let Some(Some(recipient)) = tx.get_recipients().first() {
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
            recipient: parsed_data.recipient,
            peg_wallet_address,
            amount,
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

            0      2  3                  24                            64       80
            |------|--|------------------|-----------------------------|--------|
             magic  op   Stacks address      Contract name (optional)     memo

             Note that `data` is missing the first 3 bytes -- the magic and op must
             be stripped before this method is called. At the time of writing,
             this is done in `burnchains::bitcoin::blocks::BitcoinBlockParser::parse_data`.
        */

        if data.len() < 21 {
            warn!(
                "PegInOp payload is malformed ({} bytes, expected at least {})",
                data.len(),
                21
            );
            return Err(ParseError::MalformedData);
        }

        let version = *data.get(0).expect("No version byte");
        let address_data: [u8; 20] = data
            .get(1..21)
            .ok_or(ParseError::MalformedData)?
            .try_into()?;

        let standard_principal_data = StandardPrincipalData(version, address_data);

        let memo = data.get(61..).unwrap_or(&[]).to_vec();

        let recipient: PrincipalData =
            if let Some(contract_bytes) = Self::leading_non_zero_bytes(data, 21, 61) {
                let contract_name: String = std::str::from_utf8(contract_bytes)?.to_owned();

                QualifiedContractIdentifier::new(standard_principal_data, contract_name.try_into()?)
                    .into()
            } else {
                standard_principal_data.into()
            };

        Ok(ParsedData { recipient, memo })
    }

    pub fn check(&self) -> Result<(), OpError> {
        if self.amount == 0 {
            warn!("PEG_IN Invalid: Peg amount must be positive");
            return Err(OpError::PegInAmountMustBePositive);
        }

        Ok(())
    }

    /// Returns the leading non-zero bytes of the subslice `data[from..to]`
    ///
    /// # Panics
    ///
    /// Panics if `from` is larger than or equal to `to`
    fn leading_non_zero_bytes(data: &[u8], from: usize, to: usize) -> Option<&[u8]> {
        assert!(from < to);

        let end_of_non_zero_slice = {
            let mut end = to.min(data.len());
            for i in from..end {
                if data[i] == 0 {
                    end = i;
                    break;
                }
            }
            end
        };

        if from == end_of_non_zero_slice {
            return None;
        }

        data.get(from..end_of_non_zero_slice)
    }
}

struct ParsedData {
    recipient: PrincipalData,
    memo: Vec<u8>,
}

enum ParseError {
    BadContractName,
    MalformedData,
    Utf8Error,
}

impl From<ParseError> for OpError {
    fn from(_: ParseError) -> Self {
        Self::ParseError
    }
}

impl From<std::str::Utf8Error> for ParseError {
    fn from(_: std::str::Utf8Error) -> Self {
        Self::Utf8Error
    }
}

impl From<std::array::TryFromSliceError> for ParseError {
    fn from(_: std::array::TryFromSliceError) -> Self {
        Self::MalformedData
    }
}

impl From<ClarityRuntimeError> for ParseError {
    fn from(_: ClarityRuntimeError) -> Self {
        Self::BadContractName
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

        assert_eq!(op.recipient, stx_address.into());
        assert_eq!(op.amount, amount);
        assert_eq!(op.peg_wallet_address.bytes(), peg_wallet_address);
    }

    #[test]
    fn test_parse_peg_in_should_succeed_given_a_contract_recipient() {
        let mut rng = seeded_rng();
        let opcode = Opcodes::PegIn;

        let contract_name = "This_is_a_valid_contract_name";
        let peg_wallet_address = random_bytes(&mut rng);
        let amount = 10;
        let output2 = Output2Data::new_as_option(amount, peg_wallet_address);

        let mut data = vec![1];
        let addr_bytes = random_bytes(&mut rng);
        let stx_address = StacksAddress::new(1, addr_bytes.into());
        data.extend_from_slice(&addr_bytes);
        data.extend_from_slice(contract_name.as_bytes());

        let tx = burnchain_transaction(data, output2, opcode);
        let header = burnchain_block_header();

        let op = PegInOp::from_tx(&header, &tx).expect("Failed to construct peg-in operation");

        let expected_principal =
            QualifiedContractIdentifier::new(stx_address.into(), contract_name.into()).into();

        assert_eq!(op.recipient, expected_principal);
        assert_eq!(op.amount, amount);
        assert_eq!(op.peg_wallet_address.bytes(), peg_wallet_address);
    }

    #[test]
    fn test_parse_peg_in_should_return_error_given_invalid_contract_name() {
        let mut rng = seeded_rng();
        let opcode = Opcodes::PegIn;

        let contract_name = "Mårten_is_not_a_valid_smart_contract_name";
        let peg_wallet_address = random_bytes(&mut rng);
        let amount = 10;
        let output2 = Output2Data::new_as_option(amount, peg_wallet_address);

        let mut data = vec![1];
        let addr_bytes = random_bytes(&mut rng);
        let stx_address = StacksAddress::new(1, addr_bytes.into());
        data.extend_from_slice(&addr_bytes);
        data.extend_from_slice(contract_name.as_bytes());

        let tx = burnchain_transaction(data, output2, opcode);
        let header = burnchain_block_header();

        let op = PegInOp::from_tx(&header, &tx);

        match op {
            Err(OpError::ParseError) => (),
            result => panic!("Expected OpError::ParseError, got {:?}", result),
        }
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
    fn test_parse_peg_in_should_return_error_given_invalid_utf8_contract_name() {
        let invalid_utf8_byte_sequence = [255, 255];

        let mut rng = seeded_rng();
        let opcode = Opcodes::PegIn;

        let peg_wallet_address = random_bytes(&mut rng);
        let amount = 10;
        let output2 = Output2Data::new_as_option(amount, peg_wallet_address);

        let mut data = vec![1];
        let addr_bytes: [u8; 20] = random_bytes(&mut rng);
        data.extend_from_slice(&addr_bytes);
        data.extend_from_slice(&invalid_utf8_byte_sequence);

        let tx = burnchain_transaction(data, output2, opcode);
        let header = burnchain_block_header();

        let op = PegInOp::from_tx(&header, &tx);

        match op {
            Err(OpError::ParseError) => (),
            result => panic!("Expected OpError::ParseError, got {:?}", result),
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
