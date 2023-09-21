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

use stacks_common::address::public_keys_to_address_hash;
use stacks_common::address::AddressHashMode;
use stacks_common::codec::StacksMessageCodec;
use stacks_common::types::chainstate::StacksPublicKey;
use stacks_common::util::hash::Sha256Sum;
use stacks_common::util::secp256k1::MessageSignature;

use crate::burnchains::BurnchainBlockHeader;
use crate::burnchains::BurnchainTransaction;
use crate::chainstate::burn::operations::Error as OpError;
use crate::chainstate::burn::operations::PegOutRequestOp;
use crate::chainstate::burn::Opcodes;
use crate::types::chainstate::StacksAddress;
use crate::types::Address;

/// Transaction structure:
///
/// Output 0: data output (see PegOutRequestOp::parse_data())
/// Output 1: Bitcoin address to send the BTC to
/// Output 2: Bitcoin fee payment to the peg wallet (which the peg wallet will spend on fulfillment)
///
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
            warn!("Invalid tx: First output not recognized");
            return Err(OpError::InvalidInput);
        };

        let (fulfillment_fee, peg_wallet_address) =
            if let Some(Some(recipient)) = tx.get_recipients().get(1) {
                (recipient.amount, recipient.address.clone())
            } else {
                warn!("Invalid tx: Second output not recognized");
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
            peg_wallet_address,
            fulfillment_fee,
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

    /// Recover the stacks address which was used by the sBTC holder to sign
    /// the amount and recipient fields of this peg out request.
    pub fn stx_address(&self, version: u8) -> Result<StacksAddress, RecoverError> {
        let script_pubkey = self.recipient.to_bitcoin_tx_out(0).script_pubkey;

        let mut msg = self.amount.to_be_bytes().to_vec();
        msg.extend_from_slice(script_pubkey.as_bytes());

        let msg_hash = Sha256Sum::from_data(&msg);
        let pub_key = StacksPublicKey::recover_to_pubkey(msg_hash.as_bytes(), &self.signature)
            .map_err(RecoverError::PubKeyRecoveryFailed)?;

        let hash_bits =
            public_keys_to_address_hash(&AddressHashMode::SerializeP2PKH, 1, &vec![pub_key]);
        Ok(StacksAddress::new(version, hash_bits))
    }

    pub fn check(&self) -> Result<(), OpError> {
        if self.amount == 0 {
            warn!("PEG_OUT_REQUEST Invalid: Requested BTC amount must be positive");
            return Err(OpError::AmountMustBePositive);
        }

        if self.fulfillment_fee == 0 {
            warn!("PEG_OUT_REQUEST Invalid: Fulfillment fee must be positive");
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

#[derive(Debug, PartialEq)]
enum ParseError {
    MalformedPayload,
    SliceConversion,
}

#[derive(Debug, PartialEq)]
pub enum RecoverError {
    PubKeyRecoveryFailed(&'static str),
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
    use stacks_common::deps_common::bitcoin::blockdata::transaction::Transaction;
    use stacks_common::deps_common::bitcoin::network::serialize::deserialize;
    use stacks_common::types::chainstate::BurnchainHeaderHash;
    use stacks_common::types::chainstate::StacksPrivateKey;
    use stacks_common::types::PrivateKey;
    use stacks_common::types::StacksEpochId;
    use stacks_common::util::hash::{hex_bytes, to_hex};

    use super::*;
    use crate::burnchains::bitcoin::blocks::BitcoinBlockParser;
    use crate::burnchains::bitcoin::BitcoinNetworkType;
    use crate::burnchains::Txid;
    use crate::burnchains::BLOCKSTACK_MAGIC_MAINNET;
    use crate::chainstate::burn::operations::test;
    use crate::chainstate::stacks::address::PoxAddress;
    use crate::chainstate::stacks::address::PoxAddressType32;
    use crate::chainstate::stacks::C32_ADDRESS_VERSION_TESTNET_SINGLESIG;

    #[test]
    fn test_parse_peg_out_request_should_succeed_given_a_conforming_transaction() {
        let mut rng = test::seeded_rng();
        let opcode = Opcodes::PegOutRequest;

        let dust_amount = 1;
        let recipient_address_bytes = test::random_bytes(&mut rng);
        let output2 = test::Output::new(dust_amount, recipient_address_bytes);

        let peg_wallet_address = test::random_bytes(&mut rng);
        let fulfillment_fee = 3;
        let output3 = test::Output::new(fulfillment_fee, peg_wallet_address);

        let mut data = vec![];
        let amount: u64 = 10;
        let signature: [u8; 65] = test::random_bytes(&mut rng);
        data.extend_from_slice(&amount.to_be_bytes());
        data.extend_from_slice(&signature);

        let tx = test::burnchain_transaction(data, [output2, output3], opcode);
        let header = test::burnchain_block_header();

        let op =
            PegOutRequestOp::from_tx(&header, &tx).expect("Failed to construct peg-out operation");

        assert_eq!(op.recipient.bytes(), recipient_address_bytes);
        assert_eq!(op.signature.as_bytes(), &signature);
        assert_eq!(op.amount, amount);
    }

    #[test]
    fn test_parse_peg_out_request_should_succeed_given_a_transaction_with_extra_memo_bytes() {
        let mut rng = test::seeded_rng();
        let opcode = Opcodes::PegOutRequest;

        let dust_amount = 1;
        let recipient_address_bytes = test::random_bytes(&mut rng);
        let output2 = test::Output::new(dust_amount, recipient_address_bytes);

        let peg_wallet_address = test::random_bytes(&mut rng);
        let fulfillment_fee = 3;
        let output3 = test::Output::new(fulfillment_fee, peg_wallet_address);

        let mut data = vec![];
        let amount: u64 = 10;
        let signature: [u8; 65] = test::random_bytes(&mut rng);
        data.extend_from_slice(&amount.to_be_bytes());
        data.extend_from_slice(&signature);
        let memo_bytes: [u8; 4] = test::random_bytes(&mut rng);
        data.extend_from_slice(&memo_bytes);

        let tx = test::burnchain_transaction(data, [output2, output3], opcode);
        let header = test::burnchain_block_header();

        let op =
            PegOutRequestOp::from_tx(&header, &tx).expect("Failed to construct peg-out operation");

        assert_eq!(op.recipient.bytes(), recipient_address_bytes);
        assert_eq!(op.signature.as_bytes(), &signature);
        assert_eq!(&op.memo, &memo_bytes);
        assert_eq!(op.amount, amount);
        assert_eq!(op.peg_wallet_address.bytes(), peg_wallet_address);
        assert_eq!(op.fulfillment_fee, fulfillment_fee);
    }

    #[test]
    fn test_parse_peg_out_request_should_return_error_given_wrong_opcode() {
        let mut rng = test::seeded_rng();
        let opcode = Opcodes::LeaderKeyRegister;

        let dust_amount = 1;
        let recipient_address_bytes = test::random_bytes(&mut rng);
        let output2 = test::Output::new(dust_amount, recipient_address_bytes);

        let peg_wallet_address = test::random_bytes(&mut rng);
        let fulfillment_fee = 3;
        let output3 = test::Output::new(fulfillment_fee, peg_wallet_address);

        let mut data = vec![];
        let amount: u64 = 10;
        let signature: [u8; 65] = test::random_bytes(&mut rng);
        data.extend_from_slice(&amount.to_be_bytes());
        data.extend_from_slice(&signature);

        let tx = test::burnchain_transaction(data, [output2, output3], opcode);
        let header = test::burnchain_block_header();

        let op = PegOutRequestOp::from_tx(&header, &tx);

        match op {
            Err(OpError::InvalidInput) => (),
            result => panic!("Expected OpError::InvalidInput, got {:?}", result),
        }
    }

    #[test]
    fn test_parse_peg_out_request_should_return_error_given_no_outputs() {
        let mut rng = test::seeded_rng();
        let opcode = Opcodes::PegOutRequest;

        let mut data = vec![];
        let amount: u64 = 10;
        let signature: [u8; 65] = test::random_bytes(&mut rng);
        data.extend_from_slice(&amount.to_be_bytes());
        data.extend_from_slice(&signature);

        let tx = test::burnchain_transaction(data, None, opcode);
        let header = test::burnchain_block_header();

        let op = PegOutRequestOp::from_tx(&header, &tx);

        match op {
            Err(OpError::InvalidInput) => (),
            result => panic!("Expected OpError::InvalidInput, got {:?}", result),
        }
    }

    #[test]
    fn test_parse_peg_out_request_should_return_error_given_no_third_output() {
        let mut rng = test::seeded_rng();
        let opcode = Opcodes::PegOutRequest;

        let dust_amount = 1;
        let recipient_address_bytes = test::random_bytes(&mut rng);
        let output2 = test::Output::new(dust_amount, recipient_address_bytes);

        let mut data = vec![];
        let amount: u64 = 10;
        let signature: [u8; 65] = test::random_bytes(&mut rng);
        data.extend_from_slice(&amount.to_be_bytes());
        data.extend_from_slice(&signature);

        let tx = test::burnchain_transaction(data, Some(output2), opcode);
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
        let output2 = test::Output::new(dust_amount, recipient_address_bytes);

        let peg_wallet_address = test::random_bytes(&mut rng);
        let fulfillment_fee = 3;
        let output3 = test::Output::new(fulfillment_fee, peg_wallet_address);

        let mut data = vec![];
        let amount: u64 = 10;
        let signature: [u8; 0] = test::random_bytes(&mut rng);
        data.extend_from_slice(&amount.to_be_bytes());
        data.extend_from_slice(&signature);

        let tx = test::burnchain_transaction(data, [output2, output3], opcode);
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
        let output2 = test::Output::new(dust_amount, recipient_address_bytes);

        let peg_wallet_address = test::random_bytes(&mut rng);

        let mut create_op = move |amount: u64, fulfillment_fee: u64| {
            let opcode = Opcodes::PegOutRequest;

            let mut data = vec![];
            let signature: [u8; 65] = test::random_bytes(&mut rng);
            data.extend_from_slice(&amount.to_be_bytes());
            data.extend_from_slice(&signature);

            let output3 = test::Output::new(fulfillment_fee, peg_wallet_address.clone());

            let tx = test::burnchain_transaction(data, [output2.clone(), output3.clone()], opcode);
            let header = test::burnchain_block_header();

            PegOutRequestOp::from_tx(&header, &tx)
                .expect("Failed to construct peg-out request operation")
        };

        match create_op(0, 1).check() {
            Err(OpError::AmountMustBePositive) => (),
            result => panic!(
                "Expected OpError::PegInAmountMustBePositive, got {:?}",
                result
            ),
        };

        match create_op(1, 0).check() {
            Err(OpError::AmountMustBePositive) => (),
            result => panic!(
                "Expected OpError::PegInAmountMustBePositive, got {:?}",
                result
            ),
        };

        create_op(1, 1)
            .check()
            .expect("Any strictly positive amounts should be ok");

        create_op(u64::MAX, 1)
            .check()
            .expect("Any strictly positive amounts should be ok");
    }

    #[test]
    fn test_stx_address_should_recover_the_same_address_used_to_sign_the_request() {
        let mut rng = test::seeded_rng();
        let opcode = Opcodes::PegOutRequest;

        let private_key = StacksPrivateKey::from_hex(
            "42faca653724860da7a41bfcef7e6ba78db55146f6900de8cb2a9f760ffac70c01",
        )
        .unwrap();

        let stx_address = StacksAddress::from_public_keys(
            C32_ADDRESS_VERSION_TESTNET_SINGLESIG,
            &AddressHashMode::SerializeP2PKH,
            1,
            &vec![StacksPublicKey::from_private(&private_key)],
        )
        .unwrap();

        let dust_amount = 1;
        let recipient_address_bytes = test::random_bytes(&mut rng);
        let output2 = test::Output::new(dust_amount, recipient_address_bytes);

        let peg_wallet_address = test::random_bytes(&mut rng);
        let fulfillment_fee = 3;
        let output3 = test::Output::new(fulfillment_fee, peg_wallet_address);

        let mut data = vec![];
        let amount: u64 = 10;

        let mut script_pubkey = vec![81, 32]; // OP_1 OP_PUSHBYTES_32
        script_pubkey.extend_from_slice(&recipient_address_bytes);

        let mut msg = amount.to_be_bytes().to_vec();
        msg.extend_from_slice(&script_pubkey);

        let msg_hash = Sha256Sum::from_data(&msg);

        let signature = private_key.sign(msg_hash.as_bytes()).unwrap();
        data.extend_from_slice(&amount.to_be_bytes());
        data.extend_from_slice(signature.as_bytes());

        let tx = test::burnchain_transaction(data, [output2, output3], opcode);
        let header = test::burnchain_block_header();

        let op =
            PegOutRequestOp::from_tx(&header, &tx).expect("Failed to construct peg-out operation");

        assert_eq!(
            op.stx_address(C32_ADDRESS_VERSION_TESTNET_SINGLESIG)
                .unwrap(),
            stx_address
        );
    }

    #[test]
    fn test_stx_address_should_fail_to_recover_stx_address_if_signature_is_noise() {
        let mut rng = test::seeded_rng();
        let opcode = Opcodes::PegOutRequest;

        let private_key = StacksPrivateKey::from_hex(
            "42faca653724860da7a41bfcef7e6ba78db55146f6900de8cb2a9f760ffac70c01",
        )
        .unwrap();

        let stx_address = StacksAddress::from_public_keys(
            C32_ADDRESS_VERSION_TESTNET_SINGLESIG,
            &AddressHashMode::SerializeP2PKH,
            1,
            &vec![StacksPublicKey::from_private(&private_key)],
        )
        .unwrap();

        let dust_amount = 1;
        let recipient_address_bytes = test::random_bytes(&mut rng);
        let output2 = test::Output::new(dust_amount, recipient_address_bytes);

        let peg_wallet_address = test::random_bytes(&mut rng);
        let fulfillment_fee = 3;
        let output3 = test::Output::new(fulfillment_fee, peg_wallet_address);

        let mut data = vec![];
        let amount: u64 = 10;

        let mut script_pubkey = vec![81, 32]; // OP_1 OP_PUSHBYTES_32
        script_pubkey.extend_from_slice(&recipient_address_bytes);

        let mut msg = amount.to_be_bytes().to_vec();
        msg.extend_from_slice(&script_pubkey);

        let msg_hash = Sha256Sum::from_data(&msg);

        let signature = MessageSignature(test::random_bytes(&mut rng));
        data.extend_from_slice(&amount.to_be_bytes());
        data.extend_from_slice(signature.as_bytes());

        let tx = test::burnchain_transaction(data, [output2, output3], opcode);
        let header = test::burnchain_block_header();

        let op =
            PegOutRequestOp::from_tx(&header, &tx).expect("Failed to construct peg-out operation");

        assert_eq!(
            op.stx_address(C32_ADDRESS_VERSION_TESTNET_SINGLESIG)
                .unwrap_err(),
            RecoverError::PubKeyRecoveryFailed(
                "Invalid signature: failed to decode recoverable signature"
            ),
        );
    }

    #[test]
    fn test_stx_address_with_hard_coded_fixtures() {
        let vtxindex = 1;
        let _block_height = 694;
        let burn_header_hash = BurnchainHeaderHash::from_hex(
            "0000000000000000000000000000000000000000000000000000000000000000",
        )
        .unwrap();

        let fixtures = [
            OpFixture {
            txstr: "02000000010000000000000000000000000000000000000000000000000000000000000000ffffffff00ffffffff0300000000000000004f6a4c4c69643e000000000000053900dc18d08e2ee9f476a89c4c195edd402610176bb6264ec56f3f9e42e7386c543846e09282b6f03495c663c8509df7c97ffbcd2adc537bbabe23abd828a52bc8cd390500000000000022512000000000000000000000000000000000000000000000000000000000000000002a00000000000000225120000000000000000000000000000000000000000000000000000000000000000000000000",
            signer: StacksAddress::from_string("ST3W2ATS1H9RF29DMYW5QP7NYJ643WNP2YFT4Z45C").unwrap(),
            result: Ok(PegOutRequestOp {
                amount: 1337,
                recipient: PoxAddress::Addr32(false, PoxAddressType32::P2TR, [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0]),
                signature: MessageSignature::from_hex("00dc18d08e2ee9f476a89c4c195edd402610176bb6264ec56f3f9e42e7386c543846e09282b6f03495c663c8509df7c97ffbcd2adc537bbabe23abd828a52bc8cd").unwrap(),
                peg_wallet_address: PoxAddress::Addr32(false, PoxAddressType32::P2TR, [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0]),
                fulfillment_fee: 42, memo: vec![], txid: Txid::from_hex("44a2aea3936f7764b4c089d3245b001069e0961e501fcb0024277ea9dedb2fea").unwrap(),
                vtxindex: 1,
                block_height: 0,
                burn_header_hash: BurnchainHeaderHash::from_hex("0000000000000000000000000000000000000000000000000000000000000000").unwrap() }),
            },
            OpFixture {
            txstr: "02000000010000000000000000000000000000000000000000000000000000000000000000ffffffff00ffffffff030000000000000000536a4c5069643e000000000000053900dc18d08e2ee9f476a89c4c195edd402610176bb6264ec56f3f9e42e7386c543846e09282b6f03495c663c8509df7c97ffbcd2adc537bbabe23abd828a52bc8cddeadbeef390500000000000022512000000000000000000000000000000000000000000000000000000000000000002a00000000000000225120000000000000000000000000000000000000000000000000000000000000000000000000",
            signer: StacksAddress::from_string("ST3W2ATS1H9RF29DMYW5QP7NYJ643WNP2YFT4Z45C").unwrap(),
            result: Ok(PegOutRequestOp {
                amount: 1337,
                recipient: PoxAddress::Addr32(false, PoxAddressType32::P2TR, [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0]),
                signature: MessageSignature::from_hex("00dc18d08e2ee9f476a89c4c195edd402610176bb6264ec56f3f9e42e7386c543846e09282b6f03495c663c8509df7c97ffbcd2adc537bbabe23abd828a52bc8cd").unwrap(),
                peg_wallet_address: PoxAddress::Addr32(false, PoxAddressType32::P2TR, [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0]),
                fulfillment_fee: 42, memo: vec![222, 173, 190, 239], txid: Txid::from_hex("7431035f255c4ce215b66883d67e593f392b0b2026c24186e650019872b6f095").unwrap(),
                vtxindex: 1,
                block_height: 0,
                burn_header_hash: BurnchainHeaderHash::from_hex("0000000000000000000000000000000000000000000000000000000000000000").unwrap() }),
            },
        ];

        let parser = BitcoinBlockParser::new(BitcoinNetworkType::Testnet, BLOCKSTACK_MAGIC_MAINNET);

        for fixture in fixtures {
            let tx = make_tx(&fixture.txstr).unwrap();
            let burnchain_tx = BurnchainTransaction::Bitcoin(
                parser
                    .parse_tx(&tx, vtxindex as usize, StacksEpochId::Epoch21)
                    .unwrap(),
            );

            let header = match fixture.result {
                Ok(ref op) => BurnchainBlockHeader {
                    block_height: op.block_height,
                    block_hash: op.burn_header_hash.clone(),
                    parent_block_hash: op.burn_header_hash.clone(),
                    num_txs: 1,
                    timestamp: 0,
                },
                Err(_) => BurnchainBlockHeader {
                    block_height: 0,
                    block_hash: BurnchainHeaderHash::zero(),
                    parent_block_hash: BurnchainHeaderHash::zero(),
                    num_txs: 0,
                    timestamp: 0,
                },
            };

            let result = PegOutRequestOp::from_tx(&header, &burnchain_tx);

            match (result, fixture.result) {
                (Ok(actual), Ok(expected)) => {
                    assert_eq!(actual, expected);
                    assert_eq!(
                        actual
                            .stx_address(C32_ADDRESS_VERSION_TESTNET_SINGLESIG)
                            .unwrap(),
                        fixture.signer
                    );
                }
                _ => panic!("Unsupported test scenario"),
            }
        }
    }

    pub struct OpFixture {
        txstr: &'static str,
        signer: StacksAddress,
        result: Result<PegOutRequestOp, OpError>,
    }

    fn make_tx(hex_str: &str) -> Result<Transaction, &'static str> {
        let tx_bin = hex_bytes(hex_str).map_err(|_e| "failed to decode hex string")?;
        let tx = deserialize(&tx_bin.to_vec()).map_err(|_e| "failed to deserialize")?;
        Ok(tx)
    }
}
