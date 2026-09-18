// Copyright (C) 2013-2020 Blockstack PBC, a public benefit corporation
// Copyright (C) 2020-2026 Stacks Open Internet Foundation
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

#[cfg(test)]
mod test {
    use stacks_common::codec::StacksMessageCodec;
    use stacks_common::types::StacksEpochId;
    use stacks_common::util::hash::Hash160;
    use stacks_common::util::secp256k1::MessageSignature;

    use crate::burnchains::Txid;
    use crate::chainstate::stacks::{
        MultisigHashMode, MultisigSpendingCondition, OrderIndependentMultisigHashMode,
        OrderIndependentMultisigSpendingCondition, SinglesigHashMode, SinglesigSpendingCondition,
        StacksPrivateKey, StacksPublicKey, StacksPublicKey as PubKey, TransactionAuth,
        TransactionAuthField, TransactionAuthFieldID, TransactionAuthFlags,
        TransactionAuthVerificationMode, TransactionPublicKeyEncoding,
        TransactionSpendingCondition,
    };
    use crate::net::codec::test::check_codec_and_corruption;

    #[test]
    fn tx_stacks_spending_condition_p2pkh() {
        // p2pkh
        let spending_condition_p2pkh_uncompressed = SinglesigSpendingCondition {
            signer: Hash160([0x11; 20]),
            hash_mode: SinglesigHashMode::P2PKH,
            key_encoding: TransactionPublicKeyEncoding::Uncompressed,
            nonce: 123,
            tx_fee: 456,
            signature: MessageSignature::from_raw(&[0xff; 65]),
        };

        #[rustfmt::skip]
        let spending_condition_p2pkh_uncompressed_bytes = vec![
            // hash mode
            SinglesigHashMode::P2PKH as u8,
            // signer
            0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11,
            // nonce
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x7b,
            // fee rate
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01, 0xc8,
            // key encoding,
            TransactionPublicKeyEncoding::Uncompressed as u8,
            // signature
            0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
        ];

        let spending_condition_p2pkh_compressed = SinglesigSpendingCondition {
            signer: Hash160([0x11; 20]),
            hash_mode: SinglesigHashMode::P2PKH,
            key_encoding: TransactionPublicKeyEncoding::Compressed,
            nonce: 345,
            tx_fee: 456,
            signature: MessageSignature::from_raw(&[0xfe; 65]),
        };

        #[rustfmt::skip]
        let spending_condition_p2pkh_compressed_bytes = vec![
            // hash mode
            SinglesigHashMode::P2PKH as u8,
            // signer
            0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11,
            // nonce
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01, 0x59,
            // fee rate
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01, 0xc8,
            // key encoding
            TransactionPublicKeyEncoding::Compressed as u8,
            // signature
            0xfe, 0xfe, 0xfe, 0xfe, 0xfe, 0xfe, 0xfe, 0xfe, 0xfe, 0xfe, 0xfe, 0xfe, 0xfe, 0xfe, 0xfe, 0xfe, 0xfe, 0xfe, 0xfe, 0xfe, 0xfe, 0xfe, 0xfe, 0xfe, 0xfe, 0xfe, 0xfe, 0xfe, 0xfe, 0xfe, 0xfe, 0xfe, 0xfe, 0xfe, 0xfe, 0xfe, 0xfe, 0xfe, 0xfe, 0xfe, 0xfe, 0xfe, 0xfe, 0xfe, 0xfe, 0xfe, 0xfe, 0xfe, 0xfe, 0xfe, 0xfe, 0xfe, 0xfe, 0xfe, 0xfe, 0xfe, 0xfe, 0xfe, 0xfe, 0xfe, 0xfe, 0xfe, 0xfe, 0xfe, 0xfe,
        ];

        let spending_conditions = [
            spending_condition_p2pkh_compressed,
            spending_condition_p2pkh_uncompressed,
        ];
        let spending_conditions_bytes = [
            spending_condition_p2pkh_compressed_bytes,
            spending_condition_p2pkh_uncompressed_bytes,
        ];

        for i in 0..spending_conditions.len() {
            check_codec_and_corruption::<SinglesigSpendingCondition>(
                &spending_conditions[i],
                &spending_conditions_bytes[i],
            );
        }
    }

    #[test]
    fn tx_stacks_spending_condition_p2sh() {
        // p2sh
        let spending_condition_p2sh_uncompressed = MultisigSpendingCondition {
            signer: Hash160([0x11; 20]),
            hash_mode: MultisigHashMode::P2SH,
            nonce: 123,
            tx_fee: 456,
            fields: vec![
                TransactionAuthField::Signature(TransactionPublicKeyEncoding::Uncompressed, MessageSignature::from_raw(&[0xff; 65])),
                TransactionAuthField::Signature(TransactionPublicKeyEncoding::Uncompressed, MessageSignature::from_raw(&[0xfe; 65])),
                TransactionAuthField::PublicKey(PubKey::from_hex("04ef2340518b5867b23598a9cf74611f8b98064f7d55cdb8c107c67b5efcbc5c771f112f919b00a6c6c5f51f7c63e1762fe9fac9b66ec75a053db7f51f4a52712b").unwrap()),
            ],
            signatures_required: 2
        };

        #[rustfmt::skip]
        let spending_condition_p2sh_uncompressed_bytes = vec![
            // hash mode
            MultisigHashMode::P2SH as u8,
            // signer
            0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11,
            // nonce
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x7b,
            // fee rate
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01, 0xc8,
            // fields length
            0x00, 0x00, 0x00, 0x03,
            // field #1: signature
            TransactionAuthFieldID::SignatureUncompressed as u8,
            // field #1: signature
            0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
            // field #2: signature
            TransactionAuthFieldID::SignatureUncompressed as u8,
            // filed #2: signature
            0xfe, 0xfe, 0xfe, 0xfe, 0xfe, 0xfe, 0xfe, 0xfe, 0xfe, 0xfe, 0xfe, 0xfe, 0xfe, 0xfe, 0xfe, 0xfe, 0xfe, 0xfe, 0xfe, 0xfe, 0xfe, 0xfe, 0xfe, 0xfe, 0xfe, 0xfe, 0xfe, 0xfe, 0xfe, 0xfe, 0xfe, 0xfe, 0xfe, 0xfe, 0xfe, 0xfe, 0xfe, 0xfe, 0xfe, 0xfe, 0xfe, 0xfe, 0xfe, 0xfe, 0xfe, 0xfe, 0xfe, 0xfe, 0xfe, 0xfe, 0xfe, 0xfe, 0xfe, 0xfe, 0xfe, 0xfe, 0xfe, 0xfe, 0xfe, 0xfe, 0xfe, 0xfe, 0xfe, 0xfe, 0xfe,
            // field #3: public key
            TransactionAuthFieldID::PublicKeyUncompressed as u8,
            // field #3: key (uncompressed)
            0x03, 0xef, 0x23, 0x40, 0x51, 0x8b, 0x58, 0x67, 0xb2, 0x35, 0x98, 0xa9, 0xcf, 0x74, 0x61, 0x1f, 0x8b, 0x98, 0x06, 0x4f, 0x7d, 0x55, 0xcd, 0xb8, 0xc1, 0x07, 0xc6, 0x7b, 0x5e, 0xfc, 0xbc, 0x5c, 0x77,
            // number of signatures required
            0x00, 0x02,
        ];

        let spending_condition_p2sh_compressed = MultisigSpendingCondition {
            signer: Hash160([0x11; 20]),
            hash_mode: MultisigHashMode::P2SH,
            nonce: 456,
            tx_fee: 567,
            fields: vec![
                TransactionAuthField::Signature(
                    TransactionPublicKeyEncoding::Compressed,
                    MessageSignature::from_raw(&[0xff; 65]),
                ),
                TransactionAuthField::Signature(
                    TransactionPublicKeyEncoding::Compressed,
                    MessageSignature::from_raw(&[0xfe; 65]),
                ),
                TransactionAuthField::PublicKey(
                    PubKey::from_hex(
                        "03ef2340518b5867b23598a9cf74611f8b98064f7d55cdb8c107c67b5efcbc5c77",
                    )
                    .unwrap(),
                ),
            ],
            signatures_required: 2,
        };

        #[rustfmt::skip]
        let spending_condition_p2sh_compressed_bytes = vec![
            // hash mode
            MultisigHashMode::P2SH as u8,
            // signer
            0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11,
            // nonce
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01, 0xc8,
            // fee rate
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x02, 0x37,
            // fields length
            0x00, 0x00, 0x00, 0x03,
            // field #1: signature
            TransactionAuthFieldID::SignatureCompressed as u8,
            // field #1: signature
            0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
            // field #2: signature
            TransactionAuthFieldID::SignatureCompressed as u8,
            // filed #2: signature
            0xfe, 0xfe, 0xfe, 0xfe, 0xfe, 0xfe, 0xfe, 0xfe, 0xfe, 0xfe, 0xfe, 0xfe, 0xfe, 0xfe, 0xfe, 0xfe, 0xfe, 0xfe, 0xfe, 0xfe, 0xfe, 0xfe, 0xfe, 0xfe, 0xfe, 0xfe, 0xfe, 0xfe, 0xfe, 0xfe, 0xfe, 0xfe, 0xfe, 0xfe, 0xfe, 0xfe, 0xfe, 0xfe, 0xfe, 0xfe, 0xfe, 0xfe, 0xfe, 0xfe, 0xfe, 0xfe, 0xfe, 0xfe, 0xfe, 0xfe, 0xfe, 0xfe, 0xfe, 0xfe, 0xfe, 0xfe, 0xfe, 0xfe, 0xfe, 0xfe, 0xfe, 0xfe, 0xfe, 0xfe, 0xfe,
            // field #3: public key
            TransactionAuthFieldID::PublicKeyCompressed as u8,
            // field #3: key (compressed)
            0x03, 0xef, 0x23, 0x40, 0x51, 0x8b, 0x58, 0x67, 0xb2, 0x35, 0x98, 0xa9, 0xcf, 0x74, 0x61, 0x1f, 0x8b, 0x98, 0x06, 0x4f, 0x7d, 0x55, 0xcd, 0xb8, 0xc1, 0x07, 0xc6, 0x7b, 0x5e, 0xfc, 0xbc, 0x5c, 0x77,
            // number of signatures
            0x00, 0x02,
        ];

        let spending_conditions = [
            spending_condition_p2sh_compressed,
            spending_condition_p2sh_uncompressed,
        ];
        let spending_conditions_bytes = [
            spending_condition_p2sh_compressed_bytes,
            spending_condition_p2sh_uncompressed_bytes,
        ];

        for i in 0..spending_conditions.len() {
            check_codec_and_corruption::<MultisigSpendingCondition>(
                &spending_conditions[i],
                &spending_conditions_bytes[i],
            );
        }
    }

    #[test]
    fn tx_stacks_spending_condition_order_independent_p2sh() {
        // order independent p2sh
        let spending_condition_order_independent_p2sh_uncompressed = OrderIndependentMultisigSpendingCondition {
            signer: Hash160([0x11; 20]),
            hash_mode: OrderIndependentMultisigHashMode::P2SH,
            nonce: 123,
            tx_fee: 456,
            fields: vec![
                TransactionAuthField::Signature(TransactionPublicKeyEncoding::Uncompressed, MessageSignature::from_raw(&[0xff; 65])),
                TransactionAuthField::Signature(TransactionPublicKeyEncoding::Uncompressed, MessageSignature::from_raw(&[0xfe; 65])),
                TransactionAuthField::PublicKey(PubKey::from_hex("04ef2340518b5867b23598a9cf74611f8b98064f7d55cdb8c107c67b5efcbc5c771f112f919b00a6c6c5f51f7c63e1762fe9fac9b66ec75a053db7f51f4a52712b").unwrap()),
            ],
            signatures_required: 2
        };

        #[rustfmt::skip]
        let spending_condition_order_independent_p2sh_uncompressed_bytes = vec![
            // hash mode
            OrderIndependentMultisigHashMode::P2SH as u8,
            // signer
            0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11,
            // nonce
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x7b,
            // fee rate
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01, 0xc8,
            // fields length
            0x00, 0x00, 0x00, 0x03,
            // field #1: signature
            TransactionAuthFieldID::SignatureUncompressed as u8,
            // field #1: signature
            0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
            // field #2: signature
            TransactionAuthFieldID::SignatureUncompressed as u8,
            // filed #2: signature
            0xfe, 0xfe, 0xfe, 0xfe, 0xfe, 0xfe, 0xfe, 0xfe, 0xfe, 0xfe, 0xfe, 0xfe, 0xfe, 0xfe, 0xfe, 0xfe, 0xfe, 0xfe, 0xfe, 0xfe, 0xfe, 0xfe, 0xfe, 0xfe, 0xfe, 0xfe, 0xfe, 0xfe, 0xfe, 0xfe, 0xfe, 0xfe, 0xfe, 0xfe, 0xfe, 0xfe, 0xfe, 0xfe, 0xfe, 0xfe, 0xfe, 0xfe, 0xfe, 0xfe, 0xfe, 0xfe, 0xfe, 0xfe, 0xfe, 0xfe, 0xfe, 0xfe, 0xfe, 0xfe, 0xfe, 0xfe, 0xfe, 0xfe, 0xfe, 0xfe, 0xfe, 0xfe, 0xfe, 0xfe, 0xfe,
            // field #3: public key
            TransactionAuthFieldID::PublicKeyUncompressed as u8,
            // field #3: key (uncompressed)
            0x03, 0xef, 0x23, 0x40, 0x51, 0x8b, 0x58, 0x67, 0xb2, 0x35, 0x98, 0xa9, 0xcf, 0x74, 0x61, 0x1f, 0x8b, 0x98, 0x06, 0x4f, 0x7d, 0x55, 0xcd, 0xb8, 0xc1, 0x07, 0xc6, 0x7b, 0x5e, 0xfc, 0xbc, 0x5c, 0x77,
            // number of signatures required
            0x00, 0x02,
        ];

        let spending_condition_order_independent_p2sh_compressed =
            OrderIndependentMultisigSpendingCondition {
                signer: Hash160([0x11; 20]),
                hash_mode: OrderIndependentMultisigHashMode::P2SH,
                nonce: 456,
                tx_fee: 567,
                fields: vec![
                    TransactionAuthField::Signature(
                        TransactionPublicKeyEncoding::Compressed,
                        MessageSignature::from_raw(&[0xff; 65]),
                    ),
                    TransactionAuthField::Signature(
                        TransactionPublicKeyEncoding::Compressed,
                        MessageSignature::from_raw(&[0xfe; 65]),
                    ),
                    TransactionAuthField::PublicKey(
                        PubKey::from_hex(
                            "03ef2340518b5867b23598a9cf74611f8b98064f7d55cdb8c107c67b5efcbc5c77",
                        )
                        .unwrap(),
                    ),
                ],
                signatures_required: 2,
            };

        #[rustfmt::skip]
        let spending_condition_order_independent_p2sh_compressed_bytes = vec![
            // hash mode
            OrderIndependentMultisigHashMode::P2SH as u8,
            // signer
            0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11,
            // nonce
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01, 0xc8,
            // fee rate
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x02, 0x37,
            // fields length
            0x00, 0x00, 0x00, 0x03,
            // field #1: signature
            TransactionAuthFieldID::SignatureCompressed as u8,
            // field #1: signature
            0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
            // field #2: signature
            TransactionAuthFieldID::SignatureCompressed as u8,
            // filed #2: signature
            0xfe, 0xfe, 0xfe, 0xfe, 0xfe, 0xfe, 0xfe, 0xfe, 0xfe, 0xfe, 0xfe, 0xfe, 0xfe, 0xfe, 0xfe, 0xfe, 0xfe, 0xfe, 0xfe, 0xfe, 0xfe, 0xfe, 0xfe, 0xfe, 0xfe, 0xfe, 0xfe, 0xfe, 0xfe, 0xfe, 0xfe, 0xfe, 0xfe, 0xfe, 0xfe, 0xfe, 0xfe, 0xfe, 0xfe, 0xfe, 0xfe, 0xfe, 0xfe, 0xfe, 0xfe, 0xfe, 0xfe, 0xfe, 0xfe, 0xfe, 0xfe, 0xfe, 0xfe, 0xfe, 0xfe, 0xfe, 0xfe, 0xfe, 0xfe, 0xfe, 0xfe, 0xfe, 0xfe, 0xfe, 0xfe,
            // field #3: public key
            TransactionAuthFieldID::PublicKeyCompressed as u8,
            // field #3: key (compressed)
            0x03, 0xef, 0x23, 0x40, 0x51, 0x8b, 0x58, 0x67, 0xb2, 0x35, 0x98, 0xa9, 0xcf, 0x74, 0x61, 0x1f, 0x8b, 0x98, 0x06, 0x4f, 0x7d, 0x55, 0xcd, 0xb8, 0xc1, 0x07, 0xc6, 0x7b, 0x5e, 0xfc, 0xbc, 0x5c, 0x77,
            // number of signatures
            0x00, 0x02,
        ];

        let spending_conditions = [
            spending_condition_order_independent_p2sh_compressed,
            spending_condition_order_independent_p2sh_uncompressed,
        ];
        let spending_conditions_bytes = [
            spending_condition_order_independent_p2sh_compressed_bytes,
            spending_condition_order_independent_p2sh_uncompressed_bytes,
        ];

        for i in 0..spending_conditions.len() {
            check_codec_and_corruption::<OrderIndependentMultisigSpendingCondition>(
                &spending_conditions[i],
                &spending_conditions_bytes[i],
            );
        }
    }

    #[test]
    fn tx_stacks_spending_condition_p2wpkh() {
        let spending_condition_p2wpkh_compressed = SinglesigSpendingCondition {
            signer: Hash160([0x11; 20]),
            hash_mode: SinglesigHashMode::P2WPKH,
            key_encoding: TransactionPublicKeyEncoding::Compressed,
            nonce: 345,
            tx_fee: 567,
            signature: MessageSignature::from_raw(&[0xfe; 65]),
        };

        #[rustfmt::skip]
        let spending_condition_p2wpkh_compressed_bytes = vec![
            // hash mode
            SinglesigHashMode::P2WPKH as u8,
            // signer
            0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11,
            // nonce
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01, 0x59,
            // fee rate
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x02, 0x37,
            // key encoding
            TransactionPublicKeyEncoding::Compressed as u8,
            // signature
            0xfe, 0xfe, 0xfe, 0xfe, 0xfe, 0xfe, 0xfe, 0xfe, 0xfe, 0xfe, 0xfe, 0xfe, 0xfe, 0xfe, 0xfe, 0xfe, 0xfe, 0xfe, 0xfe, 0xfe, 0xfe, 0xfe, 0xfe, 0xfe, 0xfe, 0xfe, 0xfe, 0xfe, 0xfe, 0xfe, 0xfe, 0xfe, 0xfe, 0xfe, 0xfe, 0xfe, 0xfe, 0xfe, 0xfe, 0xfe, 0xfe, 0xfe, 0xfe, 0xfe, 0xfe, 0xfe, 0xfe, 0xfe, 0xfe, 0xfe, 0xfe, 0xfe, 0xfe, 0xfe, 0xfe, 0xfe, 0xfe, 0xfe, 0xfe, 0xfe, 0xfe, 0xfe, 0xfe, 0xfe, 0xfe,
        ];

        check_codec_and_corruption::<SinglesigSpendingCondition>(
            &spending_condition_p2wpkh_compressed,
            &spending_condition_p2wpkh_compressed_bytes,
        );
    }

    #[test]
    fn tx_stacks_spending_condition_p2wsh() {
        let spending_condition_p2wsh = MultisigSpendingCondition {
            signer: Hash160([0x11; 20]),
            hash_mode: MultisigHashMode::P2WSH,
            nonce: 456,
            tx_fee: 567,
            fields: vec![
                TransactionAuthField::Signature(
                    TransactionPublicKeyEncoding::Compressed,
                    MessageSignature::from_raw(&[0xff; 65]),
                ),
                TransactionAuthField::Signature(
                    TransactionPublicKeyEncoding::Compressed,
                    MessageSignature::from_raw(&[0xfe; 65]),
                ),
                TransactionAuthField::PublicKey(
                    PubKey::from_hex(
                        "03ef2340518b5867b23598a9cf74611f8b98064f7d55cdb8c107c67b5efcbc5c77",
                    )
                    .unwrap(),
                ),
            ],
            signatures_required: 2,
        };

        #[rustfmt::skip]
        let spending_condition_p2wsh_bytes = vec![
            // hash mode
            MultisigHashMode::P2WSH as u8,
            // signer
            0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11,
            // nonce
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01, 0xc8,
            // fee rate
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x02, 0x37,
            // fields length
            0x00, 0x00, 0x00, 0x03,
            // field #1: signature
            TransactionAuthFieldID::SignatureCompressed as u8,
            // field #1: signature
            0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
            // field #2: signature
            TransactionAuthFieldID::SignatureCompressed as u8,
            // filed #2: signature
            0xfe, 0xfe, 0xfe, 0xfe, 0xfe, 0xfe, 0xfe, 0xfe, 0xfe, 0xfe, 0xfe, 0xfe, 0xfe, 0xfe, 0xfe, 0xfe, 0xfe, 0xfe, 0xfe, 0xfe, 0xfe, 0xfe, 0xfe, 0xfe, 0xfe, 0xfe, 0xfe, 0xfe, 0xfe, 0xfe, 0xfe, 0xfe, 0xfe, 0xfe, 0xfe, 0xfe, 0xfe, 0xfe, 0xfe, 0xfe, 0xfe, 0xfe, 0xfe, 0xfe, 0xfe, 0xfe, 0xfe, 0xfe, 0xfe, 0xfe, 0xfe, 0xfe, 0xfe, 0xfe, 0xfe, 0xfe, 0xfe, 0xfe, 0xfe, 0xfe, 0xfe, 0xfe, 0xfe, 0xfe, 0xfe,
            // field #3: public key
            TransactionAuthFieldID::PublicKeyCompressed as u8,
            // field #3: key (compressed)
            0x03, 0xef, 0x23, 0x40, 0x51, 0x8b, 0x58, 0x67, 0xb2, 0x35, 0x98, 0xa9, 0xcf, 0x74, 0x61, 0x1f, 0x8b, 0x98, 0x06, 0x4f, 0x7d, 0x55, 0xcd, 0xb8, 0xc1, 0x07, 0xc6, 0x7b, 0x5e, 0xfc, 0xbc, 0x5c, 0x77,
            // number of signatures
            0x00, 0x02,
        ];

        check_codec_and_corruption::<MultisigSpendingCondition>(
            &spending_condition_p2wsh,
            &spending_condition_p2wsh_bytes,
        );
    }

    #[test]
    fn tx_stacks_auth() {
        // same spending conditions above
        let spending_conditions = vec![
            TransactionSpendingCondition::Singlesig(SinglesigSpendingCondition {
                signer: Hash160([0x11; 20]),
                hash_mode: SinglesigHashMode::P2PKH,
                key_encoding: TransactionPublicKeyEncoding::Uncompressed,
                nonce: 123,
                tx_fee: 567,
                signature: MessageSignature::from_raw(&[0xff; 65])
            }),
            TransactionSpendingCondition::Singlesig(SinglesigSpendingCondition {
                signer: Hash160([0x11; 20]),
                hash_mode: SinglesigHashMode::P2PKH,
                key_encoding: TransactionPublicKeyEncoding::Compressed,
                nonce: 345,
                tx_fee: 567,
                signature: MessageSignature::from_raw(&[0xff; 65])
            }),
            TransactionSpendingCondition::Multisig(MultisigSpendingCondition {
                signer: Hash160([0x11; 20]),
                hash_mode: MultisigHashMode::P2SH,
                nonce: 123,
                tx_fee: 567,
                fields: vec![
                    TransactionAuthField::Signature(TransactionPublicKeyEncoding::Uncompressed, MessageSignature::from_raw(&[0xff; 65])),
                    TransactionAuthField::Signature(TransactionPublicKeyEncoding::Uncompressed, MessageSignature::from_raw(&[0xfe; 65])),
                    TransactionAuthField::PublicKey(PubKey::from_hex("04ef2340518b5867b23598a9cf74611f8b98064f7d55cdb8c107c67b5efcbc5c771f112f919b00a6c6c5f51f7c63e1762fe9fac9b66ec75a053db7f51f4a52712b").unwrap()),
                ],
                signatures_required: 2
            }),
            TransactionSpendingCondition::Multisig(MultisigSpendingCondition {
                signer: Hash160([0x11; 20]),
                hash_mode: MultisigHashMode::P2SH,
                nonce: 456,
                tx_fee: 567,
                fields: vec![
                    TransactionAuthField::Signature(TransactionPublicKeyEncoding::Compressed, MessageSignature::from_raw(&[0xff; 65])),
                    TransactionAuthField::Signature(TransactionPublicKeyEncoding::Compressed, MessageSignature::from_raw(&[0xfe; 65])),
                    TransactionAuthField::PublicKey(PubKey::from_hex("03ef2340518b5867b23598a9cf74611f8b98064f7d55cdb8c107c67b5efcbc5c77").unwrap())
                ],
                signatures_required: 2
            }),
            TransactionSpendingCondition::OrderIndependentMultisig(OrderIndependentMultisigSpendingCondition {
                signer: Hash160([0x11; 20]),
                hash_mode: OrderIndependentMultisigHashMode::P2SH,
                nonce: 123,
                tx_fee: 567,
                fields: vec![
                    TransactionAuthField::Signature(TransactionPublicKeyEncoding::Uncompressed, MessageSignature::from_raw(&[0xff; 65])),
                    TransactionAuthField::Signature(TransactionPublicKeyEncoding::Uncompressed, MessageSignature::from_raw(&[0xfe; 65])),
                    TransactionAuthField::PublicKey(PubKey::from_hex("04ef2340518b5867b23598a9cf74611f8b98064f7d55cdb8c107c67b5efcbc5c771f112f919b00a6c6c5f51f7c63e1762fe9fac9b66ec75a053db7f51f4a52712b").unwrap()),
                ],
                signatures_required: 2
            }),
            TransactionSpendingCondition::OrderIndependentMultisig(OrderIndependentMultisigSpendingCondition {
                signer: Hash160([0x11; 20]),
                hash_mode: OrderIndependentMultisigHashMode::P2SH,
                nonce: 456,
                tx_fee: 567,
                fields: vec![
                    TransactionAuthField::Signature(TransactionPublicKeyEncoding::Compressed, MessageSignature::from_raw(&[0xff; 65])),
                    TransactionAuthField::Signature(TransactionPublicKeyEncoding::Compressed, MessageSignature::from_raw(&[0xfe; 65])),
                    TransactionAuthField::PublicKey(PubKey::from_hex("03ef2340518b5867b23598a9cf74611f8b98064f7d55cdb8c107c67b5efcbc5c77").unwrap())
                ],
                signatures_required: 2
            }),
            TransactionSpendingCondition::OrderIndependentMultisig(OrderIndependentMultisigSpendingCondition {
                signer: Hash160([0x11; 20]),
                hash_mode: OrderIndependentMultisigHashMode::P2SH,
                nonce: 123,
                tx_fee: 567,
                fields: vec![
                    TransactionAuthField::Signature(TransactionPublicKeyEncoding::Uncompressed, MessageSignature::from_raw(&[0xff; 65])),
                    TransactionAuthField::Signature(TransactionPublicKeyEncoding::Uncompressed, MessageSignature::from_raw(&[0xfe; 65])),
                    TransactionAuthField::Signature(TransactionPublicKeyEncoding::Uncompressed, MessageSignature::from_raw(&[0xfd; 65])),
                ],
                signatures_required: 1
            }),
            TransactionSpendingCondition::OrderIndependentMultisig(OrderIndependentMultisigSpendingCondition {
                signer: Hash160([0x11; 20]),
                hash_mode: OrderIndependentMultisigHashMode::P2SH,
                nonce: 456,
                tx_fee: 567,
                fields: vec![
                    TransactionAuthField::Signature(TransactionPublicKeyEncoding::Compressed, MessageSignature::from_raw(&[0xff; 65])),
                    TransactionAuthField::Signature(TransactionPublicKeyEncoding::Compressed, MessageSignature::from_raw(&[0xfe; 65])),
                    TransactionAuthField::Signature(TransactionPublicKeyEncoding::Compressed, MessageSignature::from_raw(&[0xfd; 65])),
                ],
                signatures_required: 1
            }),
            TransactionSpendingCondition::Singlesig(SinglesigSpendingCondition {
                signer: Hash160([0x11; 20]),
                hash_mode: SinglesigHashMode::P2WPKH,
                key_encoding: TransactionPublicKeyEncoding::Compressed,
                nonce: 345,
                tx_fee: 567,
                signature: MessageSignature::from_raw(&[0xfe; 65]),
            }),
            TransactionSpendingCondition::Multisig(MultisigSpendingCondition {
                signer: Hash160([0x11; 20]),
                hash_mode: MultisigHashMode::P2WSH,
                nonce: 456,
                tx_fee: 567,
                fields: vec![
                    TransactionAuthField::Signature(TransactionPublicKeyEncoding::Compressed, MessageSignature::from_raw(&[0xff; 65])),
                    TransactionAuthField::Signature(TransactionPublicKeyEncoding::Compressed, MessageSignature::from_raw(&[0xfe; 65])),
                    TransactionAuthField::PublicKey(PubKey::from_hex("03ef2340518b5867b23598a9cf74611f8b98064f7d55cdb8c107c67b5efcbc5c77").unwrap())
                ],
                signatures_required: 2
            }),
            TransactionSpendingCondition::OrderIndependentMultisig(OrderIndependentMultisigSpendingCondition {
                signer: Hash160([0x11; 20]),
                hash_mode: OrderIndependentMultisigHashMode::P2WSH,
                nonce: 456,
                tx_fee: 567,
                fields: vec![
                    TransactionAuthField::Signature(TransactionPublicKeyEncoding::Compressed, MessageSignature::from_raw(&[0xff; 65])),
                    TransactionAuthField::Signature(TransactionPublicKeyEncoding::Compressed, MessageSignature::from_raw(&[0xfe; 65])),
                    TransactionAuthField::PublicKey(PubKey::from_hex("03ef2340518b5867b23598a9cf74611f8b98064f7d55cdb8c107c67b5efcbc5c77").unwrap())
                ],
                signatures_required: 2
            }),
            TransactionSpendingCondition::OrderIndependentMultisig(OrderIndependentMultisigSpendingCondition {
                signer: Hash160([0x11; 20]),
                hash_mode: OrderIndependentMultisigHashMode::P2WSH,
                nonce: 456,
                tx_fee: 567,
                fields: vec![
                    TransactionAuthField::Signature(TransactionPublicKeyEncoding::Compressed, MessageSignature::from_raw(&[0xff; 65])),
                    TransactionAuthField::Signature(TransactionPublicKeyEncoding::Compressed, MessageSignature::from_raw(&[0xfe; 65])),
                    TransactionAuthField::Signature(TransactionPublicKeyEncoding::Compressed, MessageSignature::from_raw(&[0xfd; 65])),
                ],
                signatures_required: 1
            })
        ];

        for i in 0..spending_conditions.len() {
            let mut spending_condition_bytes = vec![];
            spending_conditions[i]
                .consensus_serialize(&mut spending_condition_bytes)
                .unwrap();

            let mut spending_condition_2_bytes = vec![];
            spending_conditions[(i + 1) % spending_conditions.len()]
                .consensus_serialize(&mut spending_condition_2_bytes)
                .unwrap();

            let auth_standard = TransactionAuth::Standard(spending_conditions[i].clone());
            let mut auth_standard_bytes = vec![TransactionAuthFlags::AuthStandard as u8];
            auth_standard_bytes.append(&mut spending_condition_bytes.clone());

            let auth_sponsored = TransactionAuth::Sponsored(
                spending_conditions[i].clone(),
                spending_conditions[(i + 1) % spending_conditions.len()].clone(),
            );
            let mut auth_sponsored_bytes = vec![TransactionAuthFlags::AuthSponsored as u8];
            auth_sponsored_bytes.append(&mut spending_condition_bytes.clone());
            auth_sponsored_bytes.append(&mut spending_condition_2_bytes.clone());

            check_codec_and_corruption::<TransactionAuth>(&auth_standard, &auth_standard_bytes);
            check_codec_and_corruption::<TransactionAuth>(&auth_sponsored, &auth_sponsored_bytes);
        }
    }

    #[test]
    fn tx_stacks_invalid_spending_conditions() {
        #[rustfmt::skip]
        let bad_hash_mode_bytes = [
            // singlesig
            // hash mode
            0xff,
            // signer
            0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11,
            // nonce
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01, 0xc8,
            // fee rate
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x02, 0x37,
            // key encoding,
            TransactionPublicKeyEncoding::Compressed as u8,
            // signature
            0xfd, 0xfd, 0xfd, 0xfd, 0xfd, 0xfd, 0xfd, 0xfd, 0xfd, 0xfd, 0xfd, 0xfd, 0xfd, 0xfd, 0xfd, 0xfd, 0xfd, 0xfd, 0xfd, 0xfd, 0xfd, 0xfd, 0xfd, 0xfd, 0xfd, 0xfd, 0xfd, 0xfd, 0xfd, 0xfd, 0xfd, 0xfd, 0xfd, 0xfd, 0xfd, 0xfd, 0xfd, 0xfd, 0xfd, 0xfd, 0xfd, 0xfd, 0xfd, 0xfd, 0xfd, 0xfd, 0xfd, 0xfd, 0xfd, 0xfd, 0xfd, 0xfd, 0xfd, 0xfd, 0xfd, 0xfd, 0xfd, 0xfd, 0xfd, 0xfd, 0xfd, 0xfd, 0xfd, 0xfd, 0xfd, 0xfd,
        ];

        #[rustfmt::skip]
        let bad_hash_mode_multisig_bytes = [
            // hash mode
            MultisigHashMode::P2SH as u8,
            // signer
            0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11,
            // nonce
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01, 0xc8,
            // fee rate
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x02, 0x37,
            // key encoding,
            TransactionPublicKeyEncoding::Compressed as u8,
            // signature
            0xfd, 0xfd, 0xfd, 0xfd, 0xfd, 0xfd, 0xfd, 0xfd, 0xfd, 0xfd, 0xfd, 0xfd, 0xfd, 0xfd, 0xfd, 0xfd, 0xfd, 0xfd, 0xfd, 0xfd, 0xfd, 0xfd, 0xfd, 0xfd, 0xfd, 0xfd, 0xfd, 0xfd, 0xfd, 0xfd, 0xfd, 0xfd, 0xfd, 0xfd, 0xfd, 0xfd, 0xfd, 0xfd, 0xfd, 0xfd, 0xfd, 0xfd, 0xfd, 0xfd, 0xfd, 0xfd, 0xfd, 0xfd, 0xfd, 0xfd, 0xfd, 0xfd, 0xfd, 0xfd, 0xfd, 0xfd, 0xfd, 0xfd, 0xfd, 0xfd, 0xfd, 0xfd, 0xfd, 0xfd, 0xfd, 0xfd,
        ];

        #[rustfmt::skip]
        let bad_hash_mode_order_independent_multisig_bytes = [
            // hash mode
            OrderIndependentMultisigHashMode::P2SH as u8,
            // signer
            0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11,
            // nonce
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01, 0xc8,
            // fee rate
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x02, 0x37,
            // key encoding,
            TransactionPublicKeyEncoding::Compressed as u8,
            // signature
            0xfd, 0xfd, 0xfd, 0xfd, 0xfd, 0xfd, 0xfd, 0xfd, 0xfd, 0xfd, 0xfd, 0xfd, 0xfd, 0xfd, 0xfd, 0xfd, 0xfd, 0xfd, 0xfd, 0xfd, 0xfd, 0xfd, 0xfd, 0xfd, 0xfd, 0xfd, 0xfd, 0xfd, 0xfd, 0xfd, 0xfd, 0xfd, 0xfd, 0xfd, 0xfd, 0xfd, 0xfd, 0xfd, 0xfd, 0xfd, 0xfd, 0xfd, 0xfd, 0xfd, 0xfd, 0xfd, 0xfd, 0xfd, 0xfd, 0xfd, 0xfd, 0xfd, 0xfd, 0xfd, 0xfd, 0xfd, 0xfd, 0xfd, 0xfd, 0xfd, 0xfd, 0xfd, 0xfd, 0xfd, 0xfd, 0xfd,
        ];

        // this will parse into a singlesig spending condition, but data will still remain.
        // the reason it parses is because the public keys length field encodes a valid 2-byte
        // prefix of a public key, and the parser will lump it into a public key
        #[rustfmt::skip]
        let bad_hash_mode_singlesig_bytes_parseable = [
            // hash mode
            SinglesigHashMode::P2PKH as u8,
            // signer
            0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11,
            // nonce (embeds key encoding and part of the parsed nonce)
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01, 0xc8,
            // fee rate
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x02, 0x37,
            // number of fields (embed part of the signature)
            0x00, 0x00, 0x00, 0x01,
            // field #1: signature
            TransactionAuthFieldID::SignatureCompressed as u8,
            // field #1: signature
            0x01, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
            // number of signatures
            0x00, 0x01,
        ];

        // wrong number of public keys (too many signatures)
        #[rustfmt::skip]
        let bad_public_key_count_bytes = vec![
            // hash mode
            MultisigHashMode::P2SH as u8,
            // signer
            0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11,
            // nonce
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01, 0xc8,
            // fee rate
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x02, 0x37,
            // fields length
            0x00, 0x00, 0x00, 0x03,
            // field #1: signature
            TransactionAuthFieldID::SignatureCompressed as u8,
            // field #1: signature
            0x01, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
            // field #2: signature
            TransactionAuthFieldID::SignatureCompressed as u8,
            // filed #2: signature
            0x02, 0xfe, 0xfe, 0xfe, 0xfe, 0xfe, 0xfe, 0xfe, 0xfe, 0xfe, 0xfe, 0xfe, 0xfe, 0xfe, 0xfe, 0xfe, 0xfe, 0xfe, 0xfe, 0xfe, 0xfe, 0xfe, 0xfe, 0xfe, 0xfe, 0xfe, 0xfe, 0xfe, 0xfe, 0xfe, 0xfe, 0xfe, 0xfe, 0xfe, 0xfe, 0xfe, 0xfe, 0xfe, 0xfe, 0xfe, 0xfe, 0xfe, 0xfe, 0xfe, 0xfe, 0xfe, 0xfe, 0xfe, 0xfe, 0xfe, 0xfe, 0xfe, 0xfe, 0xfe, 0xfe, 0xfe, 0xfe, 0xfe, 0xfe, 0xfe, 0xfe, 0xfe, 0xfe, 0xfe, 0xfe,
            // field #3: public key
            TransactionAuthFieldID::PublicKeyCompressed as u8,
            // field #3: key (compressed)
            0x03, 0xef, 0x23, 0x40, 0x51, 0x8b, 0x58, 0x67, 0xb2, 0x35, 0x98, 0xa9, 0xcf, 0x74, 0x61, 0x1f, 0x8b, 0x98, 0x06, 0x4f, 0x7d, 0x55, 0xcd, 0xb8, 0xc1, 0x07, 0xc6, 0x7b, 0x5e, 0xfc, 0xbc, 0x5c, 0x77,
            // number of signatures
            0x00, 0x01,
        ];

        // wrong number of public keys (not enough signatures)
        #[rustfmt::skip]
        let bad_public_key_count_bytes_2 = vec![
            // hash mode
            MultisigHashMode::P2SH as u8,
            // signer
            0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11,
            // nonce
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01, 0xc8,
            // fee rate
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x02, 0x37,
            // fields length
            0x00, 0x00, 0x00, 0x03,
            // field #1: signature
            TransactionAuthFieldID::SignatureCompressed as u8,
            // field #1: signature
            0x01, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
            // field #2: signature
            TransactionAuthFieldID::SignatureCompressed as u8,
            // filed #2: signature
            0x02, 0xfe, 0xfe, 0xfe, 0xfe, 0xfe, 0xfe, 0xfe, 0xfe, 0xfe, 0xfe, 0xfe, 0xfe, 0xfe, 0xfe, 0xfe, 0xfe, 0xfe, 0xfe, 0xfe, 0xfe, 0xfe, 0xfe, 0xfe, 0xfe, 0xfe, 0xfe, 0xfe, 0xfe, 0xfe, 0xfe, 0xfe, 0xfe, 0xfe, 0xfe, 0xfe, 0xfe, 0xfe, 0xfe, 0xfe, 0xfe, 0xfe, 0xfe, 0xfe, 0xfe, 0xfe, 0xfe, 0xfe, 0xfe, 0xfe, 0xfe, 0xfe, 0xfe, 0xfe, 0xfe, 0xfe, 0xfe, 0xfe, 0xfe, 0xfe, 0xfe, 0xfe, 0xfe, 0xfe, 0xfe,
            // field #3: public key
            TransactionAuthFieldID::PublicKeyCompressed as u8,
            // field #3: key (compressed)
            0x03, 0xef, 0x23, 0x40, 0x51, 0x8b, 0x58, 0x67, 0xb2, 0x35, 0x98, 0xa9, 0xcf, 0x74, 0x61, 0x1f, 0x8b, 0x98, 0x06, 0x4f, 0x7d, 0x55, 0xcd, 0xb8, 0xc1, 0x07, 0xc6, 0x7b, 0x5e, 0xfc, 0xbc, 0x5c, 0x77,
            // number of signatures
            0x00, 0x03,
        ];

        // wrong number of public keys (not enough signatures)
        #[rustfmt::skip]
        let bad_public_key_count_bytes_3 = vec![
            // hash mode
            OrderIndependentMultisigHashMode::P2SH as u8,
            // signer
            0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11,
            // nonce
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01, 0xc8,
            // fee rate
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x02, 0x37,
            // fields length
            0x00, 0x00, 0x00, 0x03,
            // field #1: signature
            TransactionAuthFieldID::SignatureCompressed as u8,
            // field #1: signature
            0x01, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
            // field #2: signature
            TransactionAuthFieldID::SignatureCompressed as u8,
            // filed #2: signature
            0x02, 0xfe, 0xfe, 0xfe, 0xfe, 0xfe, 0xfe, 0xfe, 0xfe, 0xfe, 0xfe, 0xfe, 0xfe, 0xfe, 0xfe, 0xfe, 0xfe, 0xfe, 0xfe, 0xfe, 0xfe, 0xfe, 0xfe, 0xfe, 0xfe, 0xfe, 0xfe, 0xfe, 0xfe, 0xfe, 0xfe, 0xfe, 0xfe, 0xfe, 0xfe, 0xfe, 0xfe, 0xfe, 0xfe, 0xfe, 0xfe, 0xfe, 0xfe, 0xfe, 0xfe, 0xfe, 0xfe, 0xfe, 0xfe, 0xfe, 0xfe, 0xfe, 0xfe, 0xfe, 0xfe, 0xfe, 0xfe, 0xfe, 0xfe, 0xfe, 0xfe, 0xfe, 0xfe, 0xfe, 0xfe,
            // field #3: public key
            TransactionAuthFieldID::PublicKeyCompressed as u8,
            // field #3: key (compressed)
            0x03, 0xef, 0x23, 0x40, 0x51, 0x8b, 0x58, 0x67, 0xb2, 0x35, 0x98, 0xa9, 0xcf, 0x74, 0x61, 0x1f, 0x8b, 0x98, 0x06, 0x4f, 0x7d, 0x55, 0xcd, 0xb8, 0xc1, 0x07, 0xc6, 0x7b, 0x5e, 0xfc, 0xbc, 0x5c, 0x77,
            // number of signatures
            0x00, 0x03,
        ];

        // hashing mode doesn't allow uncompressed keys
        let bad_p2wpkh_uncompressed =
            TransactionSpendingCondition::Singlesig(SinglesigSpendingCondition {
                signer: Hash160([0x11; 20]),
                hash_mode: SinglesigHashMode::P2WPKH,
                nonce: 123,
                tx_fee: 567,
                key_encoding: TransactionPublicKeyEncoding::Uncompressed,
                signature: MessageSignature::from_raw(&[0xff; 65]),
            });

        #[rustfmt::skip]
        let bad_p2wpkh_uncompressed_bytes = vec![
            // hash mode
            SinglesigHashMode::P2WPKH as u8,
            // signer
            0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11,
            // nonce
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x7b,
            // fee rate
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x02, 0x37,
            // public key uncompressed
            TransactionPublicKeyEncoding::Uncompressed as u8,
            // signature
            0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
        ];

        // hashing mode doesn't allow uncompressed keys
        let bad_p2wsh_uncompressed = TransactionSpendingCondition::Multisig(MultisigSpendingCondition {
            signer: Hash160([0x11; 20]),
            hash_mode: MultisigHashMode::P2WSH,
            nonce: 456,
            tx_fee: 567,
            fields: vec![
                TransactionAuthField::Signature(TransactionPublicKeyEncoding::Uncompressed, MessageSignature::from_raw(&[0xff; 65])),
                TransactionAuthField::Signature(TransactionPublicKeyEncoding::Uncompressed, MessageSignature::from_raw(&[0xfe; 65])),
                TransactionAuthField::PublicKey(PubKey::from_hex("04b7e10dd2c02dec648880ea346ece86a7820c4fa5114fb500b2645f6c972092dbe2334a653db0ab8d8ccffa6c35d3919e4cf8da3aeedafc7b9eb8235d0f2e7fdc").unwrap()),
            ],
            signatures_required: 2
        });

        #[rustfmt::skip]
        let bad_p2wsh_uncompressed_bytes = vec![
            // hash mode
            MultisigHashMode::P2WSH as u8,
            // signer
            0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11,
            // nonce
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01, 0xc8,
            // fee rate
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x02, 0x37,
            // number of fields
            0x00, 0x00, 0x00, 0x03,
            // signature
            TransactionAuthFieldID::SignatureUncompressed as u8,
            0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
            // signature
            TransactionAuthFieldID::SignatureUncompressed as u8,
            0xfe, 0xfe, 0xfe, 0xfe, 0xfe, 0xfe, 0xfe, 0xfe, 0xfe, 0xfe, 0xfe, 0xfe, 0xfe, 0xfe, 0xfe, 0xfe, 0xfe, 0xfe, 0xfe, 0xfe, 0xfe, 0xfe, 0xfe, 0xfe, 0xfe, 0xfe, 0xfe, 0xfe, 0xfe, 0xfe, 0xfe, 0xfe, 0xfe, 0xfe, 0xfe, 0xfe, 0xfe, 0xfe, 0xfe, 0xfe, 0xfe, 0xfe, 0xfe, 0xfe, 0xfe, 0xfe, 0xfe, 0xfe, 0xfe, 0xfe, 0xfe, 0xfe, 0xfe, 0xfe, 0xfe, 0xfe, 0xfe, 0xfe, 0xfe, 0xfe, 0xfe, 0xfe, 0xfe, 0xfe, 0xfe,
            // key
            TransactionAuthFieldID::PublicKeyUncompressed as u8,
            0x02, 0xb7, 0xe1, 0x0d, 0xd2, 0xc0, 0x2d, 0xec, 0x64, 0x88, 0x80, 0xea, 0x34, 0x6e, 0xce, 0x86, 0xa7, 0x82, 0x0c, 0x4f, 0xa5, 0x11, 0x4f, 0xb5, 0x00, 0xb2, 0x64, 0x5f, 0x6c, 0x97, 0x20, 0x92, 0xdb,
            // signatures
            0x00, 0x02,
        ];

        // hashing mode doesn't allow uncompressed keys
        let bad_order_independent_p2wsh_uncompressed = TransactionSpendingCondition::OrderIndependentMultisig(OrderIndependentMultisigSpendingCondition {
            signer: Hash160([0x11; 20]),
            hash_mode: OrderIndependentMultisigHashMode::P2WSH,
            nonce: 456,
            tx_fee: 567,
            fields: vec![
                TransactionAuthField::Signature(TransactionPublicKeyEncoding::Uncompressed, MessageSignature::from_raw(&[0xff; 65])),
                TransactionAuthField::Signature(TransactionPublicKeyEncoding::Uncompressed, MessageSignature::from_raw(&[0xfe; 65])),
                TransactionAuthField::PublicKey(PubKey::from_hex("04b7e10dd2c02dec648880ea346ece86a7820c4fa5114fb500b2645f6c972092dbe2334a653db0ab8d8ccffa6c35d3919e4cf8da3aeedafc7b9eb8235d0f2e7fdc").unwrap()),
            ],
            signatures_required: 2
        });

        #[rustfmt::skip]
        let bad_order_independent_p2wsh_uncompressed_bytes = vec![
            // hash mode
            OrderIndependentMultisigHashMode::P2WSH as u8,
            // signer
            0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11,
            // nonce
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01, 0xc8,
            // fee rate
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x02, 0x37,
            // number of fields
            0x00, 0x00, 0x00, 0x03,
            // signature
            TransactionAuthFieldID::SignatureUncompressed as u8,
            0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
            // signature
            TransactionAuthFieldID::SignatureUncompressed as u8,
            0xfe, 0xfe, 0xfe, 0xfe, 0xfe, 0xfe, 0xfe, 0xfe, 0xfe, 0xfe, 0xfe, 0xfe, 0xfe, 0xfe, 0xfe, 0xfe, 0xfe, 0xfe, 0xfe, 0xfe, 0xfe, 0xfe, 0xfe, 0xfe, 0xfe, 0xfe, 0xfe, 0xfe, 0xfe, 0xfe, 0xfe, 0xfe, 0xfe, 0xfe, 0xfe, 0xfe, 0xfe, 0xfe, 0xfe, 0xfe, 0xfe, 0xfe, 0xfe, 0xfe, 0xfe, 0xfe, 0xfe, 0xfe, 0xfe, 0xfe, 0xfe, 0xfe, 0xfe, 0xfe, 0xfe, 0xfe, 0xfe, 0xfe, 0xfe, 0xfe, 0xfe, 0xfe, 0xfe, 0xfe, 0xfe,
            // key
            TransactionAuthFieldID::PublicKeyUncompressed as u8,
            0x02, 0xb7, 0xe1, 0x0d, 0xd2, 0xc0, 0x2d, 0xec, 0x64, 0x88, 0x80, 0xea, 0x34, 0x6e, 0xce, 0x86, 0xa7, 0x82, 0x0c, 0x4f, 0xa5, 0x11, 0x4f, 0xb5, 0x00, 0xb2, 0x64, 0x5f, 0x6c, 0x97, 0x20, 0x92, 0xdb,
            // signatures
            0x00, 0x02,
        ];

        // we can serialize the invalid p2wpkh uncompressed condition, but we can't deserialize it
        let mut actual_bytes = vec![];
        bad_p2wpkh_uncompressed
            .consensus_serialize(&mut actual_bytes)
            .unwrap();
        assert_eq!(actual_bytes, bad_p2wpkh_uncompressed_bytes);

        // we can serialize the invalid p2wsh uncompressed condition, but we can't deserialize it
        let mut actual_bytes = vec![];
        bad_p2wsh_uncompressed
            .consensus_serialize(&mut actual_bytes)
            .unwrap();
        assert_eq!(actual_bytes, bad_p2wsh_uncompressed_bytes);

        // we can serialize the invalid p2wsh uncompressed condition, but we can't deserialize it
        let mut actual_bytes = vec![];
        bad_order_independent_p2wsh_uncompressed
            .consensus_serialize(&mut actual_bytes)
            .unwrap();
        assert_eq!(actual_bytes, bad_order_independent_p2wsh_uncompressed_bytes);

        assert!(TransactionSpendingCondition::consensus_deserialize(
            &mut &bad_public_key_count_bytes[..]
        )
        .is_err());
        assert!(TransactionSpendingCondition::consensus_deserialize(
            &mut &bad_public_key_count_bytes_2[..]
        )
        .is_err());
        assert!(TransactionSpendingCondition::consensus_deserialize(
            &mut &bad_public_key_count_bytes_3[..]
        )
        .is_err());
        assert!(
            TransactionSpendingCondition::consensus_deserialize(&mut &bad_hash_mode_bytes[..])
                .is_err()
        );
        assert!(TransactionSpendingCondition::consensus_deserialize(
            &mut &bad_hash_mode_multisig_bytes[..]
        )
        .is_err());
        assert!(TransactionSpendingCondition::consensus_deserialize(
            &mut &bad_hash_mode_order_independent_multisig_bytes[..]
        )
        .is_err());
        assert!(TransactionSpendingCondition::consensus_deserialize(
            &mut &bad_p2wpkh_uncompressed_bytes[..]
        )
        .is_err());
        assert!(TransactionSpendingCondition::consensus_deserialize(
            &mut &bad_p2wsh_uncompressed_bytes[..]
        )
        .is_err());
        assert!(TransactionSpendingCondition::consensus_deserialize(
            &mut &bad_order_independent_p2wsh_uncompressed_bytes[..]
        )
        .is_err());

        // corrupt but will parse with trailing bits
        assert!(TransactionSpendingCondition::consensus_deserialize(
            &mut &bad_hash_mode_singlesig_bytes_parseable[..]
        )
        .is_ok());
    }

    #[test]
    fn tx_stacks_signature() {
        let cur_sighash = Txid([0u8; 32]);
        let privk = StacksPrivateKey::from_hex(
            "6d430bb91222408e7706c9001cfaeb91b08c2be6d5ac95779ab52c6b431950e001",
        )
        .unwrap();
        let privk_uncompressed = StacksPrivateKey::from_hex(
            "6d430bb91222408e7706c9001cfaeb91b08c2be6d5ac95779ab52c6b431950e0",
        )
        .unwrap();

        let keys = [
            privk.clone(),
            privk.clone(),
            privk_uncompressed.clone(),
            privk_uncompressed.clone(),
        ];

        let key_modes = [
            TransactionPublicKeyEncoding::Compressed,
            TransactionPublicKeyEncoding::Compressed,
            TransactionPublicKeyEncoding::Uncompressed,
            TransactionPublicKeyEncoding::Uncompressed,
        ];

        let auth_flags = [
            TransactionAuthFlags::AuthStandard,
            TransactionAuthFlags::AuthSponsored,
            TransactionAuthFlags::AuthStandard,
            TransactionAuthFlags::AuthSponsored,
        ];

        let tx_fees = [123, 456, 123, 456];

        let nonces: Vec<u64> = vec![1, 2, 3, 4];

        for i in 0..4 {
            let (sig, next_sighash) = TransactionSpendingCondition::next_signature(
                &cur_sighash,
                &auth_flags[i],
                tx_fees[i],
                nonces[i],
                &keys[i],
            )
            .unwrap();

            let mut expected_sighash_bytes = vec![];

            expected_sighash_bytes.clear();
            expected_sighash_bytes.extend_from_slice(cur_sighash.as_bytes());
            expected_sighash_bytes.extend_from_slice(&[auth_flags[i] as u8]);
            expected_sighash_bytes.extend_from_slice(&tx_fees[i].to_be_bytes());
            expected_sighash_bytes.extend_from_slice(&nonces[i].to_be_bytes());
            let expected_sighash_presign = Txid::from_sighash_bytes(&expected_sighash_bytes[..]);

            expected_sighash_bytes.clear();
            expected_sighash_bytes.extend_from_slice(expected_sighash_presign.as_bytes());
            expected_sighash_bytes.extend_from_slice(&[key_modes[i] as u8]);
            expected_sighash_bytes.extend_from_slice(sig.as_bytes());
            let expected_sighash_postsign = Txid::from_sighash_bytes(&expected_sighash_bytes[..]);

            assert_eq!(next_sighash, expected_sighash_postsign);

            let key_encoding = if keys[i].compress_public() {
                TransactionPublicKeyEncoding::Compressed
            } else {
                TransactionPublicKeyEncoding::Uncompressed
            };

            let (next_pubkey, verified_next_sighash) =
                TransactionSpendingCondition::next_verification(
                    &cur_sighash,
                    &auth_flags[i],
                    tx_fees[i],
                    nonces[i],
                    &key_encoding,
                    &sig,
                    TransactionAuthVerificationMode::EnforceLowS,
                )
                .unwrap();

            assert_eq!(verified_next_sighash, expected_sighash_postsign);
            assert_eq!(next_pubkey, StacksPublicKey::from_private(&keys[i]));
        }
    }

    fn tx_auth_check_all_epochs(auth: TransactionAuth, activation_epoch_id: Option<StacksEpochId>) {
        let epoch_list = [
            StacksEpochId::Epoch10,
            StacksEpochId::Epoch20,
            StacksEpochId::Epoch2_05,
            StacksEpochId::Epoch21,
            StacksEpochId::Epoch22,
            StacksEpochId::Epoch23,
            StacksEpochId::Epoch24,
            StacksEpochId::Epoch25,
            StacksEpochId::Epoch30,
        ];

        for epoch_id in epoch_list.iter() {
            if activation_epoch_id.is_none() {
                assert!(auth.is_supported_in_epoch(*epoch_id));
            } else if activation_epoch_id.unwrap() > *epoch_id {
                assert!(!auth.is_supported_in_epoch(*epoch_id));
            } else {
                assert!(auth.is_supported_in_epoch(*epoch_id));
            }
        }
    }

    #[test]
    fn tx_auth_is_supported_in_epoch() {
        let privk_1 = StacksPrivateKey::from_hex(
            "6d430bb91222408e7706c9001cfaeb91b08c2be6d5ac95779ab52c6b431950e001",
        )
        .unwrap();

        let privk_2 = StacksPrivateKey::from_hex(
            "7e3af4db6af6b3c67e2c6c6d7d5983b519f4d9b3a6e00580ae96dcace3bde8bc01",
        )
        .unwrap();

        let auth_p2pkh = TransactionAuth::from_p2pkh(&privk_1).unwrap();
        let auth_sponsored_p2pkh = auth_p2pkh
            .clone()
            .into_sponsored(TransactionAuth::from_p2pkh(&privk_2).unwrap())
            .unwrap();

        tx_auth_check_all_epochs(auth_p2pkh, None);
        tx_auth_check_all_epochs(auth_sponsored_p2pkh, None);

        let auth_p2wpkh = TransactionAuth::from_p2wpkh(&privk_1).unwrap();
        let auth_sponsored_p2wpkh = auth_p2wpkh
            .clone()
            .into_sponsored(TransactionAuth::from_p2wpkh(&privk_2).unwrap())
            .unwrap();

        tx_auth_check_all_epochs(auth_p2wpkh, None);
        tx_auth_check_all_epochs(auth_sponsored_p2wpkh, None);

        let privks = [privk_1.clone(), privk_2.clone()];
        let auth_p2sh = TransactionAuth::from_p2sh(&privks, 2).unwrap();
        let auth_sponsored_p2sh = auth_p2sh
            .clone()
            .into_sponsored(TransactionAuth::from_p2sh(&privks, 2).unwrap())
            .unwrap();

        tx_auth_check_all_epochs(auth_p2sh, None);
        tx_auth_check_all_epochs(auth_sponsored_p2sh, None);

        let auth_p2wsh = TransactionAuth::from_p2wsh(&privks, 2).unwrap();
        let auth_sponsored_p2wsh = auth_p2wsh
            .clone()
            .into_sponsored(TransactionAuth::from_p2wsh(&privks, 2).unwrap())
            .unwrap();

        tx_auth_check_all_epochs(auth_p2wsh, None);
        tx_auth_check_all_epochs(auth_sponsored_p2wsh, None);

        let auth_order_independent_p2sh =
            TransactionAuth::from_order_independent_p2sh(&privks, 2).unwrap();
        let auth_sponsored_order_independent_p2sh = auth_order_independent_p2sh
            .clone()
            .into_sponsored(TransactionAuth::from_order_independent_p2sh(&privks, 2).unwrap())
            .unwrap();

        tx_auth_check_all_epochs(auth_order_independent_p2sh, Some(StacksEpochId::Epoch30));
        tx_auth_check_all_epochs(
            auth_sponsored_order_independent_p2sh,
            Some(StacksEpochId::Epoch30),
        );

        let auth_order_independent_p2wsh =
            TransactionAuth::from_order_independent_p2wsh(&privks, 2).unwrap();
        let auth_sponsored_order_independent_p2wsh = auth_order_independent_p2wsh
            .clone()
            .into_sponsored(TransactionAuth::from_order_independent_p2wsh(&privks, 2).unwrap())
            .unwrap();

        tx_auth_check_all_epochs(auth_order_independent_p2wsh, Some(StacksEpochId::Epoch30));
        tx_auth_check_all_epochs(
            auth_sponsored_order_independent_p2wsh,
            Some(StacksEpochId::Epoch30),
        );
    }
}
