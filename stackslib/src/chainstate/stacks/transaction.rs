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

use crate::chainstate::stacks::{
    Error, StacksPrivateKey, StacksPublicKey, StacksTransaction, StacksTransactionSigner,
    TransactionAuth, TransactionAuthField, TransactionAuthVerificationMode,
    TransactionSpendingCondition,
};
use crate::net::Error as net_error;

/// Pop the last auth field
fn pop_auth_field(condition: &mut TransactionSpendingCondition) -> Option<TransactionAuthField> {
    match condition {
        TransactionSpendingCondition::Multisig(ref mut cond) => cond.pop_auth_field(),
        TransactionSpendingCondition::OrderIndependentMultisig(ref mut cond) => {
            cond.pop_auth_field()
        }
        TransactionSpendingCondition::Singlesig(ref mut cond) => cond.pop_signature(),
    }
}

impl StacksTransactionSigner {
    pub fn new(tx: &StacksTransaction) -> StacksTransactionSigner {
        StacksTransactionSigner {
            tx: tx.clone(),
            sighash: tx.sign_begin(),
            origin_done: false,
            check_oversign: true,
            check_overlap: true,
        }
    }

    pub fn new_sponsor(
        tx: &StacksTransaction,
        spending_condition: TransactionSpendingCondition,
    ) -> Result<StacksTransactionSigner, Error> {
        if !tx.auth.is_sponsored() {
            return Err(Error::IncompatibleSpendingConditionError);
        }
        let mut new_tx = tx.clone();
        new_tx.auth.set_sponsor(spending_condition)?;
        let origin_sighash = new_tx.verify_origin(TransactionAuthVerificationMode::EnforceLowS)?;

        Ok(StacksTransactionSigner {
            tx: new_tx,
            sighash: origin_sighash,
            origin_done: true,
            check_oversign: true,
            check_overlap: true,
        })
    }

    pub fn resume(&mut self, tx: &StacksTransaction) {
        self.tx = tx.clone()
    }

    pub fn disable_checks(&mut self) {
        self.check_oversign = false;
        self.check_overlap = false;
    }

    pub fn sign_origin(&mut self, privk: &StacksPrivateKey) -> Result<(), net_error> {
        if self.check_overlap && self.origin_done {
            // can't sign another origin private key since we started signing sponsors
            return Err(net_error::SigningError(
                "Cannot sign origin after sponsor key".to_string(),
            ));
        }

        match self.tx.auth {
            TransactionAuth::Standard(ref origin_condition) => {
                if self.check_oversign
                    && origin_condition.num_signatures() >= origin_condition.signatures_required()
                {
                    return Err(net_error::SigningError(
                        "Origin would have too many signatures".to_string(),
                    ));
                }
            }
            TransactionAuth::Sponsored(ref origin_condition, _) => {
                if self.check_oversign
                    && origin_condition.num_signatures() >= origin_condition.signatures_required()
                {
                    return Err(net_error::SigningError(
                        "Origin would have too many signatures".to_string(),
                    ));
                }
            }
        }

        let next_sighash = self.tx.sign_next_origin(&self.sighash, privk)?;
        self.sighash = next_sighash;
        Ok(())
    }

    pub fn append_origin(&mut self, pubk: &StacksPublicKey) -> Result<(), net_error> {
        if self.check_overlap && self.origin_done {
            // can't append another origin key
            return Err(net_error::SigningError(
                "Cannot append public key to origin after sponsor key".to_string(),
            ));
        }

        self.tx.append_next_origin(pubk).map_err(net_error::from)
    }

    pub fn sign_sponsor(&mut self, privk: &StacksPrivateKey) -> Result<(), net_error> {
        if let TransactionAuth::Sponsored(_, ref sponsor_condition) = self.tx.auth {
            if self.check_oversign
                && sponsor_condition.num_signatures() >= sponsor_condition.signatures_required()
            {
                return Err(net_error::SigningError(
                    "Sponsor would have too many signatures".to_string(),
                ));
            }
        }

        let next_sighash = self.tx.sign_next_sponsor(&self.sighash, privk)?;
        self.sighash = next_sighash;
        self.origin_done = true;
        Ok(())
    }

    pub fn append_sponsor(&mut self, pubk: &StacksPublicKey) -> Result<(), net_error> {
        self.tx.append_next_sponsor(pubk).map_err(net_error::from)
    }

    pub fn pop_origin_auth_field(&mut self) -> Option<TransactionAuthField> {
        match self.tx.auth {
            TransactionAuth::Standard(ref mut origin_condition) => pop_auth_field(origin_condition),
            TransactionAuth::Sponsored(ref mut origin_condition, _) => {
                pop_auth_field(origin_condition)
            }
        }
    }

    pub fn pop_sponsor_auth_field(&mut self) -> Option<TransactionAuthField> {
        match self.tx.auth {
            TransactionAuth::Sponsored(_, ref mut sponsor_condition) => {
                pop_auth_field(sponsor_condition)
            }
            _ => None,
        }
    }

    pub fn complete(&self) -> bool {
        match self.tx.auth {
            TransactionAuth::Standard(ref origin_condition) => {
                origin_condition.num_signatures() >= origin_condition.signatures_required()
            }
            TransactionAuth::Sponsored(ref origin_condition, ref sponsored_condition) => {
                origin_condition.num_signatures() >= origin_condition.signatures_required()
                    && sponsored_condition.num_signatures()
                        >= sponsored_condition.signatures_required()
                    && (self.origin_done || !self.check_overlap)
            }
        }
    }

    pub fn get_tx_incomplete(&self) -> StacksTransaction {
        self.tx.clone()
    }

    pub fn get_tx(&self) -> Option<StacksTransaction> {
        if self.complete() {
            Some(self.tx.clone())
        } else {
            None
        }
    }
}

#[cfg(test)]
mod test {
    use clarity::types::StacksEpochId;
    use clarity::vm::representations::{ClarityName, ContractName};
    use clarity::vm::Value;
    use stacks_common::codec::StacksMessageCodec;
    use stacks_common::types::chainstate::StacksAddress;
    use stacks_common::util::hash::*;
    use stacks_common::util::retry::LogReader;

    use crate::burnchains::Txid;
    use crate::chainstate::stacks::test::codec_all_transactions;
    use crate::chainstate::stacks::{
        C32_ADDRESS_VERSION_MAINNET_MULTISIG, C32_ADDRESS_VERSION_MAINNET_SINGLESIG, *,
    };
    use crate::core::EMPTY_MICROBLOCK_PARENT_HASH;
    use crate::net::codec::test::check_codec_and_corruption;

    /// Test-only helpers that used to live as inherent methods on
    /// `StacksTransaction`. Now that the type lives in `stacks-codec`,
    /// the inherent impl would violate the orphan rule; an extension
    /// trait lets call sites keep the method-call syntax unchanged.
    trait StacksTransactionTestExt {
        fn sign_no_append_origin(
            &self,
            cur_sighash: &Txid,
            privk: &StacksPrivateKey,
        ) -> Result<MessageSignature, AuthError>;

        fn append_origin_signature(
            &mut self,
            signature: MessageSignature,
            key_encoding: TransactionPublicKeyEncoding,
        );

        fn sign_no_append_sponsor(
            &mut self,
            cur_sighash: &Txid,
            privk: &StacksPrivateKey,
        ) -> Result<MessageSignature, AuthError>;

        fn append_sponsor_signature(
            &mut self,
            signature: MessageSignature,
            key_encoding: TransactionPublicKeyEncoding,
        ) -> Result<(), AuthError>;
    }

    impl StacksTransactionTestExt for StacksTransaction {
        fn sign_no_append_origin(
            &self,
            cur_sighash: &Txid,
            privk: &StacksPrivateKey,
        ) -> Result<MessageSignature, AuthError> {
            let next_sig = match self.auth {
                TransactionAuth::Standard(ref origin_condition)
                | TransactionAuth::Sponsored(ref origin_condition, _) => {
                    let (next_sig, _next_sighash) = TransactionSpendingCondition::next_signature(
                        cur_sighash,
                        &TransactionAuthFlags::AuthStandard,
                        origin_condition.tx_fee(),
                        origin_condition.nonce(),
                        privk,
                    )?;
                    next_sig
                }
            };
            Ok(next_sig)
        }

        fn append_origin_signature(
            &mut self,
            signature: MessageSignature,
            key_encoding: TransactionPublicKeyEncoding,
        ) {
            match self.auth {
                TransactionAuth::Standard(ref mut origin_condition)
                | TransactionAuth::Sponsored(ref mut origin_condition, _) => match origin_condition
                {
                    TransactionSpendingCondition::Singlesig(ref mut cond) => {
                        cond.set_signature(signature);
                    }
                    TransactionSpendingCondition::Multisig(ref mut cond) => {
                        cond.push_signature(key_encoding, signature);
                    }
                    TransactionSpendingCondition::OrderIndependentMultisig(ref mut cond) => {
                        cond.push_signature(key_encoding, signature);
                    }
                },
            };
        }

        fn sign_no_append_sponsor(
            &mut self,
            cur_sighash: &Txid,
            privk: &StacksPrivateKey,
        ) -> Result<MessageSignature, AuthError> {
            let next_sig = match self.auth {
                TransactionAuth::Standard(_) => {
                    return Err(AuthError::SigningError(
                        "Cannot sign standard authorization with a sponsoring private key"
                            .to_string(),
                    ));
                }
                TransactionAuth::Sponsored(_, ref mut sponsor_condition) => {
                    let (next_sig, _next_sighash) = TransactionSpendingCondition::next_signature(
                        cur_sighash,
                        &TransactionAuthFlags::AuthSponsored,
                        sponsor_condition.tx_fee(),
                        sponsor_condition.nonce(),
                        privk,
                    )?;
                    next_sig
                }
            };
            Ok(next_sig)
        }

        fn append_sponsor_signature(
            &mut self,
            signature: MessageSignature,
            key_encoding: TransactionPublicKeyEncoding,
        ) -> Result<(), AuthError> {
            match self.auth {
                TransactionAuth::Standard(_) => Err(AuthError::SigningError(
                    "Cannot appned a public key to the sponsor of a standard auth condition"
                        .to_string(),
                )),
                TransactionAuth::Sponsored(_, ref mut sponsor_condition) => match sponsor_condition
                {
                    TransactionSpendingCondition::Singlesig(ref mut cond) => {
                        Ok(cond.set_signature(signature))
                    }
                    TransactionSpendingCondition::Multisig(ref mut cond) => {
                        Ok(cond.push_signature(key_encoding, signature))
                    }
                    TransactionSpendingCondition::OrderIndependentMultisig(ref mut cond) => {
                        Ok(cond.push_signature(key_encoding, signature))
                    }
                },
            }
        }
    }

    fn corrupt_auth_field(
        corrupt_auth_fields: &TransactionAuth,
        i: usize,
        corrupt_origin: bool,
        corrupt_sponsor: bool,
    ) -> TransactionAuth {
        let mut new_corrupt_auth_fields = corrupt_auth_fields.clone();
        match new_corrupt_auth_fields {
            TransactionAuth::Standard(ref mut origin_condition) => {
                if corrupt_origin {
                    match origin_condition {
                        TransactionSpendingCondition::Singlesig(ref mut data) => {
                            let mut sig_bytes = data.signature.as_bytes().to_vec();
                            sig_bytes[1] ^= 1u8; // this breaks the `r` parameter
                            data.signature = MessageSignature::from_raw(&sig_bytes);
                        }
                        TransactionSpendingCondition::Multisig(ref mut data) => {
                            let corrupt_field = match data.fields[i] {
                                TransactionAuthField::PublicKey(ref pubkey) => {
                                    TransactionAuthField::PublicKey(StacksPublicKey::from_hex("0270790e675116a63a75008832d82ad93e4332882ab0797b0f156de9d739160a0b").unwrap())
                                },
                                TransactionAuthField::Signature(ref key_encoding, ref sig) => {
                                    let mut sig_bytes = sig.as_bytes().to_vec();
                                    sig_bytes[1] ^= 1u8;    // this breaks the `r` paramter
                                    let corrupt_sig = MessageSignature::from_raw(&sig_bytes);
                                    TransactionAuthField::Signature(*key_encoding, corrupt_sig)
                                }
                            };
                            data.fields[i] = corrupt_field
                        }
                        TransactionSpendingCondition::OrderIndependentMultisig(ref mut data) => {
                            let corrupt_field = match data.fields[i] {
                                TransactionAuthField::PublicKey(ref pubkey) => {
                                    TransactionAuthField::PublicKey(StacksPublicKey::from_hex("0270790e675116a63a75008832d82ad93e4332882ab0797b0f156de9d739160a0b").unwrap())
                                }
                                TransactionAuthField::Signature(ref key_encoding, ref sig) => {
                                    let mut sig_bytes = sig.as_bytes().to_vec();
                                    sig_bytes[1] ^= 1u8;    // this breaks the `r` paramter
                                    let corrupt_sig = MessageSignature::from_raw(&sig_bytes);
                                    TransactionAuthField::Signature(*key_encoding, corrupt_sig)
                                }
                            };
                            data.fields[i] = corrupt_field
                        }
                    }
                }
            }
            TransactionAuth::Sponsored(ref mut origin_condition, ref mut sponsor_condition) => {
                if corrupt_origin {
                    match origin_condition {
                        TransactionSpendingCondition::Singlesig(ref mut data) => {
                            let mut sig_bytes = data.signature.as_bytes().to_vec();
                            sig_bytes[1] ^= 1u8; // this breaks the `r` parameter
                            data.signature = MessageSignature::from_raw(&sig_bytes);
                        }
                        TransactionSpendingCondition::Multisig(ref mut data) => {
                            let corrupt_field = match data.fields[i] {
                                TransactionAuthField::PublicKey(_) => {
                                    TransactionAuthField::PublicKey(StacksPublicKey::from_hex("0270790e675116a63a75008832d82ad93e4332882ab0797b0f156de9d739160a0b").unwrap())
                                },
                                TransactionAuthField::Signature(ref key_encoding, ref sig) => {
                                    let mut sig_bytes = sig.as_bytes().to_vec();
                                    sig_bytes[1] ^= 1u8;    // this breaks the `r` paramter
                                    let corrupt_sig = MessageSignature::from_raw(&sig_bytes);
                                    TransactionAuthField::Signature(*key_encoding, corrupt_sig)
                                }
                            };
                            data.fields[i] = corrupt_field
                        }
                        TransactionSpendingCondition::OrderIndependentMultisig(ref mut data) => {
                            let corrupt_field = match data.fields[i] {
                                TransactionAuthField::PublicKey(_) => {
                                    TransactionAuthField::PublicKey(StacksPublicKey::from_hex("0270790e675116a63a75008832d82ad93e4332882ab0797b0f156de9d739160a0b").unwrap())
                                }
                                TransactionAuthField::Signature(ref key_encoding, ref sig) => {
                                    let mut sig_bytes = sig.as_bytes().to_vec();
                                    sig_bytes[1] ^= 1u8;    // this breaks the `r` paramter
                                    let corrupt_sig = MessageSignature::from_raw(&sig_bytes);
                                    TransactionAuthField::Signature(*key_encoding, corrupt_sig)
                                }
                            };
                            data.fields[i] = corrupt_field
                        }
                    }
                }
                if corrupt_sponsor {
                    match sponsor_condition {
                        TransactionSpendingCondition::Singlesig(ref mut data) => {
                            let mut sig_bytes = data.signature.as_bytes().to_vec();
                            sig_bytes[1] ^= 1u8; // this breaks the `r` parameter
                            data.signature = MessageSignature::from_raw(&sig_bytes);
                        }
                        TransactionSpendingCondition::Multisig(ref mut data) => {
                            let corrupt_field = match data.fields[i] {
                                TransactionAuthField::PublicKey(ref pubkey) => {
                                    TransactionAuthField::PublicKey(StacksPublicKey::from_hex("0270790e675116a63a75008832d82ad93e4332882ab0797b0f156de9d739160a0b").unwrap())
                                },
                                TransactionAuthField::Signature(ref key_encoding, ref sig) => {
                                    let mut sig_bytes = sig.as_bytes().to_vec();
                                    sig_bytes[1] ^= 1u8;    // this breaks the `r` paramter
                                    let corrupt_sig = MessageSignature::from_raw(&sig_bytes);
                                    TransactionAuthField::Signature(*key_encoding, corrupt_sig)
                                }
                            };
                            data.fields[i] = corrupt_field
                        }
                        TransactionSpendingCondition::OrderIndependentMultisig(ref mut data) => {
                            let corrupt_field = match data.fields[i] {
                                TransactionAuthField::PublicKey(ref pubkey) => {
                                    TransactionAuthField::PublicKey(StacksPublicKey::from_hex("0270790e675116a63a75008832d82ad93e4332882ab0797b0f156de9d739160a0b").unwrap())
                                }
                                TransactionAuthField::Signature(ref key_encoding, ref sig) => {
                                    let mut sig_bytes = sig.as_bytes().to_vec();
                                    sig_bytes[1] ^= 1u8;    // this breaks the `r` paramter
                                    let corrupt_sig = MessageSignature::from_raw(&sig_bytes);
                                    TransactionAuthField::Signature(*key_encoding, corrupt_sig)
                                }
                            };
                            data.fields[i] = corrupt_field
                        }
                    }
                }
            }
        };
        new_corrupt_auth_fields
    }

    fn find_signature(spend: &TransactionSpendingCondition) -> usize {
        match spend {
            TransactionSpendingCondition::Singlesig(_) => 0,
            TransactionSpendingCondition::Multisig(ref data) => {
                let mut j = 0;
                for f in 0..data.fields.len() {
                    if matches!(data.fields[f], TransactionAuthField::Signature(..)) {
                        j = f;
                        break;
                    };
                }
                j
            }
            TransactionSpendingCondition::OrderIndependentMultisig(ref data) => {
                let mut j = 0;
                for f in 0..data.fields.len() {
                    if matches!(data.fields[f], TransactionAuthField::Signature(..)) {
                        j = f;
                        break;
                    };
                }
                j
            }
        }
    }

    fn find_public_key(spend: &TransactionSpendingCondition) -> usize {
        match spend {
            TransactionSpendingCondition::Singlesig(_) => 0,
            TransactionSpendingCondition::Multisig(ref data) => {
                let mut j = 0;
                for f in 0..data.fields.len() {
                    if matches!(data.fields[f], TransactionAuthField::PublicKey(_)) {
                        j = f;
                        break;
                    };
                }
                j
            }
            TransactionSpendingCondition::OrderIndependentMultisig(ref data) => {
                let mut j = 0;
                for f in 0..data.fields.len() {
                    if matches!(data.fields[f], TransactionAuthField::PublicKey(_)) {
                        j = f;
                        break;
                    };
                }
                j
            }
        }
    }

    fn corrupt_auth_field_signature(
        corrupt_auth_fields: &TransactionAuth,
        corrupt_origin: bool,
        corrupt_sponsor: bool,
    ) -> TransactionAuth {
        let i = match corrupt_auth_fields {
            TransactionAuth::Standard(ref spend) => {
                if corrupt_origin {
                    find_signature(spend)
                } else {
                    0
                }
            }
            TransactionAuth::Sponsored(ref origin_spend, ref sponsor_spend) => {
                if corrupt_sponsor {
                    find_signature(sponsor_spend)
                } else if corrupt_origin {
                    find_signature(origin_spend)
                } else {
                    0
                }
            }
        };
        corrupt_auth_field(corrupt_auth_fields, i, corrupt_origin, corrupt_sponsor)
    }

    fn corrupt_auth_field_public_key(
        corrupt_auth_fields: &TransactionAuth,
        corrupt_origin: bool,
        corrupt_sponsor: bool,
    ) -> TransactionAuth {
        let i = match corrupt_auth_fields {
            TransactionAuth::Standard(ref spend) => {
                if corrupt_origin {
                    find_public_key(spend)
                } else {
                    0
                }
            }
            TransactionAuth::Sponsored(ref origin_spend, ref sponsor_spend) => {
                if corrupt_sponsor {
                    find_public_key(sponsor_spend)
                } else if corrupt_origin {
                    find_public_key(origin_spend)
                } else {
                    0
                }
            }
        };
        corrupt_auth_field(corrupt_auth_fields, i, corrupt_origin, corrupt_sponsor)
    }

    // verify that we can verify signatures over a transaction.
    // also verify that we can corrupt any field and fail to verify the transaction.
    // corruption tests should obviously fail -- the initial sighash changes if any of the
    // serialized data changes.
    fn test_signature_and_corruption(
        signed_tx: &StacksTransaction,
        corrupt_origin: bool,
        corrupt_sponsor: bool,
    ) {
        // signature is well-formed otherwise
        signed_tx
            .verify(TransactionAuthVerificationMode::EnforceLowS)
            .unwrap();

        let tx_with_high_s = signed_tx.with_negated_s_in_signature();
        let lenient_result = tx_with_high_s.verify(TransactionAuthVerificationMode::AllowHighS);
        let strict_result = tx_with_high_s.verify(TransactionAuthVerificationMode::EnforceLowS);
        assert!(
            lenient_result.is_ok(),
            "lenient verification result should be ok but was {lenient_result:?}",
        );
        assert!(
            strict_result.is_err(),
            "strict verification result should be error but was {strict_result:?}",
        );

        // mess with the auth hash code
        let mut corrupt_tx_hash_mode = signed_tx.clone();
        let mut corrupt_auth_hash_mode = corrupt_tx_hash_mode.auth().clone();
        match corrupt_auth_hash_mode {
            TransactionAuth::Standard(ref mut origin_condition) => {
                if corrupt_origin {
                    match origin_condition {
                        TransactionSpendingCondition::Singlesig(ref mut data) => {
                            data.hash_mode = if data.hash_mode == SinglesigHashMode::P2PKH {
                                SinglesigHashMode::P2WPKH
                            } else {
                                SinglesigHashMode::P2PKH
                            };
                        }
                        TransactionSpendingCondition::Multisig(ref mut data) => {
                            data.hash_mode = if data.hash_mode == MultisigHashMode::P2SH {
                                MultisigHashMode::P2WSH
                            } else {
                                MultisigHashMode::P2SH
                            };
                        }
                        TransactionSpendingCondition::OrderIndependentMultisig(ref mut data) => {
                            data.hash_mode =
                                if data.hash_mode == OrderIndependentMultisigHashMode::P2SH {
                                    OrderIndependentMultisigHashMode::P2WSH
                                } else {
                                    OrderIndependentMultisigHashMode::P2SH
                                };
                        }
                    }
                }
            }
            TransactionAuth::Sponsored(ref mut origin_condition, ref mut sponsored_condition) => {
                if corrupt_origin {
                    match origin_condition {
                        TransactionSpendingCondition::Singlesig(ref mut data) => {
                            data.hash_mode = if data.hash_mode == SinglesigHashMode::P2PKH {
                                SinglesigHashMode::P2WPKH
                            } else {
                                SinglesigHashMode::P2PKH
                            };
                        }
                        TransactionSpendingCondition::Multisig(ref mut data) => {
                            data.hash_mode = if data.hash_mode == MultisigHashMode::P2SH {
                                MultisigHashMode::P2WSH
                            } else {
                                MultisigHashMode::P2SH
                            };
                        }
                        TransactionSpendingCondition::OrderIndependentMultisig(ref mut data) => {
                            data.hash_mode =
                                if data.hash_mode == OrderIndependentMultisigHashMode::P2SH {
                                    OrderIndependentMultisigHashMode::P2WSH
                                } else {
                                    OrderIndependentMultisigHashMode::P2SH
                                };
                        }
                    }
                }
                if corrupt_sponsor {
                    match sponsored_condition {
                        TransactionSpendingCondition::Singlesig(ref mut data) => {
                            data.hash_mode = if data.hash_mode == SinglesigHashMode::P2PKH {
                                SinglesigHashMode::P2WPKH
                            } else {
                                SinglesigHashMode::P2PKH
                            };
                        }
                        TransactionSpendingCondition::Multisig(ref mut data) => {
                            data.hash_mode = if data.hash_mode == MultisigHashMode::P2SH {
                                MultisigHashMode::P2WSH
                            } else {
                                MultisigHashMode::P2SH
                            };
                        }
                        TransactionSpendingCondition::OrderIndependentMultisig(ref mut data) => {
                            data.hash_mode =
                                if data.hash_mode == OrderIndependentMultisigHashMode::P2SH {
                                    OrderIndependentMultisigHashMode::P2WSH
                                } else {
                                    OrderIndependentMultisigHashMode::P2SH
                                };
                        }
                    }
                }
            }
        };
        corrupt_tx_hash_mode.auth = corrupt_auth_hash_mode;
        assert!(corrupt_tx_hash_mode.txid() != signed_tx.txid());

        // mess with the auth nonce
        let mut corrupt_tx_nonce = signed_tx.clone();
        let mut corrupt_auth_nonce = corrupt_tx_nonce.auth().clone();
        match corrupt_auth_nonce {
            TransactionAuth::Standard(ref mut origin_condition) => {
                if corrupt_origin {
                    match origin_condition {
                        TransactionSpendingCondition::Singlesig(ref mut data) => {
                            data.nonce += 1;
                        }
                        TransactionSpendingCondition::Multisig(ref mut data) => {
                            data.nonce += 1;
                        }
                        TransactionSpendingCondition::OrderIndependentMultisig(ref mut data) => {
                            data.nonce += 1;
                        }
                    };
                }
            }
            TransactionAuth::Sponsored(ref mut origin_condition, ref mut sponsored_condition) => {
                if corrupt_origin {
                    match origin_condition {
                        TransactionSpendingCondition::Singlesig(ref mut data) => {
                            data.nonce += 1;
                        }
                        TransactionSpendingCondition::Multisig(ref mut data) => {
                            data.nonce += 1;
                        }
                        TransactionSpendingCondition::OrderIndependentMultisig(ref mut data) => {
                            data.nonce += 1;
                        }
                    }
                }
                if corrupt_sponsor {
                    match sponsored_condition {
                        TransactionSpendingCondition::Singlesig(ref mut data) => {
                            data.nonce += 1;
                        }
                        TransactionSpendingCondition::Multisig(ref mut data) => {
                            data.nonce += 1;
                        }
                        TransactionSpendingCondition::OrderIndependentMultisig(ref mut data) => {
                            data.nonce += 1;
                        }
                    }
                }
            }
        };
        corrupt_tx_nonce.auth = corrupt_auth_nonce;
        assert!(corrupt_tx_nonce.txid() != signed_tx.txid());

        // corrupt a signature
        let mut corrupt_tx_signature = signed_tx.clone();
        let corrupt_auth_signature = corrupt_tx_signature.auth;
        corrupt_tx_signature.auth =
            corrupt_auth_field_signature(&corrupt_auth_signature, corrupt_origin, corrupt_sponsor);

        assert!(corrupt_tx_signature.txid() != signed_tx.txid());

        // corrupt a public key
        let mut corrupt_tx_public_key = signed_tx.clone();
        let corrupt_auth_public_key = corrupt_tx_public_key.auth.clone();
        corrupt_tx_public_key.auth = corrupt_auth_field_public_key(
            &corrupt_auth_public_key,
            corrupt_origin,
            corrupt_sponsor,
        );

        assert!(corrupt_tx_public_key.txid() != signed_tx.txid());

        // mess with the auth num-signatures required, if applicable
        let mut corrupt_tx_signatures_required = signed_tx.clone();
        let mut corrupt_auth_signatures_required = corrupt_tx_signatures_required.auth().clone();
        let mut is_multisig_origin = false;
        let mut is_multisig_sponsor = false;
        match corrupt_auth_signatures_required {
            TransactionAuth::Standard(ref mut origin_condition) => {
                if corrupt_origin {
                    match origin_condition {
                        TransactionSpendingCondition::Singlesig(ref mut data) => {}
                        TransactionSpendingCondition::Multisig(ref mut data) => {
                            is_multisig_origin = true;
                            data.signatures_required += 1;
                        }
                        TransactionSpendingCondition::OrderIndependentMultisig(ref mut data) => {
                            is_multisig_origin = true;
                            data.signatures_required += 1;
                        }
                    };
                }
            }
            TransactionAuth::Sponsored(ref mut origin_condition, ref mut sponsored_condition) => {
                if corrupt_origin {
                    match origin_condition {
                        TransactionSpendingCondition::Singlesig(ref mut data) => {}
                        TransactionSpendingCondition::Multisig(ref mut data) => {
                            is_multisig_origin = true;
                            data.signatures_required += 1;
                        }
                        TransactionSpendingCondition::OrderIndependentMultisig(ref mut data) => {
                            is_multisig_origin = true;
                            data.signatures_required += 1;
                        }
                    }
                }
                if corrupt_sponsor {
                    match sponsored_condition {
                        TransactionSpendingCondition::Singlesig(ref mut data) => {}
                        TransactionSpendingCondition::Multisig(ref mut data) => {
                            is_multisig_sponsor = true;
                            data.signatures_required += 1;
                        }
                        TransactionSpendingCondition::OrderIndependentMultisig(ref mut data) => {
                            is_multisig_sponsor = true;
                            data.signatures_required += 1;
                        }
                    }
                }
            }
        };
        corrupt_tx_signatures_required.auth = corrupt_auth_signatures_required;
        if is_multisig_origin || is_multisig_sponsor {
            assert!(corrupt_tx_signatures_required.txid() != signed_tx.txid());
        }

        // mess with transaction version
        let mut corrupt_tx_version = signed_tx.clone();
        corrupt_tx_version.version = if corrupt_tx_version.version == TransactionVersion::Mainnet {
            TransactionVersion::Testnet
        } else {
            TransactionVersion::Mainnet
        };

        assert!(corrupt_tx_version.txid() != signed_tx.txid());

        // mess with chain ID
        let mut corrupt_tx_chain_id = signed_tx.clone();
        corrupt_tx_chain_id.chain_id = signed_tx.chain_id + 1;
        assert!(corrupt_tx_chain_id.txid() != signed_tx.txid());

        // mess with transaction fee
        let mut corrupt_tx_fee = signed_tx.clone();
        corrupt_tx_fee.set_tx_fee(corrupt_tx_fee.get_tx_fee() + 1);
        assert!(corrupt_tx_fee.txid() != signed_tx.txid());

        // mess with anchor mode
        let mut corrupt_tx_anchor_mode = signed_tx.clone();
        corrupt_tx_anchor_mode.anchor_mode =
            if corrupt_tx_anchor_mode.anchor_mode == TransactionAnchorMode::OffChainOnly {
                TransactionAnchorMode::OnChainOnly
            } else if corrupt_tx_anchor_mode.anchor_mode == TransactionAnchorMode::OnChainOnly {
                TransactionAnchorMode::Any
            } else {
                TransactionAnchorMode::OffChainOnly
            };

        assert!(corrupt_tx_anchor_mode.txid() != signed_tx.txid());

        // mess with post conditions
        let mut corrupt_tx_post_conditions = signed_tx.clone();
        corrupt_tx_post_conditions
            .post_conditions
            .push(TransactionPostCondition::STX(
                PostConditionPrincipal::Origin,
                FungibleConditionCode::SentGt,
                0,
            ));

        let mut corrupt_tx_post_condition_mode = signed_tx.clone();
        corrupt_tx_post_condition_mode.post_condition_mode =
            match corrupt_tx_post_condition_mode.post_condition_mode {
                TransactionPostConditionMode::Allow => TransactionPostConditionMode::Deny,
                TransactionPostConditionMode::Deny => TransactionPostConditionMode::Originator,
                TransactionPostConditionMode::Originator => TransactionPostConditionMode::Allow,
            };

        // mess with payload
        let mut corrupt_tx_payload = signed_tx.clone();
        corrupt_tx_payload.payload = match corrupt_tx_payload.payload {
            TransactionPayload::TokenTransfer(ref addr, ref amount, ref memo) => {
                TransactionPayload::TokenTransfer(addr.clone(), amount + 1, memo.clone())
            }
            TransactionPayload::ContractCall(_) => TransactionPayload::SmartContract(
                TransactionSmartContract {
                    name: ContractName::try_from("corrupt-name").unwrap(),
                    code_body: StacksString::from_str("corrupt body").unwrap(),
                },
                None,
            ),
            TransactionPayload::SmartContract(..) => {
                TransactionPayload::ContractCall(TransactionContractCall {
                    address: StacksAddress::new(1, Hash160([0xff; 20])).unwrap(),
                    contract_name: ContractName::try_from("hello-world").unwrap(),
                    function_name: ClarityName::try_from("hello-function").unwrap(),
                    function_args: vec![Value::Int(0)],
                })
            }
            TransactionPayload::PoisonMicroblock(ref h1, ref h2) => {
                let mut corrupt_h1 = h1.clone();
                let mut corrupt_h2 = h2.clone();

                corrupt_h1.sequence += 1;
                corrupt_h2.sequence += 1;
                TransactionPayload::PoisonMicroblock(corrupt_h1, corrupt_h2)
            }
            TransactionPayload::Coinbase(ref buf, ref recipient_opt, ref vrf_proof_opt) => {
                let mut corrupt_buf_bytes = *buf.as_bytes();
                corrupt_buf_bytes[0] = (((corrupt_buf_bytes[0] as u16) + 1) % 256) as u8;

                let corrupt_buf = CoinbasePayload(corrupt_buf_bytes);
                TransactionPayload::Coinbase(
                    corrupt_buf,
                    recipient_opt.clone(),
                    vrf_proof_opt.clone(),
                )
            }
            TransactionPayload::TenureChange(ref tc) => {
                let mut hash = *tc.pubkey_hash.as_bytes();
                hash[8] ^= 0x04; // Flip one bit
                let corrupt_tc = TenureChangePayload {
                    pubkey_hash: hash.into(),
                    ..tc.clone()
                };
                TransactionPayload::TenureChange(corrupt_tc)
            }
        };
        assert!(corrupt_tx_payload.txid() != signed_tx.txid());

        let mut corrupt_transactions = vec![
            corrupt_tx_hash_mode,
            corrupt_tx_nonce,
            corrupt_tx_signature,
            corrupt_tx_public_key,
            corrupt_tx_version,
            corrupt_tx_chain_id,
            corrupt_tx_fee,
            corrupt_tx_anchor_mode,
            corrupt_tx_post_condition_mode,
            corrupt_tx_post_conditions,
            corrupt_tx_payload,
        ];
        if is_multisig_origin || is_multisig_sponsor {
            corrupt_transactions.push(corrupt_tx_signatures_required);
        }

        // make sure all corrupted transactions fail
        for corrupt_tx in corrupt_transactions.iter() {
            assert!(
                matches!(
                    corrupt_tx.verify(TransactionAuthVerificationMode::AllowHighS),
                    Err(AuthError::VerifyingError(msg))
                ),
                "corrupt_tx: {corrupt_tx:#?}"
            );
        }

        // exhaustive test -- mutate each byte
        let mut tx_bytes: Vec<u8> = vec![];
        signed_tx.consensus_serialize(&mut tx_bytes).unwrap();
        test_debug!("mutate tx: {}", to_hex(&tx_bytes));
        for i in 0..tx_bytes.len() {
            let next_byte = tx_bytes[i] as u16;
            tx_bytes[i] = ((next_byte + 1) % 0xff) as u8;

            // test_debug!("mutate byte {}", &i);
            let mut cursor = io::Cursor::new(&tx_bytes);
            let mut reader = LogReader::from_reader(&mut cursor);
            if let Ok(corrupt_tx) = StacksTransaction::consensus_deserialize(&mut reader) {
                let mut corrupt_tx_bytes = vec![];
                corrupt_tx
                    .consensus_serialize(&mut corrupt_tx_bytes)
                    .unwrap();
                if corrupt_tx_bytes.len() < tx_bytes.len() {
                    // didn't parse fully; the block-parsing logic would reject this block.
                    tx_bytes[i] = next_byte as u8;
                    continue;
                }
                assert!(
                    corrupt_tx
                        .verify(TransactionAuthVerificationMode::AllowHighS)
                        .is_err()
                        || corrupt_tx == *signed_tx,
                    "corrupt tx: {corrupt_tx:#?}\n signed_tx: {signed_tx:#?}"
                );
            }
            // restore
            tx_bytes[i] = next_byte as u8;
        }
    }

    #[test]
    fn tx_stacks_transaction_codec() {
        let all_txs = codec_all_transactions(
            &TransactionVersion::Mainnet,
            0,
            &TransactionAnchorMode::OnChainOnly,
            &TransactionPostConditionMode::Deny,
            StacksEpochId::latest(),
        );
        for tx in all_txs.iter() {
            let mut tx_bytes = vec![
                // version
                TransactionVersion::Mainnet as u8,
                // chain ID
                0x00,
                0x00,
                0x00,
                0x00,
            ];

            tx.auth.consensus_serialize(&mut tx_bytes).unwrap();
            tx_bytes.append(&mut vec![TransactionAnchorMode::OnChainOnly as u8]);
            tx_bytes.append(&mut vec![TransactionPostConditionMode::Deny as u8]);
            tx.post_conditions
                .consensus_serialize(&mut tx_bytes)
                .unwrap();
            tx.payload.consensus_serialize(&mut tx_bytes).unwrap();

            test_debug!("---------");
            test_debug!("test tx:\n{:?}", &tx);
            test_debug!("---------");
            test_debug!("text tx bytes:\n{}", &to_hex(&tx_bytes));

            check_codec_and_corruption::<StacksTransaction>(tx, &tx_bytes);
        }
    }

    fn tx_stacks_transaction_test_txs(auth: &TransactionAuth) -> Vec<StacksTransaction> {
        let header_1 = StacksMicroblockHeader {
            version: 0x12,
            sequence: 0x34,
            prev_block: EMPTY_MICROBLOCK_PARENT_HASH.clone(),
            tx_merkle_root: Sha512Trunc256Sum([1u8; 32]),
            signature: MessageSignature([2u8; 65]),
        };

        let header_2 = StacksMicroblockHeader {
            version: 0x12,
            sequence: 0x34,
            prev_block: EMPTY_MICROBLOCK_PARENT_HASH.clone(),
            tx_merkle_root: Sha512Trunc256Sum([2u8; 32]),
            signature: MessageSignature([3u8; 65]),
        };

        let hello_contract_name = "hello-contract-name";
        let hello_asset_name = "hello-asset";
        let hello_token_name = "hello-token";

        let contract_name = ContractName::try_from(hello_contract_name).unwrap();
        let asset_name = ClarityName::try_from(hello_asset_name).unwrap();
        let token_name = StacksString::from_str(hello_token_name).unwrap();

        let asset_value = StacksString::from_str("asset-value").unwrap();

        let contract_addr = StacksAddress::new(2, Hash160([0xfe; 20])).unwrap();

        let asset_info = AssetInfo {
            contract_address: contract_addr.clone(),
            contract_name,
            asset_name,
        };

        let stx_address = StacksAddress::new(1, Hash160([0xff; 20])).unwrap();

        let tx_contract_call = StacksTransaction::new(
            TransactionVersion::Mainnet,
            auth.clone(),
            TransactionPayload::new_contract_call(
                stx_address.clone(),
                "hello",
                "world",
                vec![Value::Int(1)],
            )
            .unwrap(),
        );

        let tx_smart_contract = StacksTransaction::new(
            TransactionVersion::Mainnet,
            auth.clone(),
            TransactionPayload::new_smart_contract("name-contract", "hello smart contract", None)
                .unwrap(),
        );

        let tx_coinbase = StacksTransaction::new(
            TransactionVersion::Mainnet,
            auth.clone(),
            TransactionPayload::Coinbase(CoinbasePayload([0u8; 32]), None, None),
        );

        let tx_stx = StacksTransaction::new(
            TransactionVersion::Mainnet,
            auth.clone(),
            TransactionPayload::TokenTransfer(
                stx_address.clone().into(),
                123,
                TokenTransferMemo([0u8; 34]),
            ),
        );

        let tx_poison = StacksTransaction::new(
            TransactionVersion::Mainnet,
            auth.clone(),
            TransactionPayload::PoisonMicroblock(header_1, header_2),
        );

        let tx_tenure_change = StacksTransaction::new(
            TransactionVersion::Mainnet,
            auth.clone(),
            TransactionPayload::TenureChange(TenureChangePayload {
                tenure_consensus_hash: ConsensusHash([0x01; 20]),
                prev_tenure_consensus_hash: ConsensusHash([0x02; 20]),
                burn_view_consensus_hash: ConsensusHash([0x03; 20]),
                previous_tenure_end: StacksBlockId([0x00; 32]),
                previous_tenure_blocks: 0,
                cause: TenureChangeCause::BlockFound,
                pubkey_hash: Hash160([0x00; 20]),
            }),
        );

        let txs = vec![
            tx_contract_call,
            tx_smart_contract,
            tx_coinbase,
            tx_stx,
            tx_poison,
            tx_tenure_change,
        ];
        txs
    }

    fn check_oversign_origin_singlesig(signed_tx: &mut StacksTransaction) {
        let txid_before = signed_tx.txid();
        if let Err(AuthError::SigningError(msg)) = signed_tx.append_next_origin(
            &StacksPublicKey::from_hex(
                "03442a63b6d312710b1d6b24d803120dc6f5714352ba57907863b78de55974123c",
            )
            .unwrap(),
        ) {
            assert_eq!(&msg, "Not a multisig condition");
        } else {
            panic!("Expexcted a signing error");
        }

        // no change affected
        assert_eq!(txid_before, signed_tx.txid());
    }

    fn check_sign_no_sponsor(signed_tx: &mut StacksTransaction) {
        let txid_before = signed_tx.txid();
        if let Err(AuthError::SigningError(msg)) = signed_tx.append_next_sponsor(
            &StacksPublicKey::from_hex(
                "03442a63b6d312710b1d6b24d803120dc6f5714352ba57907863b78de55974123c",
            )
            .unwrap(),
        ) {
            assert_eq!(
                &msg,
                "Cannot appned a public key to the sponsor of a standard auth condition"
            );
        } else {
            panic!("Expected a signing error");
        }
        assert_eq!(txid_before, signed_tx.txid());
    }

    fn check_oversign_sponsor_singlesig(signed_tx: &mut StacksTransaction) {
        let txid_before = signed_tx.txid();
        if let Err(AuthError::SigningError(msg)) = signed_tx.append_next_sponsor(
            &StacksPublicKey::from_hex(
                "03442a63b6d312710b1d6b24d803120dc6f5714352ba57907863b78de55974123c",
            )
            .unwrap(),
        ) {
            assert_eq!(&msg, "Not a multisig condition");
        } else {
            panic!("Expected a signing error");
        }
        assert_eq!(txid_before, signed_tx.txid());
    }

    fn is_order_independent_multisig(tx: &StacksTransaction) -> bool {
        let spending_condition = match &tx.auth {
            TransactionAuth::Standard(origin) => origin,
            TransactionAuth::Sponsored(_, sponsor) => sponsor,
        };
        matches!(
            spending_condition,
            TransactionSpendingCondition::OrderIndependentMultisig(..)
        )
    }

    fn check_oversign_origin_multisig(signed_tx: &StacksTransaction) {
        let tx = signed_tx.clone();
        let privk = StacksPrivateKey::from_hex(
            "c6ebf45dabca8cac9a25ae39ab690743b96eb2b0960066e98ba6df50d6f9293b01",
        )
        .unwrap();

        let mut tx_signer = StacksTransactionSigner::new(&tx);
        tx_signer.disable_checks();
        tx_signer.sign_origin(&privk).unwrap();
        let oversigned_tx = tx_signer.get_tx().unwrap();

        let Err(AuthError::VerifyingError(msg)) =
            oversigned_tx.verify(TransactionAuthVerificationMode::AllowHighS)
        else {
            panic!("Expected a verifying error");
        };
        if is_order_independent_multisig(&oversigned_tx) {
            assert!(
                msg.contains("Signer hash does not equal hash of public key(s)"),
                "{msg}"
            )
        } else {
            assert_eq!(&msg, "Incorrect number of signatures")
        }
    }

    fn check_oversign_origin_multisig_uncompressed(signed_tx: &StacksTransaction) {
        let tx = signed_tx.clone();
        let privk = StacksPrivateKey::from_hex(
            "c6ebf45dabca8cac9a25ae39ab690743b96eb2b0960066e98ba6df50d6f9293b",
        )
        .unwrap();

        let mut tx_signer = StacksTransactionSigner::new(&tx);
        tx_signer.disable_checks();

        match tx_signer.pop_origin_auth_field().unwrap() {
            TransactionAuthField::Signature(_, _) => {
                tx_signer.sign_origin(&privk).unwrap();
            }
            TransactionAuthField::PublicKey(_) => {
                tx_signer
                    .append_origin(&StacksPublicKey::from_private(&privk))
                    .unwrap();
            }
        };

        let oversigned_tx = tx_signer.get_tx().unwrap();

        let Err(AuthError::VerifyingError(msg)) =
            oversigned_tx.verify(TransactionAuthVerificationMode::AllowHighS)
        else {
            panic!("Expected a verifying error");
        };
        assert_eq!(&msg, "Uncompressed keys are not allowed in this hash mode");
    }

    fn check_oversign_sponsor_multisig(signed_tx: &StacksTransaction) {
        let tx = signed_tx.clone();
        let privk = StacksPrivateKey::from_hex(
            "c6ebf45dabca8cac9a25ae39ab690743b96eb2b0960066e98ba6df50d6f9293b01",
        )
        .unwrap();

        let mut tx_signer = StacksTransactionSigner::new(&tx);
        tx_signer.disable_checks();
        tx_signer.sign_sponsor(&privk).unwrap();
        let oversigned_tx = tx_signer.get_tx().unwrap();

        let Err(AuthError::VerifyingError(msg)) =
            oversigned_tx.verify(TransactionAuthVerificationMode::AllowHighS)
        else {
            panic!("Expected a verifying error");
        };
        if is_order_independent_multisig(&oversigned_tx) {
            assert!(
                msg.contains("Signer hash does not equal hash of public key(s)"),
                "{msg}"
            )
        } else {
            assert_eq!(&msg, "Incorrect number of signatures")
        }
    }

    fn check_oversign_sponsor_multisig_uncompressed(signed_tx: &StacksTransaction) {
        let tx = signed_tx.clone();
        let privk = StacksPrivateKey::from_hex(
            "c6ebf45dabca8cac9a25ae39ab690743b96eb2b0960066e98ba6df50d6f9293b",
        )
        .unwrap();

        let mut tx_signer = StacksTransactionSigner::new(&tx);
        tx_signer.disable_checks();

        match tx_signer.pop_sponsor_auth_field().unwrap() {
            TransactionAuthField::Signature(_, _) => {
                tx_signer.sign_sponsor(&privk).unwrap();
            }
            TransactionAuthField::PublicKey(_) => {
                tx_signer
                    .append_sponsor(&StacksPublicKey::from_private(&privk))
                    .unwrap();
            }
        };

        let oversigned_tx = tx_signer.get_tx().unwrap();

        let Err(AuthError::VerifyingError(msg)) =
            oversigned_tx.verify(TransactionAuthVerificationMode::AllowHighS)
        else {
            panic!("Expected a verifying error");
        };
        assert_eq!(&msg, "Uncompressed keys are not allowed in this hash mode");
    }

    #[test]
    fn tx_stacks_transaction_sign_verify_standard_p2pkh() {
        let privk = StacksPrivateKey::from_hex(
            "6d430bb91222408e7706c9001cfaeb91b08c2be6d5ac95779ab52c6b431950e001",
        )
        .unwrap();
        let origin_auth = TransactionAuth::Standard(
            TransactionSpendingCondition::new_singlesig_p2pkh(StacksPublicKey::from_private(
                &privk,
            ))
            .unwrap(),
        );

        let origin_address = origin_auth.origin().address_mainnet();
        assert_eq!(
            origin_address,
            StacksAddress::new(
                C32_ADDRESS_VERSION_MAINNET_SINGLESIG,
                Hash160::from_hex("143e543243dfcd8c02a12ad7ea371bd07bc91df9").unwrap()
            )
            .unwrap(),
        );

        let txs = tx_stacks_transaction_test_txs(&origin_auth);

        for tx in txs {
            assert_eq!(tx.auth().origin().num_signatures(), 0);

            let mut tx_signer = StacksTransactionSigner::new(&tx);
            tx_signer.sign_origin(&privk).unwrap();
            let mut signed_tx = tx_signer.get_tx().unwrap();

            assert_eq!(signed_tx.auth().origin().num_signatures(), 1);

            // try to over-sign
            check_oversign_origin_singlesig(&mut signed_tx);
            check_sign_no_sponsor(&mut signed_tx);

            // tx and signed_tx are otherwise equal
            assert_eq!(tx.version, signed_tx.version);
            assert_eq!(tx.get_tx_fee(), signed_tx.get_tx_fee());
            assert_eq!(tx.get_origin_nonce(), signed_tx.get_origin_nonce());
            assert_eq!(tx.get_sponsor_nonce(), signed_tx.get_sponsor_nonce());
            assert_eq!(tx.anchor_mode, signed_tx.anchor_mode);
            assert_eq!(tx.post_condition_mode, signed_tx.post_condition_mode);
            assert_eq!(tx.post_conditions, signed_tx.post_conditions);
            assert_eq!(tx.payload, signed_tx.payload);

            // auth is standard and public key is compressed
            if let TransactionAuth::Standard(TransactionSpendingCondition::Singlesig(ref data)) =
                signed_tx.auth
            {
                assert_eq!(data.key_encoding, TransactionPublicKeyEncoding::Compressed);
                assert_eq!(data.signer, *origin_address.bytes());
            } else {
                panic!("Expected a standard singlesig auth condition");
            }

            test_signature_and_corruption(&signed_tx, true, false);
        }
    }

    #[test]
    fn tx_stacks_transaction_sign_verify_sponsored_p2pkh() {
        let privk = StacksPrivateKey::from_hex(
            "6d430bb91222408e7706c9001cfaeb91b08c2be6d5ac95779ab52c6b431950e001",
        )
        .unwrap();
        let privk_sponsor = StacksPrivateKey::from_hex(
            "807bbe9e471ac976592cc35e3056592ecc0f778ee653fced3b491a122dd8d59701",
        )
        .unwrap();
        let privk_diff_sponsor = StacksPrivateKey::from_hex(
            "d5200dee706ee53ae98a03fba6cf4fdcc5084c30cfa9e1b3462dcdeaa3e0f1d2",
        )
        .unwrap();

        let auth = TransactionAuth::Sponsored(
            TransactionSpendingCondition::new_singlesig_p2pkh(StacksPublicKey::from_private(
                &privk,
            ))
            .unwrap(),
            TransactionSpendingCondition::new_singlesig_p2pkh(StacksPublicKey::from_private(
                &privk_sponsor,
            ))
            .unwrap(), // will be replaced once the origin finishes signing
        );

        let origin_address = auth.origin().address_mainnet();
        assert_eq!(
            origin_address,
            StacksAddress::new(
                C32_ADDRESS_VERSION_MAINNET_SINGLESIG,
                Hash160::from_hex("143e543243dfcd8c02a12ad7ea371bd07bc91df9").unwrap()
            )
            .unwrap(),
        );

        let sponsor_address = auth.sponsor().unwrap().address_mainnet();
        assert_eq!(
            sponsor_address,
            StacksAddress::new(
                C32_ADDRESS_VERSION_MAINNET_SINGLESIG,
                Hash160::from_hex("3597aaa4bde720be93e3829aae24e76e7fcdfd3e").unwrap(),
            )
            .unwrap(),
        );

        let diff_sponsor_address = StacksAddress::new(
            C32_ADDRESS_VERSION_MAINNET_SINGLESIG,
            Hash160::from_hex("a139de6733cef9e4663c4a093c1a7390a1dcc297").unwrap(),
        )
        .unwrap();

        let txs = tx_stacks_transaction_test_txs(&auth);

        for mut tx in txs {
            assert_eq!(tx.auth().origin().num_signatures(), 0);
            assert_eq!(tx.auth().sponsor().unwrap().num_signatures(), 0);

            tx.set_tx_fee(123);
            tx.set_sponsor_nonce(456).unwrap();
            let mut tx_signer = StacksTransactionSigner::new(&tx);

            test_debug!("Sign origin");
            tx_signer.sign_origin(&privk).unwrap();

            // sponsor sets keys, nonce, and fee after origin signs
            let origin_tx = tx_signer.get_tx_incomplete();

            let mut sponsor_auth = TransactionSpendingCondition::new_singlesig_p2pkh(
                StacksPublicKey::from_private(&privk_diff_sponsor),
            )
            .unwrap();
            sponsor_auth.set_tx_fee(456);
            sponsor_auth.set_nonce(789);

            let mut tx_sponsor_signer =
                StacksTransactionSigner::new_sponsor(&origin_tx, sponsor_auth).unwrap();

            test_debug!("Sign sponsor");
            tx_sponsor_signer.sign_sponsor(&privk_diff_sponsor).unwrap();

            // make comparable
            tx.set_tx_fee(456);
            tx.set_sponsor_nonce(789).unwrap();
            let mut signed_tx = tx_sponsor_signer.get_tx().unwrap();

            assert_eq!(signed_tx.auth().origin().num_signatures(), 1);
            assert_eq!(signed_tx.auth().sponsor().unwrap().num_signatures(), 1);

            // try to over-sign
            check_oversign_origin_singlesig(&mut signed_tx);
            check_oversign_sponsor_singlesig(&mut signed_tx);

            // tx and signed_tx are otherwise equal
            assert_eq!(tx.version, signed_tx.version);
            assert_eq!(tx.chain_id, signed_tx.chain_id);
            assert_eq!(tx.get_tx_fee(), 456);
            assert_eq!(tx.get_origin_nonce(), signed_tx.get_origin_nonce());
            assert_eq!(tx.get_sponsor_nonce(), signed_tx.get_sponsor_nonce());
            assert_eq!(tx.anchor_mode, signed_tx.anchor_mode);
            assert_eq!(tx.post_condition_mode, signed_tx.post_condition_mode);
            assert_eq!(tx.post_conditions, signed_tx.post_conditions);
            assert_eq!(tx.payload, signed_tx.payload);

            // auth is a sponsor and public key is compressed.
            // auth sponsor is privk_diff_sponsor
            if let TransactionAuth::Sponsored(
                TransactionSpendingCondition::Singlesig(origin_data),
                TransactionSpendingCondition::Singlesig(sponsor_data),
            ) = &signed_tx.auth
            {
                assert_eq!(
                    origin_data.key_encoding,
                    TransactionPublicKeyEncoding::Compressed
                );
                assert_eq!(origin_data.signer, *origin_address.bytes());

                assert_eq!(
                    sponsor_data.key_encoding,
                    TransactionPublicKeyEncoding::Uncompressed
                ); // not what the origin would have seen
                assert_eq!(sponsor_data.signer, *diff_sponsor_address.bytes());
                // not what the origin would have seen
            } else {
                panic!("Unexpected auth condition");
            }

            test_signature_and_corruption(&signed_tx, true, false);
            test_signature_and_corruption(&signed_tx, false, true);
        }
    }

    #[test]
    fn tx_stacks_transaction_sign_verify_standard_p2pkh_uncompressed() {
        let privk = StacksPrivateKey::from_hex(
            "6d430bb91222408e7706c9001cfaeb91b08c2be6d5ac95779ab52c6b431950e0",
        )
        .unwrap();
        let origin_auth = TransactionAuth::Standard(
            TransactionSpendingCondition::new_singlesig_p2pkh(StacksPublicKey::from_private(
                &privk,
            ))
            .unwrap(),
        );

        let origin_address = origin_auth.origin().address_mainnet();
        assert_eq!(
            origin_address,
            StacksAddress::new(
                C32_ADDRESS_VERSION_MAINNET_SINGLESIG,
                Hash160::from_hex("693cd53eb47d4749762d7cfaf46902bda5be5f97").unwrap(),
            )
            .unwrap()
        );

        let txs = tx_stacks_transaction_test_txs(&origin_auth);

        for tx in txs {
            assert_eq!(tx.auth().origin().num_signatures(), 0);

            let mut tx_signer = StacksTransactionSigner::new(&tx);
            tx_signer.sign_origin(&privk).unwrap();
            let mut signed_tx = tx_signer.get_tx().unwrap();

            // try to over-sign
            check_oversign_origin_singlesig(&mut signed_tx);
            check_sign_no_sponsor(&mut signed_tx);

            assert_eq!(signed_tx.auth().origin().num_signatures(), 1);

            // tx and signed_tx are otherwise equal
            assert_eq!(tx.version, signed_tx.version);
            assert_eq!(tx.get_tx_fee(), signed_tx.get_tx_fee());
            assert_eq!(tx.get_origin_nonce(), signed_tx.get_origin_nonce());
            assert_eq!(tx.get_sponsor_nonce(), signed_tx.get_sponsor_nonce());
            assert_eq!(tx.anchor_mode, signed_tx.anchor_mode);
            assert_eq!(tx.post_condition_mode, signed_tx.post_condition_mode);
            assert_eq!(tx.post_conditions, signed_tx.post_conditions);
            assert_eq!(tx.payload, signed_tx.payload);

            // auth is standard and public key is uncompressed
            if let TransactionAuth::Standard(TransactionSpendingCondition::Singlesig(data)) =
                &signed_tx.auth
            {
                assert_eq!(
                    data.key_encoding,
                    TransactionPublicKeyEncoding::Uncompressed
                );
                assert_eq!(data.signer, *origin_address.bytes());
            } else {
                panic!("Unexpected auth condition");
            }

            test_signature_and_corruption(&signed_tx, true, false);
        }
    }

    #[test]
    fn tx_stacks_transaction_sign_verify_sponsored_p2pkh_uncompressed() {
        let privk = StacksPrivateKey::from_hex(
            "807bbe9e471ac976592cc35e3056592ecc0f778ee653fced3b491a122dd8d59701",
        )
        .unwrap();
        let privk_sponsored = StacksPrivateKey::from_hex(
            "6d430bb91222408e7706c9001cfaeb91b08c2be6d5ac95779ab52c6b431950e0",
        )
        .unwrap();

        let mut random_sponsor = StacksPrivateKey::random(); // what the origin sees
        random_sponsor.set_compress_public(true);

        let auth = TransactionAuth::Sponsored(
            TransactionSpendingCondition::new_singlesig_p2pkh(StacksPublicKey::from_private(
                &privk,
            ))
            .unwrap(),
            TransactionSpendingCondition::new_singlesig_p2pkh(StacksPublicKey::from_private(
                &random_sponsor,
            ))
            .unwrap(),
        );

        let real_sponsor = TransactionSpendingCondition::new_singlesig_p2pkh(
            StacksPublicKey::from_private(&privk_sponsored),
        )
        .unwrap();

        let origin_address = auth.origin().address_mainnet();
        let sponsor_address = real_sponsor.address_mainnet();

        assert_eq!(
            origin_address,
            StacksAddress::new(
                C32_ADDRESS_VERSION_MAINNET_SINGLESIG,
                Hash160::from_hex("3597aaa4bde720be93e3829aae24e76e7fcdfd3e").unwrap(),
            )
            .unwrap()
        );
        assert_eq!(
            sponsor_address,
            StacksAddress::new(
                C32_ADDRESS_VERSION_MAINNET_SINGLESIG,
                Hash160::from_hex("693cd53eb47d4749762d7cfaf46902bda5be5f97").unwrap(),
            )
            .unwrap()
        );

        let txs = tx_stacks_transaction_test_txs(&auth);

        for mut tx in txs {
            assert_eq!(tx.auth().origin().num_signatures(), 0);
            assert_eq!(tx.auth().sponsor().unwrap().num_signatures(), 0);

            tx.set_tx_fee(123);
            tx.set_sponsor_nonce(456).unwrap();

            let mut tx_signer = StacksTransactionSigner::new(&tx);
            tx_signer.sign_origin(&privk).unwrap();

            // sponsor sets and pays fee after origin signs
            let mut origin_tx = tx_signer.get_tx_incomplete();
            origin_tx.auth.set_sponsor(real_sponsor.clone()).unwrap();
            origin_tx.set_tx_fee(456);
            origin_tx.set_sponsor_nonce(789).unwrap();
            tx_signer.resume(&origin_tx);

            tx_signer.sign_sponsor(&privk_sponsored).unwrap();

            tx.set_tx_fee(456);
            tx.set_sponsor_nonce(789).unwrap();
            let mut signed_tx = tx_signer.get_tx().unwrap();

            // try to over-sign
            check_oversign_origin_singlesig(&mut signed_tx);
            check_oversign_sponsor_singlesig(&mut signed_tx);

            assert_eq!(signed_tx.auth().origin().num_signatures(), 1);
            assert_eq!(signed_tx.auth().sponsor().unwrap().num_signatures(), 1);

            // tx and signed_tx are otherwise equal
            assert_eq!(tx.version, signed_tx.version);
            assert_eq!(tx.chain_id, signed_tx.chain_id);
            assert_eq!(tx.get_tx_fee(), signed_tx.get_tx_fee());
            assert_eq!(tx.get_origin_nonce(), signed_tx.get_origin_nonce());
            assert_eq!(tx.get_sponsor_nonce(), signed_tx.get_sponsor_nonce());
            assert_eq!(tx.anchor_mode, signed_tx.anchor_mode);
            assert_eq!(tx.post_condition_mode, signed_tx.post_condition_mode);
            assert_eq!(tx.post_conditions, signed_tx.post_conditions);
            assert_eq!(tx.payload, signed_tx.payload);

            // auth is standard and public key is uncompressed
            if let TransactionAuth::Sponsored(
                TransactionSpendingCondition::Singlesig(origin_data),
                TransactionSpendingCondition::Singlesig(sponsor_data),
            ) = &signed_tx.auth
            {
                assert_eq!(
                    origin_data.key_encoding,
                    TransactionPublicKeyEncoding::Compressed
                );
                assert_eq!(origin_data.signer, *origin_address.bytes());

                assert_eq!(
                    sponsor_data.key_encoding,
                    TransactionPublicKeyEncoding::Uncompressed
                );
                assert_eq!(sponsor_data.signer, *sponsor_address.bytes());
            } else {
                panic!("Unexpected auth condition");
            }

            test_signature_and_corruption(&signed_tx, true, false);
            test_signature_and_corruption(&signed_tx, false, true);
        }
    }

    #[test]
    fn tx_stacks_transaction_sign_verify_standard_p2sh() {
        let privk_1 = StacksPrivateKey::from_hex(
            "6d430bb91222408e7706c9001cfaeb91b08c2be6d5ac95779ab52c6b431950e001",
        )
        .unwrap();
        let privk_2 = StacksPrivateKey::from_hex(
            "2a584d899fed1d24e26b524f202763c8ab30260167429f157f1c119f550fa6af01",
        )
        .unwrap();
        let privk_3 = StacksPrivateKey::from_hex(
            "d5200dee706ee53ae98a03fba6cf4fdcc5084c30cfa9e1b3462dcdeaa3e0f1d201",
        )
        .unwrap();

        let pubk_1 = StacksPublicKey::from_private(&privk_1);
        let pubk_2 = StacksPublicKey::from_private(&privk_2);
        let pubk_3 = StacksPublicKey::from_private(&privk_3);

        let origin_auth = TransactionAuth::Standard(
            TransactionSpendingCondition::new_multisig_p2sh(
                2,
                vec![pubk_1.clone(), pubk_2.clone(), pubk_3.clone()],
            )
            .unwrap(),
        );

        let origin_address = origin_auth.origin().address_mainnet();
        assert_eq!(
            origin_address,
            StacksAddress::new(
                C32_ADDRESS_VERSION_MAINNET_MULTISIG,
                Hash160::from_hex("a23ea89d6529ac48ac766f720e480beec7f19273").unwrap(),
            )
            .unwrap()
        );

        let txs = tx_stacks_transaction_test_txs(&origin_auth);

        for tx in txs {
            assert_eq!(tx.auth().origin().num_signatures(), 0);

            let mut tx_signer = StacksTransactionSigner::new(&tx);
            tx_signer.sign_origin(&privk_1).unwrap();
            tx_signer.sign_origin(&privk_2).unwrap();
            tx_signer.append_origin(&pubk_3).unwrap();
            let mut signed_tx = tx_signer.get_tx().unwrap();

            check_oversign_origin_multisig(&signed_tx);
            check_sign_no_sponsor(&mut signed_tx);

            assert_eq!(signed_tx.auth().origin().num_signatures(), 2);

            // tx and signed_tx are otherwise equal
            assert_eq!(tx.version, signed_tx.version);
            assert_eq!(tx.get_tx_fee(), signed_tx.get_tx_fee());
            assert_eq!(tx.get_origin_nonce(), signed_tx.get_origin_nonce());
            assert_eq!(tx.get_sponsor_nonce(), signed_tx.get_sponsor_nonce());
            assert_eq!(tx.anchor_mode, signed_tx.anchor_mode);
            assert_eq!(tx.post_condition_mode, signed_tx.post_condition_mode);
            assert_eq!(tx.post_conditions, signed_tx.post_conditions);
            assert_eq!(tx.payload, signed_tx.payload);

            // auth is standard and first two auth fields are signatures for compressed keys.
            // third field is the third public key
            if let TransactionAuth::Standard(TransactionSpendingCondition::Multisig(data)) =
                &signed_tx.auth
            {
                assert_eq!(data.signer, *origin_address.bytes());
                assert_eq!(data.fields.len(), 3);
                assert!(data.fields[0].is_signature());
                assert!(data.fields[1].is_signature());
                assert!(data.fields[2].is_public_key());

                assert_eq!(
                    data.fields[0].as_signature().unwrap().0,
                    TransactionPublicKeyEncoding::Compressed
                );
                assert_eq!(
                    data.fields[1].as_signature().unwrap().0,
                    TransactionPublicKeyEncoding::Compressed
                );
                assert_eq!(data.fields[2].as_public_key().unwrap(), pubk_3);
            } else {
                panic!("Unexpected auth condition");
            }
            test_signature_and_corruption(&signed_tx, true, false);
        }
    }

    #[test]
    fn tx_stacks_transaction_sign_verify_sponsored_p2sh() {
        let origin_privk = StacksPrivateKey::from_hex(
            "807bbe9e471ac976592cc35e3056592ecc0f778ee653fced3b491a122dd8d59701",
        )
        .unwrap();

        let privk_1 = StacksPrivateKey::from_hex(
            "6d430bb91222408e7706c9001cfaeb91b08c2be6d5ac95779ab52c6b431950e001",
        )
        .unwrap();
        let privk_2 = StacksPrivateKey::from_hex(
            "2a584d899fed1d24e26b524f202763c8ab30260167429f157f1c119f550fa6af01",
        )
        .unwrap();
        let privk_3 = StacksPrivateKey::from_hex(
            "d5200dee706ee53ae98a03fba6cf4fdcc5084c30cfa9e1b3462dcdeaa3e0f1d201",
        )
        .unwrap();

        let pubk_1 = StacksPublicKey::from_private(&privk_1);
        let pubk_2 = StacksPublicKey::from_private(&privk_2);
        let pubk_3 = StacksPublicKey::from_private(&privk_3);

        let random_sponsor = StacksPrivateKey::random(); // what the origin sees

        let auth = TransactionAuth::Sponsored(
            TransactionSpendingCondition::new_singlesig_p2pkh(StacksPublicKey::from_private(
                &origin_privk,
            ))
            .unwrap(),
            TransactionSpendingCondition::new_singlesig_p2pkh(StacksPublicKey::from_private(
                &random_sponsor,
            ))
            .unwrap(),
        );

        let real_sponsor = TransactionSpendingCondition::new_multisig_p2sh(
            2,
            vec![pubk_1.clone(), pubk_2.clone(), pubk_3.clone()],
        )
        .unwrap();

        let origin_address = auth.origin().address_mainnet();
        let sponsor_address = real_sponsor.address_mainnet();

        assert_eq!(
            origin_address,
            StacksAddress::new(
                C32_ADDRESS_VERSION_MAINNET_SINGLESIG,
                Hash160::from_hex("3597aaa4bde720be93e3829aae24e76e7fcdfd3e").unwrap(),
            )
            .unwrap()
        );
        assert_eq!(
            sponsor_address,
            StacksAddress::new(
                C32_ADDRESS_VERSION_MAINNET_MULTISIG,
                Hash160::from_hex("a23ea89d6529ac48ac766f720e480beec7f19273").unwrap(),
            )
            .unwrap()
        );

        let txs = tx_stacks_transaction_test_txs(&auth);

        for mut tx in txs {
            assert_eq!(tx.auth().origin().num_signatures(), 0);
            assert_eq!(tx.auth().sponsor().unwrap().num_signatures(), 0);

            tx.set_tx_fee(123);
            tx.set_sponsor_nonce(456).unwrap();
            let mut tx_signer = StacksTransactionSigner::new(&tx);

            tx_signer.sign_origin(&origin_privk).unwrap();

            // sponsor sets and pays fee after origin signs
            let mut origin_tx = tx_signer.get_tx_incomplete();
            origin_tx.auth.set_sponsor(real_sponsor.clone()).unwrap();
            origin_tx.set_tx_fee(456);
            origin_tx.set_sponsor_nonce(789).unwrap();
            tx_signer.resume(&origin_tx);

            tx_signer.sign_sponsor(&privk_1).unwrap();
            tx_signer.sign_sponsor(&privk_2).unwrap();
            tx_signer.append_sponsor(&pubk_3).unwrap();

            tx.set_tx_fee(456);
            tx.set_sponsor_nonce(789).unwrap();
            let mut signed_tx = tx_signer.get_tx().unwrap();

            check_oversign_origin_singlesig(&mut signed_tx);
            check_oversign_sponsor_multisig(&signed_tx);

            assert_eq!(signed_tx.auth().origin().num_signatures(), 1);
            assert_eq!(signed_tx.auth().sponsor().unwrap().num_signatures(), 2);

            // tx and signed_tx are otherwise equal
            assert_eq!(tx.version, signed_tx.version);
            assert_eq!(tx.chain_id, signed_tx.chain_id);
            assert_eq!(tx.get_tx_fee(), signed_tx.get_tx_fee());
            assert_eq!(tx.get_origin_nonce(), signed_tx.get_origin_nonce());
            assert_eq!(tx.get_sponsor_nonce(), signed_tx.get_sponsor_nonce());
            assert_eq!(tx.anchor_mode, signed_tx.anchor_mode);
            assert_eq!(tx.post_condition_mode, signed_tx.post_condition_mode);
            assert_eq!(tx.post_conditions, signed_tx.post_conditions);
            assert_eq!(tx.payload, signed_tx.payload);

            // auth is standard and first two auth fields are signatures for compressed keys.
            // third field is the third public key
            if let TransactionAuth::Sponsored(
                TransactionSpendingCondition::Singlesig(origin_data),
                TransactionSpendingCondition::Multisig(sponsor_data),
            ) = &signed_tx.auth
            {
                assert_eq!(
                    origin_data.key_encoding,
                    TransactionPublicKeyEncoding::Compressed
                );
                assert_eq!(origin_data.signer, *origin_address.bytes());

                assert_eq!(sponsor_data.signer, *sponsor_address.bytes());
                assert_eq!(sponsor_data.fields.len(), 3);
                assert!(sponsor_data.fields[0].is_signature());
                assert!(sponsor_data.fields[1].is_signature());
                assert!(sponsor_data.fields[2].is_public_key());

                assert_eq!(
                    sponsor_data.fields[0].as_signature().unwrap().0,
                    TransactionPublicKeyEncoding::Compressed
                );
                assert_eq!(
                    sponsor_data.fields[1].as_signature().unwrap().0,
                    TransactionPublicKeyEncoding::Compressed
                );
                assert_eq!(sponsor_data.fields[2].as_public_key().unwrap(), pubk_3);
            } else {
                panic!("Unexpected auth condition");
            }

            test_signature_and_corruption(&signed_tx, true, false);
            test_signature_and_corruption(&signed_tx, false, true);
        }
    }

    #[test]
    fn tx_stacks_transaction_sign_verify_standard_p2sh_uncompressed() {
        let privk_1 = StacksPrivateKey::from_hex(
            "6d430bb91222408e7706c9001cfaeb91b08c2be6d5ac95779ab52c6b431950e0",
        )
        .unwrap();
        let privk_2 = StacksPrivateKey::from_hex(
            "2a584d899fed1d24e26b524f202763c8ab30260167429f157f1c119f550fa6af",
        )
        .unwrap();
        let privk_3 = StacksPrivateKey::from_hex(
            "d5200dee706ee53ae98a03fba6cf4fdcc5084c30cfa9e1b3462dcdeaa3e0f1d2",
        )
        .unwrap();

        let pubk_1 = StacksPublicKey::from_private(&privk_1);
        let pubk_2 = StacksPublicKey::from_private(&privk_2);
        let pubk_3 = StacksPublicKey::from_private(&privk_3);

        let auth = TransactionAuth::Standard(
            TransactionSpendingCondition::new_multisig_p2sh(
                2,
                vec![pubk_1.clone(), pubk_2.clone(), pubk_3.clone()],
            )
            .unwrap(),
        );

        let origin_address = auth.origin().address_mainnet();

        assert_eq!(
            origin_address,
            StacksAddress::new(
                C32_ADDRESS_VERSION_MAINNET_MULTISIG,
                Hash160::from_hex("73a8b4a751a678fe83e9d35ce301371bb3d397f7").unwrap(),
            )
            .unwrap()
        );

        let txs = tx_stacks_transaction_test_txs(&auth);

        for tx in txs {
            assert_eq!(tx.auth().origin().num_signatures(), 0);

            let mut tx_signer = StacksTransactionSigner::new(&tx);

            tx_signer.sign_origin(&privk_1).unwrap();
            tx_signer.sign_origin(&privk_2).unwrap();
            tx_signer.append_origin(&pubk_3).unwrap();

            let mut signed_tx = tx_signer.get_tx().unwrap();

            check_oversign_origin_multisig(&signed_tx);
            check_sign_no_sponsor(&mut signed_tx);

            assert_eq!(signed_tx.auth().origin().num_signatures(), 2);

            // tx and signed_tx are otherwise equal
            assert_eq!(tx.version, signed_tx.version);
            assert_eq!(tx.chain_id, signed_tx.chain_id);
            assert_eq!(tx.get_tx_fee(), signed_tx.get_tx_fee());
            assert_eq!(tx.get_origin_nonce(), signed_tx.get_origin_nonce());
            assert_eq!(tx.get_sponsor_nonce(), signed_tx.get_sponsor_nonce());
            assert_eq!(tx.anchor_mode, signed_tx.anchor_mode);
            assert_eq!(tx.post_condition_mode, signed_tx.post_condition_mode);
            assert_eq!(tx.post_conditions, signed_tx.post_conditions);
            assert_eq!(tx.payload, signed_tx.payload);

            // auth is standard and first two auth fields are signatures for uncompressed keys.
            // third field is the third public key
            if let TransactionAuth::Standard(TransactionSpendingCondition::Multisig(data)) =
                &signed_tx.auth
            {
                assert_eq!(data.signer, *origin_address.bytes());
                assert_eq!(data.fields.len(), 3);
                assert!(data.fields[0].is_signature());
                assert!(data.fields[1].is_signature());
                assert!(data.fields[2].is_public_key());

                assert_eq!(
                    data.fields[0].as_signature().unwrap().0,
                    TransactionPublicKeyEncoding::Uncompressed
                );
                assert_eq!(
                    data.fields[1].as_signature().unwrap().0,
                    TransactionPublicKeyEncoding::Uncompressed
                );
                assert_eq!(data.fields[2].as_public_key().unwrap(), pubk_3);
            } else {
                panic!("Unexpected auth condition");
            }

            test_signature_and_corruption(&signed_tx, true, false);
        }
    }

    #[test]
    fn tx_stacks_transaction_sign_verify_sponsored_p2sh_uncompressed() {
        let origin_privk = StacksPrivateKey::from_hex(
            "807bbe9e471ac976592cc35e3056592ecc0f778ee653fced3b491a122dd8d59701",
        )
        .unwrap();

        let privk_1 = StacksPrivateKey::from_hex(
            "6d430bb91222408e7706c9001cfaeb91b08c2be6d5ac95779ab52c6b431950e0",
        )
        .unwrap();
        let privk_2 = StacksPrivateKey::from_hex(
            "2a584d899fed1d24e26b524f202763c8ab30260167429f157f1c119f550fa6af",
        )
        .unwrap();
        let privk_3 = StacksPrivateKey::from_hex(
            "d5200dee706ee53ae98a03fba6cf4fdcc5084c30cfa9e1b3462dcdeaa3e0f1d2",
        )
        .unwrap();

        let pubk_1 = StacksPublicKey::from_private(&privk_1);
        let pubk_2 = StacksPublicKey::from_private(&privk_2);
        let pubk_3 = StacksPublicKey::from_private(&privk_3);

        let random_sponsor = StacksPrivateKey::random(); // what the origin sees

        let auth = TransactionAuth::Sponsored(
            TransactionSpendingCondition::new_singlesig_p2pkh(StacksPublicKey::from_private(
                &origin_privk,
            ))
            .unwrap(),
            TransactionSpendingCondition::new_singlesig_p2pkh(StacksPublicKey::from_private(
                &random_sponsor,
            ))
            .unwrap(),
        );

        let real_sponsor = TransactionSpendingCondition::new_multisig_p2sh(
            2,
            vec![pubk_1.clone(), pubk_2.clone(), pubk_3.clone()],
        )
        .unwrap();

        let origin_address = auth.origin().address_mainnet();
        let sponsor_address = real_sponsor.address_mainnet();

        assert_eq!(
            origin_address,
            StacksAddress::new(
                C32_ADDRESS_VERSION_MAINNET_SINGLESIG,
                Hash160::from_hex("3597aaa4bde720be93e3829aae24e76e7fcdfd3e").unwrap(),
            )
            .unwrap()
        );
        assert_eq!(
            sponsor_address,
            StacksAddress::new(
                C32_ADDRESS_VERSION_MAINNET_MULTISIG,
                Hash160::from_hex("73a8b4a751a678fe83e9d35ce301371bb3d397f7").unwrap(),
            )
            .unwrap()
        );

        let txs = tx_stacks_transaction_test_txs(&auth);

        for mut tx in txs {
            assert_eq!(tx.auth().origin().num_signatures(), 0);
            assert_eq!(tx.auth().sponsor().unwrap().num_signatures(), 0);

            tx.set_tx_fee(123);
            tx.set_sponsor_nonce(456).unwrap();
            let mut tx_signer = StacksTransactionSigner::new(&tx);

            tx_signer.sign_origin(&origin_privk).unwrap();

            // sponsor sets and pays fee after origin signs
            let mut origin_tx = tx_signer.get_tx_incomplete();
            origin_tx.auth.set_sponsor(real_sponsor.clone()).unwrap();
            origin_tx.set_tx_fee(456);
            origin_tx.set_sponsor_nonce(789).unwrap();
            tx_signer.resume(&origin_tx);

            tx_signer.sign_sponsor(&privk_1).unwrap();
            tx_signer.sign_sponsor(&privk_2).unwrap();
            tx_signer.append_sponsor(&pubk_3).unwrap();

            tx.set_tx_fee(456);
            tx.set_sponsor_nonce(789).unwrap();
            let mut signed_tx = tx_signer.get_tx().unwrap();

            check_oversign_origin_singlesig(&mut signed_tx);
            check_oversign_sponsor_multisig(&signed_tx);

            assert_eq!(signed_tx.auth().origin().num_signatures(), 1);
            assert_eq!(signed_tx.auth().sponsor().unwrap().num_signatures(), 2);

            // tx and signed_tx are otherwise equal
            assert_eq!(tx.version, signed_tx.version);
            assert_eq!(tx.get_tx_fee(), signed_tx.get_tx_fee());
            assert_eq!(tx.get_origin_nonce(), signed_tx.get_origin_nonce());
            assert_eq!(tx.get_sponsor_nonce(), signed_tx.get_sponsor_nonce());
            assert_eq!(tx.anchor_mode, signed_tx.anchor_mode);
            assert_eq!(tx.post_condition_mode, signed_tx.post_condition_mode);
            assert_eq!(tx.post_conditions, signed_tx.post_conditions);
            assert_eq!(tx.payload, signed_tx.payload);

            // auth is standard and first two auth fields are signatures for uncompressed keys.
            // third field is the third public key
            if let TransactionAuth::Sponsored(
                TransactionSpendingCondition::Singlesig(origin_data),
                TransactionSpendingCondition::Multisig(sponsor_data),
            ) = &signed_tx.auth
            {
                assert_eq!(
                    origin_data.key_encoding,
                    TransactionPublicKeyEncoding::Compressed
                );
                assert_eq!(origin_data.signer, *origin_address.bytes());

                assert_eq!(sponsor_data.signer, *sponsor_address.bytes());
                assert_eq!(sponsor_data.fields.len(), 3);
                assert!(sponsor_data.fields[0].is_signature());
                assert!(sponsor_data.fields[1].is_signature());
                assert!(sponsor_data.fields[2].is_public_key());

                assert_eq!(
                    sponsor_data.fields[0].as_signature().unwrap().0,
                    TransactionPublicKeyEncoding::Uncompressed
                );
                assert_eq!(
                    sponsor_data.fields[1].as_signature().unwrap().0,
                    TransactionPublicKeyEncoding::Uncompressed
                );
                assert_eq!(sponsor_data.fields[2].as_public_key().unwrap(), pubk_3);
            } else {
                panic!("Unexpected auth condition");
            }

            test_signature_and_corruption(&signed_tx, true, false);
            test_signature_and_corruption(&signed_tx, false, true);
        }
    }

    #[test]
    fn tx_stacks_transaction_sign_verify_standard_p2sh_mixed() {
        let privk_1 = StacksPrivateKey::from_hex(
            "6d430bb91222408e7706c9001cfaeb91b08c2be6d5ac95779ab52c6b431950e001",
        )
        .unwrap();
        let privk_2 = StacksPrivateKey::from_hex(
            "2a584d899fed1d24e26b524f202763c8ab30260167429f157f1c119f550fa6af",
        )
        .unwrap();
        let privk_3 = StacksPrivateKey::from_hex(
            "d5200dee706ee53ae98a03fba6cf4fdcc5084c30cfa9e1b3462dcdeaa3e0f1d2",
        )
        .unwrap();

        let pubk_1 = StacksPublicKey::from_private(&privk_1);
        let pubk_2 = StacksPublicKey::from_private(&privk_2);
        let pubk_3 = StacksPublicKey::from_private(&privk_3);

        let origin_auth = TransactionAuth::Standard(
            TransactionSpendingCondition::new_multisig_p2sh(
                2,
                vec![pubk_1.clone(), pubk_2.clone(), pubk_3.clone()],
            )
            .unwrap(),
        );

        let origin_address = origin_auth.origin().address_mainnet();
        assert_eq!(
            origin_address,
            StacksAddress::new(
                C32_ADDRESS_VERSION_MAINNET_MULTISIG,
                Hash160::from_hex("2136367c9c740e7dbed8795afdf8a6d273096718").unwrap(),
            )
            .unwrap()
        );

        let txs = tx_stacks_transaction_test_txs(&origin_auth);

        for tx in txs {
            assert_eq!(tx.auth().origin().num_signatures(), 0);

            let mut tx_signer = StacksTransactionSigner::new(&tx);
            tx_signer.sign_origin(&privk_1).unwrap();
            tx_signer.append_origin(&pubk_2).unwrap();
            tx_signer.sign_origin(&privk_3).unwrap();
            let mut signed_tx = tx_signer.get_tx().unwrap();

            check_oversign_origin_multisig(&signed_tx);
            check_sign_no_sponsor(&mut signed_tx);

            assert_eq!(signed_tx.auth().origin().num_signatures(), 2);

            // tx and signed_tx are otherwise equal
            assert_eq!(tx.version, signed_tx.version);
            assert_eq!(tx.get_tx_fee(), signed_tx.get_tx_fee());
            assert_eq!(tx.get_origin_nonce(), signed_tx.get_origin_nonce());
            assert_eq!(tx.get_sponsor_nonce(), signed_tx.get_sponsor_nonce());
            assert_eq!(tx.anchor_mode, signed_tx.anchor_mode);
            assert_eq!(tx.post_condition_mode, signed_tx.post_condition_mode);
            assert_eq!(tx.post_conditions, signed_tx.post_conditions);
            assert_eq!(tx.payload, signed_tx.payload);

            // auth is standard and first & third auth fields are signatures for (un)compressed keys.
            // 2nd field is the 2nd public key
            if let TransactionAuth::Standard(TransactionSpendingCondition::Multisig(data)) =
                &signed_tx.auth
            {
                assert_eq!(data.signer, *origin_address.bytes());
                assert_eq!(data.fields.len(), 3);
                assert!(data.fields[0].is_signature());
                assert!(data.fields[1].is_public_key());
                assert!(data.fields[2].is_signature());

                assert_eq!(
                    data.fields[0].as_signature().unwrap().0,
                    TransactionPublicKeyEncoding::Compressed
                );
                assert_eq!(data.fields[1].as_public_key().unwrap(), pubk_2);
                assert_eq!(
                    data.fields[2].as_signature().unwrap().0,
                    TransactionPublicKeyEncoding::Uncompressed
                );
            } else {
                panic!("Unexpected auth condition");
            }

            test_signature_and_corruption(&signed_tx, true, false);
        }
    }

    #[test]
    fn tx_stacks_transaction_sign_verify_sponsored_p2sh_mixed() {
        let origin_privk = StacksPrivateKey::from_hex(
            "807bbe9e471ac976592cc35e3056592ecc0f778ee653fced3b491a122dd8d59701",
        )
        .unwrap();

        let privk_1 = StacksPrivateKey::from_hex(
            "6d430bb91222408e7706c9001cfaeb91b08c2be6d5ac95779ab52c6b431950e001",
        )
        .unwrap();
        let privk_2 = StacksPrivateKey::from_hex(
            "2a584d899fed1d24e26b524f202763c8ab30260167429f157f1c119f550fa6af",
        )
        .unwrap();
        let privk_3 = StacksPrivateKey::from_hex(
            "d5200dee706ee53ae98a03fba6cf4fdcc5084c30cfa9e1b3462dcdeaa3e0f1d2",
        )
        .unwrap();

        let pubk_1 = StacksPublicKey::from_private(&privk_1);
        let pubk_2 = StacksPublicKey::from_private(&privk_2);
        let pubk_3 = StacksPublicKey::from_private(&privk_3);

        let random_sponsor = StacksPrivateKey::random(); // what the origin sees

        let auth = TransactionAuth::Sponsored(
            TransactionSpendingCondition::new_singlesig_p2pkh(StacksPublicKey::from_private(
                &origin_privk,
            ))
            .unwrap(),
            TransactionSpendingCondition::new_singlesig_p2pkh(StacksPublicKey::from_private(
                &random_sponsor,
            ))
            .unwrap(),
        );

        let real_sponsor = TransactionSpendingCondition::new_multisig_p2sh(
            2,
            vec![pubk_1.clone(), pubk_2.clone(), pubk_3.clone()],
        )
        .unwrap();

        let origin_address = auth.origin().address_mainnet();
        let sponsor_address = real_sponsor.address_mainnet();

        assert_eq!(
            origin_address,
            StacksAddress::new(
                C32_ADDRESS_VERSION_MAINNET_SINGLESIG,
                Hash160::from_hex("3597aaa4bde720be93e3829aae24e76e7fcdfd3e").unwrap(),
            )
            .unwrap()
        );
        assert_eq!(
            sponsor_address,
            StacksAddress::new(
                C32_ADDRESS_VERSION_MAINNET_MULTISIG,
                Hash160::from_hex("2136367c9c740e7dbed8795afdf8a6d273096718").unwrap(),
            )
            .unwrap()
        );

        let txs = tx_stacks_transaction_test_txs(&auth);

        for mut tx in txs {
            assert_eq!(tx.auth().origin().num_signatures(), 0);
            assert_eq!(tx.auth().sponsor().unwrap().num_signatures(), 0);

            tx.set_tx_fee(123);
            tx.set_sponsor_nonce(456).unwrap();
            let mut tx_signer = StacksTransactionSigner::new(&tx);

            tx_signer.sign_origin(&origin_privk).unwrap();

            // sponsor sets and pays fee after origin signs
            let mut origin_tx = tx_signer.get_tx_incomplete();
            origin_tx.auth.set_sponsor(real_sponsor.clone()).unwrap();
            origin_tx.set_tx_fee(456);
            origin_tx.set_sponsor_nonce(789).unwrap();
            tx_signer.resume(&origin_tx);

            tx_signer.sign_sponsor(&privk_1).unwrap();
            tx_signer.append_sponsor(&pubk_2).unwrap();
            tx_signer.sign_sponsor(&privk_3).unwrap();

            tx.set_tx_fee(456);
            tx.set_sponsor_nonce(789).unwrap();
            let mut signed_tx = tx_signer.get_tx().unwrap();

            check_oversign_origin_singlesig(&mut signed_tx);
            check_oversign_sponsor_multisig(&signed_tx);

            assert_eq!(signed_tx.auth().origin().num_signatures(), 1);
            assert_eq!(signed_tx.auth().sponsor().unwrap().num_signatures(), 2);

            // tx and signed_tx are otherwise equal
            assert_eq!(tx.version, signed_tx.version);
            assert_eq!(tx.chain_id, signed_tx.chain_id);
            assert_eq!(tx.get_tx_fee(), signed_tx.get_tx_fee());
            assert_eq!(tx.get_origin_nonce(), signed_tx.get_origin_nonce());
            assert_eq!(tx.get_sponsor_nonce(), signed_tx.get_sponsor_nonce());
            assert_eq!(tx.anchor_mode, signed_tx.anchor_mode);
            assert_eq!(tx.post_condition_mode, signed_tx.post_condition_mode);
            assert_eq!(tx.post_conditions, signed_tx.post_conditions);
            assert_eq!(tx.payload, signed_tx.payload);

            // auth is standard and first & third auth fields are signatures for (un)compressed keys.
            // 2nd field is the 2nd public key
            if let TransactionAuth::Sponsored(
                TransactionSpendingCondition::Singlesig(origin_data),
                TransactionSpendingCondition::Multisig(sponsor_data),
            ) = &signed_tx.auth
            {
                assert_eq!(
                    origin_data.key_encoding,
                    TransactionPublicKeyEncoding::Compressed
                );
                assert_eq!(origin_data.signer, *origin_address.bytes());

                assert_eq!(sponsor_data.signer, *sponsor_address.bytes());
                assert_eq!(sponsor_data.fields.len(), 3);
                assert!(sponsor_data.fields[0].is_signature());
                assert!(sponsor_data.fields[1].is_public_key());
                assert!(sponsor_data.fields[2].is_signature());

                assert_eq!(
                    sponsor_data.fields[0].as_signature().unwrap().0,
                    TransactionPublicKeyEncoding::Compressed
                );
                assert_eq!(sponsor_data.fields[1].as_public_key().unwrap(), pubk_2);
                assert_eq!(
                    sponsor_data.fields[2].as_signature().unwrap().0,
                    TransactionPublicKeyEncoding::Uncompressed
                );
            } else {
                panic!("Unexpected auth condition");
            }

            test_signature_and_corruption(&signed_tx, true, false);
            test_signature_and_corruption(&signed_tx, false, true);
        }
    }

    #[test]
    fn tx_stacks_transaction_sign_verify_standard_p2wpkh() {
        let privk = StacksPrivateKey::from_hex(
            "6d430bb91222408e7706c9001cfaeb91b08c2be6d5ac95779ab52c6b431950e001",
        )
        .unwrap();
        let origin_auth = TransactionAuth::Standard(
            TransactionSpendingCondition::new_singlesig_p2wpkh(StacksPublicKey::from_private(
                &privk,
            ))
            .unwrap(),
        );

        let origin_address = origin_auth.origin().address_mainnet();
        assert_eq!(
            origin_address,
            StacksAddress::new(
                C32_ADDRESS_VERSION_MAINNET_MULTISIG,
                Hash160::from_hex("f15fa5c59d14ffcb615fa6153851cd802bb312d2").unwrap(),
            )
            .unwrap()
        );

        let txs = tx_stacks_transaction_test_txs(&origin_auth);

        for tx in txs {
            assert_eq!(tx.auth().origin().num_signatures(), 0);

            let mut tx_signer = StacksTransactionSigner::new(&tx);
            tx_signer.sign_origin(&privk).unwrap();
            let mut signed_tx = tx_signer.get_tx().unwrap();

            // try to over-sign
            check_oversign_origin_singlesig(&mut signed_tx);
            check_sign_no_sponsor(&mut signed_tx);

            assert_eq!(signed_tx.auth().origin().num_signatures(), 1);

            // tx and signed_tx are otherwise equal
            assert_eq!(tx.version, signed_tx.version);
            assert_eq!(tx.get_tx_fee(), signed_tx.get_tx_fee());
            assert_eq!(tx.get_origin_nonce(), signed_tx.get_origin_nonce());
            assert_eq!(tx.get_sponsor_nonce(), signed_tx.get_sponsor_nonce());
            assert_eq!(tx.anchor_mode, signed_tx.anchor_mode);
            assert_eq!(tx.post_condition_mode, signed_tx.post_condition_mode);
            assert_eq!(tx.post_conditions, signed_tx.post_conditions);
            assert_eq!(tx.payload, signed_tx.payload);

            // auth is standard and public key is compressed
            if let TransactionAuth::Standard(TransactionSpendingCondition::Singlesig(data)) =
                &signed_tx.auth
            {
                assert_eq!(data.signer, *origin_address.bytes());
                assert_eq!(data.key_encoding, TransactionPublicKeyEncoding::Compressed);
            } else {
                panic!("Unexpected auth condition");
            }

            test_signature_and_corruption(&signed_tx, true, false);
        }
    }

    #[test]
    fn tx_stacks_transaction_sign_verify_sponsored_p2wpkh() {
        let origin_privk = StacksPrivateKey::from_hex(
            "807bbe9e471ac976592cc35e3056592ecc0f778ee653fced3b491a122dd8d59701",
        )
        .unwrap();
        let privk = StacksPrivateKey::from_hex(
            "6d430bb91222408e7706c9001cfaeb91b08c2be6d5ac95779ab52c6b431950e001",
        )
        .unwrap();

        let random_sponsor = StacksPrivateKey::random();

        let auth = TransactionAuth::Sponsored(
            TransactionSpendingCondition::new_singlesig_p2pkh(StacksPublicKey::from_private(
                &origin_privk,
            ))
            .unwrap(),
            TransactionSpendingCondition::new_singlesig_p2pkh(StacksPublicKey::from_private(
                &random_sponsor,
            ))
            .unwrap(),
        );

        let real_sponsor = TransactionSpendingCondition::new_singlesig_p2wpkh(
            StacksPublicKey::from_private(&privk),
        )
        .unwrap();

        let origin_address = auth.origin().address_mainnet();
        let sponsor_address = real_sponsor.address_mainnet();

        assert_eq!(
            origin_address,
            StacksAddress::new(
                C32_ADDRESS_VERSION_MAINNET_SINGLESIG,
                Hash160::from_hex("3597aaa4bde720be93e3829aae24e76e7fcdfd3e").unwrap(),
            )
            .unwrap()
        );
        assert_eq!(
            sponsor_address,
            StacksAddress::new(
                C32_ADDRESS_VERSION_MAINNET_MULTISIG,
                Hash160::from_hex("f15fa5c59d14ffcb615fa6153851cd802bb312d2").unwrap(),
            )
            .unwrap()
        );

        let txs = tx_stacks_transaction_test_txs(&auth);

        for mut tx in txs {
            assert_eq!(tx.auth().origin().num_signatures(), 0);
            assert_eq!(tx.auth().sponsor().unwrap().num_signatures(), 0);

            tx.set_tx_fee(123);
            tx.set_sponsor_nonce(456).unwrap();
            let mut tx_signer = StacksTransactionSigner::new(&tx);

            tx_signer.sign_origin(&origin_privk).unwrap();

            // sponsor sets and pays fee after origin signs
            let mut origin_tx = tx_signer.get_tx_incomplete();
            origin_tx.auth.set_sponsor(real_sponsor.clone()).unwrap();
            origin_tx.set_tx_fee(456);
            origin_tx.set_sponsor_nonce(789).unwrap();
            tx_signer.resume(&origin_tx);

            tx_signer.sign_sponsor(&privk).unwrap();

            tx.set_tx_fee(456);
            tx.set_sponsor_nonce(789).unwrap();
            let mut signed_tx = tx_signer.get_tx().unwrap();

            // try to over-sign
            check_oversign_origin_singlesig(&mut signed_tx);
            check_oversign_sponsor_singlesig(&mut signed_tx);

            assert_eq!(signed_tx.auth().origin().num_signatures(), 1);
            assert_eq!(signed_tx.auth().sponsor().unwrap().num_signatures(), 1);

            // tx and signed_tx are otherwise equal
            assert_eq!(tx.version, signed_tx.version);
            assert_eq!(tx.get_tx_fee(), signed_tx.get_tx_fee());
            assert_eq!(tx.get_origin_nonce(), signed_tx.get_origin_nonce());
            assert_eq!(tx.get_sponsor_nonce(), signed_tx.get_sponsor_nonce());
            assert_eq!(tx.anchor_mode, signed_tx.anchor_mode);
            assert_eq!(tx.post_condition_mode, signed_tx.post_condition_mode);
            assert_eq!(tx.post_conditions, signed_tx.post_conditions);
            assert_eq!(tx.payload, signed_tx.payload);

            // auth is standard and public key is compressed
            if let TransactionAuth::Sponsored(
                TransactionSpendingCondition::Singlesig(origin_data),
                TransactionSpendingCondition::Singlesig(sponsor_data),
            ) = &signed_tx.auth
            {
                assert_eq!(
                    origin_data.key_encoding,
                    TransactionPublicKeyEncoding::Compressed
                );
                assert_eq!(origin_data.signer, *origin_address.bytes());

                assert_eq!(sponsor_data.signer, *sponsor_address.bytes());
                assert_eq!(
                    sponsor_data.key_encoding,
                    TransactionPublicKeyEncoding::Compressed
                );
            } else {
                panic!("Unexpected auth condition");
            }

            test_signature_and_corruption(&signed_tx, true, false);
            test_signature_and_corruption(&signed_tx, false, true);
        }
    }

    #[test]
    fn tx_stacks_transaction_sign_verify_standard_p2wsh() {
        let privk_1 = StacksPrivateKey::from_hex(
            "6d430bb91222408e7706c9001cfaeb91b08c2be6d5ac95779ab52c6b431950e001",
        )
        .unwrap();
        let privk_2 = StacksPrivateKey::from_hex(
            "2a584d899fed1d24e26b524f202763c8ab30260167429f157f1c119f550fa6af01",
        )
        .unwrap();
        let privk_3 = StacksPrivateKey::from_hex(
            "d5200dee706ee53ae98a03fba6cf4fdcc5084c30cfa9e1b3462dcdeaa3e0f1d201",
        )
        .unwrap();

        let pubk_1 = StacksPublicKey::from_private(&privk_1);
        let pubk_2 = StacksPublicKey::from_private(&privk_2);
        let pubk_3 = StacksPublicKey::from_private(&privk_3);

        let origin_auth = TransactionAuth::Standard(
            TransactionSpendingCondition::new_multisig_p2wsh(
                2,
                vec![pubk_1.clone(), pubk_2.clone(), pubk_3.clone()],
            )
            .unwrap(),
        );

        let origin_address = origin_auth.origin().address_mainnet();
        assert_eq!(
            origin_address,
            StacksAddress::new(
                C32_ADDRESS_VERSION_MAINNET_MULTISIG,
                Hash160::from_hex("f5cfb61a07fb41a32197da01ce033888f0fe94a7").unwrap(),
            )
            .unwrap()
        );

        let txs = tx_stacks_transaction_test_txs(&origin_auth);

        for tx in txs {
            assert_eq!(tx.auth().origin().num_signatures(), 0);

            let mut tx_signer = StacksTransactionSigner::new(&tx);
            tx_signer.sign_origin(&privk_1).unwrap();
            tx_signer.sign_origin(&privk_2).unwrap();
            tx_signer.append_origin(&pubk_3).unwrap();
            let mut signed_tx = tx_signer.get_tx().unwrap();

            check_oversign_origin_multisig(&signed_tx);
            check_oversign_origin_multisig_uncompressed(&signed_tx);
            check_sign_no_sponsor(&mut signed_tx);

            assert_eq!(signed_tx.auth().origin().num_signatures(), 2);

            // tx and signed_tx are otherwise equal
            assert_eq!(tx.version, signed_tx.version);
            assert_eq!(tx.get_tx_fee(), signed_tx.get_tx_fee());
            assert_eq!(tx.get_origin_nonce(), signed_tx.get_origin_nonce());
            assert_eq!(tx.get_sponsor_nonce(), signed_tx.get_sponsor_nonce());
            assert_eq!(tx.anchor_mode, signed_tx.anchor_mode);
            assert_eq!(tx.post_condition_mode, signed_tx.post_condition_mode);
            assert_eq!(tx.post_conditions, signed_tx.post_conditions);
            assert_eq!(tx.payload, signed_tx.payload);

            // auth is standard and first two auth fields are signatures for compressed keys.
            // third field is the third public key
            if let TransactionAuth::Standard(TransactionSpendingCondition::Multisig(data)) =
                &signed_tx.auth
            {
                assert_eq!(data.signer, *origin_address.bytes());
                assert_eq!(data.fields.len(), 3);
                assert!(data.fields[0].is_signature());
                assert!(data.fields[1].is_signature());
                assert!(data.fields[2].is_public_key());

                assert_eq!(
                    data.fields[0].as_signature().unwrap().0,
                    TransactionPublicKeyEncoding::Compressed
                );
                assert_eq!(
                    data.fields[1].as_signature().unwrap().0,
                    TransactionPublicKeyEncoding::Compressed
                );
                assert_eq!(data.fields[2].as_public_key().unwrap(), pubk_3);
            } else {
                panic!("Unexpected auth condition");
            }

            test_signature_and_corruption(&signed_tx, true, false);
        }
    }

    #[test]
    fn tx_stacks_transaction_sign_verify_sponsored_p2wsh() {
        let origin_privk = StacksPrivateKey::from_hex(
            "807bbe9e471ac976592cc35e3056592ecc0f778ee653fced3b491a122dd8d59701",
        )
        .unwrap();

        let privk_1 = StacksPrivateKey::from_hex(
            "6d430bb91222408e7706c9001cfaeb91b08c2be6d5ac95779ab52c6b431950e001",
        )
        .unwrap();
        let privk_2 = StacksPrivateKey::from_hex(
            "2a584d899fed1d24e26b524f202763c8ab30260167429f157f1c119f550fa6af01",
        )
        .unwrap();
        let privk_3 = StacksPrivateKey::from_hex(
            "d5200dee706ee53ae98a03fba6cf4fdcc5084c30cfa9e1b3462dcdeaa3e0f1d201",
        )
        .unwrap();

        let pubk_1 = StacksPublicKey::from_private(&privk_1);
        let pubk_2 = StacksPublicKey::from_private(&privk_2);
        let pubk_3 = StacksPublicKey::from_private(&privk_3);

        let random_sponsor = StacksPrivateKey::random();

        let auth = TransactionAuth::Sponsored(
            TransactionSpendingCondition::new_singlesig_p2pkh(StacksPublicKey::from_private(
                &origin_privk,
            ))
            .unwrap(),
            TransactionSpendingCondition::new_singlesig_p2pkh(StacksPublicKey::from_private(
                &random_sponsor,
            ))
            .unwrap(),
        );

        let real_sponsor = TransactionSpendingCondition::new_multisig_p2wsh(
            2,
            vec![pubk_1.clone(), pubk_2.clone(), pubk_3.clone()],
        )
        .unwrap();

        let origin_address = auth.origin().address_mainnet();
        let sponsor_address = real_sponsor.address_mainnet();

        assert_eq!(
            origin_address,
            StacksAddress::new(
                C32_ADDRESS_VERSION_MAINNET_SINGLESIG,
                Hash160::from_hex("3597aaa4bde720be93e3829aae24e76e7fcdfd3e").unwrap(),
            )
            .unwrap()
        );
        assert_eq!(
            sponsor_address,
            StacksAddress::new(
                C32_ADDRESS_VERSION_MAINNET_MULTISIG,
                Hash160::from_hex("f5cfb61a07fb41a32197da01ce033888f0fe94a7").unwrap(),
            )
            .unwrap()
        );

        let txs = tx_stacks_transaction_test_txs(&auth);

        for mut tx in txs {
            assert_eq!(tx.auth().origin().num_signatures(), 0);
            assert_eq!(tx.auth().sponsor().unwrap().num_signatures(), 0);

            tx.set_tx_fee(123);
            tx.set_sponsor_nonce(456).unwrap();
            let mut tx_signer = StacksTransactionSigner::new(&tx);

            tx_signer.sign_origin(&origin_privk).unwrap();

            // sponsor sets and pays fee after origin signs
            let mut origin_tx = tx_signer.get_tx_incomplete();
            origin_tx.auth.set_sponsor(real_sponsor.clone()).unwrap();
            origin_tx.set_tx_fee(456);
            origin_tx.set_sponsor_nonce(789).unwrap();
            tx_signer.resume(&origin_tx);

            tx_signer.sign_sponsor(&privk_1).unwrap();
            tx_signer.sign_sponsor(&privk_2).unwrap();
            tx_signer.append_sponsor(&pubk_3).unwrap();

            tx.set_tx_fee(456);
            tx.set_sponsor_nonce(789).unwrap();
            let mut signed_tx = tx_signer.get_tx().unwrap();

            check_oversign_origin_singlesig(&mut signed_tx);
            check_oversign_sponsor_multisig(&signed_tx);
            check_oversign_sponsor_multisig_uncompressed(&signed_tx);

            assert_eq!(signed_tx.auth().origin().num_signatures(), 1);
            assert_eq!(signed_tx.auth().sponsor().unwrap().num_signatures(), 2);

            // tx and signed_tx are otherwise equal
            assert_eq!(tx.version, signed_tx.version);
            assert_eq!(tx.chain_id, signed_tx.chain_id);
            assert_eq!(tx.get_tx_fee(), signed_tx.get_tx_fee());
            assert_eq!(tx.get_origin_nonce(), signed_tx.get_origin_nonce());
            assert_eq!(tx.get_sponsor_nonce(), signed_tx.get_sponsor_nonce());
            assert_eq!(tx.anchor_mode, signed_tx.anchor_mode);
            assert_eq!(tx.post_condition_mode, signed_tx.post_condition_mode);
            assert_eq!(tx.post_conditions, signed_tx.post_conditions);
            assert_eq!(tx.payload, signed_tx.payload);

            // auth is standard and first two auth fields are signatures for compressed keys.
            // third field is the third public key
            if let TransactionAuth::Sponsored(
                TransactionSpendingCondition::Singlesig(origin_data),
                TransactionSpendingCondition::Multisig(sponsor_data),
            ) = &signed_tx.auth
            {
                assert_eq!(
                    origin_data.key_encoding,
                    TransactionPublicKeyEncoding::Compressed
                );
                assert_eq!(origin_data.signer, *origin_address.bytes());

                assert_eq!(sponsor_data.signer, *sponsor_address.bytes());
                assert_eq!(sponsor_data.fields.len(), 3);
                assert!(sponsor_data.fields[0].is_signature());
                assert!(sponsor_data.fields[1].is_signature());
                assert!(sponsor_data.fields[2].is_public_key());

                assert_eq!(
                    sponsor_data.fields[0].as_signature().unwrap().0,
                    TransactionPublicKeyEncoding::Compressed
                );
                assert_eq!(
                    sponsor_data.fields[1].as_signature().unwrap().0,
                    TransactionPublicKeyEncoding::Compressed
                );
                assert_eq!(sponsor_data.fields[2].as_public_key().unwrap(), pubk_3);
            } else {
                panic!("Unexpected auth condition");
            }

            test_signature_and_corruption(&signed_tx, true, false);
            test_signature_and_corruption(&signed_tx, false, true);
        }
    }

    #[test]
    fn tx_stacks_transaction_sign_verify_standard_order_independent_p2sh() {
        let privk_1 = StacksPrivateKey::from_hex(
            "6d430bb91222408e7706c9001cfaeb91b08c2be6d5ac95779ab52c6b431950e001",
        )
        .unwrap();
        let privk_2 = StacksPrivateKey::from_hex(
            "2a584d899fed1d24e26b524f202763c8ab30260167429f157f1c119f550fa6af01",
        )
        .unwrap();
        let privk_3 = StacksPrivateKey::from_hex(
            "d5200dee706ee53ae98a03fba6cf4fdcc5084c30cfa9e1b3462dcdeaa3e0f1d201",
        )
        .unwrap();

        let pubk_1 = StacksPublicKey::from_private(&privk_1);
        let pubk_2 = StacksPublicKey::from_private(&privk_2);
        let pubk_3 = StacksPublicKey::from_private(&privk_3);

        let origin_auth = TransactionAuth::Standard(
            TransactionSpendingCondition::new_multisig_order_independent_p2sh(
                2,
                vec![pubk_1.clone(), pubk_2.clone(), pubk_3.clone()],
            )
            .unwrap(),
        );

        let origin_address = origin_auth.origin().address_mainnet();
        assert_eq!(
            origin_address,
            StacksAddress::new(
                C32_ADDRESS_VERSION_MAINNET_MULTISIG,
                Hash160::from_hex("a23ea89d6529ac48ac766f720e480beec7f19273").unwrap(),
            )
            .unwrap()
        );

        let txs = tx_stacks_transaction_test_txs(&origin_auth);

        for mut tx in txs {
            assert_eq!(tx.auth().origin().num_signatures(), 0);

            let initial_sig_hash = tx.sign_begin();
            let sig3 = tx
                .sign_no_append_origin(&initial_sig_hash, &privk_3)
                .unwrap();
            let sig2 = tx
                .sign_no_append_origin(&initial_sig_hash, &privk_2)
                .unwrap();

            let _ = tx.append_next_origin(&pubk_1);
            tx.append_origin_signature(sig2, TransactionPublicKeyEncoding::Compressed);
            tx.append_origin_signature(sig3, TransactionPublicKeyEncoding::Compressed);

            check_oversign_origin_multisig(&tx);
            check_sign_no_sponsor(&mut tx);

            assert_eq!(tx.auth().origin().num_signatures(), 2);

            // auth is standard and first two auth fields are signatures for compressed keys.
            // third field is the third public key
            if let TransactionAuth::Standard(
                TransactionSpendingCondition::OrderIndependentMultisig(data),
            ) = &tx.auth
            {
                assert_eq!(data.signer, *origin_address.bytes());
                assert_eq!(data.fields.len(), 3);
                assert!(data.fields[0].is_public_key());
                assert!(data.fields[1].is_signature());
                assert!(data.fields[2].is_signature());

                assert_eq!(data.fields[0].as_public_key().unwrap(), pubk_1);
                assert_eq!(
                    data.fields[1].as_signature().unwrap().0,
                    TransactionPublicKeyEncoding::Compressed
                );
                assert_eq!(
                    data.fields[2].as_signature().unwrap().0,
                    TransactionPublicKeyEncoding::Compressed
                );
            } else {
                panic!("Unexpected auth condition");
            }

            test_signature_and_corruption(&tx, true, false);
        }
    }

    #[test]
    fn tx_stacks_transaction_sign_verify_standard_order_independent_p2sh_extra_signers() {
        let privk_1 = StacksPrivateKey::from_hex(
            "6d430bb91222408e7706c9001cfaeb91b08c2be6d5ac95779ab52c6b431950e001",
        )
        .unwrap();
        let privk_2 = StacksPrivateKey::from_hex(
            "2a584d899fed1d24e26b524f202763c8ab30260167429f157f1c119f550fa6af01",
        )
        .unwrap();
        let privk_3 = StacksPrivateKey::from_hex(
            "d5200dee706ee53ae98a03fba6cf4fdcc5084c30cfa9e1b3462dcdeaa3e0f1d201",
        )
        .unwrap();

        let pubk_1 = StacksPublicKey::from_private(&privk_1);
        let pubk_2 = StacksPublicKey::from_private(&privk_2);
        let pubk_3 = StacksPublicKey::from_private(&privk_3);

        let origin_auth = TransactionAuth::Standard(
            TransactionSpendingCondition::new_multisig_order_independent_p2sh(
                2,
                vec![pubk_1.clone(), pubk_2.clone(), pubk_3.clone()],
            )
            .unwrap(),
        );

        let origin_address = origin_auth.origin().address_mainnet();
        assert_eq!(
            origin_address,
            StacksAddress::new(
                C32_ADDRESS_VERSION_MAINNET_MULTISIG,
                Hash160::from_hex("a23ea89d6529ac48ac766f720e480beec7f19273").unwrap(),
            )
            .unwrap()
        );

        let txs = tx_stacks_transaction_test_txs(&origin_auth);

        for mut tx in txs {
            assert_eq!(tx.auth().origin().num_signatures(), 0);

            let initial_sig_hash = tx.sign_begin();
            let sig3 = tx
                .sign_no_append_origin(&initial_sig_hash, &privk_3)
                .unwrap();
            let sig2 = tx
                .sign_no_append_origin(&initial_sig_hash, &privk_2)
                .unwrap();
            let sig1 = tx
                .sign_no_append_origin(&initial_sig_hash, &privk_1)
                .unwrap();

            tx.append_origin_signature(sig1, TransactionPublicKeyEncoding::Compressed);
            tx.append_origin_signature(sig2, TransactionPublicKeyEncoding::Compressed);
            tx.append_origin_signature(sig3, TransactionPublicKeyEncoding::Compressed);

            //check_oversign_origin_multisig(&tx);
            check_sign_no_sponsor(&mut tx);

            assert_eq!(tx.auth().origin().num_signatures(), 3);

            // auth is standard and first two auth fields are signatures for compressed keys.
            // third field is the third public key
            if let TransactionAuth::Standard(
                TransactionSpendingCondition::OrderIndependentMultisig(data),
            ) = &tx.auth
            {
                assert_eq!(data.signer, *origin_address.bytes());
                assert_eq!(data.fields.len(), 3);
                assert!(data.fields[0].is_signature());
                assert!(data.fields[1].is_signature());
                assert!(data.fields[2].is_signature());

                assert_eq!(
                    data.fields[0].as_signature().unwrap().0,
                    TransactionPublicKeyEncoding::Compressed
                );
                assert_eq!(
                    data.fields[1].as_signature().unwrap().0,
                    TransactionPublicKeyEncoding::Compressed
                );
                assert_eq!(
                    data.fields[2].as_signature().unwrap().0,
                    TransactionPublicKeyEncoding::Compressed
                );
            } else {
                panic!("Unexpected auth condition");
            }

            test_signature_and_corruption(&tx, true, false);
        }
    }

    #[test]
    fn tx_stacks_transaction_sign_verify_sponsored_order_independent_p2sh() {
        let origin_privk = StacksPrivateKey::from_hex(
            "807bbe9e471ac976592cc35e3056592ecc0f778ee653fced3b491a122dd8d59701",
        )
        .unwrap();

        let privk_1 = StacksPrivateKey::from_hex(
            "6d430bb91222408e7706c9001cfaeb91b08c2be6d5ac95779ab52c6b431950e001",
        )
        .unwrap();
        let privk_2 = StacksPrivateKey::from_hex(
            "2a584d899fed1d24e26b524f202763c8ab30260167429f157f1c119f550fa6af01",
        )
        .unwrap();
        let privk_3 = StacksPrivateKey::from_hex(
            "d5200dee706ee53ae98a03fba6cf4fdcc5084c30cfa9e1b3462dcdeaa3e0f1d201",
        )
        .unwrap();

        let pubk_1 = StacksPublicKey::from_private(&privk_1);
        let pubk_2 = StacksPublicKey::from_private(&privk_2);
        let pubk_3 = StacksPublicKey::from_private(&privk_3);

        let random_sponsor = StacksPrivateKey::random(); // what the origin sees

        let auth = TransactionAuth::Sponsored(
            TransactionSpendingCondition::new_singlesig_p2pkh(StacksPublicKey::from_private(
                &origin_privk,
            ))
            .unwrap(),
            TransactionSpendingCondition::new_singlesig_p2pkh(StacksPublicKey::from_private(
                &random_sponsor,
            ))
            .unwrap(),
        );

        let real_sponsor = TransactionSpendingCondition::new_multisig_order_independent_p2sh(
            2,
            vec![pubk_1.clone(), pubk_2.clone(), pubk_3.clone()],
        )
        .unwrap();

        let origin_address = auth.origin().address_mainnet();
        let sponsor_address = real_sponsor.address_mainnet();

        assert_eq!(
            origin_address,
            StacksAddress::new(
                C32_ADDRESS_VERSION_MAINNET_SINGLESIG,
                Hash160::from_hex("3597aaa4bde720be93e3829aae24e76e7fcdfd3e").unwrap(),
            )
            .unwrap()
        );
        assert_eq!(
            sponsor_address,
            StacksAddress::new(
                C32_ADDRESS_VERSION_MAINNET_MULTISIG,
                Hash160::from_hex("a23ea89d6529ac48ac766f720e480beec7f19273").unwrap(),
            )
            .unwrap()
        );

        let txs = tx_stacks_transaction_test_txs(&auth);

        for mut tx in txs {
            assert_eq!(tx.auth().origin().num_signatures(), 0);
            assert_eq!(tx.auth().sponsor().unwrap().num_signatures(), 0);

            tx.set_tx_fee(123);
            tx.set_sponsor_nonce(456).unwrap();
            let mut tx_signer = StacksTransactionSigner::new(&tx);

            tx_signer.sign_origin(&origin_privk).unwrap();

            // sponsor sets and pays fee after origin signs
            let mut origin_tx = tx_signer.get_tx_incomplete();
            origin_tx.auth.set_sponsor(real_sponsor.clone()).unwrap();
            origin_tx.set_tx_fee(456);
            origin_tx.set_sponsor_nonce(789).unwrap();

            let initial_sig_hash = tx_signer.sighash;
            let sig1 = origin_tx
                .sign_no_append_sponsor(&initial_sig_hash, &privk_1)
                .unwrap();
            let sig2 = origin_tx
                .sign_no_append_sponsor(&initial_sig_hash, &privk_2)
                .unwrap();

            let _ =
                origin_tx.append_sponsor_signature(sig1, TransactionPublicKeyEncoding::Compressed);
            let _ =
                origin_tx.append_sponsor_signature(sig2, TransactionPublicKeyEncoding::Compressed);
            let _ = origin_tx.append_next_sponsor(&pubk_3);

            tx.set_tx_fee(456);
            tx.set_sponsor_nonce(789).unwrap();

            check_oversign_origin_singlesig(&mut origin_tx);
            check_oversign_sponsor_multisig(&origin_tx);

            assert_eq!(origin_tx.auth().origin().num_signatures(), 1);
            assert_eq!(origin_tx.auth().sponsor().unwrap().num_signatures(), 2);

            // tx and origin_tx are otherwise equal
            assert_eq!(tx.version, origin_tx.version);
            assert_eq!(tx.chain_id, origin_tx.chain_id);
            assert_eq!(tx.get_tx_fee(), origin_tx.get_tx_fee());
            assert_eq!(tx.get_origin_nonce(), origin_tx.get_origin_nonce());
            assert_eq!(tx.get_sponsor_nonce(), origin_tx.get_sponsor_nonce());
            assert_eq!(tx.anchor_mode, origin_tx.anchor_mode);
            assert_eq!(tx.post_condition_mode, origin_tx.post_condition_mode);
            assert_eq!(tx.post_conditions, origin_tx.post_conditions);
            assert_eq!(tx.payload, origin_tx.payload);

            // auth is standard and first two auth fields are signatures for compressed keys.
            // third field is the third public key
            if let TransactionAuth::Sponsored(
                TransactionSpendingCondition::Singlesig(origin_data),
                TransactionSpendingCondition::OrderIndependentMultisig(sponsor_data),
            ) = &origin_tx.auth
            {
                assert_eq!(
                    origin_data.key_encoding,
                    TransactionPublicKeyEncoding::Compressed
                );
                assert_eq!(origin_data.signer, *origin_address.bytes());

                assert_eq!(sponsor_data.signer, *sponsor_address.bytes());
                assert_eq!(sponsor_data.fields.len(), 3);
                assert!(sponsor_data.fields[0].is_signature());
                assert!(sponsor_data.fields[1].is_signature());
                assert!(sponsor_data.fields[2].is_public_key());

                assert_eq!(
                    sponsor_data.fields[0].as_signature().unwrap().0,
                    TransactionPublicKeyEncoding::Compressed
                );
                assert_eq!(
                    sponsor_data.fields[1].as_signature().unwrap().0,
                    TransactionPublicKeyEncoding::Compressed
                );
                assert_eq!(sponsor_data.fields[2].as_public_key().unwrap(), pubk_3);
            } else {
                panic!("Unexpected auth condition");
            }

            test_signature_and_corruption(&origin_tx, true, false);
            test_signature_and_corruption(&origin_tx, false, true);
        }
    }

    #[test]
    fn tx_stacks_transaction_sign_verify_standard_order_independent_p2sh_uncompressed() {
        let privk_1 = StacksPrivateKey::from_hex(
            "6d430bb91222408e7706c9001cfaeb91b08c2be6d5ac95779ab52c6b431950e0",
        )
        .unwrap();
        let privk_2 = StacksPrivateKey::from_hex(
            "2a584d899fed1d24e26b524f202763c8ab30260167429f157f1c119f550fa6af",
        )
        .unwrap();
        let privk_3 = StacksPrivateKey::from_hex(
            "d5200dee706ee53ae98a03fba6cf4fdcc5084c30cfa9e1b3462dcdeaa3e0f1d2",
        )
        .unwrap();

        let pubk_1 = StacksPublicKey::from_private(&privk_1);
        let pubk_2 = StacksPublicKey::from_private(&privk_2);
        let pubk_3 = StacksPublicKey::from_private(&privk_3);

        let origin_auth = TransactionAuth::Standard(
            TransactionSpendingCondition::new_multisig_order_independent_p2sh(
                2,
                vec![pubk_1.clone(), pubk_2.clone(), pubk_3.clone()],
            )
            .unwrap(),
        );

        let origin_address = origin_auth.origin().address_mainnet();
        assert_eq!(
            origin_address,
            StacksAddress::new(
                C32_ADDRESS_VERSION_MAINNET_MULTISIG,
                Hash160::from_hex("73a8b4a751a678fe83e9d35ce301371bb3d397f7").unwrap(),
            )
            .unwrap()
        );

        let txs = tx_stacks_transaction_test_txs(&origin_auth);

        for mut tx in txs {
            assert_eq!(tx.auth().origin().num_signatures(), 0);

            let tx_signer = StacksTransactionSigner::new(&tx);

            let initial_sig_hash = tx.sign_begin();
            let sig3 = tx
                .sign_no_append_origin(&initial_sig_hash, &privk_3)
                .unwrap();
            let sig2 = tx
                .sign_no_append_origin(&initial_sig_hash, &privk_2)
                .unwrap();

            let _ = tx.append_next_origin(&pubk_1);
            tx.append_origin_signature(sig2, TransactionPublicKeyEncoding::Uncompressed);
            tx.append_origin_signature(sig3, TransactionPublicKeyEncoding::Uncompressed);

            check_oversign_origin_multisig(&tx);
            check_sign_no_sponsor(&mut tx);

            assert_eq!(tx.auth().origin().num_signatures(), 2);

            // auth is standard and first two auth fields are signatures for compressed keys.
            // third field is the third public key
            if let TransactionAuth::Standard(
                TransactionSpendingCondition::OrderIndependentMultisig(data),
            ) = &tx.auth
            {
                assert_eq!(data.signer, *origin_address.bytes());
                assert_eq!(data.fields.len(), 3);
                assert!(data.fields[0].is_public_key());
                assert!(data.fields[1].is_signature());
                assert!(data.fields[2].is_signature());

                assert_eq!(data.fields[0].as_public_key().unwrap(), pubk_1);
                assert_eq!(
                    data.fields[1].as_signature().unwrap().0,
                    TransactionPublicKeyEncoding::Uncompressed
                );
                assert_eq!(
                    data.fields[2].as_signature().unwrap().0,
                    TransactionPublicKeyEncoding::Uncompressed
                );
            } else {
                panic!("Unexpected auth condition");
            }

            test_signature_and_corruption(&tx, true, false);
        }
    }

    #[test]
    fn tx_stacks_transaction_sign_verify_sponsored_order_independent_p2sh_uncompressed() {
        let origin_privk = StacksPrivateKey::from_hex(
            "807bbe9e471ac976592cc35e3056592ecc0f778ee653fced3b491a122dd8d59701",
        )
        .unwrap();

        let privk_1 = StacksPrivateKey::from_hex(
            "6d430bb91222408e7706c9001cfaeb91b08c2be6d5ac95779ab52c6b431950e0",
        )
        .unwrap();
        let privk_2 = StacksPrivateKey::from_hex(
            "2a584d899fed1d24e26b524f202763c8ab30260167429f157f1c119f550fa6af",
        )
        .unwrap();
        let privk_3 = StacksPrivateKey::from_hex(
            "d5200dee706ee53ae98a03fba6cf4fdcc5084c30cfa9e1b3462dcdeaa3e0f1d2",
        )
        .unwrap();

        let pubk_1 = StacksPublicKey::from_private(&privk_1);
        let pubk_2 = StacksPublicKey::from_private(&privk_2);
        let pubk_3 = StacksPublicKey::from_private(&privk_3);

        let random_sponsor = StacksPrivateKey::random(); // what the origin sees

        let auth = TransactionAuth::Sponsored(
            TransactionSpendingCondition::new_singlesig_p2pkh(StacksPublicKey::from_private(
                &origin_privk,
            ))
            .unwrap(),
            TransactionSpendingCondition::new_singlesig_p2pkh(StacksPublicKey::from_private(
                &random_sponsor,
            ))
            .unwrap(),
        );

        let real_sponsor = TransactionSpendingCondition::new_multisig_order_independent_p2sh(
            2,
            vec![pubk_1.clone(), pubk_2.clone(), pubk_3.clone()],
        )
        .unwrap();

        let origin_address = auth.origin().address_mainnet();
        let sponsor_address = real_sponsor.address_mainnet();

        assert_eq!(
            origin_address,
            StacksAddress::new(
                C32_ADDRESS_VERSION_MAINNET_SINGLESIG,
                Hash160::from_hex("3597aaa4bde720be93e3829aae24e76e7fcdfd3e").unwrap(),
            )
            .unwrap()
        );
        assert_eq!(
            sponsor_address,
            StacksAddress::new(
                C32_ADDRESS_VERSION_MAINNET_MULTISIG,
                Hash160::from_hex("73a8b4a751a678fe83e9d35ce301371bb3d397f7").unwrap(),
            )
            .unwrap()
        );

        let txs = tx_stacks_transaction_test_txs(&auth);

        for mut tx in txs {
            assert_eq!(tx.auth().origin().num_signatures(), 0);
            assert_eq!(tx.auth().sponsor().unwrap().num_signatures(), 0);

            tx.set_tx_fee(123);
            tx.set_sponsor_nonce(456).unwrap();
            let mut tx_signer = StacksTransactionSigner::new(&tx);

            tx_signer.sign_origin(&origin_privk).unwrap();

            // sponsor sets and pays fee after origin signs
            let mut origin_tx = tx_signer.get_tx_incomplete();
            origin_tx.auth.set_sponsor(real_sponsor.clone()).unwrap();
            origin_tx.set_tx_fee(456);
            origin_tx.set_sponsor_nonce(789).unwrap();

            let initial_sig_hash = tx_signer.sighash;
            let sig1 = origin_tx
                .sign_no_append_sponsor(&initial_sig_hash, &privk_1)
                .unwrap();
            let sig2 = origin_tx
                .sign_no_append_sponsor(&initial_sig_hash, &privk_2)
                .unwrap();

            let _ = origin_tx
                .append_sponsor_signature(sig1, TransactionPublicKeyEncoding::Uncompressed);
            let _ = origin_tx
                .append_sponsor_signature(sig2, TransactionPublicKeyEncoding::Uncompressed);
            let _ = origin_tx.append_next_sponsor(&pubk_3);

            tx.set_tx_fee(456);
            tx.set_sponsor_nonce(789).unwrap();

            check_oversign_origin_singlesig(&mut origin_tx);
            check_oversign_sponsor_multisig(&origin_tx);

            assert_eq!(origin_tx.auth().origin().num_signatures(), 1);
            assert_eq!(origin_tx.auth().sponsor().unwrap().num_signatures(), 2);

            // tx and origin_tx are otherwise equal
            assert_eq!(tx.version, origin_tx.version);
            assert_eq!(tx.chain_id, origin_tx.chain_id);
            assert_eq!(tx.get_tx_fee(), origin_tx.get_tx_fee());
            assert_eq!(tx.get_origin_nonce(), origin_tx.get_origin_nonce());
            assert_eq!(tx.get_sponsor_nonce(), origin_tx.get_sponsor_nonce());
            assert_eq!(tx.anchor_mode, origin_tx.anchor_mode);
            assert_eq!(tx.post_condition_mode, origin_tx.post_condition_mode);
            assert_eq!(tx.post_conditions, origin_tx.post_conditions);
            assert_eq!(tx.payload, origin_tx.payload);

            // auth is standard and first two auth fields are signatures for compressed keys.
            // third field is the third public key
            if let TransactionAuth::Sponsored(
                TransactionSpendingCondition::Singlesig(origin_data),
                TransactionSpendingCondition::OrderIndependentMultisig(sponsor_data),
            ) = &origin_tx.auth
            {
                assert_eq!(
                    origin_data.key_encoding,
                    TransactionPublicKeyEncoding::Compressed
                );
                assert_eq!(origin_data.signer, *origin_address.bytes());

                assert_eq!(sponsor_data.signer, *sponsor_address.bytes());
                assert_eq!(sponsor_data.fields.len(), 3);
                assert!(sponsor_data.fields[0].is_signature());
                assert!(sponsor_data.fields[1].is_signature());
                assert!(sponsor_data.fields[2].is_public_key());

                assert_eq!(
                    sponsor_data.fields[0].as_signature().unwrap().0,
                    TransactionPublicKeyEncoding::Uncompressed
                );
                assert_eq!(
                    sponsor_data.fields[1].as_signature().unwrap().0,
                    TransactionPublicKeyEncoding::Uncompressed
                );
                assert_eq!(sponsor_data.fields[2].as_public_key().unwrap(), pubk_3);
            } else {
                panic!("Unexpected auth condition");
            }

            test_signature_and_corruption(&origin_tx, true, false);
            test_signature_and_corruption(&origin_tx, false, true);
        }
    }

    #[test]
    fn tx_stacks_transaction_sign_verify_standard_order_independent_p2sh_mixed() {
        let privk_1 = StacksPrivateKey::from_hex(
            "6d430bb91222408e7706c9001cfaeb91b08c2be6d5ac95779ab52c6b431950e001",
        )
        .unwrap();
        let privk_2 = StacksPrivateKey::from_hex(
            "2a584d899fed1d24e26b524f202763c8ab30260167429f157f1c119f550fa6af01",
        )
        .unwrap();
        let privk_3 = StacksPrivateKey::from_hex(
            "d5200dee706ee53ae98a03fba6cf4fdcc5084c30cfa9e1b3462dcdeaa3e0f1d201",
        )
        .unwrap();

        let pubk_1 = StacksPublicKey::from_private(&privk_1);
        let pubk_2 = StacksPublicKey::from_private(&privk_2);
        let pubk_3 = StacksPublicKey::from_private(&privk_3);

        let origin_auth = TransactionAuth::Standard(
            TransactionSpendingCondition::new_multisig_order_independent_p2sh(
                2,
                vec![pubk_1.clone(), pubk_2.clone(), pubk_3.clone()],
            )
            .unwrap(),
        );

        let origin_address = origin_auth.origin().address_mainnet();
        assert_eq!(
            origin_address,
            StacksAddress::new(
                C32_ADDRESS_VERSION_MAINNET_MULTISIG,
                Hash160::from_hex("a23ea89d6529ac48ac766f720e480beec7f19273").unwrap(),
            )
            .unwrap()
        );

        let txs = tx_stacks_transaction_test_txs(&origin_auth);

        for mut tx in txs {
            assert_eq!(tx.auth().origin().num_signatures(), 0);

            let tx_signer = StacksTransactionSigner::new(&tx);

            let initial_sig_hash = tx.sign_begin();
            let sig3 = tx
                .sign_no_append_origin(&initial_sig_hash, &privk_3)
                .unwrap();
            let sig1 = tx
                .sign_no_append_origin(&initial_sig_hash, &privk_1)
                .unwrap();

            tx.append_origin_signature(sig1, TransactionPublicKeyEncoding::Compressed);
            let _ = tx.append_next_origin(&pubk_2);
            tx.append_origin_signature(sig3, TransactionPublicKeyEncoding::Compressed);

            check_oversign_origin_multisig(&tx);
            check_sign_no_sponsor(&mut tx);

            assert_eq!(tx.auth().origin().num_signatures(), 2);

            // auth is standard and first two auth fields are signatures for compressed keys.
            // third field is the third public key
            if let TransactionAuth::Standard(
                TransactionSpendingCondition::OrderIndependentMultisig(data),
            ) = &tx.auth
            {
                assert_eq!(data.signer, *origin_address.bytes());
                assert_eq!(data.fields.len(), 3);
                assert!(data.fields[0].is_signature());
                assert!(data.fields[1].is_public_key());
                assert!(data.fields[2].is_signature());

                assert_eq!(data.fields[1].as_public_key().unwrap(), pubk_2);
                assert_eq!(
                    data.fields[0].as_signature().unwrap().0,
                    TransactionPublicKeyEncoding::Compressed
                );
                assert_eq!(
                    data.fields[2].as_signature().unwrap().0,
                    TransactionPublicKeyEncoding::Compressed
                );
            } else {
                panic!("Unexpected auth condition");
            }

            test_signature_and_corruption(&tx, true, false);
        }
    }

    #[test]
    fn tx_stacks_transaction_sign_verify_standard_order_independent_p2sh_mixed_3_out_of_9() {
        let privk_1 = StacksPrivateKey::from_hex(
            "6d430bb91222408e7706c9001cfaeb91b08c2be6d5ac95779ab52c6b431950e001",
        )
        .unwrap();
        let privk_2 = StacksPrivateKey::from_hex(
            "2a584d899fed1d24e26b524f202763c8ab30260167429f157f1c119f550fa6af01",
        )
        .unwrap();
        let privk_3 = StacksPrivateKey::from_hex(
            "d5200dee706ee53ae98a03fba6cf4fdcc5084c30cfa9e1b3462dcdeaa3e0f1d201",
        )
        .unwrap();
        let privk_4 = StacksPrivateKey::from_hex(
            "3beb8916404874f5d5de162c95470951de5b4a7f6ec8d7a20511551821f16db501",
        )
        .unwrap();
        let privk_5 = StacksPrivateKey::from_hex(
            "601aa0939e98efec29a4dc645377c9d4acaa0b7318444ec8fd7d090d0b36d85b01",
        )
        .unwrap();
        let privk_6 = StacksPrivateKey::from_hex(
            "5a4ca3db5a3b36bc32d9f2f0894435cbc4b2b1207e95ee283616d9a0797210da01",
        )
        .unwrap();
        let privk_7 = StacksPrivateKey::from_hex(
            "068856c242bfebdc57700fa598fae4e8ebb6b5f6bf932177018071489737d3ff01",
        )
        .unwrap();
        let privk_8 = StacksPrivateKey::from_hex(
            "a07a397f6b31c803f5d7f0c4620576cb03c66c12cdbdb6cd91d001d6f0052de201",
        )
        .unwrap();
        let privk_9 = StacksPrivateKey::from_hex(
            "f395129abc42c57e394dcceebeca9f51f0cb0a3f1c3a899d62e40b9340c7cc1101",
        )
        .unwrap();

        let pubk_1 = StacksPublicKey::from_private(&privk_1);
        let pubk_2 = StacksPublicKey::from_private(&privk_2);
        let pubk_3 = StacksPublicKey::from_private(&privk_3);
        let pubk_4 = StacksPublicKey::from_private(&privk_4);
        let pubk_5 = StacksPublicKey::from_private(&privk_5);
        let pubk_6 = StacksPublicKey::from_private(&privk_6);
        let pubk_7 = StacksPublicKey::from_private(&privk_7);
        let pubk_8 = StacksPublicKey::from_private(&privk_8);
        let pubk_9 = StacksPublicKey::from_private(&privk_9);

        let origin_auth = TransactionAuth::Standard(
            TransactionSpendingCondition::new_multisig_order_independent_p2sh(
                3,
                vec![
                    pubk_1.clone(),
                    pubk_2.clone(),
                    pubk_3.clone(),
                    pubk_4.clone(),
                    pubk_5.clone(),
                    pubk_6.clone(),
                    pubk_7.clone(),
                    pubk_8.clone(),
                    pubk_9.clone(),
                ],
            )
            .unwrap(),
        );

        let origin_address = origin_auth.origin().address_mainnet();
        assert_eq!(
            origin_address,
            StacksAddress::new(
                C32_ADDRESS_VERSION_MAINNET_MULTISIG,
                Hash160::from_hex("315d672961ef2583faf4107ab4ec5566014c867c").unwrap(),
            )
            .unwrap()
        );

        let txs = tx_stacks_transaction_test_txs(&origin_auth);

        for mut tx in txs {
            assert_eq!(tx.auth().origin().num_signatures(), 0);

            let tx_signer = StacksTransactionSigner::new(&tx);

            let initial_sig_hash = tx.sign_begin();
            let sig3 = tx
                .sign_no_append_origin(&initial_sig_hash, &privk_3)
                .unwrap();
            let sig1 = tx
                .sign_no_append_origin(&initial_sig_hash, &privk_1)
                .unwrap();
            let sig9 = tx
                .sign_no_append_origin(&initial_sig_hash, &privk_9)
                .unwrap();

            tx.append_origin_signature(sig1, TransactionPublicKeyEncoding::Compressed);
            let _ = tx.append_next_origin(&pubk_2);
            tx.append_origin_signature(sig3, TransactionPublicKeyEncoding::Compressed);
            let _ = tx.append_next_origin(&pubk_4);
            let _ = tx.append_next_origin(&pubk_5);
            let _ = tx.append_next_origin(&pubk_6);
            let _ = tx.append_next_origin(&pubk_7);
            let _ = tx.append_next_origin(&pubk_8);
            tx.append_origin_signature(sig9, TransactionPublicKeyEncoding::Compressed);

            check_oversign_origin_multisig(&tx);
            check_sign_no_sponsor(&mut tx);

            assert_eq!(tx.auth().origin().num_signatures(), 3);

            // auth is standard and first two auth fields are signatures for compressed keys.
            // third field is the third public key
            if let TransactionAuth::Standard(
                TransactionSpendingCondition::OrderIndependentMultisig(data),
            ) = &tx.auth
            {
                assert_eq!(data.signer, *origin_address.bytes());
                assert_eq!(data.fields.len(), 9);
                assert!(data.fields[0].is_signature());
                assert!(data.fields[1].is_public_key());
                assert!(data.fields[2].is_signature());
                assert!(data.fields[3].is_public_key());
                assert!(data.fields[4].is_public_key());
                assert!(data.fields[5].is_public_key());
                assert!(data.fields[6].is_public_key());
                assert!(data.fields[7].is_public_key());
                assert!(data.fields[8].is_signature());

                assert_eq!(data.fields[1].as_public_key().unwrap(), pubk_2);
                assert_eq!(data.fields[3].as_public_key().unwrap(), pubk_4);
                assert_eq!(data.fields[4].as_public_key().unwrap(), pubk_5);
                assert_eq!(data.fields[5].as_public_key().unwrap(), pubk_6);
                assert_eq!(data.fields[6].as_public_key().unwrap(), pubk_7);
                assert_eq!(data.fields[7].as_public_key().unwrap(), pubk_8);
                assert_eq!(
                    data.fields[0].as_signature().unwrap().0,
                    TransactionPublicKeyEncoding::Compressed
                );
                assert_eq!(
                    data.fields[2].as_signature().unwrap().0,
                    TransactionPublicKeyEncoding::Compressed
                );
                assert_eq!(
                    data.fields[8].as_signature().unwrap().0,
                    TransactionPublicKeyEncoding::Compressed
                );
            } else {
                panic!("Unexpected auth condition");
            }

            test_signature_and_corruption(&tx, true, false);
        }
    }

    #[test]
    fn tx_stacks_transaction_sign_verify_sponsored_order_independent_p2sh_mixed() {
        let origin_privk = StacksPrivateKey::from_hex(
            "807bbe9e471ac976592cc35e3056592ecc0f778ee653fced3b491a122dd8d59701",
        )
        .unwrap();

        let privk_1 = StacksPrivateKey::from_hex(
            "6d430bb91222408e7706c9001cfaeb91b08c2be6d5ac95779ab52c6b431950e001",
        )
        .unwrap();
        let privk_2 = StacksPrivateKey::from_hex(
            "2a584d899fed1d24e26b524f202763c8ab30260167429f157f1c119f550fa6af01",
        )
        .unwrap();
        let privk_3 = StacksPrivateKey::from_hex(
            "d5200dee706ee53ae98a03fba6cf4fdcc5084c30cfa9e1b3462dcdeaa3e0f1d201",
        )
        .unwrap();

        let pubk_1 = StacksPublicKey::from_private(&privk_1);
        let pubk_2 = StacksPublicKey::from_private(&privk_2);
        let pubk_3 = StacksPublicKey::from_private(&privk_3);

        let random_sponsor = StacksPrivateKey::random(); // what the origin sees

        let auth = TransactionAuth::Sponsored(
            TransactionSpendingCondition::new_singlesig_p2pkh(StacksPublicKey::from_private(
                &origin_privk,
            ))
            .unwrap(),
            TransactionSpendingCondition::new_singlesig_p2pkh(StacksPublicKey::from_private(
                &random_sponsor,
            ))
            .unwrap(),
        );

        let real_sponsor = TransactionSpendingCondition::new_multisig_order_independent_p2sh(
            2,
            vec![pubk_1.clone(), pubk_2.clone(), pubk_3.clone()],
        )
        .unwrap();

        let origin_address = auth.origin().address_mainnet();
        let sponsor_address = real_sponsor.address_mainnet();

        assert_eq!(
            origin_address,
            StacksAddress::new(
                C32_ADDRESS_VERSION_MAINNET_SINGLESIG,
                Hash160::from_hex("3597aaa4bde720be93e3829aae24e76e7fcdfd3e").unwrap(),
            )
            .unwrap()
        );
        assert_eq!(
            sponsor_address,
            StacksAddress::new(
                C32_ADDRESS_VERSION_MAINNET_MULTISIG,
                Hash160::from_hex("a23ea89d6529ac48ac766f720e480beec7f19273").unwrap(),
            )
            .unwrap()
        );

        let txs = tx_stacks_transaction_test_txs(&auth);

        for mut tx in txs {
            assert_eq!(tx.auth().origin().num_signatures(), 0);
            assert_eq!(tx.auth().sponsor().unwrap().num_signatures(), 0);

            tx.set_tx_fee(123);
            tx.set_sponsor_nonce(456).unwrap();
            let mut tx_signer = StacksTransactionSigner::new(&tx);

            tx_signer.sign_origin(&origin_privk).unwrap();

            // sponsor sets and pays fee after origin signs
            let mut origin_tx = tx_signer.get_tx_incomplete();
            origin_tx.auth.set_sponsor(real_sponsor.clone()).unwrap();
            origin_tx.set_tx_fee(456);
            origin_tx.set_sponsor_nonce(789).unwrap();

            let initial_sig_hash = tx_signer.sighash;
            let sig1 = origin_tx
                .sign_no_append_sponsor(&initial_sig_hash, &privk_1)
                .unwrap();
            let sig3 = origin_tx
                .sign_no_append_sponsor(&initial_sig_hash, &privk_3)
                .unwrap();

            let _ =
                origin_tx.append_sponsor_signature(sig1, TransactionPublicKeyEncoding::Compressed);
            let _ = origin_tx.append_next_sponsor(&pubk_2);
            let _ =
                origin_tx.append_sponsor_signature(sig3, TransactionPublicKeyEncoding::Compressed);

            tx.set_tx_fee(456);
            tx.set_sponsor_nonce(789).unwrap();

            check_oversign_origin_singlesig(&mut origin_tx);
            check_oversign_sponsor_multisig(&origin_tx);

            assert_eq!(origin_tx.auth().origin().num_signatures(), 1);
            assert_eq!(origin_tx.auth().sponsor().unwrap().num_signatures(), 2);

            // tx and origin_tx are otherwise equal
            assert_eq!(tx.version, origin_tx.version);
            assert_eq!(tx.chain_id, origin_tx.chain_id);
            assert_eq!(tx.get_tx_fee(), origin_tx.get_tx_fee());
            assert_eq!(tx.get_origin_nonce(), origin_tx.get_origin_nonce());
            assert_eq!(tx.get_sponsor_nonce(), origin_tx.get_sponsor_nonce());
            assert_eq!(tx.anchor_mode, origin_tx.anchor_mode);
            assert_eq!(tx.post_condition_mode, origin_tx.post_condition_mode);
            assert_eq!(tx.post_conditions, origin_tx.post_conditions);
            assert_eq!(tx.payload, origin_tx.payload);

            // auth is standard and first two auth fields are signatures for compressed keys.
            // third field is the third public key
            if let TransactionAuth::Sponsored(
                TransactionSpendingCondition::Singlesig(origin_data),
                TransactionSpendingCondition::OrderIndependentMultisig(sponsor_data),
            ) = &origin_tx.auth
            {
                assert_eq!(
                    origin_data.key_encoding,
                    TransactionPublicKeyEncoding::Compressed
                );
                assert_eq!(origin_data.signer, *origin_address.bytes());

                assert_eq!(sponsor_data.signer, *sponsor_address.bytes());
                assert_eq!(sponsor_data.fields.len(), 3);
                assert!(sponsor_data.fields[0].is_signature());
                assert!(sponsor_data.fields[1].is_public_key());
                assert!(sponsor_data.fields[2].is_signature());

                assert_eq!(
                    sponsor_data.fields[0].as_signature().unwrap().0,
                    TransactionPublicKeyEncoding::Compressed
                );
                assert_eq!(
                    sponsor_data.fields[2].as_signature().unwrap().0,
                    TransactionPublicKeyEncoding::Compressed
                );
                assert_eq!(sponsor_data.fields[1].as_public_key().unwrap(), pubk_2);
            } else {
                panic!("Unexpected auth condition");
            }

            test_signature_and_corruption(&origin_tx, true, false);
            test_signature_and_corruption(&origin_tx, false, true);
        }
    }

    #[test]
    fn tx_stacks_transaction_sign_verify_sponsored_order_independent_p2sh_mixed_5_out_of_5() {
        let origin_privk = StacksPrivateKey::from_hex(
            "807bbe9e471ac976592cc35e3056592ecc0f778ee653fced3b491a122dd8d59701",
        )
        .unwrap();

        let privk_1 = StacksPrivateKey::from_hex(
            "6d430bb91222408e7706c9001cfaeb91b08c2be6d5ac95779ab52c6b431950e001",
        )
        .unwrap();
        let privk_2 = StacksPrivateKey::from_hex(
            "2a584d899fed1d24e26b524f202763c8ab30260167429f157f1c119f550fa6af01",
        )
        .unwrap();
        let privk_3 = StacksPrivateKey::from_hex(
            "d5200dee706ee53ae98a03fba6cf4fdcc5084c30cfa9e1b3462dcdeaa3e0f1d201",
        )
        .unwrap();
        let privk_4 = StacksPrivateKey::from_hex(
            "3beb8916404874f5d5de162c95470951de5b4a7f6ec8d7a20511551821f16db501",
        )
        .unwrap();
        let privk_5 = StacksPrivateKey::from_hex(
            "601aa0939e98efec29a4dc645377c9d4acaa0b7318444ec8fd7d090d0b36d85b01",
        )
        .unwrap();

        let pubk_1 = StacksPublicKey::from_private(&privk_1);
        let pubk_2 = StacksPublicKey::from_private(&privk_2);
        let pubk_3 = StacksPublicKey::from_private(&privk_3);
        let pubk_4 = StacksPublicKey::from_private(&privk_4);
        let pubk_5 = StacksPublicKey::from_private(&privk_5);

        let random_sponsor = StacksPrivateKey::random(); // what the origin sees

        let auth = TransactionAuth::Sponsored(
            TransactionSpendingCondition::new_singlesig_p2pkh(StacksPublicKey::from_private(
                &origin_privk,
            ))
            .unwrap(),
            TransactionSpendingCondition::new_singlesig_p2pkh(StacksPublicKey::from_private(
                &random_sponsor,
            ))
            .unwrap(),
        );

        let real_sponsor = TransactionSpendingCondition::new_multisig_order_independent_p2sh(
            5,
            vec![
                pubk_1.clone(),
                pubk_2.clone(),
                pubk_3.clone(),
                pubk_4.clone(),
                pubk_5.clone(),
            ],
        )
        .unwrap();

        let origin_address = auth.origin().address_mainnet();
        let sponsor_address = real_sponsor.address_mainnet();

        assert_eq!(
            origin_address,
            StacksAddress::new(
                C32_ADDRESS_VERSION_MAINNET_SINGLESIG,
                Hash160::from_hex("3597aaa4bde720be93e3829aae24e76e7fcdfd3e").unwrap(),
            )
            .unwrap()
        );
        assert_eq!(
            sponsor_address,
            StacksAddress::new(
                C32_ADDRESS_VERSION_MAINNET_MULTISIG,
                Hash160::from_hex("fc29d14be615b0f72a66b920040c2b5b8124990b").unwrap(),
            )
            .unwrap()
        );

        let txs = tx_stacks_transaction_test_txs(&auth);

        for mut tx in txs {
            assert_eq!(tx.auth().origin().num_signatures(), 0);
            assert_eq!(tx.auth().sponsor().unwrap().num_signatures(), 0);

            tx.set_tx_fee(123);
            tx.set_sponsor_nonce(456).unwrap();
            let mut tx_signer = StacksTransactionSigner::new(&tx);

            tx_signer.sign_origin(&origin_privk).unwrap();

            // sponsor sets and pays fee after origin signs
            let mut origin_tx = tx_signer.get_tx_incomplete();
            origin_tx.auth.set_sponsor(real_sponsor.clone()).unwrap();
            origin_tx.set_tx_fee(456);
            origin_tx.set_sponsor_nonce(789).unwrap();

            let initial_sig_hash = tx_signer.sighash;
            let sig1 = origin_tx
                .sign_no_append_sponsor(&initial_sig_hash, &privk_1)
                .unwrap();
            let sig3 = origin_tx
                .sign_no_append_sponsor(&initial_sig_hash, &privk_3)
                .unwrap();
            let sig2 = origin_tx
                .sign_no_append_sponsor(&initial_sig_hash, &privk_2)
                .unwrap();
            let sig4 = origin_tx
                .sign_no_append_sponsor(&initial_sig_hash, &privk_4)
                .unwrap();
            let sig5 = origin_tx
                .sign_no_append_sponsor(&initial_sig_hash, &privk_5)
                .unwrap();

            let _ =
                origin_tx.append_sponsor_signature(sig1, TransactionPublicKeyEncoding::Compressed);
            let _ =
                origin_tx.append_sponsor_signature(sig2, TransactionPublicKeyEncoding::Compressed);
            let _ =
                origin_tx.append_sponsor_signature(sig3, TransactionPublicKeyEncoding::Compressed);
            let _ =
                origin_tx.append_sponsor_signature(sig4, TransactionPublicKeyEncoding::Compressed);
            let _ =
                origin_tx.append_sponsor_signature(sig5, TransactionPublicKeyEncoding::Compressed);

            tx.set_tx_fee(456);
            tx.set_sponsor_nonce(789).unwrap();

            check_oversign_origin_singlesig(&mut origin_tx);
            check_oversign_sponsor_multisig(&origin_tx);

            assert_eq!(origin_tx.auth().origin().num_signatures(), 1);
            assert_eq!(origin_tx.auth().sponsor().unwrap().num_signatures(), 5);

            // tx and origin_tx are otherwise equal
            assert_eq!(tx.version, origin_tx.version);
            assert_eq!(tx.chain_id, origin_tx.chain_id);
            assert_eq!(tx.get_tx_fee(), origin_tx.get_tx_fee());
            assert_eq!(tx.get_origin_nonce(), origin_tx.get_origin_nonce());
            assert_eq!(tx.get_sponsor_nonce(), origin_tx.get_sponsor_nonce());
            assert_eq!(tx.anchor_mode, origin_tx.anchor_mode);
            assert_eq!(tx.post_condition_mode, origin_tx.post_condition_mode);
            assert_eq!(tx.post_conditions, origin_tx.post_conditions);
            assert_eq!(tx.payload, origin_tx.payload);

            // auth is standard and first two auth fields are signatures for compressed keys.
            // third field is the third public key
            if let TransactionAuth::Sponsored(
                TransactionSpendingCondition::Singlesig(origin_data),
                TransactionSpendingCondition::OrderIndependentMultisig(sponsor_data),
            ) = &origin_tx.auth
            {
                assert_eq!(
                    origin_data.key_encoding,
                    TransactionPublicKeyEncoding::Compressed
                );
                assert_eq!(origin_data.signer, *origin_address.bytes());

                assert_eq!(sponsor_data.signer, *sponsor_address.bytes());
                assert_eq!(sponsor_data.fields.len(), 5);
                assert!(sponsor_data.fields[0].is_signature());
                assert!(sponsor_data.fields[1].is_signature());
                assert!(sponsor_data.fields[2].is_signature());
                assert!(sponsor_data.fields[3].is_signature());
                assert!(sponsor_data.fields[4].is_signature());

                assert_eq!(
                    sponsor_data.fields[0].as_signature().unwrap().0,
                    TransactionPublicKeyEncoding::Compressed
                );
                assert_eq!(
                    sponsor_data.fields[1].as_signature().unwrap().0,
                    TransactionPublicKeyEncoding::Compressed
                );
                assert_eq!(
                    sponsor_data.fields[2].as_signature().unwrap().0,
                    TransactionPublicKeyEncoding::Compressed
                );
                assert_eq!(
                    sponsor_data.fields[3].as_signature().unwrap().0,
                    TransactionPublicKeyEncoding::Compressed
                );
                assert_eq!(
                    sponsor_data.fields[4].as_signature().unwrap().0,
                    TransactionPublicKeyEncoding::Compressed
                );
            } else {
                panic!("Unexpected auth condition");
            }

            test_signature_and_corruption(&origin_tx, true, false);
            test_signature_and_corruption(&origin_tx, false, true);
        }
    }

    #[test]
    fn tx_stacks_transaction_sign_verify_standard_order_independent_p2wsh() {
        let privk_1 = StacksPrivateKey::from_hex(
            "6d430bb91222408e7706c9001cfaeb91b08c2be6d5ac95779ab52c6b431950e001",
        )
        .unwrap();
        let privk_2 = StacksPrivateKey::from_hex(
            "2a584d899fed1d24e26b524f202763c8ab30260167429f157f1c119f550fa6af01",
        )
        .unwrap();
        let privk_3 = StacksPrivateKey::from_hex(
            "d5200dee706ee53ae98a03fba6cf4fdcc5084c30cfa9e1b3462dcdeaa3e0f1d201",
        )
        .unwrap();

        let pubk_1 = StacksPublicKey::from_private(&privk_1);
        let pubk_2 = StacksPublicKey::from_private(&privk_2);
        let pubk_3 = StacksPublicKey::from_private(&privk_3);

        let origin_auth = TransactionAuth::Standard(
            TransactionSpendingCondition::new_multisig_order_independent_p2wsh(
                2,
                vec![pubk_1.clone(), pubk_2.clone(), pubk_3.clone()],
            )
            .unwrap(),
        );

        let origin_address = origin_auth.origin().address_mainnet();
        assert_eq!(
            origin_address,
            StacksAddress::new(
                C32_ADDRESS_VERSION_MAINNET_MULTISIG,
                Hash160::from_hex("f5cfb61a07fb41a32197da01ce033888f0fe94a7").unwrap(),
            )
            .unwrap()
        );

        let txs = tx_stacks_transaction_test_txs(&origin_auth);

        for mut tx in txs {
            assert_eq!(tx.auth().origin().num_signatures(), 0);

            let tx_signer = StacksTransactionSigner::new(&tx);

            let initial_sig_hash = tx.sign_begin();
            let sig3 = tx
                .sign_no_append_origin(&initial_sig_hash, &privk_3)
                .unwrap();
            let sig1 = tx
                .sign_no_append_origin(&initial_sig_hash, &privk_1)
                .unwrap();

            tx.append_origin_signature(sig1, TransactionPublicKeyEncoding::Compressed);
            let _ = tx.append_next_origin(&pubk_2);
            tx.append_origin_signature(sig3, TransactionPublicKeyEncoding::Compressed);

            check_oversign_origin_multisig(&tx);
            check_oversign_origin_multisig_uncompressed(&tx);
            check_sign_no_sponsor(&mut tx);

            assert_eq!(tx.auth().origin().num_signatures(), 2);

            // auth is standard and first two auth fields are signatures for compressed keys.
            // third field is the third public key
            if let TransactionAuth::Standard(
                TransactionSpendingCondition::OrderIndependentMultisig(data),
            ) = &tx.auth
            {
                assert_eq!(data.signer, *origin_address.bytes());
                assert_eq!(data.fields.len(), 3);
                assert!(data.fields[0].is_signature());
                assert!(data.fields[1].is_public_key());
                assert!(data.fields[2].is_signature());

                assert_eq!(data.fields[1].as_public_key().unwrap(), pubk_2);
                assert_eq!(
                    data.fields[0].as_signature().unwrap().0,
                    TransactionPublicKeyEncoding::Compressed
                );
                assert_eq!(
                    data.fields[2].as_signature().unwrap().0,
                    TransactionPublicKeyEncoding::Compressed
                );
            } else {
                panic!("Unexpected auth condition");
            }

            test_signature_and_corruption(&tx, true, false);
        }
    }

    #[test]
    fn tx_stacks_transaction_sign_verify_standard_order_independent_p2wsh_4_out_of_6() {
        let privk_1 = StacksPrivateKey::from_hex(
            "6d430bb91222408e7706c9001cfaeb91b08c2be6d5ac95779ab52c6b431950e001",
        )
        .unwrap();
        let privk_2 = StacksPrivateKey::from_hex(
            "2a584d899fed1d24e26b524f202763c8ab30260167429f157f1c119f550fa6af01",
        )
        .unwrap();
        let privk_3 = StacksPrivateKey::from_hex(
            "d5200dee706ee53ae98a03fba6cf4fdcc5084c30cfa9e1b3462dcdeaa3e0f1d201",
        )
        .unwrap();
        let privk_4 = StacksPrivateKey::from_hex(
            "3beb8916404874f5d5de162c95470951de5b4a7f6ec8d7a20511551821f16db501",
        )
        .unwrap();
        let privk_5 = StacksPrivateKey::from_hex(
            "601aa0939e98efec29a4dc645377c9d4acaa0b7318444ec8fd7d090d0b36d85b01",
        )
        .unwrap();
        let privk_6 = StacksPrivateKey::from_hex(
            "5a4ca3db5a3b36bc32d9f2f0894435cbc4b2b1207e95ee283616d9a0797210da01",
        )
        .unwrap();

        let pubk_1 = StacksPublicKey::from_private(&privk_1);
        let pubk_2 = StacksPublicKey::from_private(&privk_2);
        let pubk_3 = StacksPublicKey::from_private(&privk_3);
        let pubk_4 = StacksPublicKey::from_private(&privk_4);
        let pubk_5 = StacksPublicKey::from_private(&privk_5);
        let pubk_6 = StacksPublicKey::from_private(&privk_6);

        let origin_auth = TransactionAuth::Standard(
            TransactionSpendingCondition::new_multisig_order_independent_p2wsh(
                4,
                vec![
                    pubk_1.clone(),
                    pubk_2.clone(),
                    pubk_3.clone(),
                    pubk_4.clone(),
                    pubk_5.clone(),
                    pubk_6.clone(),
                ],
            )
            .unwrap(),
        );

        let origin_address = origin_auth.origin().address_mainnet();
        assert_eq!(
            origin_address,
            StacksAddress::new(
                C32_ADDRESS_VERSION_MAINNET_MULTISIG,
                Hash160::from_hex("e2a4ae14ffb0a4a0982a06d07b97d57268d2bf94").unwrap(),
            )
            .unwrap()
        );

        let txs = tx_stacks_transaction_test_txs(&origin_auth);

        for mut tx in txs {
            assert_eq!(tx.auth().origin().num_signatures(), 0);

            let tx_signer = StacksTransactionSigner::new(&tx);

            let initial_sig_hash = tx.sign_begin();
            let sig3 = tx
                .sign_no_append_origin(&initial_sig_hash, &privk_3)
                .unwrap();
            let sig1 = tx
                .sign_no_append_origin(&initial_sig_hash, &privk_1)
                .unwrap();
            let sig6 = tx
                .sign_no_append_origin(&initial_sig_hash, &privk_6)
                .unwrap();
            let sig5 = tx
                .sign_no_append_origin(&initial_sig_hash, &privk_5)
                .unwrap();

            tx.append_origin_signature(sig1, TransactionPublicKeyEncoding::Compressed);
            let _ = tx.append_next_origin(&pubk_2);
            tx.append_origin_signature(sig3, TransactionPublicKeyEncoding::Compressed);
            let _ = tx.append_next_origin(&pubk_4);
            tx.append_origin_signature(sig5, TransactionPublicKeyEncoding::Compressed);
            tx.append_origin_signature(sig6, TransactionPublicKeyEncoding::Compressed);

            check_oversign_origin_multisig(&tx);
            check_oversign_origin_multisig_uncompressed(&tx);
            check_sign_no_sponsor(&mut tx);

            assert_eq!(tx.auth().origin().num_signatures(), 4);

            // auth is standard and first two auth fields are signatures for compressed keys.
            // third field is the third public key
            if let TransactionAuth::Standard(
                TransactionSpendingCondition::OrderIndependentMultisig(data),
            ) = &tx.auth
            {
                assert_eq!(data.signer, *origin_address.bytes());
                assert_eq!(data.fields.len(), 6);
                assert!(data.fields[0].is_signature());
                assert!(data.fields[1].is_public_key());
                assert!(data.fields[2].is_signature());
                assert!(data.fields[3].is_public_key());
                assert!(data.fields[4].is_signature());
                assert!(data.fields[5].is_signature());

                assert_eq!(data.fields[1].as_public_key().unwrap(), pubk_2);
                assert_eq!(data.fields[3].as_public_key().unwrap(), pubk_4);
                assert_eq!(
                    data.fields[0].as_signature().unwrap().0,
                    TransactionPublicKeyEncoding::Compressed
                );
                assert_eq!(
                    data.fields[2].as_signature().unwrap().0,
                    TransactionPublicKeyEncoding::Compressed
                );
                assert_eq!(
                    data.fields[4].as_signature().unwrap().0,
                    TransactionPublicKeyEncoding::Compressed
                );
                assert_eq!(
                    data.fields[5].as_signature().unwrap().0,
                    TransactionPublicKeyEncoding::Compressed
                );
            } else {
                panic!("Unexpected auth condition");
            }

            test_signature_and_corruption(&tx, true, false);
        }
    }

    #[test]
    fn tx_stacks_transaction_sign_verify_sponsored_order_independent_p2wsh() {
        let origin_privk = StacksPrivateKey::from_hex(
            "807bbe9e471ac976592cc35e3056592ecc0f778ee653fced3b491a122dd8d59701",
        )
        .unwrap();

        let privk_1 = StacksPrivateKey::from_hex(
            "6d430bb91222408e7706c9001cfaeb91b08c2be6d5ac95779ab52c6b431950e001",
        )
        .unwrap();
        let privk_2 = StacksPrivateKey::from_hex(
            "2a584d899fed1d24e26b524f202763c8ab30260167429f157f1c119f550fa6af01",
        )
        .unwrap();
        let privk_3 = StacksPrivateKey::from_hex(
            "d5200dee706ee53ae98a03fba6cf4fdcc5084c30cfa9e1b3462dcdeaa3e0f1d201",
        )
        .unwrap();

        let pubk_1 = StacksPublicKey::from_private(&privk_1);
        let pubk_2 = StacksPublicKey::from_private(&privk_2);
        let pubk_3 = StacksPublicKey::from_private(&privk_3);

        let random_sponsor = StacksPrivateKey::random(); // what the origin sees

        let auth = TransactionAuth::Sponsored(
            TransactionSpendingCondition::new_singlesig_p2pkh(StacksPublicKey::from_private(
                &origin_privk,
            ))
            .unwrap(),
            TransactionSpendingCondition::new_singlesig_p2pkh(StacksPublicKey::from_private(
                &random_sponsor,
            ))
            .unwrap(),
        );

        let real_sponsor = TransactionSpendingCondition::new_multisig_order_independent_p2wsh(
            2,
            vec![pubk_1.clone(), pubk_2.clone(), pubk_3.clone()],
        )
        .unwrap();

        let origin_address = auth.origin().address_mainnet();
        let sponsor_address = real_sponsor.address_mainnet();

        assert_eq!(
            origin_address,
            StacksAddress::new(
                C32_ADDRESS_VERSION_MAINNET_SINGLESIG,
                Hash160::from_hex("3597aaa4bde720be93e3829aae24e76e7fcdfd3e").unwrap(),
            )
            .unwrap()
        );
        assert_eq!(
            sponsor_address,
            StacksAddress::new(
                C32_ADDRESS_VERSION_MAINNET_MULTISIG,
                Hash160::from_hex("f5cfb61a07fb41a32197da01ce033888f0fe94a7").unwrap(),
            )
            .unwrap()
        );

        let txs = tx_stacks_transaction_test_txs(&auth);

        for mut tx in txs {
            assert_eq!(tx.auth().origin().num_signatures(), 0);
            assert_eq!(tx.auth().sponsor().unwrap().num_signatures(), 0);

            tx.set_tx_fee(123);
            tx.set_sponsor_nonce(456).unwrap();
            let mut tx_signer = StacksTransactionSigner::new(&tx);

            tx_signer.sign_origin(&origin_privk).unwrap();

            // sponsor sets and pays fee after origin signs
            let mut origin_tx = tx_signer.get_tx_incomplete();
            origin_tx.auth.set_sponsor(real_sponsor.clone()).unwrap();
            origin_tx.set_tx_fee(456);
            origin_tx.set_sponsor_nonce(789).unwrap();

            let initial_sig_hash = tx_signer.sighash;
            let sig1 = origin_tx
                .sign_no_append_sponsor(&initial_sig_hash, &privk_1)
                .unwrap();
            let sig3 = origin_tx
                .sign_no_append_sponsor(&initial_sig_hash, &privk_3)
                .unwrap();

            let _ =
                origin_tx.append_sponsor_signature(sig1, TransactionPublicKeyEncoding::Compressed);
            let _ = origin_tx.append_next_sponsor(&pubk_2);
            let _ =
                origin_tx.append_sponsor_signature(sig3, TransactionPublicKeyEncoding::Compressed);

            tx.set_tx_fee(456);
            tx.set_sponsor_nonce(789).unwrap();

            check_oversign_origin_singlesig(&mut origin_tx);
            check_oversign_sponsor_multisig(&origin_tx);
            check_oversign_sponsor_multisig_uncompressed(&origin_tx);

            assert_eq!(origin_tx.auth().origin().num_signatures(), 1);
            assert_eq!(origin_tx.auth().sponsor().unwrap().num_signatures(), 2);

            // tx and origin_tx are otherwise equal
            assert_eq!(tx.version, origin_tx.version);
            assert_eq!(tx.chain_id, origin_tx.chain_id);
            assert_eq!(tx.get_tx_fee(), origin_tx.get_tx_fee());
            assert_eq!(tx.get_origin_nonce(), origin_tx.get_origin_nonce());
            assert_eq!(tx.get_sponsor_nonce(), origin_tx.get_sponsor_nonce());
            assert_eq!(tx.anchor_mode, origin_tx.anchor_mode);
            assert_eq!(tx.post_condition_mode, origin_tx.post_condition_mode);
            assert_eq!(tx.post_conditions, origin_tx.post_conditions);
            assert_eq!(tx.payload, origin_tx.payload);

            // auth is standard and first two auth fields are signatures for compressed keys.
            // third field is the third public key
            if let TransactionAuth::Sponsored(
                TransactionSpendingCondition::Singlesig(origin_data),
                TransactionSpendingCondition::OrderIndependentMultisig(sponsor_data),
            ) = &origin_tx.auth
            {
                assert_eq!(
                    origin_data.key_encoding,
                    TransactionPublicKeyEncoding::Compressed
                );
                assert_eq!(origin_data.signer, *origin_address.bytes());

                assert_eq!(sponsor_data.signer, *sponsor_address.bytes());
                assert_eq!(sponsor_data.fields.len(), 3);
                assert!(sponsor_data.fields[0].is_signature());
                assert!(sponsor_data.fields[1].is_public_key());
                assert!(sponsor_data.fields[2].is_signature());

                assert_eq!(
                    sponsor_data.fields[0].as_signature().unwrap().0,
                    TransactionPublicKeyEncoding::Compressed
                );
                assert_eq!(
                    sponsor_data.fields[2].as_signature().unwrap().0,
                    TransactionPublicKeyEncoding::Compressed
                );
                assert_eq!(sponsor_data.fields[1].as_public_key().unwrap(), pubk_2);
            } else {
                panic!("Unexpected auth condition");
            }

            test_signature_and_corruption(&origin_tx, true, false);
            test_signature_and_corruption(&origin_tx, false, true);
        }
    }

    #[test]
    fn tx_stacks_transaction_sign_verify_sponsored_order_independent_p2wsh_2_out_of_7() {
        let origin_privk = StacksPrivateKey::from_hex(
            "807bbe9e471ac976592cc35e3056592ecc0f778ee653fced3b491a122dd8d59701",
        )
        .unwrap();

        let privk_1 = StacksPrivateKey::from_hex(
            "6d430bb91222408e7706c9001cfaeb91b08c2be6d5ac95779ab52c6b431950e001",
        )
        .unwrap();
        let privk_2 = StacksPrivateKey::from_hex(
            "2a584d899fed1d24e26b524f202763c8ab30260167429f157f1c119f550fa6af01",
        )
        .unwrap();
        let privk_3 = StacksPrivateKey::from_hex(
            "d5200dee706ee53ae98a03fba6cf4fdcc5084c30cfa9e1b3462dcdeaa3e0f1d201",
        )
        .unwrap();
        let privk_4 = StacksPrivateKey::from_hex(
            "3beb8916404874f5d5de162c95470951de5b4a7f6ec8d7a20511551821f16db501",
        )
        .unwrap();
        let privk_5 = StacksPrivateKey::from_hex(
            "601aa0939e98efec29a4dc645377c9d4acaa0b7318444ec8fd7d090d0b36d85b01",
        )
        .unwrap();
        let privk_6 = StacksPrivateKey::from_hex(
            "5a4ca3db5a3b36bc32d9f2f0894435cbc4b2b1207e95ee283616d9a0797210da01",
        )
        .unwrap();
        let privk_7 = StacksPrivateKey::from_hex(
            "068856c242bfebdc57700fa598fae4e8ebb6b5f6bf932177018071489737d3ff01",
        )
        .unwrap();

        let pubk_1 = StacksPublicKey::from_private(&privk_1);
        let pubk_2 = StacksPublicKey::from_private(&privk_2);
        let pubk_3 = StacksPublicKey::from_private(&privk_3);
        let pubk_4 = StacksPublicKey::from_private(&privk_4);
        let pubk_5 = StacksPublicKey::from_private(&privk_5);
        let pubk_6 = StacksPublicKey::from_private(&privk_6);
        let pubk_7 = StacksPublicKey::from_private(&privk_7);

        let random_sponsor = StacksPrivateKey::random(); // what the origin sees

        let auth = TransactionAuth::Sponsored(
            TransactionSpendingCondition::new_singlesig_p2pkh(StacksPublicKey::from_private(
                &origin_privk,
            ))
            .unwrap(),
            TransactionSpendingCondition::new_singlesig_p2pkh(StacksPublicKey::from_private(
                &random_sponsor,
            ))
            .unwrap(),
        );

        let real_sponsor = TransactionSpendingCondition::new_multisig_order_independent_p2wsh(
            2,
            vec![
                pubk_1.clone(),
                pubk_2.clone(),
                pubk_3.clone(),
                pubk_4.clone(),
                pubk_5.clone(),
                pubk_6.clone(),
                pubk_7.clone(),
            ],
        )
        .unwrap();

        let origin_address = auth.origin().address_mainnet();
        let sponsor_address = real_sponsor.address_mainnet();

        assert_eq!(
            origin_address,
            StacksAddress::new(
                C32_ADDRESS_VERSION_MAINNET_SINGLESIG,
                Hash160::from_hex("3597aaa4bde720be93e3829aae24e76e7fcdfd3e").unwrap(),
            )
            .unwrap()
        );
        assert_eq!(
            sponsor_address,
            StacksAddress::new(
                C32_ADDRESS_VERSION_MAINNET_MULTISIG,
                Hash160::from_hex("e3001c2b12f24ba279116d7001e3bd82b2b5eab4").unwrap(),
            )
            .unwrap()
        );

        let txs = tx_stacks_transaction_test_txs(&auth);

        for mut tx in txs {
            assert_eq!(tx.auth().origin().num_signatures(), 0);
            assert_eq!(tx.auth().sponsor().unwrap().num_signatures(), 0);

            tx.set_tx_fee(123);
            tx.set_sponsor_nonce(456).unwrap();
            let mut tx_signer = StacksTransactionSigner::new(&tx);

            tx_signer.sign_origin(&origin_privk).unwrap();

            // sponsor sets and pays fee after origin signs
            let mut origin_tx = tx_signer.get_tx_incomplete();
            origin_tx.auth.set_sponsor(real_sponsor.clone()).unwrap();
            origin_tx.set_tx_fee(456);
            origin_tx.set_sponsor_nonce(789).unwrap();

            let initial_sig_hash = tx_signer.sighash;
            let sig1 = origin_tx
                .sign_no_append_sponsor(&initial_sig_hash, &privk_1)
                .unwrap();
            let sig7 = origin_tx
                .sign_no_append_sponsor(&initial_sig_hash, &privk_7)
                .unwrap();

            let _ =
                origin_tx.append_sponsor_signature(sig1, TransactionPublicKeyEncoding::Compressed);
            let _ = origin_tx.append_next_sponsor(&pubk_2);
            let _ = origin_tx.append_next_sponsor(&pubk_3);
            let _ = origin_tx.append_next_sponsor(&pubk_4);
            let _ = origin_tx.append_next_sponsor(&pubk_5);
            let _ = origin_tx.append_next_sponsor(&pubk_6);
            let _ =
                origin_tx.append_sponsor_signature(sig7, TransactionPublicKeyEncoding::Compressed);

            tx.set_tx_fee(456);
            tx.set_sponsor_nonce(789).unwrap();

            check_oversign_origin_singlesig(&mut origin_tx);
            check_oversign_sponsor_multisig(&origin_tx);
            check_oversign_sponsor_multisig_uncompressed(&origin_tx);

            assert_eq!(origin_tx.auth().origin().num_signatures(), 1);
            assert_eq!(origin_tx.auth().sponsor().unwrap().num_signatures(), 2);

            // tx and origin_tx are otherwise equal
            assert_eq!(tx.version, origin_tx.version);
            assert_eq!(tx.chain_id, origin_tx.chain_id);
            assert_eq!(tx.get_tx_fee(), origin_tx.get_tx_fee());
            assert_eq!(tx.get_origin_nonce(), origin_tx.get_origin_nonce());
            assert_eq!(tx.get_sponsor_nonce(), origin_tx.get_sponsor_nonce());
            assert_eq!(tx.anchor_mode, origin_tx.anchor_mode);
            assert_eq!(tx.post_condition_mode, origin_tx.post_condition_mode);
            assert_eq!(tx.post_conditions, origin_tx.post_conditions);
            assert_eq!(tx.payload, origin_tx.payload);

            // auth is standard and first two auth fields are signatures for compressed keys.
            // third field is the third public key
            if let TransactionAuth::Sponsored(
                TransactionSpendingCondition::Singlesig(origin_data),
                TransactionSpendingCondition::OrderIndependentMultisig(sponsor_data),
            ) = &origin_tx.auth
            {
                assert_eq!(
                    origin_data.key_encoding,
                    TransactionPublicKeyEncoding::Compressed
                );
                assert_eq!(origin_data.signer, *origin_address.bytes());

                assert_eq!(sponsor_data.signer, *sponsor_address.bytes());
                assert_eq!(sponsor_data.fields.len(), 7);
                assert!(sponsor_data.fields[0].is_signature());
                assert!(sponsor_data.fields[1].is_public_key());
                assert!(sponsor_data.fields[2].is_public_key());
                assert!(sponsor_data.fields[3].is_public_key());
                assert!(sponsor_data.fields[4].is_public_key());
                assert!(sponsor_data.fields[5].is_public_key());
                assert!(sponsor_data.fields[6].is_signature());

                assert_eq!(
                    sponsor_data.fields[0].as_signature().unwrap().0,
                    TransactionPublicKeyEncoding::Compressed
                );
                assert_eq!(
                    sponsor_data.fields[6].as_signature().unwrap().0,
                    TransactionPublicKeyEncoding::Compressed
                );
                assert_eq!(sponsor_data.fields[1].as_public_key().unwrap(), pubk_2);
                assert_eq!(sponsor_data.fields[2].as_public_key().unwrap(), pubk_3);
                assert_eq!(sponsor_data.fields[3].as_public_key().unwrap(), pubk_4);
                assert_eq!(sponsor_data.fields[4].as_public_key().unwrap(), pubk_5);
                assert_eq!(sponsor_data.fields[5].as_public_key().unwrap(), pubk_6);
            } else {
                panic!("Unexpected auth condition");
            }

            test_signature_and_corruption(&origin_tx, true, false);
            test_signature_and_corruption(&origin_tx, false, true);
        }
    }

    #[test]
    fn tx_stacks_transaction_sign_verify_standard_both_multisig_p2sh() {
        let privk_1 = StacksPrivateKey::from_hex(
            "6d430bb91222408e7706c9001cfaeb91b08c2be6d5ac95779ab52c6b431950e001",
        )
        .unwrap();
        let privk_2 = StacksPrivateKey::from_hex(
            "2a584d899fed1d24e26b524f202763c8ab30260167429f157f1c119f550fa6af01",
        )
        .unwrap();
        let privk_3 = StacksPrivateKey::from_hex(
            "d5200dee706ee53ae98a03fba6cf4fdcc5084c30cfa9e1b3462dcdeaa3e0f1d201",
        )
        .unwrap();

        let pubk_1 = StacksPublicKey::from_private(&privk_1);
        let pubk_2 = StacksPublicKey::from_private(&privk_2);
        let pubk_3 = StacksPublicKey::from_private(&privk_3);

        let origin_auth = TransactionAuth::Standard(
            TransactionSpendingCondition::new_multisig_p2sh(
                2,
                vec![pubk_1.clone(), pubk_2.clone(), pubk_3.clone()],
            )
            .unwrap(),
        );

        let order_independent_origin_auth = TransactionAuth::Standard(
            TransactionSpendingCondition::new_multisig_order_independent_p2sh(
                2,
                vec![pubk_1.clone(), pubk_2.clone(), pubk_3.clone()],
            )
            .unwrap(),
        );

        let origin_address = origin_auth.origin().address_mainnet();
        let order_independent_origin_address =
            order_independent_origin_auth.origin().address_mainnet();

        assert_eq!(origin_address, order_independent_origin_address);
        assert_eq!(
            origin_address,
            StacksAddress::new(
                C32_ADDRESS_VERSION_MAINNET_MULTISIG,
                Hash160::from_hex("a23ea89d6529ac48ac766f720e480beec7f19273").unwrap(),
            )
            .unwrap()
        );

        let txs = tx_stacks_transaction_test_txs(&origin_auth);
        let order_independent_txs = tx_stacks_transaction_test_txs(&order_independent_origin_auth);

        assert_eq!(txs.len(), order_independent_txs.len());

        for tx in txs {
            assert_eq!(tx.auth().origin().num_signatures(), 0);

            let mut tx_signer = StacksTransactionSigner::new(&tx);
            tx_signer.sign_origin(&privk_1).unwrap();
            tx_signer.sign_origin(&privk_2).unwrap();
            tx_signer.append_origin(&pubk_3).unwrap();
            let mut signed_tx = tx_signer.get_tx().unwrap();
            assert_eq!(signed_tx.auth().origin().num_signatures(), 2);

            check_oversign_origin_multisig(&signed_tx);
            check_sign_no_sponsor(&mut signed_tx);

            // tx and signed_tx are otherwise equal
            assert_eq!(tx.version, signed_tx.version);
            assert_eq!(tx.get_tx_fee(), signed_tx.get_tx_fee());
            assert_eq!(tx.get_origin_nonce(), signed_tx.get_origin_nonce());
            assert_eq!(tx.get_sponsor_nonce(), signed_tx.get_sponsor_nonce());
            assert_eq!(tx.anchor_mode, signed_tx.anchor_mode);
            assert_eq!(tx.post_condition_mode, signed_tx.post_condition_mode);
            assert_eq!(tx.post_conditions, signed_tx.post_conditions);
            assert_eq!(tx.payload, signed_tx.payload);

            if let TransactionAuth::Standard(TransactionSpendingCondition::Multisig(data)) =
                &signed_tx.auth
            {
                assert_eq!(data.signer, *origin_address.bytes());
                assert_eq!(data.fields.len(), 3);
                assert!(data.fields[0].is_signature());
                assert!(data.fields[1].is_signature());
                assert!(data.fields[2].is_public_key());

                assert_eq!(
                    data.fields[0].as_signature().unwrap().0,
                    TransactionPublicKeyEncoding::Compressed
                );
                assert_eq!(
                    data.fields[1].as_signature().unwrap().0,
                    TransactionPublicKeyEncoding::Compressed
                );
                assert_eq!(data.fields[2].as_public_key().unwrap(), pubk_3);
            } else {
                panic!("Unexpected auth condition");
            }

            test_signature_and_corruption(&signed_tx, true, false);
        }

        for mut order_independent_tx in order_independent_txs {
            assert_eq!(order_independent_tx.auth().origin().num_signatures(), 0);

            let order_independent_initial_sig_hash = order_independent_tx.sign_begin();
            let sig3 = order_independent_tx
                .sign_no_append_origin(&order_independent_initial_sig_hash, &privk_3)
                .unwrap();
            let sig2 = order_independent_tx
                .sign_no_append_origin(&order_independent_initial_sig_hash, &privk_2)
                .unwrap();

            let _ = order_independent_tx.append_next_origin(&pubk_1);
            let _ = order_independent_tx
                .append_origin_signature(sig2, TransactionPublicKeyEncoding::Compressed);
            let _ = order_independent_tx
                .append_origin_signature(sig3, TransactionPublicKeyEncoding::Compressed);

            check_oversign_origin_multisig(&order_independent_tx);
            check_sign_no_sponsor(&mut order_independent_tx);

            assert_eq!(order_independent_tx.auth().origin().num_signatures(), 2);

            if let TransactionAuth::Standard(
                TransactionSpendingCondition::OrderIndependentMultisig(data),
            ) = &order_independent_tx.auth
            {
                assert_eq!(data.signer, *origin_address.bytes());
                assert_eq!(data.fields.len(), 3);
                assert!(data.fields[0].is_public_key());
                assert!(data.fields[1].is_signature());
                assert!(data.fields[2].is_signature());

                assert_eq!(data.fields[0].as_public_key().unwrap(), pubk_1);
                assert_eq!(
                    data.fields[1].as_signature().unwrap().0,
                    TransactionPublicKeyEncoding::Compressed
                );
                assert_eq!(
                    data.fields[2].as_signature().unwrap().0,
                    TransactionPublicKeyEncoding::Compressed
                );
            } else {
                panic!("Unexpected auth condition");
            }

            test_signature_and_corruption(&order_independent_tx, true, false);
        }
    }

    #[test]
    fn tx_stacks_transaction_sign_verify_standard_both_multisig_p2sh_uncompressed() {
        let privk_1 = StacksPrivateKey::from_hex(
            "6d430bb91222408e7706c9001cfaeb91b08c2be6d5ac95779ab52c6b431950e0",
        )
        .unwrap();
        let privk_2 = StacksPrivateKey::from_hex(
            "2a584d899fed1d24e26b524f202763c8ab30260167429f157f1c119f550fa6af",
        )
        .unwrap();
        let privk_3 = StacksPrivateKey::from_hex(
            "d5200dee706ee53ae98a03fba6cf4fdcc5084c30cfa9e1b3462dcdeaa3e0f1d2",
        )
        .unwrap();

        let pubk_1 = StacksPublicKey::from_private(&privk_1);
        let pubk_2 = StacksPublicKey::from_private(&privk_2);
        let pubk_3 = StacksPublicKey::from_private(&privk_3);

        let origin_auth = TransactionAuth::Standard(
            TransactionSpendingCondition::new_multisig_p2sh(
                2,
                vec![pubk_1.clone(), pubk_2.clone(), pubk_3.clone()],
            )
            .unwrap(),
        );

        let order_independent_origin_auth = TransactionAuth::Standard(
            TransactionSpendingCondition::new_multisig_order_independent_p2sh(
                2,
                vec![pubk_1.clone(), pubk_2.clone(), pubk_3.clone()],
            )
            .unwrap(),
        );

        let origin_address = origin_auth.origin().address_mainnet();
        let order_independent_origin_address =
            order_independent_origin_auth.origin().address_mainnet();
        assert_eq!(origin_address, order_independent_origin_address);

        assert_eq!(
            origin_address,
            StacksAddress::new(
                C32_ADDRESS_VERSION_MAINNET_MULTISIG,
                Hash160::from_hex("73a8b4a751a678fe83e9d35ce301371bb3d397f7").unwrap(),
            )
            .unwrap()
        );

        let txs = tx_stacks_transaction_test_txs(&origin_auth);
        let order_independent_txs = tx_stacks_transaction_test_txs(&order_independent_origin_auth);

        assert_eq!(txs.len(), order_independent_txs.len());

        for tx in txs {
            assert_eq!(tx.auth().origin().num_signatures(), 0);

            let mut tx_signer = StacksTransactionSigner::new(&tx);

            tx_signer.sign_origin(&privk_1).unwrap();
            tx_signer.sign_origin(&privk_2).unwrap();
            tx_signer.append_origin(&pubk_3).unwrap();

            let mut signed_tx = tx_signer.get_tx().unwrap();

            check_oversign_origin_multisig(&signed_tx);
            check_sign_no_sponsor(&mut signed_tx);

            assert_eq!(signed_tx.auth().origin().num_signatures(), 2);

            // tx and signed_tx are otherwise equal
            assert_eq!(tx.version, signed_tx.version);
            assert_eq!(tx.chain_id, signed_tx.chain_id);
            assert_eq!(tx.get_tx_fee(), signed_tx.get_tx_fee());
            assert_eq!(tx.get_origin_nonce(), signed_tx.get_origin_nonce());
            assert_eq!(tx.get_sponsor_nonce(), signed_tx.get_sponsor_nonce());
            assert_eq!(tx.anchor_mode, signed_tx.anchor_mode);
            assert_eq!(tx.post_condition_mode, signed_tx.post_condition_mode);
            assert_eq!(tx.post_conditions, signed_tx.post_conditions);
            assert_eq!(tx.payload, signed_tx.payload);

            // auth is standard and first two auth fields are signatures for uncompressed keys.
            // third field is the third public key
            if let TransactionAuth::Standard(TransactionSpendingCondition::Multisig(data)) =
                &signed_tx.auth
            {
                assert_eq!(data.signer, *origin_address.bytes());
                assert_eq!(data.fields.len(), 3);
                assert!(data.fields[0].is_signature());
                assert!(data.fields[1].is_signature());
                assert!(data.fields[2].is_public_key());

                assert_eq!(
                    data.fields[0].as_signature().unwrap().0,
                    TransactionPublicKeyEncoding::Uncompressed
                );
                assert_eq!(
                    data.fields[1].as_signature().unwrap().0,
                    TransactionPublicKeyEncoding::Uncompressed
                );
                assert_eq!(data.fields[2].as_public_key().unwrap(), pubk_3);
            } else {
                panic!("Unexpected auth condition");
            }

            test_signature_and_corruption(&signed_tx, true, false);
        }

        for mut tx in order_independent_txs {
            assert_eq!(tx.auth().origin().num_signatures(), 0);

            let tx_signer = StacksTransactionSigner::new(&tx);

            let initial_sig_hash = tx.sign_begin();
            let sig3 = tx
                .sign_no_append_origin(&initial_sig_hash, &privk_3)
                .unwrap();
            let sig2 = tx
                .sign_no_append_origin(&initial_sig_hash, &privk_2)
                .unwrap();

            let _ = tx.append_next_origin(&pubk_1);
            tx.append_origin_signature(sig2, TransactionPublicKeyEncoding::Uncompressed);
            tx.append_origin_signature(sig3, TransactionPublicKeyEncoding::Uncompressed);

            check_oversign_origin_multisig(&tx);
            check_sign_no_sponsor(&mut tx);

            assert_eq!(tx.auth().origin().num_signatures(), 2);

            // auth is standard and first two auth fields are signatures for compressed keys.
            // third field is the third public key
            if let TransactionAuth::Standard(
                TransactionSpendingCondition::OrderIndependentMultisig(data),
            ) = &tx.auth
            {
                assert_eq!(data.signer, *origin_address.bytes());
                assert_eq!(data.fields.len(), 3);
                assert!(data.fields[0].is_public_key());
                assert!(data.fields[1].is_signature());
                assert!(data.fields[2].is_signature());

                assert_eq!(data.fields[0].as_public_key().unwrap(), pubk_1);
                assert_eq!(
                    data.fields[1].as_signature().unwrap().0,
                    TransactionPublicKeyEncoding::Uncompressed
                );
                assert_eq!(
                    data.fields[2].as_signature().unwrap().0,
                    TransactionPublicKeyEncoding::Uncompressed
                );
            } else {
                panic!("Unexpected auth condition");
            }

            test_signature_and_corruption(&tx, true, false);
        }
    }

    #[test]
    fn tx_stacks_transaction_sign_verify_standard_both_multisig_p2wsh() {
        let privk_1 = StacksPrivateKey::from_hex(
            "6d430bb91222408e7706c9001cfaeb91b08c2be6d5ac95779ab52c6b431950e001",
        )
        .unwrap();
        let privk_2 = StacksPrivateKey::from_hex(
            "2a584d899fed1d24e26b524f202763c8ab30260167429f157f1c119f550fa6af01",
        )
        .unwrap();
        let privk_3 = StacksPrivateKey::from_hex(
            "d5200dee706ee53ae98a03fba6cf4fdcc5084c30cfa9e1b3462dcdeaa3e0f1d201",
        )
        .unwrap();

        let pubk_1 = StacksPublicKey::from_private(&privk_1);
        let pubk_2 = StacksPublicKey::from_private(&privk_2);
        let pubk_3 = StacksPublicKey::from_private(&privk_3);

        let origin_auth = TransactionAuth::Standard(
            TransactionSpendingCondition::new_multisig_p2wsh(
                2,
                vec![pubk_1.clone(), pubk_2.clone(), pubk_3.clone()],
            )
            .unwrap(),
        );

        let order_independent_origin_auth = TransactionAuth::Standard(
            TransactionSpendingCondition::new_multisig_order_independent_p2wsh(
                2,
                vec![pubk_1.clone(), pubk_2.clone(), pubk_3.clone()],
            )
            .unwrap(),
        );

        let origin_address = origin_auth.origin().address_mainnet();
        let order_independent_origin_address =
            order_independent_origin_auth.origin().address_mainnet();
        assert_eq!(origin_address, order_independent_origin_address);

        assert_eq!(
            origin_address,
            StacksAddress::new(
                C32_ADDRESS_VERSION_MAINNET_MULTISIG,
                Hash160::from_hex("f5cfb61a07fb41a32197da01ce033888f0fe94a7").unwrap(),
            )
            .unwrap()
        );

        let txs = tx_stacks_transaction_test_txs(&origin_auth);
        let order_independent_txs = tx_stacks_transaction_test_txs(&order_independent_origin_auth);

        for tx in txs {
            assert_eq!(tx.auth().origin().num_signatures(), 0);

            let mut tx_signer = StacksTransactionSigner::new(&tx);
            tx_signer.sign_origin(&privk_1).unwrap();
            tx_signer.sign_origin(&privk_2).unwrap();
            tx_signer.append_origin(&pubk_3).unwrap();
            let mut signed_tx = tx_signer.get_tx().unwrap();

            check_oversign_origin_multisig(&signed_tx);
            check_oversign_origin_multisig_uncompressed(&signed_tx);
            check_sign_no_sponsor(&mut signed_tx);

            assert_eq!(signed_tx.auth().origin().num_signatures(), 2);

            // tx and signed_tx are otherwise equal
            assert_eq!(tx.version, signed_tx.version);
            assert_eq!(tx.get_tx_fee(), signed_tx.get_tx_fee());
            assert_eq!(tx.get_origin_nonce(), signed_tx.get_origin_nonce());
            assert_eq!(tx.get_sponsor_nonce(), signed_tx.get_sponsor_nonce());
            assert_eq!(tx.anchor_mode, signed_tx.anchor_mode);
            assert_eq!(tx.post_condition_mode, signed_tx.post_condition_mode);
            assert_eq!(tx.post_conditions, signed_tx.post_conditions);
            assert_eq!(tx.payload, signed_tx.payload);

            // auth is standard and first two auth fields are signatures for compressed keys.
            // third field is the third public key
            if let TransactionAuth::Standard(TransactionSpendingCondition::Multisig(data)) =
                &signed_tx.auth
            {
                assert_eq!(data.signer, *origin_address.bytes());
                assert_eq!(data.fields.len(), 3);
                assert!(data.fields[0].is_signature());
                assert!(data.fields[1].is_signature());
                assert!(data.fields[2].is_public_key());

                assert_eq!(
                    data.fields[0].as_signature().unwrap().0,
                    TransactionPublicKeyEncoding::Compressed
                );
                assert_eq!(
                    data.fields[1].as_signature().unwrap().0,
                    TransactionPublicKeyEncoding::Compressed
                );
                assert_eq!(data.fields[2].as_public_key().unwrap(), pubk_3);
            } else {
                panic!("Unexpected auth condition");
            }

            test_signature_and_corruption(&signed_tx, true, false);
        }

        for mut tx in order_independent_txs {
            assert_eq!(tx.auth().origin().num_signatures(), 0);

            let tx_signer = StacksTransactionSigner::new(&tx);

            let initial_sig_hash = tx.sign_begin();
            let sig3 = tx
                .sign_no_append_origin(&initial_sig_hash, &privk_3)
                .unwrap();
            let sig1 = tx
                .sign_no_append_origin(&initial_sig_hash, &privk_1)
                .unwrap();

            tx.append_origin_signature(sig1, TransactionPublicKeyEncoding::Compressed);
            let _ = tx.append_next_origin(&pubk_2);
            tx.append_origin_signature(sig3, TransactionPublicKeyEncoding::Compressed);

            check_oversign_origin_multisig(&tx);
            check_oversign_origin_multisig_uncompressed(&tx);
            check_sign_no_sponsor(&mut tx);

            assert_eq!(tx.auth().origin().num_signatures(), 2);

            // auth is standard and first two auth fields are signatures for compressed keys.
            // third field is the third public key
            if let TransactionAuth::Standard(
                TransactionSpendingCondition::OrderIndependentMultisig(data),
            ) = &tx.auth
            {
                assert_eq!(data.signer, *origin_address.bytes());
                assert_eq!(data.fields.len(), 3);
                assert!(data.fields[0].is_signature());
                assert!(data.fields[1].is_public_key());
                assert!(data.fields[2].is_signature());

                assert_eq!(data.fields[1].as_public_key().unwrap(), pubk_2);
                assert_eq!(
                    data.fields[0].as_signature().unwrap().0,
                    TransactionPublicKeyEncoding::Compressed
                );
                assert_eq!(
                    data.fields[2].as_signature().unwrap().0,
                    TransactionPublicKeyEncoding::Compressed
                );
            } else {
                panic!("Unexpected auth condition");
            }

            test_signature_and_corruption(&tx, true, false);
        }
    }

    #[test]
    fn tx_stacks_transaction_sign_verify_sponsored_both_multisig_p2sh() {
        let origin_privk = StacksPrivateKey::from_hex(
            "807bbe9e471ac976592cc35e3056592ecc0f778ee653fced3b491a122dd8d59701",
        )
        .unwrap();

        let privk_1 = StacksPrivateKey::from_hex(
            "6d430bb91222408e7706c9001cfaeb91b08c2be6d5ac95779ab52c6b431950e001",
        )
        .unwrap();
        let privk_2 = StacksPrivateKey::from_hex(
            "2a584d899fed1d24e26b524f202763c8ab30260167429f157f1c119f550fa6af01",
        )
        .unwrap();
        let privk_3 = StacksPrivateKey::from_hex(
            "d5200dee706ee53ae98a03fba6cf4fdcc5084c30cfa9e1b3462dcdeaa3e0f1d201",
        )
        .unwrap();

        let pubk_1 = StacksPublicKey::from_private(&privk_1);
        let pubk_2 = StacksPublicKey::from_private(&privk_2);
        let pubk_3 = StacksPublicKey::from_private(&privk_3);

        let random_sponsor = StacksPrivateKey::random(); // what the origin sees

        let auth = TransactionAuth::Sponsored(
            TransactionSpendingCondition::new_singlesig_p2pkh(StacksPublicKey::from_private(
                &origin_privk,
            ))
            .unwrap(),
            TransactionSpendingCondition::new_singlesig_p2pkh(StacksPublicKey::from_private(
                &random_sponsor,
            ))
            .unwrap(),
        );

        let real_sponsor = TransactionSpendingCondition::new_multisig_p2sh(
            2,
            vec![pubk_1.clone(), pubk_2.clone(), pubk_3.clone()],
        )
        .unwrap();

        let real_order_independent_sponsor =
            TransactionSpendingCondition::new_multisig_order_independent_p2sh(
                2,
                vec![pubk_1.clone(), pubk_2.clone(), pubk_3.clone()],
            )
            .unwrap();

        let origin_address = auth.origin().address_mainnet();
        let sponsor_address = real_sponsor.address_mainnet();
        let order_independent_sponsor_address = real_order_independent_sponsor.address_mainnet();

        assert_eq!(
            origin_address,
            StacksAddress::new(
                C32_ADDRESS_VERSION_MAINNET_SINGLESIG,
                Hash160::from_hex("3597aaa4bde720be93e3829aae24e76e7fcdfd3e").unwrap(),
            )
            .unwrap()
        );
        assert_eq!(sponsor_address, order_independent_sponsor_address);
        assert_eq!(
            sponsor_address,
            StacksAddress::new(
                C32_ADDRESS_VERSION_MAINNET_MULTISIG,
                Hash160::from_hex("a23ea89d6529ac48ac766f720e480beec7f19273").unwrap(),
            )
            .unwrap()
        );

        let txs = tx_stacks_transaction_test_txs(&auth);
        let order_independent_txs = tx_stacks_transaction_test_txs(&auth); // no difference

        for mut tx in txs {
            assert_eq!(tx.auth().origin().num_signatures(), 0);
            assert_eq!(tx.auth().sponsor().unwrap().num_signatures(), 0);

            tx.set_tx_fee(123);
            tx.set_sponsor_nonce(456).unwrap();
            let mut tx_signer = StacksTransactionSigner::new(&tx);

            tx_signer.sign_origin(&origin_privk).unwrap();

            // sponsor sets and pays fee after origin signs
            let mut origin_tx = tx_signer.get_tx_incomplete();
            origin_tx.auth.set_sponsor(real_sponsor.clone()).unwrap();
            origin_tx.set_tx_fee(456);
            origin_tx.set_sponsor_nonce(789).unwrap();
            tx_signer.resume(&origin_tx);

            tx_signer.sign_sponsor(&privk_1).unwrap();
            tx_signer.sign_sponsor(&privk_2).unwrap();
            tx_signer.append_sponsor(&pubk_3).unwrap();

            tx.set_tx_fee(456);
            tx.set_sponsor_nonce(789).unwrap();
            let mut signed_tx = tx_signer.get_tx().unwrap();

            check_oversign_origin_singlesig(&mut signed_tx);
            check_oversign_sponsor_multisig(&signed_tx);

            assert_eq!(signed_tx.auth().origin().num_signatures(), 1);
            assert_eq!(signed_tx.auth().sponsor().unwrap().num_signatures(), 2);

            // tx and signed_tx are otherwise equal
            assert_eq!(tx.version, signed_tx.version);
            assert_eq!(tx.chain_id, signed_tx.chain_id);
            assert_eq!(tx.get_tx_fee(), signed_tx.get_tx_fee());
            assert_eq!(tx.get_origin_nonce(), signed_tx.get_origin_nonce());
            assert_eq!(tx.get_sponsor_nonce(), signed_tx.get_sponsor_nonce());
            assert_eq!(tx.anchor_mode, signed_tx.anchor_mode);
            assert_eq!(tx.post_condition_mode, signed_tx.post_condition_mode);
            assert_eq!(tx.post_conditions, signed_tx.post_conditions);
            assert_eq!(tx.payload, signed_tx.payload);

            // auth is standard and first two auth fields are signatures for compressed keys.
            // third field is the third public key
            if let TransactionAuth::Sponsored(
                TransactionSpendingCondition::Singlesig(origin_data),
                TransactionSpendingCondition::Multisig(sponsor_data),
            ) = &signed_tx.auth
            {
                assert_eq!(
                    origin_data.key_encoding,
                    TransactionPublicKeyEncoding::Compressed
                );
                assert_eq!(origin_data.signer, *origin_address.bytes());

                assert_eq!(sponsor_data.signer, *sponsor_address.bytes());
                assert_eq!(sponsor_data.fields.len(), 3);
                assert!(sponsor_data.fields[0].is_signature());
                assert!(sponsor_data.fields[1].is_signature());
                assert!(sponsor_data.fields[2].is_public_key());

                assert_eq!(
                    sponsor_data.fields[0].as_signature().unwrap().0,
                    TransactionPublicKeyEncoding::Compressed
                );
                assert_eq!(
                    sponsor_data.fields[1].as_signature().unwrap().0,
                    TransactionPublicKeyEncoding::Compressed
                );
                assert_eq!(sponsor_data.fields[2].as_public_key().unwrap(), pubk_3);
            } else {
                panic!("Unexpected auth condition");
            }

            test_signature_and_corruption(&signed_tx, true, false);
            test_signature_and_corruption(&signed_tx, false, true);
        }

        for mut tx in order_independent_txs {
            assert_eq!(tx.auth().origin().num_signatures(), 0);
            assert_eq!(tx.auth().sponsor().unwrap().num_signatures(), 0);

            tx.set_tx_fee(123);
            tx.set_sponsor_nonce(456).unwrap();
            let mut tx_signer = StacksTransactionSigner::new(&tx);

            tx_signer.sign_origin(&origin_privk).unwrap();

            // sponsor sets and pays fee after origin signs
            let mut origin_tx = tx_signer.get_tx_incomplete();
            origin_tx
                .auth
                .set_sponsor(real_order_independent_sponsor.clone())
                .unwrap();
            origin_tx.set_tx_fee(456);
            origin_tx.set_sponsor_nonce(789).unwrap();

            let initial_sig_hash = tx_signer.sighash;
            let sig1 = origin_tx
                .sign_no_append_sponsor(&initial_sig_hash, &privk_1)
                .unwrap();
            let sig2 = origin_tx
                .sign_no_append_sponsor(&initial_sig_hash, &privk_2)
                .unwrap();

            let _ =
                origin_tx.append_sponsor_signature(sig1, TransactionPublicKeyEncoding::Compressed);
            let _ =
                origin_tx.append_sponsor_signature(sig2, TransactionPublicKeyEncoding::Compressed);
            let _ = origin_tx.append_next_sponsor(&pubk_3);

            tx.set_tx_fee(456);
            tx.set_sponsor_nonce(789).unwrap();

            check_oversign_origin_singlesig(&mut origin_tx);
            check_oversign_sponsor_multisig(&origin_tx);

            assert_eq!(origin_tx.auth().origin().num_signatures(), 1);
            assert_eq!(origin_tx.auth().sponsor().unwrap().num_signatures(), 2);

            // tx and origin_tx are otherwise equal
            assert_eq!(tx.version, origin_tx.version);
            assert_eq!(tx.chain_id, origin_tx.chain_id);
            assert_eq!(tx.get_tx_fee(), origin_tx.get_tx_fee());
            assert_eq!(tx.get_origin_nonce(), origin_tx.get_origin_nonce());
            assert_eq!(tx.get_sponsor_nonce(), origin_tx.get_sponsor_nonce());
            assert_eq!(tx.anchor_mode, origin_tx.anchor_mode);
            assert_eq!(tx.post_condition_mode, origin_tx.post_condition_mode);
            assert_eq!(tx.post_conditions, origin_tx.post_conditions);
            assert_eq!(tx.payload, origin_tx.payload);

            // auth is standard and first two auth fields are signatures for compressed keys.
            // third field is the third public key
            if let TransactionAuth::Sponsored(
                TransactionSpendingCondition::Singlesig(origin_data),
                TransactionSpendingCondition::OrderIndependentMultisig(sponsor_data),
            ) = &origin_tx.auth
            {
                assert_eq!(
                    origin_data.key_encoding,
                    TransactionPublicKeyEncoding::Compressed
                );
                assert_eq!(origin_data.signer, *origin_address.bytes());

                assert_eq!(sponsor_data.signer, *sponsor_address.bytes());
                assert_eq!(sponsor_data.fields.len(), 3);
                assert!(sponsor_data.fields[0].is_signature());
                assert!(sponsor_data.fields[1].is_signature());
                assert!(sponsor_data.fields[2].is_public_key());

                assert_eq!(
                    sponsor_data.fields[0].as_signature().unwrap().0,
                    TransactionPublicKeyEncoding::Compressed
                );
                assert_eq!(
                    sponsor_data.fields[1].as_signature().unwrap().0,
                    TransactionPublicKeyEncoding::Compressed
                );
                assert_eq!(sponsor_data.fields[2].as_public_key().unwrap(), pubk_3);
            } else {
                panic!("Unexpected auth condition");
            }

            test_signature_and_corruption(&origin_tx, true, false);
            test_signature_and_corruption(&origin_tx, false, true);
        }
    }

    #[test]
    fn tx_stacks_transaction_sign_verify_sponsored_both_multisig_p2sh_uncompressed() {
        let origin_privk = StacksPrivateKey::from_hex(
            "807bbe9e471ac976592cc35e3056592ecc0f778ee653fced3b491a122dd8d59701",
        )
        .unwrap();

        let privk_1 = StacksPrivateKey::from_hex(
            "6d430bb91222408e7706c9001cfaeb91b08c2be6d5ac95779ab52c6b431950e0",
        )
        .unwrap();
        let privk_2 = StacksPrivateKey::from_hex(
            "2a584d899fed1d24e26b524f202763c8ab30260167429f157f1c119f550fa6af",
        )
        .unwrap();
        let privk_3 = StacksPrivateKey::from_hex(
            "d5200dee706ee53ae98a03fba6cf4fdcc5084c30cfa9e1b3462dcdeaa3e0f1d2",
        )
        .unwrap();

        let pubk_1 = StacksPublicKey::from_private(&privk_1);
        let pubk_2 = StacksPublicKey::from_private(&privk_2);
        let pubk_3 = StacksPublicKey::from_private(&privk_3);

        let random_sponsor = StacksPrivateKey::random(); // what the origin sees

        let auth = TransactionAuth::Sponsored(
            TransactionSpendingCondition::new_singlesig_p2pkh(StacksPublicKey::from_private(
                &origin_privk,
            ))
            .unwrap(),
            TransactionSpendingCondition::new_singlesig_p2pkh(StacksPublicKey::from_private(
                &random_sponsor,
            ))
            .unwrap(),
        );

        let real_sponsor = TransactionSpendingCondition::new_multisig_order_independent_p2sh(
            2,
            vec![pubk_1.clone(), pubk_2.clone(), pubk_3.clone()],
        )
        .unwrap();

        let real_order_independent_sponsor =
            TransactionSpendingCondition::new_multisig_order_independent_p2sh(
                2,
                vec![pubk_1.clone(), pubk_2.clone(), pubk_3.clone()],
            )
            .unwrap();

        let origin_address = auth.origin().address_mainnet();
        let sponsor_address = real_sponsor.address_mainnet();
        let order_independent_sponsor_address = real_order_independent_sponsor.address_mainnet();

        assert_eq!(
            origin_address,
            StacksAddress::new(
                C32_ADDRESS_VERSION_MAINNET_SINGLESIG,
                Hash160::from_hex("3597aaa4bde720be93e3829aae24e76e7fcdfd3e").unwrap(),
            )
            .unwrap()
        );
        assert_eq!(sponsor_address, order_independent_sponsor_address);

        assert_eq!(
            sponsor_address,
            StacksAddress::new(
                C32_ADDRESS_VERSION_MAINNET_MULTISIG,
                Hash160::from_hex("73a8b4a751a678fe83e9d35ce301371bb3d397f7").unwrap(),
            )
            .unwrap()
        );

        let txs = tx_stacks_transaction_test_txs(&auth);
        let order_independent_txs = tx_stacks_transaction_test_txs(&auth); // no difference

        for mut tx in txs {
            assert_eq!(tx.auth().origin().num_signatures(), 0);
            assert_eq!(tx.auth().sponsor().unwrap().num_signatures(), 0);

            tx.set_tx_fee(123);
            tx.set_sponsor_nonce(456).unwrap();
            let mut tx_signer = StacksTransactionSigner::new(&tx);

            tx_signer.sign_origin(&origin_privk).unwrap();

            // sponsor sets and pays fee after origin signs
            let mut origin_tx = tx_signer.get_tx_incomplete();
            origin_tx.auth.set_sponsor(real_sponsor.clone()).unwrap();
            origin_tx.set_tx_fee(456);
            origin_tx.set_sponsor_nonce(789).unwrap();

            let initial_sig_hash = tx_signer.sighash;
            let sig1 = origin_tx
                .sign_no_append_sponsor(&initial_sig_hash, &privk_1)
                .unwrap();
            let sig2 = origin_tx
                .sign_no_append_sponsor(&initial_sig_hash, &privk_2)
                .unwrap();

            let _ = origin_tx
                .append_sponsor_signature(sig1, TransactionPublicKeyEncoding::Uncompressed);
            let _ = origin_tx
                .append_sponsor_signature(sig2, TransactionPublicKeyEncoding::Uncompressed);
            let _ = origin_tx.append_next_sponsor(&pubk_3);

            tx.set_tx_fee(456);
            tx.set_sponsor_nonce(789).unwrap();

            check_oversign_origin_singlesig(&mut origin_tx);
            check_oversign_sponsor_multisig(&origin_tx);

            assert_eq!(origin_tx.auth().origin().num_signatures(), 1);
            assert_eq!(origin_tx.auth().sponsor().unwrap().num_signatures(), 2);

            // tx and origin_tx are otherwise equal
            assert_eq!(tx.version, origin_tx.version);
            assert_eq!(tx.chain_id, origin_tx.chain_id);
            assert_eq!(tx.get_tx_fee(), origin_tx.get_tx_fee());
            assert_eq!(tx.get_origin_nonce(), origin_tx.get_origin_nonce());
            assert_eq!(tx.get_sponsor_nonce(), origin_tx.get_sponsor_nonce());
            assert_eq!(tx.anchor_mode, origin_tx.anchor_mode);
            assert_eq!(tx.post_condition_mode, origin_tx.post_condition_mode);
            assert_eq!(tx.post_conditions, origin_tx.post_conditions);
            assert_eq!(tx.payload, origin_tx.payload);

            // auth is standard and first two auth fields are signatures for compressed keys.
            // third field is the third public key
            if let TransactionAuth::Sponsored(
                TransactionSpendingCondition::Singlesig(origin_data),
                TransactionSpendingCondition::OrderIndependentMultisig(sponsor_data),
            ) = &origin_tx.auth
            {
                assert_eq!(
                    origin_data.key_encoding,
                    TransactionPublicKeyEncoding::Compressed
                );
                assert_eq!(origin_data.signer, *origin_address.bytes());

                assert_eq!(sponsor_data.signer, *sponsor_address.bytes());
                assert_eq!(sponsor_data.fields.len(), 3);
                assert!(sponsor_data.fields[0].is_signature());
                assert!(sponsor_data.fields[1].is_signature());
                assert!(sponsor_data.fields[2].is_public_key());

                assert_eq!(
                    sponsor_data.fields[0].as_signature().unwrap().0,
                    TransactionPublicKeyEncoding::Uncompressed
                );
                assert_eq!(
                    sponsor_data.fields[1].as_signature().unwrap().0,
                    TransactionPublicKeyEncoding::Uncompressed
                );
                assert_eq!(sponsor_data.fields[2].as_public_key().unwrap(), pubk_3);
            } else {
                panic!("Unexpected auth condition");
            }

            test_signature_and_corruption(&origin_tx, true, false);
            test_signature_and_corruption(&origin_tx, false, true);
        }

        for mut tx in order_independent_txs {
            assert_eq!(tx.auth().origin().num_signatures(), 0);
            assert_eq!(tx.auth().sponsor().unwrap().num_signatures(), 0);

            tx.set_tx_fee(123);
            tx.set_sponsor_nonce(456).unwrap();
            let mut tx_signer = StacksTransactionSigner::new(&tx);

            tx_signer.sign_origin(&origin_privk).unwrap();

            // sponsor sets and pays fee after origin signs
            let mut origin_tx = tx_signer.get_tx_incomplete();
            origin_tx
                .auth
                .set_sponsor(real_order_independent_sponsor.clone())
                .unwrap();
            origin_tx.set_tx_fee(456);
            origin_tx.set_sponsor_nonce(789).unwrap();

            let initial_sig_hash = tx_signer.sighash;
            let sig1 = origin_tx
                .sign_no_append_sponsor(&initial_sig_hash, &privk_1)
                .unwrap();
            let sig2 = origin_tx
                .sign_no_append_sponsor(&initial_sig_hash, &privk_2)
                .unwrap();

            let _ = origin_tx
                .append_sponsor_signature(sig1, TransactionPublicKeyEncoding::Uncompressed);
            let _ = origin_tx
                .append_sponsor_signature(sig2, TransactionPublicKeyEncoding::Uncompressed);
            let _ = origin_tx.append_next_sponsor(&pubk_3);

            tx.set_tx_fee(456);
            tx.set_sponsor_nonce(789).unwrap();

            check_oversign_origin_singlesig(&mut origin_tx);
            check_oversign_sponsor_multisig(&origin_tx);

            assert_eq!(origin_tx.auth().origin().num_signatures(), 1);
            assert_eq!(origin_tx.auth().sponsor().unwrap().num_signatures(), 2);

            // tx and origin_tx are otherwise equal
            assert_eq!(tx.version, origin_tx.version);
            assert_eq!(tx.chain_id, origin_tx.chain_id);
            assert_eq!(tx.get_tx_fee(), origin_tx.get_tx_fee());
            assert_eq!(tx.get_origin_nonce(), origin_tx.get_origin_nonce());
            assert_eq!(tx.get_sponsor_nonce(), origin_tx.get_sponsor_nonce());
            assert_eq!(tx.anchor_mode, origin_tx.anchor_mode);
            assert_eq!(tx.post_condition_mode, origin_tx.post_condition_mode);
            assert_eq!(tx.post_conditions, origin_tx.post_conditions);
            assert_eq!(tx.payload, origin_tx.payload);

            // auth is standard and first two auth fields are signatures for compressed keys.
            // third field is the third public key
            if let TransactionAuth::Sponsored(
                TransactionSpendingCondition::Singlesig(origin_data),
                TransactionSpendingCondition::OrderIndependentMultisig(sponsor_data),
            ) = &origin_tx.auth
            {
                assert_eq!(
                    origin_data.key_encoding,
                    TransactionPublicKeyEncoding::Compressed
                );
                assert_eq!(origin_data.signer, *origin_address.bytes());

                assert_eq!(sponsor_data.signer, *sponsor_address.bytes());
                assert_eq!(sponsor_data.fields.len(), 3);
                assert!(sponsor_data.fields[0].is_signature());
                assert!(sponsor_data.fields[1].is_signature());
                assert!(sponsor_data.fields[2].is_public_key());

                assert_eq!(
                    sponsor_data.fields[0].as_signature().unwrap().0,
                    TransactionPublicKeyEncoding::Uncompressed
                );
                assert_eq!(
                    sponsor_data.fields[1].as_signature().unwrap().0,
                    TransactionPublicKeyEncoding::Uncompressed
                );
                assert_eq!(sponsor_data.fields[2].as_public_key().unwrap(), pubk_3);
            } else {
                panic!("Unexpected auth condition");
            }

            test_signature_and_corruption(&origin_tx, true, false);
            test_signature_and_corruption(&origin_tx, false, true);
        }
    }

    #[test]
    fn tx_stacks_transaction_sign_verify_sponsored_both_multisig_p2wsh() {
        let origin_privk = StacksPrivateKey::from_hex(
            "807bbe9e471ac976592cc35e3056592ecc0f778ee653fced3b491a122dd8d59701",
        )
        .unwrap();

        let privk_1 = StacksPrivateKey::from_hex(
            "6d430bb91222408e7706c9001cfaeb91b08c2be6d5ac95779ab52c6b431950e001",
        )
        .unwrap();
        let privk_2 = StacksPrivateKey::from_hex(
            "2a584d899fed1d24e26b524f202763c8ab30260167429f157f1c119f550fa6af01",
        )
        .unwrap();
        let privk_3 = StacksPrivateKey::from_hex(
            "d5200dee706ee53ae98a03fba6cf4fdcc5084c30cfa9e1b3462dcdeaa3e0f1d201",
        )
        .unwrap();

        let pubk_1 = StacksPublicKey::from_private(&privk_1);
        let pubk_2 = StacksPublicKey::from_private(&privk_2);
        let pubk_3 = StacksPublicKey::from_private(&privk_3);

        let random_sponsor = StacksPrivateKey::random(); // what the origin sees

        let auth = TransactionAuth::Sponsored(
            TransactionSpendingCondition::new_singlesig_p2pkh(StacksPublicKey::from_private(
                &origin_privk,
            ))
            .unwrap(),
            TransactionSpendingCondition::new_singlesig_p2pkh(StacksPublicKey::from_private(
                &random_sponsor,
            ))
            .unwrap(),
        );

        let real_sponsor = TransactionSpendingCondition::new_multisig_p2wsh(
            2,
            vec![pubk_1.clone(), pubk_2.clone(), pubk_3.clone()],
        )
        .unwrap();

        let real_order_independent_sponsor =
            TransactionSpendingCondition::new_multisig_order_independent_p2wsh(
                2,
                vec![pubk_1.clone(), pubk_2.clone(), pubk_3.clone()],
            )
            .unwrap();

        let origin_address = auth.origin().address_mainnet();
        let sponsor_address = real_sponsor.address_mainnet();
        let order_independent_sponsor_address = real_order_independent_sponsor.address_mainnet();

        assert_eq!(
            origin_address,
            StacksAddress::new(
                C32_ADDRESS_VERSION_MAINNET_SINGLESIG,
                Hash160::from_hex("3597aaa4bde720be93e3829aae24e76e7fcdfd3e").unwrap(),
            )
            .unwrap()
        );
        assert_eq!(sponsor_address, order_independent_sponsor_address);

        assert_eq!(
            sponsor_address,
            StacksAddress::new(
                C32_ADDRESS_VERSION_MAINNET_MULTISIG,
                Hash160::from_hex("f5cfb61a07fb41a32197da01ce033888f0fe94a7").unwrap(),
            )
            .unwrap()
        );

        let txs = tx_stacks_transaction_test_txs(&auth);
        let order_independent_txs = tx_stacks_transaction_test_txs(&auth); // no difference

        for mut tx in txs {
            assert_eq!(tx.auth().origin().num_signatures(), 0);
            assert_eq!(tx.auth().sponsor().unwrap().num_signatures(), 0);

            tx.set_tx_fee(123);
            tx.set_sponsor_nonce(456).unwrap();
            let mut tx_signer = StacksTransactionSigner::new(&tx);

            tx_signer.sign_origin(&origin_privk).unwrap();

            // sponsor sets and pays fee after origin signs
            let mut origin_tx = tx_signer.get_tx_incomplete();
            origin_tx.auth.set_sponsor(real_sponsor.clone()).unwrap();
            origin_tx.set_tx_fee(456);
            origin_tx.set_sponsor_nonce(789).unwrap();
            tx_signer.resume(&origin_tx);

            tx_signer.sign_sponsor(&privk_1).unwrap();
            tx_signer.sign_sponsor(&privk_2).unwrap();
            tx_signer.append_sponsor(&pubk_3).unwrap();

            tx.set_tx_fee(456);
            tx.set_sponsor_nonce(789).unwrap();
            let mut signed_tx = tx_signer.get_tx().unwrap();

            check_oversign_origin_singlesig(&mut signed_tx);
            check_oversign_sponsor_multisig(&signed_tx);
            check_oversign_sponsor_multisig_uncompressed(&signed_tx);

            assert_eq!(signed_tx.auth().origin().num_signatures(), 1);
            assert_eq!(signed_tx.auth().sponsor().unwrap().num_signatures(), 2);

            // tx and signed_tx are otherwise equal
            assert_eq!(tx.version, signed_tx.version);
            assert_eq!(tx.chain_id, signed_tx.chain_id);
            assert_eq!(tx.get_tx_fee(), signed_tx.get_tx_fee());
            assert_eq!(tx.get_origin_nonce(), signed_tx.get_origin_nonce());
            assert_eq!(tx.get_sponsor_nonce(), signed_tx.get_sponsor_nonce());
            assert_eq!(tx.anchor_mode, signed_tx.anchor_mode);
            assert_eq!(tx.post_condition_mode, signed_tx.post_condition_mode);
            assert_eq!(tx.post_conditions, signed_tx.post_conditions);
            assert_eq!(tx.payload, signed_tx.payload);

            // auth is standard and first two auth fields are signatures for compressed keys.
            // third field is the third public key
            if let TransactionAuth::Sponsored(
                TransactionSpendingCondition::Singlesig(origin_data),
                TransactionSpendingCondition::Multisig(sponsor_data),
            ) = &signed_tx.auth
            {
                assert_eq!(
                    origin_data.key_encoding,
                    TransactionPublicKeyEncoding::Compressed
                );
                assert_eq!(origin_data.signer, *origin_address.bytes());

                assert_eq!(sponsor_data.signer, *sponsor_address.bytes());
                assert_eq!(sponsor_data.fields.len(), 3);
                assert!(sponsor_data.fields[0].is_signature());
                assert!(sponsor_data.fields[1].is_signature());
                assert!(sponsor_data.fields[2].is_public_key());

                assert_eq!(
                    sponsor_data.fields[0].as_signature().unwrap().0,
                    TransactionPublicKeyEncoding::Compressed
                );
                assert_eq!(
                    sponsor_data.fields[1].as_signature().unwrap().0,
                    TransactionPublicKeyEncoding::Compressed
                );
                assert_eq!(sponsor_data.fields[2].as_public_key().unwrap(), pubk_3);
            } else {
                panic!("Unexpected auth condition");
            }

            test_signature_and_corruption(&signed_tx, true, false);
            test_signature_and_corruption(&signed_tx, false, true);
        }

        for mut tx in order_independent_txs {
            assert_eq!(tx.auth().origin().num_signatures(), 0);
            assert_eq!(tx.auth().sponsor().unwrap().num_signatures(), 0);

            tx.set_tx_fee(123);
            tx.set_sponsor_nonce(456).unwrap();
            let mut tx_signer = StacksTransactionSigner::new(&tx);

            tx_signer.sign_origin(&origin_privk).unwrap();

            // sponsor sets and pays fee after origin signs
            let mut origin_tx = tx_signer.get_tx_incomplete();
            origin_tx
                .auth
                .set_sponsor(real_order_independent_sponsor.clone())
                .unwrap();
            origin_tx.set_tx_fee(456);
            origin_tx.set_sponsor_nonce(789).unwrap();

            let initial_sig_hash = tx_signer.sighash;
            let sig1 = origin_tx
                .sign_no_append_sponsor(&initial_sig_hash, &privk_1)
                .unwrap();
            let sig3 = origin_tx
                .sign_no_append_sponsor(&initial_sig_hash, &privk_3)
                .unwrap();

            let _ =
                origin_tx.append_sponsor_signature(sig1, TransactionPublicKeyEncoding::Compressed);
            let _ = origin_tx.append_next_sponsor(&pubk_2);
            let _ =
                origin_tx.append_sponsor_signature(sig3, TransactionPublicKeyEncoding::Compressed);

            tx.set_tx_fee(456);
            tx.set_sponsor_nonce(789).unwrap();

            check_oversign_origin_singlesig(&mut origin_tx);
            check_oversign_sponsor_multisig(&origin_tx);
            check_oversign_sponsor_multisig_uncompressed(&origin_tx);

            assert_eq!(origin_tx.auth().origin().num_signatures(), 1);
            assert_eq!(origin_tx.auth().sponsor().unwrap().num_signatures(), 2);

            // tx and origin_tx are otherwise equal
            assert_eq!(tx.version, origin_tx.version);
            assert_eq!(tx.chain_id, origin_tx.chain_id);
            assert_eq!(tx.get_tx_fee(), origin_tx.get_tx_fee());
            assert_eq!(tx.get_origin_nonce(), origin_tx.get_origin_nonce());
            assert_eq!(tx.get_sponsor_nonce(), origin_tx.get_sponsor_nonce());
            assert_eq!(tx.anchor_mode, origin_tx.anchor_mode);
            assert_eq!(tx.post_condition_mode, origin_tx.post_condition_mode);
            assert_eq!(tx.post_conditions, origin_tx.post_conditions);
            assert_eq!(tx.payload, origin_tx.payload);

            // auth is standard and first two auth fields are signatures for compressed keys.
            // third field is the third public key
            if let TransactionAuth::Sponsored(
                TransactionSpendingCondition::Singlesig(origin_data),
                TransactionSpendingCondition::OrderIndependentMultisig(sponsor_data),
            ) = &origin_tx.auth
            {
                assert_eq!(
                    origin_data.key_encoding,
                    TransactionPublicKeyEncoding::Compressed
                );
                assert_eq!(origin_data.signer, *origin_address.bytes());

                assert_eq!(sponsor_data.signer, *sponsor_address.bytes());
                assert_eq!(sponsor_data.fields.len(), 3);
                assert!(sponsor_data.fields[0].is_signature());
                assert!(sponsor_data.fields[1].is_public_key());
                assert!(sponsor_data.fields[2].is_signature());

                assert_eq!(
                    sponsor_data.fields[0].as_signature().unwrap().0,
                    TransactionPublicKeyEncoding::Compressed
                );
                assert_eq!(
                    sponsor_data.fields[2].as_signature().unwrap().0,
                    TransactionPublicKeyEncoding::Compressed
                );
                assert_eq!(sponsor_data.fields[1].as_public_key().unwrap(), pubk_2);
            } else {
                panic!("Unexpected auth condition");
            }

            test_signature_and_corruption(&origin_tx, true, false);
            test_signature_and_corruption(&origin_tx, false, true);
        }
    }
}
