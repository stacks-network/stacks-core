// Copyright (C) 2026 Stacks Open Internet Foundation
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

//! Unit tests for the Epoch 4.1 contract-name length limit on transaction
//! fields. The block-pipeline tests that exercise it through the node stay in
//! `stackslib`.

use clarity_types::types::{PrincipalData, QualifiedContractIdentifier, StandardPrincipalData};
use clarity_types::{ClarityName, ContractName, Value};
use stacks_codec::transaction::{
    AssetInfo, CoinbasePayload, NonfungibleConditionCode, PostConditionPrincipal,
    TokenTransferMemo, TransactionContractCall, TransactionPayload, TransactionPostCondition,
};
use stacks_common::types::StacksEpochId;
use stacks_common::types::chainstate::StacksAddress;
use stacks_common::util::hash::Hash160;

use crate::{OverlongContractName, check_contract_names_supported_in_epoch};

type MakePayload = fn(usize) -> TransactionPayload;

fn contract_principal(name_len: usize) -> PrincipalData {
    PrincipalData::Contract(QualifiedContractIdentifier::new(
        StandardPrincipalData::transient(),
        ContractName::try_from("a".repeat(name_len)).unwrap(),
    ))
}

fn token_transfer(name_len: usize) -> TransactionPayload {
    TransactionPayload::TokenTransfer(contract_principal(name_len), 1, TokenTransferMemo([0; 34]))
}

fn contract_call(name_len: usize) -> TransactionPayload {
    TransactionPayload::ContractCall(TransactionContractCall {
        address: StacksAddress::new(1, Hash160([0x01; 20])).unwrap(),
        contract_name: ContractName::from_literal("target"),
        function_name: ClarityName::from_literal("take"),
        function_args: vec![
            Value::UInt(1),
            Value::some(Value::Principal(contract_principal(name_len))).unwrap(),
        ],
    })
}

fn coinbase(name_len: usize) -> TransactionPayload {
    TransactionPayload::Coinbase(
        CoinbasePayload([0; 32]),
        Some(contract_principal(name_len)),
        None,
    )
}

fn nft_post_condition(name_len: usize) -> TransactionPostCondition {
    TransactionPostCondition::Nonfungible(
        PostConditionPrincipal::Origin,
        AssetInfo {
            contract_address: StacksAddress::new(1, Hash160([0x01; 20])).unwrap(),
            contract_name: ContractName::from_literal("nft"),
            asset_name: ClarityName::from_literal("token"),
        },
        Value::Principal(contract_principal(name_len)),
        NonfungibleConditionCode::Sent,
    )
}

/// Every field that can carry a 128-byte name through the codec is rejected from
/// Epoch 4.1 when the name exceeds 40 bytes, and accepted before 4.1 or at 40.
#[test]
fn test_check_contract_names_supported_in_epoch() {
    use OverlongContractName::*;

    let payload_cases: [(MakePayload, OverlongContractName); 3] = [
        (token_transfer, TokenTransferRecipient),
        (contract_call, ContractCallArgument),
        (coinbase, CoinbaseRecipient),
    ];
    for (make_payload, field) in payload_cases {
        for epoch in [StacksEpochId::Epoch40, StacksEpochId::Epoch41] {
            assert_eq!(
                Ok(()),
                check_contract_names_supported_in_epoch(&make_payload(40), &[], epoch),
                "{field:?} with a 40-byte name at {epoch}"
            );
        }
        assert_eq!(
            Ok(()),
            check_contract_names_supported_in_epoch(&make_payload(41), &[], StacksEpochId::Epoch40),
            "{field:?} with a 41-byte name at 4.0"
        );
        assert_eq!(
            Err(field),
            check_contract_names_supported_in_epoch(&make_payload(41), &[], StacksEpochId::Epoch41),
            "{field:?} with a 41-byte name at 4.1"
        );
    }

    let payload = contract_call(40);
    for epoch in [StacksEpochId::Epoch40, StacksEpochId::Epoch41] {
        assert_eq!(
            Ok(()),
            check_contract_names_supported_in_epoch(&payload, &[nft_post_condition(40)], epoch)
        );
    }
    assert_eq!(
        Ok(()),
        check_contract_names_supported_in_epoch(
            &payload,
            &[nft_post_condition(41)],
            StacksEpochId::Epoch40
        )
    );
    assert_eq!(
        Err(NonfungiblePostCondition),
        check_contract_names_supported_in_epoch(
            &payload,
            &[nft_post_condition(41)],
            StacksEpochId::Epoch41
        )
    );
}
