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

//! Unit tests for transaction-level post-condition checking
//! ([`crate::vm::post_conditions::check_transaction_postconditions`]).
//!
//! These cover the checker in isolation: a hand-built [`AssetMap`] plus a list
//! of post-conditions, asserting pass/fail per condition code, per post-condition
//! mode, and per epoch gate. The full `process_transaction` pipeline tests that
//! exercise the checker through the node (fee handling, receipts, rollback) stay
//! in `stackslib::chainstate::stacks::db::transactions`.
//!
//! Not to be confused with [`crate::vm::tests::post_conditions`], which tests the
//! *in-language* SIP-040 allowances (`restrict-assets?` / `as-contract?`).

use clarity_types::types::{
    AssetIdentifier, QualifiedContractIdentifier, StacksAddressExtensions, StandardPrincipalData,
};
use clarity_types::{ClarityName, ContractName, Value};
use pinny::tag;
use proptest::prelude::*;
use stacks_codec::transaction::{
    AssetInfo, FungibleConditionCode, NonfungibleConditionCode, PostConditionPrincipal,
    PoxConditionCode, TransactionAuth, TransactionPostCondition, TransactionPostConditionMode,
};
use stacks_common::types::StacksEpochId;
use stacks_common::types::chainstate::{StacksAddress, StacksPrivateKey, Txid};
use stacks_common::util::hash::Hash160;

use crate::vm::contexts::AssetMap;
use crate::vm::post_conditions::check_transaction_postconditions;

#[test]
fn test_check_postconditions_multiple_fts() {
    let privk = StacksPrivateKey::from_hex(
        "6d430bb91222408e7706c9001cfaeb91b08c2be6d5ac95779ab52c6b431950e001",
    )
    .unwrap();
    let auth = TransactionAuth::from_p2pkh(&privk).unwrap();
    let addr = auth.origin().address_testnet();
    let origin = addr.to_account_principal();
    let recv_addr = StacksAddress::new(1, Hash160([0xff; 20])).unwrap();
    let contract_addr = StacksAddress::new(1, Hash160([0x01; 20])).unwrap();

    let asset_info_1 = AssetInfo {
        contract_address: contract_addr.clone(),
        contract_name: ContractName::try_from("hello-world").unwrap(),
        asset_name: ClarityName::try_from("test-asset-1").unwrap(),
    };

    let asset_info_2 = AssetInfo {
        contract_address: contract_addr.clone(),
        contract_name: ContractName::try_from("hello-world").unwrap(),
        asset_name: ClarityName::try_from("test-asset-2").unwrap(),
    };

    let asset_info_3 = AssetInfo {
        contract_address: contract_addr.clone(),
        contract_name: ContractName::try_from("hello-world").unwrap(),
        asset_name: ClarityName::try_from("test-asset-3").unwrap(),
    };

    let asset_id_1 = AssetIdentifier {
        contract_identifier: QualifiedContractIdentifier::new(
            StandardPrincipalData::from(asset_info_1.contract_address.clone()),
            asset_info_1.contract_name.clone(),
        ),
        asset_name: asset_info_1.asset_name.clone(),
    };

    let asset_id_2 = AssetIdentifier {
        contract_identifier: QualifiedContractIdentifier::new(
            StandardPrincipalData::from(asset_info_2.contract_address.clone()),
            asset_info_2.contract_name.clone(),
        ),
        asset_name: asset_info_2.asset_name.clone(),
    };

    let _asset_id_3 = AssetIdentifier {
        contract_identifier: QualifiedContractIdentifier::new(
            StandardPrincipalData::from(asset_info_3.contract_address.clone()),
            asset_info_3.contract_name.clone(),
        ),
        asset_name: asset_info_3.asset_name.clone(),
    };

    // multi-ft
    let mut ft_transfer_2 = AssetMap::new();
    ft_transfer_2
        .add_token_transfer(&origin, asset_id_1, 123)
        .unwrap();
    ft_transfer_2
        .add_token_transfer(&origin, asset_id_2, 123)
        .unwrap();

    let tests = vec![
        // no-postconditions in allow mode
        (
            true,
            vec![],
            TransactionPostConditionMode::Allow,
            origin.clone(),
        ),
        // one post-condition on origin in allow mode
        (
            true,
            vec![TransactionPostCondition::Fungible(
                PostConditionPrincipal::Origin,
                asset_info_1.clone(),
                FungibleConditionCode::SentEq,
                123,
            )],
            TransactionPostConditionMode::Allow,
            origin.clone(),
        ),
        (
            true,
            vec![TransactionPostCondition::Fungible(
                PostConditionPrincipal::Origin,
                asset_info_1.clone(),
                FungibleConditionCode::SentLe,
                123,
            )],
            TransactionPostConditionMode::Allow,
            origin.clone(),
        ),
        (
            true,
            vec![TransactionPostCondition::Fungible(
                PostConditionPrincipal::Origin,
                asset_info_1.clone(),
                FungibleConditionCode::SentGe,
                123,
            )],
            TransactionPostConditionMode::Allow,
            origin.clone(),
        ),
        (
            true,
            vec![TransactionPostCondition::Fungible(
                PostConditionPrincipal::Origin,
                asset_info_1.clone(),
                FungibleConditionCode::SentLt,
                124,
            )],
            TransactionPostConditionMode::Allow,
            origin.clone(),
        ),
        (
            true,
            vec![TransactionPostCondition::Fungible(
                PostConditionPrincipal::Origin,
                asset_info_1.clone(),
                FungibleConditionCode::SentGt,
                122,
            )],
            TransactionPostConditionMode::Allow,
            origin.clone(),
        ),
        // two post-conditions on origin in allow mode
        (
            true,
            vec![
                TransactionPostCondition::Fungible(
                    PostConditionPrincipal::Origin,
                    asset_info_1.clone(),
                    FungibleConditionCode::SentEq,
                    123,
                ),
                TransactionPostCondition::Fungible(
                    PostConditionPrincipal::Origin,
                    asset_info_2.clone(),
                    FungibleConditionCode::SentEq,
                    123,
                ),
            ],
            TransactionPostConditionMode::Allow,
            origin.clone(),
        ),
        (
            true,
            vec![
                TransactionPostCondition::Fungible(
                    PostConditionPrincipal::Origin,
                    asset_info_1.clone(),
                    FungibleConditionCode::SentLe,
                    123,
                ),
                TransactionPostCondition::Fungible(
                    PostConditionPrincipal::Origin,
                    asset_info_2.clone(),
                    FungibleConditionCode::SentLe,
                    123,
                ),
            ],
            TransactionPostConditionMode::Allow,
            origin.clone(),
        ),
        (
            true,
            vec![
                TransactionPostCondition::Fungible(
                    PostConditionPrincipal::Origin,
                    asset_info_1.clone(),
                    FungibleConditionCode::SentGe,
                    123,
                ),
                TransactionPostCondition::Fungible(
                    PostConditionPrincipal::Origin,
                    asset_info_2.clone(),
                    FungibleConditionCode::SentGe,
                    123,
                ),
            ],
            TransactionPostConditionMode::Allow,
            origin.clone(),
        ),
        (
            true,
            vec![
                TransactionPostCondition::Fungible(
                    PostConditionPrincipal::Origin,
                    asset_info_1.clone(),
                    FungibleConditionCode::SentLt,
                    124,
                ),
                TransactionPostCondition::Fungible(
                    PostConditionPrincipal::Origin,
                    asset_info_2.clone(),
                    FungibleConditionCode::SentLt,
                    124,
                ),
            ],
            TransactionPostConditionMode::Allow,
            origin.clone(),
        ),
        (
            true,
            vec![
                TransactionPostCondition::Fungible(
                    PostConditionPrincipal::Origin,
                    asset_info_1.clone(),
                    FungibleConditionCode::SentGt,
                    122,
                ),
                TransactionPostCondition::Fungible(
                    PostConditionPrincipal::Origin,
                    asset_info_2.clone(),
                    FungibleConditionCode::SentGt,
                    122,
                ),
            ],
            TransactionPostConditionMode::Allow,
            origin.clone(),
        ),
        // three post-conditions on origin in allow mode, one with sending 0 tokens
        (
            true,
            vec![
                TransactionPostCondition::Fungible(
                    PostConditionPrincipal::Origin,
                    asset_info_1.clone(),
                    FungibleConditionCode::SentEq,
                    123,
                ),
                TransactionPostCondition::Fungible(
                    PostConditionPrincipal::Origin,
                    asset_info_3.clone(),
                    FungibleConditionCode::SentEq,
                    0,
                ),
                TransactionPostCondition::Fungible(
                    PostConditionPrincipal::Origin,
                    asset_info_2.clone(),
                    FungibleConditionCode::SentEq,
                    123,
                ),
            ],
            TransactionPostConditionMode::Allow,
            origin.clone(),
        ),
        (
            true,
            vec![
                TransactionPostCondition::Fungible(
                    PostConditionPrincipal::Origin,
                    asset_info_1.clone(),
                    FungibleConditionCode::SentLe,
                    123,
                ),
                TransactionPostCondition::Fungible(
                    PostConditionPrincipal::Origin,
                    asset_info_3.clone(),
                    FungibleConditionCode::SentLe,
                    0,
                ),
                TransactionPostCondition::Fungible(
                    PostConditionPrincipal::Origin,
                    asset_info_2.clone(),
                    FungibleConditionCode::SentLe,
                    123,
                ),
            ],
            TransactionPostConditionMode::Allow,
            origin.clone(),
        ),
        (
            true,
            vec![
                TransactionPostCondition::Fungible(
                    PostConditionPrincipal::Origin,
                    asset_info_1.clone(),
                    FungibleConditionCode::SentGe,
                    123,
                ),
                TransactionPostCondition::Fungible(
                    PostConditionPrincipal::Origin,
                    asset_info_3.clone(),
                    FungibleConditionCode::SentGe,
                    0,
                ),
                TransactionPostCondition::Fungible(
                    PostConditionPrincipal::Origin,
                    asset_info_2.clone(),
                    FungibleConditionCode::SentGe,
                    123,
                ),
            ],
            TransactionPostConditionMode::Allow,
            origin.clone(),
        ),
        (
            true,
            vec![
                TransactionPostCondition::Fungible(
                    PostConditionPrincipal::Origin,
                    asset_info_1.clone(),
                    FungibleConditionCode::SentLt,
                    124,
                ),
                TransactionPostCondition::Fungible(
                    PostConditionPrincipal::Origin,
                    asset_info_3.clone(),
                    FungibleConditionCode::SentLt,
                    1,
                ),
                TransactionPostCondition::Fungible(
                    PostConditionPrincipal::Origin,
                    asset_info_2.clone(),
                    FungibleConditionCode::SentLt,
                    124,
                ),
            ],
            TransactionPostConditionMode::Allow,
            origin.clone(),
        ),
        (
            true,
            vec![
                TransactionPostCondition::Fungible(
                    PostConditionPrincipal::Origin,
                    asset_info_1.clone(),
                    FungibleConditionCode::SentGt,
                    122,
                ),
                TransactionPostCondition::Fungible(
                    PostConditionPrincipal::Origin,
                    asset_info_3.clone(),
                    FungibleConditionCode::SentEq,
                    0,
                ),
                TransactionPostCondition::Fungible(
                    PostConditionPrincipal::Origin,
                    asset_info_2.clone(),
                    FungibleConditionCode::SentGt,
                    122,
                ),
            ],
            TransactionPostConditionMode::Allow,
            origin.clone(),
        ),
        // four post-conditions on origin in allow mode, one with sending 0 tokens, one with
        // an unchecked address and a vacuous amount
        (
            true,
            vec![
                TransactionPostCondition::Fungible(
                    PostConditionPrincipal::Origin,
                    asset_info_1.clone(),
                    FungibleConditionCode::SentEq,
                    123,
                ),
                TransactionPostCondition::Fungible(
                    PostConditionPrincipal::Origin,
                    asset_info_3.clone(),
                    FungibleConditionCode::SentEq,
                    0,
                ),
                TransactionPostCondition::Fungible(
                    PostConditionPrincipal::Standard(recv_addr.clone()),
                    asset_info_1.clone(),
                    FungibleConditionCode::SentEq,
                    0,
                ),
                TransactionPostCondition::Fungible(
                    PostConditionPrincipal::Origin,
                    asset_info_2.clone(),
                    FungibleConditionCode::SentEq,
                    123,
                ),
            ],
            TransactionPostConditionMode::Allow,
            origin.clone(),
        ),
        (
            true,
            vec![
                TransactionPostCondition::Fungible(
                    PostConditionPrincipal::Origin,
                    asset_info_1.clone(),
                    FungibleConditionCode::SentLe,
                    123,
                ),
                TransactionPostCondition::Fungible(
                    PostConditionPrincipal::Origin,
                    asset_info_3.clone(),
                    FungibleConditionCode::SentLe,
                    0,
                ),
                TransactionPostCondition::Fungible(
                    PostConditionPrincipal::Standard(recv_addr.clone()),
                    asset_info_1.clone(),
                    FungibleConditionCode::SentLe,
                    0,
                ),
                TransactionPostCondition::Fungible(
                    PostConditionPrincipal::Origin,
                    asset_info_2.clone(),
                    FungibleConditionCode::SentLe,
                    123,
                ),
            ],
            TransactionPostConditionMode::Allow,
            origin.clone(),
        ),
        (
            true,
            vec![
                TransactionPostCondition::Fungible(
                    PostConditionPrincipal::Origin,
                    asset_info_1.clone(),
                    FungibleConditionCode::SentGe,
                    123,
                ),
                TransactionPostCondition::Fungible(
                    PostConditionPrincipal::Origin,
                    asset_info_3.clone(),
                    FungibleConditionCode::SentGe,
                    0,
                ),
                TransactionPostCondition::Fungible(
                    PostConditionPrincipal::Standard(recv_addr.clone()),
                    asset_info_1.clone(),
                    FungibleConditionCode::SentGe,
                    0,
                ),
                TransactionPostCondition::Fungible(
                    PostConditionPrincipal::Origin,
                    asset_info_2.clone(),
                    FungibleConditionCode::SentGe,
                    123,
                ),
            ],
            TransactionPostConditionMode::Allow,
            origin.clone(),
        ),
        (
            true,
            vec![
                TransactionPostCondition::Fungible(
                    PostConditionPrincipal::Origin,
                    asset_info_1.clone(),
                    FungibleConditionCode::SentLt,
                    124,
                ),
                TransactionPostCondition::Fungible(
                    PostConditionPrincipal::Origin,
                    asset_info_3.clone(),
                    FungibleConditionCode::SentLt,
                    1,
                ),
                TransactionPostCondition::Fungible(
                    PostConditionPrincipal::Standard(recv_addr.clone()),
                    asset_info_1.clone(),
                    FungibleConditionCode::SentLt,
                    1,
                ),
                TransactionPostCondition::Fungible(
                    PostConditionPrincipal::Origin,
                    asset_info_2.clone(),
                    FungibleConditionCode::SentLt,
                    124,
                ),
            ],
            TransactionPostConditionMode::Allow,
            origin.clone(),
        ),
        (
            true,
            vec![
                TransactionPostCondition::Fungible(
                    PostConditionPrincipal::Origin,
                    asset_info_1.clone(),
                    FungibleConditionCode::SentGt,
                    122,
                ),
                TransactionPostCondition::Fungible(
                    PostConditionPrincipal::Origin,
                    asset_info_3.clone(),
                    FungibleConditionCode::SentEq,
                    0,
                ),
                TransactionPostCondition::Fungible(
                    PostConditionPrincipal::Standard(recv_addr.clone()),
                    asset_info_1.clone(),
                    FungibleConditionCode::SentEq,
                    0,
                ),
                TransactionPostCondition::Fungible(
                    PostConditionPrincipal::Origin,
                    asset_info_2.clone(),
                    FungibleConditionCode::SentGt,
                    122,
                ),
            ],
            TransactionPostConditionMode::Allow,
            origin.clone(),
        ),
        // one post-condition on origin in allow mode, explicit origin
        (
            true,
            vec![TransactionPostCondition::Fungible(
                PostConditionPrincipal::Standard(addr.clone()),
                asset_info_1.clone(),
                FungibleConditionCode::SentEq,
                123,
            )],
            TransactionPostConditionMode::Allow,
            origin.clone(),
        ),
        (
            true,
            vec![TransactionPostCondition::Fungible(
                PostConditionPrincipal::Standard(addr.clone()),
                asset_info_1.clone(),
                FungibleConditionCode::SentLe,
                123,
            )],
            TransactionPostConditionMode::Allow,
            origin.clone(),
        ),
        (
            true,
            vec![TransactionPostCondition::Fungible(
                PostConditionPrincipal::Standard(addr.clone()),
                asset_info_1.clone(),
                FungibleConditionCode::SentGe,
                123,
            )],
            TransactionPostConditionMode::Allow,
            origin.clone(),
        ),
        (
            true,
            vec![TransactionPostCondition::Fungible(
                PostConditionPrincipal::Standard(addr.clone()),
                asset_info_1.clone(),
                FungibleConditionCode::SentLt,
                124,
            )],
            TransactionPostConditionMode::Allow,
            origin.clone(),
        ),
        (
            true,
            vec![TransactionPostCondition::Fungible(
                PostConditionPrincipal::Standard(addr.clone()),
                asset_info_1.clone(),
                FungibleConditionCode::SentGt,
                122,
            )],
            TransactionPostConditionMode::Allow,
            origin.clone(),
        ),
        // two post-conditions on origin in allow mode, explicit origin
        (
            true,
            vec![
                TransactionPostCondition::Fungible(
                    PostConditionPrincipal::Standard(addr.clone()),
                    asset_info_1.clone(),
                    FungibleConditionCode::SentEq,
                    123,
                ),
                TransactionPostCondition::Fungible(
                    PostConditionPrincipal::Standard(addr.clone()),
                    asset_info_2.clone(),
                    FungibleConditionCode::SentEq,
                    123,
                ),
            ],
            TransactionPostConditionMode::Allow,
            origin.clone(),
        ),
        (
            true,
            vec![
                TransactionPostCondition::Fungible(
                    PostConditionPrincipal::Standard(addr.clone()),
                    asset_info_1.clone(),
                    FungibleConditionCode::SentLe,
                    123,
                ),
                TransactionPostCondition::Fungible(
                    PostConditionPrincipal::Standard(addr.clone()),
                    asset_info_2.clone(),
                    FungibleConditionCode::SentLe,
                    123,
                ),
            ],
            TransactionPostConditionMode::Allow,
            origin.clone(),
        ),
        (
            true,
            vec![
                TransactionPostCondition::Fungible(
                    PostConditionPrincipal::Standard(addr.clone()),
                    asset_info_1.clone(),
                    FungibleConditionCode::SentGe,
                    123,
                ),
                TransactionPostCondition::Fungible(
                    PostConditionPrincipal::Standard(addr.clone()),
                    asset_info_2.clone(),
                    FungibleConditionCode::SentGe,
                    123,
                ),
            ],
            TransactionPostConditionMode::Allow,
            origin.clone(),
        ),
        (
            true,
            vec![
                TransactionPostCondition::Fungible(
                    PostConditionPrincipal::Standard(addr.clone()),
                    asset_info_1.clone(),
                    FungibleConditionCode::SentLt,
                    124,
                ),
                TransactionPostCondition::Fungible(
                    PostConditionPrincipal::Standard(addr.clone()),
                    asset_info_2.clone(),
                    FungibleConditionCode::SentLt,
                    124,
                ),
            ],
            TransactionPostConditionMode::Allow,
            origin.clone(),
        ),
        (
            true,
            vec![
                TransactionPostCondition::Fungible(
                    PostConditionPrincipal::Standard(addr.clone()),
                    asset_info_1.clone(),
                    FungibleConditionCode::SentGt,
                    122,
                ),
                TransactionPostCondition::Fungible(
                    PostConditionPrincipal::Standard(addr.clone()),
                    asset_info_2.clone(),
                    FungibleConditionCode::SentGt,
                    122,
                ),
            ],
            TransactionPostConditionMode::Allow,
            origin.clone(),
        ),
        // three post-conditions on origin in allow mode, one with sending 0 tokens, explicit
        // origin
        (
            true,
            vec![
                TransactionPostCondition::Fungible(
                    PostConditionPrincipal::Standard(addr.clone()),
                    asset_info_1.clone(),
                    FungibleConditionCode::SentEq,
                    123,
                ),
                TransactionPostCondition::Fungible(
                    PostConditionPrincipal::Standard(addr.clone()),
                    asset_info_3.clone(),
                    FungibleConditionCode::SentEq,
                    0,
                ),
                TransactionPostCondition::Fungible(
                    PostConditionPrincipal::Standard(addr.clone()),
                    asset_info_2.clone(),
                    FungibleConditionCode::SentEq,
                    123,
                ),
            ],
            TransactionPostConditionMode::Allow,
            origin.clone(),
        ),
        (
            true,
            vec![
                TransactionPostCondition::Fungible(
                    PostConditionPrincipal::Standard(addr.clone()),
                    asset_info_1.clone(),
                    FungibleConditionCode::SentLe,
                    123,
                ),
                TransactionPostCondition::Fungible(
                    PostConditionPrincipal::Standard(addr.clone()),
                    asset_info_3.clone(),
                    FungibleConditionCode::SentLe,
                    0,
                ),
                TransactionPostCondition::Fungible(
                    PostConditionPrincipal::Standard(addr.clone()),
                    asset_info_2.clone(),
                    FungibleConditionCode::SentLe,
                    123,
                ),
            ],
            TransactionPostConditionMode::Allow,
            origin.clone(),
        ),
        (
            true,
            vec![
                TransactionPostCondition::Fungible(
                    PostConditionPrincipal::Standard(addr.clone()),
                    asset_info_1.clone(),
                    FungibleConditionCode::SentGe,
                    123,
                ),
                TransactionPostCondition::Fungible(
                    PostConditionPrincipal::Standard(addr.clone()),
                    asset_info_3.clone(),
                    FungibleConditionCode::SentGe,
                    0,
                ),
                TransactionPostCondition::Fungible(
                    PostConditionPrincipal::Standard(addr.clone()),
                    asset_info_2.clone(),
                    FungibleConditionCode::SentGe,
                    123,
                ),
            ],
            TransactionPostConditionMode::Allow,
            origin.clone(),
        ),
        (
            true,
            vec![
                TransactionPostCondition::Fungible(
                    PostConditionPrincipal::Standard(addr.clone()),
                    asset_info_1.clone(),
                    FungibleConditionCode::SentLt,
                    124,
                ),
                TransactionPostCondition::Fungible(
                    PostConditionPrincipal::Standard(addr.clone()),
                    asset_info_3.clone(),
                    FungibleConditionCode::SentLt,
                    1,
                ),
                TransactionPostCondition::Fungible(
                    PostConditionPrincipal::Standard(addr.clone()),
                    asset_info_2.clone(),
                    FungibleConditionCode::SentLt,
                    124,
                ),
            ],
            TransactionPostConditionMode::Allow,
            origin.clone(),
        ),
        (
            true,
            vec![
                TransactionPostCondition::Fungible(
                    PostConditionPrincipal::Standard(addr.clone()),
                    asset_info_1.clone(),
                    FungibleConditionCode::SentGt,
                    122,
                ),
                TransactionPostCondition::Fungible(
                    PostConditionPrincipal::Standard(addr.clone()),
                    asset_info_3.clone(),
                    FungibleConditionCode::SentEq,
                    0,
                ),
                TransactionPostCondition::Fungible(
                    PostConditionPrincipal::Standard(addr.clone()),
                    asset_info_2.clone(),
                    FungibleConditionCode::SentGt,
                    122,
                ),
            ],
            TransactionPostConditionMode::Allow,
            origin.clone(),
        ),
        // four post-conditions on origin in allow mode, one with sending 0 tokens, one with
        // an unchecked address and a vacuous amount, explicit origin
        (
            true,
            vec![
                TransactionPostCondition::Fungible(
                    PostConditionPrincipal::Standard(addr.clone()),
                    asset_info_1.clone(),
                    FungibleConditionCode::SentEq,
                    123,
                ),
                TransactionPostCondition::Fungible(
                    PostConditionPrincipal::Standard(addr.clone()),
                    asset_info_3.clone(),
                    FungibleConditionCode::SentEq,
                    0,
                ),
                TransactionPostCondition::Fungible(
                    PostConditionPrincipal::Standard(recv_addr.clone()),
                    asset_info_1.clone(),
                    FungibleConditionCode::SentEq,
                    0,
                ),
                TransactionPostCondition::Fungible(
                    PostConditionPrincipal::Standard(addr.clone()),
                    asset_info_2.clone(),
                    FungibleConditionCode::SentEq,
                    123,
                ),
            ],
            TransactionPostConditionMode::Allow,
            origin.clone(),
        ),
        (
            true,
            vec![
                TransactionPostCondition::Fungible(
                    PostConditionPrincipal::Standard(addr.clone()),
                    asset_info_1.clone(),
                    FungibleConditionCode::SentLe,
                    123,
                ),
                TransactionPostCondition::Fungible(
                    PostConditionPrincipal::Standard(addr.clone()),
                    asset_info_3.clone(),
                    FungibleConditionCode::SentLe,
                    0,
                ),
                TransactionPostCondition::Fungible(
                    PostConditionPrincipal::Standard(recv_addr.clone()),
                    asset_info_1.clone(),
                    FungibleConditionCode::SentLe,
                    0,
                ),
                TransactionPostCondition::Fungible(
                    PostConditionPrincipal::Standard(addr.clone()),
                    asset_info_2.clone(),
                    FungibleConditionCode::SentLe,
                    123,
                ),
            ],
            TransactionPostConditionMode::Allow,
            origin.clone(),
        ),
        (
            true,
            vec![
                TransactionPostCondition::Fungible(
                    PostConditionPrincipal::Standard(addr.clone()),
                    asset_info_1.clone(),
                    FungibleConditionCode::SentGe,
                    123,
                ),
                TransactionPostCondition::Fungible(
                    PostConditionPrincipal::Standard(addr.clone()),
                    asset_info_3.clone(),
                    FungibleConditionCode::SentGe,
                    0,
                ),
                TransactionPostCondition::Fungible(
                    PostConditionPrincipal::Standard(recv_addr.clone()),
                    asset_info_1.clone(),
                    FungibleConditionCode::SentGe,
                    0,
                ),
                TransactionPostCondition::Fungible(
                    PostConditionPrincipal::Standard(addr.clone()),
                    asset_info_2.clone(),
                    FungibleConditionCode::SentGe,
                    123,
                ),
            ],
            TransactionPostConditionMode::Allow,
            origin.clone(),
        ),
        (
            true,
            vec![
                TransactionPostCondition::Fungible(
                    PostConditionPrincipal::Standard(addr.clone()),
                    asset_info_1.clone(),
                    FungibleConditionCode::SentLt,
                    124,
                ),
                TransactionPostCondition::Fungible(
                    PostConditionPrincipal::Standard(addr.clone()),
                    asset_info_3.clone(),
                    FungibleConditionCode::SentLt,
                    1,
                ),
                TransactionPostCondition::Fungible(
                    PostConditionPrincipal::Standard(recv_addr.clone()),
                    asset_info_1.clone(),
                    FungibleConditionCode::SentLt,
                    1,
                ),
                TransactionPostCondition::Fungible(
                    PostConditionPrincipal::Standard(addr.clone()),
                    asset_info_2.clone(),
                    FungibleConditionCode::SentLt,
                    124,
                ),
            ],
            TransactionPostConditionMode::Allow,
            origin.clone(),
        ),
        (
            true,
            vec![
                TransactionPostCondition::Fungible(
                    PostConditionPrincipal::Standard(addr.clone()),
                    asset_info_1.clone(),
                    FungibleConditionCode::SentGt,
                    122,
                ),
                TransactionPostCondition::Fungible(
                    PostConditionPrincipal::Standard(addr.clone()),
                    asset_info_3.clone(),
                    FungibleConditionCode::SentEq,
                    0,
                ),
                TransactionPostCondition::Fungible(
                    PostConditionPrincipal::Standard(recv_addr.clone()),
                    asset_info_1.clone(),
                    FungibleConditionCode::SentEq,
                    0,
                ),
                TransactionPostCondition::Fungible(
                    PostConditionPrincipal::Standard(addr.clone()),
                    asset_info_2.clone(),
                    FungibleConditionCode::SentGt,
                    122,
                ),
            ],
            TransactionPostConditionMode::Allow,
            origin.clone(),
        ),
        // no-postconditions in deny mode
        (
            false,
            vec![],
            TransactionPostConditionMode::Deny,
            origin.clone(),
        ),
        // one post-condition on origin in allow mode
        (
            false,
            vec![TransactionPostCondition::Fungible(
                PostConditionPrincipal::Origin,
                asset_info_1.clone(),
                FungibleConditionCode::SentEq,
                123,
            )],
            TransactionPostConditionMode::Deny,
            origin.clone(),
        ),
        (
            false,
            vec![TransactionPostCondition::Fungible(
                PostConditionPrincipal::Origin,
                asset_info_1.clone(),
                FungibleConditionCode::SentLe,
                123,
            )],
            TransactionPostConditionMode::Deny,
            origin.clone(),
        ),
        (
            false,
            vec![TransactionPostCondition::Fungible(
                PostConditionPrincipal::Origin,
                asset_info_1.clone(),
                FungibleConditionCode::SentGe,
                123,
            )],
            TransactionPostConditionMode::Deny,
            origin.clone(),
        ),
        (
            false,
            vec![TransactionPostCondition::Fungible(
                PostConditionPrincipal::Origin,
                asset_info_1.clone(),
                FungibleConditionCode::SentLt,
                124,
            )],
            TransactionPostConditionMode::Deny,
            origin.clone(),
        ),
        (
            false,
            vec![TransactionPostCondition::Fungible(
                PostConditionPrincipal::Origin,
                asset_info_1.clone(),
                FungibleConditionCode::SentGt,
                122,
            )],
            TransactionPostConditionMode::Deny,
            origin.clone(),
        ),
        // two post-conditions on origin in allow mode
        (
            true,
            vec![
                TransactionPostCondition::Fungible(
                    PostConditionPrincipal::Origin,
                    asset_info_1.clone(),
                    FungibleConditionCode::SentEq,
                    123,
                ),
                TransactionPostCondition::Fungible(
                    PostConditionPrincipal::Origin,
                    asset_info_2.clone(),
                    FungibleConditionCode::SentEq,
                    123,
                ),
            ],
            TransactionPostConditionMode::Deny,
            origin.clone(),
        ),
        (
            true,
            vec![
                TransactionPostCondition::Fungible(
                    PostConditionPrincipal::Origin,
                    asset_info_1.clone(),
                    FungibleConditionCode::SentLe,
                    123,
                ),
                TransactionPostCondition::Fungible(
                    PostConditionPrincipal::Origin,
                    asset_info_2.clone(),
                    FungibleConditionCode::SentLe,
                    123,
                ),
            ],
            TransactionPostConditionMode::Deny,
            origin.clone(),
        ),
        (
            true,
            vec![
                TransactionPostCondition::Fungible(
                    PostConditionPrincipal::Origin,
                    asset_info_1.clone(),
                    FungibleConditionCode::SentGe,
                    123,
                ),
                TransactionPostCondition::Fungible(
                    PostConditionPrincipal::Origin,
                    asset_info_2.clone(),
                    FungibleConditionCode::SentGe,
                    123,
                ),
            ],
            TransactionPostConditionMode::Deny,
            origin.clone(),
        ),
        (
            true,
            vec![
                TransactionPostCondition::Fungible(
                    PostConditionPrincipal::Origin,
                    asset_info_1.clone(),
                    FungibleConditionCode::SentLt,
                    124,
                ),
                TransactionPostCondition::Fungible(
                    PostConditionPrincipal::Origin,
                    asset_info_2.clone(),
                    FungibleConditionCode::SentLt,
                    124,
                ),
            ],
            TransactionPostConditionMode::Deny,
            origin.clone(),
        ),
        (
            true,
            vec![
                TransactionPostCondition::Fungible(
                    PostConditionPrincipal::Origin,
                    asset_info_1.clone(),
                    FungibleConditionCode::SentGt,
                    122,
                ),
                TransactionPostCondition::Fungible(
                    PostConditionPrincipal::Origin,
                    asset_info_2.clone(),
                    FungibleConditionCode::SentGt,
                    122,
                ),
            ],
            TransactionPostConditionMode::Deny,
            origin.clone(),
        ),
        // three post-conditions on origin in allow mode, one with sending 0 tokens
        (
            true,
            vec![
                TransactionPostCondition::Fungible(
                    PostConditionPrincipal::Origin,
                    asset_info_1.clone(),
                    FungibleConditionCode::SentEq,
                    123,
                ),
                TransactionPostCondition::Fungible(
                    PostConditionPrincipal::Origin,
                    asset_info_3.clone(),
                    FungibleConditionCode::SentEq,
                    0,
                ),
                TransactionPostCondition::Fungible(
                    PostConditionPrincipal::Origin,
                    asset_info_2.clone(),
                    FungibleConditionCode::SentEq,
                    123,
                ),
            ],
            TransactionPostConditionMode::Deny,
            origin.clone(),
        ),
        (
            true,
            vec![
                TransactionPostCondition::Fungible(
                    PostConditionPrincipal::Origin,
                    asset_info_1.clone(),
                    FungibleConditionCode::SentLe,
                    123,
                ),
                TransactionPostCondition::Fungible(
                    PostConditionPrincipal::Origin,
                    asset_info_3.clone(),
                    FungibleConditionCode::SentLe,
                    0,
                ),
                TransactionPostCondition::Fungible(
                    PostConditionPrincipal::Origin,
                    asset_info_2.clone(),
                    FungibleConditionCode::SentLe,
                    123,
                ),
            ],
            TransactionPostConditionMode::Deny,
            origin.clone(),
        ),
        (
            true,
            vec![
                TransactionPostCondition::Fungible(
                    PostConditionPrincipal::Origin,
                    asset_info_1.clone(),
                    FungibleConditionCode::SentGe,
                    123,
                ),
                TransactionPostCondition::Fungible(
                    PostConditionPrincipal::Origin,
                    asset_info_3.clone(),
                    FungibleConditionCode::SentGe,
                    0,
                ),
                TransactionPostCondition::Fungible(
                    PostConditionPrincipal::Origin,
                    asset_info_2.clone(),
                    FungibleConditionCode::SentGe,
                    123,
                ),
            ],
            TransactionPostConditionMode::Deny,
            origin.clone(),
        ),
        (
            true,
            vec![
                TransactionPostCondition::Fungible(
                    PostConditionPrincipal::Origin,
                    asset_info_1.clone(),
                    FungibleConditionCode::SentLt,
                    124,
                ),
                TransactionPostCondition::Fungible(
                    PostConditionPrincipal::Origin,
                    asset_info_3.clone(),
                    FungibleConditionCode::SentLt,
                    1,
                ),
                TransactionPostCondition::Fungible(
                    PostConditionPrincipal::Origin,
                    asset_info_2.clone(),
                    FungibleConditionCode::SentLt,
                    124,
                ),
            ],
            TransactionPostConditionMode::Deny,
            origin.clone(),
        ),
        (
            true,
            vec![
                TransactionPostCondition::Fungible(
                    PostConditionPrincipal::Origin,
                    asset_info_1.clone(),
                    FungibleConditionCode::SentGt,
                    122,
                ),
                TransactionPostCondition::Fungible(
                    PostConditionPrincipal::Origin,
                    asset_info_3.clone(),
                    FungibleConditionCode::SentEq,
                    0,
                ),
                TransactionPostCondition::Fungible(
                    PostConditionPrincipal::Origin,
                    asset_info_2.clone(),
                    FungibleConditionCode::SentGt,
                    122,
                ),
            ],
            TransactionPostConditionMode::Deny,
            origin.clone(),
        ),
        // four post-conditions on origin in allow mode, one with sending 0 tokens, one with
        // an unchecked address and a vacuous amount
        (
            true,
            vec![
                TransactionPostCondition::Fungible(
                    PostConditionPrincipal::Origin,
                    asset_info_1.clone(),
                    FungibleConditionCode::SentEq,
                    123,
                ),
                TransactionPostCondition::Fungible(
                    PostConditionPrincipal::Origin,
                    asset_info_3.clone(),
                    FungibleConditionCode::SentEq,
                    0,
                ),
                TransactionPostCondition::Fungible(
                    PostConditionPrincipal::Standard(recv_addr.clone()),
                    asset_info_1.clone(),
                    FungibleConditionCode::SentEq,
                    0,
                ),
                TransactionPostCondition::Fungible(
                    PostConditionPrincipal::Origin,
                    asset_info_2.clone(),
                    FungibleConditionCode::SentEq,
                    123,
                ),
            ],
            TransactionPostConditionMode::Deny,
            origin.clone(),
        ),
        (
            true,
            vec![
                TransactionPostCondition::Fungible(
                    PostConditionPrincipal::Origin,
                    asset_info_1.clone(),
                    FungibleConditionCode::SentLe,
                    123,
                ),
                TransactionPostCondition::Fungible(
                    PostConditionPrincipal::Origin,
                    asset_info_3.clone(),
                    FungibleConditionCode::SentLe,
                    0,
                ),
                TransactionPostCondition::Fungible(
                    PostConditionPrincipal::Standard(recv_addr.clone()),
                    asset_info_1.clone(),
                    FungibleConditionCode::SentLe,
                    0,
                ),
                TransactionPostCondition::Fungible(
                    PostConditionPrincipal::Origin,
                    asset_info_2.clone(),
                    FungibleConditionCode::SentLe,
                    123,
                ),
            ],
            TransactionPostConditionMode::Deny,
            origin.clone(),
        ),
        (
            true,
            vec![
                TransactionPostCondition::Fungible(
                    PostConditionPrincipal::Origin,
                    asset_info_1.clone(),
                    FungibleConditionCode::SentGe,
                    123,
                ),
                TransactionPostCondition::Fungible(
                    PostConditionPrincipal::Origin,
                    asset_info_3.clone(),
                    FungibleConditionCode::SentGe,
                    0,
                ),
                TransactionPostCondition::Fungible(
                    PostConditionPrincipal::Standard(recv_addr.clone()),
                    asset_info_1.clone(),
                    FungibleConditionCode::SentGe,
                    0,
                ),
                TransactionPostCondition::Fungible(
                    PostConditionPrincipal::Origin,
                    asset_info_2.clone(),
                    FungibleConditionCode::SentGe,
                    123,
                ),
            ],
            TransactionPostConditionMode::Deny,
            origin.clone(),
        ),
        (
            true,
            vec![
                TransactionPostCondition::Fungible(
                    PostConditionPrincipal::Origin,
                    asset_info_1.clone(),
                    FungibleConditionCode::SentLt,
                    124,
                ),
                TransactionPostCondition::Fungible(
                    PostConditionPrincipal::Origin,
                    asset_info_3.clone(),
                    FungibleConditionCode::SentLt,
                    1,
                ),
                TransactionPostCondition::Fungible(
                    PostConditionPrincipal::Standard(recv_addr.clone()),
                    asset_info_1.clone(),
                    FungibleConditionCode::SentLt,
                    1,
                ),
                TransactionPostCondition::Fungible(
                    PostConditionPrincipal::Origin,
                    asset_info_2.clone(),
                    FungibleConditionCode::SentLt,
                    124,
                ),
            ],
            TransactionPostConditionMode::Deny,
            origin.clone(),
        ),
        (
            true,
            vec![
                TransactionPostCondition::Fungible(
                    PostConditionPrincipal::Origin,
                    asset_info_1.clone(),
                    FungibleConditionCode::SentGt,
                    122,
                ),
                TransactionPostCondition::Fungible(
                    PostConditionPrincipal::Origin,
                    asset_info_3.clone(),
                    FungibleConditionCode::SentEq,
                    0,
                ),
                TransactionPostCondition::Fungible(
                    PostConditionPrincipal::Standard(recv_addr.clone()),
                    asset_info_1.clone(),
                    FungibleConditionCode::SentEq,
                    0,
                ),
                TransactionPostCondition::Fungible(
                    PostConditionPrincipal::Origin,
                    asset_info_2.clone(),
                    FungibleConditionCode::SentGt,
                    122,
                ),
            ],
            TransactionPostConditionMode::Deny,
            origin.clone(),
        ),
        // one post-condition on origin in allow mode, explicit origin
        (
            false,
            vec![TransactionPostCondition::Fungible(
                PostConditionPrincipal::Standard(addr.clone()),
                asset_info_1.clone(),
                FungibleConditionCode::SentEq,
                123,
            )],
            TransactionPostConditionMode::Deny,
            origin.clone(),
        ),
        (
            false,
            vec![TransactionPostCondition::Fungible(
                PostConditionPrincipal::Standard(addr.clone()),
                asset_info_1.clone(),
                FungibleConditionCode::SentLe,
                123,
            )],
            TransactionPostConditionMode::Deny,
            origin.clone(),
        ),
        (
            false,
            vec![TransactionPostCondition::Fungible(
                PostConditionPrincipal::Standard(addr.clone()),
                asset_info_1.clone(),
                FungibleConditionCode::SentGe,
                123,
            )],
            TransactionPostConditionMode::Deny,
            origin.clone(),
        ),
        (
            false,
            vec![TransactionPostCondition::Fungible(
                PostConditionPrincipal::Standard(addr.clone()),
                asset_info_1.clone(),
                FungibleConditionCode::SentLt,
                124,
            )],
            TransactionPostConditionMode::Deny,
            origin.clone(),
        ),
        (
            false,
            vec![TransactionPostCondition::Fungible(
                PostConditionPrincipal::Standard(addr.clone()),
                asset_info_1.clone(),
                FungibleConditionCode::SentGt,
                122,
            )],
            TransactionPostConditionMode::Deny,
            origin.clone(),
        ),
        // two post-conditions on origin in allow mode, explicit origin
        (
            true,
            vec![
                TransactionPostCondition::Fungible(
                    PostConditionPrincipal::Standard(addr.clone()),
                    asset_info_1.clone(),
                    FungibleConditionCode::SentEq,
                    123,
                ),
                TransactionPostCondition::Fungible(
                    PostConditionPrincipal::Standard(addr.clone()),
                    asset_info_2.clone(),
                    FungibleConditionCode::SentEq,
                    123,
                ),
            ],
            TransactionPostConditionMode::Deny,
            origin.clone(),
        ),
        (
            true,
            vec![
                TransactionPostCondition::Fungible(
                    PostConditionPrincipal::Standard(addr.clone()),
                    asset_info_1.clone(),
                    FungibleConditionCode::SentLe,
                    123,
                ),
                TransactionPostCondition::Fungible(
                    PostConditionPrincipal::Standard(addr.clone()),
                    asset_info_2.clone(),
                    FungibleConditionCode::SentLe,
                    123,
                ),
            ],
            TransactionPostConditionMode::Deny,
            origin.clone(),
        ),
        (
            true,
            vec![
                TransactionPostCondition::Fungible(
                    PostConditionPrincipal::Standard(addr.clone()),
                    asset_info_1.clone(),
                    FungibleConditionCode::SentGe,
                    123,
                ),
                TransactionPostCondition::Fungible(
                    PostConditionPrincipal::Standard(addr.clone()),
                    asset_info_2.clone(),
                    FungibleConditionCode::SentGe,
                    123,
                ),
            ],
            TransactionPostConditionMode::Deny,
            origin.clone(),
        ),
        (
            true,
            vec![
                TransactionPostCondition::Fungible(
                    PostConditionPrincipal::Standard(addr.clone()),
                    asset_info_1.clone(),
                    FungibleConditionCode::SentLt,
                    124,
                ),
                TransactionPostCondition::Fungible(
                    PostConditionPrincipal::Standard(addr.clone()),
                    asset_info_2.clone(),
                    FungibleConditionCode::SentLt,
                    124,
                ),
            ],
            TransactionPostConditionMode::Deny,
            origin.clone(),
        ),
        (
            true,
            vec![
                TransactionPostCondition::Fungible(
                    PostConditionPrincipal::Standard(addr.clone()),
                    asset_info_1.clone(),
                    FungibleConditionCode::SentGt,
                    122,
                ),
                TransactionPostCondition::Fungible(
                    PostConditionPrincipal::Standard(addr.clone()),
                    asset_info_2.clone(),
                    FungibleConditionCode::SentGt,
                    122,
                ),
            ],
            TransactionPostConditionMode::Deny,
            origin.clone(),
        ),
        // three post-conditions on origin in allow mode, one with sending 0 tokens, explicit
        // origin
        (
            true,
            vec![
                TransactionPostCondition::Fungible(
                    PostConditionPrincipal::Standard(addr.clone()),
                    asset_info_1.clone(),
                    FungibleConditionCode::SentEq,
                    123,
                ),
                TransactionPostCondition::Fungible(
                    PostConditionPrincipal::Standard(addr.clone()),
                    asset_info_3.clone(),
                    FungibleConditionCode::SentEq,
                    0,
                ),
                TransactionPostCondition::Fungible(
                    PostConditionPrincipal::Standard(addr.clone()),
                    asset_info_2.clone(),
                    FungibleConditionCode::SentEq,
                    123,
                ),
            ],
            TransactionPostConditionMode::Deny,
            origin.clone(),
        ),
        (
            true,
            vec![
                TransactionPostCondition::Fungible(
                    PostConditionPrincipal::Standard(addr.clone()),
                    asset_info_1.clone(),
                    FungibleConditionCode::SentLe,
                    123,
                ),
                TransactionPostCondition::Fungible(
                    PostConditionPrincipal::Standard(addr.clone()),
                    asset_info_3.clone(),
                    FungibleConditionCode::SentLe,
                    0,
                ),
                TransactionPostCondition::Fungible(
                    PostConditionPrincipal::Standard(addr.clone()),
                    asset_info_2.clone(),
                    FungibleConditionCode::SentLe,
                    123,
                ),
            ],
            TransactionPostConditionMode::Deny,
            origin.clone(),
        ),
        (
            true,
            vec![
                TransactionPostCondition::Fungible(
                    PostConditionPrincipal::Standard(addr.clone()),
                    asset_info_1.clone(),
                    FungibleConditionCode::SentGe,
                    123,
                ),
                TransactionPostCondition::Fungible(
                    PostConditionPrincipal::Standard(addr.clone()),
                    asset_info_3.clone(),
                    FungibleConditionCode::SentGe,
                    0,
                ),
                TransactionPostCondition::Fungible(
                    PostConditionPrincipal::Standard(addr.clone()),
                    asset_info_2.clone(),
                    FungibleConditionCode::SentGe,
                    123,
                ),
            ],
            TransactionPostConditionMode::Deny,
            origin.clone(),
        ),
        (
            true,
            vec![
                TransactionPostCondition::Fungible(
                    PostConditionPrincipal::Standard(addr.clone()),
                    asset_info_1.clone(),
                    FungibleConditionCode::SentLt,
                    124,
                ),
                TransactionPostCondition::Fungible(
                    PostConditionPrincipal::Standard(addr.clone()),
                    asset_info_3.clone(),
                    FungibleConditionCode::SentLt,
                    1,
                ),
                TransactionPostCondition::Fungible(
                    PostConditionPrincipal::Standard(addr.clone()),
                    asset_info_2.clone(),
                    FungibleConditionCode::SentLt,
                    124,
                ),
            ],
            TransactionPostConditionMode::Deny,
            origin.clone(),
        ),
        (
            true,
            vec![
                TransactionPostCondition::Fungible(
                    PostConditionPrincipal::Standard(addr.clone()),
                    asset_info_1.clone(),
                    FungibleConditionCode::SentGt,
                    122,
                ),
                TransactionPostCondition::Fungible(
                    PostConditionPrincipal::Standard(addr.clone()),
                    asset_info_3.clone(),
                    FungibleConditionCode::SentEq,
                    0,
                ),
                TransactionPostCondition::Fungible(
                    PostConditionPrincipal::Standard(addr.clone()),
                    asset_info_2.clone(),
                    FungibleConditionCode::SentGt,
                    122,
                ),
            ],
            TransactionPostConditionMode::Deny,
            origin.clone(),
        ),
        // four post-conditions on origin in allow mode, one with sending 0 tokens, one with
        // an unchecked address and a vacuous amount, explicit origin
        (
            true,
            vec![
                TransactionPostCondition::Fungible(
                    PostConditionPrincipal::Standard(addr.clone()),
                    asset_info_1.clone(),
                    FungibleConditionCode::SentEq,
                    123,
                ),
                TransactionPostCondition::Fungible(
                    PostConditionPrincipal::Standard(addr.clone()),
                    asset_info_3.clone(),
                    FungibleConditionCode::SentEq,
                    0,
                ),
                TransactionPostCondition::Fungible(
                    PostConditionPrincipal::Standard(recv_addr.clone()),
                    asset_info_1.clone(),
                    FungibleConditionCode::SentEq,
                    0,
                ),
                TransactionPostCondition::Fungible(
                    PostConditionPrincipal::Standard(addr.clone()),
                    asset_info_2.clone(),
                    FungibleConditionCode::SentEq,
                    123,
                ),
            ],
            TransactionPostConditionMode::Deny,
            origin.clone(),
        ),
        (
            true,
            vec![
                TransactionPostCondition::Fungible(
                    PostConditionPrincipal::Standard(addr.clone()),
                    asset_info_1.clone(),
                    FungibleConditionCode::SentLe,
                    123,
                ),
                TransactionPostCondition::Fungible(
                    PostConditionPrincipal::Standard(addr.clone()),
                    asset_info_3.clone(),
                    FungibleConditionCode::SentLe,
                    0,
                ),
                TransactionPostCondition::Fungible(
                    PostConditionPrincipal::Standard(recv_addr.clone()),
                    asset_info_1.clone(),
                    FungibleConditionCode::SentLe,
                    0,
                ),
                TransactionPostCondition::Fungible(
                    PostConditionPrincipal::Standard(addr.clone()),
                    asset_info_2.clone(),
                    FungibleConditionCode::SentLe,
                    123,
                ),
            ],
            TransactionPostConditionMode::Deny,
            origin.clone(),
        ),
        (
            true,
            vec![
                TransactionPostCondition::Fungible(
                    PostConditionPrincipal::Standard(addr.clone()),
                    asset_info_1.clone(),
                    FungibleConditionCode::SentGe,
                    123,
                ),
                TransactionPostCondition::Fungible(
                    PostConditionPrincipal::Standard(addr.clone()),
                    asset_info_3.clone(),
                    FungibleConditionCode::SentGe,
                    0,
                ),
                TransactionPostCondition::Fungible(
                    PostConditionPrincipal::Standard(recv_addr.clone()),
                    asset_info_1.clone(),
                    FungibleConditionCode::SentGe,
                    0,
                ),
                TransactionPostCondition::Fungible(
                    PostConditionPrincipal::Standard(addr.clone()),
                    asset_info_2.clone(),
                    FungibleConditionCode::SentGe,
                    123,
                ),
            ],
            TransactionPostConditionMode::Deny,
            origin.clone(),
        ),
        (
            true,
            vec![
                TransactionPostCondition::Fungible(
                    PostConditionPrincipal::Standard(addr.clone()),
                    asset_info_1.clone(),
                    FungibleConditionCode::SentLt,
                    124,
                ),
                TransactionPostCondition::Fungible(
                    PostConditionPrincipal::Standard(addr.clone()),
                    asset_info_3.clone(),
                    FungibleConditionCode::SentLt,
                    1,
                ),
                TransactionPostCondition::Fungible(
                    PostConditionPrincipal::Standard(recv_addr.clone()),
                    asset_info_1.clone(),
                    FungibleConditionCode::SentLt,
                    1,
                ),
                TransactionPostCondition::Fungible(
                    PostConditionPrincipal::Standard(addr.clone()),
                    asset_info_2.clone(),
                    FungibleConditionCode::SentLt,
                    124,
                ),
            ],
            TransactionPostConditionMode::Deny,
            origin.clone(),
        ),
        (
            true,
            vec![
                TransactionPostCondition::Fungible(
                    PostConditionPrincipal::Standard(addr.clone()),
                    asset_info_1.clone(),
                    FungibleConditionCode::SentGt,
                    122,
                ),
                TransactionPostCondition::Fungible(
                    PostConditionPrincipal::Standard(addr.clone()),
                    asset_info_3,
                    FungibleConditionCode::SentEq,
                    0,
                ),
                TransactionPostCondition::Fungible(
                    PostConditionPrincipal::Standard(recv_addr.clone()),
                    asset_info_1,
                    FungibleConditionCode::SentEq,
                    0,
                ),
                TransactionPostCondition::Fungible(
                    PostConditionPrincipal::Standard(addr.clone()),
                    asset_info_2,
                    FungibleConditionCode::SentGt,
                    122,
                ),
            ],
            TransactionPostConditionMode::Deny,
            origin.clone(),
        ),
    ];

    for test in tests {
        let expected_result = test.0;
        let post_conditions = &test.1;
        let mode = &test.2;
        let origin = &test.3;

        let result = check_transaction_postconditions(
            post_conditions,
            mode,
            origin,
            &ft_transfer_2,
            StacksEpochId::latest(),
            Txid([0; 32]),
        )
        .unwrap();
        assert_eq!(
            result.is_none(),
            expected_result,
            "test failed:\nasset map: {ft_transfer_2:?}\nscenario: {test:?}"
        );
    }
}

#[test]
fn test_check_postconditions_multiple_nfts() {
    let privk = StacksPrivateKey::from_hex(
        "6d430bb91222408e7706c9001cfaeb91b08c2be6d5ac95779ab52c6b431950e001",
    )
    .unwrap();
    let auth = TransactionAuth::from_p2pkh(&privk).unwrap();
    let addr = auth.origin().address_testnet();
    let origin = addr.to_account_principal();
    let _recv_addr = StacksAddress::new(1, Hash160([0xff; 20])).unwrap();
    let contract_addr = StacksAddress::new(1, Hash160([0x01; 20])).unwrap();

    let asset_info = AssetInfo {
        contract_address: contract_addr.clone(),
        contract_name: ContractName::try_from("hello-world").unwrap(),
        asset_name: ClarityName::try_from("test-asset").unwrap(),
    };

    let asset_id = AssetIdentifier {
        contract_identifier: QualifiedContractIdentifier::new(
            StandardPrincipalData::from(asset_info.contract_address.clone()),
            asset_info.contract_name.clone(),
        ),
        asset_name: asset_info.asset_name.clone(),
    };

    // multi-nft transfer
    let mut nft_transfer_2 = AssetMap::new();
    nft_transfer_2.add_asset_transfer(&origin, asset_id.clone(), Value::Int(1));
    nft_transfer_2.add_asset_transfer(&origin, asset_id, Value::Int(2));

    let tests = vec![
        // no post-conditions in allow mode
        (
            true,
            vec![],
            TransactionPostConditionMode::Allow,
            origin.clone(),
        ),
        // one post-condition on origin in allow mode
        (
            true,
            vec![TransactionPostCondition::Nonfungible(
                PostConditionPrincipal::Origin,
                asset_info.clone(),
                Value::Int(1),
                NonfungibleConditionCode::Sent,
            )],
            TransactionPostConditionMode::Allow,
            origin.clone(),
        ),
        (
            true,
            vec![TransactionPostCondition::Nonfungible(
                PostConditionPrincipal::Origin,
                asset_info.clone(),
                Value::Int(2),
                NonfungibleConditionCode::Sent,
            )],
            TransactionPostConditionMode::Allow,
            origin.clone(),
        ),
        // two post-conditions on origin in allow mode
        (
            true,
            vec![
                TransactionPostCondition::Nonfungible(
                    PostConditionPrincipal::Origin,
                    asset_info.clone(),
                    Value::Int(1),
                    NonfungibleConditionCode::Sent,
                ),
                TransactionPostCondition::Nonfungible(
                    PostConditionPrincipal::Origin,
                    asset_info.clone(),
                    Value::Int(2),
                    NonfungibleConditionCode::Sent,
                ),
            ],
            TransactionPostConditionMode::Allow,
            origin.clone(),
        ),
        // post-condition on a non-sent asset
        (
            true,
            vec![
                TransactionPostCondition::Nonfungible(
                    PostConditionPrincipal::Origin,
                    asset_info.clone(),
                    Value::Int(1),
                    NonfungibleConditionCode::Sent,
                ),
                TransactionPostCondition::Nonfungible(
                    PostConditionPrincipal::Origin,
                    asset_info.clone(),
                    Value::Int(2),
                    NonfungibleConditionCode::Sent,
                ),
                TransactionPostCondition::Nonfungible(
                    PostConditionPrincipal::Origin,
                    asset_info.clone(),
                    Value::Int(3),
                    NonfungibleConditionCode::NotSent,
                ),
            ],
            TransactionPostConditionMode::Allow,
            origin.clone(),
        ),
        // one post-condition on origin in allow mode, explicit origin
        (
            true,
            vec![TransactionPostCondition::Nonfungible(
                PostConditionPrincipal::Standard(addr.clone()),
                asset_info.clone(),
                Value::Int(1),
                NonfungibleConditionCode::Sent,
            )],
            TransactionPostConditionMode::Allow,
            origin.clone(),
        ),
        (
            true,
            vec![TransactionPostCondition::Nonfungible(
                PostConditionPrincipal::Standard(addr.clone()),
                asset_info.clone(),
                Value::Int(2),
                NonfungibleConditionCode::Sent,
            )],
            TransactionPostConditionMode::Allow,
            origin.clone(),
        ),
        // two post-conditions on origin in allow mode, explicit origin
        (
            true,
            vec![
                TransactionPostCondition::Nonfungible(
                    PostConditionPrincipal::Standard(addr.clone()),
                    asset_info.clone(),
                    Value::Int(1),
                    NonfungibleConditionCode::Sent,
                ),
                TransactionPostCondition::Nonfungible(
                    PostConditionPrincipal::Standard(addr.clone()),
                    asset_info.clone(),
                    Value::Int(2),
                    NonfungibleConditionCode::Sent,
                ),
            ],
            TransactionPostConditionMode::Allow,
            origin.clone(),
        ),
        // post-condition on a non-sent asset, explicit origin
        (
            true,
            vec![
                TransactionPostCondition::Nonfungible(
                    PostConditionPrincipal::Standard(addr.clone()),
                    asset_info.clone(),
                    Value::Int(1),
                    NonfungibleConditionCode::Sent,
                ),
                TransactionPostCondition::Nonfungible(
                    PostConditionPrincipal::Standard(addr.clone()),
                    asset_info.clone(),
                    Value::Int(2),
                    NonfungibleConditionCode::Sent,
                ),
                TransactionPostCondition::Nonfungible(
                    PostConditionPrincipal::Standard(addr.clone()),
                    asset_info.clone(),
                    Value::Int(3),
                    NonfungibleConditionCode::NotSent,
                ),
            ],
            TransactionPostConditionMode::Allow,
            origin.clone(),
        ),
        // no post-conditions in deny mode
        (
            false,
            vec![],
            TransactionPostConditionMode::Deny,
            origin.clone(),
        ),
        // one post-condition on origin in deny mode
        (
            false,
            vec![TransactionPostCondition::Nonfungible(
                PostConditionPrincipal::Origin,
                asset_info.clone(),
                Value::Int(1),
                NonfungibleConditionCode::Sent,
            )],
            TransactionPostConditionMode::Deny,
            origin.clone(),
        ),
        (
            false,
            vec![TransactionPostCondition::Nonfungible(
                PostConditionPrincipal::Origin,
                asset_info.clone(),
                Value::Int(2),
                NonfungibleConditionCode::Sent,
            )],
            TransactionPostConditionMode::Deny,
            origin.clone(),
        ),
        // two post-conditions on origin in allow mode
        (
            true,
            vec![
                TransactionPostCondition::Nonfungible(
                    PostConditionPrincipal::Origin,
                    asset_info.clone(),
                    Value::Int(1),
                    NonfungibleConditionCode::Sent,
                ),
                TransactionPostCondition::Nonfungible(
                    PostConditionPrincipal::Origin,
                    asset_info.clone(),
                    Value::Int(2),
                    NonfungibleConditionCode::Sent,
                ),
            ],
            TransactionPostConditionMode::Allow,
            origin.clone(),
        ),
        // post-condition on a non-sent asset
        (
            true,
            vec![
                TransactionPostCondition::Nonfungible(
                    PostConditionPrincipal::Origin,
                    asset_info.clone(),
                    Value::Int(1),
                    NonfungibleConditionCode::Sent,
                ),
                TransactionPostCondition::Nonfungible(
                    PostConditionPrincipal::Origin,
                    asset_info.clone(),
                    Value::Int(2),
                    NonfungibleConditionCode::Sent,
                ),
                TransactionPostCondition::Nonfungible(
                    PostConditionPrincipal::Origin,
                    asset_info.clone(),
                    Value::Int(3),
                    NonfungibleConditionCode::NotSent,
                ),
            ],
            TransactionPostConditionMode::Deny,
            origin.clone(),
        ),
        // one post-condition on origin in deny mode, explicit origin
        (
            false,
            vec![TransactionPostCondition::Nonfungible(
                PostConditionPrincipal::Standard(addr.clone()),
                asset_info.clone(),
                Value::Int(1),
                NonfungibleConditionCode::Sent,
            )],
            TransactionPostConditionMode::Deny,
            origin.clone(),
        ),
        (
            false,
            vec![TransactionPostCondition::Nonfungible(
                PostConditionPrincipal::Standard(addr.clone()),
                asset_info.clone(),
                Value::Int(2),
                NonfungibleConditionCode::Sent,
            )],
            TransactionPostConditionMode::Deny,
            origin.clone(),
        ),
        // two post-conditions on origin in allow mode, explicit origin
        (
            true,
            vec![
                TransactionPostCondition::Nonfungible(
                    PostConditionPrincipal::Standard(addr.clone()),
                    asset_info.clone(),
                    Value::Int(1),
                    NonfungibleConditionCode::Sent,
                ),
                TransactionPostCondition::Nonfungible(
                    PostConditionPrincipal::Standard(addr.clone()),
                    asset_info.clone(),
                    Value::Int(2),
                    NonfungibleConditionCode::Sent,
                ),
            ],
            TransactionPostConditionMode::Allow,
            origin.clone(),
        ),
        // post-condition on a non-sent asset, explicit origin
        (
            true,
            vec![
                TransactionPostCondition::Nonfungible(
                    PostConditionPrincipal::Standard(addr.clone()),
                    asset_info.clone(),
                    Value::Int(1),
                    NonfungibleConditionCode::Sent,
                ),
                TransactionPostCondition::Nonfungible(
                    PostConditionPrincipal::Standard(addr.clone()),
                    asset_info.clone(),
                    Value::Int(2),
                    NonfungibleConditionCode::Sent,
                ),
                TransactionPostCondition::Nonfungible(
                    PostConditionPrincipal::Standard(addr.clone()),
                    asset_info,
                    Value::Int(3),
                    NonfungibleConditionCode::NotSent,
                ),
            ],
            TransactionPostConditionMode::Deny,
            origin.clone(),
        ),
    ];

    for test in tests.iter() {
        let expected_result = test.0;
        let post_conditions = &test.1;
        let mode = &test.2;
        let origin = &test.3;

        let result = check_transaction_postconditions(
            post_conditions,
            mode,
            origin,
            &nft_transfer_2,
            StacksEpochId::latest(),
            Txid([0; 32]),
        )
        .unwrap();
        assert_eq!(
            result.is_none(),
            expected_result,
            "test failed:\nasset map: {nft_transfer_2:?}\nscenario: {test:?}"
        );
    }
}

#[test]
fn test_check_postconditions_originator_mode_coverage() {
    let privk = StacksPrivateKey::from_hex(
        "6d430bb91222408e7706c9001cfaeb91b08c2be6d5ac95779ab52c6b431950e001",
    )
    .unwrap();
    let auth = TransactionAuth::from_p2pkh(&privk).unwrap();
    let origin_addr = auth.origin().address_testnet();
    let origin = origin_addr.to_account_principal();
    let other_addr = StacksAddress::new(1, Hash160([0xee; 20])).unwrap();
    let other = other_addr.to_account_principal();

    let mut mixed_stx_transfer = AssetMap::new();
    mixed_stx_transfer.add_stx_transfer(&origin, 50).unwrap();
    mixed_stx_transfer.add_stx_transfer(&other, 75).unwrap();

    let tests = vec![
        // in originator mode, uncovered transfers from non-origin principals are permitted
        (
            true,
            vec![TransactionPostCondition::STX(
                PostConditionPrincipal::Origin,
                FungibleConditionCode::SentEq,
                50,
            )],
            TransactionPostConditionMode::Originator,
        ),
        // in originator mode, uncovered transfers from origin are forbidden
        (
            false,
            vec![TransactionPostCondition::STX(
                PostConditionPrincipal::Standard(other_addr.clone()),
                FungibleConditionCode::SentEq,
                75,
            )],
            TransactionPostConditionMode::Originator,
        ),
        // in originator mode, covering both should pass
        (
            true,
            vec![
                TransactionPostCondition::STX(
                    PostConditionPrincipal::Origin,
                    FungibleConditionCode::SentEq,
                    50,
                ),
                TransactionPostCondition::STX(
                    PostConditionPrincipal::Standard(other_addr.clone()),
                    FungibleConditionCode::SentEq,
                    75,
                ),
            ],
            TransactionPostConditionMode::Originator,
        ),
        // sanity check: deny mode still requires all principals to be covered
        (
            false,
            vec![TransactionPostCondition::STX(
                PostConditionPrincipal::Origin,
                FungibleConditionCode::SentEq,
                50,
            )],
            TransactionPostConditionMode::Deny,
        ),
    ];

    for (expected_result, post_conditions, mode) in tests {
        let result = check_transaction_postconditions(
            &post_conditions,
            &mode,
            &origin,
            &mixed_stx_transfer,
            StacksEpochId::latest(),
            Txid([0; 32]),
        )
        .unwrap();
        assert_eq!(
            result.is_none(),
            expected_result,
            "test failed:\nasset map: {mixed_stx_transfer:?}\nscenario: {post_conditions:?} mode={mode:?}"
        );
    }
}

#[test]
fn test_check_postconditions_staking() {
    let privk = StacksPrivateKey::from_hex(
        "6d430bb91222408e7706c9001cfaeb91b08c2be6d5ac95779ab52c6b431950e001",
    )
    .unwrap();
    let auth = TransactionAuth::from_p2pkh(&privk).unwrap();
    let origin_addr = auth.origin().address_testnet();
    let origin = origin_addr.to_account_principal();

    // Asset map in which the origin staked 100 uSTX.
    let mut stacked = AssetMap::new();
    stacked
        .add_stacking(&origin, 100, StacksEpochId::Epoch40)
        .unwrap();

    // (expected_pass, post_conditions, mode, epoch)
    let tests = vec![
        // Allow mode: uncovered stacking is permitted.
        (
            true,
            vec![],
            TransactionPostConditionMode::Allow,
            StacksEpochId::Epoch40,
        ),
        // Deny mode: uncovered stacking is forbidden.
        (
            false,
            vec![],
            TransactionPostConditionMode::Deny,
            StacksEpochId::Epoch40,
        ),
        // Deny mode with a covering allowance (stacked <= limit) passes.
        (
            true,
            vec![TransactionPostCondition::Staking(
                PostConditionPrincipal::Origin,
                FungibleConditionCode::SentLe,
                100,
            )],
            TransactionPostConditionMode::Deny,
            StacksEpochId::Epoch40,
        ),
        // A limit that is too small (stacked > limit) fails the condition.
        (
            false,
            vec![TransactionPostCondition::Staking(
                PostConditionPrincipal::Origin,
                FungibleConditionCode::SentLe,
                99,
            )],
            TransactionPostConditionMode::Allow,
            StacksEpochId::Epoch40,
        ),
        // SentEq matching the exact stacked amount passes even in Deny mode.
        (
            true,
            vec![TransactionPostCondition::Staking(
                PostConditionPrincipal::Origin,
                FungibleConditionCode::SentEq,
                100,
            )],
            TransactionPostConditionMode::Deny,
            StacksEpochId::Epoch40,
        ),
        // Before epoch 4.0, stacking is not enforced even in Deny mode.
        (
            true,
            vec![],
            TransactionPostConditionMode::Deny,
            StacksEpochId::Epoch33,
        ),
    ];

    for (expected_pass, post_conditions, mode, epoch) in tests {
        let result = check_transaction_postconditions(
            &post_conditions,
            &mode,
            &origin,
            &stacked,
            epoch,
            Txid([0; 32]),
        )
        .unwrap();
        assert_eq!(
            result.is_none(),
            expected_pass,
            "test failed:\nscenario: {post_conditions:?} mode={mode:?} epoch={epoch:?}"
        );
    }
}

#[test]
fn test_check_postconditions_pox() {
    let privk = StacksPrivateKey::from_hex(
        "6d430bb91222408e7706c9001cfaeb91b08c2be6d5ac95779ab52c6b431950e001",
    )
    .unwrap();
    let auth = TransactionAuth::from_p2pkh(&privk).unwrap();
    let origin_addr = auth.origin().address_testnet();
    let origin = origin_addr.to_account_principal();

    // Asset map in which the origin performed a position-altering PoX action.
    let mut pox_acted = AssetMap::new();
    pox_acted.add_pox_action(&origin);

    let forbid_pox = || {
        TransactionPostCondition::Pox(
            PostConditionPrincipal::Origin,
            PoxConditionCode::NotPerformed,
        )
    };
    let allow_pox = || {
        TransactionPostCondition::Pox(
            PostConditionPrincipal::Origin,
            PoxConditionCode::MaybePerformed,
        )
    };
    let require_pox = || {
        TransactionPostCondition::Pox(PostConditionPrincipal::Origin, PoxConditionCode::Performed)
    };

    // (expected_pass, post_conditions, mode, epoch)
    let tests = vec![
        // Allow mode: uncovered unstaking is permitted.
        (
            true,
            vec![],
            TransactionPostConditionMode::Allow,
            StacksEpochId::Epoch40,
        ),
        // Deny mode: uncovered unstaking is forbidden.
        (
            false,
            vec![],
            TransactionPostConditionMode::Deny,
            StacksEpochId::Epoch40,
        ),
        // `MaybeUnstaked` opts in, so an unstake passes even in Deny mode.
        (
            true,
            vec![allow_pox()],
            TransactionPostConditionMode::Deny,
            StacksEpochId::Epoch40,
        ),
        // `Unstaked` (must) is satisfied since an unstake occurred.
        (
            true,
            vec![require_pox()],
            TransactionPostConditionMode::Deny,
            StacksEpochId::Epoch40,
        ),
        // `NotUnstaked` fails in allow mode because an unstake occurred.
        (
            false,
            vec![forbid_pox()],
            TransactionPostConditionMode::Allow,
            StacksEpochId::Epoch40,
        ),
        // Before epoch 4.0, unstaking is not enforced even in Deny mode.
        (
            true,
            vec![],
            TransactionPostConditionMode::Deny,
            StacksEpochId::Epoch33,
        ),
    ];

    for (expected_pass, post_conditions, mode, epoch) in tests {
        let result = check_transaction_postconditions(
            &post_conditions,
            &mode,
            &origin,
            &pox_acted,
            epoch,
            Txid([0; 32]),
        )
        .unwrap();
        assert_eq!(
            result.is_none(),
            expected_pass,
            "test failed:\nscenario: {post_conditions:?} mode={mode:?} epoch={epoch:?}"
        );
    }

    // `NotUnstaked` passes when no unstake occurred.
    let empty = AssetMap::new();
    let result = check_transaction_postconditions(
        &[forbid_pox()],
        &TransactionPostConditionMode::Allow,
        &origin,
        &empty,
        StacksEpochId::Epoch40,
        Txid([0; 32]),
    )
    .unwrap();
    assert!(result.is_none());
}

#[test]
fn test_check_postconditions_nft_maybe_sent() {
    let privk = StacksPrivateKey::from_hex(
        "6d430bb91222408e7706c9001cfaeb91b08c2be6d5ac95779ab52c6b431950e001",
    )
    .unwrap();
    let auth = TransactionAuth::from_p2pkh(&privk).unwrap();
    let origin_addr = auth.origin().address_testnet();
    let origin = origin_addr.to_account_principal();
    let contract_addr = StacksAddress::new(1, Hash160([0x01; 20])).unwrap();

    let asset_info = AssetInfo {
        contract_address: contract_addr.clone(),
        contract_name: ContractName::try_from("hello-world").unwrap(),
        asset_name: ClarityName::try_from("test-asset").unwrap(),
    };

    let asset_id = AssetIdentifier {
        contract_identifier: QualifiedContractIdentifier::new(
            StandardPrincipalData::from(asset_info.contract_address.clone()),
            asset_info.contract_name.clone(),
        ),
        asset_name: asset_info.asset_name.clone(),
    };

    let mut nft_sent_value_1 = AssetMap::new();
    nft_sent_value_1.add_asset_transfer(&origin, asset_id.clone(), Value::Int(1));

    let nft_not_sent = AssetMap::new();

    let mut nft_sent_value_2 = AssetMap::new();
    nft_sent_value_2.add_asset_transfer(&origin, asset_id, Value::Int(2));

    let tests = vec![
        // MAY-SEND should pass if the specified NFT is sent
        (
            true,
            vec![TransactionPostCondition::Nonfungible(
                PostConditionPrincipal::Origin,
                asset_info.clone(),
                Value::Int(1),
                NonfungibleConditionCode::MaybeSent,
            )],
            TransactionPostConditionMode::Deny,
            &nft_sent_value_1,
        ),
        // MAY-SEND should also pass if the specified NFT is not sent
        (
            true,
            vec![TransactionPostCondition::Nonfungible(
                PostConditionPrincipal::Origin,
                asset_info.clone(),
                Value::Int(1),
                NonfungibleConditionCode::MaybeSent,
            )],
            TransactionPostConditionMode::Deny,
            &nft_not_sent,
        ),
        // MAY-SEND covers only the specific NFT instance (value 1 does not cover value 2)
        (
            false,
            vec![TransactionPostCondition::Nonfungible(
                PostConditionPrincipal::Origin,
                asset_info.clone(),
                Value::Int(1),
                NonfungibleConditionCode::MaybeSent,
            )],
            TransactionPostConditionMode::Deny,
            &nft_sent_value_2,
        ),
        // allow mode remains permissive regardless
        (
            true,
            vec![TransactionPostCondition::Nonfungible(
                PostConditionPrincipal::Origin,
                asset_info,
                Value::Int(1),
                NonfungibleConditionCode::MaybeSent,
            )],
            TransactionPostConditionMode::Allow,
            &nft_sent_value_2,
        ),
    ];

    for (expected_result, post_conditions, mode, asset_map) in tests {
        let result = check_transaction_postconditions(
            &post_conditions,
            &mode,
            &origin,
            asset_map,
            StacksEpochId::latest(),
            Txid([0; 32]),
        )
        .unwrap();
        assert_eq!(
            result.is_none(),
            expected_result,
            "test failed:\nasset map: {asset_map:?}\nscenario: {post_conditions:?} mode={mode:?}"
        );
    }
}

proptest! {
    #[tag(t_prop)]
    #[test]
    fn proptest_check_postconditions_originator_mode_coverage(
        origin_sent in 1u64..10_000,
        other_sent in 1u64..10_000,
        include_origin_check in any::<bool>(),
        include_other_check in any::<bool>(),
        origin_check_matches in any::<bool>(),
    ) {
        let privk = StacksPrivateKey::from_hex(
            "6d430bb91222408e7706c9001cfaeb91b08c2be6d5ac95779ab52c6b431950e001",
        )
        .unwrap();
        let auth = TransactionAuth::from_p2pkh(&privk).unwrap();
        let origin_addr = auth.origin().address_testnet();
        let origin = origin_addr.to_account_principal();
        let other_addr = StacksAddress::new(1, Hash160([0xee; 20])).unwrap();
        let other = other_addr.to_account_principal();

        let mut asset_map = AssetMap::new();
        asset_map
            .add_stx_transfer(&origin, u128::from(origin_sent))
            .unwrap();
        asset_map
            .add_stx_transfer(&other, u128::from(other_sent))
            .unwrap();

        let mut post_conditions = vec![];
        if include_origin_check {
            let checked_amt = if origin_check_matches {
                origin_sent
            } else {
                origin_sent.saturating_add(1)
            };
            post_conditions.push(TransactionPostCondition::STX(
                PostConditionPrincipal::Origin,
                FungibleConditionCode::SentEq,
                checked_amt,
            ));
        }
        if include_other_check {
            post_conditions.push(TransactionPostCondition::STX(
                PostConditionPrincipal::Standard(other_addr.clone()),
                FungibleConditionCode::SentEq,
                other_sent,
            ));
        }

        let result = check_transaction_postconditions(
            &post_conditions,
            &TransactionPostConditionMode::Originator,
            &origin,
            &asset_map,
            StacksEpochId::latest(),
            Txid([0; 32]),
        )
        .unwrap();

        let expected_pass = include_origin_check && origin_check_matches;
        prop_assert_eq!(result.is_none(), expected_pass);
    }
}

proptest! {
    #[tag(t_prop)]
    #[test]
    fn proptest_check_postconditions_nft_maybe_sent_variety(
        checked_id in 0u16..500,
        moved_id in 0u16..500,
        move_asset in any::<bool>(),
        mode_is_allow in any::<bool>(),
    ) {
        let privk = StacksPrivateKey::from_hex(
            "6d430bb91222408e7706c9001cfaeb91b08c2be6d5ac95779ab52c6b431950e001",
        )
        .unwrap();
        let auth = TransactionAuth::from_p2pkh(&privk).unwrap();
        let origin_addr = auth.origin().address_testnet();
        let origin = origin_addr.to_account_principal();

        let asset_info = AssetInfo {
            contract_address: StacksAddress::new(1, Hash160([0x01; 20])).unwrap(),
            contract_name: ContractName::try_from("hello-world").unwrap(),
            asset_name: ClarityName::try_from("test-asset").unwrap(),
        };
        let asset_id = AssetIdentifier {
            contract_identifier: QualifiedContractIdentifier::new(
                StandardPrincipalData::from(asset_info.contract_address.clone()),
                asset_info.contract_name.clone(),
            ),
            asset_name: asset_info.asset_name.clone(),
        };

        let mut asset_map = AssetMap::new();
        if move_asset {
            asset_map.add_asset_transfer(
                &origin,
                asset_id,
                Value::UInt(u128::from(moved_id)),
            );
        }

        let mode = if mode_is_allow {
            TransactionPostConditionMode::Allow
        } else {
            TransactionPostConditionMode::Deny
        };

        let post_conditions = vec![TransactionPostCondition::Nonfungible(
            PostConditionPrincipal::Origin,
            asset_info,
            Value::UInt(u128::from(checked_id)),
            NonfungibleConditionCode::MaybeSent,
        )];

        let result = check_transaction_postconditions(
            &post_conditions,
            &mode,
            &origin,
            &asset_map,
            StacksEpochId::latest(),
            Txid([0; 32]),
        )
        .unwrap();

        let expected_pass = if mode_is_allow {
            true
        } else {
            !move_asset || checked_id == moved_id
        };
        prop_assert_eq!(result.is_none(), expected_pass);
    }
}

#[test]
fn test_check_postconditions_stx() {
    let privk = StacksPrivateKey::from_hex(
        "6d430bb91222408e7706c9001cfaeb91b08c2be6d5ac95779ab52c6b431950e001",
    )
    .unwrap();
    let auth = TransactionAuth::from_p2pkh(&privk).unwrap();
    let addr = auth.origin().address_testnet();
    let origin = addr.to_account_principal();
    let _recv_addr = StacksAddress::new(1, Hash160([0xff; 20])).unwrap();

    // stx-transfer for 123 microstx
    let mut stx_asset_map = AssetMap::new();
    stx_asset_map.add_stx_transfer(&origin, 123).unwrap();

    // stx-burn for 123 microstx
    let mut stx_burn_asset_map = AssetMap::new();
    stx_burn_asset_map.add_stx_burn(&origin, 123).unwrap();

    // stx-transfer and stx-burn for a total of 123 microstx
    let mut stx_transfer_burn_asset_map = AssetMap::new();
    stx_transfer_burn_asset_map
        .add_stx_transfer(&origin, 100)
        .unwrap();
    stx_transfer_burn_asset_map
        .add_stx_burn(&origin, 23)
        .unwrap();

    let tests = vec![
        // no post-conditions in allow mode
        (
            true,
            vec![],
            TransactionPostConditionMode::Allow,
            origin.clone(),
        ), // should pass
        // post-conditions on origin in allow mode
        (
            true,
            vec![TransactionPostCondition::STX(
                PostConditionPrincipal::Origin,
                FungibleConditionCode::SentEq,
                123,
            )],
            TransactionPostConditionMode::Allow,
            origin.clone(),
        ), // should pass
        (
            true,
            vec![TransactionPostCondition::STX(
                PostConditionPrincipal::Origin,
                FungibleConditionCode::SentLe,
                123,
            )],
            TransactionPostConditionMode::Allow,
            origin.clone(),
        ), // should pass
        (
            true,
            vec![TransactionPostCondition::STX(
                PostConditionPrincipal::Origin,
                FungibleConditionCode::SentGe,
                123,
            )],
            TransactionPostConditionMode::Allow,
            origin.clone(),
        ), // should pass
        (
            true,
            vec![TransactionPostCondition::STX(
                PostConditionPrincipal::Origin,
                FungibleConditionCode::SentLt,
                124,
            )],
            TransactionPostConditionMode::Allow,
            origin.clone(),
        ), // should pass
        (
            true,
            vec![TransactionPostCondition::STX(
                PostConditionPrincipal::Origin,
                FungibleConditionCode::SentGt,
                122,
            )],
            TransactionPostConditionMode::Allow,
            origin.clone(),
        ), // should pass
        // post-conditions with an explicitly-set address in allow mode
        (
            true,
            vec![TransactionPostCondition::STX(
                PostConditionPrincipal::Standard(addr.clone()),
                FungibleConditionCode::SentEq,
                123,
            )],
            TransactionPostConditionMode::Allow,
            origin.clone(),
        ), // should pass
        (
            true,
            vec![TransactionPostCondition::STX(
                PostConditionPrincipal::Standard(addr.clone()),
                FungibleConditionCode::SentLe,
                123,
            )],
            TransactionPostConditionMode::Allow,
            origin.clone(),
        ), // should pass
        (
            true,
            vec![TransactionPostCondition::STX(
                PostConditionPrincipal::Standard(addr.clone()),
                FungibleConditionCode::SentGe,
                123,
            )],
            TransactionPostConditionMode::Allow,
            origin.clone(),
        ), // should pass
        (
            true,
            vec![TransactionPostCondition::STX(
                PostConditionPrincipal::Standard(addr.clone()),
                FungibleConditionCode::SentLt,
                124,
            )],
            TransactionPostConditionMode::Allow,
            origin.clone(),
        ), // should pass
        (
            true,
            vec![TransactionPostCondition::STX(
                PostConditionPrincipal::Standard(addr.clone()),
                FungibleConditionCode::SentGt,
                122,
            )],
            TransactionPostConditionMode::Allow,
            origin.clone(),
        ), // should pass
        // post-conditions with an unrelated contract address in allow mode
        (
            true,
            vec![TransactionPostCondition::STX(
                PostConditionPrincipal::Contract(
                    addr.clone(),
                    ContractName::try_from("hello-world").unwrap(),
                ),
                FungibleConditionCode::SentEq,
                0,
            )],
            TransactionPostConditionMode::Allow,
            origin.clone(),
        ), // should pass
        (
            true,
            vec![TransactionPostCondition::STX(
                PostConditionPrincipal::Contract(
                    addr.clone(),
                    ContractName::try_from("hello-world").unwrap(),
                ),
                FungibleConditionCode::SentLe,
                0,
            )],
            TransactionPostConditionMode::Allow,
            origin.clone(),
        ), // should pass
        (
            true,
            vec![TransactionPostCondition::STX(
                PostConditionPrincipal::Contract(
                    addr.clone(),
                    ContractName::try_from("hello-world").unwrap(),
                ),
                FungibleConditionCode::SentGe,
                0,
            )],
            TransactionPostConditionMode::Allow,
            origin.clone(),
        ), // should pass
        (
            true,
            vec![TransactionPostCondition::STX(
                PostConditionPrincipal::Contract(
                    addr.clone(),
                    ContractName::try_from("hello-world").unwrap(),
                ),
                FungibleConditionCode::SentLt,
                1,
            )],
            TransactionPostConditionMode::Allow,
            origin.clone(),
        ), // should pass
        // post-conditions with both the origin and an unrelated contract address in allow mode
        (
            true,
            vec![
                TransactionPostCondition::STX(
                    PostConditionPrincipal::Contract(
                        addr.clone(),
                        ContractName::try_from("hello-world").unwrap(),
                    ),
                    FungibleConditionCode::SentEq,
                    0,
                ),
                TransactionPostCondition::STX(
                    PostConditionPrincipal::Origin,
                    FungibleConditionCode::SentEq,
                    123,
                ),
            ],
            TransactionPostConditionMode::Allow,
            origin.clone(),
        ), // should pass
        (
            true,
            vec![
                TransactionPostCondition::STX(
                    PostConditionPrincipal::Contract(
                        addr.clone(),
                        ContractName::try_from("hello-world").unwrap(),
                    ),
                    FungibleConditionCode::SentLe,
                    0,
                ),
                TransactionPostCondition::STX(
                    PostConditionPrincipal::Origin,
                    FungibleConditionCode::SentLe,
                    123,
                ),
            ],
            TransactionPostConditionMode::Allow,
            origin.clone(),
        ), // should pass
        (
            true,
            vec![
                TransactionPostCondition::STX(
                    PostConditionPrincipal::Contract(
                        addr.clone(),
                        ContractName::try_from("hello-world").unwrap(),
                    ),
                    FungibleConditionCode::SentGe,
                    0,
                ),
                TransactionPostCondition::STX(
                    PostConditionPrincipal::Origin,
                    FungibleConditionCode::SentGe,
                    123,
                ),
            ],
            TransactionPostConditionMode::Allow,
            origin.clone(),
        ), // should pass
        (
            true,
            vec![
                TransactionPostCondition::STX(
                    PostConditionPrincipal::Contract(
                        addr.clone(),
                        ContractName::try_from("hello-world").unwrap(),
                    ),
                    FungibleConditionCode::SentLt,
                    1,
                ),
                TransactionPostCondition::STX(
                    PostConditionPrincipal::Origin,
                    FungibleConditionCode::SentLt,
                    124,
                ),
            ],
            TransactionPostConditionMode::Allow,
            origin.clone(),
        ), // should pass
        // post-conditions that fail since the amount is wrong
        (
            false,
            vec![TransactionPostCondition::STX(
                PostConditionPrincipal::Origin,
                FungibleConditionCode::SentEq,
                124,
            )],
            TransactionPostConditionMode::Allow,
            origin.clone(),
        ), // should fail
        (
            false,
            vec![TransactionPostCondition::STX(
                PostConditionPrincipal::Origin,
                FungibleConditionCode::SentLe,
                122,
            )],
            TransactionPostConditionMode::Allow,
            origin.clone(),
        ), // should fail
        (
            false,
            vec![TransactionPostCondition::STX(
                PostConditionPrincipal::Origin,
                FungibleConditionCode::SentGe,
                124,
            )],
            TransactionPostConditionMode::Allow,
            origin.clone(),
        ), // should fail
        (
            false,
            vec![TransactionPostCondition::STX(
                PostConditionPrincipal::Origin,
                FungibleConditionCode::SentLt,
                122,
            )],
            TransactionPostConditionMode::Allow,
            origin.clone(),
        ), // should fail
        (
            false,
            vec![TransactionPostCondition::STX(
                PostConditionPrincipal::Origin,
                FungibleConditionCode::SentGt,
                124,
            )],
            TransactionPostConditionMode::Allow,
            origin.clone(),
        ), // should fail
        // no post-conditions in deny mode (should fail)
        (
            false,
            vec![],
            TransactionPostConditionMode::Deny,
            origin.clone(),
        ), // should fail
        // post-conditions on origin in deny mode (should all pass since origin is specified
        (
            true,
            vec![TransactionPostCondition::STX(
                PostConditionPrincipal::Origin,
                FungibleConditionCode::SentEq,
                123,
            )],
            TransactionPostConditionMode::Deny,
            origin.clone(),
        ), // should pass
        (
            true,
            vec![TransactionPostCondition::STX(
                PostConditionPrincipal::Origin,
                FungibleConditionCode::SentLe,
                123,
            )],
            TransactionPostConditionMode::Deny,
            origin.clone(),
        ), // should pass
        (
            true,
            vec![TransactionPostCondition::STX(
                PostConditionPrincipal::Origin,
                FungibleConditionCode::SentGe,
                123,
            )],
            TransactionPostConditionMode::Deny,
            origin.clone(),
        ), // should pass
        (
            true,
            vec![TransactionPostCondition::STX(
                PostConditionPrincipal::Origin,
                FungibleConditionCode::SentLt,
                124,
            )],
            TransactionPostConditionMode::Deny,
            origin.clone(),
        ), // should pass
        (
            true,
            vec![TransactionPostCondition::STX(
                PostConditionPrincipal::Origin,
                FungibleConditionCode::SentGt,
                122,
            )],
            TransactionPostConditionMode::Deny,
            origin.clone(),
        ), // should pass
        // post-conditions with an explicitly-set address in deny mode (should all pass since
        // address matches the address in the asset map)
        (
            true,
            vec![TransactionPostCondition::STX(
                PostConditionPrincipal::Standard(addr.clone()),
                FungibleConditionCode::SentEq,
                123,
            )],
            TransactionPostConditionMode::Deny,
            origin.clone(),
        ), // should pass
        (
            true,
            vec![TransactionPostCondition::STX(
                PostConditionPrincipal::Standard(addr.clone()),
                FungibleConditionCode::SentLe,
                123,
            )],
            TransactionPostConditionMode::Deny,
            origin.clone(),
        ), // should pass
        (
            true,
            vec![TransactionPostCondition::STX(
                PostConditionPrincipal::Standard(addr.clone()),
                FungibleConditionCode::SentGe,
                123,
            )],
            TransactionPostConditionMode::Deny,
            origin.clone(),
        ), // should pass
        (
            true,
            vec![TransactionPostCondition::STX(
                PostConditionPrincipal::Standard(addr.clone()),
                FungibleConditionCode::SentLt,
                124,
            )],
            TransactionPostConditionMode::Deny,
            origin.clone(),
        ), // should pass
        (
            true,
            vec![TransactionPostCondition::STX(
                PostConditionPrincipal::Standard(addr.clone()),
                FungibleConditionCode::SentGt,
                122,
            )],
            TransactionPostConditionMode::Deny,
            origin.clone(),
        ), // should pass
        // post-conditions with an unrelated contract address in allow mode, with check on
        // origin (should all pass)
        (
            true,
            vec![
                TransactionPostCondition::STX(
                    PostConditionPrincipal::Contract(
                        addr.clone(),
                        ContractName::try_from("hello-world").unwrap(),
                    ),
                    FungibleConditionCode::SentEq,
                    0,
                ),
                TransactionPostCondition::STX(
                    PostConditionPrincipal::Origin,
                    FungibleConditionCode::SentEq,
                    123,
                ),
            ],
            TransactionPostConditionMode::Allow,
            origin.clone(),
        ), // should fail
        (
            true,
            vec![
                TransactionPostCondition::STX(
                    PostConditionPrincipal::Contract(
                        addr.clone(),
                        ContractName::try_from("hello-world").unwrap(),
                    ),
                    FungibleConditionCode::SentLe,
                    0,
                ),
                TransactionPostCondition::STX(
                    PostConditionPrincipal::Origin,
                    FungibleConditionCode::SentEq,
                    123,
                ),
            ],
            TransactionPostConditionMode::Allow,
            origin.clone(),
        ), // should fail
        (
            true,
            vec![
                TransactionPostCondition::STX(
                    PostConditionPrincipal::Contract(
                        addr.clone(),
                        ContractName::try_from("hello-world").unwrap(),
                    ),
                    FungibleConditionCode::SentGe,
                    0,
                ),
                TransactionPostCondition::STX(
                    PostConditionPrincipal::Origin,
                    FungibleConditionCode::SentEq,
                    123,
                ),
            ],
            TransactionPostConditionMode::Allow,
            origin.clone(),
        ), // should fail
        (
            true,
            vec![
                TransactionPostCondition::STX(
                    PostConditionPrincipal::Contract(
                        addr.clone(),
                        ContractName::try_from("hello-world").unwrap(),
                    ),
                    FungibleConditionCode::SentLt,
                    1,
                ),
                TransactionPostCondition::STX(
                    PostConditionPrincipal::Origin,
                    FungibleConditionCode::SentEq,
                    123,
                ),
            ],
            TransactionPostConditionMode::Allow,
            origin.clone(),
        ), // should fail
        // post-conditions with an unrelated contract address in deny mode (should all fail
        // since stx-transfer isn't covered)
        (
            false,
            vec![TransactionPostCondition::STX(
                PostConditionPrincipal::Contract(
                    addr.clone(),
                    ContractName::try_from("hello-world").unwrap(),
                ),
                FungibleConditionCode::SentEq,
                0,
            )],
            TransactionPostConditionMode::Deny,
            origin.clone(),
        ), // should fail
        (
            false,
            vec![TransactionPostCondition::STX(
                PostConditionPrincipal::Contract(
                    addr.clone(),
                    ContractName::try_from("hello-world").unwrap(),
                ),
                FungibleConditionCode::SentLe,
                0,
            )],
            TransactionPostConditionMode::Deny,
            origin.clone(),
        ), // should fail
        (
            false,
            vec![TransactionPostCondition::STX(
                PostConditionPrincipal::Contract(
                    addr.clone(),
                    ContractName::try_from("hello-world").unwrap(),
                ),
                FungibleConditionCode::SentGe,
                0,
            )],
            TransactionPostConditionMode::Deny,
            origin.clone(),
        ), // should fail
        (
            false,
            vec![TransactionPostCondition::STX(
                PostConditionPrincipal::Contract(
                    addr.clone(),
                    ContractName::try_from("hello-world").unwrap(),
                ),
                FungibleConditionCode::SentLt,
                1,
            )],
            TransactionPostConditionMode::Deny,
            origin.clone(),
        ), // should fail
        // post-conditions with an unrelated contract address in deny mode, with check on
        // origin (should all pass)
        (
            true,
            vec![
                TransactionPostCondition::STX(
                    PostConditionPrincipal::Contract(
                        addr.clone(),
                        ContractName::try_from("hello-world").unwrap(),
                    ),
                    FungibleConditionCode::SentEq,
                    0,
                ),
                TransactionPostCondition::STX(
                    PostConditionPrincipal::Origin,
                    FungibleConditionCode::SentEq,
                    123,
                ),
            ],
            TransactionPostConditionMode::Deny,
            origin.clone(),
        ), // should fail
        (
            true,
            vec![
                TransactionPostCondition::STX(
                    PostConditionPrincipal::Contract(
                        addr.clone(),
                        ContractName::try_from("hello-world").unwrap(),
                    ),
                    FungibleConditionCode::SentLe,
                    0,
                ),
                TransactionPostCondition::STX(
                    PostConditionPrincipal::Origin,
                    FungibleConditionCode::SentEq,
                    123,
                ),
            ],
            TransactionPostConditionMode::Deny,
            origin.clone(),
        ), // should fail
        (
            true,
            vec![
                TransactionPostCondition::STX(
                    PostConditionPrincipal::Contract(
                        addr.clone(),
                        ContractName::try_from("hello-world").unwrap(),
                    ),
                    FungibleConditionCode::SentGe,
                    0,
                ),
                TransactionPostCondition::STX(
                    PostConditionPrincipal::Origin,
                    FungibleConditionCode::SentEq,
                    123,
                ),
            ],
            TransactionPostConditionMode::Deny,
            origin.clone(),
        ), // should fail
        (
            true,
            vec![
                TransactionPostCondition::STX(
                    PostConditionPrincipal::Contract(
                        addr.clone(),
                        ContractName::try_from("hello-world").unwrap(),
                    ),
                    FungibleConditionCode::SentLt,
                    1,
                ),
                TransactionPostCondition::STX(
                    PostConditionPrincipal::Origin,
                    FungibleConditionCode::SentEq,
                    123,
                ),
            ],
            TransactionPostConditionMode::Deny,
            origin.clone(),
        ), // should fail
        // post-conditions with both the origin and an unrelated contract address in deny mode (should all pass)
        (
            true,
            vec![
                TransactionPostCondition::STX(
                    PostConditionPrincipal::Contract(
                        addr.clone(),
                        ContractName::try_from("hello-world").unwrap(),
                    ),
                    FungibleConditionCode::SentEq,
                    0,
                ),
                TransactionPostCondition::STX(
                    PostConditionPrincipal::Origin,
                    FungibleConditionCode::SentEq,
                    123,
                ),
            ],
            TransactionPostConditionMode::Deny,
            origin.clone(),
        ), // should pass
        (
            true,
            vec![
                TransactionPostCondition::STX(
                    PostConditionPrincipal::Contract(
                        addr.clone(),
                        ContractName::try_from("hello-world").unwrap(),
                    ),
                    FungibleConditionCode::SentLe,
                    0,
                ),
                TransactionPostCondition::STX(
                    PostConditionPrincipal::Origin,
                    FungibleConditionCode::SentLe,
                    123,
                ),
            ],
            TransactionPostConditionMode::Deny,
            origin.clone(),
        ), // should pass
        (
            true,
            vec![
                TransactionPostCondition::STX(
                    PostConditionPrincipal::Contract(
                        addr.clone(),
                        ContractName::try_from("hello-world").unwrap(),
                    ),
                    FungibleConditionCode::SentGe,
                    0,
                ),
                TransactionPostCondition::STX(
                    PostConditionPrincipal::Origin,
                    FungibleConditionCode::SentGe,
                    123,
                ),
            ],
            TransactionPostConditionMode::Deny,
            origin.clone(),
        ), // should pass
        (
            true,
            vec![
                TransactionPostCondition::STX(
                    PostConditionPrincipal::Contract(
                        addr.clone(),
                        ContractName::try_from("hello-world").unwrap(),
                    ),
                    FungibleConditionCode::SentLt,
                    1,
                ),
                TransactionPostCondition::STX(
                    PostConditionPrincipal::Origin,
                    FungibleConditionCode::SentLt,
                    124,
                ),
            ],
            TransactionPostConditionMode::Deny,
            origin.clone(),
        ), // should pass
        // post-conditions that fail since the amount is wrong, even though all principals are
        // covered
        (
            false,
            vec![TransactionPostCondition::STX(
                PostConditionPrincipal::Origin,
                FungibleConditionCode::SentEq,
                124,
            )],
            TransactionPostConditionMode::Deny,
            origin.clone(),
        ), // should fail
        (
            false,
            vec![TransactionPostCondition::STX(
                PostConditionPrincipal::Origin,
                FungibleConditionCode::SentLe,
                122,
            )],
            TransactionPostConditionMode::Deny,
            origin.clone(),
        ), // should fail
        (
            false,
            vec![TransactionPostCondition::STX(
                PostConditionPrincipal::Origin,
                FungibleConditionCode::SentGe,
                124,
            )],
            TransactionPostConditionMode::Deny,
            origin.clone(),
        ), // should fail
        (
            false,
            vec![TransactionPostCondition::STX(
                PostConditionPrincipal::Origin,
                FungibleConditionCode::SentLt,
                122,
            )],
            TransactionPostConditionMode::Deny,
            origin.clone(),
        ), // should fail
        (
            false,
            vec![TransactionPostCondition::STX(
                PostConditionPrincipal::Origin,
                FungibleConditionCode::SentGt,
                124,
            )],
            TransactionPostConditionMode::Deny,
            origin.clone(),
        ), // should fail
    ];

    for asset_map in &[
        &stx_asset_map,
        &stx_burn_asset_map,
        &stx_transfer_burn_asset_map,
    ] {
        for test in tests.iter() {
            let expected_result = test.0;
            let post_conditions = &test.1;
            let post_condition_mode = &test.2;
            let origin_account = &test.3;

            let result = check_transaction_postconditions(
                post_conditions,
                post_condition_mode,
                origin_account,
                asset_map,
                StacksEpochId::latest(),
                Txid([0; 32]),
            )
            .unwrap();
            assert_eq!(
                result.is_none(),
                expected_result,
                "test failed:\nasset map: {asset_map:?}\nscenario: {test:?}"
            );
        }
    }
}
