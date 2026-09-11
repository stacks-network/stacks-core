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

use stacks_common::types::StacksEpochId;

use crate::effects::{AssetMap, AssetMapEntry, AssetMapError};
use crate::representations::ClarityName;
use crate::types::{AssetIdentifier, PrincipalData, QualifiedContractIdentifier, Value};

fn contract_principal(name: &str) -> PrincipalData {
    PrincipalData::Contract(QualifiedContractIdentifier::local(name).unwrap())
}

fn asset_identifier(contract_name: &str, asset_name: &str) -> AssetIdentifier {
    AssetIdentifier {
        contract_identifier: QualifiedContractIdentifier::local(contract_name).unwrap(),
        asset_name: ClarityName::try_from(asset_name.to_owned()).unwrap(),
    }
}

#[test]
fn merge_is_atomic_on_overflow() {
    let principal_1 = contract_principal("a");
    let principal_2 = contract_principal("b");
    let token = asset_identifier("token", "asset");
    let mut parent = AssetMap::new();
    let mut child = AssetMap::new();

    parent
        .add_token_transfer(&principal_1, token.clone(), 1)
        .unwrap();
    parent
        .add_token_transfer(&principal_2, token.clone(), u128::MAX)
        .unwrap();
    child
        .add_token_transfer(&principal_1, token.clone(), 1)
        .unwrap();
    child
        .add_token_transfer(&principal_2, token.clone(), 1)
        .unwrap();

    assert_eq!(
        parent
            .commit_other(child, StacksEpochId::Epoch30)
            .unwrap_err(),
        AssetMapError::AmountOverflow
    );
    assert_eq!(parent.get_fungible_tokens(&principal_1, &token), Some(1));
    assert_eq!(
        parent.get_fungible_tokens(&principal_2, &token),
        Some(u128::MAX)
    );
}

#[test]
fn merge_combines_recorded_asset_changes() {
    let principal_1 = contract_principal("a");
    let principal_2 = contract_principal("b");
    let principal_3 = contract_principal("c");
    let token = asset_identifier("token", "ft");
    let new_token = asset_identifier("new-token", "ft");
    let new_principal_token = asset_identifier("other-token", "ft");
    let nft = asset_identifier("token", "nft");
    let new_nft = asset_identifier("new-token", "nft");
    let new_principal_nft = asset_identifier("other-token", "nft");
    let mut parent = AssetMap::new();
    let mut child = AssetMap::new();

    parent
        .add_token_transfer(&principal_1, token.clone(), 10)
        .unwrap();
    child
        .add_token_transfer(&principal_1, token.clone(), 15)
        .unwrap();
    child
        .add_token_transfer(&principal_1, new_token.clone(), 1)
        .unwrap();
    child
        .add_token_transfer(&principal_2, new_principal_token.clone(), 10)
        .unwrap();
    child
        .add_token_transfer(&principal_2, new_principal_token.clone(), 1)
        .unwrap();
    parent.add_stx_transfer(&principal_1, 20).unwrap();
    child.add_stx_transfer(&principal_1, 21).unwrap();
    parent.add_stx_burn(&principal_2, 30).unwrap();
    child.add_stx_burn(&principal_2, 31).unwrap();
    parent.add_asset_transfer(&principal_1, nft.clone(), Value::Int(1));
    child.add_asset_transfer(&principal_1, nft.clone(), Value::Int(2));
    child.add_asset_transfer(&principal_1, new_nft.clone(), Value::Int(3));
    child.add_asset_transfer(&principal_1, new_nft.clone(), Value::Int(4));
    child.add_asset_transfer(&principal_3, new_principal_nft.clone(), Value::Int(5));
    parent.add_pox_action(&principal_1);
    child.add_pox_action(&principal_2);

    parent.commit_other(child, StacksEpochId::Epoch30).unwrap();
    assert!(parent.did_pox_action(&principal_1));
    assert!(parent.did_pox_action(&principal_2));
    assert!(!parent.did_pox_action(&principal_3));

    let table = parent.to_table();

    assert_eq!(table.len(), 3);
    assert_eq!(table[&principal_1][&token], AssetMapEntry::Token(25));
    assert_eq!(table[&principal_1][&new_token], AssetMapEntry::Token(1));
    assert_eq!(
        table[&principal_2][&new_principal_token],
        AssetMapEntry::Token(11)
    );
    assert_eq!(
        table[&principal_1][&nft],
        AssetMapEntry::Asset(vec![Value::Int(1), Value::Int(2)])
    );
    assert_eq!(
        table[&principal_1][&new_nft],
        AssetMapEntry::Asset(vec![Value::Int(3), Value::Int(4)])
    );
    assert_eq!(
        table[&principal_3][&new_principal_nft],
        AssetMapEntry::Asset(vec![Value::Int(5)])
    );
    assert_eq!(
        table[&principal_1][&AssetIdentifier::STX()],
        AssetMapEntry::STX(41)
    );
    assert_eq!(
        table[&principal_2][&AssetIdentifier::STX_burned()],
        AssetMapEntry::Burn(61)
    );
}

#[test]
fn stacking_merge_obeys_epoch_rules() {
    let principal_1 = contract_principal("a");
    let principal_2 = contract_principal("b");

    let mut parent = AssetMap::new();
    let mut child = AssetMap::new();
    parent
        .add_stacking(&principal_1, 100, StacksEpochId::Epoch40)
        .unwrap();
    child
        .add_stacking(&principal_1, 50, StacksEpochId::Epoch40)
        .unwrap();
    assert_eq!(
        parent
            .commit_other(child, StacksEpochId::Epoch30)
            .unwrap_err(),
        AssetMapError::StackingEntryConflict
    );
    assert_eq!(parent.get_stacking(&principal_1), Some(100));

    let mut parent = AssetMap::new();
    let mut child = AssetMap::new();
    parent
        .add_stacking(&principal_1, 100, StacksEpochId::Epoch40)
        .unwrap();
    child
        .add_stacking(&principal_1, 50, StacksEpochId::Epoch40)
        .unwrap();
    child
        .add_stacking(&principal_2, 25, StacksEpochId::Epoch40)
        .unwrap();
    parent.commit_other(child, StacksEpochId::Epoch40).unwrap();
    assert_eq!(parent.get_stacking(&principal_1), Some(150));
    assert_eq!(parent.get_stacking(&principal_2), Some(25));

    let mut parent = AssetMap::new();
    let mut child = AssetMap::new();
    parent
        .add_stacking(&principal_1, u128::MAX, StacksEpochId::Epoch40)
        .unwrap();
    child
        .add_stacking(&principal_1, 1, StacksEpochId::Epoch40)
        .unwrap();
    parent.add_stx_transfer(&principal_2, 1).unwrap();
    child.add_stx_transfer(&principal_2, 1).unwrap();
    assert_eq!(
        parent
            .commit_other(child, StacksEpochId::Epoch40)
            .unwrap_err(),
        AssetMapError::AmountOverflow
    );
    assert_eq!(parent.get_stacking(&principal_1), Some(u128::MAX));
    assert_eq!(parent.get_stx(&principal_2), Some(1));
}

#[test]
fn arithmetic_overflows_are_reported_without_mutation() {
    let principal = contract_principal("a");
    let token = asset_identifier("token", "asset");
    let mut assets = AssetMap::new();

    assets
        .add_token_transfer(&principal, token.clone(), u128::MAX)
        .unwrap();
    assert_eq!(
        assets
            .add_token_transfer(&principal, token.clone(), 1)
            .unwrap_err(),
        AssetMapError::AmountOverflow
    );
    assert_eq!(
        assets.get_fungible_tokens(&principal, &token),
        Some(u128::MAX)
    );

    assets.add_stx_burn(&principal, u128::MAX).unwrap();
    assert_eq!(
        assets.add_stx_burn(&principal, 1).unwrap_err(),
        AssetMapError::AmountOverflow
    );

    assets.add_stx_transfer(&principal, u128::MAX).unwrap();
    assert_eq!(
        assets.add_stx_transfer(&principal, 1).unwrap_err(),
        AssetMapError::AmountOverflow
    );
}

#[test]
fn burn_total_overflow_is_distinct_from_amount_overflow() {
    let principal_1 = contract_principal("a");
    let principal_2 = contract_principal("b");
    let mut assets = AssetMap::new();
    assets.add_stx_burn(&principal_1, u128::MAX).unwrap();
    assets.add_stx_burn(&principal_2, 1).unwrap();

    assert_eq!(
        assets.get_stx_burned_total().unwrap_err(),
        AssetMapError::BurnTotalOverflow
    );
}

#[cfg(feature = "asset-map-json")]
#[test]
fn json_contains_each_asset_category() {
    let principal = contract_principal("a");
    let token = asset_identifier("token", "ft");
    let nft = asset_identifier("token", "nft");
    let mut assets = AssetMap::new();
    assets.add_stx_transfer(&principal, 1).unwrap();
    assets.add_stx_burn(&principal, 2).unwrap();
    assets.add_token_transfer(&principal, token, 3).unwrap();
    assets.add_asset_transfer(&principal, nft, Value::Int(4));
    assets
        .add_stacking(&principal, 5, StacksEpochId::Epoch40)
        .unwrap();
    assets.add_pox_action(&principal);

    let json = assets.to_json();
    assert_eq!(json["stx"][principal.to_string()], "1");
    assert_eq!(json["burns"][principal.to_string()], "2");
    assert_eq!(json["stacking"][principal.to_string()], "5");
    assert_eq!(json["pox"], serde_json::json!([principal.to_string()]));
    assert_eq!(json["tokens"].as_object().unwrap().len(), 1);
    assert_eq!(json["assets"].as_object().unwrap().len(), 1);
}
