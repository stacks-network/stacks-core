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

//! Generate v2 deposit fixtures using the pinned upstream sBTC crate.

use std::error::Error;
use std::fs;

use bitcoin::ScriptBuf;
use bitcoin::hex::{DisplayHex, FromHex};
use bitcoin::secp256k1::PublicKey;
use bitcoin::taproot::{LeafVersion, TapLeafHash};
use clarity_types::types::PrincipalData;
use sbtc::SignerKeySet;
use sbtc::deposits::{
    DepositScriptInputsV2, ReclaimScriptInputs, to_v2_script_pubkey, to_v2_taproot,
};
use serde_json::{Value, json};

/// Rebuild every expected value from input-only cases and write the fixture file.
fn main() -> Result<(), Box<dyn Error>> {
    let mut fixtures: Vec<Value> = serde_json::from_str(include_str!("../inputs.json"))?;
    for fixture in &mut fixtures {
        let input = &fixture["inputs"];
        let keys = input["signer_keys_compressed_hex"]
            .as_array()
            .expect("signer key array")
            .iter()
            .map(|key| key.as_str().expect("hex signer key").parse::<PublicKey>())
            .collect::<Result<Vec<_>, _>>()?;
        let key_set = SignerKeySet::derive(
            keys,
            u16::try_from(input["signatures_required"].as_u64().expect("threshold"))?,
        )?;
        let deposit = DepositScriptInputsV2 {
            signer_key_set: key_set.clone(),
            recipient: PrincipalData::parse(
                input["recipient_principal"].as_str().expect("principal"),
            )?,
            max_fee: input["max_fee"].as_u64().expect("max fee"),
        }
        .deposit_script();
        let reclaim = ReclaimScriptInputs::try_new(
            u32::try_from(input["lock_time"].as_u64().expect("lock time"))?,
            ScriptBuf::from_bytes(Vec::<u8>::from_hex(
                input["reclaim_user_script_hex"]
                    .as_str()
                    .expect("reclaim hex"),
            )?),
        )?
        .reclaim_script();
        let taproot = to_v2_taproot(deposit.clone(), reclaim.clone());
        let script_pubkey = to_v2_script_pubkey(deposit.clone(), reclaim.clone());
        fixture["intermediate"] = json!({
            "derived_xonly_keys_sorted_hex": key_set.public_keys().iter().map(ToString::to_string).collect::<Vec<_>>(),
            "signing_script_hex": key_set.signing_script().as_bytes().to_lower_hex_string(),
            "key_set_script_pubkey_hex": key_set.script_pubkey().as_bytes().to_lower_hex_string(),
            "deposit_script_hex": deposit.as_bytes().to_lower_hex_string(),
            "reclaim_script_hex": reclaim.as_bytes().to_lower_hex_string(),
            "deposit_tapleaf_hash_hex": TapLeafHash::from_script(&deposit, LeafVersion::TapScript).to_string(),
            "reclaim_tapleaf_hash_hex": TapLeafHash::from_script(&reclaim, LeafVersion::TapScript).to_string(),
            "merkle_root_hex": taproot.merkle_root().expect("two-leaf tree").to_string(),
            "taproot_output_key_xonly_hex": taproot.output_key().to_string(),
        });
        fixture["expected"] = json!({
            "script_pubkey_hex": script_pubkey.as_bytes().to_lower_hex_string(),
        });
    }
    let output = json!({
        "fixtures": fixtures,
        "sbtc_reference_commit": "6ec5dbeecb606fc2e921661ec9b43a6ad3545e6e",
        "source": "sbtc crate: SignerKeySet::derive, DepositScriptInputsV2::deposit_script, ReclaimScriptInputs::reclaim_script, to_v2_taproot, to_v2_script_pubkey (https://github.com/stacks-sbtc/sbtc)",
        "v2_nums_x_coordinate_hex": sbtc::V2_NUMS_X_COORDINATE.to_lower_hex_string(),
    });
    let output_path = std::env::args_os()
        .nth(1)
        .expect("output JSON path required");
    fs::write(output_path, serde_json::to_string_pretty(&output)? + "\n")?;
    Ok(())
}
