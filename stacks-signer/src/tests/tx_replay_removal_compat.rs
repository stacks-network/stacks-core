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

//! Compatibility tripwires for the removal of transaction replay.
//!
//! These tests pin the compatibility surfaces that the tx-replay removal must **not**
//! disturb as a first phase.

use blockstack_lib::chainstate::stacks::{
    StacksTransaction, TokenTransferMemo, TransactionAnchorMode, TransactionAuth,
    TransactionPayload, TransactionPostConditionMode, TransactionVersion,
};
use blockstack_lib::net::api::get_tenures_fork_info::TenureForkingInfo;
use blockstack_lib::net::api::postblock_proposal::{BlockValidateOk, ValidateRejectCode};
use clarity::codec::StacksMessageCodec;
use clarity::types::chainstate::{
    BurnchainHeaderHash, ConsensusHash, SortitionId, StacksAddress, StacksPrivateKey,
};
use clarity::vm::types::PrincipalData;
use libsigner::v0::messages::StateMachineUpdate;
use serde_json::json;

use crate::signerdb::SignerDb;

/// Byte layout of a `StateMachineUpdate` carrying a `V2` content payload with an
/// `ActiveMiner`, assembled **by hand** rather than through the Rust types.
///
/// This is the point of the helper: it encodes the frozen wire format independently of
/// the structs, so it cannot silently drift along with them. If the encoder changes, the
/// round-trip assertion below fails instead of both sides moving together.
fn encode_state_machine_update_v2(replay_txs: &[StacksTransaction]) -> Vec<u8> {
    let mut content = Vec::new();
    content.extend_from_slice(&[0x55; 20]); // burn_block: ConsensusHash
    content.extend_from_slice(&100u64.to_be_bytes()); // burn_block_height
    content.push(0x01); // current_miner variant: ActiveMiner
    content.extend_from_slice(&[0xab; 20]); // current_miner_pkh: Hash160
    content.extend_from_slice(&[0x44; 20]); // tenure_id: ConsensusHash
    content.extend_from_slice(&[0x22; 20]); // parent_tenure_id: ConsensusHash
    content.extend_from_slice(&[0x33; 32]); // parent_tenure_last_block: StacksBlockId
    content.extend_from_slice(&1u64.to_be_bytes()); // parent_tenure_last_block_height

    // replay_transactions: u32 length prefix, then each transaction
    content.extend_from_slice(&(replay_txs.len() as u32).to_be_bytes());
    for tx in replay_txs {
        tx.consensus_serialize(&mut content)
            .expect("failed to serialize replay transaction");
    }

    let mut bytes = Vec::new();
    bytes.extend_from_slice(&2u64.to_be_bytes()); // active_signer_protocol_version
    bytes.extend_from_slice(&2u64.to_be_bytes()); // local_supported_signer_protocol_version
    bytes.extend_from_slice(&(content.len() as u32).to_be_bytes()); // content_len
    bytes.extend_from_slice(&content);
    bytes
}

fn make_transaction(memo: [u8; 34]) -> StacksTransaction {
    let pk = StacksPrivateKey::random();
    StacksTransaction {
        version: TransactionVersion::Testnet,
        chain_id: 0x80000000,
        auth: TransactionAuth::from_p2pkh(&pk).unwrap(),
        anchor_mode: TransactionAnchorMode::Any,
        post_condition_mode: TransactionPostConditionMode::Allow,
        post_conditions: vec![],
        payload: TransactionPayload::TokenTransfer(
            PrincipalData::from(StacksAddress::burn_address(false)),
            100,
            TokenTransferMemo(memo),
        ),
    }
}

/// Tripwire 1 — the `StateMachineUpdate` V2 wire format is frozen.
///
/// A signer that has not upgraded still reads `replay_transactions` off the wire. If a
/// newer binary stops emitting the four-byte empty vector, that read hits EOF, the codec
/// errors, and the **entire** update is dropped — leaving the old signer blind to its
/// peers' burn view and miner state. Emitting the bytes is therefore permanent.
#[test]
fn state_machine_update_v2_wire_format_is_frozen() {
    let bytes = encode_state_machine_update_v2(&[]);

    // 20 + 8 + 1 + 20 + 20 + 20 + 32 + 8 + 4 (empty replay vector) = 133
    assert_eq!(
        u32::from_be_bytes(bytes[16..20].try_into().unwrap()),
        133,
        "V2 content length changed: the wire format is not frozen"
    );
    assert_eq!(
        &bytes[bytes.len() - 4..],
        &[0, 0, 0, 0],
        "V2 payload must end in a zero-length replay vector"
    );

    let decoded = StateMachineUpdate::consensus_deserialize(&mut &bytes[..])
        .expect("a V2 update with an empty replay set must decode");

    let mut reencoded = Vec::new();
    decoded
        .consensus_serialize(&mut reencoded)
        .expect("re-encoding must succeed");
    assert_eq!(
        reencoded, bytes,
        "V2 must re-encode byte-identically; older signers parse these bytes"
    );

    assert_eq!(decoded.content.version(), 2);
    let (_, burn_block_height) = decoded.content.burn_block_view();
    assert_eq!(burn_block_height, 100);

    // Demonstrate the hazard rather than merely asserting it: drop the empty replay vector
    // and re-declare `content_len` accordingly, i.e. exactly the bytes a newer binary would
    // emit if it stopped writing the field. The update then fails to decode outright, which
    // is what every pre-removal signer on the network would experience.
    let mut truncated = bytes[..bytes.len() - 4].to_vec();
    let shortened_content_len = u32::try_from(truncated.len() - 20).unwrap();
    truncated[16..20].copy_from_slice(&shortened_content_len.to_be_bytes());
    assert!(
        StateMachineUpdate::consensus_deserialize(&mut &truncated[..]).is_err(),
        "omitting the replay vector must break decoding — this is why the four bytes \
         are permanent, not merely conventional"
    );
}

/// Tripwire 2 — a message from a *pre-removal* signer still decodes.
///
/// Until every signer has upgraded, peers keep broadcasting populated replay sets. Those
/// messages must still parse, and their non-replay fields must survive intact.
///
/// NOTE: this asserts decoding **only**, never a byte-identical round trip. After the
/// removal the transactions are read and discarded, so re-encoding legitimately yields the
/// empty vector. Asserting round-trip equality here would pass today and fail at the end of
/// the removal — and the tempting "fix" would be to weaken the test, which is precisely the
/// mistake these tripwires exist to prevent.
#[test]
fn state_machine_update_v2_with_populated_replay_set_still_decodes() {
    let txs = vec![make_transaction([1u8; 34]), make_transaction([2u8; 34])];
    let bytes = encode_state_machine_update_v2(&txs);

    let decoded = StateMachineUpdate::consensus_deserialize(&mut &bytes[..])
        .expect("a V2 update carrying a replay set must still decode");

    assert_eq!(decoded.content.version(), 2);
    let (_, burn_block_height) = decoded.content.burn_block_view();
    assert_eq!(
        burn_block_height, 100,
        "non-replay fields must survive a populated replay set"
    );
}

/// Tripwire 3 — `/v3/block_proposal` responses still carry the replay fields.
///
/// `BlockValidateOk` is a plain `Deserialize` with no `#[serde(default)]`, so
/// `replay_tx_exhausted` is **required**. Dropping it from a newer node would make an older
/// signer fail to parse validation responses entirely — silently, since serde's tolerance
/// for *unknown* fields does not extend to *missing* ones.
///
/// The two assertions are a matched pair: the positive case would fail loudly if the JSON
/// fixture below drifted, so the negative case cannot pass for the wrong reason.
#[test]
fn block_validate_ok_response_still_carries_replay_fields() {
    let cost = json!({
        "write_length": 0, "write_count": 0,
        "read_length": 0, "read_count": 0, "runtime": 0,
    });
    let hash = "0".repeat(64);

    let with_replay_fields = json!({
        "signer_signature_hash": hash,
        "cost": cost,
        "size": 100,
        "validation_time_ms": 10,
        "replay_tx_hash": null,
        "replay_tx_exhausted": false,
    });
    serde_json::from_value::<BlockValidateOk>(with_replay_fields)
        .expect("a response carrying the replay fields must deserialize");

    let without_replay_fields = json!({
        "signer_signature_hash": hash,
        "cost": cost,
        "size": 100,
        "validation_time_ms": 10,
    });
    assert!(
        serde_json::from_value::<BlockValidateOk>(without_replay_fields).is_err(),
        "replay_tx_exhausted is a required field; a node that stops emitting it \
         breaks block-proposal validation for every signer running an older binary"
    );
}

/// Tripwire 4 — reject code 7 stays reserved.
///
/// The discriminant is part of the `/v3/block_proposal` response API. Even once no node
/// emits it, a newer signer must still be able to decode a `7` sent by an older node, so
/// the variant is retained and the number is never reused.
#[test]
fn validate_reject_code_seven_stays_reserved() {
    assert_eq!(ValidateRejectCode::InvalidTransactionReplay.to_u8(), 7);
    assert_eq!(
        ValidateRejectCode::from_u8(7),
        Some(ValidateRejectCode::InvalidTransactionReplay),
        "code 7 must remain decodable and must never be reassigned"
    );
}

/// Tripwire 5 — the signer database schema version is pinned.
///
/// Bumping `SCHEMA_VERSION` is a one-way door: a signer that migrates and then rolls back
/// to an older binary fails to start with "Database schema is newer than SCHEMA_VERSION".
/// Dropping the now-dead `block_validated_by_replay_txs` table is therefore deferred; the
/// table is left in place and only its accessors are removed.
#[test]
fn signer_db_schema_version_is_pinned() {
    assert_eq!(
        SignerDb::SCHEMA_VERSION,
        19,
        "bumping the schema removes the downgrade path; the dead replay table stays for now"
    );
}

/// Tripwire 6 — `/v3/tenures/fork_info` responses still carry a `nakamoto_blocks` key.
///
/// The field is no longer populated (always `null`), but the **key must still be emitted**. A
/// signer released before that change declares it as `#[serde(with = ...)]` with no
/// `#[serde(default)]`, which makes it *required*: serde's `Option`-defaults-to-`None` shortcut
/// does not apply once `deserialize_with` is set. Omitting the key makes such a signer fail to
/// parse the entire fork-info response.
///
/// The assertion is deliberately on the *serialized JSON*, not on the Rust type: what old signers
/// depend on is the key being on the wire, and that is what must survive the field's eventual
/// deletion being staged over two releases.
#[test]
fn tenure_forking_info_still_emits_nakamoto_blocks_key() {
    let info = TenureForkingInfo {
        burn_block_hash: BurnchainHeaderHash([0x11; 32]),
        burn_block_height: 100,
        sortition_id: SortitionId([0x22; 32]),
        parent_sortition_id: SortitionId([0x33; 32]),
        consensus_hash: ConsensusHash([0x44; 20]),
        was_sortition: true,
        first_block_mined: None,
        nakamoto_blocks: None,
    };

    let value = serde_json::to_value(&info).expect("TenureForkingInfo must serialize");
    assert_eq!(
        value.get("nakamoto_blocks"),
        Some(&serde_json::Value::Null),
        "the key must still be emitted (as null); dropping it makes every pre-removal signer \
         reject block proposals on the reorg-validation path"
    );

    // From json with omitted `nakamoto_blocks` field should deserialize properly thanks to `#[serde(default)]`
    let without_key = json!({
        "burn_block_hash": format!("0x{}", "11".repeat(32)),
        "burn_block_height": 100,
        "sortition_id": format!("0x{}", "22".repeat(32)),
        "parent_sortition_id": format!("0x{}", "33".repeat(32)),
        "consensus_hash": format!("0x{}", "44".repeat(20)),
        "was_sortition": true,
        "first_block_mined": null,
    });
    let parsed = serde_json::from_value::<TenureForkingInfo>(without_key).expect(
        "a response omitting nakamoto_blocks must deserialize, so the field can be dropped later",
    );
    assert!(parsed.nakamoto_blocks.is_none());
}
