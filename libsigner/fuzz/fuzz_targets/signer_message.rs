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

//! A StackerDB chunk payload, as any miner or signer can write it. Decodes
//! it as a `SignerMessage`, then makes the calls a signer makes on what it
//! decoded (hashes, signature checks, logging), and checks that the message
//! re-encodes to something that decodes to the same message. Proposed blocks
//! and state updates must also survive the serde JSON round trip the signer
//! DB stores them with.

#![no_main]

use libfuzzer_sys::fuzz_target;
use libsigner::v0::messages::{
    BlockResponse, BlockResponseData, MockProposal, RejectReason, RejectReasonPrefix,
    SignerMessage, BLOCK_RESPONSE_DATA_VERSION,
};
use libsigner::v0::signer_state::MinerState;
use serde::de::DeserializeOwned;
use serde::Serialize;
use stacks_common::codec::StacksMessageCodec;
use stacks_common::types::chainstate::{StacksPrivateKey, StacksPublicKey};
use stacks_common::util::hash::MerkleHashFunc;
use stacks_common::util::secp256k1::Secp256k1PublicKey;

fn some_public_key() -> StacksPublicKey {
    let sk = StacksPrivateKey::from_hex(
        "0101010101010101010101010101010101010101010101010101010101010101",
    )
    .unwrap();
    StacksPublicKey::from_private(&sk)
}

/// Store-and-reload through serde JSON, as `SignerDb` does.
fn json_round_trip<T: Serialize + DeserializeOwned + PartialEq + std::fmt::Debug>(value: &T) {
    let json = serde_json::to_string(value).expect("must serialize to JSON");
    let back: T = serde_json::from_str(&json).expect("stored JSON must load");
    assert_eq!(value, &back, "stored JSON must load to the same value");
}

fn exercise_mock_proposal(proposal: &MockProposal) {
    let _ = proposal.miner_signature_hash();
    let _ = proposal.signer_signature_hash();
    let _ = proposal.verify(&some_public_key());
}

fn exercise(msg: &SignerMessage) {
    let _ = format!("{msg:?}");
    let _ = msg.msg_id();
    match msg {
        SignerMessage::BlockProposal(proposal) => {
            let block = &proposal.block;
            let _ = block.header.signer_signature_hash();
            let _ = block.block_id();
            let _ = block.header.recover_miner_pk();
            let _ = block.get_tenure_change_tx_payload();
            let _ = block.get_tenure_extend_tx_payload();
            let _ = block.get_tenure_tx_payload();
            let _ = block.is_wellformed_tenure_start_block();
            json_round_trip(block);
        }
        SignerMessage::BlockResponse(response) => {
            let _ = format!("{response}");
            let _ = response.get_signer_signature_hash();
            let _ = response.get_tenure_extend_timestamp();
            if let Some(accepted) = response.as_block_accepted() {
                let _ = Secp256k1PublicKey::recover_to_pubkey_without_validating_low_s(
                    accepted.signer_signature_hash.bits(),
                    &accepted.signature,
                );
            }
            if let Some(rejection) = response.as_block_rejection() {
                let _ = format!(
                    "{} {}",
                    rejection.reason_code, rejection.response_data.reject_reason
                );
                let _ = rejection.hash();
                if let Ok(pk) = rejection.recover_public_key() {
                    let _ = rejection.verify(&pk);
                }
            }
        }
        SignerMessage::BlockPushed(block) => {
            let _ = block.header.signer_signature_hash();
            let _ = block.block_id();
        }
        SignerMessage::MockProposal(proposal) => exercise_mock_proposal(proposal),
        SignerMessage::MockSignature(signature) => {
            exercise_mock_proposal(&signature.mock_proposal);
            let _ = signature.verify(&some_public_key());
        }
        SignerMessage::MockBlock(block) => {
            exercise_mock_proposal(&block.mock_proposal);
            for signature in &block.mock_signatures {
                let _ = signature.verify(&some_public_key());
            }
        }
        SignerMessage::StateMachineUpdate(update) => {
            let _ = format!("{update}");
            let _ = update.content.version();
            let _ = update.content.burn_block_view();
            let _ = MinerState::from(update.content.current_miner().clone());
            json_round_trip(update);
        }
        SignerMessage::BlockPreCommit(_) => {}
    }
}

/// Two lossy re-encodings of block response data, both left out of the
/// comparison. Data older than the current version doesn't round-trip:
/// encoding writes every field whatever `version` says, so the newer fields'
/// bytes come back as `unknown_bytes` (nothing re-encodes a peer's
/// response). And an unknown reject reason is re-encoded as the generic
/// `Unknown` prefix rather than its original code, by design.
fn normalize_response_data(mut msg: SignerMessage) -> SignerMessage {
    if let SignerMessage::BlockResponse(response) = &mut msg {
        let data = match response {
            BlockResponse::Accepted(accepted) => &mut accepted.response_data,
            BlockResponse::Rejected(rejection) => &mut rejection.response_data,
        };
        if data.version < BLOCK_RESPONSE_DATA_VERSION {
            *data = BlockResponseData::empty();
        }
        if let RejectReason::Unknown(code) = &mut data.reject_reason {
            *code = RejectReasonPrefix::Unknown as u8;
        }
    }
    msg
}

fuzz_target!(|data: &[u8]| {
    let Ok(msg) = SignerMessage::consensus_deserialize(&mut &data[..]) else {
        return;
    };
    exercise(&msg);

    let bytes = msg.serialize_to_vec();
    let again = SignerMessage::consensus_deserialize(&mut &bytes[..])
        .expect("a re-encoded message must decode");
    assert_eq!(
        normalize_response_data(msg),
        normalize_response_data(again),
        "a re-encoded message must decode to itself"
    );
});
