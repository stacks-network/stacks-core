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

use std::sync::Arc;

use clarity::vm::types::ResponseData;
use clarity::vm::{ClarityVersion, Value};
use madhouse::{Command, CommandWrapper};
use proptest::prelude::{any, Strategy};
use stacks_common::util::hash::{to_hex, Sha256Sum};
use stacks_common::util::secp256r1::{Secp256r1PrivateKey, Secp256r1PublicKey};

use super::unwrap_single_tx_success;
use crate::chainstate::tests::consensus::{
    ConsensusUtils, ExpectedTransactionOutput, TestBlock, FAUCET_PRIV_KEY,
};
use crate::chainstate::tests::madhouse::context::Epoch33ToEpoch34TestContext;
use crate::chainstate::tests::madhouse::state::Epoch33ToEpoch34TestState;
use crate::core::test_util::to_addr;

/// Derive a secp256r1 key pair, message hash, and double-hash signature from
/// a seed. The signature is produced with `.sign()` (double-hash mode): it
/// verifies under Clarity4 but fails under Clarity5 (prehash).
fn double_hash_vector(seed: &[u8; 32]) -> (String, String, String) {
    let privk = Secp256r1PrivateKey::from_seed(seed);
    let pubk = Secp256r1PublicKey::from_private(&privk);
    let msg_hash = Sha256Sum::from_data(seed);
    let sig = privk
        .sign(msg_hash.as_bytes())
        .expect("secp256r1 double-hash signing should succeed");

    (
        to_hex(msg_hash.as_bytes()),
        to_hex(&sig.0),
        to_hex(&pubk.to_bytes_compressed()),
    )
}

/// Derive a secp256r1 key pair, message hash, and prehash signature from a
/// seed. The signature is produced with `.sign_digest()` (prehash mode): it
/// verifies under Clarity5 but fails under Clarity4 (double-hash).
fn prehash_vector(seed: &[u8; 32]) -> (String, String, String) {
    let privk = Secp256r1PrivateKey::from_seed(seed);
    let pubk = Secp256r1PublicKey::from_private(&privk);
    let msg_hash = Sha256Sum::from_data(seed);
    let sig = privk
        .sign_digest(msg_hash.as_bytes())
        .expect("secp256r1 prehash signing should succeed");

    (
        to_hex(msg_hash.as_bytes()),
        to_hex(&sig.0),
        to_hex(&pubk.to_bytes_compressed()),
    )
}

/// Deploy a contract with a public `verify` function that calls
/// `secp256r1-verify`, then invoke it and assert the result matches
/// `expected`.
fn deploy_and_verify(
    state: &mut Epoch33ToEpoch34TestState,
    label: &str,
    name: &str,
    msg: &str,
    sig: &str,
    pk: &str,
    version: ClarityVersion,
    expected: bool,
) {
    let chain_epoch = state.chain_epoch();
    assert_eq!(
        state.current_epoch, chain_epoch,
        "{label}: model epoch {:?} disagrees with chain {:?}",
        state.current_epoch, chain_epoch,
    );

    let code =
        format!(r#"(define-public (verify) (ok (secp256r1-verify 0x{msg} 0x{sig} 0x{pk})))"#);
    let deploy_tx = ConsensusUtils::new_deploy_tx(state.next_nonce, name, &code, Some(version));
    let block = TestBlock {
        transactions: vec![deploy_tx],
    };
    let result = state.chain.append_block(block, true);
    let tx_out = unwrap_single_tx_success(&result, &format!("{label}(deploy)"));
    assert!(
        tx_out.vm_error.is_none(),
        "{label}: deploy VM error: {:?}",
        tx_out.vm_error,
    );
    state.next_nonce += 1;
    state.deployed.insert(name.to_string());

    let call_tx = ConsensusUtils::new_call_tx(state.next_nonce, name, "verify");
    let block = TestBlock {
        transactions: vec![call_tx],
    };
    let result = state.chain.append_block(block, true);
    let tx_out = unwrap_single_tx_success(&result, &format!("{label}(call)"));
    assert_ok_bool(label, tx_out, expected);
    state.next_nonce += 1;
}

/// Assert return value equals `(ok <bool>)`.
fn assert_ok_bool(label: &str, output: &ExpectedTransactionOutput, expected: bool) {
    assert!(
        output.vm_error.is_none(),
        "{label}: unexpected VM error: {:?}",
        output.vm_error,
    );
    let expected_val = Value::Response(ResponseData {
        committed: true,
        data: Box::new(Value::Bool(expected)),
    });
    assert_eq!(
        output.return_type, expected_val,
        "{label}: expected (ok {expected}), got {:?}",
        output.return_type,
    );
}

/// Deploy a Clarity4 contract with a `secp256r1-verify` public function
/// using a double-hash signature, then call it. Clarity4 double-hashes
/// before verifying -> signature matches -> `true`.
pub struct VerifyC4DoubleHash {
    seed: [u8; 32],
}

impl Command<Epoch33ToEpoch34TestState, Epoch33ToEpoch34TestContext> for VerifyC4DoubleHash {
    fn check(&self, state: &Epoch33ToEpoch34TestState) -> bool {
        state.is_epoch34() && !state.deployed.contains("c4-double-hash")
    }

    fn apply(&self, state: &mut Epoch33ToEpoch34TestState) {
        let (msg, sig, pk) = double_hash_vector(&self.seed);
        deploy_and_verify(
            state,
            "VerifyC4DoubleHash",
            "c4-double-hash",
            &msg,
            &sig,
            &pk,
            ClarityVersion::Clarity4,
            true,
        );

        info!(
            "VerifyC4DoubleHash: true — C4 double-hash matches, seed={}..)",
            to_hex(&self.seed[..4]),
        );
    }

    fn label(&self) -> String {
        format!("VERIFY_C4_DOUBLE_HASH(seed={}..)", to_hex(&self.seed[..4]))
    }

    fn build(
        _ctx: Arc<Epoch33ToEpoch34TestContext>,
    ) -> impl Strategy<Value = CommandWrapper<Epoch33ToEpoch34TestState, Epoch33ToEpoch34TestContext>>
    {
        any::<[u8; 32]>().prop_map(|seed| CommandWrapper::new(VerifyC4DoubleHash { seed }))
    }
}

/// Deploy a Clarity5 contract with a `secp256r1-verify` public function using
/// a double-hash signature, then call it. Clarity5 uses prehash mode ->
/// double-hash signature mismatches -> `false`.
pub struct VerifyC5DoubleHash {
    seed: [u8; 32],
}

impl Command<Epoch33ToEpoch34TestState, Epoch33ToEpoch34TestContext> for VerifyC5DoubleHash {
    fn check(&self, state: &Epoch33ToEpoch34TestState) -> bool {
        state.is_epoch34() && !state.deployed.contains("c5-double-hash")
    }

    fn apply(&self, state: &mut Epoch33ToEpoch34TestState) {
        let (msg, sig, pk) = double_hash_vector(&self.seed);
        deploy_and_verify(
            state,
            "VerifyC5DoubleHash",
            "c5-double-hash",
            &msg,
            &sig,
            &pk,
            ClarityVersion::Clarity5,
            false,
        );

        info!(
            "VerifyC5DoubleHash: false — C5 prehash rejects double-hash sig, seed={}..)",
            to_hex(&self.seed[..4]),
        );
    }

    fn label(&self) -> String {
        format!("VERIFY_C5_DOUBLE_HASH(seed={}..)", to_hex(&self.seed[..4]))
    }

    fn build(
        _ctx: Arc<Epoch33ToEpoch34TestContext>,
    ) -> impl Strategy<Value = CommandWrapper<Epoch33ToEpoch34TestState, Epoch33ToEpoch34TestContext>>
    {
        any::<[u8; 32]>().prop_map(|seed| CommandWrapper::new(VerifyC5DoubleHash { seed }))
    }
}

/// Deploy a Clarity5 contract with a `secp256r1-verify` public function
/// using a prehash signature, then call it. Clarity5 uses prehash mode ->
/// prehash signature matches -> `true`.
pub struct VerifyC5Prehash {
    seed: [u8; 32],
}

impl Command<Epoch33ToEpoch34TestState, Epoch33ToEpoch34TestContext> for VerifyC5Prehash {
    fn check(&self, state: &Epoch33ToEpoch34TestState) -> bool {
        state.is_epoch34() && !state.deployed.contains("c5-prehash")
    }

    fn apply(&self, state: &mut Epoch33ToEpoch34TestState) {
        let (msg, sig, pk) = prehash_vector(&self.seed);
        deploy_and_verify(
            state,
            "VerifyC5Prehash",
            "c5-prehash",
            &msg,
            &sig,
            &pk,
            ClarityVersion::Clarity5,
            true,
        );

        info!(
            "VerifyC5Prehash: true — C5 prehash matches prehash sig, seed={}..)",
            to_hex(&self.seed[..4]),
        );
    }

    fn label(&self) -> String {
        format!("VERIFY_C5_PREHASH(seed={}..)", to_hex(&self.seed[..4]))
    }

    fn build(
        _ctx: Arc<Epoch33ToEpoch34TestContext>,
    ) -> impl Strategy<Value = CommandWrapper<Epoch33ToEpoch34TestState, Epoch33ToEpoch34TestContext>>
    {
        any::<[u8; 32]>().prop_map(|seed| CommandWrapper::new(VerifyC5Prehash { seed }))
    }
}

/// Deploy a C5 callee contract with a `secp256r1-verify` public function
/// using a double-hash signature, then deploy a C4 caller that invokes it
/// via `contract-call?`. The callee's Clarity5 prehash mode governs ->
/// `(ok false)`.
pub struct CallC5ViaC4Caller {
    seed: [u8; 32],
}

impl Command<Epoch33ToEpoch34TestState, Epoch33ToEpoch34TestContext> for CallC5ViaC4Caller {
    fn check(&self, state: &Epoch33ToEpoch34TestState) -> bool {
        state.is_epoch34() && !state.deployed.contains("c5-callee")
    }

    fn apply(&self, state: &mut Epoch33ToEpoch34TestState) {
        let chain_epoch = state.chain_epoch();
        assert_eq!(
            state.current_epoch, chain_epoch,
            "CallC5ViaC4Caller: model epoch {:?} disagrees with chain {:?}",
            state.current_epoch, chain_epoch,
        );

        // Deploy C5 callee with a double-hash signature.
        let (msg, sig, pk) = double_hash_vector(&self.seed);
        let callee_code = format!(
            r#"
(define-public (verify-sig)
  (ok (secp256r1-verify 0x{msg} 0x{sig} 0x{pk})))
"#
        );
        let deploy_tx = ConsensusUtils::new_deploy_tx(
            state.next_nonce,
            "c5-callee",
            &callee_code,
            Some(ClarityVersion::Clarity5),
        );
        let block = TestBlock {
            transactions: vec![deploy_tx],
        };
        let result = state.chain.append_block(block, true);
        let tx_out = unwrap_single_tx_success(&result, "CallC5ViaC4Caller(c5-callee)");
        assert!(
            tx_out.vm_error.is_none(),
            "CallC5ViaC4Caller: c5-callee deploy VM error: {:?}",
            tx_out.vm_error,
        );
        state.next_nonce += 1;
        state.deployed.insert("c5-callee".to_string());

        // Deploy C4 caller that calls the C5 callee.
        let faucet_addr = to_addr(&FAUCET_PRIV_KEY);
        let caller_code = format!(
            r#"
(define-public (call-c5)
  (contract-call? '{faucet_addr}.c5-callee verify-sig))
"#
        );
        let deploy_tx = ConsensusUtils::new_deploy_tx(
            state.next_nonce,
            "c4-caller",
            &caller_code,
            Some(ClarityVersion::Clarity4),
        );
        let block = TestBlock {
            transactions: vec![deploy_tx],
        };
        let result = state.chain.append_block(block, true);
        let tx_out = unwrap_single_tx_success(&result, "CallC5ViaC4Caller(c4-caller)");
        assert!(
            tx_out.vm_error.is_none(),
            "CallC5ViaC4Caller: c4-caller deploy VM error: {:?}",
            tx_out.vm_error,
        );
        state.next_nonce += 1;
        state.deployed.insert("c4-caller".to_string());

        // Call through C4 caller -> C5 callee. Callee's prehash governs.
        let call_tx = ConsensusUtils::new_call_tx(state.next_nonce, "c4-caller", "call-c5");
        let block = TestBlock {
            transactions: vec![call_tx],
        };
        let result = state.chain.append_block(block, true);
        let tx_out = unwrap_single_tx_success(&result, "CallC5ViaC4Caller(call)");
        assert_ok_bool("CallC5ViaC4Caller", tx_out, false);
        state.next_nonce += 1;

        info!(
            "CallC5ViaC4Caller: (ok false) — callee's C5 prehash governs, seed={}..)",
            to_hex(&self.seed[..4]),
        );
    }

    fn label(&self) -> String {
        format!("CALL_C5_VIA_C4_CALLER(seed={}..)", to_hex(&self.seed[..4]),)
    }

    fn build(
        _ctx: Arc<Epoch33ToEpoch34TestContext>,
    ) -> impl Strategy<Value = CommandWrapper<Epoch33ToEpoch34TestState, Epoch33ToEpoch34TestContext>>
    {
        any::<[u8; 32]>().prop_map(|seed| CommandWrapper::new(CallC5ViaC4Caller { seed }))
    }
}
