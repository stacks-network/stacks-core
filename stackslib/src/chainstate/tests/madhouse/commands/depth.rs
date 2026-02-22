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
use proptest::prelude::{Just, Strategy};

use super::unwrap_single_tx_success;
use crate::chainstate::tests::consensus::{
    ConsensusUtils, ExpectedResult, TestBlock, FAUCET_PRIV_KEY,
};
use crate::chainstate::tests::madhouse::context::Epoch33ToEpoch34TestContext;
use crate::chainstate::tests::madhouse::state::Epoch33ToEpoch34TestState;
use crate::core::test_util::to_addr;

/// N=33 contracts -> stack depth 2*33-1=65. Exceeds Epoch33 limit (64), fits
/// Epoch34 limit (128).
const CHAIN_SHORT_DEPTH: usize = 33;

/// N=64 contracts -> stack depth 2*64-1=127. Exact max that fits Epoch34's 128
/// limit.
const CHAIN_LONG_DEPTH: usize = 64;

/// N=65 contracts -> stack depth 2*65-1=129. Exact min that exceeds Epoch34's
/// 128 limit.
const CHAIN_OVER_DEPTH: usize = CHAIN_LONG_DEPTH + 1;

/// Epoch33 max call-stack depth.
const EPOCH33_DEPTH_LIMIT: usize = 64;

/// Epoch34 max call-stack depth.
const EPOCH34_DEPTH_LIMIT: usize = 128;

/// Expected return value from a successful ping call: `(ok true)`.
fn ok_true() -> Value {
    Value::Response(ResponseData {
        committed: true,
        data: Box::new(Value::Bool(true)),
    })
}

/// Deploy a chain of N contracts, each calling the previous one's `ping`
/// function. `contract-0.ping` returns `(ok true)`. `contract-i.ping` calls
/// `contract-(i-1).ping`.
fn deploy_call_chain(state: &mut Epoch33ToEpoch34TestState, tag: &str, depth: usize) {
    let faucet_addr = to_addr(&FAUCET_PRIV_KEY);
    let version = ClarityVersion::default_for_epoch(state.current_epoch);

    for i in 0..depth {
        let name = format!("{tag}-{i}");
        let code = if i == 0 {
            "(define-public (ping) (ok true))".to_string()
        } else {
            let prev = format!("{tag}-{}", i - 1);
            format!("(define-public (ping) (contract-call? '{faucet_addr}.{prev} ping))")
        };

        let deploy_tx =
            ConsensusUtils::new_deploy_tx(state.next_nonce, &name, &code, Some(version));

        let block = TestBlock {
            transactions: vec![deploy_tx],
        };
        let is_naka = state.current_epoch.uses_nakamoto_blocks();
        let result = state.chain.append_block(block, is_naka);
        assert!(
            matches!(result, ExpectedResult::Success(_)),
            "deploy_call_chain: deploying {} failed: {:?}",
            name,
            result,
        );
        state.next_nonce += 1;
    }

    state.deployed.insert(tag.to_string());
    info!(
        "deploy_call_chain: deployed '{tag}' \
         with depth={depth}",
    );
}

/// Call the leaf contract in a call chain and return the block result. The
/// leaf is `{tag}-{depth-1}.ping`.
fn call_chain_leaf(
    state: &mut Epoch33ToEpoch34TestState,
    tag: &str,
    depth: usize,
) -> ExpectedResult {
    let leaf = format!("{tag}-{}", depth - 1);
    let call_tx = ConsensusUtils::new_call_tx(state.next_nonce, &leaf, "ping");

    let block = TestBlock {
        transactions: vec![call_tx],
    };
    let is_naka = state.current_epoch.uses_nakamoto_blocks();
    let result = state.chain.append_block(block, is_naka);
    state.next_nonce += 1;
    result
}

/// Model-based assertion for call-chain results. Verifies the model epoch
/// matches the chain, then computes the expected outcome from `(depth,
/// current_epoch)` and checks the transaction result agrees.
fn assert_chain_call_result(
    state: &mut Epoch33ToEpoch34TestState,
    result: &ExpectedResult,
    label: &str,
    depth: usize,
) {
    let chain_epoch = state.chain_epoch();
    assert_eq!(
        state.current_epoch, chain_epoch,
        "{label}: model epoch {:?} disagrees with chain {:?}",
        state.current_epoch, chain_epoch,
    );

    let tx_out = unwrap_single_tx_success(result, label);
    let stack_depth = 2 * depth - 1;
    let limit = if state.is_epoch34() {
        EPOCH34_DEPTH_LIMIT
    } else {
        EPOCH33_DEPTH_LIMIT
    };

    if stack_depth < limit {
        assert!(
            tx_out.vm_error.is_none(),
            "{label}: unexpected VM error at stack_depth={stack_depth} \
             (limit={limit}): {:?}",
            tx_out.vm_error,
        );
        assert_eq!(
            tx_out.return_type,
            ok_true(),
            "{label}: expected (ok true) at stack_depth={stack_depth} \
             (limit={limit})",
        );
        info!(
            "{label}: stack_depth={stack_depth} < limit={limit} — \
             succeeded with (ok true)",
        );
    } else {
        assert!(
            tx_out.vm_error.is_some(),
            "{label}: expected MaxStackDepthReached at \
             stack_depth={stack_depth} (limit={limit}), got none",
        );
        info!(
            "{label}: stack_depth={stack_depth} >= limit={limit} — \
             MaxStackDepthReached as expected",
        );
    }
}

/// Deploy a short call chain (N=33, stack depth=65). Exceeds Epoch33
/// limit (64) but fits Epoch34 (128).
pub struct DeployCallChainShort;

impl Command<Epoch33ToEpoch34TestState, Epoch33ToEpoch34TestContext> for DeployCallChainShort {
    fn check(&self, state: &Epoch33ToEpoch34TestState) -> bool {
        !state.deployed.contains("chain-short")
    }

    fn apply(&self, state: &mut Epoch33ToEpoch34TestState) {
        deploy_call_chain(state, "chain-short", CHAIN_SHORT_DEPTH);
    }

    fn label(&self) -> String {
        "DEPLOY_CALL_CHAIN_SHORT".to_string()
    }

    fn build(
        _ctx: Arc<Epoch33ToEpoch34TestContext>,
    ) -> impl Strategy<Value = CommandWrapper<Epoch33ToEpoch34TestState, Epoch33ToEpoch34TestContext>>
    {
        Just(CommandWrapper::new(DeployCallChainShort))
    }
}

/// Deploy a long call chain (N=64, stack depth=127). Exact max that fits
/// Epoch34 limit of 128.
pub struct DeployCallChainLong;

impl Command<Epoch33ToEpoch34TestState, Epoch33ToEpoch34TestContext> for DeployCallChainLong {
    fn check(&self, state: &Epoch33ToEpoch34TestState) -> bool {
        state.is_epoch34() && !state.deployed.contains("chain-long")
    }

    fn apply(&self, state: &mut Epoch33ToEpoch34TestState) {
        deploy_call_chain(state, "chain-long", CHAIN_LONG_DEPTH);
    }

    fn label(&self) -> String {
        "DEPLOY_CALL_CHAIN_LONG".to_string()
    }

    fn build(
        _ctx: Arc<Epoch33ToEpoch34TestContext>,
    ) -> impl Strategy<Value = CommandWrapper<Epoch33ToEpoch34TestState, Epoch33ToEpoch34TestContext>>
    {
        Just(CommandWrapper::new(DeployCallChainLong))
    }
}

/// Deploy an over-limit call chain (N=65, stack depth=129). Exact min
/// that exceeds Epoch34's 128.
pub struct DeployCallChainTooLong;

impl Command<Epoch33ToEpoch34TestState, Epoch33ToEpoch34TestContext> for DeployCallChainTooLong {
    fn check(&self, state: &Epoch33ToEpoch34TestState) -> bool {
        state.is_epoch34() && !state.deployed.contains("chain-over")
    }

    fn apply(&self, state: &mut Epoch33ToEpoch34TestState) {
        deploy_call_chain(state, "chain-over", CHAIN_OVER_DEPTH);
    }

    fn label(&self) -> String {
        "DEPLOY_CALL_CHAIN_TOO_LONG".to_string()
    }

    fn build(
        _ctx: Arc<Epoch33ToEpoch34TestContext>,
    ) -> impl Strategy<Value = CommandWrapper<Epoch33ToEpoch34TestState, Epoch33ToEpoch34TestContext>>
    {
        Just(CommandWrapper::new(DeployCallChainTooLong))
    }
}

/// Call short chain leaf.
///
/// Pre-Epoch34: stack depth 65 >= limit 64 -> MaxStackDepthReached.
///
/// Epoch34: stack depth 65 < limit 128 -> (ok true).
pub struct CallChainShort;

impl Command<Epoch33ToEpoch34TestState, Epoch33ToEpoch34TestContext> for CallChainShort {
    fn check(&self, state: &Epoch33ToEpoch34TestState) -> bool {
        state.deployed.contains("chain-short")
    }

    fn apply(&self, state: &mut Epoch33ToEpoch34TestState) {
        let result = call_chain_leaf(state, "chain-short", CHAIN_SHORT_DEPTH);
        assert_chain_call_result(state, &result, "CallChainShort", CHAIN_SHORT_DEPTH);
    }

    fn label(&self) -> String {
        "CALL_CHAIN_SHORT".to_string()
    }

    fn build(
        _ctx: Arc<Epoch33ToEpoch34TestContext>,
    ) -> impl Strategy<Value = CommandWrapper<Epoch33ToEpoch34TestState, Epoch33ToEpoch34TestContext>>
    {
        Just(CommandWrapper::new(CallChainShort))
    }
}

/// Call long chain leaf at Epoch34. Stack depth 127 < limit 128 -> success
/// at the exact boundary.
pub struct CallChainLong;

impl Command<Epoch33ToEpoch34TestState, Epoch33ToEpoch34TestContext> for CallChainLong {
    fn check(&self, state: &Epoch33ToEpoch34TestState) -> bool {
        state.is_epoch34() && state.deployed.contains("chain-long")
    }

    fn apply(&self, state: &mut Epoch33ToEpoch34TestState) {
        let result = call_chain_leaf(state, "chain-long", CHAIN_LONG_DEPTH);
        assert_chain_call_result(state, &result, "CallChainLong", CHAIN_LONG_DEPTH);
    }

    fn label(&self) -> String {
        "CALL_CHAIN_LONG".to_string()
    }

    fn build(
        _ctx: Arc<Epoch33ToEpoch34TestContext>,
    ) -> impl Strategy<Value = CommandWrapper<Epoch33ToEpoch34TestState, Epoch33ToEpoch34TestContext>>
    {
        Just(CommandWrapper::new(CallChainLong))
    }
}

/// Call over-limit chain leaf at Epoch34. Stack depth 129 >= limit 128 ->
/// MaxStackDepthReached at the exact boundary.
pub struct CallChainTooLong;

impl Command<Epoch33ToEpoch34TestState, Epoch33ToEpoch34TestContext> for CallChainTooLong {
    fn check(&self, state: &Epoch33ToEpoch34TestState) -> bool {
        state.is_epoch34() && state.deployed.contains("chain-over")
    }

    fn apply(&self, state: &mut Epoch33ToEpoch34TestState) {
        let result = call_chain_leaf(state, "chain-over", CHAIN_OVER_DEPTH);
        assert_chain_call_result(state, &result, "CallChainTooLong", CHAIN_OVER_DEPTH);
    }

    fn label(&self) -> String {
        "CALL_CHAIN_TOO_LONG".to_string()
    }

    fn build(
        _ctx: Arc<Epoch33ToEpoch34TestContext>,
    ) -> impl Strategy<Value = CommandWrapper<Epoch33ToEpoch34TestState, Epoch33ToEpoch34TestContext>>
    {
        Just(CommandWrapper::new(CallChainTooLong))
    }
}
