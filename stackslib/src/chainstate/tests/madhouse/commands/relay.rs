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

use clarity::types::StacksEpochId;
use clarity::vm::ClarityVersion;
use madhouse::{Command, CommandWrapper};
use proptest::prelude::Strategy;

use super::unwrap_single_tx_success;
use crate::chainstate::tests::consensus::{ConsensusUtils, TestBlock};
use crate::chainstate::tests::madhouse::context::Epoch33ToEpoch34TestContext;
use crate::chainstate::tests::madhouse::state::Epoch33ToEpoch34TestState;
use crate::net::relay::Relayer;

/// The parser's AST depth buffer above `max_call_stack_depth`.  Must match
/// `AST_CALL_STACK_DEPTH_BUFFER` in `clarity/src/vm/ast/stack_depth_checker.rs`.
const AST_DEPTH_BUFFER: u64 = 5;

/// AST nesting overhead from `(define-public (deep) (ok ...))` — one list
/// level each for `define-public` and `ok`.  Specific to `make_deep_expression`.
const WRAPPER_OVERHEAD: usize = 2;

/// Build a Clarity expression with the given nesting depth. Each level wraps
/// in `(begin ...)`. The total AST nesting depth is `depth + WRAPPER_OVERHEAD`
/// due to `(define-public (deep) (ok ...))`.
fn make_deep_expression(depth: usize) -> String {
    let mut code = String::from("1");
    for _ in 0..depth {
        code = format!("(begin {code})");
    }
    format!("(define-public (deep) (ok {code}))")
}

/// Relay + mine command for deeply nested contracts.
///
/// Pre-Epoch34: the relay filter rejects the deep AST. No mining occurs.
///
/// Epoch34: the relay filter accepts, and the contract is mined on-chain.
/// Each invocation uses a unique suffix so the command is repeatable.
pub struct RelayDeepContract {
    depth: usize,
    suffix: u16,
}

impl RelayDeepContract {
    fn contract_name(&self) -> String {
        format!("deep-{}", self.suffix)
    }
}

impl Command<Epoch33ToEpoch34TestState, Epoch33ToEpoch34TestContext> for RelayDeepContract {
    fn check(&self, state: &Epoch33ToEpoch34TestState) -> bool {
        // Epoch34 deploys need a fresh name. Pre-Epoch34 never mines so the
        // name doesn't matter, but skipping duplicates keeps things clean.
        !state.deployed.contains(&self.contract_name())
    }

    fn apply(&self, state: &mut Epoch33ToEpoch34TestState) {
        let code = make_deep_expression(self.depth);
        let version = ClarityVersion::default_for_epoch(state.current_epoch);
        let name = self.contract_name();

        let deploy_tx =
            ConsensusUtils::new_deploy_tx(state.next_nonce, &name, &code, Some(version));
        let relay_result =
            Relayer::static_check_problematic_relayed_tx(false, state.current_epoch, &deploy_tx);

        // The AST nesting depth includes wrapper overhead from
        // `(define-public (deep) (ok ...))`.
        let ast_depth = (self.depth + WRAPPER_OVERHEAD) as u64;
        let call_stack_limit = if state.chain_epoch() >= StacksEpochId::Epoch34 {
            128
        } else {
            64
        };
        let parser_limit = call_stack_limit + AST_DEPTH_BUFFER;

        // Epoch34+ skips the relay depth check entirely
        // (`rejects_parse_depth_errors` returns false), so the relay always
        // accepts.  Pre-Epoch34, rejection depends on whether the AST depth
        // reaches the parser limit.
        let expect_relay_reject = !state.is_epoch34() && ast_depth >= parser_limit;

        if expect_relay_reject {
            assert!(
                relay_result.is_err(),
                "RelayDeepContract: pre-Epoch34 should reject '{}' (depth={}, ast_depth={}, parser_limit={}), got: {:?}",
                name,
                self.depth,
                ast_depth,
                parser_limit,
                relay_result,
            );

            info!(
                "RelayDeepContract: depth={} (ast_depth={}) rejected by relay in {}",
                self.depth, ast_depth, state.current_epoch,
            );
        } else {
            assert!(
                relay_result.is_ok(),
                "RelayDeepContract: should accept '{}' (depth={}, ast_depth={}, parser_limit={}, epoch={}), got: {:?}",
                name,
                self.depth,
                ast_depth,
                parser_limit,
                state.current_epoch,
                relay_result,
            );

            let block = TestBlock {
                transactions: vec![deploy_tx],
            };
            let is_naka = state.current_epoch.uses_nakamoto_blocks();
            let result = state.chain.append_block(block, is_naka);

            let tx_out = unwrap_single_tx_success(&result, "RelayDeepContract");
            assert!(
                tx_out.vm_error.is_none(),
                "RelayDeepContract: VM error mining '{}' (depth={}, epoch={}): {:?}",
                name,
                self.depth,
                state.current_epoch,
                tx_out.vm_error,
            );

            state.next_nonce += 1;
            state.deployed.insert(name.clone());

            info!(
                "RelayDeepContract: depth={} '{}' relayed and mined in {}",
                self.depth, name, state.current_epoch,
            );
        }
    }

    fn label(&self) -> String {
        format!(
            "RELAY_DEEP_CONTRACT(depth={}, suffix={})",
            self.depth, self.suffix
        )
    }

    fn build(
        _ctx: Arc<Epoch33ToEpoch34TestContext>,
    ) -> impl Strategy<Value = CommandWrapper<Epoch33ToEpoch34TestState, Epoch33ToEpoch34TestContext>>
    {
        // Depth exceeds the Epoch33 relay filter threshold but stays within
        // practical mining limits. Suffix provides unique contract names.
        (65usize..120, proptest::num::u16::ANY)
            .prop_map(|(depth, suffix)| CommandWrapper::new(RelayDeepContract { depth, suffix }))
    }
}
