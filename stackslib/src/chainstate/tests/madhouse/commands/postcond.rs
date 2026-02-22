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
use proptest::prelude::Strategy;

use super::{unwrap_block_failure, unwrap_single_tx_success};
use crate::chainstate::tests::consensus::{ConsensusUtils, TestBlock};
use crate::chainstate::tests::madhouse::context::Epoch33ToEpoch34TestContext;
use crate::chainstate::tests::madhouse::state::Epoch33ToEpoch34TestState;

fn ok_true() -> Value {
    Value::Response(ResponseData {
        committed: true,
        data: Box::new(Value::Bool(true)),
    })
}

fn err_u0() -> Value {
    Value::Response(ResponseData {
        committed: false,
        data: Box::new(Value::UInt(0)),
    })
}

/// Generates the with-stx contract code. Embeds the fund amount as top-level
/// code so the contract is funded for `as-contract?` tests at deploy time.
fn with_stx_contract_code(fund_amount: u64) -> String {
    format!(
        r#"
;; Restrict the caller's STX operations. The combined transfer + burn is
;; checked against the allowance by check_allowances after the body executes.
(define-public (test-restrict
        (allowance uint)
        (transfer-amount uint)
        (burn-amount uint)
    )
    (restrict-assets? tx-sender
        ((with-stx allowance))
        (begin
            (try! (stx-transfer? transfer-amount tx-sender current-contract))
            (try! (stx-burn? burn-amount tx-sender)))
    )
)

;; Restrict the contract's STX operations. as-contract? switches tx-sender to
;; current-contract, so the contract can transfer and burn its own STX. The
;; combined total is checked against the allowance.
(define-public (test-as-contract
        (allowance uint)
        (transfer-amount uint)
        (burn-amount uint)
    )
    (let
        ((recipient tx-sender))
        (as-contract?
            ((with-stx allowance))
            (begin
                (try! (stx-transfer? transfer-amount tx-sender recipient))
                (try! (stx-burn? burn-amount tx-sender)))
        )
    )
)

;; Fund the contract for as-contract? tests.
(unwrap-panic
    (stx-transfer? u{fund_amount} tx-sender
        current-contract))
"#
    )
}

/// Deploys the contract-level with-stx postconditions test contract and funds
/// it via top-level `stx-transfer?`.
///
/// Deploy-once, call-many: the same contract instance is called in both
/// Epoch33 and Epoch34. This checks `check_allowances` gates on the epoch at
/// call time, not deploy time.
pub struct DeployContractLvlPostCondContract {
    fund_amount: u64,
}

impl Command<Epoch33ToEpoch34TestState, Epoch33ToEpoch34TestContext>
    for DeployContractLvlPostCondContract
{
    fn check(&self, state: &Epoch33ToEpoch34TestState) -> bool {
        !state.deployed.contains("with-stx")
    }

    fn apply(&self, state: &mut Epoch33ToEpoch34TestState) {
        let version = ClarityVersion::default_for_epoch(state.current_epoch);
        let code = with_stx_contract_code(self.fund_amount);
        let deploy_tx =
            ConsensusUtils::new_deploy_tx(state.next_nonce, "with-stx", &code, Some(version));

        let block = TestBlock {
            transactions: vec![deploy_tx],
        };
        let is_naka = state.current_epoch.uses_nakamoto_blocks();
        let result = state.chain.append_block(block, is_naka);

        let tx_out = unwrap_single_tx_success(&result, "DeployContractLvlPostCondContract");
        assert!(
            tx_out.vm_error.is_none(),
            "DeployContractLvlPostCondContract: VM error: {:?}",
            tx_out.vm_error,
        );

        state.next_nonce += 1;
        state.deployed.insert("with-stx".to_string());
        state.contract_stx_balance = self.fund_amount;

        info!(
            "DeployContractLvlPostCondContract: deployed and funded {} STX in {}",
            self.fund_amount, state.current_epoch,
        );
    }

    fn label(&self) -> String {
        "DEPLOY_CL_PC_CONTRACT".to_string()
    }

    fn build(
        _ctx: Arc<Epoch33ToEpoch34TestContext>,
    ) -> impl Strategy<Value = CommandWrapper<Epoch33ToEpoch34TestState, Epoch33ToEpoch34TestContext>>
    {
        (500_000u64..1_000_000).prop_map(|fund_amount| {
            CommandWrapper::new(DeployContractLvlPostCondContract { fund_amount })
        })
    }
}

/// Calls `test-restrict` with `allowance >= transfer + burn`. Expected:
/// `(ok true)` in both epochs.
pub struct CallRestrictWithStxSafe {
    transfer: u64,
    burn: u64,
    allowance: u64,
}

impl Command<Epoch33ToEpoch34TestState, Epoch33ToEpoch34TestContext> for CallRestrictWithStxSafe {
    fn check(&self, state: &Epoch33ToEpoch34TestState) -> bool {
        state.deployed.contains("with-stx")
    }

    fn apply(&self, state: &mut Epoch33ToEpoch34TestState) {
        let call_tx = ConsensusUtils::new_call_tx_with_args(
            state.next_nonce,
            "with-stx",
            "test-restrict",
            &[
                // (allowance uint)
                Value::UInt(self.allowance as u128),
                // (transfer-amount uint)
                Value::UInt(self.transfer as u128),
                // (burn-amount uint)
                Value::UInt(self.burn as u128),
            ],
        );

        let block = TestBlock {
            transactions: vec![call_tx],
        };
        let is_naka = state.current_epoch.uses_nakamoto_blocks();
        let result = state.chain.append_block(block, is_naka);

        let tx_out = unwrap_single_tx_success(&result, "CallRestrictWithStxSafe");
        assert!(
            tx_out.vm_error.is_none(),
            "CallRestrictWithStxSafe: VM error in {}: {:?}",
            state.current_epoch,
            tx_out.vm_error,
        );
        assert_eq!(
            tx_out.return_type,
            ok_true(),
            "CallRestrictWithStxSafe: expected (ok true) in {}, got {:?}",
            state.current_epoch,
            tx_out.return_type,
        );

        state.next_nonce += 1;

        info!(
            "CallRestrictWithStxSafe: passed in {} (allowance={}, transfer={}, burn={})",
            state.current_epoch, self.allowance, self.transfer, self.burn,
        );
    }

    fn label(&self) -> String {
        "CALL_RESTRICT_WITH_STX_SAFE".to_string()
    }

    fn build(
        _ctx: Arc<Epoch33ToEpoch34TestContext>,
    ) -> impl Strategy<Value = CommandWrapper<Epoch33ToEpoch34TestState, Epoch33ToEpoch34TestContext>>
    {
        // Three independent dimensions. Buffer guarantees:
        // allowance >= transfer + burn.
        (1u64..5_000, 1u64..5_000, 0u64..5_000).prop_map(|(transfer, burn, buffer)| {
            CommandWrapper::new(CallRestrictWithStxSafe {
                transfer,
                burn,
                allowance: transfer + burn + buffer,
            })
        })
    }
}

/// Calls `test-restrict` where each operation individually fits the allowance
/// but the combined total exceeds it: `max(transfer, burn) <= allowance <
/// transfer + burn`.
///
/// Pre-Epoch34: `VmInternalError::Expect` -> `Rejectable` -> block rejected.
///
/// Epoch34: clean `(err u0)` Clarity response, effects rolled back.
pub struct CallRestrictWithStxCombinedExceeds {
    transfer: u64,
    burn: u64,
    allowance: u64,
}

impl Command<Epoch33ToEpoch34TestState, Epoch33ToEpoch34TestContext>
    for CallRestrictWithStxCombinedExceeds
{
    fn check(&self, state: &Epoch33ToEpoch34TestState) -> bool {
        state.deployed.contains("with-stx")
    }

    fn apply(&self, state: &mut Epoch33ToEpoch34TestState) {
        // Verify the model agrees with the chain before branching.
        let chain_epoch = state.chain_epoch();
        assert_eq!(
            state.current_epoch, chain_epoch,
            "CallRestrictWithStxCombinedExceeds: model epoch {:?} disagrees with chain {:?}",
            state.current_epoch, chain_epoch,
        );

        let call_tx = ConsensusUtils::new_call_tx_with_args(
            state.next_nonce,
            "with-stx",
            "test-restrict",
            &[
                // (allowance uint)
                Value::UInt(self.allowance as u128),
                // (transfer-amount uint)
                Value::UInt(self.transfer as u128),
                // (burn-amount uint)
                Value::UInt(self.burn as u128),
            ],
        );

        let block = TestBlock {
            transactions: vec![call_tx],
        };
        let is_naka = state.current_epoch.uses_nakamoto_blocks();
        let result = state.chain.append_block(block, is_naka);

        if state.is_epoch34() {
            let tx_out = unwrap_single_tx_success(&result, "CallRestrictWithStxCombinedExceeds");
            assert!(
                tx_out.vm_error.is_none(),
                "CallRestrictWithStxCombinedExceeds: VM error in {}: {:?}",
                state.current_epoch,
                tx_out.vm_error,
            );
            assert_eq!(
                tx_out.return_type,
                err_u0(),
                "CallRestrictWithStxCombinedExceeds: expected (err u0) in {}, got {:?}",
                state.current_epoch,
                tx_out.return_type,
            );
            state.next_nonce += 1;
        } else {
            unwrap_block_failure(&result, "CallRestrictWithStxCombinedExceeds");
        }

        info!(
            "CallRestrictWithStxCombinedExceeds: {} in {} (allowance={}, transfer={}, burn={})",
            if state.is_epoch34() {
                "(err u0)"
            } else {
                "block rejected"
            },
            state.current_epoch,
            self.allowance,
            self.transfer,
            self.burn,
        );
    }

    fn label(&self) -> String {
        "CALL_RESTRICT_WITH_STX_COMBINED_EXCEEDS".to_string()
    }

    fn build(
        _ctx: Arc<Epoch33ToEpoch34TestContext>,
    ) -> impl Strategy<Value = CommandWrapper<Epoch33ToEpoch34TestState, Epoch33ToEpoch34TestContext>>
    {
        // Generate transfer and burn independently, then pick allowance in
        // [max(t,b), t+b). Each op individually fits the allowance but the
        // combined total exceeds it.
        (1u64..5_000, 1u64..5_000).prop_flat_map(|(transfer, burn)| {
            let lo = std::cmp::max(transfer, burn);
            let hi = transfer + burn;
            (lo..hi).prop_map(move |allowance| {
                CommandWrapper::new(CallRestrictWithStxCombinedExceeds {
                    transfer,
                    burn,
                    allowance,
                })
            })
        })
    }
}

/// Calls `test-as-contract` with `allowance >= transfer + burn`. Expected:
/// `(ok true)` in both epochs.
pub struct CallAsContractWithStxSafe {
    transfer: u64,
    burn: u64,
    allowance: u64,
}

impl Command<Epoch33ToEpoch34TestState, Epoch33ToEpoch34TestContext> for CallAsContractWithStxSafe {
    fn check(&self, state: &Epoch33ToEpoch34TestState) -> bool {
        // Contract must be deployed and have enough balance to cover both
        // the transfer (back to faucet) and the burn.
        state.deployed.contains("with-stx")
            && state.contract_stx_balance >= self.transfer + self.burn
    }

    fn apply(&self, state: &mut Epoch33ToEpoch34TestState) {
        let call_tx = ConsensusUtils::new_call_tx_with_args(
            state.next_nonce,
            "with-stx",
            "test-as-contract",
            &[
                // (allowance uint)
                Value::UInt(self.allowance as u128),
                // (transfer-amount uint)
                Value::UInt(self.transfer as u128),
                // (burn-amount uint)
                Value::UInt(self.burn as u128),
            ],
        );

        let block = TestBlock {
            transactions: vec![call_tx],
        };
        let is_naka = state.current_epoch.uses_nakamoto_blocks();
        let result = state.chain.append_block(block, is_naka);

        let tx_out = unwrap_single_tx_success(&result, "CallAsContractWithStxSafe");
        assert!(
            tx_out.vm_error.is_none(),
            "CallAsContractWithStxSafe: VM error in {}: {:?}",
            state.current_epoch,
            tx_out.vm_error,
        );
        assert_eq!(
            tx_out.return_type,
            ok_true(),
            "CallAsContractWithStxSafe: expected (ok true) in {}, got {:?}",
            state.current_epoch,
            tx_out.return_type,
        );

        state.next_nonce += 1;
        // Transfer goes back to the caller; burn is destroyed.
        state.contract_stx_balance -= self.transfer + self.burn;

        info!(
            "CallAsContractWithStxSafe: passed in {} (allowance={}, transfer={}, burn={}, contract_balance={})",
            state.current_epoch, self.allowance, self.transfer, self.burn, state.contract_stx_balance,
        );
    }

    fn label(&self) -> String {
        "CALL_AS_CONTRACT_WITH_STX_SAFE".to_string()
    }

    fn build(
        _ctx: Arc<Epoch33ToEpoch34TestContext>,
    ) -> impl Strategy<Value = CommandWrapper<Epoch33ToEpoch34TestState, Epoch33ToEpoch34TestContext>>
    {
        // Three independent dimensions. Buffer guarantees:
        // allowance >= transfer + burn.
        (1u64..5_000, 1u64..5_000, 0u64..5_000).prop_map(|(transfer, burn, buffer)| {
            CommandWrapper::new(CallAsContractWithStxSafe {
                transfer,
                burn,
                allowance: transfer + burn + buffer,
            })
        })
    }
}

/// Same combined-exceeds logic as `CallRestrictWithStxCombinedExceeds` but via
/// `as-contract?`. Same epoch-dependent behavior.
pub struct CallAsContractWithStxCombinedExceeds {
    transfer: u64,
    burn: u64,
    allowance: u64,
}

impl Command<Epoch33ToEpoch34TestState, Epoch33ToEpoch34TestContext>
    for CallAsContractWithStxCombinedExceeds
{
    fn check(&self, state: &Epoch33ToEpoch34TestState) -> bool {
        // Contract must have enough balance for the body to fully execute
        // (stx-transfer? then stx-burn?). Otherwise `try!` short-circuits on
        // insufficient balance before the combined check triggers.
        state.deployed.contains("with-stx")
            && state.contract_stx_balance >= self.transfer + self.burn
    }

    fn apply(&self, state: &mut Epoch33ToEpoch34TestState) {
        // Verify the model agrees with the chain before branching.
        let chain_epoch = state.chain_epoch();
        assert_eq!(
            state.current_epoch, chain_epoch,
            "CallAsContractWithStxCombinedExceeds: model epoch {:?} disagrees with chain {:?}",
            state.current_epoch, chain_epoch,
        );

        let call_tx = ConsensusUtils::new_call_tx_with_args(
            state.next_nonce,
            "with-stx",
            "test-as-contract",
            &[
                Value::UInt(self.allowance as u128),
                Value::UInt(self.transfer as u128),
                Value::UInt(self.burn as u128),
            ],
        );

        let block = TestBlock {
            transactions: vec![call_tx],
        };
        let is_naka = state.current_epoch.uses_nakamoto_blocks();
        let result = state.chain.append_block(block, is_naka);

        if state.is_epoch34() {
            let tx_out = unwrap_single_tx_success(&result, "CallAsContractWithStxCombinedExceeds");
            assert!(
                tx_out.vm_error.is_none(),
                "CallAsContractWithStxCombinedExceeds: VM error in {}: {:?}",
                state.current_epoch,
                tx_out.vm_error,
            );
            assert_eq!(
                tx_out.return_type,
                err_u0(),
                "CallAsContractWithStxCombinedExceeds: expected (err u0) in {}, got {:?}",
                state.current_epoch,
                tx_out.return_type,
            );
            state.next_nonce += 1;
        } else {
            unwrap_block_failure(&result, "CallAsContractWithStxCombinedExceeds");
        }

        info!(
            "CallAsContractWithStxCombinedExceeds: {} in {} (allowance={}, transfer={}, burn={})",
            if state.is_epoch34() {
                "(err u0)"
            } else {
                "block rejected"
            },
            state.current_epoch,
            self.allowance,
            self.transfer,
            self.burn,
        );
    }

    fn label(&self) -> String {
        "CALL_AS_CONTRACT_WITH_STX_COMBINED_EXCEEDS".to_string()
    }

    fn build(
        _ctx: Arc<Epoch33ToEpoch34TestContext>,
    ) -> impl Strategy<Value = CommandWrapper<Epoch33ToEpoch34TestState, Epoch33ToEpoch34TestContext>>
    {
        // Generate transfer and burn independently, then pick allowance in
        // [max(t,b), t+b). Each op individually fits the allowance but the
        // combined total exceeds it.
        (1u64..5_000, 1u64..5_000).prop_flat_map(|(transfer, burn)| {
            let lo = std::cmp::max(transfer, burn);
            let hi = transfer + burn;
            (lo..hi).prop_map(move |allowance| {
                CommandWrapper::new(CallAsContractWithStxCombinedExceeds {
                    transfer,
                    burn,
                    allowance,
                })
            })
        })
    }
}
