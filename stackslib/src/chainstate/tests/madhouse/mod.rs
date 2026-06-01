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

mod commands;
mod context;
mod state;

use std::sync::Arc;

use madhouse::{execute_commands, prop_allof, scenario, Command};
use proptest::prelude::Strategy;

use self::commands::*;
use self::context::Epoch33ToEpoch34TestContext;

/// Pre-Epoch34 returns a block-invalidating `Rejectable` error; Epoch34
/// returns `(err u0)` with effects rolled back. Both "safe" (within allowance)
/// and "combined-exceeds" (each op passes individually, combined total exceeds)
/// are exercised in each epoch.
#[test]
fn scenario_with_stx_postconditions() {
    let ctx = Arc::new(Epoch33ToEpoch34TestContext::default());

    scenario![
        ctx,
        // -- Deploy (Epoch33) --
        DeployContractLvlPostCondContract,
        // -- Epoch33: combined-exceeds -> Rejectable --
        CallRestrictWithStxSafe,
        CallRestrictWithStxCombinedExceeds,
        CallAsContractWithStxSafe,
        CallAsContractWithStxCombinedExceeds,
        // -- Transition --
        AdvanceToEpoch34,
        // -- Epoch34: combined-exceeds -> (err u0) --
        CallRestrictWithStxSafe,
        CallRestrictWithStxCombinedExceeds,
        CallAsContractWithStxSafe,
        CallAsContractWithStxCombinedExceeds,
    ];
}

/// A 33-contract chain (depth=65) exceeds the Epoch33 limit but fits Epoch34.
/// A 64-contract chain (depth=127) is the exact max for Epoch34. A 65-contract
/// chain (depth=129) exceeds even Epoch34.
#[test]
fn scenario_depth_limits() {
    let ctx = Arc::new(Epoch33ToEpoch34TestContext::default());

    scenario![
        ctx,
        // -- Epoch33: short chain exceeds 64 --
        DeployCallChainShort,
        CallChainShort,
        // -- Transition --
        AdvanceToEpoch34,
        // -- Epoch34: short chain now fits 128 --
        CallChainShort,
        // -- Exact boundary: 127 fits, 129 exceeds --
        DeployCallChainLong,
        CallChainLong,
        DeployCallChainTooLong,
        CallChainTooLong,
    ];
}

/// `secp256r1-verify` semantics differ by Clarity version: C4 double-hashes,
/// C5 uses prehash. Each command deploys a contract with a strategy-generated
/// key pair and calls its public function to verify the expected result.
/// Cross-version call proves the callee's version governs, not the caller's.
/// Epoch34-only because Clarity5 requires Epoch34.
#[test]
fn scenario_cross_version_calls() {
    let ctx = Arc::new(Epoch33ToEpoch34TestContext::default());

    scenario![
        ctx,
        AdvanceToEpoch34,
        // C4 double-hash sig (ok true).
        VerifyC4DoubleHash,
        // C5 double-hash sig (ok false), prehash rejects.
        VerifyC5DoubleHash,
        // C5 prehash sig (ok true), prehash matches.
        VerifyC5Prehash,
        // C4 caller C5 callee: callee's version governs (ok false).
        CallC5ViaC4Caller,
    ];
}

/// SIP-040 post-condition new features: `Originator` mode and `MaybeSent`
/// condition code. Pre-Epoch34 both features are rejected by static epoch
/// validation. Epoch34 exercises all happy and failure paths.
#[test]
fn scenario_sip040_postconditions() {
    let ctx = Arc::new(Epoch33ToEpoch34TestContext::default());

    scenario![
        ctx,
        // -- Deploy (Epoch33) --
        DeployNftContract,
        // -- Epoch33: SIP-040 features rejected --
        PreEpoch34SIP040Rejected,
        // -- Transition --
        AdvanceToEpoch34,
        // -- Epoch34: Originator + MaybeSent --
        MintSendOriginatorMode,
        MintSendDenyMode,
        OriginatorSendsWithPostCond,
        SendNftMaybeSentActuallySent,
        MintNftMaybeSentNotSent,
        OriginatorSendsNoPostCond,
        // -- Multi-tx sequences --
        MultiTxMintThenSend,
        MultiTxStxPerTxPostConds,
        OriginatorMultiTxMixed,
    ];
}

/// The same command checks the relay filter AND mines the contract. Pre-Epoch34
/// the relay rejects (no mining). Epoch34 the relay accepts and the contract is
/// deployed on-chain.
#[test]
fn scenario_relay_filter() {
    let ctx = Arc::new(Epoch33ToEpoch34TestContext::default());

    scenario![
        ctx,
        // -- Epoch33: relay rejects --
        RelayDeepContract,
        // -- Transition --
        AdvanceToEpoch34,
        // -- Epoch34: relay accepts, mines --
        RelayDeepContract,
    ];
}

/// Unified scenario exercising all Epoch34 behavioral changes in a single
/// chain. Deterministic order covers the full happy-path. `MADHOUSE=1`
/// randomizes command selection so that `check()` guards enforce valid
/// interleavings, uncovering ordering-dependent and cross-feature interaction
/// bugs.
#[test]
fn scenario_epoch34_full() {
    let ctx = Arc::new(Epoch33ToEpoch34TestContext::default());

    scenario![
        ctx,
        // -- Deploy contracts (Epoch33) --
        DeployContractLvlPostCondContract,
        DeployCallChainShort,
        DeployNftContract,
        // -- Epoch33 behavior --
        RelayDeepContract,
        CallRestrictWithStxSafe,
        CallRestrictWithStxCombinedExceeds,
        CallAsContractWithStxSafe,
        CallAsContractWithStxCombinedExceeds,
        CallChainShort,
        PreEpoch34SIP040Rejected,
        // -- Transition --
        AdvanceToEpoch34,
        // -- Epoch34 behavior --
        RelayDeepContract,
        CallRestrictWithStxSafe,
        CallRestrictWithStxCombinedExceeds,
        CallAsContractWithStxSafe,
        CallAsContractWithStxCombinedExceeds,
        CallChainShort,
        VerifyC4DoubleHash,
        VerifyC5DoubleHash,
        VerifyC5Prehash,
        CallC5ViaC4Caller,
        DeployCallChainLong,
        CallChainLong,
        DeployCallChainTooLong,
        CallChainTooLong,
        // -- SIP-040 --
        MintSendOriginatorMode,
        MintSendDenyMode,
        OriginatorSendsWithPostCond,
        SendNftMaybeSentActuallySent,
        MintNftMaybeSentNotSent,
        OriginatorSendsNoPostCond,
        MultiTxMintThenSend,
        MultiTxStxPerTxPostConds,
        OriginatorMultiTxMixed,
    ];
}
