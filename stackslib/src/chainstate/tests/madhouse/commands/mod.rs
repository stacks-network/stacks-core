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

pub mod advance;
pub mod cross_call;
pub mod depth;
pub mod postcond;
pub mod relay;

pub use advance::AdvanceToEpoch34;

use crate::chainstate::tests::consensus::{ExpectedResult, ExpectedTransactionOutput};

/// Unwrap a single-tx block success. Panics with `label` on failure or
/// unexpected tx count.
pub fn unwrap_single_tx_success<'a>(
    result: &'a ExpectedResult,
    label: &str,
) -> &'a ExpectedTransactionOutput {
    let ExpectedResult::Success(output) = result else {
        panic!("{label}: expected block success, got: {result:?}");
    };
    assert_eq!(
        output.transactions.len(),
        1,
        "{label}: expected 1 tx output, got {}",
        output.transactions.len(),
    );
    &output.transactions[0]
}

/// Unwrap a block failure. Panics with `label` if the block succeeded.
pub fn unwrap_block_failure(result: &ExpectedResult, label: &str) {
    let ExpectedResult::Failure(_) = result else {
        panic!("{label}: expected block failure, got: {result:?}");
    };
}
pub use cross_call::{CallC5ViaC4Caller, VerifyC4DoubleHash, VerifyC5DoubleHash, VerifyC5Prehash};
pub use depth::{
    CallChainLong, CallChainShort, CallChainTooLong, DeployCallChainLong, DeployCallChainShort,
    DeployCallChainTooLong,
};
pub use postcond::{
    CallAsContractWithStxCombinedExceeds, CallAsContractWithStxSafe,
    CallRestrictWithStxCombinedExceeds, CallRestrictWithStxSafe, DeployContractLvlPostCondContract,
};
pub use relay::RelayDeepContract;
