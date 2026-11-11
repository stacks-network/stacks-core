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

use madhouse::{Command, CommandWrapper};
use proptest::prelude::{Just, Strategy};
use stacks_common::types::StacksEpochId;

use crate::chainstate::tests::madhouse::context::Epoch33ToEpoch34TestContext;
use crate::chainstate::tests::madhouse::state::Epoch33ToEpoch34TestState;

/// Advances the chain from Epoch33 into Epoch34. Only fires once per scenario;
/// `check()` prevents re-entry.
pub struct AdvanceToEpoch34;

impl Command<Epoch33ToEpoch34TestState, Epoch33ToEpoch34TestContext> for AdvanceToEpoch34 {
    fn check(&self, state: &Epoch33ToEpoch34TestState) -> bool {
        !state.is_epoch34()
    }

    fn apply(&self, state: &mut Epoch33ToEpoch34TestState) {
        info!("AdvanceToEpoch34: transitioning from Epoch33 to Epoch34");

        let miner_key = state.chain.test_chainstate.miner.nakamoto_miner_key();
        state
            .chain
            .test_chainstate
            .advance_into_epoch(&miner_key, StacksEpochId::Epoch34);

        state.current_epoch = StacksEpochId::Epoch34;

        info!("AdvanceToEpoch34: now in Epoch34");
    }

    fn label(&self) -> String {
        "ADVANCE_TO_EPOCH34".to_string()
    }

    fn build(
        _ctx: Arc<Epoch33ToEpoch34TestContext>,
    ) -> impl Strategy<Value = CommandWrapper<Epoch33ToEpoch34TestState, Epoch33ToEpoch34TestContext>>
    {
        Just(CommandWrapper::new(AdvanceToEpoch34))
    }
}
