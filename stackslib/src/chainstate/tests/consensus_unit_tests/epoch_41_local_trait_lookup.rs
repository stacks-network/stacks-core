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

//! From Epoch 4.1, a contract can dispatch through a trait it defines at the
//! top level while it deploys. Before, the trait was looked up in the database,
//! where the deploying contract is not yet stored.

use clarity::types::StacksEpochId;
use clarity::vm::ClarityVersion;

use crate::chainstate::tests::consensus::{contract_deploy_consensus_unit_test, SetupContract};

const TARGET: &str = "(define-public (foo) (ok true))";

const DISPATCHER: &str = "
    (define-trait trait-1 ((foo () (response bool uint))))
    (define-private (bar (f <trait-1>))
      (unwrap-panic (contract-call? f foo)))
    (bar .target)";

/// The deploy fails at 4.0 with an includable runtime error and executes at 4.1.
#[test]
fn test_epoch41_dispatches_through_own_trait_while_deploying() {
    let report = contract_deploy_consensus_unit_test!(
        contract_name: "dispatcher",
        contract_code: DISPATCHER,
        deploy_epochs: &[StacksEpochId::Epoch40, StacksEpochId::Epoch41],
        clarity_versions: &[ClarityVersion::Clarity6, ClarityVersion::Clarity7],
        setup_contracts: &[SetupContract::new("target", TARGET)
            .with_epoch(StacksEpochId::Epoch40)
            .with_clarity_version(ClarityVersion::Clarity6)],
    );
    assert!(report.all_blocks_accepted());
    let deploys = report.contract_deploys();
    assert_eq!(deploys.len(), 2);
    for deploy in deploys {
        match deploy.contract_epoch() {
            StacksEpochId::Epoch40 => assert!(
                deploy.vm_error().unwrap().contains("NoSuchContract"),
                "{deploy:?}"
            ),
            StacksEpochId::Epoch41 => assert!(deploy.executed(), "{deploy:?}"),
            other => panic!("unexpected deploy epoch {other}"),
        }
    }
}
