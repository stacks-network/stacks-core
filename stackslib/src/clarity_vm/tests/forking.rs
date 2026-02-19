// Copyright (C) 2013-2020 Blockstack PBC, a public benefit corporation
// Copyright (C) 2020-2026 Stacks Open Internet Foundation
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
use clarity::vm::analysis::errors::RuntimeCheckErrorKind;
use clarity::vm::contexts::OwnedEnvironment;
use clarity::vm::costs::ExecutionCost;
use clarity::vm::database::BurnStateDB;
use clarity::vm::errors::{ClarityEvalError, RuntimeError, VmExecutionError};
use clarity::vm::test_util::{
    execute, is_committed, is_err_code, symbols_from_values, TEST_BURN_STATE_DB, TEST_HEADER_DB,
};
use clarity::vm::tests::test_clarity_versions;
use clarity::vm::types::{PrincipalData, QualifiedContractIdentifier, TupleData, Value};
use clarity::vm::version::ClarityVersion;
use clarity::vm::{ContractContext, StacksEpoch};
use stacks_common::consts::{BITCOIN_REGTEST_FIRST_BLOCK_HASH, PEER_VERSION_EPOCH_2_0};
use stacks_common::types::chainstate::{
    BlockHeaderHash, BurnchainHeaderHash, ConsensusHash, PoxId, SortitionId, StacksBlockId,
};
use stacks_common::types::StacksEpochId;

use crate::chainstate::stacks::index::ClarityMarfTrieId;
use crate::clarity_vm::clarity::{ClarityMarfStore, ClarityMarfStoreTransaction};
use crate::clarity_vm::database::marf::MarfedKV;

const p1_str: &str = "'SZ2J6ZY48GV1EZ5V2V5RB9MP66SW86PYKKQ9H6DPR";

#[apply(test_clarity_versions)]
fn test_forking_simple(#[case] version: ClarityVersion, #[case] epoch: StacksEpochId) {
    with_separate_forks_environment(
        version,
        epoch,
        initialize_contract,
        |x| {
            branched_execution(version, x, true);
        },
        |x| {
            branched_execution(version, x, true);
        },
        |x| {
            branched_execution(version, x, false);
        },
    );
}

#[apply(test_clarity_versions)]
fn test_at_block_mutations(#[case] version: ClarityVersion, #[case] epoch: StacksEpochId) {
    // test how at-block works when a mutation has occurred
    fn initialize(owned_env: &mut OwnedEnvironment) {
        let c = QualifiedContractIdentifier::local("contract").unwrap();
        let contract =
            "(define-data-var datum int 1)
             (define-public (working)
               (ok (at-block 0x0101010101010101010101010101010101010101010101010101010101010101 (var-get datum))))
             (define-public (broken)
               (begin
                 (var-set datum 10)
                 ;; this should return 1, not 10!
                 (ok (at-block 0x0101010101010101010101010101010101010101010101010101010101010101 (var-get datum)))))";

        eprintln!("Initializing contract...");
        owned_env.initialize_contract(c, contract, None).unwrap();
    }

    fn branch(
        owned_env: &mut OwnedEnvironment,
        version: ClarityVersion,
        expected_value: i128,
        to_exec: &str,
    ) -> Result<Value, VmExecutionError> {
        let c = QualifiedContractIdentifier::local("contract").unwrap();
        let p1 = execute(p1_str).expect_principal().unwrap();
        let placeholder_context =
            ContractContext::new(QualifiedContractIdentifier::transient(), version);
        eprintln!("Branched execution...");

        {
            let mut env = owned_env.get_exec_environment(None, None, &placeholder_context);
            let command = "(var-get datum)";
            let value = env.eval_read_only(&c, command).unwrap();
            assert_eq!(value, Value::Int(expected_value));
        }

        owned_env
            .execute_transaction(p1, None, c, to_exec, &[])
            .map(|(x, _, _)| x)
    }

    with_separate_forks_environment(
        version,
        epoch,
        initialize,
        |x| {
            assert_eq!(
                branch(x, version, 1, "working").unwrap(),
                Value::okay(Value::Int(1)).unwrap()
            );
            assert_eq!(
                branch(x, version, 1, "broken").unwrap(),
                Value::okay(Value::Int(1)).unwrap()
            );
            assert_eq!(
                branch(x, version, 10, "working").unwrap(),
                Value::okay(Value::Int(1)).unwrap()
            );
            // make this test fail: this assertion _should_ be
            //  true, but at-block is broken. when a context
            //  switches to an at-block context, _any_ of the db
            //  wrapping that the Clarity VM does needs to be
            //  ignored.
            assert_eq!(
                branch(x, version, 10, "broken").unwrap(),
                Value::okay(Value::Int(1)).unwrap()
            );
        },
        |_x| {},
        |_x| {},
    );
}

#[apply(test_clarity_versions)]
fn test_at_block_good(#[case] version: ClarityVersion, #[case] epoch: StacksEpochId) {
    fn initialize(owned_env: &mut OwnedEnvironment) {
        let c = QualifiedContractIdentifier::local("contract").unwrap();
        let contract =
            "(define-data-var datum int 1)
             (define-public (reset)
               (begin
                 (var-set datum (+
                   (at-block 0x0202020202020202020202020202020202020202020202020202020202020202 (var-get datum))
                   (at-block 0x0101010101010101010101010101010101010101010101010101010101010101 (var-get datum))))
                 (ok (var-get datum))))
             (define-public (set-val)
               (begin
                 (var-set datum 10)
                 (ok (var-get datum))))";

        eprintln!("Initializing contract...");
        owned_env.initialize_contract(c, contract, None).unwrap();
    }

    fn branch(
        owned_env: &mut OwnedEnvironment,
        version: ClarityVersion,
        expected_value: i128,
        to_exec: &str,
    ) -> Result<Value, VmExecutionError> {
        let c = QualifiedContractIdentifier::local("contract").unwrap();
        let p1 = execute(p1_str).expect_principal().unwrap();
        let placeholder_context =
            ContractContext::new(QualifiedContractIdentifier::transient(), version);
        eprintln!("Branched execution...");

        {
            let mut env = owned_env.get_exec_environment(None, None, &placeholder_context);
            let command = "(var-get datum)";
            let value = env.eval_read_only(&c, command).unwrap();
            assert_eq!(value, Value::Int(expected_value));
        }

        owned_env
            .execute_transaction(p1, None, c, to_exec, &[])
            .map(|(x, _, _)| x)
    }

    with_separate_forks_environment(
        version,
        epoch,
        initialize,
        |x| {
            assert_eq!(
                branch(x, version, 1, "set-val").unwrap(),
                Value::okay(Value::Int(10)).unwrap()
            );
        },
        |x| {
            let resp = branch(x, version, 1, "reset").unwrap_err();
            eprintln!("{}", resp);
            match resp {
                VmExecutionError::Runtime(x, _) => assert_eq!(
                    x,
                    RuntimeError::UnknownBlockHeaderHash(BlockHeaderHash::from(
                        vec![2; 32].as_slice()
                    ))
                ),
                _ => panic!("Unexpected error"),
            }
        },
        |x| {
            assert_eq!(
                branch(x, version, 10, "reset").unwrap(),
                Value::okay(Value::Int(11)).unwrap()
            );
        },
    );
}

#[apply(test_clarity_versions)]
fn test_at_block_missing_defines(#[case] version: ClarityVersion, #[case] epoch: StacksEpochId) {
    fn initialize_1(owned_env: &mut OwnedEnvironment) {
        let c_a = QualifiedContractIdentifier::local("contract-a").unwrap();

        let contract = "(define-map datum { id: bool } { value: int })

             (define-public (flip)
               (let ((current (default-to (get value (map-get?! datum {id: true})) 0)))
                 (map-set datum {id: true} (if (is-eq 1 current) 0 1))
                 (ok current)))";

        eprintln!("Initializing contract...");
        owned_env.initialize_contract(c_a, contract, None).unwrap();
    }

    fn initialize_2(owned_env: &mut OwnedEnvironment) -> ClarityEvalError {
        let c_b = QualifiedContractIdentifier::local("contract-b").unwrap();

        let contract = "(define-private (problematic-cc)
               (at-block 0x0101010101010101010101010101010101010101010101010101010101010101
                 (contract-call? .contract-a flip)))
             (problematic-cc)
            ";

        eprintln!("Initializing contract...");
        let e = owned_env
            .initialize_contract(c_b, contract, None)
            .unwrap_err();
        e
    }

    with_separate_forks_environment(
        version,
        epoch,
        |_| {},
        initialize_1,
        |_| {},
        |env| {
            let err = initialize_2(env);
            assert_eq!(
                err,
                RuntimeCheckErrorKind::NoSuchContract(
                    "S1G2081040G2081040G2081040G208105NK8PE5.contract-a".into()
                )
                .into()
            );
        },
    );
}

#[apply(test_clarity_versions)]
fn test_at_block_bounded_window(#[case] version: ClarityVersion, #[case] epoch: StacksEpochId) {
    fn initialize(owned_env: &mut OwnedEnvironment) {
        let c = QualifiedContractIdentifier::local("contract").unwrap();
        let contract = "(define-data-var datum int 1)
             (define-public (read-historical)
               (ok (at-block 0x0101010101010101010101010101010101010101010101010101010101010101
                 (var-get datum))))";
        owned_env.initialize_contract(c, contract, None).unwrap();
    }

    fn branch(
        owned_env: &mut OwnedEnvironment,
        version: ClarityVersion,
        to_exec: &str,
    ) -> Result<Value, VmExecutionError> {
        let c = QualifiedContractIdentifier::local("contract").unwrap();
        let p1 = execute(p1_str).expect_principal().unwrap();
        let placeholder_context =
            ContractContext::new(QualifiedContractIdentifier::transient(), version);

        {
            let mut env = owned_env.get_exec_environment(None, None, &placeholder_context);
            let value = env.eval_read_only(&c, "(var-get datum)").unwrap();
            assert_eq!(value, Value::Int(1));
        }

        owned_env
            .execute_transaction(p1, None, c, to_exec, &[])
            .map(|(x, _, _)| x)
    }

    let test_burn_state_db = AtBlockWindowTestBurnStateDB {
        epoch_id: epoch,
        tip_burn_height: 100,
        reward_cycle_length: 1,
    };

    with_separate_forks_environment_with_burn_state(
        version,
        epoch,
        &test_burn_state_db,
        initialize,
        |x| {
            if epoch >= StacksEpochId::Epoch34 {
                let resp = branch(x, version, "read-historical").unwrap_err();
                assert_eq!(
                    resp,
                    VmExecutionError::RuntimeCheck(
                        RuntimeCheckErrorKind::AtBlockOutOfLookbackWindow
                    )
                );
            } else {
                assert_eq!(
                    branch(x, version, "read-historical").unwrap(),
                    Value::okay(Value::Int(1)).unwrap()
                );
            }
        },
        |_x| {},
        |_x| {},
    );
}

// execute:
// f -> a -> z
//    \--> b
// with f @ block 1;32
// with a @ block 2;32
// with b @ block 3;32
// with z @ block 4;32

fn with_separate_forks_environment<F0, F1, F2, F3>(
    version: ClarityVersion,
    epoch: StacksEpochId,
    f: F0,
    a: F1,
    b: F2,
    z: F3,
) where
    F0: FnOnce(&mut OwnedEnvironment),
    F1: FnOnce(&mut OwnedEnvironment),
    F2: FnOnce(&mut OwnedEnvironment),
    F3: FnOnce(&mut OwnedEnvironment),
{
    let mut marf_kv = MarfedKV::temporary();

    {
        let mut store = marf_kv.begin(&StacksBlockId::sentinel(), &StacksBlockId([0; 32]));
        store
            .as_clarity_db(&TEST_HEADER_DB, &TEST_BURN_STATE_DB)
            .initialize();
        store.test_commit();
    }

    {
        let mut store = marf_kv.begin(&StacksBlockId([0; 32]), &StacksBlockId([1; 32]));
        let mut owned_env = OwnedEnvironment::new(
            store.as_clarity_db(&TEST_HEADER_DB, &TEST_BURN_STATE_DB),
            epoch,
        );
        f(&mut owned_env);
        store.test_commit();
    }

    // Now, we can do our forking.

    {
        let mut store = marf_kv.begin(&StacksBlockId([1; 32]), &StacksBlockId([2; 32]));
        let mut owned_env = OwnedEnvironment::new(
            store.as_clarity_db(&TEST_HEADER_DB, &TEST_BURN_STATE_DB),
            epoch,
        );
        a(&mut owned_env);
        store.test_commit();
    }

    {
        let mut store = marf_kv.begin(&StacksBlockId([1; 32]), &StacksBlockId([3; 32]));
        let mut owned_env = OwnedEnvironment::new(
            store.as_clarity_db(&TEST_HEADER_DB, &TEST_BURN_STATE_DB),
            epoch,
        );
        b(&mut owned_env);
        store.test_commit();
    }

    {
        let mut store = marf_kv.begin(&StacksBlockId([2; 32]), &StacksBlockId([4; 32]));
        let mut owned_env = OwnedEnvironment::new(
            store.as_clarity_db(&TEST_HEADER_DB, &TEST_BURN_STATE_DB),
            epoch,
        );
        z(&mut owned_env);
        store.test_commit();
    }
}

fn with_separate_forks_environment_with_burn_state<F0, F1, F2, F3>(
    version: ClarityVersion,
    epoch: StacksEpochId,
    burn_state_db: &dyn BurnStateDB,
    f: F0,
    a: F1,
    b: F2,
    z: F3,
) where
    F0: FnOnce(&mut OwnedEnvironment),
    F1: FnOnce(&mut OwnedEnvironment),
    F2: FnOnce(&mut OwnedEnvironment),
    F3: FnOnce(&mut OwnedEnvironment),
{
    let mut marf_kv = MarfedKV::temporary();

    {
        let mut store = marf_kv.begin(&StacksBlockId::sentinel(), &StacksBlockId([0; 32]));
        store
            .as_clarity_db(&TEST_HEADER_DB, burn_state_db)
            .initialize();
        store.test_commit();
    }

    {
        let mut store = marf_kv.begin(&StacksBlockId([0; 32]), &StacksBlockId([1; 32]));
        let mut owned_env =
            OwnedEnvironment::new(store.as_clarity_db(&TEST_HEADER_DB, burn_state_db), epoch);
        f(&mut owned_env);
        store.test_commit();
    }

    // Now, we can do our forking.

    {
        let mut store = marf_kv.begin(&StacksBlockId([1; 32]), &StacksBlockId([2; 32]));
        let mut owned_env =
            OwnedEnvironment::new(store.as_clarity_db(&TEST_HEADER_DB, burn_state_db), epoch);
        a(&mut owned_env);
        store.test_commit();
    }

    {
        let mut store = marf_kv.begin(&StacksBlockId([1; 32]), &StacksBlockId([3; 32]));
        let mut owned_env =
            OwnedEnvironment::new(store.as_clarity_db(&TEST_HEADER_DB, burn_state_db), epoch);
        b(&mut owned_env);
        store.test_commit();
    }

    {
        let mut store = marf_kv.begin(&StacksBlockId([2; 32]), &StacksBlockId([4; 32]));
        let mut owned_env =
            OwnedEnvironment::new(store.as_clarity_db(&TEST_HEADER_DB, burn_state_db), epoch);
        z(&mut owned_env);
        store.test_commit();
    }
}

struct AtBlockWindowTestBurnStateDB {
    epoch_id: StacksEpochId,
    tip_burn_height: u32,
    reward_cycle_length: u32,
}

impl BurnStateDB for AtBlockWindowTestBurnStateDB {
    fn get_tip_burn_block_height(&self) -> Option<u32> {
        Some(self.tip_burn_height)
    }

    fn get_tip_sortition_id(&self) -> Option<SortitionId> {
        let bhh = BurnchainHeaderHash::from_hex(BITCOIN_REGTEST_FIRST_BLOCK_HASH).unwrap();
        Some(SortitionId::new(&bhh, &PoxId::stubbed()))
    }

    fn get_v1_unlock_height(&self) -> u32 {
        u32::MAX
    }

    fn get_v2_unlock_height(&self) -> u32 {
        u32::MAX
    }

    fn get_v3_unlock_height(&self) -> u32 {
        u32::MAX
    }

    fn get_pox_3_activation_height(&self) -> u32 {
        u32::MAX
    }

    fn get_pox_4_activation_height(&self) -> u32 {
        u32::MAX
    }

    fn get_burn_block_height(&self, _sortition_id: &SortitionId) -> Option<u32> {
        Some(self.tip_burn_height)
    }

    fn get_burn_start_height(&self) -> u32 {
        0
    }

    fn get_pox_prepare_length(&self) -> u32 {
        1
    }

    fn get_pox_reward_cycle_length(&self) -> u32 {
        self.reward_cycle_length
    }

    fn get_pox_rejection_fraction(&self) -> u64 {
        1
    }

    fn get_burn_header_hash(
        &self,
        _height: u32,
        _sortition_id: &SortitionId,
    ) -> Option<BurnchainHeaderHash> {
        Some(BurnchainHeaderHash::from_hex(BITCOIN_REGTEST_FIRST_BLOCK_HASH).unwrap())
    }

    fn get_sortition_id_from_consensus_hash(
        &self,
        _consensus_hash: &ConsensusHash,
    ) -> Option<SortitionId> {
        let bhh = BurnchainHeaderHash::from_hex(BITCOIN_REGTEST_FIRST_BLOCK_HASH).unwrap();
        Some(SortitionId::new(&bhh, &PoxId::stubbed()))
    }

    fn get_stacks_epoch(&self, _height: u32) -> Option<StacksEpoch> {
        Some(StacksEpoch {
            epoch_id: self.epoch_id,
            start_height: 0,
            end_height: u64::MAX,
            block_limit: ExecutionCost::max_value(),
            network_epoch: PEER_VERSION_EPOCH_2_0,
        })
    }

    fn get_stacks_epoch_by_epoch_id(&self, _epoch_id: &StacksEpochId) -> Option<StacksEpoch> {
        self.get_stacks_epoch(0)
    }

    fn get_pox_payout_addrs(
        &self,
        _height: u32,
        _sortition_id: &SortitionId,
    ) -> Option<(Vec<TupleData>, u128)> {
        Some((
            vec![TupleData::from_data(vec![
                ("version".into(), Value::buff_from(vec![0u8]).unwrap()),
                ("hashbytes".into(), Value::buff_from(vec![0u8; 20]).unwrap()),
            ])
            .unwrap()],
            123,
        ))
    }
}

fn initialize_contract(owned_env: &mut OwnedEnvironment) {
    let Value::Principal(PrincipalData::Standard(p1_address)) = execute(p1_str) else {
        panic!("Expected a standard principal data");
    };
    let contract = format!(
        "(define-constant burn-address 'SP000000000000000000002Q6VF78)
         (define-fungible-token stackaroos)
         (define-read-only (get-balance (p principal))
           (ft-get-balance stackaroos p))
         (define-public (destroy (x uint))
           (if (< (ft-get-balance stackaroos tx-sender) x)
               (err u30)
               (ft-transfer? stackaroos x tx-sender burn-address)))
         (ft-mint? stackaroos u10 {})",
        p1_str
    );

    eprintln!("Initializing contract...");

    let contract_identifier = QualifiedContractIdentifier::new(p1_address, "tokens".into());
    owned_env
        .initialize_contract(contract_identifier, &contract, None)
        .unwrap();
}

fn branched_execution(
    version: ClarityVersion,
    owned_env: &mut OwnedEnvironment,
    expect_success: bool,
) {
    let Value::Principal(PrincipalData::Standard(p1_address)) = execute(p1_str) else {
        panic!("Expected a standard principal data");
    };
    let contract_identifier = QualifiedContractIdentifier::new(p1_address.clone(), "tokens".into());
    let placeholder_context =
        ContractContext::new(QualifiedContractIdentifier::transient(), version);

    eprintln!("Branched execution...");

    {
        let mut env = owned_env.get_exec_environment(None, None, &placeholder_context);
        let command = format!("(get-balance {})", p1_str);
        let balance = env.eval_read_only(&contract_identifier, &command).unwrap();
        let expected = if expect_success { 10 } else { 0 };
        assert_eq!(balance, Value::UInt(expected));
    }

    let (result, _, _) = owned_env
        .execute_transaction(
            PrincipalData::Standard(p1_address),
            None,
            contract_identifier,
            "destroy",
            &symbols_from_values(vec![Value::UInt(10)]),
        )
        .unwrap();

    if expect_success {
        assert!(is_committed(&result))
    } else {
        assert!(is_err_code(&result, 30))
    }
}
