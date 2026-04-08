// Copyright (C) 2024-2026 Stacks Open Internet Foundation
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

//! Integration tests for `pox_5_make_reward_set` that exercise the real
//! Clarity contract reading/parsing routines (`ClarityPox5PoolInfoProvider`,
//! `StakeEntryIteratorPox5`, `RawPox5Entry::try_parse`) against an actual
//! PoX-5 contract deployed in a lightweight Clarity environment.

use clarity::types::chainstate::SortitionId;
use clarity::vm::contexts::OwnedEnvironment;
use clarity::vm::costs::ExecutionCost;
use clarity::vm::database::clarity_db::StacksEpoch;
use clarity::vm::database::{BurnStateDB, HeadersDB};
use clarity::vm::types::{
    PrincipalData, QualifiedContractIdentifier, StandardPrincipalData, TupleData,
};
use clarity::vm::{ClarityVersion, SymbolicExpression, Value};
use stacks_common::types::chainstate::{
    BlockHeaderHash, BurnchainHeaderHash, ConsensusHash, StacksAddress, StacksBlockId, VRFSeed,
};
use stacks_common::types::StacksEpochId;
use stacks_common::util::hash::Hash160;

use crate::burnchains::bitcoin::{WatchedP2WSHOutput, WitnessScriptHash};
use crate::burnchains::{PoxConstants, Txid};
use crate::chainstate::burn::db::sortdb::WatchedP2WSHOutputMetadata;
use crate::chainstate::burn::ConsensusHash as BurnConsensusHash;
use crate::chainstate::nakamoto::signer_set::{
    ClarityPox5PoolInfoProvider, NakamotoSigners, Pox5PoolInfoProvider, RawPox5Entry,
    RawPox5EntryInfo,
};
use crate::chainstate::stacks::address::PoxAddress;
use crate::chainstate::stacks::boot::POX_5_CODE;
use crate::chainstate::stacks::index::ClarityMarfTrieId;
use crate::clarity_vm::clarity::{
    ClarityBlockConnection, ClarityMarfStore, ClarityMarfStoreTransaction, WritableMarfStore,
};
use crate::clarity_vm::database::marf::MarfedKV;
use crate::util_lib::boot::boot_code_id;

// ---------------------------------------------------------------------------
// Test constants
// ---------------------------------------------------------------------------

const FIRST_BURN_HEIGHT: u64 = 0;
const REWARD_CYCLE_LENGTH: u64 = 10;
const PREPARE_CYCLE_LENGTH: u64 = 3;
/// burn-block-height returned by our test BurnStateDB.
/// Puts us in reward cycle 10.
const TIP_BURN_HEIGHT: u32 = 105;
/// start-burn-ht argument passed to inner-stake.
/// burn-height-to-reward-cycle(100) = 10, so specified-reward-cycle = 11.
const STAKING_START_HEIGHT: u128 = 100;
/// The reward cycle that stakers will be registered for.
const STAKING_REWARD_CYCLE: u64 = 11;
/// Amount each test principal starts with (1 billion uSTX).
const INITIAL_BALANCE: u128 = 1_000_000_000_000;

// ---------------------------------------------------------------------------
// Minimal HeadersDB / BurnStateDB for Epoch35
// ---------------------------------------------------------------------------

struct TestHeadersDB;

impl HeadersDB for TestHeadersDB {
    fn get_stacks_block_header_hash_for_block(
        &self,
        _id_bhh: &StacksBlockId,
        _epoch: &StacksEpochId,
    ) -> Option<BlockHeaderHash> {
        Some(BlockHeaderHash([0u8; 32]))
    }
    fn get_burn_header_hash_for_block(
        &self,
        _id_bhh: &StacksBlockId,
    ) -> Option<BurnchainHeaderHash> {
        Some(BurnchainHeaderHash([0u8; 32]))
    }
    fn get_consensus_hash_for_block(
        &self,
        _id_bhh: &StacksBlockId,
        _epoch: &StacksEpochId,
    ) -> Option<ConsensusHash> {
        Some(ConsensusHash([0u8; 20]))
    }
    fn get_vrf_seed_for_block(
        &self,
        _id_bhh: &StacksBlockId,
        _epoch: &StacksEpochId,
    ) -> Option<VRFSeed> {
        Some(VRFSeed([0u8; 32]))
    }
    fn get_stacks_block_time_for_block(&self, _id_bhh: &StacksBlockId) -> Option<u64> {
        Some(1)
    }
    fn get_burn_block_time_for_block(
        &self,
        _id_bhh: &StacksBlockId,
        _epoch: Option<&StacksEpochId>,
    ) -> Option<u64> {
        Some(1)
    }
    fn get_burn_block_height_for_block(&self, _id_bhh: &StacksBlockId) -> Option<u32> {
        Some(TIP_BURN_HEIGHT)
    }
    fn get_miner_address(
        &self,
        _id_bhh: &StacksBlockId,
        _epoch: &StacksEpochId,
    ) -> Option<StacksAddress> {
        None
    }
    fn get_burnchain_tokens_spent_for_block(
        &self,
        _id_bhh: &StacksBlockId,
        _epoch: &StacksEpochId,
    ) -> Option<u128> {
        Some(0)
    }
    fn get_burnchain_tokens_spent_for_winning_block(
        &self,
        _id_bhh: &StacksBlockId,
        _epoch: &StacksEpochId,
    ) -> Option<u128> {
        Some(0)
    }
    fn get_tokens_earned_for_block(
        &self,
        _id_bhh: &StacksBlockId,
        _epoch: &StacksEpochId,
    ) -> Option<u128> {
        Some(0)
    }
    fn get_stacks_height_for_tenure_height(
        &self,
        _tip: &StacksBlockId,
        _tenure_height: u32,
    ) -> Option<u32> {
        None
    }
}

struct TestBurnStateDB;

impl BurnStateDB for TestBurnStateDB {
    fn get_tip_burn_block_height(&self) -> Option<u32> {
        Some(TIP_BURN_HEIGHT)
    }

    fn get_tip_sortition_id(&self) -> Option<SortitionId> {
        Some(SortitionId([0u8; 32]))
    }

    fn get_burn_block_height(&self, _sortition_id: &SortitionId) -> Option<u32> {
        Some(TIP_BURN_HEIGHT)
    }

    fn get_burn_header_hash(
        &self,
        _height: u32,
        _sortition_id: &SortitionId,
    ) -> Option<BurnchainHeaderHash> {
        Some(BurnchainHeaderHash([0u8; 32]))
    }

    fn get_stacks_epoch(&self, _height: u32) -> Option<StacksEpoch> {
        Some(StacksEpoch {
            epoch_id: StacksEpochId::Epoch35,
            start_height: 0,
            end_height: u64::MAX,
            block_limit: ExecutionCost::max_value(),
            network_epoch: 0,
        })
    }

    fn get_stacks_epoch_by_epoch_id(&self, _epoch_id: &StacksEpochId) -> Option<StacksEpoch> {
        self.get_stacks_epoch(0)
    }

    fn get_burn_start_height(&self) -> u32 {
        FIRST_BURN_HEIGHT as u32
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
    fn get_pox_5_activation_height(&self) -> u32 {
        0
    }

    fn get_pox_prepare_length(&self) -> u32 {
        PREPARE_CYCLE_LENGTH as u32
    }
    fn get_pox_reward_cycle_length(&self) -> u32 {
        REWARD_CYCLE_LENGTH as u32
    }
    fn get_pox_rejection_fraction(&self) -> u64 {
        0
    }

    fn get_sortition_id_from_consensus_hash(
        &self,
        _consensus_hash: &ConsensusHash,
    ) -> Option<SortitionId> {
        Some(SortitionId([0u8; 32]))
    }

    fn get_pox_payout_addrs(
        &self,
        _height: u32,
        _sortition_id: &SortitionId,
    ) -> Option<(Vec<TupleData>, u128)> {
        Some((vec![], 0))
    }
}

// ---------------------------------------------------------------------------
// Block-id helpers
// ---------------------------------------------------------------------------

fn block_id(height: u64) -> StacksBlockId {
    let mut bytes = [0u8; 32];
    bytes[0..8].copy_from_slice(&height.to_le_bytes());
    StacksBlockId(bytes)
}

// ---------------------------------------------------------------------------
// Clarity-value helpers
// ---------------------------------------------------------------------------

fn sym(v: Value) -> SymbolicExpression {
    SymbolicExpression::atom_value(v)
}

fn pox_addr_tuple(hash_bytes: [u8; 20]) -> Value {
    Value::Tuple(
        TupleData::from_data(vec![
            (
                "version".into(),
                Value::buff_from(vec![0x00]).unwrap(),
            ),
            (
                "hashbytes".into(),
                Value::buff_from(hash_bytes.to_vec()).unwrap(),
            ),
        ])
        .unwrap(),
    )
}

fn solo_pool_or_solo_info(hash_bytes: [u8; 20], signer_key: [u8; 33]) -> Value {
    let info = Value::Tuple(
        TupleData::from_data(vec![
            ("pox-addr".into(), pox_addr_tuple(hash_bytes)),
            (
                "signer-key".into(),
                Value::buff_from(signer_key.to_vec()).unwrap(),
            ),
        ])
        .unwrap(),
    );
    // Solo stakers use (err { pox-addr, signer-key })
    Value::error(info).unwrap()
}

fn pool_pool_or_solo_info(pool_principal: PrincipalData) -> Value {
    // Pool stakers use (ok pool-principal)
    Value::okay(Value::Principal(pool_principal)).unwrap()
}

// ---------------------------------------------------------------------------
// Test principals
// ---------------------------------------------------------------------------

fn test_principal(seed: u8) -> StandardPrincipalData {
    let addr = StacksAddress::new(0x1a, Hash160([seed; 20])).unwrap();
    StandardPrincipalData::from(addr)
}

// ---------------------------------------------------------------------------
// Test WatchedP2WSHOutputMetadata
// ---------------------------------------------------------------------------

fn make_test_watched_output(sats: u64) -> WatchedP2WSHOutputMetadata {
    WatchedP2WSHOutputMetadata {
        output: WatchedP2WSHOutput {
            witness_script_hash: WitnessScriptHash([0u8; 32]),
            amount: sats,
            txid: Txid([0u8; 32]),
            vout: 0,
        },
        at_block_ch: BurnConsensusHash([0u8; 20]),
        at_block_ht: 100,
    }
}

fn make_test_pox_constants() -> PoxConstants {
    PoxConstants::new(
        REWARD_CYCLE_LENGTH as u32,
        PREPARE_CYCLE_LENGTH as u32,
        PREPARE_CYCLE_LENGTH as u32,
        10,
        10,
        5000,
        5100,
        1000,
        2000,
        3000,
        2000,
        4000,
    )
}

// ---------------------------------------------------------------------------
// Pox5TestEnv — lightweight clarity env with deployed pox-5 contract
// ---------------------------------------------------------------------------

struct Pox5TestEnv {
    marf: MarfedKV,
    block_height: u64,
}

impl Pox5TestEnv {
    fn pox5_contract_id() -> QualifiedContractIdentifier {
        boot_code_id("pox-5", false)
    }

    /// Create a new test environment:
    /// - Block 0: initialize Clarity DB, fund test principals, set epoch
    /// - Block 1: deploy pox-5.clar and call set-burnchain-parameters
    fn new(principals: &[StandardPrincipalData]) -> Self {
        let mut marf = MarfedKV::temporary();

        // Block 0: initialize + fund + set epoch
        {
            let mut store = marf.begin(
                &StacksBlockId::sentinel(),
                &block_id(0),
            );

            let mut db = store.as_clarity_db(&TestHeadersDB, &TestBurnStateDB);
            db.initialize();

            // Set the epoch so OwnedEnvironment picks up Epoch35
            db.begin();
            db.set_clarity_epoch_version(StacksEpochId::Epoch35)
                .unwrap();
            db.commit().unwrap();

            // Fund test principals
            let mut owned = OwnedEnvironment::new_toplevel(db);
            for p in principals {
                owned.stx_faucet(&PrincipalData::Standard(p.clone()), INITIAL_BALANCE);
            }
            // Also fund the boot address (contract deployer)
            let boot_principal =
                PrincipalData::Standard(StacksAddress::burn_address(false).into());
            owned.stx_faucet(&boot_principal, INITIAL_BALANCE);

            store.test_commit();
        }

        // Block 1: deploy pox-5, set burnchain params
        {
            let mut store = marf.begin(&block_id(0), &block_id(1));

            let db = store.as_clarity_db(&TestHeadersDB, &TestBurnStateDB);
            let mut owned = OwnedEnvironment::new_toplevel(db);

            let pox5_id = Self::pox5_contract_id();

            // Deploy the pox-5 contract
            owned
                .initialize_versioned_contract(
                    pox5_id.clone(),
                    ClarityVersion::Clarity5,
                    &*POX_5_CODE,
                    None,
                )
                .expect("Failed to deploy pox-5 contract");

            // Call set-burnchain-parameters
            let boot_addr =
                PrincipalData::Standard(StacksAddress::burn_address(false).into());
            owned
                .execute_in_env(boot_addr, None, None, |exec_state, invoke_ctx| {
                    exec_state.execute_contract(
                        invoke_ctx,
                        &pox5_id,
                        "set-burnchain-parameters",
                        &[
                            sym(Value::UInt(FIRST_BURN_HEIGHT as u128)),
                            sym(Value::UInt(PREPARE_CYCLE_LENGTH as u128)),
                            sym(Value::UInt(REWARD_CYCLE_LENGTH as u128)),
                            sym(Value::UInt(0)), // begin-pox5-reward-cycle
                        ],
                        false,
                    )
                })
                .expect("Failed to call set-burnchain-parameters");

            store.test_commit();
        }

        Self {
            marf,
            block_height: 1,
        }
    }

    /// Call `inner-stake` as `staker` to register a solo staker.
    /// This populates both the linked list and staking-state map.
    fn add_solo_staker(
        &mut self,
        staker: &StandardPrincipalData,
        amount_ustx: u128,
        num_cycles: u128,
        pox_addr_hash: [u8; 20],
        signer_key: [u8; 33],
    ) {
        let prev = block_id(self.block_height);
        self.block_height += 1;
        let next = block_id(self.block_height);

        let mut store = self.marf.begin(&prev, &next);
        let db = store.as_clarity_db(&TestHeadersDB, &TestBurnStateDB);
        let mut owned = OwnedEnvironment::new_toplevel(db);

        let pox5_id = Self::pox5_contract_id();
        let sender = PrincipalData::Standard(staker.clone());

        let result = owned.execute_in_env(
            sender,
            None,
            None,
            |exec_state, invoke_ctx| {
                exec_state.execute_contract_allow_private(
                    invoke_ctx,
                    &pox5_id,
                    "inner-stake",
                    &[
                        sym(Value::UInt(amount_ustx)),
                        sym(Value::UInt(num_cycles)),
                        sym(Value::buff_from(vec![]).unwrap()), // unlock-bytes
                        sym(Value::UInt(STAKING_START_HEIGHT)),
                        sym(solo_pool_or_solo_info(pox_addr_hash, signer_key)),
                    ],
                    false,
                )
            },
        );

        match &result {
            Ok((val, _, _)) => {
                assert!(
                    matches!(val, Value::Response(data) if data.committed),
                    "inner-stake returned err: {val}"
                );
            }
            Err(e) => panic!("inner-stake execution failed: {e:?}"),
        }

        store.test_commit();
    }

    /// Directly write a pool entry to the `pools` data map.
    fn add_pool(
        &mut self,
        pool_principal: &PrincipalData,
        pox_addr_hash: [u8; 20],
        signer_key: [u8; 33],
    ) {
        let prev = block_id(self.block_height);
        self.block_height += 1;
        let next = block_id(self.block_height);

        let mut store = self.marf.begin(&prev, &next);

        let pox5_id = Self::pox5_contract_id();
        let key = Value::Principal(pool_principal.clone());
        let value = Value::Tuple(
            TupleData::from_data(vec![
                (
                    "signer-key".into(),
                    Value::buff_from(signer_key.to_vec()).unwrap(),
                ),
                ("pox-addr".into(), pox_addr_tuple(pox_addr_hash)),
            ])
            .unwrap(),
        );

        let mut db = store.as_clarity_db(&TestHeadersDB, &TestBurnStateDB);
        db.begin();
        db.set_entry_unknown_descriptor(
            &pox5_id,
            "pools",
            key,
            value,
            &StacksEpochId::Epoch35,
        )
        .expect("Failed to write pools map entry");
        db.commit().unwrap();

        store.test_commit();
    }

    /// Call `inner-stake` as `staker` to register a pool staker.
    /// Requires that the pool's entry in the `pools` map is already set.
    fn add_pool_staker(
        &mut self,
        staker: &StandardPrincipalData,
        amount_ustx: u128,
        num_cycles: u128,
        pool_principal: &PrincipalData,
    ) {
        let prev = block_id(self.block_height);
        self.block_height += 1;
        let next = block_id(self.block_height);

        let mut store = self.marf.begin(&prev, &next);
        let db = store.as_clarity_db(&TestHeadersDB, &TestBurnStateDB);
        let mut owned = OwnedEnvironment::new_toplevel(db);

        let pox5_id = Self::pox5_contract_id();
        let sender = PrincipalData::Standard(staker.clone());

        let result = owned.execute_in_env(
            sender,
            None,
            None,
            |exec_state, invoke_ctx| {
                exec_state.execute_contract_allow_private(
                    invoke_ctx,
                    &pox5_id,
                    "inner-stake",
                    &[
                        sym(Value::UInt(amount_ustx)),
                        sym(Value::UInt(num_cycles)),
                        sym(Value::buff_from(vec![]).unwrap()), // unlock-bytes
                        sym(Value::UInt(STAKING_START_HEIGHT)),
                        sym(pool_pool_or_solo_info(pool_principal.clone())),
                    ],
                    false,
                )
            },
        );

        match &result {
            Ok((val, _, _)) => {
                assert!(
                    matches!(val, Value::Response(data) if data.committed),
                    "inner-stake (pool) returned err: {val}"
                );
            }
            Err(e) => panic!("inner-stake (pool) execution failed: {e:?}"),
        }

        store.test_commit();
    }

    /// Bulk-write staker entries directly to the pox-5 contract data maps.
    ///
    /// This bypasses the Clarity VM for setup (no `inner-stake` calls) and
    /// instead writes the linked-list nodes, `staking-state` entries, and
    /// `pools` entries via `ClarityDatabase::set_entry_unknown_descriptor`.
    /// This is orders of magnitude faster than individual contract calls
    /// and is intended for stress tests with thousands of stakers.
    ///
    /// `solo_stakers`: (principal, amount_ustx, pox_addr_hash, signer_key)
    /// `pool_stakers`: (principal, amount_ustx, pool_principal)
    /// `pools`:        (pool_principal, pox_addr_hash, signer_key)
    fn bulk_setup_stakers(
        &mut self,
        solo_stakers: &[(StandardPrincipalData, u128, [u8; 20], [u8; 33])],
        pool_stakers: &[(StandardPrincipalData, u128, PrincipalData)],
        pools: &[(PrincipalData, [u8; 20], [u8; 33])],
        reward_cycle: u128,
        first_reward_cycle: u128,
        num_cycles: u128,
    ) {
        let prev = block_id(self.block_height);
        self.block_height += 1;
        let next = block_id(self.block_height);

        let mut store = self.marf.begin(&prev, &next);
        let pox5_id = Self::pox5_contract_id();
        let epoch = StacksEpochId::Epoch35;

        // Collect all staker principals in insertion order for the linked list.
        let all_principals: Vec<PrincipalData> = solo_stakers
            .iter()
            .map(|(p, ..)| PrincipalData::Standard(p.clone()))
            .chain(
                pool_stakers
                    .iter()
                    .map(|(p, ..)| PrincipalData::Standard(p.clone())),
            )
            .collect();

        let mut db = store.as_clarity_db(&TestHeadersDB, &TestBurnStateDB);
        db.begin();

        // --- Write pool entries ---
        for (pool_principal, pox_hash, signer_key) in pools {
            let key = Value::Principal(pool_principal.clone());
            let value = Value::Tuple(
                TupleData::from_data(vec![
                    (
                        "signer-key".into(),
                        Value::buff_from(signer_key.to_vec()).unwrap(),
                    ),
                    ("pox-addr".into(), pox_addr_tuple(*pox_hash)),
                ])
                .unwrap(),
            );
            db.set_entry_unknown_descriptor(&pox5_id, "pools", key, value, &epoch)
                .expect("Failed to write pools map entry");
        }

        // --- Write staking-state entries ---
        for (principal, amount, pox_hash, signer_key) in solo_stakers {
            let key = Value::Principal(PrincipalData::Standard(principal.clone()));
            let value = Value::Tuple(
                TupleData::from_data(vec![
                    ("amount-ustx".into(), Value::UInt(*amount)),
                    ("first-reward-cycle".into(), Value::UInt(first_reward_cycle)),
                    ("num-cycles".into(), Value::UInt(num_cycles)),
                    (
                        "pool-or-solo-info".into(),
                        solo_pool_or_solo_info(*pox_hash, *signer_key),
                    ),
                    (
                        "unlock-bytes".into(),
                        Value::buff_from(vec![]).unwrap(),
                    ),
                ])
                .unwrap(),
            );
            db.set_entry_unknown_descriptor(&pox5_id, "staking-state", key, value, &epoch)
                .expect("Failed to write staking-state");
        }

        for (principal, amount, pool_principal) in pool_stakers {
            let key = Value::Principal(PrincipalData::Standard(principal.clone()));
            let value = Value::Tuple(
                TupleData::from_data(vec![
                    ("amount-ustx".into(), Value::UInt(*amount)),
                    ("first-reward-cycle".into(), Value::UInt(first_reward_cycle)),
                    ("num-cycles".into(), Value::UInt(num_cycles)),
                    (
                        "pool-or-solo-info".into(),
                        pool_pool_or_solo_info(pool_principal.clone()),
                    ),
                    (
                        "unlock-bytes".into(),
                        Value::buff_from(vec![]).unwrap(),
                    ),
                ])
                .unwrap(),
            );
            db.set_entry_unknown_descriptor(&pox5_id, "staking-state", key, value, &epoch)
                .expect("Failed to write staking-state");
        }

        // --- Build the linked list for this reward cycle ---
        if !all_principals.is_empty() {
            // first-for-cycle
            db.set_entry_unknown_descriptor(
                &pox5_id,
                "staker-set-ll-first-for-cycle",
                Value::UInt(reward_cycle),
                Value::Principal(all_principals[0].clone()),
                &epoch,
            )
            .expect("Failed to write first-for-cycle");

            // last-for-cycle
            db.set_entry_unknown_descriptor(
                &pox5_id,
                "staker-set-ll-last-for-cycle",
                Value::UInt(reward_cycle),
                Value::Principal(all_principals.last().unwrap().clone()),
                &epoch,
            )
            .expect("Failed to write last-for-cycle");

            // Linked list nodes
            let len = all_principals.len();
            for (i, principal) in all_principals.iter().enumerate() {
                let prev_val = if i == 0 {
                    Value::none()
                } else {
                    Value::some(Value::Principal(all_principals[i - 1].clone())).unwrap()
                };
                let next_val = if i == len - 1 {
                    Value::none()
                } else {
                    Value::some(Value::Principal(all_principals[i + 1].clone())).unwrap()
                };

                let ll_key = Value::Tuple(
                    TupleData::from_data(vec![
                        ("cycle".into(), Value::UInt(reward_cycle)),
                        ("staker".into(), Value::Principal(principal.clone())),
                    ])
                    .unwrap(),
                );
                let ll_value = Value::Tuple(
                    TupleData::from_data(vec![
                        ("prev".into(), prev_val),
                        ("next".into(), next_val),
                    ])
                    .unwrap(),
                );

                db.set_entry_unknown_descriptor(
                    &pox5_id,
                    "staker-set-ll-for-cycle",
                    ll_key,
                    ll_value,
                    &epoch,
                )
                .expect("Failed to write ll-for-cycle");
            }
        }

        db.commit().unwrap();
        store.test_commit();
    }

    /// Open a new block and execute `f` with a `ClarityBlockConnection`.
    /// The closure receives the connection and can call `as_transaction`
    /// to obtain a `ClarityTransactionConnection` for the real parsing routines.
    fn with_block_conn<F, R>(&mut self, f: F) -> R
    where
        F: FnOnce(&mut ClarityBlockConnection) -> R,
    {
        let prev = block_id(self.block_height);
        self.block_height += 1;
        let next = block_id(self.block_height);

        let store: Box<dyn WritableMarfStore + '_> = Box::new(self.marf.begin(&prev, &next));
        let mut block_conn = ClarityBlockConnection::new_test_conn(
            store,
            &TestHeadersDB,
            &TestBurnStateDB,
            StacksEpochId::Epoch35,
        );
        let r = f(&mut block_conn);
        block_conn.commit_block();
        r
    }
}

// ===========================================================================
// Tests
// ===========================================================================

/// Test that `ClarityPox5PoolInfoProvider` reads pool info from the contract.
#[test]
fn test_pool_info_provider_reads_pool_data() {
    let pool_owner = test_principal(0xA0);
    let pool_principal = PrincipalData::Standard(pool_owner.clone());
    let signer_key = [0x42u8; 33];
    let pox_hash = [0xA0u8; 20];

    let mut env = Pox5TestEnv::new(&[]);
    env.add_pool(&pool_principal, pox_hash, signer_key);

    env.with_block_conn(|block_conn| {
        block_conn.as_transaction(|clarity| {
            let pox5_id = Pox5TestEnv::pox5_contract_id();
            let mut provider = ClarityPox5PoolInfoProvider::new(clarity, &pox5_id);

            // Should return the pool info we wrote
            let result = provider
                .get_pool_info(&pool_principal)
                .expect("get_pool_info should succeed");

            let (key, addr) = result.expect("Pool should be found");
            assert_eq!(key, signer_key);

            // PoX version 0x00 maps to a P2PKH address; on testnet
            // the Stacks address version becomes 0x1a.
            match &addr {
                PoxAddress::Standard(stx_addr, hash_mode) => {
                    assert_eq!(*stx_addr.bytes(), Hash160(pox_hash));
                    assert!(hash_mode.is_some());
                }
                other => panic!("Expected PoxAddress::Standard, got {other:?}"),
            }
        });
    });
}

/// Test that `ClarityPox5PoolInfoProvider` returns None for unknown pools.
#[test]
fn test_pool_info_provider_returns_none_for_unknown() {
    let mut env = Pox5TestEnv::new(&[]);

    env.with_block_conn(|block_conn| {
        block_conn.as_transaction(|clarity| {
            let pox5_id = Pox5TestEnv::pox5_contract_id();
            let mut provider = ClarityPox5PoolInfoProvider::new(clarity, &pox5_id);

            let unknown = PrincipalData::Standard(test_principal(0xFF));
            let result = provider
                .get_pool_info(&unknown)
                .expect("get_pool_info should succeed");
            assert!(result.is_none(), "Unknown pool should return None");
        });
    });
}

/// Test that `StakeEntryIteratorPox5` correctly iterates solo staker entries.
#[test]
fn test_stake_entry_iterator_solo() {
    let staker1 = test_principal(0x01);
    let staker2 = test_principal(0x02);
    let key1 = [0x11u8; 33];
    let key2 = [0x22u8; 33];
    let hash1 = [0x01u8; 20];
    let hash2 = [0x02u8; 20];

    let mut env = Pox5TestEnv::new(&[staker1.clone(), staker2.clone()]);

    env.add_solo_staker(&staker1, 200_000_000, 1, hash1, key1);
    env.add_solo_staker(&staker2, 500_000_000, 2, hash2, key2);

    let pox_constants = make_test_pox_constants();

    env.with_block_conn(|block_conn| {
        block_conn.as_transaction(|clarity| {
            let entries: Vec<_> = NakamotoSigners::pox_5_stake_entries(
                clarity,
                STAKING_REWARD_CYCLE,
                "pox-5",
                pox_constants,
                FIRST_BURN_HEIGHT,
            )
            .expect("pox_5_stake_entries should succeed")
            .collect();

            assert_eq!(entries.len(), 2, "Should have 2 staker entries");

            let mut parsed: Vec<RawPox5Entry> = entries
                .into_iter()
                .map(|r| r.expect("Entry should parse successfully"))
                .collect();

            // Sort by amount for deterministic assertions
            parsed.sort_by_key(|e| e.amount_ustx);

            assert_eq!(parsed[0].amount_ustx, 200_000_000);
            assert_eq!(parsed[0].num_cycles, 1);
            assert!(matches!(
                &parsed[0].pox_info,
                RawPox5EntryInfo::Solo { signer_key, .. } if *signer_key == key1
            ));

            assert_eq!(parsed[1].amount_ustx, 500_000_000);
            assert_eq!(parsed[1].num_cycles, 2);
            assert!(matches!(
                &parsed[1].pox_info,
                RawPox5EntryInfo::Solo { signer_key, .. } if *signer_key == key2
            ));
        });
    });
}

/// Test that `StakeEntryIteratorPox5` returns pool entries with the pool principal.
#[test]
fn test_stake_entry_iterator_pool() {
    let pool_owner = test_principal(0xBB);
    let pool_principal = PrincipalData::Standard(pool_owner.clone());
    let pool_signer_key = [0xBBu8; 33];
    let pool_hash = [0xBBu8; 20];

    let staker1 = test_principal(0x01);
    let staker2 = test_principal(0x02);

    let mut env = Pox5TestEnv::new(&[
        pool_owner.clone(),
        staker1.clone(),
        staker2.clone(),
    ]);

    // Set up pool info and pool stakers
    env.add_pool(&pool_principal, pool_hash, pool_signer_key);
    env.add_pool_staker(&staker1, 300_000_000, 1, &pool_principal);
    env.add_pool_staker(&staker2, 700_000_000, 1, &pool_principal);

    let pox_constants = make_test_pox_constants();

    env.with_block_conn(|block_conn| {
        block_conn.as_transaction(|clarity| {
            let entries: Vec<_> = NakamotoSigners::pox_5_stake_entries(
                clarity,
                STAKING_REWARD_CYCLE,
                "pox-5",
                pox_constants,
                FIRST_BURN_HEIGHT,
            )
            .expect("pox_5_stake_entries should succeed")
            .collect();

            assert_eq!(entries.len(), 2, "Should have 2 pool staker entries");

            for entry_result in &entries {
                let entry = entry_result.as_ref().expect("Entry should parse");
                assert!(
                    matches!(&entry.pox_info, RawPox5EntryInfo::Pool(p) if *p == pool_principal),
                    "Entry should reference the pool principal"
                );
            }
        });
    });
}

/// End-to-end: solo stakers -> entry iteration -> pox_5_make_reward_set.
#[test]
fn test_end_to_end_solo_make_reward_set() {
    let staker1 = test_principal(0x01);
    let staker2 = test_principal(0x02);
    let key1 = [0x11u8; 33];
    let key2 = [0x22u8; 33];
    let hash1 = [0x01u8; 20];
    let hash2 = [0x02u8; 20];

    let mut env = Pox5TestEnv::new(&[staker1.clone(), staker2.clone()]);

    env.add_solo_staker(&staker1, 200_000_000, 1, hash1, key1);
    env.add_solo_staker(&staker2, 500_000_000, 1, hash2, key2);

    let pox_constants = make_test_pox_constants();

    env.with_block_conn(|block_conn| {
        block_conn.as_transaction(|clarity| {
            // Phase 1: collect entries from the contract
            let raw_entries: Vec<RawPox5Entry> = NakamotoSigners::pox_5_stake_entries(
                clarity,
                STAKING_REWARD_CYCLE,
                "pox-5",
                pox_constants.clone(),
                FIRST_BURN_HEIGHT,
            )
            .expect("pox_5_stake_entries should succeed")
            .filter_map(|r| r.ok())
            .collect();

            assert!(!raw_entries.is_empty(), "Should have entries");

            // Pair each entry with a test watched output
            let entries_with_outputs: Vec<_> = raw_entries
                .into_iter()
                .map(|e| (e, vec![make_test_watched_output(1_000_000)]))
                .collect();

            // Phase 2: create pool provider and compute reward set
            let pox5_id = Pox5TestEnv::pox5_contract_id();
            let mut provider = ClarityPox5PoolInfoProvider::new(clarity, &pox5_id);

            let (reward_set, _new_ratios) = NakamotoSigners::pox_5_make_reward_set(
                entries_with_outputs,
                &pox_constants,
                &mut provider,
                vec![],
            )
            .expect("pox_5_make_reward_set should succeed");

            // Verify signers
            let signers = reward_set.signers.expect("Should have signers");
            assert_eq!(signers.len(), 2, "Should have 2 solo signers");

            assert!(signers.iter().any(|s| s.signing_key == key1));
            assert!(signers.iter().any(|s| s.signing_key == key2));

            let s1 = signers.iter().find(|s| s.signing_key == key1).unwrap();
            let s2 = signers.iter().find(|s| s.signing_key == key2).unwrap();
            assert_eq!(s1.stacked_amt, 200_000_000);
            assert_eq!(s2.stacked_amt, 500_000_000);
        });
    });
}

/// End-to-end: pool stakers -> entry iteration -> pool info lookup -> pox_5_make_reward_set.
#[test]
fn test_end_to_end_pool_make_reward_set() {
    let pool_owner = test_principal(0xCC);
    let pool_principal = PrincipalData::Standard(pool_owner.clone());
    let pool_signer_key = [0xCCu8; 33];
    let pool_hash = [0xCCu8; 20];

    let staker1 = test_principal(0x01);
    let staker2 = test_principal(0x02);

    let mut env = Pox5TestEnv::new(&[
        pool_owner.clone(),
        staker1.clone(),
        staker2.clone(),
    ]);

    env.add_pool(&pool_principal, pool_hash, pool_signer_key);
    env.add_pool_staker(&staker1, 300_000_000, 1, &pool_principal);
    env.add_pool_staker(&staker2, 700_000_000, 1, &pool_principal);

    let pox_constants = make_test_pox_constants();

    env.with_block_conn(|block_conn| {
        block_conn.as_transaction(|clarity| {
            // Phase 1: collect entries
            let raw_entries: Vec<RawPox5Entry> = NakamotoSigners::pox_5_stake_entries(
                clarity,
                STAKING_REWARD_CYCLE,
                "pox-5",
                pox_constants.clone(),
                FIRST_BURN_HEIGHT,
            )
            .expect("pox_5_stake_entries should succeed")
            .filter_map(|r| r.ok())
            .collect();

            assert_eq!(raw_entries.len(), 2, "Should have 2 pool entries");

            let entries_with_outputs: Vec<_> = raw_entries
                .into_iter()
                .map(|e| (e, vec![make_test_watched_output(1_000_000)]))
                .collect();

            // Phase 2: compute reward set with real pool provider
            let pox5_id = Pox5TestEnv::pox5_contract_id();
            let mut provider = ClarityPox5PoolInfoProvider::new(clarity, &pox5_id);

            let (reward_set, _new_ratios) = NakamotoSigners::pox_5_make_reward_set(
                entries_with_outputs,
                &pox_constants,
                &mut provider,
                vec![],
            )
            .expect("pox_5_make_reward_set should succeed");

            // Pool entries should be aggregated into a single signer
            let signers = reward_set.signers.expect("Should have signers");
            assert_eq!(
                signers.len(),
                1,
                "Pool entries should aggregate into one signer"
            );
            assert_eq!(signers[0].signing_key, pool_signer_key);
            assert_eq!(
                signers[0].stacked_amt,
                1_000_000_000,
                "Aggregated pool amount should be 300M + 700M"
            );
        });
    });
}

/// End-to-end: mixed solo + pool stakers -> pox_5_make_reward_set.
#[test]
fn test_end_to_end_mixed_make_reward_set() {
    let pool_owner = test_principal(0xDD);
    let pool_principal = PrincipalData::Standard(pool_owner.clone());
    let pool_signer_key = [0xDDu8; 33];
    let pool_hash = [0xDDu8; 20];

    let solo_staker = test_principal(0x01);
    let solo_key = [0x11u8; 33];
    let solo_hash = [0x01u8; 20];

    let pool_staker1 = test_principal(0x02);
    let pool_staker2 = test_principal(0x03);

    let mut env = Pox5TestEnv::new(&[
        pool_owner.clone(),
        solo_staker.clone(),
        pool_staker1.clone(),
        pool_staker2.clone(),
    ]);

    // Solo staker
    env.add_solo_staker(&solo_staker, 400_000_000, 1, solo_hash, solo_key);

    // Pool setup
    env.add_pool(&pool_principal, pool_hash, pool_signer_key);
    env.add_pool_staker(&pool_staker1, 200_000_000, 1, &pool_principal);
    env.add_pool_staker(&pool_staker2, 300_000_000, 1, &pool_principal);

    let pox_constants = make_test_pox_constants();

    env.with_block_conn(|block_conn| {
        block_conn.as_transaction(|clarity| {
            let raw_entries: Vec<RawPox5Entry> = NakamotoSigners::pox_5_stake_entries(
                clarity,
                STAKING_REWARD_CYCLE,
                "pox-5",
                pox_constants.clone(),
                FIRST_BURN_HEIGHT,
            )
            .expect("pox_5_stake_entries should succeed")
            .filter_map(|r| r.ok())
            .collect();

            assert_eq!(raw_entries.len(), 3, "Should have 1 solo + 2 pool entries");

            let entries_with_outputs: Vec<_> = raw_entries
                .into_iter()
                .map(|e| (e, vec![make_test_watched_output(1_000_000)]))
                .collect();

            let pox5_id = Pox5TestEnv::pox5_contract_id();
            let mut provider = ClarityPox5PoolInfoProvider::new(clarity, &pox5_id);

            let (reward_set, _new_ratios) = NakamotoSigners::pox_5_make_reward_set(
                entries_with_outputs,
                &pox_constants,
                &mut provider,
                vec![],
            )
            .expect("pox_5_make_reward_set should succeed");

            let signers = reward_set.signers.expect("Should have signers");
            // 1 solo signer + 1 aggregated pool signer = 2
            assert_eq!(signers.len(), 2, "Should have 2 signers (1 solo + 1 pool)");

            assert!(signers
                .iter()
                .any(|s| s.signing_key == solo_key && s.stacked_amt == 400_000_000));
            assert!(signers
                .iter()
                .any(|s| s.signing_key == pool_signer_key && s.stacked_amt == 500_000_000));
        });
    });
}

/// Test that iterating an empty reward cycle produces no entries.
#[test]
fn test_stake_entry_iterator_empty_cycle() {
    let mut env = Pox5TestEnv::new(&[]);

    let pox_constants = make_test_pox_constants();

    env.with_block_conn(|block_conn| {
        block_conn.as_transaction(|clarity| {
            let entries: Vec<_> = NakamotoSigners::pox_5_stake_entries(
                clarity,
                999, // no stakers in cycle 999
                "pox-5",
                pox_constants,
                FIRST_BURN_HEIGHT,
            )
            .expect("pox_5_stake_entries should succeed")
            .collect();

            assert!(entries.is_empty(), "Empty cycle should yield no entries");
        });
    });
}

// ---------------------------------------------------------------------------
// Stress test helpers
// ---------------------------------------------------------------------------

/// Generate a unique principal from a 32-bit index.
fn indexed_principal(index: u32) -> StandardPrincipalData {
    let mut hash = [0u8; 20];
    hash[0..4].copy_from_slice(&index.to_be_bytes());
    StandardPrincipalData::from(StacksAddress::new(0x1a, Hash160(hash)).unwrap())
}

/// Generate a unique signer key from a 32-bit index.
fn indexed_signer_key(index: u32) -> [u8; 33] {
    let mut key = [0u8; 33];
    // First byte is the "compression flag" for a pubkey
    key[0] = 0x02;
    key[1..5].copy_from_slice(&index.to_be_bytes());
    key
}

/// Generate a unique 20-byte hash from a 32-bit index.
fn indexed_hash(index: u32) -> [u8; 20] {
    let mut hash = [0u8; 20];
    hash[0..4].copy_from_slice(&index.to_be_bytes());
    hash
}

// ---------------------------------------------------------------------------
// Stress test
// ---------------------------------------------------------------------------

/// Stress test: ~3000 solo stakers + ~50,000 pool stakers across 100 pools.
///
/// This test exercises `pox_5_make_reward_set` at realistic scale. State is
/// written directly to the contract data maps (bypassing Clarity VM calls)
/// for fast setup, then the real entry iteration and reward set computation
/// are run against actual contract state.
///
/// Uses mainnet-like PoX constants (4000 reward slots) so that the signer
/// threshold is reasonable relative to staking amounts.
#[test]
#[ignore]
fn test_stress_make_reward_set_large_staker_set() {
    use std::time::Instant;

    let num_solo: u32 = 3_000;
    let num_pools: u32 = 100;
    let pool_members_per_pool: u32 = 500;
    let num_pool_stakers = num_pools * pool_members_per_pool; // 50,000
    let total_stakers = num_solo + num_pool_stakers; // 53,000

    // Mainnet-like PoX constants: 4000 reward slots = (2100 - 100) * 2.
    // This ensures the signer threshold is reasonable.
    let stress_pox_constants = PoxConstants::new(
        2100, // reward_cycle_length
        100,  // prepare_length
        100,  // anchor_threshold
        10,   // pox_rejection_fraction
        10,   // pox_participation_threshold_pct
        5000, // sunset_start
        5100, // sunset_end
        1000, // v1_unlock_height
        2000, // v2_unlock_height
        3000, // v3_unlock_height
        2000, // pox_3_activation_height
        4000, // v4_unlock_height
    );

    eprintln!(
        "Stress test: {num_solo} solo + {num_pool_stakers} pool stakers ({num_pools} pools)"
    );

    // --- Build staker data ---
    //
    // Solo: 500K STX each  -> total = 3000 * 500K = 1.5B STX
    // Pool: 1K STX each    -> per pool = 500K STX; total = 50M STX
    // Grand total ~1.55B STX, threshold ~387K STX/slot with 4000 slots.
    // Solo (500K) and pools (500K) both exceed the threshold.
    let t0 = Instant::now();

    let solo_stakers: Vec<(StandardPrincipalData, u128, [u8; 20], [u8; 33])> = (0..num_solo)
        .map(|i| {
            // 500K STX + small variance to avoid identical entries
            let amount = 500_000_000_000u128 + (i as u128 * 1_000_000);
            (indexed_principal(i), amount, indexed_hash(i), indexed_signer_key(i))
        })
        .collect();

    let pools: Vec<(PrincipalData, [u8; 20], [u8; 33])> = (0..num_pools)
        .map(|i| {
            let pool_idx = 1_000_000 + i;
            (
                PrincipalData::Standard(indexed_principal(pool_idx)),
                indexed_hash(pool_idx),
                indexed_signer_key(pool_idx),
            )
        })
        .collect();

    let pool_stakers: Vec<(StandardPrincipalData, u128, PrincipalData)> = (0..num_pool_stakers)
        .map(|i| {
            let staker_idx = num_solo + i;
            let pool_idx = (i % num_pools) as usize;
            // 1K STX + small variance
            let amount = 1_000_000_000u128 + (i as u128 * 1_000);
            (
                indexed_principal(staker_idx),
                amount,
                pools[pool_idx].0.clone(),
            )
        })
        .collect();

    eprintln!("  Data generation: {:?}", t0.elapsed());

    // --- Set up env (deploy contract) ---
    let t1 = Instant::now();
    let mut env = Pox5TestEnv::new(&[]);
    eprintln!("  Contract deploy: {:?}", t1.elapsed());

    // --- Bulk write all staker state ---
    let t2 = Instant::now();
    env.bulk_setup_stakers(
        &solo_stakers,
        &pool_stakers,
        &pools,
        STAKING_REWARD_CYCLE as u128,
        STAKING_REWARD_CYCLE as u128, // first_reward_cycle
        1,                            // num_cycles
    );
    eprintln!(
        "  Bulk MARF writes ({total_stakers} stakers): {:?}",
        t2.elapsed()
    );

    // --- Iterate entries and compute reward set ---
    env.with_block_conn(|block_conn| {
        block_conn.as_transaction(|clarity| {
            // Phase 1: iterate all entries from the contract linked list.
            // Use the small test pox_constants for entry iteration (only
            // affects unlock_height computation, not the linked list traversal).
            let iter_pox_constants = make_test_pox_constants();
            let t3 = Instant::now();
            let raw_entries: Vec<RawPox5Entry> = NakamotoSigners::pox_5_stake_entries(
                clarity,
                STAKING_REWARD_CYCLE,
                "pox-5",
                iter_pox_constants,
                FIRST_BURN_HEIGHT,
            )
            .expect("pox_5_stake_entries should succeed")
            .filter_map(|r| r.ok())
            .collect();
            eprintln!(
                "  Entry iteration ({} entries): {:?}",
                raw_entries.len(),
                t3.elapsed()
            );

            assert_eq!(
                raw_entries.len(),
                total_stakers as usize,
                "Should iterate all stakers"
            );

            // Count solo vs pool
            let solo_count = raw_entries
                .iter()
                .filter(|e| matches!(&e.pox_info, RawPox5EntryInfo::Solo { .. }))
                .count();
            let pool_count = raw_entries
                .iter()
                .filter(|e| matches!(&e.pox_info, RawPox5EntryInfo::Pool(_)))
                .count();
            assert_eq!(solo_count, num_solo as usize);
            assert_eq!(pool_count, num_pool_stakers as usize);

            // Pair with watched outputs (1 BTC = 100M sats per entry)
            let entries_with_outputs: Vec<_> = raw_entries
                .into_iter()
                .map(|e| (e, vec![make_test_watched_output(100_000_000)]))
                .collect();

            // Phase 2: compute reward set with mainnet-like PoX constants
            let t4 = Instant::now();
            let pox5_id = Pox5TestEnv::pox5_contract_id();
            let mut provider = ClarityPox5PoolInfoProvider::new(clarity, &pox5_id);

            let (reward_set, new_ratios) = NakamotoSigners::pox_5_make_reward_set(
                entries_with_outputs,
                &stress_pox_constants,
                &mut provider,
                vec![],
            )
            .expect("pox_5_make_reward_set should succeed");
            eprintln!("  Reward set computation: {:?}", t4.elapsed());

            // --- Verify results ---
            let signers = reward_set.signers.expect("Should have signers");
            eprintln!(
                "  Result: {} signers, {} reward addresses",
                signers.len(),
                reward_set.rewarded_addresses.len()
            );

            // With 4000 reward slots and the amounts above, all solo stakers
            // and all pools should be above the threshold.
            assert!(
                !signers.is_empty(),
                "Reward set must have at least one signer"
            );

            // All pool stakers for a given pool should be aggregated into one signer.
            // Count unique signer keys to verify aggregation.
            let mut signer_keys: std::collections::HashSet<[u8; 33]> =
                std::collections::HashSet::new();
            for s in &signers {
                signer_keys.insert(s.signing_key);
            }
            // No duplicate signer keys
            assert_eq!(signer_keys.len(), signers.len());

            // Verify pool aggregation: each pool's signer key should appear at most once
            for (_pool_principal, _, pool_key) in &pools {
                let pool_signers: Vec<_> =
                    signers.iter().filter(|s| s.signing_key == *pool_key).collect();
                assert!(
                    pool_signers.len() <= 1,
                    "Pool signer key should appear at most once (aggregated)"
                );
            }

            // Verify we got signers from both solo and pool populations
            let solo_signer_count = signers
                .iter()
                .filter(|s| {
                    solo_stakers
                        .iter()
                        .any(|(_, _, _, key)| *key == s.signing_key)
                })
                .count();
            let pool_signer_count = signers
                .iter()
                .filter(|s| pools.iter().any(|(_, _, key)| *key == s.signing_key))
                .count();

            eprintln!(
                "  Signer breakdown: {solo_signer_count} solo, {pool_signer_count} pool"
            );
            assert!(
                solo_signer_count > 0,
                "Should have at least one solo signer"
            );
            assert!(
                pool_signer_count > 0,
                "Should have at least one pool signer"
            );

            // Verify new_ratios is returned
            assert!(
                new_ratios.len() <= 4,
                "Should return at most 4 ratio percentiles"
            );

            // Verify the total stacked amount is sane
            let total_stacked: u128 = signers.iter().map(|s| s.stacked_amt).sum();
            assert!(
                total_stacked > 0,
                "Total stacked amount must be positive"
            );

            eprintln!(
                "  Total stacked: {total_stacked} uSTX across {} signers",
                signers.len()
            );
        });
    });

    eprintln!("  Total test time: {:?}", t0.elapsed());
}
