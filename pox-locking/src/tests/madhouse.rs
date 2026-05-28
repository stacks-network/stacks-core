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

//! Stateful PBT for the pox-5 locking primitives. A random sequence of
//! `Stake`, `StakeUpdate`, `Unstake`, `AdvanceBurnHeight` commands runs
//! against `MemoryBackingStore` plus a settable burn-height oracle, with a
//! shadow model kept in lockstep.
//!
//! Invariants checked after every command:
//! 1. conservation: available + locked == TOTAL_USTX
//! 2. auto-unlock: burn_height >= unlock_height implies locked_ustx == 0 on the SUT
//! 3. monotonic locking: StakeUpdate never reduces locked_ustx
//!
//! Generators emit structurally valid args (amount > 0, unlock > 0); legality
//! against the current state is decided by `Command::check`, never by
//! `prop_assume!` inside `apply`.

use std::sync::atomic::{AtomicU32, Ordering};
use std::sync::{Arc, Mutex};

use clarity::types::StacksEpochId;
use clarity::vm::costs::ExecutionCost;
use clarity::vm::database::clarity_db::StacksEpoch;
use clarity::vm::database::{
    BurnStateDB, ClarityDatabase, MemoryBackingStore, NULL_HEADER_DB,
};
use clarity::vm::types::{PrincipalData, StandardPrincipalData, TupleData};
use madhouse::{
    Command, CommandWrapper, State, TestContext, execute_commands, prop_allof,
};
use pinny::tag;
use proptest::prelude::{Just, Strategy};
use stacks_common::types::chainstate::{
    BurnchainHeaderHash, ConsensusHash, SortitionId,
};

use crate::pox_5::{pox_lock_update_v5, pox_lock_v5, pox_unstake_v5};
use crate::LockingError;

/// Starting STX balance. Large enough to absorb any sequence the generators emit.
const TOTAL_USTX: u128 = 100_000_000_000;

/// Cap on random unlock_height deltas.
const UNLOCK_WINDOW: u64 = 1_000_000;

/// Reward cycle length used by `Unstake` for scheduling.
const REWARD_CYCLE_LENGTH: u64 = 1_000;

/// `BurnStateDB` with a settable tip; other methods mirror `NullBurnStateDB`.
#[derive(Debug)]
struct ConfigurableBurnStateDB {
    burn_height: AtomicU32,
    epoch: StacksEpochId,
}

impl ConfigurableBurnStateDB {
    fn new(epoch: StacksEpochId) -> Self {
        Self {
            burn_height: AtomicU32::new(0),
            epoch,
        }
    }

    fn set_burn_height(&self, h: u32) {
        self.burn_height.store(h, Ordering::SeqCst);
    }
}

impl BurnStateDB for ConfigurableBurnStateDB {
    fn get_tip_burn_block_height(&self) -> Option<u32> {
        Some(self.burn_height.load(Ordering::SeqCst))
    }

    fn get_tip_sortition_id(&self) -> Option<SortitionId> {
        None
    }

    fn get_burn_block_height(&self, _sortition_id: &SortitionId) -> Option<u32> {
        None
    }

    fn get_burn_start_height(&self) -> u32 {
        0
    }

    fn get_sortition_id_from_consensus_hash(
        &self,
        _consensus_hash: &ConsensusHash,
    ) -> Option<SortitionId> {
        None
    }

    fn get_burn_header_hash(
        &self,
        _height: u32,
        _sortition_id: &SortitionId,
    ) -> Option<BurnchainHeaderHash> {
        None
    }

    fn get_stacks_epoch(&self, _height: u32) -> Option<StacksEpoch> {
        Some(StacksEpoch {
            epoch_id: self.epoch,
            start_height: 0,
            end_height: u64::MAX,
            block_limit: ExecutionCost::max_value(),
            network_epoch: 0,
        })
    }

    fn get_stacks_epoch_by_epoch_id(
        &self,
        _epoch_id: &StacksEpochId,
    ) -> Option<StacksEpoch> {
        self.get_stacks_epoch(0)
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
        u32::MAX
    }

    fn get_pox_prepare_length(&self) -> u32 {
        panic!("ConfigurableBurnStateDB should not return PoX info");
    }
    fn get_pox_reward_cycle_length(&self) -> u32 {
        panic!("ConfigurableBurnStateDB should not return PoX info");
    }
    fn get_pox_rejection_fraction(&self) -> u64 {
        panic!("ConfigurableBurnStateDB should not return PoX info");
    }
    fn get_pox_payout_addrs(
        &self,
        _height: u32,
        _sortition_id: &SortitionId,
    ) -> Option<(Vec<TupleData>, u128)> {
        None
    }
}

/// Account model. `Unstake` is not a separate state: it only reschedules
/// `unlock_height`. The `unstake_scheduled` flag exists so `StakeUpdate` can be
/// rejected once an unstake is pending.
#[derive(Debug, Clone, PartialEq)]
enum AccountState {
    Unlocked,
    Locked {
        locked_ustx: u128,
        unlock_height: u64,
        unstake_scheduled: bool,
    },
}

impl AccountState {
    fn locked_amount(&self) -> u128 {
        match self {
            AccountState::Unlocked => 0,
            AccountState::Locked { locked_ustx, .. } => *locked_ustx,
        }
    }
}

#[derive(Debug, Clone)]
struct Pox5StakerState {
    current_burn_height: u64,
    account: AccountState,
}

impl Default for Pox5StakerState {
    fn default() -> Self {
        Self {
            current_burn_height: 0,
            account: AccountState::Unlocked,
        }
    }
}

impl State for Pox5StakerState {}

impl Pox5StakerState {
    fn available_ustx(&self, total: u128) -> u128 {
        total - self.account.locked_amount()
    }

    /// If current burn height has reached unlock_height, the lock has expired.
    fn maybe_auto_unlock(&mut self) {
        if let AccountState::Locked { unlock_height, .. } = self.account {
            if self.current_burn_height >= unlock_height {
                self.account = AccountState::Unlocked;
            }
        }
    }
}

struct Pox5SystemUnderTest {
    store: MemoryBackingStore,
    burn_state_db: ConfigurableBurnStateDB,
    staker: PrincipalData,
}

impl std::fmt::Debug for Pox5SystemUnderTest {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Pox5SystemUnderTest")
            .field("staker", &self.staker)
            .finish_non_exhaustive()
    }
}

impl Pox5SystemUnderTest {
    fn new(staker: PrincipalData) -> Self {
        Self {
            store: MemoryBackingStore::new(),
            burn_state_db: ConfigurableBurnStateDB::new(StacksEpochId::Epoch40),
            staker,
        }
    }

    /// Begin/commit a transaction around `f` against a fresh `ClarityDatabase`.
    fn run<R, F>(&mut self, f: F) -> R
    where
        F: FnOnce(&mut ClarityDatabase) -> R,
    {
        let mut db = ClarityDatabase::new(
            &mut self.store,
            &NULL_HEADER_DB,
            &self.burn_state_db,
        );
        db.begin();
        db.set_clarity_epoch_version(StacksEpochId::Epoch40).unwrap();
        let r = f(&mut db);
        db.commit().unwrap();
        r
    }

    fn fund(&mut self, total: u128) {
        let staker = self.staker.clone();
        self.run(|db| {
            let mut snapshot = db.get_stx_balance_snapshot(&staker).unwrap();
            snapshot.credit(total).unwrap();
            snapshot.save().unwrap();
        });
    }

    fn set_burn_height(&self, h: u64) {
        let h32 = u32::try_from(h).expect("burn height fits in u32 in this test");
        self.burn_state_db.set_burn_height(h32);
    }

    /// (locked, unlocked) after canonicalization, matching what a Clarity
    /// contract observes via `stx-get-balance`.
    fn balance_canonical(&mut self) -> (u128, u128) {
        let staker = self.staker.clone();
        self.run(|db| {
            let mut snapshot = db.get_stx_balance_snapshot(&staker).unwrap();
            let bal = snapshot.canonical_balance_repr().unwrap();
            (bal.amount_locked(), bal.amount_unlocked())
        })
    }

    fn has_locked_tokens(&mut self) -> bool {
        let staker = self.staker.clone();
        self.run(|db| {
            let mut snapshot = db.get_stx_balance_snapshot(&staker).unwrap();
            snapshot.has_locked_tokens().unwrap()
        })
    }
}

// Per-bucket counters bumped by `check_invariants`. `pox5_coverage_smoke`
// asserts each is > 0 so generator drift (e.g. `Unstake.check` getting stricter)
// surfaces as a coverage failure rather than passing silently. Counters live in
// the per-test context to avoid cross-talk between parallel tests.

#[derive(Debug, Default, Clone, Copy)]
struct CoverageCounters {
    unlocked: u64,
    locked_nosched: u64,
    locked_sched: u64,
}

#[derive(Clone)]
pub struct Pox5Context {
    sut: Arc<Mutex<Pox5SystemUnderTest>>,
    total_ustx: u128,
    coverage: Arc<Mutex<CoverageCounters>>,
}

impl std::fmt::Debug for Pox5Context {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Pox5Context")
            .field("total_ustx", &self.total_ustx)
            .finish_non_exhaustive()
    }
}

impl TestContext for Pox5Context {}

impl Pox5Context {
    pub fn new() -> Self {
        let staker: PrincipalData = StandardPrincipalData::transient().into();
        let mut sut = Pox5SystemUnderTest::new(staker);
        sut.fund(TOTAL_USTX);
        Self {
            sut: Arc::new(Mutex::new(sut)),
            total_ustx: TOTAL_USTX,
            coverage: Arc::new(Mutex::new(CoverageCounters::default())),
        }
    }

    /// Reset the SUT to a fresh, funded state between proptest iterations.
    /// `proptest!` reruns the body for shrinking even at `cases = 1`, and the
    /// SUT is shared via `Arc<Mutex<_>>`, so without this state would leak.
    fn reset_sut(&self) {
        let staker: PrincipalData = StandardPrincipalData::transient().into();
        let mut fresh = Pox5SystemUnderTest::new(staker);
        fresh.fund(self.total_ustx);
        *self.sut.lock().unwrap() = fresh;
    }

    fn coverage_snapshot(&self) -> CoverageCounters {
        *self.coverage.lock().unwrap()
    }
}

fn classify_state(model: &Pox5StakerState, ctx: &Pox5Context) {
    let mut c = ctx.coverage.lock().unwrap();
    match &model.account {
        AccountState::Unlocked => c.unlocked += 1,
        AccountState::Locked { unstake_scheduled: false, .. } => c.locked_nosched += 1,
        AccountState::Locked { unstake_scheduled: true, .. } => c.locked_sched += 1,
    }
}

/// Invariants checked after every command. A failed assert panics out as a
/// madhouse test failure with shrinking.
fn check_invariants(model: &Pox5StakerState, ctx: &Pox5Context) {
    classify_state(model, ctx);
    let mut sut = ctx.sut.lock().unwrap();
    let (sut_locked, sut_unlocked) = sut.balance_canonical();

    // Invariant 1: conservation on the SUT.
    assert_eq!(
        sut_locked + sut_unlocked,
        ctx.total_ustx,
        "conservation broken on SUT: locked={} + unlocked={} != total={}",
        sut_locked,
        sut_unlocked,
        ctx.total_ustx,
    );

    // Invariant: model and SUT agree on canonical locked amount.
    assert_eq!(
        model.account.locked_amount(),
        sut_locked,
        "model/SUT mismatch on canonical locked amount"
    );

    // Invariant 2: once burn height reaches unlock_height, `has_locked_tokens()`
    // must be false on the SUT (raw `amount_locked` reflects pre-canonicalization).
    if let AccountState::Locked { unlock_height, .. } = model.account {
        if model.current_burn_height >= unlock_height {
            assert!(
                !sut.has_locked_tokens(),
                "auto-unlock invariant: current={} >= unlock={}, but SUT still reports locked tokens",
                model.current_burn_height, unlock_height,
            );
        }
    }
}

/// Stake `amount` ustx with unlock at `unlock_height`. Legal only when unlocked.
struct Stake {
    ctx: Arc<Pox5Context>,
    amount: u128,
    unlock_height: u64,
}

impl Command<Pox5StakerState, Pox5Context> for Stake {
    fn check(&self, state: &Pox5StakerState) -> bool {
        matches!(state.account, AccountState::Unlocked)
            && self.amount <= state.available_ustx(self.ctx.total_ustx)
            && self.unlock_height > state.current_burn_height
    }

    fn apply(&self, state: &mut Pox5StakerState) {
        let staker = {
            let sut = self.ctx.sut.lock().unwrap();
            sut.staker.clone()
        };
        let result = {
            let mut sut = self.ctx.sut.lock().unwrap();
            sut.run(|db| pox_lock_v5(db, &staker, self.amount, self.unlock_height))
        };
        match result {
            Ok(()) => {
                state.account = AccountState::Locked {
                    locked_ustx: self.amount,
                    unlock_height: self.unlock_height,
                    unstake_scheduled: false,
                };
            }
            Err(e) => panic!(
                "Stake expected to succeed (model says legal) but SUT returned {e:?}"
            ),
        }
        check_invariants(state, &self.ctx);
    }

    fn label(&self) -> String {
        format!("STAKE({}, unlock={})", self.amount, self.unlock_height)
    }

    fn build(ctx: Arc<Pox5Context>) -> impl Strategy<Value = CommandWrapper<Pox5StakerState, Pox5Context>> {
        let total = ctx.total_ustx;
        // Up to `total` (not `total/2`) so the full-balance edge is sampled.
        let amount_strategy = 1u128..=total;
        let unlock_strategy = 1u64..=UNLOCK_WINDOW;
        (amount_strategy, unlock_strategy).prop_map(move |(amount, unlock_height)| {
            CommandWrapper::new(Stake {
                ctx: ctx.clone(),
                amount,
                unlock_height,
            })
        })
    }
}

/// Extend or increase the lock. Legal only when locked, not unstaking, and
/// `new_total >= locked_ustx` (invariant 3).
struct StakeUpdate {
    ctx: Arc<Pox5Context>,
    new_total: u128,
    new_unlock_height: u64,
}

impl Command<Pox5StakerState, Pox5Context> for StakeUpdate {
    fn check(&self, state: &Pox5StakerState) -> bool {
        match state.account {
            AccountState::Locked {
                locked_ustx,
                unstake_scheduled,
                ..
            } => {
                !unstake_scheduled
                    && self.new_total >= locked_ustx
                    && self.new_unlock_height > state.current_burn_height
            }
            _ => false,
        }
    }

    fn apply(&self, state: &mut Pox5StakerState) {
        let staker = {
            let sut = self.ctx.sut.lock().unwrap();
            sut.staker.clone()
        };
        let result = {
            let mut sut = self.ctx.sut.lock().unwrap();
            sut.run(|db| {
                pox_lock_update_v5(db, &staker, self.new_unlock_height, self.new_total)
            })
        };
        match result {
            Ok(_balance) => {
                if let AccountState::Locked {
                    locked_ustx,
                    unlock_height,
                    ..
                } = &mut state.account
                {
                    // Monotonic locking pre/post check.
                    assert!(
                        self.new_total >= *locked_ustx,
                        "monotonic locking violated by model: prev={}, new={}",
                        *locked_ustx,
                        self.new_total,
                    );
                    *locked_ustx = self.new_total;
                    *unlock_height = self.new_unlock_height;
                }
            }
            Err(e) => panic!(
                "StakeUpdate expected to succeed but SUT returned {e:?}"
            ),
        }
        check_invariants(state, &self.ctx);
    }

    fn label(&self) -> String {
        format!(
            "STAKE_UPDATE(new_total={}, new_unlock={})",
            self.new_total, self.new_unlock_height
        )
    }

    fn build(ctx: Arc<Pox5Context>) -> impl Strategy<Value = CommandWrapper<Pox5StakerState, Pox5Context>> {
        let total = ctx.total_ustx;
        let new_total_strategy = 1u128..=total;
        let new_unlock_strategy = 1u64..=UNLOCK_WINDOW;
        (new_total_strategy, new_unlock_strategy).prop_map(move |(new_total, new_unlock)| {
            CommandWrapper::new(StakeUpdate {
                ctx: ctx.clone(),
                new_total,
                new_unlock_height: new_unlock,
            })
        })
    }
}

/// Reschedule the lock's unlock_height to the start of the next reward cycle.
/// Legal only when locked and not already unstaking.
struct Unstake {
    ctx: Arc<Pox5Context>,
}

impl Command<Pox5StakerState, Pox5Context> for Unstake {
    fn check(&self, state: &Pox5StakerState) -> bool {
        matches!(
            state.account,
            AccountState::Locked {
                unstake_scheduled: false,
                ..
            }
        )
    }

    fn apply(&self, state: &mut Pox5StakerState) {
        // Schedule unlock at start of next cycle; > current so `pox_unstake_v5`'s
        // unlock_height > 0 + has_locked_tokens gates pass.
        let new_unlock = next_reward_cycle_start(state.current_burn_height);
        let staker = {
            let sut = self.ctx.sut.lock().unwrap();
            sut.staker.clone()
        };
        let result = {
            let mut sut = self.ctx.sut.lock().unwrap();
            sut.run(|db| pox_unstake_v5(db, &staker, new_unlock))
        };
        match result {
            Ok(()) => {
                if let AccountState::Locked {
                    unlock_height,
                    unstake_scheduled,
                    ..
                } = &mut state.account
                {
                    *unlock_height = new_unlock;
                    *unstake_scheduled = true;
                }
            }
            Err(e) => panic!("Unstake expected to succeed but SUT returned {e:?}"),
        }
        check_invariants(state, &self.ctx);
    }

    fn label(&self) -> String {
        "UNSTAKE".to_string()
    }

    fn build(ctx: Arc<Pox5Context>) -> impl Strategy<Value = CommandWrapper<Pox5StakerState, Pox5Context>> {
        Just(CommandWrapper::new(Unstake { ctx: ctx.clone() }))
    }
}

/// Bump the SUT-visible burn height by `delta` and run auto-unlock on the model.
struct AdvanceBurnHeight {
    ctx: Arc<Pox5Context>,
    delta: u64,
}

impl Command<Pox5StakerState, Pox5Context> for AdvanceBurnHeight {
    fn check(&self, _state: &Pox5StakerState) -> bool {
        true
    }

    fn apply(&self, state: &mut Pox5StakerState) {
        state.current_burn_height = state.current_burn_height.saturating_add(self.delta);
        {
            let sut = self.ctx.sut.lock().unwrap();
            sut.set_burn_height(state.current_burn_height);
        }
        state.maybe_auto_unlock();
        check_invariants(state, &self.ctx);
    }

    fn label(&self) -> String {
        format!("ADVANCE_BURN({})", self.delta)
    }

    fn build(ctx: Arc<Pox5Context>) -> impl Strategy<Value = CommandWrapper<Pox5StakerState, Pox5Context>> {
        (1u64..=10_000u64).prop_map(move |delta| {
            CommandWrapper::new(AdvanceBurnHeight {
                ctx: ctx.clone(),
                delta,
            })
        })
    }
}

/// Round `h` up to the next multiple of `REWARD_CYCLE_LENGTH` (strictly > h).
fn next_reward_cycle_start(h: u64) -> u64 {
    let n = h / REWARD_CYCLE_LENGTH;
    (n + 1) * REWARD_CYCLE_LENGTH
}

// Negative-path commands. Each is enabled by `check` only in states where the
// operation is illegal, and `apply` asserts the expected error variant. Without
// these, a regression that turned (say) `PoxAlreadyLocked` into `Ok` would slip
// past because the legal `Stake` command's `check` would just skip.

/// Stake while already locked: must return `PoxAlreadyLocked`.
struct IllegalStakeWhileLocked {
    ctx: Arc<Pox5Context>,
    amount: u128,
    unlock_height: u64,
}

impl Command<Pox5StakerState, Pox5Context> for IllegalStakeWhileLocked {
    fn check(&self, state: &Pox5StakerState) -> bool {
        // `pox_lock_v5` gates: unlock_burn_height != 0, amount != 0, then
        // has_locked_tokens. amount > 0 and unlock > 0 keep the failure on
        // PoxAlreadyLocked rather than an earlier gate.
        matches!(state.account, AccountState::Locked { .. })
            && self.amount > 0
            && self.unlock_height > state.current_burn_height
    }

    fn apply(&self, state: &mut Pox5StakerState) {
        let staker = self.ctx.sut.lock().unwrap().staker.clone();
        let result = {
            let mut sut = self.ctx.sut.lock().unwrap();
            sut.run(|db| pox_lock_v5(db, &staker, self.amount, self.unlock_height))
        };
        match result {
            Err(LockingError::PoxAlreadyLocked) => {}
            other => panic!(
                "IllegalStakeWhileLocked expected PoxAlreadyLocked, got {other:?}"
            ),
        }
        // Failed call must not mutate the SUT; model is unchanged.
        check_invariants(state, &self.ctx);
    }

    fn label(&self) -> String {
        format!(
            "ILLEGAL_STAKE_LOCKED({}, unlock={})",
            self.amount, self.unlock_height
        )
    }

    fn build(
        ctx: Arc<Pox5Context>,
    ) -> impl Strategy<Value = CommandWrapper<Pox5StakerState, Pox5Context>> {
        let total = ctx.total_ustx;
        (1u128..=total, 1u64..=UNLOCK_WINDOW).prop_map(move |(amount, unlock_height)| {
            CommandWrapper::new(IllegalStakeWhileLocked {
                ctx: ctx.clone(),
                amount,
                unlock_height,
            })
        })
    }
}

/// Stake-update while unlocked: must return `PoxExtendNotLocked`. Args clear
/// the zero-amount/zero-height gates so that's the rule actually hit.
struct IllegalStakeUpdateOnUnlocked {
    ctx: Arc<Pox5Context>,
    new_total: u128,
    new_unlock_height: u64,
}

impl Command<Pox5StakerState, Pox5Context> for IllegalStakeUpdateOnUnlocked {
    fn check(&self, state: &Pox5StakerState) -> bool {
        matches!(state.account, AccountState::Unlocked)
            && self.new_total > 0
            && self.new_unlock_height > state.current_burn_height
    }

    fn apply(&self, state: &mut Pox5StakerState) {
        let staker = self.ctx.sut.lock().unwrap().staker.clone();
        let result = {
            let mut sut = self.ctx.sut.lock().unwrap();
            sut.run(|db| {
                pox_lock_update_v5(db, &staker, self.new_unlock_height, self.new_total)
            })
        };
        match result {
            Err(LockingError::PoxExtendNotLocked) => {}
            other => panic!(
                "IllegalStakeUpdateOnUnlocked expected PoxExtendNotLocked, got {other:?}"
            ),
        }
        check_invariants(state, &self.ctx);
    }

    fn label(&self) -> String {
        format!(
            "ILLEGAL_UPDATE_UNLOCKED(new_total={}, new_unlock={})",
            self.new_total, self.new_unlock_height
        )
    }

    fn build(
        ctx: Arc<Pox5Context>,
    ) -> impl Strategy<Value = CommandWrapper<Pox5StakerState, Pox5Context>> {
        let total = ctx.total_ustx;
        (1u128..=total, 1u64..=UNLOCK_WINDOW).prop_map(move |(new_total, new_unlock)| {
            CommandWrapper::new(IllegalStakeUpdateOnUnlocked {
                ctx: ctx.clone(),
                new_total,
                new_unlock_height: new_unlock,
            })
        })
    }
}

/// Unstake while unlocked: must return `PoxUnstakeNotLocked`. `new_unlock_height
/// > 0` clears the earlier gate.
struct IllegalUnstakeOnUnlocked {
    ctx: Arc<Pox5Context>,
    new_unlock_height: u64,
}

impl Command<Pox5StakerState, Pox5Context> for IllegalUnstakeOnUnlocked {
    fn check(&self, state: &Pox5StakerState) -> bool {
        matches!(state.account, AccountState::Unlocked)
    }

    fn apply(&self, state: &mut Pox5StakerState) {
        let staker = self.ctx.sut.lock().unwrap().staker.clone();
        let result = {
            let mut sut = self.ctx.sut.lock().unwrap();
            sut.run(|db| pox_unstake_v5(db, &staker, self.new_unlock_height))
        };
        match result {
            Err(LockingError::PoxUnstakeNotLocked) => {}
            other => panic!(
                "IllegalUnstakeOnUnlocked expected PoxUnstakeNotLocked, got {other:?}"
            ),
        }
        check_invariants(state, &self.ctx);
    }

    fn label(&self) -> String {
        format!("ILLEGAL_UNSTAKE_UNLOCKED(unlock={})", self.new_unlock_height)
    }

    fn build(
        ctx: Arc<Pox5Context>,
    ) -> impl Strategy<Value = CommandWrapper<Pox5StakerState, Pox5Context>> {
        (1u64..=UNLOCK_WINDOW).prop_map(move |new_unlock| {
            CommandWrapper::new(IllegalUnstakeOnUnlocked {
                ctx: ctx.clone(),
                new_unlock_height: new_unlock,
            })
        })
    }
}

/// Update-lock with `new_total < locked_ustx`: must return `PoxInvalidIncrease`.
/// `stake-update` is not a hidden unstake.
struct IllegalDecreaseInUpdate {
    ctx: Arc<Pox5Context>,
    decrease: u128,
    new_unlock_height: u64,
}

impl Command<Pox5StakerState, Pox5Context> for IllegalDecreaseInUpdate {
    fn check(&self, state: &Pox5StakerState) -> bool {
        match &state.account {
            AccountState::Locked {
                locked_ustx,
                unstake_scheduled,
                ..
            } => {
                // Need `locked > 1` to have room to decrease, no pending
                // unstake (which has its own rules), and `new_unlock_height >
                // current` to clear the `unlock_burn_height <= burn_block_height` gate.
                !unstake_scheduled
                    && *locked_ustx > 1
                    && self.decrease > 0
                    && self.decrease < *locked_ustx
                    && self.new_unlock_height > state.current_burn_height
            }
            _ => false,
        }
    }

    fn apply(&self, state: &mut Pox5StakerState) {
        let locked = state.account.locked_amount();
        let new_total = locked - self.decrease;
        let staker = self.ctx.sut.lock().unwrap().staker.clone();
        let result = {
            let mut sut = self.ctx.sut.lock().unwrap();
            sut.run(|db| {
                pox_lock_update_v5(db, &staker, self.new_unlock_height, new_total)
            })
        };
        match result {
            Err(LockingError::PoxInvalidIncrease) => {}
            other => panic!(
                "IllegalDecreaseInUpdate expected PoxInvalidIncrease (locked={locked}, new_total={new_total}), got {other:?}"
            ),
        }
        check_invariants(state, &self.ctx);
    }

    fn label(&self) -> String {
        format!(
            "ILLEGAL_DECREASE(by={}, new_unlock={})",
            self.decrease, self.new_unlock_height
        )
    }

    fn build(
        ctx: Arc<Pox5Context>,
    ) -> impl Strategy<Value = CommandWrapper<Pox5StakerState, Pox5Context>> {
        // `decrease` is bounded against the runtime locked amount in `check`.
        (1u128..=ctx.total_ustx, 1u64..=UNLOCK_WINDOW).prop_map(
            move |(decrease, new_unlock)| {
                CommandWrapper::new(IllegalDecreaseInUpdate {
                    ctx: ctx.clone(),
                    decrease,
                    new_unlock_height: new_unlock,
                })
            },
        )
    }
}

/// Drive the staker through a random sequence of commands, checking invariants
/// after each.
///
/// The madhouse `scenario!` macro is intentionally NOT used: it builds the
/// context once and shares it across iterations, but `proptest!` reruns the
/// body for shrinking (even at `cases = 1`), and burn-height + balance state
/// would leak across iterations. Expanding the macro by hand lets us reset the
/// SUT per iteration.
///
/// `MADHOUSE=1` switches from declaration order to random permutation.
#[test]
#[cfg_attr(test, tag(t_prop))]
fn pox5_staker_lifecycle_madhouse() {
    let ctx = Arc::new(Pox5Context::new());
    let config = proptest::test_runner::Config {
        cases: 1,
        max_shrink_iters: 0,
        ..proptest::test_runner::Config::default()
    };

    let use_madhouse = std::env::var("MADHOUSE") == Ok("1".into());

    if use_madhouse {
        proptest::proptest!(config.clone(), |(commands in proptest::collection::vec(
            proptest::prop_oneof![
                Stake::build(ctx.clone()),
                StakeUpdate::build(ctx.clone()),
                Unstake::build(ctx.clone()),
                AdvanceBurnHeight::build(ctx.clone()),
                IllegalStakeWhileLocked::build(ctx.clone()),
                IllegalStakeUpdateOnUnlocked::build(ctx.clone()),
                IllegalUnstakeOnUnlocked::build(ctx.clone()),
                IllegalDecreaseInUpdate::build(ctx.clone()),
            ],
            1..16,
        ))| {
            ctx.reset_sut();
            let mut state = Pox5StakerState::default();
            execute_commands(&commands, &mut state);
        });
    } else {
        proptest::proptest!(config, |(commands in prop_allof![
            Stake::build(ctx.clone()),
            StakeUpdate::build(ctx.clone()),
            Unstake::build(ctx.clone()),
            AdvanceBurnHeight::build(ctx.clone()),
            IllegalStakeWhileLocked::build(ctx.clone()),
            IllegalStakeUpdateOnUnlocked::build(ctx.clone()),
            IllegalUnstakeOnUnlocked::build(ctx.clone()),
            IllegalDecreaseInUpdate::build(ctx.clone()),
        ])| {
            ctx.reset_sut();
            let mut state = Pox5StakerState::default();
            execute_commands(&commands, &mut state);
        });
    }
}

/// Coverage smoke: random walks must reach every `AccountState` variant. Uses
/// the same command alphabet (legal + IllegalX) as `pox5_staker_lifecycle_madhouse`
/// so coverage tracks the test that actually runs in CI.
///
/// Fails if generator drift (e.g. `Unstake.check` getting stricter) silently
/// stops sampling a state, separating "generator never reaches X" from
/// "invariant on X is broken".
#[test]
#[cfg_attr(test, tag(t_prop))]
fn pox5_coverage_smoke() {
    let ctx = Arc::new(Pox5Context::new());
    let config = proptest::test_runner::Config {
        cases: 50,
        max_shrink_iters: 0,
        ..proptest::test_runner::Config::default()
    };

    proptest::proptest!(config, |(commands in proptest::collection::vec(
        proptest::prop_oneof![
            Stake::build(ctx.clone()),
            StakeUpdate::build(ctx.clone()),
            Unstake::build(ctx.clone()),
            AdvanceBurnHeight::build(ctx.clone()),
            IllegalStakeWhileLocked::build(ctx.clone()),
            IllegalStakeUpdateOnUnlocked::build(ctx.clone()),
            IllegalUnstakeOnUnlocked::build(ctx.clone()),
            IllegalDecreaseInUpdate::build(ctx.clone()),
        ],
        4..=24,
    ))| {
        ctx.reset_sut();
        let mut state = Pox5StakerState::default();
        execute_commands(&commands, &mut state);
    });

    let c = ctx.coverage_snapshot();

    assert!(
        c.unlocked > 0,
        "Unlocked never sampled across 50 walks (generator drift?)"
    );
    assert!(
        c.locked_nosched > 0,
        "Locked-no-unstake never sampled across 50 walks (Stake.check too strict?)"
    );
    assert!(
        c.locked_sched > 0,
        "Locked+unstake_scheduled never sampled across 50 walks (Unstake.check too strict?)"
    );

    // Print distribution to make a degraded run debuggable.
    eprintln!(
        "pox5_coverage_smoke: unlocked={} locked_nosched={} locked_sched={}",
        c.unlocked, c.locked_nosched, c.locked_sched,
    );
}
