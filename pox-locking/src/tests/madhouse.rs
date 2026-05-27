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

//! # PoX-5 Staker Lifecycle (Madhouse)
//!
//! Stateful property-based testing of the pox-5 locking primitives. The
//! test composes random sequences of `Stake`, `StakeUpdate`, `Unstake`, and
//! `AdvanceBurnHeight` commands against a shared system-under-test
//! (`MemoryBackingStore` + a configurable burn-height oracle), keeping a
//! shadow model of the expected state in lockstep.
//!
//! After every command we verify three invariants:
//! 1. **Conservation**: `available + locked == total_ustx` (constant).
//! 2. **Auto-unlock**: `current_burn_height >= unlock_height` implies
//!    `locked_ustx == 0` on the SUT.
//! 3. **Monotonic locking**: `StakeUpdate` never reduces `locked_ustx`.
//!
//! Design notes:
//! - The model is an explicit ADT (`enum AccountState`), not a blob of
//!   `Option<…>` fields.
//! - Generators produce only structurally valid arguments (`amount > 0`,
//!   `unlock > 0`); whether the command is *legal in this state* is the
//!   responsibility of `Command::check`. No `prop_assume!` in command
//!   bodies.
//! - One driving function (`pox5_staker_lifecycle_madhouse`) folds the
//!   commands; per-command postconditions live inside each `apply`.

use std::sync::atomic::{AtomicU32, AtomicU64, Ordering};
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

/// Total STX balance the staker starts with. Big enough to absorb any
/// random sequence of stakes/updates that the generators below produce.
const TOTAL_USTX: u128 = 100_000_000_000;

/// Cap for random `unlock_height` deltas. Burn height starts at 0 and the
/// generators bound the unlock height to `current + 1..=current + WINDOW`,
/// so this also caps how far in the future a lock can be scheduled.
const UNLOCK_WINDOW: u64 = 1_000_000;

/// Reward cycle length used by `Unstake` (when scheduling the new unlock).
const REWARD_CYCLE_LENGTH: u64 = 1_000;

// ---------------------------------------------------------------------------
// ConfigurableBurnStateDB — like NullBurnStateDB but with a settable tip
// ---------------------------------------------------------------------------

/// `BurnStateDB` whose `get_tip_burn_block_height` is controlled by a
/// settable `AtomicU32`. All other methods mirror `NullBurnStateDB` (the
/// defaults used by the existing in-memory test setup).
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

// ---------------------------------------------------------------------------
// Model: AccountState ADT + Pox5StakerState
// ---------------------------------------------------------------------------

/// Account-level model. Two states only — `Unlocked` and `Locked`.
/// `Unstake` does NOT introduce a separate state; semantically it merely
/// reschedules the `unlock_height`. The boolean `unstake_scheduled` is a
/// marker for invariant 3 ("`StakeUpdate` doesn't run on an unstaking
/// account") rather than a real state.
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

    /// Apply the auto-unlock rule to the model: if the current burn height
    /// has caught up to the lock's unlock height, the lock has expired.
    fn maybe_auto_unlock(&mut self) {
        if let AccountState::Locked { unlock_height, .. } = self.account {
            if self.current_burn_height >= unlock_height {
                self.account = AccountState::Unlocked;
            }
        }
    }
}

// ---------------------------------------------------------------------------
// Test context: shared system-under-test
// ---------------------------------------------------------------------------

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

    /// Run a closure with a fresh `ClarityDatabase` wired up to our
    /// in-memory store + configurable burn state. Begins and commits a
    /// transaction around the closure.
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

    /// Read the SUT's CANONICAL view of the staker balance: (locked,
    /// unlocked). Canonical means the snapshot's auto-unlock logic has
    /// been applied (a lock past its unlock height collapses to
    /// `locked = 0`, `unlocked = total`), matching what a Clarity contract
    /// would observe via `stx-get-balance`.
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

#[derive(Clone)]
pub struct Pox5Context {
    sut: Arc<Mutex<Pox5SystemUnderTest>>,
    total_ustx: u128,
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
        }
    }

    /// Reset the system-under-test to a fresh, funded state. Required
    /// between proptest iterations because `proptest!` reruns the body
    /// for shrinking even when `cases = 1`, and the SUT lives behind an
    /// `Arc<Mutex<>>` shared across iterations.
    fn reset_sut(&self) {
        let staker: PrincipalData = StandardPrincipalData::transient().into();
        let mut fresh = Pox5SystemUnderTest::new(staker);
        fresh.fund(self.total_ustx);
        *self.sut.lock().unwrap() = fresh;
    }
}

// ---------------------------------------------------------------------------
// Coverage classification
// ---------------------------------------------------------------------------
//
// Per-bucket counters bumped by `check_invariants` on every step. A weak
// `> 0` assertion in `pox5_coverage_smoke` proves the random walk
// actually reaches every macro-state of the FSM — protects against a
// silent generator drift where (e.g.) `Unstake.check` becomes stricter
// and `unstake_scheduled = true` stops being sampled at all.

static COVERAGE_UNLOCKED: AtomicU64 = AtomicU64::new(0);
static COVERAGE_LOCKED_NOSCHED: AtomicU64 = AtomicU64::new(0);
static COVERAGE_LOCKED_SCHED: AtomicU64 = AtomicU64::new(0);

fn classify_state(model: &Pox5StakerState) {
    match &model.account {
        AccountState::Unlocked => {
            COVERAGE_UNLOCKED.fetch_add(1, Ordering::Relaxed);
        }
        AccountState::Locked { unstake_scheduled: false, .. } => {
            COVERAGE_LOCKED_NOSCHED.fetch_add(1, Ordering::Relaxed);
        }
        AccountState::Locked { unstake_scheduled: true, .. } => {
            COVERAGE_LOCKED_SCHED.fetch_add(1, Ordering::Relaxed);
        }
    }
}

/// Invariants verified after every command. Returns immediately if any
/// fails — the panic surfaces as a madhouse test failure with shrinking.
fn check_invariants(model: &Pox5StakerState, ctx: &Pox5Context) {
    classify_state(model);
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

    // Invariant 2: auto-unlock — if the current burn height has reached or
    // passed the unlock height, `has_locked_tokens()` must be false on the
    // SUT (regardless of the raw `amount_locked` field, which reflects
    // the snapshot pre-canonicalization).
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

// ---------------------------------------------------------------------------
// Commands
// ---------------------------------------------------------------------------

/// Stake: lock `amount` ustx with unlock at `unlock_height`. Legal only
/// when the account is currently unlocked.
struct Stake {
    ctx: Arc<Pox5Context>,
    amount: u128,
    unlock_height: u64,
}

impl Command<Pox5StakerState, Pox5Context> for Stake {
    fn check(&self, state: &Pox5StakerState) -> bool {
        matches!(state.account, AccountState::Unlocked)
            && self.amount > 0
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
        // Range up to `total` (not `total/2`) so the full-balance edge is
        // actually sampled — narrowing would silently skip the boundary.
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

/// StakeUpdate: extend or increase the lock. Legal only when locked and
/// NOT yet unstaking, and the new total must be >= the current locked
/// amount (monotonic locking — invariant 3).
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
                    && self.new_total <= self.ctx.total_ustx
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
                    // Monotonic locking — pre/post check.
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

/// Unstake: reschedule the lock's unlock height to the start of the next
/// reward cycle. Legal only when locked and not already unstaking.
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
        // Schedule the unlock at the start of the next reward cycle from
        // the current burn height. Must be > current to satisfy
        // `pox_unstake_v5`'s unlock_height > 0 + has_locked_tokens checks.
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

/// AdvanceBurnHeight: bumps the SUT-visible burn height by `delta` and
/// updates the model. After advancement, the model applies auto-unlock if
/// the new height has caught up.
struct AdvanceBurnHeight {
    ctx: Arc<Pox5Context>,
    delta: u64,
}

impl Command<Pox5StakerState, Pox5Context> for AdvanceBurnHeight {
    fn check(&self, _state: &Pox5StakerState) -> bool {
        self.delta > 0
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

/// Round `h` up to the next multiple of `REWARD_CYCLE_LENGTH`. Always
/// strictly greater than `h`.
fn next_reward_cycle_start(h: u64) -> u64 {
    let n = h / REWARD_CYCLE_LENGTH;
    (n + 1) * REWARD_CYCLE_LENGTH
}

// ---------------------------------------------------------------------------
// Negative-path commands — adversarial pins on rejection errors
// ---------------------------------------------------------------------------
//
// These commands DO call into the SUT (unlike the legal commands above
// which only run when the state allows). Each is enabled by `check` only
// in states where the operation is illegal, and `apply` asserts the
// expected error variant.
//
// Without these, an interleaving regression that breaks (say)
// `PoxAlreadyLocked` returning `Ok` would never surface in the FSM run —
// the legal `Stake` command's `check` would just skip and we'd move on.

/// Try to stake while already locked. Must produce `PoxAlreadyLocked`.
struct IllegalStakeWhileLocked {
    ctx: Arc<Pox5Context>,
    amount: u128,
    unlock_height: u64,
}

impl Command<Pox5StakerState, Pox5Context> for IllegalStakeWhileLocked {
    fn check(&self, state: &Pox5StakerState) -> bool {
        // `pox_lock_v5` checks unlock_burn_height != 0, amount != 0, then
        // has_locked_tokens. We supply amount > 0 and unlock > 0 so the
        // failure is genuinely PoxAlreadyLocked, not an earlier gate.
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
        // Model is unchanged: the failed call must not mutate the SUT.
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

/// Try to stake-update while NOT locked. Must produce
/// `PoxExtendNotLocked`. (Args pass the earlier zero-amount/zero-height
/// gates to ensure that's the rule we're hitting.)
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

/// Try to unstake while NOT locked. Must produce `PoxUnstakeNotLocked`.
/// Supplies `new_unlock_height > 0` to bypass the earlier gate.
struct IllegalUnstakeOnUnlocked {
    ctx: Arc<Pox5Context>,
    new_unlock_height: u64,
}

impl Command<Pox5StakerState, Pox5Context> for IllegalUnstakeOnUnlocked {
    fn check(&self, state: &Pox5StakerState) -> bool {
        matches!(state.account, AccountState::Unlocked) && self.new_unlock_height > 0
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

/// Try to update-lock with `new_total < current locked_ustx`. Must
/// produce `PoxInvalidIncrease` — `stake-update` cannot be used as a
/// covert unstake.
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
                // Need room to decrease (`locked > 1`), the unstake flag
                // false (the unstake-in-progress path has its own rules),
                // and the new unlock_height strictly > current to bypass
                // the `unlock_burn_height <= burn_block_height` gate.
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
        // The `decrease` is bounded against the runtime locked amount in
        // `check`, so here we pick freely from the universe of possible
        // decrements.
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

// ---------------------------------------------------------------------------
// Test entry point
// ---------------------------------------------------------------------------

/// Drive the staker through a sequence of random legal operations and
/// verify the invariants after every step.
///
/// We deliberately do NOT use madhouse's `scenario!` macro here: the macro
/// creates the test context once and shares it across proptest iterations.
/// Because `proptest!` reruns the body during shrinking (even with
/// `cases = 1`), the SUT would leak burn-height advancement and balance
/// state across iterations. We expand the macro by hand and reset the SUT
/// at the start of every iteration so each command sequence starts from a
/// clean slate.
///
/// Set `MADHOUSE=1` to switch from deterministic ordering (commands in
/// declaration order) to random permutation mode.
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

/// Asserts that random walks of the FSM actually reach every
/// macro-state of `AccountState`. Bumps per-bucket atomic counters in
/// `classify_state` (called from `check_invariants` after every
/// command), then asserts every counter is `> 0` after 50 walks.
///
/// If a future change makes `Unstake.check` stricter (e.g., only inside
/// a reward cycle window) so the generator silently stops producing
/// `unstake_scheduled = true`, this smoke fails — separating "the
/// generator doesn't reach X" from "X doesn't hold".
#[test]
#[cfg_attr(test, tag(t_prop))]
fn pox5_coverage_smoke() {
    // Reset counters so we measure only this test's walks.
    COVERAGE_UNLOCKED.store(0, Ordering::Relaxed);
    COVERAGE_LOCKED_NOSCHED.store(0, Ordering::Relaxed);
    COVERAGE_LOCKED_SCHED.store(0, Ordering::Relaxed);

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
        ],
        4..=24,
    ))| {
        ctx.reset_sut();
        let mut state = Pox5StakerState::default();
        execute_commands(&commands, &mut state);
    });

    let unlocked = COVERAGE_UNLOCKED.load(Ordering::Relaxed);
    let locked_nosched = COVERAGE_LOCKED_NOSCHED.load(Ordering::Relaxed);
    let locked_sched = COVERAGE_LOCKED_SCHED.load(Ordering::Relaxed);

    assert!(
        unlocked > 0,
        "Unlocked state never observed across 50 walks — generator drift?"
    );
    assert!(
        locked_nosched > 0,
        "Locked-no-unstake never observed across 50 walks — Stake.check() too strict?"
    );
    assert!(
        locked_sched > 0,
        "Locked+unstake_scheduled never observed across 50 walks — Unstake.check() too strict?"
    );

    // Surface the distribution so a degraded run is debuggable.
    eprintln!(
        "pox5_coverage_smoke: unlocked={unlocked} locked_nosched={locked_nosched} locked_sched={locked_sched}"
    );
}
