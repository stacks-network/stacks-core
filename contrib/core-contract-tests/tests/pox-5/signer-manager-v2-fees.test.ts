// Port of the fee/reward tests in `signer-manager.test.ts` to the v2 reference
// contract (`contracts/signer-manager-v2.clar`).
//
// Two things differ from the v1 originals:
//
//   * Rates. v1's tests were written when `MAX_BIPS` was u10000 and use 1000 /
//     5000 / 9999 bips. The cap is now 500 (5%, inclusive in v2), so these use
//     rates at or below it.
//   * Timing. In v2 a fee *increase* only becomes snapshottable
//     `FEE_ACTIVATION_DELAY_CYCLES` (2) cycles after it is queued, so the
//     helpers below wait for activation before crystallizing a cycle.
//     Decreases still apply immediately, which a couple of these rely on.
import { beforeEach, expect, test } from 'vitest';
import {
  signerManagerV2,
  signerManagerV2Errors,
  pox5,
  initPox5,
  registerSignerManagerV2,
  sbtc,
  sbtcBalance,
  HALF_CYCLE_LENGTH,
  BASIS_POINTS,
} from './pox-5-helpers';
import { filterEvents, rov, txErr, txOk } from '@clarigen/test';
import { accounts } from '../clarigen-types';
import { mineUntil, stxToUStx } from '../test-helpers';
import { CoreNodeEventType, cvToValue } from '@clarigen/core';

const deployer = accounts.deployer.address;
const alice = accounts.wallet_1.address;
const bob = accounts.wallet_2.address;
const charlie = accounts.wallet_3.address;
const dave = accounts.wallet_4.address;

// 4% -- the working rate for these ports, in place of v1's 10%.
const FEE_BIPS = 400n;

beforeEach(() => {
  initPox5();
  registerSignerManagerV2();
});

function reserveRewards(rewards: bigint) {
  return (rewards * pox5.constants.RESERVE_RATIO) / BASIS_POINTS;
}

/** The portion of a reward pot that reaches stakers, after the pox-5 reserve. */
function stxRewards(rewards: bigint) {
  return rewards - reserveRewards(rewards);
}

/** `gross * bips / 10000`, matching the contract's integer division. */
function feeOn(gross: bigint, bips: bigint) {
  return (gross * bips) / BASIS_POINTS;
}

/**
 * Queue a fee change and, if it was an increase, advance to the cycle at which
 * it becomes snapshottable. Decreases activate immediately and return at once.
 */
function activateFees(bips: bigint) {
  txOk(signerManagerV2.updateFees(bips), deployer);
  const activation = rov(signerManagerV2.getPendingFees()).activationCycle;
  const activationHeight = rov(pox5.rewardCycleToBurnHeight(activation));
  if (activationHeight > simnet.burnBlockHeight) {
    mineUntil(activationHeight);
  }
  expect(rov(signerManagerV2.getActiveFeeBips())).toBe(bips);
}

function stake(staker: string, amountUstx = stxToUStx(50_000)) {
  txOk(
    pox5.stake({
      signerManager: signerManagerV2.identifier,
      amountUstx,
      numCycles: 2n,
      startBurnHt: simnet.burnBlockHeight,
      signerCalldata: null,
    }),
    staker,
  );
}

/**
 * Fund `rewards` into pox-5, crystallize the cycle the current stakers are
 * staked for, and have the manager pull the pot. Returns that reward cycle.
 *
 * pox-5 allows one `calculate-rewards` per distribution window (half a cycle),
 * so crystallizing the same cycle a second time advances half a cycle first --
 * otherwise it fails with `ERR_DISTRIBUTION_ALREADY_COMPUTED`.
 */
function crystallize(rewards: bigint, cycle?: bigint) {
  const target = cycle ?? rov(pox5.currentPoxRewardCycle()) + 1n;
  txOk(
    sbtc.transfer({
      recipient: pox5.identifier,
      amount: rewards,
      sender: deployer,
      memo: null,
    }),
    deployer,
  );
  const height = rov(pox5.rewardCycleToBurnHeight(target)) + HALF_CYCLE_LENGTH;
  mineUntil(
    height > simnet.burnBlockHeight
      ? height
      : BigInt(simnet.burnBlockHeight) + HALF_CYCLE_LENGTH,
  );
  txOk(pox5.calculateRewards([]), deployer);
  txOk(signerManagerV2.claimRewards([], target), deployer);
  return target;
}

test('only admins can update fees and fees must be at most max bips', () => {
  expect(txErr(signerManagerV2.updateFees(100n), alice).value).toBe(
    signerManagerV2Errors.ERR_UNAUTHORIZED_ADMIN,
  );
  // v2's cap is inclusive, so 500 (exactly 5%) is settable and 501 is not.
  txOk(signerManagerV2.updateFees(500n), deployer);
  expect(txErr(signerManagerV2.updateFees(501n), deployer).value).toBe(
    signerManagerV2Errors.ERR_INVALID_FEES_BIPS,
  );
  expect(txErr(signerManagerV2.updateFees(10000n), deployer).value).toBe(
    signerManagerV2Errors.ERR_INVALID_FEES_BIPS,
  );
  expect(txErr(signerManagerV2.updateFees(10001n), deployer).value).toBe(
    signerManagerV2Errors.ERR_INVALID_FEES_BIPS,
  );
});

test('fees are deducted from newly earned staker rewards', () => {
  const rewards = 2000n;
  const grossPerStaker = stxRewards(rewards) / 2n;
  const fee = feeOn(grossPerStaker, FEE_BIPS);

  activateFees(FEE_BIPS);
  stake(alice);
  stake(bob);
  const cycle = crystallize(rewards);

  expect(rov(signerManagerV2.getEarnedStakerRewards(alice, cycle, null))).toEqual(
    { earned: grossPerStaker - fee, fees: fee },
  );
  expect(rov(signerManagerV2.getEarnedStakerRewards(bob, cycle, null))).toEqual({
    earned: grossPerStaker - fee,
    fees: fee,
  });
});

test('uneven multi-staker rewards conserve gross, fees, and residual dust', () => {
  const rewards = 2000n;

  activateFees(FEE_BIPS);
  stake(alice, stxToUStx(50_000));
  stake(bob, stxToUStx(30_000));
  stake(charlie, stxToUStx(20_001));
  const cycle = crystallize(rewards);

  const grossClaimedBySigner = rov(signerManagerV2.getUnclaimedStakerRewards());
  const aliceRewards = rov(
    signerManagerV2.getEarnedStakerRewards(alice, cycle, null),
  );
  const bobRewards = rov(signerManagerV2.getEarnedStakerRewards(bob, cycle, null));
  const charlieRewards = rov(
    signerManagerV2.getEarnedStakerRewards(charlie, cycle, null),
  );
  const grossAlice = aliceRewards.earned + aliceRewards.fees;
  const grossBob = bobRewards.earned + bobRewards.fees;
  const grossCharlie = charlieRewards.earned + charlieRewards.fees;
  const totalGross = grossAlice + grossBob + grossCharlie;
  const residualDust = grossClaimedBySigner - totalGross;

  // The per-staker gross split is pox-5's and is independent of the fee rate,
  // so these pin the same values the v1 test did.
  expect(grossAlice).toBe(849n);
  expect(grossBob).toBe(509n);
  expect(grossCharlie).toBe(340n);
  expect(grossClaimedBySigner).toBe(1699n);
  expect(residualDust).toBe(1n);

  // Fees are that gross times the snapshotted rate, rounded down.
  expect(aliceRewards.fees).toBe(feeOn(grossAlice, FEE_BIPS));
  expect(bobRewards.fees).toBe(feeOn(grossBob, FEE_BIPS));
  expect(charlieRewards.fees).toBe(feeOn(grossCharlie, FEE_BIPS));

  const aliceBalance = sbtcBalance(alice);
  const bobBalance = sbtcBalance(bob);
  const charlieBalance = sbtcBalance(charlie);
  txOk(signerManagerV2.claimStakerRewards(alice, cycle, null), alice);
  txOk(signerManagerV2.claimStakerRewards(bob, cycle, null), bob);
  txOk(signerManagerV2.claimStakerRewards(charlie, cycle, null), charlie);

  expect(sbtcBalance(alice)).toBe(aliceBalance + aliceRewards.earned);
  expect(sbtcBalance(bob)).toBe(bobBalance + bobRewards.earned);
  expect(sbtcBalance(charlie)).toBe(charlieBalance + charlieRewards.earned);
  expect(rov(signerManagerV2.getEarnedFees())).toBe(
    aliceRewards.fees + bobRewards.fees + charlieRewards.fees,
  );
  // Only the un-attributable residue is left reserved.
  expect(rov(signerManagerV2.getUnclaimedStakerRewards())).toBe(residualDust);
  expect(sbtcBalance(signerManagerV2.identifier)).toBe(
    rov(signerManagerV2.getEarnedFees()) + residualDust,
  );

  expect(txErr(signerManagerV2.sweepFeeRefunds(dave), deployer).value).toBe(
    signerManagerV2Errors.ERR_NO_REFUNDS,
  );

  txOk(signerManagerV2.updateAdmin(dave, true), deployer);
  expect(txErr(signerManagerV2.sweepFeeRefunds(dave), dave).value).toBe(
    signerManagerV2Errors.ERR_NO_REFUNDS,
  );

  const deployerBalance = sbtcBalance(deployer);
  const fees = rov(signerManagerV2.getEarnedFees());
  txOk(
    signerManagerV2.withdrawFees({ amount: fees, recipient: deployer }),
    deployer,
  );
  expect(sbtcBalance(deployer)).toBe(deployerBalance + fees);
  expect(rov(signerManagerV2.getEarnedFees())).toBe(0n);
  // The residue stays in the contract and is still not sweepable.
  expect(sbtcBalance(signerManagerV2.identifier)).toBe(residualDust);
  expect(txErr(signerManagerV2.sweepFeeRefunds(dave), dave).value).toBe(
    signerManagerV2Errors.ERR_NO_REFUNDS,
  );
});

test('claiming staker rewards transfers net rewards after fees', () => {
  const rewards = 2000n;
  const grossPerStaker = stxRewards(rewards) / 2n;
  const netRewards = grossPerStaker - feeOn(grossPerStaker, FEE_BIPS);

  activateFees(FEE_BIPS);
  stake(alice);
  stake(bob);
  const cycle = crystallize(rewards);

  const aliceBalance = sbtcBalance(alice);
  const claim = txOk(
    signerManagerV2.claimStakerRewards(alice, cycle, null),
    alice,
  );

  // No payout config, so the staker is paid directly in sBTC and no L1
  // withdrawal is initiated; the return carries `none` for the request-id.
  expect(claim.value).toStrictEqual({
    earned: netRewards,
    withdrawalRequest: null,
  });
  const [transfer] = filterEvents(
    claim.events,
    CoreNodeEventType.FtTransferEvent,
  );
  // v2 splits the claim into a settle and a payout, each with its own event.
  const prints = filterEvents(claim.events, CoreNodeEventType.ContractEvent)
    .filter((e) => e.data.contract_identifier === signerManagerV2.identifier)
    .map((e) => cvToValue<{ topic: string } & Record<string, any>>(e.data.value));
  const settleEvent = prints.find((p) => p.topic === 'settle-staker-rewards')!;
  const payoutEvent = prints.find((p) => p.topic === 'payout')!;

  expect(transfer.data.sender).toBe(signerManagerV2.identifier);
  expect(transfer.data.recipient).toBe(alice);
  expect(transfer.data.amount).toBe(netRewards.toString());
  expect(settleEvent).toEqual({
    topic: 'settle-staker-rewards',
    staker: alice,
    rewardCycle: cycle,
    bondIndex: null,
    earned: netRewards,
    fees: feeOn(grossPerStaker, FEE_BIPS),
    pendingPayout: netRewards,
  });
  expect(payoutEvent).toEqual({
    topic: 'payout',
    amountSats: netRewards,
    l1Withdrawal: null,
    staker: alice,
  });
  expect(sbtcBalance(alice)).toBe(aliceBalance + netRewards);
  expect(
    rov(signerManagerV2.getEarnedStakerRewards(alice, cycle, null)),
  ).toEqual({ earned: 0n, fees: 0n });
});

test('admins can withdraw accrued fees', () => {
  const rewards = 2000n;
  const grossPerStaker = stxRewards(rewards) / 2n;
  const fee = feeOn(grossPerStaker, FEE_BIPS);

  activateFees(FEE_BIPS);
  stake(alice);
  stake(bob);
  const cycle = crystallize(rewards);
  txOk(signerManagerV2.claimStakerRewards(alice, cycle, null), alice);
  txOk(signerManagerV2.claimStakerRewards(bob, cycle, null), bob);

  expect(rov(signerManagerV2.getEarnedFees())).toBe(fee * 2n);
  expect(
    txErr(
      signerManagerV2.withdrawFees({ amount: 1n, recipient: deployer }),
      alice,
    ).value,
  ).toBe(signerManagerV2Errors.ERR_UNAUTHORIZED_ADMIN);
  expect(
    txErr(
      signerManagerV2.withdrawFees({
        amount: fee * 2n + 1n,
        recipient: deployer,
      }),
      deployer,
    ).value,
  ).toBe(signerManagerV2Errors.ERR_INSUFFICIENT_FEES);

  const deployerBalance = sbtcBalance(deployer);
  const withdraw = txOk(
    signerManagerV2.withdrawFees({ amount: fee, recipient: deployer }),
    deployer,
  );
  const [transfer] = filterEvents(
    withdraw.events,
    CoreNodeEventType.FtTransferEvent,
  );

  expect(withdraw.value).toBe(fee);
  expect(transfer.data.sender).toBe(signerManagerV2.identifier);
  expect(transfer.data.recipient).toBe(deployer);
  expect(transfer.data.amount).toBe(fee.toString());
  expect(sbtcBalance(deployer)).toBe(deployerBalance + fee);
  expect(rov(signerManagerV2.getEarnedFees())).toBe(fee);
});

test('fee changes do not apply retroactively to an already recorded cycle', () => {
  const rewards = 2000n;
  const grossAfterTwoCalculations = stxRewards(rewards * 2n) / 2n;
  const fee = feeOn(grossAfterTwoCalculations, FEE_BIPS);

  activateFees(FEE_BIPS);
  stake(alice);
  stake(bob);
  const cycle = crystallize(rewards);
  const grossPerStaker = stxRewards(rewards) / 2n;
  expect(rov(signerManagerV2.getEarnedStakerRewards(alice, cycle, null))).toEqual(
    {
      earned: grossPerStaker - feeOn(grossPerStaker, FEE_BIPS),
      fees: feeOn(grossPerStaker, FEE_BIPS),
    },
  );

  // A *decrease* takes effect immediately, so this is the sharpest version of
  // the test: even a rate that is active right now must not revise the rate
  // already snapshotted for `cycle`.
  txOk(signerManagerV2.updateFees(100n), deployer);
  expect(rov(signerManagerV2.getActiveFeeBips())).toBe(100n);
  crystallize(rewards, cycle);

  expect(rov(signerManagerV2.getFeeBipsForCycle(cycle, null))).toBe(FEE_BIPS);
  expect(rov(signerManagerV2.getEarnedStakerRewards(alice, cycle, null))).toEqual(
    { earned: grossAfterTwoCalculations - fee, fees: fee },
  );
});

test('already claimed rewards are not affected by later fee changes', () => {
  const rewards = 2000n;
  const grossPerStaker = stxRewards(rewards) / 2n;
  const net = grossPerStaker - feeOn(grossPerStaker, FEE_BIPS);

  activateFees(FEE_BIPS);
  stake(alice);
  stake(bob);
  const cycle = crystallize(rewards);

  const aliceBalance = sbtcBalance(alice);
  txOk(signerManagerV2.claimStakerRewards(alice, cycle, null), alice);
  expect(sbtcBalance(alice)).toBe(aliceBalance + net);

  txOk(signerManagerV2.updateFees(100n), deployer);
  crystallize(rewards, cycle);

  // The second pot is charged at the cycle's original snapshot, not the new
  // rate, and the already-paid first claim is untouched.
  expect(rov(signerManagerV2.getEarnedStakerRewards(alice, cycle, null))).toEqual(
    {
      earned: grossPerStaker - feeOn(grossPerStaker, FEE_BIPS),
      fees: feeOn(grossPerStaker, FEE_BIPS),
    },
  );
  txOk(signerManagerV2.claimStakerRewards(alice, cycle, null), alice);
  expect(sbtcBalance(alice)).toBe(aliceBalance + net * 2n);
});
