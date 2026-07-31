// Tests for v2's split between settling rewards and paying them out.
//
// pox-5 keys rewards by reward cycle and never rolls them forward, so a staker
// whose reward in any single cycle is below the sBTC dust limit could never
// take an L1 payout at all -- every per-cycle claim would revert, forever.
// `settle-staker-rewards` moves a cycle's net reward into a per-staker pending
// balance without paying it out, and `payout` drains that balance in one
// transfer, so small per-cycle rewards accumulate until a withdrawal is worth
// making.
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
} from './pox-5-helpers';
import { rov, txErr, txOk } from '@clarigen/test';
import { projectFactory } from '@clarigen/core';
import { accounts, project } from '../clarigen-types';
import { mineUntil, stxToUStx } from '../test-helpers';

const contracts = projectFactory(project, 'simnet');
const sbtcRegistry = contracts.sbtcRegistry;

const deployer = accounts.deployer.address;
const alice = accounts.wallet_1.address;
const bob = accounts.wallet_2.address;

const DUST_LIMIT = 546n;
const MAX_FEE = 100n;
// Must exceed `max-fee + DUST_LIMIT` (646) per `check-payout-config`.
const MIN_CLAIM = 647n;
// A pot of 700 leaves 595 for a sole staker after the pox-5 reserve -- under
// the 646 floor, so no single cycle can be paid out on its own.
const POT = 700n;
const PER_CYCLE = 595n;

const POX_ADDR = {
  version: Uint8Array.from([0x01]),
  hashbytes: new Uint8Array(20).fill(0xab),
};

beforeEach(() => {
  initPox5();
  registerSignerManagerV2();
});

function stakeAlice(numCycles = 4n) {
  txOk(
    pox5.stake({
      signerManager: signerManagerV2.identifier,
      amountUstx: stxToUStx(50_000),
      numCycles,
      startBurnHt: simnet.burnBlockHeight,
      signerCalldata: null,
    }),
    alice,
  );
}

function crystallize(cycle: bigint, rewards = POT) {
  txOk(
    sbtc.transfer({
      recipient: pox5.identifier,
      amount: rewards,
      sender: deployer,
      memo: null,
    }),
    deployer,
  );
  const height = rov(pox5.rewardCycleToBurnHeight(cycle)) + HALF_CYCLE_LENGTH;
  mineUntil(
    height > simnet.burnBlockHeight
      ? height
      : BigInt(simnet.burnBlockHeight) + HALF_CYCLE_LENGTH,
  );
  txOk(pox5.calculateRewards([]), deployer);
  txOk(signerManagerV2.claimRewards([], cycle), deployer);
}

function setL1Config(maxFee = MAX_FEE, minClaim = MIN_CLAIM) {
  txOk(
    signerManagerV2.setPayoutConfig({
      poxAddr: POX_ADDR,
      maxFee,
      minClaim,
    }),
    alice,
  );
}

test('rewards too small to withdraw per cycle accumulate into one payout', () => {
  stakeAlice();
  crystallize(1n);
  crystallize(2n);
  setL1Config();

  // Each cycle on its own is under `max-fee + DUST_LIMIT`, so the one-shot
  // path cannot pay it out -- even for the staker themselves, who is exempt
  // from `min-claim` but not from the sBTC dust limit.
  expect(
    txErr(signerManagerV2.claimStakerRewards(alice, 1n, null), alice).value,
  ).toBe(signerManagerV2Errors.ERR_BELOW_DUST_LIMIT);

  // Settling is always possible: it moves no sBTC.
  expect(txOk(signerManagerV2.settleStakerRewards(alice, 1n, null), alice).value)
    .toBe(PER_CYCLE);
  expect(rov(signerManagerV2.getPendingPayout(alice))).toBe(PER_CYCLE);
  expect(txOk(signerManagerV2.settleStakerRewards(alice, 2n, null), alice).value)
    .toBe(PER_CYCLE);
  expect(rov(signerManagerV2.getPendingPayout(alice))).toBe(PER_CYCLE * 2n);
  expect(rov(signerManagerV2.getTotalPendingPayouts())).toBe(PER_CYCLE * 2n);

  // Two cycles together clear the floor, so one withdrawal covers both --
  // one Bitcoin fee instead of two.
  const payout = txOk(signerManagerV2.payout(alice), alice);
  expect(payout.value).toStrictEqual({
    amount: PER_CYCLE * 2n,
    withdrawalRequest: 1n,
  });
  expect(rov(signerManagerV2.getPendingPayout(alice))).toBe(0n);
  expect(rov(signerManagerV2.getTotalPendingPayouts())).toBe(0n);

  const request = rov(sbtcRegistry.getWithdrawalRequest(1n))!;
  expect(request.amount).toBe(PER_CYCLE * 2n - MAX_FEE);
  expect(request.maxFee).toBe(MAX_FEE);
  expect(request.recipient).toStrictEqual(POX_ADDR);
  expect(rov(signerManagerV2.getWithdrawalRequestStaker(1n))).toBe(alice);
  // The whole payout left the balance into the sBTC withdrawal system.
  expect(rov(signerManagerV2.getWithdrawalLiability())).toBe(PER_CYCLE * 2n);
});

test('settling is permissionless and ungated; only payout enforces min-claim', () => {
  stakeAlice();
  crystallize(1n);
  crystallize(2n);
  setL1Config(MAX_FEE, PER_CYCLE * 2n + 1n); // floor above even the combined total

  // A third party may settle for a staker -- it can only ever credit them.
  txOk(signerManagerV2.settleStakerRewards(alice, 1n, null), bob);
  txOk(signerManagerV2.settleStakerRewards(alice, 2n, null), bob);
  expect(rov(signerManagerV2.getPendingPayout(alice))).toBe(PER_CYCLE * 2n);

  // But they may not force the Bitcoin payout below alice's floor.
  expect(txErr(signerManagerV2.payout(alice), bob).value).toBe(
    signerManagerV2Errors.ERR_BELOW_MIN_CLAIM,
  );

  // Alice is never gated by her own floor.
  txOk(signerManagerV2.payout(alice), alice);
  expect(rov(signerManagerV2.getPendingPayout(alice))).toBe(0n);
});

test('payout without anything settled is rejected', () => {
  expect(txErr(signerManagerV2.payout(alice), alice).value).toBe(
    signerManagerV2Errors.ERR_NO_PENDING_PAYOUT,
  );

  // ...and cannot be replayed once drained.
  stakeAlice();
  crystallize(1n);
  txOk(signerManagerV2.settleStakerRewards(alice, 1n, null), alice);
  txOk(signerManagerV2.payout(alice), alice);
  expect(txErr(signerManagerV2.payout(alice), alice).value).toBe(
    signerManagerV2Errors.ERR_NO_PENDING_PAYOUT,
  );
});

test('settled-but-unpaid rewards are reserved from an admin sweep', () => {
  stakeAlice();
  crystallize(1n);
  txOk(signerManagerV2.settleStakerRewards(alice, 1n, null), alice);

  // The sBTC is in the contract and no longer counted against the cycle
  // bucket, but it is owed to alice and must not be sweepable.
  expect(rov(signerManagerV2.getPendingPayout(alice))).toBe(PER_CYCLE);
  expect(sbtcBalance(signerManagerV2.identifier)).toBeGreaterThanOrEqual(
    PER_CYCLE,
  );
  expect(txErr(signerManagerV2.sweepFeeRefunds(bob), deployer).value).toBe(
    signerManagerV2Errors.ERR_NO_REFUNDS,
  );

  // Alice still gets it in full (no L1 config, so paid directly in sBTC).
  const before = sbtcBalance(alice);
  expect(txOk(signerManagerV2.payout(alice), alice).value).toStrictEqual({
    amount: PER_CYCLE,
    withdrawalRequest: null,
  });
  expect(sbtcBalance(alice)).toBe(before + PER_CYCLE);
});

test('claim-staker-rewards drains any previously settled balance too', () => {
  stakeAlice();
  crystallize(1n);
  crystallize(2n);

  // Settle cycle 1 without paying out, then use the one-shot path on cycle 2.
  txOk(signerManagerV2.settleStakerRewards(alice, 1n, null), alice);
  const before = sbtcBalance(alice);
  const claim = txOk(signerManagerV2.claimStakerRewards(alice, 2n, null), alice);

  // The convenience path pays out the whole pending balance, so `earned`
  // covers both cycles, not just the one named.
  expect(claim.value).toStrictEqual({
    earned: PER_CYCLE * 2n,
    withdrawalRequest: null,
  });
  expect(sbtcBalance(alice)).toBe(before + PER_CYCLE * 2n);
  expect(rov(signerManagerV2.getPendingPayout(alice))).toBe(0n);
});
