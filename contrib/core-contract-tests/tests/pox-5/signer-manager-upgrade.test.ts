import { beforeEach, expect, test } from 'vitest';
import {
  signerManagerCore,
  signerManagerCoreErrors,
  signerManagerV1,
  testSignerManagerV2,
  pox5,
  sbtc,
  sbtcBalance,
  initPox5,
  registerSignerManagerCore,
  randomPayoutConfig,
  payoutConfigCalldata,
  PayoutConfig,
  BASIS_POINTS,
  HALF_CYCLE_LENGTH,
} from './pox-5-helpers';
import { rov, txErr, txOk } from '@clarigen/test';
import { ContractCallTyped, Response, projectFactory } from '@clarigen/core';
import { accounts, project } from '../clarigen-types';
import { mineUntil, stxToUStx } from '../test-helpers';

// What an upgrade must preserve. Core keeps all accounting, so pending
// payouts, unsettled reserves and live withdrawals carry over to the new
// module untouched. Policy state the old module kept for itself (v1's fee
// snapshots) stays readable through a literal call, so cycles pulled in
// before the upgrade still settle at the fee they were pulled in with.

const contracts = projectFactory(project, 'simnet');
const sbtcWithdrawal = contracts.sbtcWithdrawal;
const SBTC_SIGNER = 'SM3VDXK3WZZSA84XXFKAFAF15NNZX32CTSG82JFQ4';

const deployer = accounts.deployer.address;
const alice = accounts.wallet_1.address;
const bob = accounts.wallet_2.address;

beforeEach(() => {
  initPox5();
  registerSignerManagerCore();
});

function stake(staker: string, config: PayoutConfig | null = null) {
  txOk(
    pox5.stake({
      signerManager: signerManagerCore.identifier,
      amountUstx: stxToUStx(50_000),
      numCycles: 3n,
      startBurnHt: simnet.burnBlockHeight,
      signerCalldata: config && payoutConfigCalldata(config),
    }),
    staker,
  );
}

function fundAndCrystallize(cycle: bigint, rewards: bigint): bigint {
  txOk(
    sbtc.transfer({
      recipient: pox5.identifier,
      amount: rewards,
      sender: deployer,
      memo: null,
    }),
    deployer,
  );
  mineUntil(rov(pox5.rewardCycleToBurnHeight(cycle)) + HALF_CYCLE_LENGTH);
  txOk(pox5.calculateRewards([]), deployer);
  return rewards - (rewards * pox5.constants.RESERVE_RATIO) / BASIS_POINTS;
}

function upgradeToV2() {
  txOk(signerManagerV1.setModule(testSignerManagerV2.identifier), deployer);
  expect(rov(signerManagerCore.getCurrentModule())).toBe(
    testSignerManagerV2.identifier,
  );
}

test('the old module is fully cut off after hand-off', () => {
  stake(alice);
  fundAndCrystallize(1n, 2000n);
  upgradeToV2();
  const calls: ContractCallTyped<any, Response<any, bigint>>[] = [
    signerManagerV1.claimRewards([], 1n),
    signerManagerV1.settleStakerRewards(alice, 1n, null),
    signerManagerV1.payout(alice),
    signerManagerV1.reclaimFailedWithdrawal(1n),
    signerManagerV1.withdrawFees(1n, deployer),
    signerManagerV1.sweepFeeRefunds(deployer),
    signerManagerV1.setModule(signerManagerV1.identifier),
    signerManagerV1.setPayoutConfig({
      l1Withdrawal: null,
      sbtcRecipient: null,
    }),
  ];
  for (const call of calls) {
    expect(txErr(call, deployer).value).toBe(
      signerManagerCoreErrors.ERR_UNAUTHORIZED_MODULE,
    );
  }
});

test('a cycle pulled in under v1 settles at the v1 fee after upgrade', () => {
  stake(alice);
  txOk(signerManagerV1.updateFees(500n), deployer);
  const gross1 = fundAndCrystallize(1n, 2000n);
  txOk(signerManagerV1.claimRewards([], 1n), deployer);
  upgradeToV2();

  // v2 reads v1's snapshot for cycle 1: 5%, not its own flat 10%.
  expect(
    txOk(testSignerManagerV2.settleStakerRewards(alice, 1n, null), bob).value,
  ).toEqual({ gross: gross1, fee: (gross1 * 500n) / BASIS_POINTS });

  // A cycle v2 pulls in itself uses v2's fee.
  const gross2 = fundAndCrystallize(2n, 2000n);
  txOk(testSignerManagerV2.claimRewards([], 2n), deployer);
  expect(
    txOk(testSignerManagerV2.settleStakerRewards(alice, 2n, null), bob).value,
  ).toEqual({ gross: gross2, fee: (gross2 * 1000n) / BASIS_POINTS });

  const net =
    gross1 -
    (gross1 * 500n) / BASIS_POINTS +
    gross2 -
    (gross2 * 1000n) / BASIS_POINTS;
  expect(rov(signerManagerCore.getPendingPayout(alice))).toBe(net);
  const before = sbtcBalance(alice);
  txOk(testSignerManagerV2.payout(alice), alice);
  expect(sbtcBalance(alice)).toBe(before + net);
});

test('pending payouts and unsettled reserves survive the upgrade', () => {
  stake(alice);
  stake(bob);
  const total = fundAndCrystallize(1n, 2000n);
  txOk(signerManagerV1.claimRewards([], 1n), deployer);
  txOk(signerManagerV1.settleStakerRewards(alice, 1n, null), alice);
  const alicePending = rov(signerManagerCore.getPendingPayout(alice));
  upgradeToV2();

  expect(rov(signerManagerCore.getPendingPayout(alice))).toBe(alicePending);
  expect(rov(signerManagerCore.getRewardReserve(1n, null))).toBe(
    total - alicePending,
  );
  txOk(testSignerManagerV2.settleStakerRewards(bob, 1n, null), bob);
  expect(rov(signerManagerCore.getRewardReserve(1n, null))).toBe(0n);
  txOk(testSignerManagerV2.payout(alice), alice);
  txOk(testSignerManagerV2.payout(bob), bob);
  expect(sbtcBalance(signerManagerCore.identifier)).toBe(0n);
});

test('a withdrawal initiated under v1 and rejected later is retried by v2', () => {
  stake(alice, randomPayoutConfig({ maxFee: 100n, minClaim: 0n }));
  const total = fundAndCrystallize(1n, 2000n);
  txOk(signerManagerV1.claimRewards([], 1n), deployer);
  txOk(signerManagerV1.claimStakerRewards(alice, 1n, null), bob);
  expect(rov(signerManagerCore.getWithdrawalLiability())).toBe(total);
  upgradeToV2();

  txOk(sbtcWithdrawal.rejectWithdrawalRequest(1n, 0n), SBTC_SIGNER);
  expect(txOk(testSignerManagerV2.reclaimFailedWithdrawal(1n), bob).value).toBe(
    total,
  );
  expect(rov(signerManagerCore.getPendingPayout(alice))).toBe(total);
  expect(rov(signerManagerCore.getWithdrawalLiability())).toBe(0n);
  // Retry through v2 using the config alice set under v1.
  expect(txOk(testSignerManagerV2.payout(alice), bob).value).toBe(2n);
  expect(rov(signerManagerCore.getWithdrawalRequestStaker(2n))).toBe(alice);
});
