import { projectFactory } from '@clarigen/core';
import { rov, txErr, txOk } from '@clarigen/test';
import { hex } from '@scure/base';
import { beforeEach, expect, test } from 'vitest';
import { accounts, project } from '../clarigen-types';
import { mineUntil, stxToUStx } from '../test-helpers';
import {
  BASIS_POINTS,
  HALF_CYCLE_LENGTH,
  initPox5,
  type PayoutConfig,
  payoutConfigCalldata,
  pox5,
  randomPayoutConfig,
  registerSignerManagerV2,
  signerManagerV2,
  signerManagerV2Errors,
  sbtc,
  sbtcBalance,
} from './pox-5-helpers';

const contracts = projectFactory(project, 'simnet');
const sbtcWithdrawal = contracts.sbtcWithdrawal;

// The principal allowed to accept/reject sBTC withdrawals: the sBTC registry's
// `current-signer-principal`, which defaults to the sBTC deployer.
const SBTC_SIGNER = 'SM3VDXK3WZZSA84XXFKAFAF15NNZX32CTSG82JFQ4';
const DUST_LIMIT = 546n;

const deployer = accounts.deployer.address;
const alice = accounts.wallet_1.address;
const bob = accounts.wallet_2.address;
const charlie = accounts.wallet_3.address;

beforeEach(() => {
  initPox5();
  registerSignerManagerV2();
});

function stake(staker: string, config: PayoutConfig | null = null) {
  txOk(
    pox5.stake({
      signerManager: signerManagerV2.identifier,
      amountUstx: stxToUStx(50_000),
      numCycles: 3n,
      startBurnHt: simnet.burnBlockHeight,
      signerCalldata: config && payoutConfigCalldata(config),
    }),
    staker,
  );
}

// Fund pox-5 with `rewards`, roll into `cycle`, crystallize and pull the
// signer's share into the manager. Returns the STX-staker portion (after pox-5's
// reserve skim), which is the whole cycle when there is one staker.
function claimCycle(cycle: bigint, rewards: bigint): bigint {
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
  txOk(signerManagerV2.claimRewards([], cycle), deployer);
  return rewards - (rewards * pox5.constants.RESERVE_RATIO) / BASIS_POINTS;
}

// The bitcoin header hash at `height`. The sBTC `accept-withdrawal-request`
// fork check requires it to equal the burn header at the same height.
function burnHeader(height: bigint): Uint8Array {
  const result = simnet.execute(
    `(get-burn-block-info? header-hash u${height})`,
  );
  return hex.decode((result.result as any).value.value);
}

function acceptWithdrawal(requestId: bigint, fee: bigint) {
  const height = BigInt(simnet.burnBlockHeight - 1);
  txOk(
    sbtcWithdrawal.acceptWithdrawalRequest(
      requestId,
      new Uint8Array(32),
      0n,
      0n,
      fee,
      burnHeader(height),
      height,
      new Uint8Array(32),
    ),
    SBTC_SIGNER,
  );
}

function expectSolvent() {
  expect(sbtcBalance(signerManagerV2.identifier)).toBeGreaterThanOrEqual(
    rov(signerManagerV2.getReservedBalance()),
  );
}

test('claim-rewards reserves the cycle and snapshots the fee', () => {
  stake(alice);
  txOk(signerManagerV2.updateFees(500n), deployer);
  const total = claimCycle(1n, 2000n);
  expect(sbtcBalance(signerManagerV2.identifier)).toBe(total);
  expect(rov(signerManagerV2.getUnclaimedStakerRewardsForCycle(1n, null))).toBe(
    total,
  );
  expect(rov(signerManagerV2.getUnclaimedStakerRewards())).toBe(total);
  expect(rov(signerManagerV2.getFeeBipsForCycle(1n))).toBe(500n);
  // Everything in the vault is spoken for.
  expect(txErr(signerManagerV2.sweepFeeRefunds(deployer), deployer).value).toBe(
    signerManagerV2Errors.ERR_NO_REFUNDS,
  );
  expectSolvent();
});

test('settling credits pending net of the snapshotted fee', () => {
  stake(alice);
  txOk(signerManagerV2.updateFees(500n), deployer);
  const gross = claimCycle(1n, 2000n);
  const fee = (gross * 500n) / BASIS_POINTS;
  // A later fee change does not touch the already-pulled cycle.
  txOk(signerManagerV2.updateFees(9000n), deployer);

  expect(
    txOk(signerManagerV2.settleStakerRewards(alice, 1n, null), bob).value,
  ).toEqual({ gross, fee });
  expect(rov(signerManagerV2.getPendingPayout(alice))).toBe(gross - fee);
  expect(rov(signerManagerV2.getEarnedFees())).toBe(fee);
  expect(rov(signerManagerV2.getUnclaimedStakerRewardsForCycle(1n, null))).toBe(
    0n,
  );
  expect(rov(signerManagerV2.getUnclaimedStakerRewards())).toBe(0n);

  // Nothing left to settle for this cycle.
  expect(
    txErr(signerManagerV2.settleStakerRewards(alice, 1n, null), bob).value,
  ).toBe(signerManagerV2Errors.ERR_NO_CLAIMABLE_REWARDS);
  expectSolvent();
});

test('settling before the signer pulls the cycle has nothing to claim', () => {
  stake(alice);
  mineUntil(rov(pox5.rewardCycleToBurnHeight(1n)) + HALF_CYCLE_LENGTH);
  expect(
    txErr(signerManagerV2.settleStakerRewards(alice, 1n, null), bob).value,
  ).toBe(signerManagerV2Errors.ERR_NO_CLAIMABLE_REWARDS);
});

test('payout pays sBTC to the staker, or to their sbtc-recipient', () => {
  stake(alice);
  stake(bob, { l1Withdrawal: null, sbtcRecipient: charlie });
  const total = claimCycle(1n, 2000n);
  const each = total / 2n;

  txOk(signerManagerV2.settleStakerRewards(alice, 1n, null), alice);
  const aliceBefore = sbtcBalance(alice);
  expect(txOk(signerManagerV2.payout(alice), alice).value).toEqual({
    amount: each,
    withdrawalRequest: null,
  });
  expect(sbtcBalance(alice)).toBe(aliceBefore + each);
  expect(rov(signerManagerV2.getPendingPayout(alice))).toBe(0n);

  const charlieBefore = sbtcBalance(charlie);
  txOk(signerManagerV2.claimStakerRewards(bob, 1n, null), bob);
  expect(sbtcBalance(charlie)).toBe(charlieBefore + each);
  expectSolvent();
});

test('payout with nothing pending fails', () => {
  stake(alice);
  expect(txErr(signerManagerV2.payout(alice), alice).value).toBe(
    signerManagerV2Errors.ERR_INSUFFICIENT_PENDING,
  );
});

test('third parties must clear min-claim on L1 payouts, the staker need not', () => {
  stake(alice, randomPayoutConfig({ maxFee: 100n, minClaim: 5000n }));
  const total = claimCycle(1n, 2000n);
  txOk(signerManagerV2.settleStakerRewards(alice, 1n, null), bob);
  expect(total).toBeLessThan(5000n);
  expect(txErr(signerManagerV2.payout(alice), bob).value).toBe(
    signerManagerV2Errors.ERR_BELOW_MIN_CLAIM,
  );
  // The staker can trigger a payout below their third-party minimum.
  expect(txOk(signerManagerV2.payout(alice), alice).value).toEqual({
    amount: total,
    withdrawalRequest: 1n,
  });
});

test('claim-staker-rewards with an L1 config initiates a withdrawal', () => {
  const config = randomPayoutConfig({ maxFee: 100n, minClaim: 0n });
  stake(alice, config);
  const total = claimCycle(1n, 2000n);

  const result = txOk(
    signerManagerV2.claimStakerRewards(alice, 1n, null),
    bob,
  ).value;
  expect(result).toEqual({ earned: total, withdrawalRequest: 1n });
  expect(rov(signerManagerV2.getWithdrawalRequestStaker(1n))).toBe(alice);
  expect(rov(signerManagerV2.getWithdrawalLiability())).toBe(total);
  expect(rov(signerManagerV2.getPendingPayout(alice))).toBe(0n);
  // `amount + max-fee` is locked by the sBTC withdrawal system; it still
  // counts toward the contract's balance until the request is resolved.
  expect(sbtcBalance(signerManagerV2.identifier)).toBe(total);
  const request = rov(contracts.sbtcRegistry.getWithdrawalRequest(1n))!;
  expect(request.amount).toBe(total - 100n);
  expect(request.maxFee).toBe(100n);
  expect(request.sender).toBe(signerManagerV2.identifier);
  expectSolvent();
});

test('L1 payouts below max-fee plus dust are rejected up front', () => {
  stake(alice, randomPayoutConfig({ maxFee: 100n, minClaim: 0n }));
  // 700 * 85% = 595 <= 100 + 546.
  const total = claimCycle(1n, 700n);
  expect(total).toBeLessThanOrEqual(100n + DUST_LIMIT);
  txOk(signerManagerV2.settleStakerRewards(alice, 1n, null), alice);
  expect(txErr(signerManagerV2.payout(alice), alice).value).toBe(
    signerManagerV2Errors.ERR_BELOW_DUST_LIMIT,
  );
  // The balance is untouched and still pending.
  expect(rov(signerManagerV2.getPendingPayout(alice))).toBe(total);
});

test('sub-dust cycles accumulate in pending until one payout clears', () => {
  stake(alice, randomPayoutConfig({ maxFee: 100n, minClaim: 0n }));
  const first = claimCycle(1n, 700n);
  txOk(signerManagerV2.settleStakerRewards(alice, 1n, null), alice);
  const second = claimCycle(2n, 700n);
  expect(
    txOk(signerManagerV2.claimStakerRewards(alice, 2n, null), alice).value,
  ).toEqual({ earned: first + second, withdrawalRequest: 1n });
  expectSolvent();
});

test('a rejected withdrawal is credited back and retried in one call', () => {
  stake(alice, randomPayoutConfig({ maxFee: 100n, minClaim: 0n }));
  const total = claimCycle(1n, 2000n);
  txOk(signerManagerV2.claimStakerRewards(alice, 1n, null), bob);

  // Still pending: nothing to reclaim yet.
  expect(txErr(signerManagerV2.retryFailedWithdrawal(1n), bob).value).toBe(
    signerManagerV2Errors.ERR_WITHDRAWAL_NOT_REJECTED,
  );
  txOk(sbtcWithdrawal.rejectWithdrawalRequest(1n, 0n), SBTC_SIGNER);
  expect(sbtcBalance(signerManagerV2.identifier)).toBe(total);

  // Raise the fee budget, then retry: a new request with the new fee.
  txOk(
    signerManagerV2.setPayoutConfig({
      l1Withdrawal: {
        poxAddr: rov(signerManagerV2.getPayoutConfig(alice))!.l1Withdrawal!
          .poxAddr,
        maxFee: 300n,
        minClaim: 0n,
      },
      sbtcRecipient: null,
    }),
    alice,
  );
  expect(txOk(signerManagerV2.retryFailedWithdrawal(1n), bob).value).toEqual({
    amount: total,
    withdrawalRequest: 2n,
  });
  expect(rov(signerManagerV2.getWithdrawalRequestStaker(1n))).toBeNull();
  expect(rov(signerManagerV2.getWithdrawalRequestStaker(2n))).toBe(alice);
  expect(rov(signerManagerV2.getWithdrawalLiability())).toBe(total);
  expect(rov(contracts.sbtcRegistry.getWithdrawalRequest(2n))!.maxFee).toBe(
    300n,
  );
  // The old id is gone, so the retry cannot be replayed.
  expect(txErr(signerManagerV2.retryFailedWithdrawal(1n), bob).value).toBe(
    signerManagerV2Errors.ERR_UNKNOWN_WITHDRAWAL_REQUEST,
  );
  expectSolvent();
});

test('a rejected withdrawal can be taken as sBTC by clearing the config', () => {
  stake(alice, randomPayoutConfig({ maxFee: 100n, minClaim: 0n }));
  const total = claimCycle(1n, 2000n);
  txOk(signerManagerV2.claimStakerRewards(alice, 1n, null), bob);
  txOk(sbtcWithdrawal.rejectWithdrawalRequest(1n, 0n), SBTC_SIGNER);

  txOk(signerManagerV2.reclaimFailedWithdrawal(1n), bob);
  expect(rov(signerManagerV2.getPendingPayout(alice))).toBe(total);
  expect(rov(signerManagerV2.getWithdrawalLiability())).toBe(0n);

  txOk(signerManagerV2.clearPayoutConfig(), alice);
  const before = sbtcBalance(alice);
  expect(txOk(signerManagerV2.payout(alice), bob).value).toEqual({
    amount: total,
    withdrawalRequest: null,
  });
  expect(sbtcBalance(alice)).toBe(before + total);
  expectSolvent();
});

test('an accepted withdrawal is settled and its fee dust swept', () => {
  stake(alice, randomPayoutConfig({ maxFee: 100n, minClaim: 0n }));
  claimCycle(1n, 2000n);
  txOk(signerManagerV2.claimStakerRewards(alice, 1n, null), bob);
  acceptWithdrawal(1n, 30n);
  const dust = 100n - 30n;
  expect(sbtcBalance(signerManagerV2.identifier)).toBe(dust);

  // Until settled, the live liability keeps the dust unsweepable.
  expect(txErr(signerManagerV2.sweepFeeRefunds(deployer), deployer).value).toBe(
    signerManagerV2Errors.ERR_NO_REFUNDS,
  );
  expect(txErr(signerManagerV2.reclaimFailedWithdrawal(1n), bob).value).toBe(
    signerManagerV2Errors.ERR_WITHDRAWAL_NOT_REJECTED,
  );
  txOk(signerManagerV2.settleAcceptedWithdrawal(1n), bob);
  expect(rov(signerManagerV2.getWithdrawalLiability())).toBe(0n);
  expect(txOk(signerManagerV2.sweepFeeRefunds(deployer), deployer).value).toBe(
    dust,
  );
  expect(sbtcBalance(signerManagerV2.identifier)).toBe(0n);
});

test('admins withdraw fees, bounded by what has been charged', () => {
  stake(alice);
  txOk(signerManagerV2.updateFees(1000n), deployer);
  const gross = claimCycle(1n, 2000n);
  const fee = (gross * 1000n) / BASIS_POINTS;
  txOk(signerManagerV2.settleStakerRewards(alice, 1n, null), alice);

  expect(txErr(signerManagerV2.withdrawFees(fee, bob), alice).value).toBe(
    signerManagerV2Errors.ERR_UNAUTHORIZED_ADMIN,
  );
  expect(
    txErr(signerManagerV2.withdrawFees(fee + 1n, bob), deployer).value,
  ).toBe(signerManagerV2Errors.ERR_INSUFFICIENT_FEES);
  const before = sbtcBalance(bob);
  txOk(signerManagerV2.withdrawFees(fee, bob), deployer);
  expect(sbtcBalance(bob)).toBe(before + fee);
  expect(rov(signerManagerV2.getEarnedFees())).toBe(0n);
  // The staker's net is still fully covered.
  expect(sbtcBalance(signerManagerV2.identifier)).toBe(gross - fee);
  expectSolvent();
});

test('only admins can update fees, and fees must be below 100%', () => {
  expect(txErr(signerManagerV2.updateFees(100n), alice).value).toBe(
    signerManagerV2Errors.ERR_UNAUTHORIZED_ADMIN,
  );
  expect(txErr(signerManagerV2.updateFees(10000n), deployer).value).toBe(
    signerManagerV2Errors.ERR_INVALID_FEES_BIPS,
  );
  txOk(signerManagerV2.updateFees(9999n), deployer);
});

test('the max fee caps the fee rate and can only be lowered', () => {
  expect(rov(signerManagerV2.getMaxFeesBips())).toBe(BASIS_POINTS);
  expect(txErr(signerManagerV2.setMaxFees(500n), alice).value).toBe(
    signerManagerV2Errors.ERR_UNAUTHORIZED_ADMIN,
  );

  txOk(signerManagerV2.updateFees(800n), deployer);
  // The max cannot drop below the current fee rate.
  expect(txErr(signerManagerV2.setMaxFees(500n), deployer).value).toBe(
    signerManagerV2Errors.ERR_FEES_ABOVE_MAX,
  );
  txOk(signerManagerV2.updateFees(300n), deployer);
  txOk(signerManagerV2.setMaxFees(500n), deployer);
  expect(rov(signerManagerV2.getMaxFeesBips())).toBe(500n);

  expect(txErr(signerManagerV2.updateFees(501n), deployer).value).toBe(
    signerManagerV2Errors.ERR_FEES_ABOVE_MAX,
  );
  txOk(signerManagerV2.updateFees(500n), deployer);
  txOk(signerManagerV2.updateFees(0n), deployer);

  expect(txErr(signerManagerV2.setMaxFees(501n), deployer).value).toBe(
    signerManagerV2Errors.ERR_MAX_FEES_INCREASE,
  );
  txOk(signerManagerV2.setMaxFees(400n), deployer);
  expect(rov(signerManagerV2.getMaxFeesBips())).toBe(400n);
});
