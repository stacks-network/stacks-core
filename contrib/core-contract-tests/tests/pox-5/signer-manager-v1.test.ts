import {
  type ContractCallTyped,
  projectFactory,
  type Response,
} from '@clarigen/core';
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
  registerSignerManagerCore,
  sbtc,
  sbtcBalance,
  signerManagerCore,
  signerManagerCoreErrors,
  signerManagerV1,
  signerManagerV1Errors,
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

// Fund pox-5 with `rewards`, roll into `cycle`, crystallize and pull the
// signer's share into core. Returns the STX-staker portion (after pox-5's
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
  txOk(signerManagerV1.claimRewards([], cycle), deployer);
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
  expect(sbtcBalance(signerManagerCore.identifier)).toBeGreaterThanOrEqual(
    rov(signerManagerCore.getReservedBalance()),
  );
}

test('claim-rewards reserves the cycle in core and snapshots the fee', () => {
  stake(alice);
  txOk(signerManagerV1.updateFees(500n), deployer);
  const total = claimCycle(1n, 2000n);
  expect(sbtcBalance(signerManagerCore.identifier)).toBe(total);
  expect(rov(signerManagerCore.getRewardReserve(1n, null))).toBe(total);
  expect(rov(signerManagerV1.getFeeBipsForCycle(1n, null))).toBe(500n);
  // Everything in the vault is spoken for.
  expect(txErr(signerManagerV1.sweepFeeRefunds(deployer), deployer).value).toBe(
    signerManagerCoreErrors.ERR_NO_REFUNDS,
  );
  expectSolvent();
});

test('settling credits pending net of the snapshotted fee', () => {
  stake(alice);
  txOk(signerManagerV1.updateFees(500n), deployer);
  const gross = claimCycle(1n, 2000n);
  const fee = (gross * 500n) / BASIS_POINTS;
  // A later fee change does not touch the already-pulled cycle.
  txOk(signerManagerV1.updateFees(9000n), deployer);

  expect(
    txOk(signerManagerV1.settleStakerRewards(alice, 1n, null), bob).value,
  ).toEqual({ gross, fee });
  expect(rov(signerManagerCore.getPendingPayout(alice))).toBe(gross - fee);
  expect(rov(signerManagerCore.getEarnedFees())).toBe(fee);
  expect(rov(signerManagerCore.getRewardReserve(1n, null))).toBe(0n);

  // Nothing left to settle for this cycle.
  expect(
    txErr(signerManagerV1.settleStakerRewards(alice, 1n, null), bob).value,
  ).toBe(signerManagerCoreErrors.ERR_NO_CLAIMABLE_REWARDS);
  expectSolvent();
});

test('settling before the signer pulls the cycle has nothing to claim', () => {
  stake(alice);
  mineUntil(rov(pox5.rewardCycleToBurnHeight(1n)) + HALF_CYCLE_LENGTH);
  expect(
    txErr(signerManagerV1.settleStakerRewards(alice, 1n, null), bob).value,
  ).toBe(signerManagerCoreErrors.ERR_NO_CLAIMABLE_REWARDS);
});

test('payout pays sBTC to the staker, or to their sbtc-recipient', () => {
  stake(alice);
  stake(bob, { l1Withdrawal: null, sbtcRecipient: charlie });
  const total = claimCycle(1n, 2000n);
  const each = total / 2n;

  txOk(signerManagerV1.settleStakerRewards(alice, 1n, null), alice);
  const aliceBefore = sbtcBalance(alice);
  expect(txOk(signerManagerV1.payout(alice), alice).value).toEqual({
    amount: each,
    withdrawalRequest: null,
  });
  expect(sbtcBalance(alice)).toBe(aliceBefore + each);
  expect(rov(signerManagerCore.getPendingPayout(alice))).toBe(0n);

  const charlieBefore = sbtcBalance(charlie);
  txOk(signerManagerV1.claimStakerRewards(bob, 1n, null), bob);
  expect(sbtcBalance(charlie)).toBe(charlieBefore + each);
  expectSolvent();
});

test('payout with nothing pending fails', () => {
  stake(alice);
  expect(txErr(signerManagerV1.payout(alice), alice).value).toBe(
    signerManagerCoreErrors.ERR_INSUFFICIENT_PENDING,
  );
});

test('third parties must clear min-claim on L1 payouts, the staker need not', () => {
  stake(alice, randomPayoutConfig({ maxFee: 100n, minClaim: 5000n }));
  const total = claimCycle(1n, 2000n);
  txOk(signerManagerV1.settleStakerRewards(alice, 1n, null), bob);
  expect(total).toBeLessThan(5000n);
  expect(txErr(signerManagerV1.payout(alice), bob).value).toBe(
    signerManagerCoreErrors.ERR_BELOW_MIN_CLAIM,
  );
  // `tx-sender` survives the module hop, so core knows it is the staker.
  expect(txOk(signerManagerV1.payout(alice), alice).value).toEqual({
    amount: total,
    withdrawalRequest: 1n,
  });
});

test('claim-staker-rewards with an L1 config initiates a withdrawal', () => {
  const config = randomPayoutConfig({ maxFee: 100n, minClaim: 0n });
  stake(alice, config);
  const total = claimCycle(1n, 2000n);

  const result = txOk(
    signerManagerV1.claimStakerRewards(alice, 1n, null),
    bob,
  ).value;
  expect(result).toEqual({ earned: total, withdrawalRequest: 1n });
  expect(rov(signerManagerCore.getWithdrawalRequestStaker(1n))).toBe(alice);
  expect(rov(signerManagerCore.getWithdrawalLiability())).toBe(total);
  expect(rov(signerManagerCore.getPendingPayout(alice))).toBe(0n);
  // `amount + max-fee` is locked by the sBTC withdrawal system; it still
  // counts toward the contract's balance until the request is resolved.
  expect(sbtcBalance(signerManagerCore.identifier)).toBe(total);
  const request = rov(contracts.sbtcRegistry.getWithdrawalRequest(1n))!;
  expect(request.amount).toBe(total - 100n);
  expect(request.maxFee).toBe(100n);
  expect(request.sender).toBe(signerManagerCore.identifier);
  expectSolvent();
});

test('L1 payouts below max-fee plus dust are rejected up front', () => {
  stake(alice, randomPayoutConfig({ maxFee: 100n, minClaim: 0n }));
  // 700 * 85% = 595 <= 100 + 546.
  const total = claimCycle(1n, 700n);
  expect(total).toBeLessThanOrEqual(100n + DUST_LIMIT);
  txOk(signerManagerV1.settleStakerRewards(alice, 1n, null), alice);
  expect(txErr(signerManagerV1.payout(alice), alice).value).toBe(
    signerManagerCoreErrors.ERR_BELOW_DUST_LIMIT,
  );
  // The balance is untouched and still pending.
  expect(rov(signerManagerCore.getPendingPayout(alice))).toBe(total);
});

test('sub-dust cycles accumulate in pending until one payout clears', () => {
  stake(alice, randomPayoutConfig({ maxFee: 100n, minClaim: 0n }));
  const first = claimCycle(1n, 700n);
  txOk(signerManagerV1.settleStakerRewards(alice, 1n, null), alice);
  const second = claimCycle(2n, 700n);
  expect(
    txOk(signerManagerV1.claimStakerRewards(alice, 2n, null), alice).value,
  ).toEqual({ earned: first + second, withdrawalRequest: 1n });
  expectSolvent();
});

test('a rejected withdrawal is credited back and retried in one call', () => {
  stake(alice, randomPayoutConfig({ maxFee: 100n, minClaim: 0n }));
  const total = claimCycle(1n, 2000n);
  txOk(signerManagerV1.claimStakerRewards(alice, 1n, null), bob);

  // Still pending: nothing to reclaim yet.
  expect(txErr(signerManagerV1.retryFailedWithdrawal(1n), bob).value).toBe(
    signerManagerCoreErrors.ERR_WITHDRAWAL_NOT_REJECTED,
  );
  txOk(sbtcWithdrawal.rejectWithdrawalRequest(1n, 0n), SBTC_SIGNER);
  expect(sbtcBalance(signerManagerCore.identifier)).toBe(total);

  // Raise the fee budget, then retry: a new request with the new fee.
  txOk(
    signerManagerV1.setPayoutConfig({
      l1Withdrawal: {
        poxAddr: rov(signerManagerCore.getPayoutConfig(alice))!.l1Withdrawal!
          .poxAddr,
        maxFee: 300n,
        minClaim: 0n,
      },
      sbtcRecipient: null,
    }),
    alice,
  );
  expect(txOk(signerManagerV1.retryFailedWithdrawal(1n), bob).value).toEqual({
    amount: total,
    withdrawalRequest: 2n,
  });
  expect(rov(signerManagerCore.getWithdrawalRequestStaker(1n))).toBeNull();
  expect(rov(signerManagerCore.getWithdrawalRequestStaker(2n))).toBe(alice);
  expect(rov(signerManagerCore.getWithdrawalLiability())).toBe(total);
  expect(rov(contracts.sbtcRegistry.getWithdrawalRequest(2n))!.maxFee).toBe(
    300n,
  );
  // The old id is gone, so the retry cannot be replayed.
  expect(txErr(signerManagerV1.retryFailedWithdrawal(1n), bob).value).toBe(
    signerManagerV1Errors.ERR_UNKNOWN_WITHDRAWAL_REQUEST,
  );
  expectSolvent();
});

test('a rejected withdrawal can be taken as sBTC by clearing the config', () => {
  stake(alice, randomPayoutConfig({ maxFee: 100n, minClaim: 0n }));
  const total = claimCycle(1n, 2000n);
  txOk(signerManagerV1.claimStakerRewards(alice, 1n, null), bob);
  txOk(sbtcWithdrawal.rejectWithdrawalRequest(1n, 0n), SBTC_SIGNER);

  txOk(signerManagerV1.reclaimFailedWithdrawal(1n), bob);
  expect(rov(signerManagerCore.getPendingPayout(alice))).toBe(total);
  expect(rov(signerManagerCore.getWithdrawalLiability())).toBe(0n);

  txOk(signerManagerV1.clearPayoutConfig(), alice);
  const before = sbtcBalance(alice);
  expect(txOk(signerManagerV1.payout(alice), bob).value).toEqual({
    amount: total,
    withdrawalRequest: null,
  });
  expect(sbtcBalance(alice)).toBe(before + total);
  expectSolvent();
});

test('an accepted withdrawal is settled and its fee dust swept', () => {
  stake(alice, randomPayoutConfig({ maxFee: 100n, minClaim: 0n }));
  claimCycle(1n, 2000n);
  txOk(signerManagerV1.claimStakerRewards(alice, 1n, null), bob);
  acceptWithdrawal(1n, 30n);
  const dust = 100n - 30n;
  expect(sbtcBalance(signerManagerCore.identifier)).toBe(dust);

  // Until settled, the live liability keeps the dust unsweepable.
  expect(txErr(signerManagerV1.sweepFeeRefunds(deployer), deployer).value).toBe(
    signerManagerCoreErrors.ERR_NO_REFUNDS,
  );
  expect(txErr(signerManagerV1.reclaimFailedWithdrawal(1n), bob).value).toBe(
    signerManagerCoreErrors.ERR_WITHDRAWAL_NOT_REJECTED,
  );
  txOk(signerManagerV1.settleAcceptedWithdrawal(1n), bob);
  expect(rov(signerManagerCore.getWithdrawalLiability())).toBe(0n);
  expect(txOk(signerManagerV1.sweepFeeRefunds(deployer), deployer).value).toBe(
    dust,
  );
  expect(sbtcBalance(signerManagerCore.identifier)).toBe(0n);
});

test('admins withdraw fees, bounded by what has been charged', () => {
  stake(alice);
  txOk(signerManagerV1.updateFees(1000n), deployer);
  const gross = claimCycle(1n, 2000n);
  const fee = (gross * 1000n) / BASIS_POINTS;
  txOk(signerManagerV1.settleStakerRewards(alice, 1n, null), alice);

  expect(txErr(signerManagerV1.withdrawFees(fee, bob), alice).value).toBe(
    signerManagerV1Errors.ERR_UNAUTHORIZED_ADMIN,
  );
  expect(
    txErr(signerManagerV1.withdrawFees(fee + 1n, bob), deployer).value,
  ).toBe(signerManagerCoreErrors.ERR_INSUFFICIENT_FEES);
  const before = sbtcBalance(bob);
  txOk(signerManagerV1.withdrawFees(fee, bob), deployer);
  expect(sbtcBalance(bob)).toBe(before + fee);
  expect(rov(signerManagerCore.getEarnedFees())).toBe(0n);
  // The staker's net is still fully covered.
  expect(sbtcBalance(signerManagerCore.identifier)).toBe(gross - fee);
  expectSolvent();
});

test('only admins can update fees, and fees must be below 100%', () => {
  expect(txErr(signerManagerV1.updateFees(100n), alice).value).toBe(
    signerManagerV1Errors.ERR_UNAUTHORIZED_ADMIN,
  );
  expect(txErr(signerManagerV1.updateFees(10000n), deployer).value).toBe(
    signerManagerV1Errors.ERR_INVALID_FEES_BIPS,
  );
  txOk(signerManagerV1.updateFees(9999n), deployer);
  expect(rov(signerManagerV1.getFeesBips())).toBe(9999n);
});

test('core functions cannot be called around the module', () => {
  stake(alice);
  claimCycle(1n, 2000n);
  txOk(signerManagerV1.settleStakerRewards(alice, 1n, null), alice);
  const pending = rov(signerManagerCore.getPendingPayout(alice));
  const calls: ContractCallTyped<any, Response<any, bigint>>[] = [
    signerManagerCore.settleStakerRewards(alice, 1n, null),
    signerManagerCore.chargeFee(alice, 1n),
    signerManagerCore.payout(alice, pending),
    signerManagerCore.withdrawFees(1n, alice),
    signerManagerCore.sweepFeeRefunds(alice),
    signerManagerCore.claimRewards([], 2n),
  ];
  for (const call of calls) {
    expect(txErr(call, alice).value).toBe(
      signerManagerCoreErrors.ERR_UNAUTHORIZED_MODULE,
    );
  }
  expect(rov(signerManagerCore.getPendingPayout(alice))).toBe(pending);
});
