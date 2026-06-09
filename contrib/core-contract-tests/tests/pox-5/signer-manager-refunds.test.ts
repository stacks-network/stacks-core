import { beforeEach, expect, test } from 'vitest';
import {
  signerManager,
  signerManagerErrors,
  pox5,
  sbtc,
  sbtcBalance,
  initPox5,
  registerSignerManager,
  BASIS_POINTS,
  HALF_CYCLE_LENGTH,
  makePoxAddrCalldata,
} from './pox-5-helpers';
import { rov, txErr, txOk } from '@clarigen/test';
import { projectFactory } from '@clarigen/core';
import { hex } from '@scure/base';
import { accounts, project } from '../clarigen-types';
import { mineUntil, stxToUStx } from '../test-helpers';

// Regression tests for POX5-M04: L1 withdrawal fee refunds were not returned to
// stakers. A staker's pox-5 balance is zeroed the moment `claim-staker-rewards`
// initiates the sBTC withdrawal, but because the signer-manager contract is the
// withdrawal's requester, any sBTC the sBTC protocol returns lands on the
// contract, not the staker. The fix adds:
//   * `reclaim-failed-withdrawal` (permissionless) -- pays a REJECTED
//     withdrawal's full `amount + max-fee` back to the mapped staker.
//   * `settle-accepted-withdrawal` (permissionless) -- retires an ACCEPTED
//     withdrawal's liability so its unused-fee dust becomes sweepable.
//   * `sweep-fee-refunds` (admin-gated) -- recovers the accept-case dust.
//
// These drive the full accept/reject path against the real sBTC protocol-role
// functions. The sBTC `current-signer-principal` (which alone may accept/reject
// a withdrawal) defaults to the sBTC deployer, so those calls are sent as it.

const contracts = projectFactory(project, 'simnet');
const sbtcWithdrawal = contracts.sbtcWithdrawal;

// The principal allowed to accept/reject sBTC withdrawals: the sBTC registry's
// `current-signer-principal`, which defaults to the sBTC deployer.
const SBTC_SIGNER = 'SM3VDXK3WZZSA84XXFKAFAF15NNZX32CTSG82JFQ4';

const deployer = accounts.deployer.address;
const alice = accounts.wallet_1.address;
const bob = accounts.wallet_2.address;

beforeEach(() => {
  initPox5();
  registerSignerManager();
});

// Stake `alice` (and nobody else, so all rewards are hers) with an L1 pox-addr,
// then crystallize and claim. The claim initiates withdrawal request id 1 of
// `earned - max-fee` (amount) plus `max-fee`. Returns `earned`.
function stakeAndClaimWithPoxAddr(maxFee: bigint): bigint {
  const rewards = 2000n;
  const earned =
    rewards - (rewards * pox5.constants.RESERVE_RATIO) / BASIS_POINTS;
  const calldata = makePoxAddrCalldata({ maxFee }).calldata;
  txOk(
    pox5.stake({
      signerManager: signerManager.identifier,
      amountUstx: stxToUStx(50_000),
      numCycles: 2n,
      startBurnHt: simnet.burnBlockHeight,
      signerCalldata: calldata,
    }),
    alice,
  );
  txOk(
    sbtc.transfer({
      recipient: pox5.identifier,
      amount: rewards,
      sender: deployer,
      memo: null,
    }),
    deployer,
  );
  mineUntil(rov(pox5.rewardCycleToBurnHeight(1n)) + HALF_CYCLE_LENGTH);
  txOk(pox5.calculateRewards([]), deployer);
  txOk(signerManager.claimRewards([], 1n), deployer);
  txOk(signerManager.claimStakerRewards(alice, 1n, null), bob);

  return earned;
}

// The bitcoin header hash at `height`. The sBTC `accept-withdrawal-request`
// fork check requires it to equal the burn header at the same height.
function burnHeader(height: bigint): Uint8Array {
  const result = simnet.execute(
    `(get-burn-block-info? header-hash u${height})`,
  );
  return hex.decode((result.result as any).value.value);
}

test('reclaim-failed-withdrawal returns the full amount to a rejected staker', () => {
  const maxFee = 100n;
  const earned = stakeAndClaimWithPoxAddr(maxFee);

  // The withdrawal moved `earned` (amount + max-fee) out of the contract.
  expect(rov(signerManager.getWithdrawalLiability())).toBe(earned);
  expect(rov(signerManager.getWithdrawalRequestStaker(1n))).toBe(alice);

  // While the request is pending, the full amount is not yet reclaimable.
  expect(txErr(signerManager.reclaimFailedWithdrawal(1n), bob).value).toBe(
    signerManagerErrors.ERR_WITHDRAWAL_NOT_REJECTED,
  );

  // The sBTC signers reject the withdrawal, re-minting `amount + max-fee` to the
  // contract (the requester).
  txOk(sbtcWithdrawal.rejectWithdrawalRequest(1n, 0n), SBTC_SIGNER);

  // Anyone may trigger the reclaim; it pays the full amount to the staker.
  const aliceBalance = sbtcBalance(alice);
  txOk(signerManager.reclaimFailedWithdrawal(1n), bob);
  expect(sbtcBalance(alice)).toBe(aliceBalance + earned);
  expect(rov(signerManager.getWithdrawalLiability())).toBe(0n);

  // The entry is deleted, so the reclaim cannot be replayed.
  expect(txErr(signerManager.reclaimFailedWithdrawal(1n), bob).value).toBe(
    signerManagerErrors.ERR_UNKNOWN_WITHDRAWAL_REQUEST,
  );
});

test('settle-accepted-withdrawal frees the dust for sweeping', () => {
  const maxFee = 100n;
  const actualFee = 30n;
  const dust = maxFee - actualFee;
  stakeAndClaimWithPoxAddr(maxFee);

  // Accept the withdrawal: the sBTC signers pay the staker on L1 and mint only
  // the unused fee budget (`max-fee - fee`) back to the contract as dust.
  const height = BigInt(simnet.burnBlockHeight - 1);
  txOk(
    sbtcWithdrawal.acceptWithdrawalRequest(
      1n,
      new Uint8Array(32),
      0n,
      0n,
      actualFee,
      burnHeader(height),
      height,
      new Uint8Array(32),
    ),
    SBTC_SIGNER,
  );
  expect(sbtcBalance(signerManager.identifier)).toBe(dust);

  // Until the request is settled its liability suppresses the sweepable amount,
  // so even the dust cannot be swept.
  expect(txErr(signerManager.sweepFeeRefunds(deployer), deployer).value).toBe(
    signerManagerErrors.ERR_NO_REFUNDS,
  );

  // Settling releases the liability; nothing is owed to the staker.
  txOk(signerManager.settleAcceptedWithdrawal(1n), bob);
  expect(rov(signerManager.getWithdrawalLiability())).toBe(0n);

  // Now an admin can sweep the dust; the full sweepable amount is taken.
  const deployerBalance = sbtcBalance(deployer);
  expect(txOk(signerManager.sweepFeeRefunds(deployer), deployer).value).toBe(
    dust,
  );
  expect(sbtcBalance(deployer)).toBe(deployerBalance + dust);
  expect(sbtcBalance(signerManager.identifier)).toBe(0n);

  // The entry is deleted, so the settle cannot be replayed.
  expect(txErr(signerManager.settleAcceptedWithdrawal(1n), bob).value).toBe(
    signerManagerErrors.ERR_UNKNOWN_WITHDRAWAL_REQUEST,
  );
});

test('settle-accepted-withdrawal rejects a still-pending request', () => {
  stakeAndClaimWithPoxAddr(100n);
  expect(txErr(signerManager.settleAcceptedWithdrawal(1n), bob).value).toBe(
    signerManagerErrors.ERR_WITHDRAWAL_NOT_ACCEPTED,
  );
});

test('reclaim-failed-withdrawal rejects an unknown request id', () => {
  // No withdrawal has been initiated, so request id 999 is untracked.
  expect(txErr(signerManager.reclaimFailedWithdrawal(999n), alice).value).toBe(
    signerManagerErrors.ERR_UNKNOWN_WITHDRAWAL_REQUEST,
  );
});

test('settle-accepted-withdrawal rejects an unknown request id', () => {
  // No withdrawal has been initiated, so request id 999 is untracked.
  expect(txErr(signerManager.settleAcceptedWithdrawal(999n), alice).value).toBe(
    signerManagerErrors.ERR_UNKNOWN_WITHDRAWAL_REQUEST,
  );
});

test('sweep-fee-refunds is admin-gated', () => {
  // alice is not an admin (only the deployer is, by default).
  expect(txErr(signerManager.sweepFeeRefunds(alice), alice).value).toBe(
    signerManagerErrors.ERR_UNAUTHORIZED_ADMIN,
  );
});

test('sweep-fee-refunds rejects when there is nothing to sweep', () => {
  // With a fresh contract the sBTC balance is 0 and no fees are accrued, so the
  // sweepable amount is 0 and the sweep must be rejected.
  expect(txErr(signerManager.sweepFeeRefunds(deployer), deployer).value).toBe(
    signerManagerErrors.ERR_NO_REFUNDS,
  );
});

test('sweep-fee-refunds cannot sweep unclaimed staker rewards', () => {
  // `claim-rewards` pulls the sBTC for ALL of the signer's stakers into this
  // contract at once; each staker is paid out later via `claim-staker-rewards`.
  // Between those steps a plain (no pox-addr) staker's rewards sit in the
  // balance with no offsetting `earned-fees` or `withdrawal-liability` entry, so
  // they must NOT be sweepable -- otherwise an admin can drain staker principal.
  const rewards = 2000n;
  const earned =
    rewards - (rewards * pox5.constants.RESERVE_RATIO) / BASIS_POINTS;

  // Alice stakes WITHOUT a pox-addr, so she is owed sBTC directly.
  txOk(
    pox5.stake({
      signerManager: signerManager.identifier,
      amountUstx: stxToUStx(50_000),
      numCycles: 2n,
      startBurnHt: simnet.burnBlockHeight,
      signerCalldata: null,
    }),
    alice,
  );
  txOk(
    sbtc.transfer({
      recipient: pox5.identifier,
      amount: rewards,
      sender: deployer,
      memo: null,
    }),
    deployer,
  );
  mineUntil(rov(pox5.rewardCycleToBurnHeight(1n)) + HALF_CYCLE_LENGTH);
  txOk(pox5.calculateRewards([]), deployer);
  txOk(signerManager.claimRewards([], 1n), deployer);

  // Alice's full reward is now in the contract, unclaimed. The admin must not be
  // able to sweep any of it to a recipient of their choosing.
  expect(txErr(signerManager.sweepFeeRefunds(bob), deployer).value).toBe(
    signerManagerErrors.ERR_NO_REFUNDS,
  );

  // Alice can still claim her rewards in full.
  const aliceBalance = sbtcBalance(alice);
  txOk(signerManager.claimStakerRewards(alice, 1n, null), alice);
  expect(sbtcBalance(alice)).toBe(aliceBalance + earned);
});
