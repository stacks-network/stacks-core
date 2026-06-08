import { beforeEach, expect, test } from 'vitest';
import {
  signerManager,
  signerManagerErrors,
  initPox5,
  registerSignerManager,
} from './pox-5-helpers';
import { txErr } from '@clarigen/test';
import { accounts } from '../clarigen-types';

// Regression tests for POX5-M04: L1 withdrawal fee refunds were not returned
// to stakers. The fix adds `reclaim-failed-withdrawal` (permissionless, returns
// a rejected withdrawal's full amount to the mapped staker) and an admin-gated
// `sweep-fee-refunds` (recovers the unattributable accept-case fee dust).
//
// These cover the guard logic. The full accept/reject end-to-end path requires
// driving the sBTC protocol-role functions (complete/reject-withdrawal-request)
// in simnet, which the suite does not yet set up.

const deployer = accounts.deployer.address;
const alice = accounts.wallet_1.address;

beforeEach(() => {
  initPox5();
  registerSignerManager();
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
  expect(txErr(signerManager.sweepFeeRefunds(0n, alice), alice).value).toBe(
    signerManagerErrors.ERR_UNAUTHORIZED_ADMIN,
  );
});

test('sweep-fee-refunds caps the amount at the non-fee sBTC balance', () => {
  // With a fresh contract the sBTC balance is 0 and no fees are accrued, so the
  // sweepable amount is 0; any positive sweep must be rejected.
  expect(
    txErr(signerManager.sweepFeeRefunds(1n, deployer), deployer).value,
  ).toBe(signerManagerErrors.ERR_INVALID_SWEEP_AMOUNT);
});
