import { beforeEach, expect, test } from 'vitest';
import { rov, txErr, txOk } from '@clarigen/test';
import { accounts } from '../clarigen-types';
import { mineUntil, stxToUStx } from '../test-helpers';
import {
  errorCodes,
  initPox5,
  pox5,
  registerSigner,
  sbtc,
  sbtcBalance,
  testSigner,
} from './pox-5-helpers';

const deployer = accounts.deployer.address;
const alice = accounts.wallet_1.address;
const bob = accounts.wallet_2.address;

beforeEach(() => {
  initPox5();
});

test('only the pause admin can change the admin or pause rewards', () => {
  expect(txErr(pox5.setPauseAdmin(bob), alice).value).toBe(
    errorCodes.ERR_UNAUTHORIZED,
  );
  expect(txErr(pox5.pauseRewards(), alice).value).toBe(
    errorCodes.ERR_UNAUTHORIZED,
  );
});

test('pause admin can transfer authority', () => {
  expect(txOk(pox5.setPauseAdmin(alice), deployer).value).toEqual({
    oldAdmin: deployer,
    newAdmin: alice,
  });
  expect(txErr(pox5.pauseRewards(), deployer).value).toBe(
    errorCodes.ERR_UNAUTHORIZED,
  );
  expect(txOk(pox5.pauseRewards(), alice).value).toBe(true);
  expect(txOk(pox5.pauseRewards(), alice).value).toBe(true);
});

test('paused rewards cannot be claimed', () => {
  const signer = testSigner.identifier;
  const stakeAmount = stxToUStx(50_000);

  registerSigner();
  txOk(
    pox5.stake({
      signerManager: signer,
      amountUstx: stakeAmount,
      numCycles: 2n,
      startBurnHt: simnet.burnBlockHeight,
      signerCalldata: null,
    }),
    alice,
  );
  txOk(
    sbtc.transfer({
      recipient: pox5.identifier,
      amount: 1000n,
      sender: deployer,
      memo: null,
    }),
    deployer,
  );

  mineUntil(rov(pox5.rewardCycleToBurnHeight(1n)) + 50n);
  txOk(pox5.calculateRewards([]), deployer);

  const earned = rov(pox5.getEarned(signer, 1n, null));
  const poxBalance = sbtcBalance(pox5.identifier);
  const signerBalance = sbtcBalance(signer);

  txOk(pox5.pauseRewards(), deployer);

  expect(txErr(testSigner.claimRewards([], 1n), deployer).value).toBe(
    errorCodes.ERR_REWARDS_PAUSED,
  );
  expect(rov(pox5.getEarned(signer, 1n, null))).toBe(earned);
  expect(sbtcBalance(pox5.identifier)).toBe(poxBalance);
  expect(sbtcBalance(signer)).toBe(signerBalance);
});
