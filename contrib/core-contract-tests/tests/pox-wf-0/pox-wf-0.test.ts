import {
  CoreNodeEventType,
  err,
  extractErrors,
  projectFactory,
} from '@clarigen/core';
import { accounts, project } from '../clarigen-types';
import { beforeEach, expect, test } from 'vitest';
import { filterEvents, rov, rovOk, txErr, txOk } from '@clarigen/test';

const contracts = projectFactory(project, 'simnet');
const wf = contracts.poxWaterfall0;

const wfErrors = extractErrors(wf);

const deployer = accounts.deployer.address;
const alice = accounts.wallet_1.address;
const bob = accounts.wallet_2.address;

function sbtcBalance(address: string): bigint {
  return rovOk(contracts.sbtcToken.getBalance(address));
}

const REWARD_CYCLE_LENGTH = 100n;

beforeEach(() => {
  txOk(
    wf.setBurnchainParameters({
      firstBurnHeight: 0n,
      prepareCycleLength: 10n,
      rewardCycleLength: REWARD_CYCLE_LENGTH,
      beginWfRewardCycle: 1n,
    }),
    deployer,
  );
});

test('can calculate bond start height correctly', () => {
  expect(rov(wf.bondPeriodToBurnHeight(0n))).toBe(
    rov(wf.rewardCycleToBurnHeight(1n)),
  );
  expect(rov(wf.bondPeriodToBurnHeight(1n))).toBe(
    rov(wf.rewardCycleToBurnHeight(1n)) + REWARD_CYCLE_LENGTH * 2n,
  );
});

test('scenario - setting up and starting a bond', () => {
  const minUstxRatio = 1000n; // 10%
  const stxValueRatio = 1000n; // 1 ustx = 1 sat
  txOk(
    wf.setupBond({
      bondIndex: 0n,
      targetRate: 300n,
      stxValueRatio,
      minUstxRatio,
      earlyUnlockSigners: new Uint8Array(),
      allowlist: [
        {
          maxSats: 100000000n,
          staker: alice,
        },
        {
          maxSats: 100000000n,
          staker: bob,
        },
      ],
    }),
    deployer,
  );

  const allowance = rov(wf.getBondAllowance(0n, alice));
  expect(allowance).toBe(100000000n);

  const sbtcAmount = 500n;

  const aliceRegister = txOk(
    wf.registerForBond({
      bondIndex: 0n,
      poxAddr: null,
      signerSig: null,
      signerKey: new Uint8Array(),
      maxAmount: 100000000n,
      authId: 0n,
      amountUstx: 100000000n,
      btcLockup: err(sbtcAmount),
    }),
    alice,
  );

  const transferEvent = filterEvents(
    aliceRegister.events,
    CoreNodeEventType.FtTransferEvent,
  )[0]!;
  expect(transferEvent.data.recipient).toBe(wf.identifier);
  expect(transferEvent.data.amount).toBe(sbtcAmount.toString());
  expect(transferEvent.data.sender).toBe(alice);

  // cannot register again
  const aliceRegisterErr = txErr(
    wf.registerForBond({
      bondIndex: 0n,
      poxAddr: null,
      signerSig: null,
      signerKey: new Uint8Array(),
      maxAmount: 100000000n,
      authId: 0n,
      amountUstx: 100000000n,
      btcLockup: err(sbtcAmount),
    }),
    alice,
  );
  expect(aliceRegisterErr.value).toEqual(wfErrors.ERR_ALREADY_REGISTERED);

  const bobAllowance = rov(wf.getBondAllowance(0n, bob));
  const stxMinAmount = (bobAllowance! * minUstxRatio) / 10000n;

  // must send enough STX
  // with 1 ustx = 1 sat and 10% min USTX ratio
  const bobRegisterStxErr = txErr(
    wf.registerForBond({
      bondIndex: 0n,
      poxAddr: null,
      signerSig: null,
      signerKey: new Uint8Array(),
      maxAmount: 100000000n,
      authId: 0n,
      amountUstx: stxMinAmount - 1n,
      btcLockup: err(bobAllowance!),
    }),
    bob,
  );
  expect(bobRegisterStxErr.value).toEqual(wfErrors.ERR_INSUFFICIENT_STX);

  // cannot send more than allowance
  const bobRegisterSatsErr = txErr(
    wf.registerForBond({
      bondIndex: 0n,
      poxAddr: null,
      signerSig: null,
      signerKey: new Uint8Array(),
      maxAmount: 100000000n,
      authId: 0n,
      amountUstx: 100000000n,
      btcLockup: err(bobAllowance! + 1n),
    }),
    bob,
  );
  expect(bobRegisterSatsErr.value).toEqual(wfErrors.ERR_TOO_MUCH_SATS);

  // bob can send exactly allowance and exactly the min stx
  const bobRegister = txOk(
    wf.registerForBond({
      bondIndex: 0n,
      poxAddr: null,
      signerSig: null,
      signerKey: new Uint8Array(),
      maxAmount: 100000000n,
      authId: 0n,
      amountUstx: stxMinAmount,
      btcLockup: err(bobAllowance!),
    }),
    bob,
  );

  const bobRegisterEvent = filterEvents(
    bobRegister.events,
    CoreNodeEventType.FtTransferEvent,
  )[0]!;
  expect(bobRegisterEvent.data.recipient).toBe(wf.identifier);
  expect(bobRegisterEvent.data.amount).toBe(bobAllowance!.toString());
  expect(bobRegisterEvent.data.sender).toBe(bob);
});
