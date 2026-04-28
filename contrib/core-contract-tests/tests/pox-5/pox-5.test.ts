import {
  CoreNodeEventType,
  err,
  extractErrors,
  isResponse,
  projectFactory,
} from '@clarigen/core';
import { accounts, project } from '../clarigen-types';
import { beforeEach, expect, test } from 'vitest';
import { filterEvents, rov, txErr, txOk } from '@clarigen/test';
import { randomSecretKey, stxToUStx } from '../test-helpers';
import { secp256k1 } from '@noble/curves/secp256k1.js';
import { createSignerKeyGrant, registerPool, testPool } from './pox-5-helpers';

const contracts = projectFactory(project, 'simnet');
const pox5 = contracts.pox5;

const pox5Errors = extractErrors(pox5);

const deployer = accounts.deployer.address;
const alice = accounts.wallet_1.address;
const bob = accounts.wallet_2.address;
const charlie = accounts.wallet_3.address;

// function sbtcBalance(address: string): bigint {
//   return rovOk(contracts.sbtcToken.getBalance(address));
// }

const REWARD_CYCLE_LENGTH = 100n;

beforeEach(() => {
  txOk(
    pox5.setBurnchainParameters({
      firstBurnHeight: 0n,
      prepareCycleLength: 10n,
      rewardCycleLength: REWARD_CYCLE_LENGTH,
      beginWfRewardCycle: 1n,
    }),
    deployer,
  );
});

test('all error codes are unique', () => {
  const used = new Set<bigint>();
  for (const error of Object.values(pox5Errors)) {
    if (!isResponse(error)) continue;
    if (used.has(error.value)) {
      throw new Error(`Error code ${error.value} is not unique`);
    }
    used.add(error.value);
  }
});

test('can calculate bond start height correctly', () => {
  expect(rov(pox5.bondPeriodToBurnHeight(0n))).toBe(
    rov(pox5.rewardCycleToBurnHeight(1n)),
  );
  expect(rov(pox5.bondPeriodToBurnHeight(1n))).toBe(
    rov(pox5.rewardCycleToBurnHeight(1n)) + REWARD_CYCLE_LENGTH * 2n,
  );
});

test('scenario - setting up and starting a bond', () => {
  const signerSk = randomSecretKey();
  const signerKey = secp256k1.getPublicKey(signerSk, true);
  createSignerKeyGrant({
    staker: alice,
    signerSk: signerSk,
    poxAddr: null,
    authId: 0n,
  });
  createSignerKeyGrant({
    staker: bob,
    signerSk: signerSk,
    poxAddr: null,
    authId: 0n,
  });

  const minUstxRatio = 1000n; // 10%
  const stxValueRatio = 100n; // 1 ustx = 1 sat
  txOk(
    pox5.setupBond({
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

  const allowance = rov(pox5.getBondAllowance(0n, alice));
  expect(allowance).toBe(100000000n);

  const sbtcAmount = 500n;

  const aliceRegister = txOk(
    pox5.registerForBond({
      bondIndex: 0n,
      poxAddr: null,
      signerSig: null,
      signerKey,
      maxAmount: 100000000n,
      authId: 0n,
      amountUstx: 100000000n,
      btcLockup: err(sbtcAmount),
    }),
    alice,
  );

  const aliceStakerInfo = rov(pox5.getStakerInfo(alice))!;
  expect(aliceStakerInfo).toEqual({
    numCycles: 12n,
    amountUstx: 100000000n,
    firstRewardCycle: 1n,
    signerKey,
  });

  const transferEvent = filterEvents(
    aliceRegister.events,
    CoreNodeEventType.FtTransferEvent,
  )[0]!;
  expect(transferEvent.data.recipient).toBe(pox5.identifier);
  expect(transferEvent.data.amount).toBe(sbtcAmount.toString());
  expect(transferEvent.data.sender).toBe(alice);

  // cannot register again
  const aliceRegisterErr = txErr(
    pox5.registerForBond({
      bondIndex: 0n,
      poxAddr: null,
      signerSig: null,
      signerKey,
      maxAmount: 100000000n,
      authId: 0n,
      amountUstx: 100000000n,
      btcLockup: err(sbtcAmount),
    }),
    alice,
  );
  expect(aliceRegisterErr.value).toEqual(pox5Errors.ERR_ALREADY_REGISTERED);

  const bobAllowance = rov(pox5.getBondAllowance(0n, bob));
  const stxMinAmount = (bobAllowance! * minUstxRatio) / 10000n;

  // must send enough STX
  // with 1 ustx = 1 sat and 10% min USTX ratio
  const bobRegisterStxErr = txErr(
    pox5.registerForBond({
      bondIndex: 0n,
      poxAddr: null,
      signerSig: null,
      signerKey,
      maxAmount: 100000000n,
      authId: 0n,
      amountUstx: stxMinAmount - 1n,
      btcLockup: err(bobAllowance!),
    }),
    bob,
  );
  expect(bobRegisterStxErr.value).toEqual(pox5Errors.ERR_INSUFFICIENT_STX);

  // cannot send more than allowance
  const bobRegisterSatsErr = txErr(
    pox5.registerForBond({
      bondIndex: 0n,
      poxAddr: null,
      signerSig: null,
      signerKey,
      maxAmount: 100000000n,
      authId: 0n,
      amountUstx: 100000000n,
      btcLockup: err(bobAllowance! + 1n),
    }),
    bob,
  );
  expect(bobRegisterSatsErr.value).toEqual(pox5Errors.ERR_TOO_MUCH_SATS);

  // bob can send exactly allowance and exactly the min stx
  const bobRegister = txOk(
    pox5.registerForBond({
      bondIndex: 0n,
      poxAddr: null,
      signerSig: null,
      signerKey,
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
  expect(bobRegisterEvent.data.recipient).toBe(pox5.identifier);
  expect(bobRegisterEvent.data.amount).toBe(bobAllowance!.toString());
  expect(bobRegisterEvent.data.sender).toBe(bob);
});

/**
 * Scenario: multiple users stake to a pool, ensuring that
 * the pool is only added to the signer set once the minimum
 * threshold is reached.
 *
 * - Register the pool
 * - Alice stakes 40k for 2 cycles
 * - Bob stakes 5k for 3 cycles
 * - Charlie stakes 5k STX for 2 cycles
 *
 * The pool should be added to signer sets 1 and 2, but not 3
 */
test('scenario - staking to a pool', () => {
  const admin = deployer;
  const pool = testPool.identifier;

  const aliceAmount = stxToUStx(40_000);
  const charlieAmount = stxToUStx(5_000);
  const bobAmount = stxToUStx(5_000);

  // sanity check that our amounts are exactly the minimum
  expect(aliceAmount + bobAmount + charlieAmount).toBe(
    pox5.constants.SIGNER_SET_MIN_USTX,
  );

  const { signerKey } = registerPool({ caller: admin });

  const poolInfo = rov(pox5.getPoolInfo(pool));
  expect(poolInfo).toEqual(signerKey);

  txOk(
    pox5.stake({
      poolOwner: pool,
      amountUstx: aliceAmount,
      numCycles: 2n,
      startBurnHt: 0n,
    }),
    alice,
  );
  // cannot stake again
  const aliceStakeErr = txErr(
    pox5.stake({
      poolOwner: pool,
      amountUstx: aliceAmount,
      numCycles: 2n,
      startBurnHt: 0n,
    }),
    alice,
  );
  expect(aliceStakeErr.value).toEqual(pox5Errors.ERR_ALREADY_POOLED);

  expect(
    rov(
      pox5.getCurrentAmountStakedForPool({
        pool,
        cycle: 1n,
      }),
    ),
  ).toBe(aliceAmount);
  expect(rov(pox5.getCurrentAmountStakedForPool({ pool, cycle: 2n }))).toBe(
    aliceAmount,
  );
  expect(rov(pox5.getPoolMembership(alice))).toEqual({
    amountUstx: aliceAmount,
    firstRewardCycle: 1n,
    numCycles: 2n,
    pool,
  });

  expect(
    rov(pox5.getStakerSetItemForCycle({ cycle: 1n, staker: pool })),
  ).toBeNull();
  expect(
    rov(pox5.getStakerSetItemForCycle({ cycle: 2n, staker: pool })),
  ).toBeNull();

  txOk(
    pox5.stake({
      poolOwner: pool,
      amountUstx: bobAmount,
      numCycles: 3n,
      startBurnHt: 0n,
    }),
    bob,
  );

  expect(rov(pox5.getCurrentAmountStakedForPool({ pool, cycle: 1n }))).toBe(
    aliceAmount + bobAmount,
  );
  expect(rov(pox5.getCurrentAmountStakedForPool({ pool, cycle: 2n }))).toBe(
    aliceAmount + bobAmount,
  );
  expect(rov(pox5.getCurrentAmountStakedForPool({ pool, cycle: 3n }))).toBe(
    bobAmount,
  );

  expect(rov(pox5.getPoolMembership(bob))).toEqual({
    amountUstx: bobAmount,
    firstRewardCycle: 1n,
    numCycles: 3n,
    pool,
  });

  expect(
    rov(pox5.getStakerSetItemForCycle({ cycle: 1n, staker: pool })),
  ).toBeNull();
  expect(
    rov(pox5.getStakerSetItemForCycle({ cycle: 2n, staker: pool })),
  ).toBeNull();
  expect(
    rov(pox5.getStakerSetItemForCycle({ cycle: 3n, staker: pool })),
  ).toBeNull();

  txOk(
    pox5.stake({
      poolOwner: pool,
      amountUstx: charlieAmount,
      numCycles: 2n,
      startBurnHt: 0n,
    }),
    charlie,
  );

  expect(rov(pox5.getCurrentAmountStakedForPool({ pool, cycle: 1n }))).toBe(
    aliceAmount + bobAmount + charlieAmount,
  );
  expect(rov(pox5.getCurrentAmountStakedForPool({ pool, cycle: 2n }))).toBe(
    aliceAmount + bobAmount + charlieAmount,
  );
  expect(rov(pox5.getCurrentAmountStakedForPool({ pool, cycle: 3n }))).toBe(
    charlieAmount,
  );

  expect(rov(pox5.getPoolMembership(charlie))).toEqual({
    amountUstx: charlieAmount,
    firstRewardCycle: 1n,
    numCycles: 2n,
    pool,
  });

  // finally, our pool should be in the signer set
  expect(
    rov(pox5.getStakerSetItemForCycle({ cycle: 1n, staker: pool })),
  ).toBeTruthy();
  expect(
    rov(pox5.getStakerSetItemForCycle({ cycle: 2n, staker: pool })),
  ).toBeTruthy();
  expect(
    rov(pox5.getStakerSetItemForCycle({ cycle: 3n, staker: pool })),
  ).toBeNull();
});
