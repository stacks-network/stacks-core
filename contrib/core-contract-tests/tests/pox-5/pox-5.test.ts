import {
  CoreNodeEventType,
  err,
  extractErrors,
  isResponse,
  projectFactory,
  ok,
} from '@clarigen/core';
import { accounts, project } from '../clarigen-types';
import { beforeEach, expect, test } from 'vitest';
import { filterEvents, rov, txErr, txOk } from '@clarigen/test';
import { mineUntil, randomSecretKey, stxToUStx } from '../test-helpers';
import { secp256k1 } from '@noble/curves/secp256k1.js';
import {
  createSignerKeyGrant,
  deployTestPool,
  expectAllSignersHaveKeys,
  getAllStakers,
  isStakerInCycle,
  registerPool,
  setupSigner,
  testPool,
} from './pox-5-helpers';
import { randomBytes } from '@stacks/transactions';

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
      beginPox5RewardCycle: 1n,
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

  const aliceInfo = rov(pox5.getBondMembership(alice))!;
  expect(aliceInfo).toEqual({
    amountSats: 500n,
    amountUstx: 100000000n,
    bondIndex: 0n,
    poxAddr: null,
    rewardPerSharePaid: 0n,
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

  expect(getAllStakers().length).toBe(2);
  expectAllSignersHaveKeys();
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
      poolOrSignerKey: ok(pool),
      amountUstx: aliceAmount,
      numCycles: 2n,
      startBurnHt: simnet.burnBlockHeight,
    }),
    alice,
  );
  // cannot stake again
  const aliceStakeErr = txErr(
    pox5.stake({
      poolOrSignerKey: ok(pool),
      amountUstx: aliceAmount,
      numCycles: 2n,
      startBurnHt: simnet.burnBlockHeight,
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
  expect(rov(pox5.getStakerInfo(alice))).toEqual({
    amountUstx: aliceAmount,
    firstRewardCycle: 1n,
    numCycles: 2n,
  });

  expect(isStakerInCycle({ staker: pool, cycle: 1n })).toBeFalsy();
  expect(isStakerInCycle({ staker: pool, cycle: 2n })).toBeFalsy();

  txOk(
    pox5.stake({
      poolOrSignerKey: ok(pool),
      amountUstx: bobAmount,
      numCycles: 3n,
      startBurnHt: simnet.burnBlockHeight,
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

  expect(rov(pox5.getStakerInfo(bob))).toEqual({
    amountUstx: bobAmount,
    firstRewardCycle: 1n,
    numCycles: 3n,
  });

  expectAllSignersHaveKeys();

  expect(isStakerInCycle({ staker: pool, cycle: 1n })).toBeFalsy();
  expect(isStakerInCycle({ staker: pool, cycle: 2n })).toBeFalsy();
  expect(isStakerInCycle({ staker: pool, cycle: 3n })).toBeFalsy();

  txOk(
    pox5.stake({
      poolOrSignerKey: ok(pool),
      amountUstx: charlieAmount,
      numCycles: 2n,
      startBurnHt: simnet.burnBlockHeight,
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

  expect(rov(pox5.getStakerInfo(charlie))).toEqual({
    amountUstx: charlieAmount,
    firstRewardCycle: 1n,
    numCycles: 2n,
  });

  expectAllSignersHaveKeys();

  // finally, our pool should be in the signer set
  expect(isStakerInCycle({ staker: pool, cycle: 1n })).toBeTruthy();
  expect(isStakerInCycle({ staker: pool, cycle: 2n })).toBeTruthy();
  expect(isStakerInCycle({ staker: pool, cycle: 3n })).toBeFalsy();
});

/**  Scenario: a user stakes to a pool, then updates their stake.
 * - Alice stakes 50k for 3 cycles
 * - In cycle 1, updates to different pool
 * - The previous pool should be removed from the signer set
 * - The new pool should be added to the signer set
 */
test('scenario - updating a stake', () => {
  const pool1 = testPool.identifier;
  registerPool({ caller: deployer });
  const testPool2 = deployTestPool('test-pool-2');

  const aliceAmount = stxToUStx(50_000);

  const stakeResult = txOk(
    pox5.stake({
      poolOrSignerKey: ok(pool1),
      amountUstx: aliceAmount,
      numCycles: 3n,
      startBurnHt: simnet.burnBlockHeight,
    }),
    alice,
  );
  expect(stakeResult.value.unlockCycle).toBe(4n);

  expectAllSignersHaveKeys();

  mineUntil(rov(pox5.rewardCycleToUnlockHeight(1n)));

  txOk(
    pox5.stakeUpdate({
      poolOrSignerKey: ok(testPool2.identifier),
      amountIncrease: 0n,
      cyclesToExtend: 1n,
    }),
    alice,
  );

  // pool1 should be removed from the signer set
  expect(isStakerInCycle({ staker: pool1, cycle: 1n })).toBeTruthy();
  expect(isStakerInCycle({ staker: pool1, cycle: 2n })).toBeFalsy();
  expect(isStakerInCycle({ staker: pool1, cycle: 3n })).toBeFalsy();

  // testPool2 should be added to the signer set from 2-4
  expect(
    isStakerInCycle({ staker: testPool2.identifier, cycle: 1n }),
  ).toBeFalsy();
  expect(
    isStakerInCycle({ staker: testPool2.identifier, cycle: 2n }),
  ).toBeTruthy();
  expect(
    isStakerInCycle({ staker: testPool2.identifier, cycle: 3n }),
  ).toBeTruthy();
  expect(
    isStakerInCycle({ staker: testPool2.identifier, cycle: 4n }),
  ).toBeTruthy();

  expectAllSignersHaveKeys();
});

/** Scenario: solo staking and switching to pooling
 * - Alice solo stakes 50k for 3 cycles
 * - Bob pools 50k for 3 cycles
 * - In cycle 1, Alice switches to pooling
 * - The previous solo stake should be removed from the signer set
 */
test('scenario - solo staking and switching to pooling', () => {
  const aliceAmount = stxToUStx(50_000);
  const bobAmount = stxToUStx(50_000);
  const pool = testPool.identifier;

  // alice cant solo stake yet without a signer key grant
  const aliceSoloStakeErr = txErr(
    pox5.stake({
      poolOrSignerKey: err(randomBytes(33)),
      amountUstx: aliceAmount,
      numCycles: 3n,
      startBurnHt: simnet.burnBlockHeight,
    }),
    alice,
  );
  expect(aliceSoloStakeErr.value).toEqual(
    pox5Errors.ERR_SIGNER_KEY_GRANT_NOT_FOUND,
  );

  const { signerKey } = setupSigner(alice);
  registerPool({ caller: deployer });

  txOk(
    pox5.stake({
      poolOrSignerKey: err(signerKey),
      amountUstx: aliceAmount,
      numCycles: 3n,
      startBurnHt: simnet.burnBlockHeight,
    }),
    alice,
  );

  expect(rov(pox5.getStakerInfo(alice))).toEqual({
    amountUstx: aliceAmount,
    firstRewardCycle: 1n,
    numCycles: 3n,
  });

  expect(isStakerInCycle({ staker: alice, cycle: 1n })).toBeTruthy();
  expect(isStakerInCycle({ staker: alice, cycle: 2n })).toBeTruthy();
  expect(isStakerInCycle({ staker: alice, cycle: 3n })).toBeTruthy();

  txOk(
    pox5.stake({
      poolOrSignerKey: ok(pool),
      amountUstx: bobAmount,
      numCycles: 3n,
      startBurnHt: simnet.burnBlockHeight,
    }),
    bob,
  );

  expect(getAllStakers().length).toBe(2);

  expectAllSignersHaveKeys();

  expect(isStakerInCycle({ staker: pool, cycle: 1n })).toBeTruthy();
  expect(isStakerInCycle({ staker: pool, cycle: 2n })).toBeTruthy();
  expect(isStakerInCycle({ staker: pool, cycle: 3n })).toBeTruthy();

  mineUntil(rov(pox5.rewardCycleToUnlockHeight(1n)));

  txOk(
    pox5.stakeUpdate({
      poolOrSignerKey: ok(pool),
      amountIncrease: 0n,
      cyclesToExtend: 0n,
    }),
    alice,
  );

  expect(getAllStakers().length).toBe(1);

  expect(isStakerInCycle({ staker: alice, cycle: 1n })).toBeTruthy();
  // alice should be removed from the signer set
  expect(isStakerInCycle({ staker: alice, cycle: 2n })).toBeFalsy();
  expect(isStakerInCycle({ staker: alice, cycle: 3n })).toBeFalsy();

  // the pool should still be in the signer set
  expect(isStakerInCycle({ staker: pool, cycle: 1n })).toBeTruthy();
  expect(isStakerInCycle({ staker: pool, cycle: 2n })).toBeTruthy();
  expect(isStakerInCycle({ staker: pool, cycle: 3n })).toBeTruthy();
});

/** Scenario: unstaking
 * - Alice stakes 50k for 3 cycles
 * - In cycle 1, Alice unstakes
 * - For cycles 2 and 3, she should be removed from the signer set
 */
test('scenario - unstaking', () => {
  const aliceAmount = stxToUStx(50_000);
  const pool = testPool.identifier;

  registerPool({ caller: deployer });

  const stakeResult = txOk(
    pox5.stake({
      poolOrSignerKey: ok(pool),
      amountUstx: aliceAmount,
      numCycles: 3n,
      startBurnHt: simnet.burnBlockHeight,
    }),
    alice,
  );
  expect(stakeResult.value.unlockCycle).toBe(4n);

  expectAllSignersHaveKeys();

  mineUntil(rov(pox5.rewardCycleToUnlockHeight(1n)));

  txOk(pox5.unstake(), alice);
  expect(rov(pox5.getStakerInfo(alice))).toEqual({
    amountUstx: aliceAmount,
    firstRewardCycle: 1n,
    numCycles: 1n,
  });

  expect(isStakerInCycle({ staker: pool, cycle: 1n })).toBeTruthy();
  expect(isStakerInCycle({ staker: pool, cycle: 2n })).toBeFalsy();
  expect(isStakerInCycle({ staker: pool, cycle: 3n })).toBeFalsy();

  expect(getAllStakers().length).toBe(0);

  mineUntil(rov(pox5.rewardCycleToUnlockHeight(2n)));

  // `getStakerInfo` should return `none` because it's expired
  expect(rov(pox5.getStakerInfo(alice))).toBeNull();
});
