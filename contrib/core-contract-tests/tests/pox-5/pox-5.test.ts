import {
  CoreNodeEventType,
  err,
  extractErrors,
  isResponse,
  ok,
} from '@clarigen/core';
import {
  Cl,
  ClarityType,
  cvToValue,
  deserializeCV,
} from '@stacks/transactions';
import { hex } from '@scure/base';
import { accounts } from '../clarigen-types';
import { beforeEach, expect, test } from 'vitest';
import { filterEvents, rov, rovErr, rovOk, txErr, txOk } from '@clarigen/test';
import { mineUntil, stxToUStx } from '../test-helpers';
import {
  buildL1Lockup,
  deployTestSigner,
  errorCodes,
  expectAllSignersHaveKeys,
  getAllStakers,
  isSignerInCycle,
  registerSigner,
  registerSignerManager,
  sbtc,
  sbtcBalance,
  signerAddress,
  testSignerErrors,
  testSigner,
  sbtcTransfer,
  pox5,
  initPox5,
} from './pox-5-helpers';

const pox5Errors = extractErrors(pox5);

const deployer = accounts.deployer.address;
const alice = accounts.wallet_1.address;
const bob = accounts.wallet_2.address;
const charlie = accounts.wallet_3.address;
const dave = accounts.wallet_4.address;
const emily = accounts.wallet_5.address;

const REWARD_CYCLE_LENGTH = 100n;
const HALF_CYCLE_LENGTH = REWARD_CYCLE_LENGTH / 2n;
const BASIS_POINTS = 10000n;

function reserveRewards(rewards: bigint) {
  return (rewards * pox5.constants.RESERVE_RATIO) / BASIS_POINTS;
}

/**
 * Read the staker's STX lock state via the native `(stx-account ...)`. Used
 * by the rollover tests to verify the lock is carried forward across a
 * bond/stake transition rather than released and re-acquired.
 *
 * NOTE: the pinned `@stacks/clarinet-sdk-wasm` doesn't currently apply
 * pox-5 STX locks in simnet, so the assertions consuming this helper are
 * commented out in the rollover tests until the wasm is refreshed against
 * this branch's stacks-core.
 */
function stxAccount(address: string): {
  locked: bigint;
  unlocked: bigint;
  unlockHeight: bigint;
} {
  const hex = simnet.runSnippet(`(stx-account '${address})`) as string;
  // `cvToValue` returns tuple inner values as `{ type, value: string }` even
  // for native uints, so we unwrap manually.
  const tuple = cvToValue(deserializeCV(hex)) as Record<
    string,
    { type: string; value: string }
  >;
  return {
    locked: BigInt(tuple.locked.value),
    unlocked: BigInt(tuple.unlocked.value),
    unlockHeight: BigInt(tuple['unlock-height'].value),
  };
}

function stxRewards(rewards: bigint) {
  return rewards - reserveRewards(rewards);
}

function claimableRewards({
  rewards,
  shares,
  totalShares,
}: {
  rewards: bigint;
  shares: bigint;
  totalShares: bigint;
}) {
  const rewardsPerShare = (rewards * pox5.constants.PRECISION) / totalShares;
  return (shares * rewardsPerShare) / pox5.constants.PRECISION;
}

function bondTargetYieldPerCalculation({
  sats,
  targetRate,
}: {
  sats: bigint;
  targetRate: bigint;
}) {
  return (sats * targetRate) / BASIS_POINTS / 50n;
}

beforeEach(() => {
  initPox5();
});

/**
 * Verifies that every exported PoX-5 error constant has a distinct uint code.
 */
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

/**
 * Verifies that bond indexes map to the expected reward cycle start heights.
 */
test('can calculate bond start height correctly', () => {
  expect(rov(pox5.bondPeriodToBurnHeight(0n))).toBe(
    rov(pox5.rewardCycleToBurnHeight(1n)),
  );
  expect(rov(pox5.bondPeriodToBurnHeight(1n))).toBe(
    rov(pox5.rewardCycleToBurnHeight(1n)) + REWARD_CYCLE_LENGTH * 2n,
  );
});

/**
 * `uint-to-buff-le` encodes a uint as a little-endian buffer. The contract's
 * bounds check accepts `n < u65536`, so the boundaries to verify are 0, 255,
 * 256 (the 1→2 byte transition), 65535 (max valid), and 65536 (must panic).
 */
test('uint-to-buff-le encodes values < 256 as a single byte', () => {
  expect(hex.encode(rov(pox5.uintToBuffLe(0n)))).toEqual('00');
  expect(hex.encode(rov(pox5.uintToBuffLe(1n)))).toEqual('01');
  expect(hex.encode(rov(pox5.uintToBuffLe(75n)))).toEqual('4b');
  expect(hex.encode(rov(pox5.uintToBuffLe(255n)))).toEqual('ff');
});

test('uint-to-buff-le encodes values in [256, 65535] as two little-endian bytes', () => {
  expect(hex.encode(rov(pox5.uintToBuffLe(256n)))).toEqual('0001');
  expect(hex.encode(rov(pox5.uintToBuffLe(257n)))).toEqual('0101');
  expect(hex.encode(rov(pox5.uintToBuffLe(0x1234n)))).toEqual('3412');
  expect(hex.encode(rov(pox5.uintToBuffLe(0xff00n)))).toEqual('00ff');
  expect(hex.encode(rov(pox5.uintToBuffLe(0xfffen)))).toEqual('feff');
  expect(hex.encode(rov(pox5.uintToBuffLe(0xffffn)))).toEqual('ffff');
});

test('uint-to-buff-le panics on values >= 65536', () => {
  expect(() => rov(pox5.uintToBuffLe(65536n))).toThrow();
  expect(() => rov(pox5.uintToBuffLe(0x10000n))).toThrow();
  expect(() => rov(pox5.uintToBuffLe(2n ** 64n))).toThrow();
});

/**
 * Helper-only test for printing the Clarity list literal used by cycle folds.
 */
test.skip('can output the list literal for max cycle iterations', () => {
  const nums: string[] = [];
  for (let i = 0; i < pox5.constants.MAX_NUM_CYCLES; i++) {
    nums.push(`u${i}`);
  }
  console.log(`(list ${nums.join(' ')})`);
});

/**
 * Sets up a bond, registers two allowed participants, and checks registration
 * limits around duplicate registration, minimum STX, and max sats.
 */
test('scenario - setting up and starting a bond', () => {
  const signer = testSigner.identifier;
  registerSigner({ caller: deployer });

  const minUstxRatio = 1000n; // 10%
  const stxValueRatio = 10000000n; // 1 ustx = 100 sat
  txOk(
    pox5.setupBond({
      bondIndex: 0n,
      targetRate: 300n,
      stxValueRatio,
      minUstxRatio,
      earlyUnlockBytes: new Uint8Array(),
      allowlist: [
        {
          maxSats: 100000000n,
          staker: alice,
        },
        {
          maxSats: 5000000n,
          staker: bob,
        },
      ],
    }),
    deployer,
  );

  const allowance = rov(pox5.getBondAllowance(0n, alice));
  expect(allowance).toBe(100000000n);

  const sbtcAmount = 5000000n;

  const minAmountUstx = rov(
    pox5.minUstxForSatsAmount(sbtcAmount, stxValueRatio, minUstxRatio),
  );
  expect(minAmountUstx).toBeGreaterThanOrEqual(
    pox5.constants.SIGNER_SET_MIN_USTX,
  );

  const aliceRegister = txOk(
    pox5.registerForBond({
      bondIndex: 0n,
      signerManager: signer,
      amountUstx: minAmountUstx,
      btcLockup: err(sbtcAmount),
      signerCalldata: null,
    }),
    alice,
  );

  expect(aliceRegister.value).toMatchObject({
    bondIndex: 0n,
    amountUstx: minAmountUstx,
    firstRewardCycle: rov(pox5.bondPeriodToRewardCycle(0n)),
    unlockCycle:
      rov(pox5.bondPeriodToRewardCycle(0n)) + pox5.constants.BOND_LENGTH_CYCLES,
    unlockBurnHeight: rov(pox5.bondPeriodToBurnHeight(6n)),
  });

  const aliceInfo = rov(pox5.getBondMembership(alice))!;
  expect(aliceInfo).toEqual({
    amountSats: sbtcAmount,
    amountUstx: minAmountUstx,
    bondIndex: 0n,
    isL1Lock: false,
    signer,
  });
  expect(rov(pox5.getStakerSharesStakedForCycle(alice, 1n, 0n, signer))).toBe(
    sbtcAmount,
  );
  expect(rov(pox5.getStakerSharesStakedForCycle(alice, 0n, null, signer))).toBe(
    0n,
  );

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
      signerManager: signer,
      amountUstx: minAmountUstx,
      btcLockup: err(sbtcAmount),
      signerCalldata: null,
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
      signerManager: signer,
      signerCalldata: null,
      amountUstx: stxMinAmount - 1n,
      btcLockup: err(bobAllowance!),
    }),
    bob,
  );
  expect(bobRegisterStxErr.value).toEqual(pox5Errors.ERR_INSUFFICIENT_STX);

  const overAllowance = bobAllowance! + 1n;
  const minForOverAllowance = rov(
    pox5.minUstxForSatsAmount(overAllowance, stxValueRatio, minUstxRatio),
  );

  // cannot send more than allowance
  const bobRegisterSatsErr = txErr(
    pox5.registerForBond({
      bondIndex: 0n,
      signerManager: signer,
      signerCalldata: null,
      amountUstx: minForOverAllowance,
      btcLockup: err(bobAllowance! + 1n),
    }),
    bob,
  );
  expect(bobRegisterSatsErr.value).toEqual(pox5Errors.ERR_TOO_MUCH_SATS);

  // bob can send exactly allowance and exactly the min stx
  const bobRegister = txOk(
    pox5.registerForBond({
      bondIndex: 0n,
      signerManager: signer,
      signerCalldata: null,
      amountUstx: minForOverAllowance,
      btcLockup: err(bobAllowance!),
    }),
    bob,
  );

  expect(bobRegister.value).toMatchObject({
    bondIndex: 0n,
    amountUstx: minForOverAllowance,
    firstRewardCycle: rov(pox5.bondPeriodToRewardCycle(0n)),
    unlockCycle:
      rov(pox5.bondPeriodToRewardCycle(0n)) + pox5.constants.BOND_LENGTH_CYCLES,
    unlockBurnHeight: rov(pox5.bondPeriodToBurnHeight(6n)),
  });

  expect(bobRegister.value).toMatchObject({
    bondIndex: 0n,
    amountUstx: minForOverAllowance,
    firstRewardCycle: rov(pox5.bondPeriodToRewardCycle(0n)),
    unlockCycle:
      rov(pox5.bondPeriodToRewardCycle(0n)) + pox5.constants.BOND_LENGTH_CYCLES,
    unlockBurnHeight: rov(pox5.bondPeriodToBurnHeight(6n)),
  });

  expect(rov(pox5.getStakerSharesStakedForCycle(bob, 1n, 0n, signer))).toBe(
    bobAllowance!,
  );
  expect(rov(pox5.getStakerSharesStakedForCycle(bob, 0n, null, signer))).toBe(
    0n,
  );

  const bobRegisterEvent = filterEvents(
    bobRegister.events,
    CoreNodeEventType.FtTransferEvent,
  )[0]!;
  expect(bobRegisterEvent.data.recipient).toBe(pox5.identifier);
  expect(bobRegisterEvent.data.amount).toBe(bobAllowance!.toString());
  expect(bobRegisterEvent.data.sender).toBe(bob);

  expect(getAllStakers().length).toBe(1);
  expectAllSignersHaveKeys();
});

/**
 * Revoking a signer key grant disables an already-registered manager from
 * accepting any *new* stake, even though its `signers` entry (and thus
 * `get-signer-info`) is intentionally left intact so outstanding obligations
 * can still settle. This is what gives `revoke-signer-grant` teeth against a
 * manager that is later found buggy or deprecated: it can no longer accumulate
 * delegated STX, so it cannot (re-)enter the signer set off new stake.
 */
test('revoking a grant blocks new stake to a registered signer', () => {
  const signer = testSigner.identifier;
  const { signerKey } = registerSigner();
  const amount = pox5.constants.SIGNER_SET_MIN_USTX;

  // Alice stakes enough to put the signer in the set for cycle 1.
  txOk(
    pox5.stake({
      signerManager: signer,
      amountUstx: amount,
      numCycles: 2n,
      startBurnHt: simnet.burnBlockHeight,
      signerCalldata: null,
    }),
    alice,
  );
  expect(isSignerInCycle({ signer, cycle: 1n })).toBe(true);

  // The signer-key principal revokes the grant.
  const revoke = txOk(
    pox5.revokeSignerGrant({ signerManager: signer, signerKey }),
    signerAddress(signerKey),
  );
  expect(revoke.value.existed).toBe(true);

  // The `signers` entry is left intact so existing obligations can settle...
  expect(rov(pox5.getSignerInfo(signer))).toEqual(signerKey);
  // ...and Alice's already-recorded stake is untouched (winds down naturally).
  expect(isSignerInCycle({ signer, cycle: 1n })).toBe(true);
  expect(rov(pox5.getAmountDelegatedForSigner({ signer, cycle: 1n }))).toBe(
    amount,
  );

  // But no new stake can flow to the now-revoked manager.
  const bobStakeErr = txErr(
    pox5.stake({
      signerManager: signer,
      amountUstx: amount,
      numCycles: 2n,
      startBurnHt: simnet.burnBlockHeight,
      signerCalldata: null,
    }),
    bob,
  );
  expect(bobStakeErr.value).toEqual(pox5Errors.ERR_SIGNER_KEY_GRANT_NOT_FOUND);
});

/**
 * Scenario: multiple users stake to a signer, ensuring that
 * the signer is only added to the signer set once the minimum
 * threshold is reached.
 *
 * - Register the signer
 * - Alice stakes 40k for 2 cycles
 * - Bob stakes 5k for 3 cycles
 * - Charlie stakes 5k STX for 2 cycles
 *
 * The signer should be added to signer sets 1 and 2, but not 3
 */
test('scenario - staking to a signer', () => {
  const admin = deployer;
  const signer = testSigner.identifier;

  const aliceAmount = stxToUStx(40_000);
  const charlieAmount = stxToUStx(5_000);
  const bobAmount = stxToUStx(5_000);

  // sanity check that our amounts are exactly the minimum
  expect(aliceAmount + bobAmount + charlieAmount).toBe(
    pox5.constants.SIGNER_SET_MIN_USTX,
  );

  const { signerKey } = registerSigner({ caller: admin });

  const signerInfo = rov(pox5.getSignerInfo(signer));
  expect(signerInfo).toEqual(signerKey);

  const aliceStake = txOk(
    pox5.stake({
      signerManager: signer,
      amountUstx: aliceAmount,
      numCycles: 2n,
      startBurnHt: simnet.burnBlockHeight,
      signerCalldata: null,
    }),
    alice,
  );

  const aliceFirstRewardCycle = rov(pox5.currentPoxRewardCycle()) + 1n;
  const aliceUnlockCycle = aliceFirstRewardCycle + 2n;
  const aliceUnlockHeight = rov(pox5.rewardCycleToBurnHeight(aliceUnlockCycle));
  expect(aliceStake.value).toMatchObject({
    signer,
    staker: alice,
    amountUstx: aliceAmount,
    firstRewardCycle: aliceFirstRewardCycle,
    unlockCycle: aliceUnlockCycle,
    unlockBurnHeight: aliceUnlockHeight,
  });

  // cannot stake again
  const aliceStakeErr = txErr(
    pox5.stake({
      signerManager: signer,
      amountUstx: aliceAmount,
      numCycles: 2n,
      startBurnHt: simnet.burnBlockHeight,
      signerCalldata: null,
    }),
    alice,
  );
  expect(aliceStakeErr.value).toEqual(pox5Errors.ERR_ALREADY_STAKED);

  expect(
    rov(
      pox5.getAmountDelegatedForSigner({
        signer,
        cycle: 1n,
      }),
    ),
  ).toBe(aliceAmount);
  expect(rov(pox5.getStakerSharesStakedForCycle(alice, 1n, null, signer))).toBe(
    aliceAmount,
  );
  expect(rov(pox5.getStakerSharesStakedForCycle(alice, 1n, 1n, signer))).toBe(
    0n,
  );
  expect(rov(pox5.getAmountDelegatedForSigner({ signer, cycle: 2n }))).toBe(
    aliceAmount,
  );
  expect(rov(pox5.getStakerSharesStakedForCycle(alice, 2n, null, signer))).toBe(
    aliceAmount,
  );
  expect(rov(pox5.getStakerInfo(alice))).toEqual({
    amountUstx: aliceAmount,
    firstRewardCycle: 1n,
    numCycles: 2n,
    signer,
  });

  expect(isSignerInCycle({ signer: signer, cycle: 1n })).toBeFalsy();
  expect(isSignerInCycle({ signer: signer, cycle: 2n })).toBeFalsy();

  const bobStake = txOk(
    pox5.stake({
      signerManager: signer,
      amountUstx: bobAmount,
      numCycles: 3n,
      startBurnHt: simnet.burnBlockHeight,
      signerCalldata: null,
    }),
    bob,
  );

  const bobFirstRewardCycle = rov(pox5.currentPoxRewardCycle()) + 1n;
  const bobUnlockCycle = bobFirstRewardCycle + 3n;
  const bobUnlockHeight = rov(pox5.rewardCycleToBurnHeight(bobUnlockCycle));
  expect(bobStake.value).toMatchObject({
    signer,
    staker: bob,
    amountUstx: bobAmount,
    firstRewardCycle: bobFirstRewardCycle,
    unlockCycle: bobUnlockCycle,
    unlockBurnHeight: bobUnlockHeight,
  });

  expect(rov(pox5.getAmountDelegatedForSigner({ signer, cycle: 1n }))).toBe(
    aliceAmount + bobAmount,
  );
  expect(rov(pox5.getAmountDelegatedForSigner({ signer, cycle: 2n }))).toBe(
    aliceAmount + bobAmount,
  );
  expect(rov(pox5.getAmountDelegatedForSigner({ signer, cycle: 3n }))).toBe(
    bobAmount,
  );
  expect(rov(pox5.getStakerSharesStakedForCycle(bob, 1n, null, signer))).toBe(
    bobAmount,
  );

  expect(rov(pox5.getStakerInfo(bob))).toEqual({
    amountUstx: bobAmount,
    firstRewardCycle: 1n,
    numCycles: 3n,
    signer,
  });

  expectAllSignersHaveKeys();

  expect(isSignerInCycle({ signer: signer, cycle: 1n })).toBeFalsy();
  expect(isSignerInCycle({ signer: signer, cycle: 2n })).toBeFalsy();
  expect(isSignerInCycle({ signer: signer, cycle: 3n })).toBeFalsy();

  txOk(
    pox5.stake({
      signerManager: signer,
      amountUstx: charlieAmount,
      numCycles: 2n,
      startBurnHt: simnet.burnBlockHeight,
      signerCalldata: null,
    }),
    charlie,
  );

  expect(rov(pox5.getAmountDelegatedForSigner({ signer, cycle: 1n }))).toBe(
    aliceAmount + bobAmount + charlieAmount,
  );
  expect(rov(pox5.getAmountDelegatedForSigner({ signer, cycle: 2n }))).toBe(
    aliceAmount + bobAmount + charlieAmount,
  );
  expect(rov(pox5.getAmountDelegatedForSigner({ signer, cycle: 3n }))).toBe(
    charlieAmount,
  );

  expect(rov(pox5.getStakerInfo(charlie))).toEqual({
    amountUstx: charlieAmount,
    firstRewardCycle: 1n,
    numCycles: 2n,
    signer,
  });

  expectAllSignersHaveKeys();

  // finally, our signer should be in the signer set
  expect(isSignerInCycle({ signer: signer, cycle: 1n })).toBeTruthy();
  expect(isSignerInCycle({ signer: signer, cycle: 2n })).toBeTruthy();
  expect(isSignerInCycle({ signer: signer, cycle: 3n })).toBeFalsy();
});

/**  Scenario: a user stakes to a signer, then updates their stake.
 * - Alice stakes 50k for 3 cycles
 * - In cycle 1, updates to different signer
 * - The previous signer should be removed from the signer set
 * - The new signer should be added to the signer set
 */
test('scenario - updating a stake', () => {
  const signer1 = testSigner.identifier;
  registerSigner({ caller: deployer });
  const testSigner2 = deployTestSigner('test-signer-2');

  const aliceAmount = stxToUStx(50_000);

  const stakeResult = txOk(
    pox5.stake({
      signerManager: signer1,
      amountUstx: aliceAmount,
      numCycles: 3n,
      startBurnHt: simnet.burnBlockHeight,
      signerCalldata: null,
    }),
    alice,
  );
  expect(stakeResult.value.unlockCycle).toBe(4n);

  expectAllSignersHaveKeys();

  mineUntil(rov(pox5.rewardCycleToBurnHeight(1n)));

  txOk(
    pox5.stakeUpdate({
      signerManager: testSigner2.identifier,
      amountIncrease: 10_000n,
      cyclesToExtend: 1n,
      signerCalldata: null,
      oldSignerManager: signer1,
    }),
    alice,
  );
  expect(
    rov(pox5.getStakerSharesStakedForCycle(alice, 1n, null, signer1)),
  ).toBe(aliceAmount);
  expect(
    rov(
      pox5.getStakerSharesStakedForCycle(
        alice,
        1n,
        null,

        testSigner2.identifier,
      ),
    ),
  ).toBe(0n);
  expect(
    rov(
      pox5.getStakerSharesStakedForCycle(
        alice,
        2n,
        null,

        testSigner2.identifier,
      ),
    ),
  ).toBe(aliceAmount + 10_000n);
  expect(
    rov(pox5.getStakerSharesStakedForCycle(alice, 2n, null, signer1)),
  ).toBe(0n);

  // signer1 should be removed from the signer set
  expect(isSignerInCycle({ signer: signer1, cycle: 1n })).toBeTruthy();
  expect(isSignerInCycle({ signer: signer1, cycle: 2n })).toBeFalsy();
  expect(isSignerInCycle({ signer: signer1, cycle: 3n })).toBeFalsy();

  // testSigner2 should be added to the signer set from 2-4
  expect(
    isSignerInCycle({ signer: testSigner2.identifier, cycle: 1n }),
  ).toBeFalsy();
  expect(
    isSignerInCycle({ signer: testSigner2.identifier, cycle: 2n }),
  ).toBeTruthy();
  expect(
    isSignerInCycle({ signer: testSigner2.identifier, cycle: 3n }),
  ).toBeTruthy();
  expect(
    isSignerInCycle({ signer: testSigner2.identifier, cycle: 4n }),
  ).toBeTruthy();

  expectAllSignersHaveKeys();
});

/** Scenario: unstaking
 * - Alice stakes 50k for 3 cycles
 * - In cycle 1, Alice unstakes
 * - For cycles 2 and 3, she should be removed from the signer set
 */
test('scenario - unstaking', () => {
  const aliceAmount = stxToUStx(50_000);
  const signer = testSigner.identifier;

  registerSigner({ caller: deployer });

  const stakeResult = txOk(
    pox5.stake({
      signerManager: signer,
      amountUstx: aliceAmount,
      numCycles: 3n,
      startBurnHt: simnet.burnBlockHeight,
      signerCalldata: null,
    }),
    alice,
  );
  expect(stakeResult.value.unlockCycle).toBe(4n);

  expectAllSignersHaveKeys();

  mineUntil(rov(pox5.rewardCycleToBurnHeight(1n)));

  txOk(pox5.unstake({ oldSignerManager: signer }), alice);
  expect(rov(pox5.getStakerInfo(alice))).toEqual({
    amountUstx: aliceAmount,
    firstRewardCycle: 1n,
    numCycles: 1n,
    signer,
  });

  expect(isSignerInCycle({ signer: signer, cycle: 1n })).toBeTruthy();
  expect(isSignerInCycle({ signer: signer, cycle: 2n })).toBeFalsy();
  expect(isSignerInCycle({ signer: signer, cycle: 3n })).toBeFalsy();

  expect(getAllStakers().length).toBe(0);

  mineUntil(rov(pox5.rewardCycleToBurnHeight(2n)));

  // `getStakerInfo` should return `none` because it's expired
  expect(rov(pox5.getStakerInfo(alice))).toBeNull();
});

/**
 * Distributes STX-only rewards across two signer managers with equal STX
 * stake, after taking the reserve cut from the reward pool.
 */
test('stx-only rewards split across signers by staked ustx', () => {
  const signer1 = testSigner.identifier;
  const signer2 = deployTestSigner('stx-reward-signer-2').identifier;
  const stakeAmount = stxToUStx(50_000);

  registerSigner();

  txOk(
    pox5.stake({
      signerManager: signer1,
      amountUstx: stakeAmount,
      numCycles: 2n,
      startBurnHt: simnet.burnBlockHeight,
      signerCalldata: null,
    }),
    alice,
  );
  txOk(
    pox5.stake({
      signerManager: signer2,
      amountUstx: stakeAmount,
      numCycles: 2n,
      startBurnHt: simnet.burnBlockHeight,
      signerCalldata: null,
    }),
    bob,
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

  mineUntil(rov(pox5.rewardCycleToBurnHeight(1n)) + HALF_CYCLE_LENGTH);
  txOk(pox5.calculateRewards([]), deployer);

  expect(rov(pox5.getReserveBalance())).toBe(reserveRewards(1000n));
  expect(rov(pox5.getEarned(signer1, 1n, null))).toBe(
    claimableRewards({
      rewards: stxRewards(1000n),
      shares: stakeAmount,
      totalShares: stakeAmount * 2n,
    }),
  );
  expect(rov(pox5.getEarned(signer2, 1n, null))).toBe(
    claimableRewards({
      rewards: stxRewards(1000n),
      shares: stakeAmount,
      totalShares: stakeAmount * 2n,
    }),
  );
});

test('cannot register for bond with more STX than they have unlocked', () => {
  const signer = testSigner.identifier;
  registerSigner();
  txOk(
    pox5.setupBond({
      bondIndex: 0n,
      targetRate: 1200n,
      stxValueRatio: 10n,
      minUstxRatio: 100n,
      earlyUnlockBytes: new Uint8Array(),
      allowlist: [{ maxSats: 100000n, staker: alice }],
    }),
    deployer,
  );

  const registerErr = txErr(
    pox5.registerForBond({
      bondIndex: 0n,
      signerManager: signer,
      amountUstx: 100_000_000_000_001n,
      btcLockup: err(100000n),
      signerCalldata: null,
    }),
    alice,
  );

  expect(registerErr.value).toBe(pox5Errors.ERR_INSUFFICIENT_STX);
});

/**
 * Distributes one bond period's rewards across two signer managers by their
 * bonded sats share, with residual rewards flowing through the STX waterfall.
 */
test('bond rewards split across signers by staked sats', () => {
  const signer1 = testSigner.identifier;
  const signer2 = deployTestSigner('bond-reward-signer-2').identifier;
  const aliceSbtc = 100000n;
  const bobSbtc = 300000n;
  const targetRate = 1200n;

  registerSigner();

  txOk(
    pox5.setupBond({
      bondIndex: 0n,
      targetRate,
      stxValueRatio: 10n,
      minUstxRatio: 100n,
      earlyUnlockBytes: new Uint8Array(),
      allowlist: [
        { maxSats: aliceSbtc, staker: alice },
        { maxSats: bobSbtc, staker: bob },
      ],
    }),
    deployer,
  );

  txOk(
    pox5.registerForBond({
      bondIndex: 0n,
      signerManager: signer1,
      amountUstx: rov(pox5.minUstxForSatsAmount(aliceSbtc, 10n, 100n)),
      btcLockup: err(aliceSbtc),
      signerCalldata: null,
    }),
    alice,
  );
  txOk(
    pox5.registerForBond({
      bondIndex: 0n,
      signerManager: signer2,
      amountUstx: rov(pox5.minUstxForSatsAmount(bobSbtc, 10n, 100n)),
      btcLockup: err(bobSbtc),
      signerCalldata: null,
    }),
    bob,
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

  mineUntil(rov(pox5.rewardCycleToBurnHeight(1n)) + HALF_CYCLE_LENGTH);
  txOk(pox5.calculateRewards([0n]), deployer);

  const totalBondRewards = bondTargetYieldPerCalculation({
    sats: aliceSbtc + bobSbtc,
    targetRate,
  });
  expect(totalBondRewards).toBe(960n);
  expect(rov(pox5.getEarned(signer1, 1n, 0n))).toBe(
    claimableRewards({
      rewards: totalBondRewards,
      shares: aliceSbtc,
      totalShares: aliceSbtc + bobSbtc,
    }),
  );
  expect(rov(pox5.getEarned(signer2, 1n, 0n))).toBe(
    claimableRewards({
      rewards: totalBondRewards,
      shares: bobSbtc,
      totalShares: aliceSbtc + bobSbtc,
    }),
  );
  // When no STX-only stake exists, the staker cut is
  // rerouted to reserve rather than stranded, so reserve receives the
  // full `remaining-rewards` (1000 - 960 = 40), not just 15% of it.
  expect(rov(pox5.getReserveBalance())).toBe(1000n - totalBondRewards);
});

/**
 * Pays an underfunded bond period all available rewards and verifies that no
 * rewards remain for reserve or STX-only stakers.
 */
test('bond shortfall leaves no rewards for reserve or stx-only stakers', () => {
  const signer = testSigner.identifier;
  const aliceSbtc = 400000n;

  registerSigner();

  txOk(
    pox5.setupBond({
      bondIndex: 0n,
      targetRate: 1200n,
      stxValueRatio: 10n,
      minUstxRatio: 100n,
      earlyUnlockBytes: new Uint8Array(),
      allowlist: [{ maxSats: aliceSbtc, staker: alice }],
    }),
    deployer,
  );
  txOk(
    pox5.registerForBond({
      bondIndex: 0n,
      signerManager: signer,
      amountUstx: rov(pox5.minUstxForSatsAmount(aliceSbtc, 10n, 100n)),
      btcLockup: err(aliceSbtc),
      signerCalldata: null,
    }),
    alice,
  );
  txOk(
    pox5.stake({
      signerManager: signer,
      amountUstx: stxToUStx(50_000),
      numCycles: 2n,
      startBurnHt: simnet.burnBlockHeight,
      signerCalldata: null,
    }),
    bob,
  );

  txOk(
    sbtc.transfer({
      recipient: pox5.identifier,
      amount: 400n,
      sender: deployer,
      memo: null,
    }),
    deployer,
  );

  mineUntil(rov(pox5.rewardCycleToBurnHeight(1n)) + HALF_CYCLE_LENGTH);
  txOk(pox5.calculateRewards([0n]), deployer);

  expect(rov(pox5.getEarned(signer, 1n, 0n))).toBe(400n);
  expect(rov(pox5.getEarned(signer, 1n, null))).toBe(0n);
  expect(rov(pox5.getReserveBalance())).toBe(0n);
});

/**
 * Runs two overlapping active bond periods with a shared reward shortfall and
 * verifies that bond priority determines who receives the remaining rewards.
 */
test('concurrent bonds are paid by priority before stx-only stakers', () => {
  const signer = testSigner.identifier;
  const targetRate = 1200n;
  const minUstxRatio = 100n;
  const aliceSbtc = 400000n;
  const bobSbtc = 400000n;

  registerSigner();

  txOk(
    pox5.setupBond({
      bondIndex: 0n,
      targetRate,
      stxValueRatio: 20n,
      minUstxRatio,
      earlyUnlockBytes: new Uint8Array(),
      allowlist: [{ maxSats: aliceSbtc, staker: alice }],
    }),
    deployer,
  );
  txOk(
    pox5.registerForBond({
      bondIndex: 0n,
      signerManager: signer,
      amountUstx: rov(pox5.minUstxForSatsAmount(aliceSbtc, 20n, minUstxRatio)),
      btcLockup: err(aliceSbtc),
      signerCalldata: null,
    }),
    alice,
  );

  mineUntil(rov(pox5.bondPeriodToBurnHeight(0n)) + 1n);

  txOk(
    pox5.setupBond({
      bondIndex: 1n,
      targetRate,
      stxValueRatio: 10n,
      minUstxRatio,
      earlyUnlockBytes: new Uint8Array(),
      allowlist: [{ maxSats: bobSbtc, staker: bob }],
    }),
    deployer,
  );
  txOk(
    pox5.registerForBond({
      bondIndex: 1n,
      signerManager: signer,
      amountUstx: rov(pox5.minUstxForSatsAmount(bobSbtc, 10n, minUstxRatio)),
      btcLockup: err(bobSbtc),
      signerCalldata: null,
    }),
    bob,
  );
  txOk(
    pox5.stake({
      signerManager: signer,
      amountUstx: stxToUStx(50_000),
      numCycles: 6n,
      startBurnHt: simnet.burnBlockHeight,
      signerCalldata: null,
    }),
    charlie,
  );

  txOk(
    sbtc.transfer({
      recipient: pox5.identifier,
      amount: 1500n,
      sender: deployer,
      memo: null,
    }),
    deployer,
  );

  mineUntil(rov(pox5.rewardCycleToBurnHeight(3n)) + HALF_CYCLE_LENGTH);
  txOk(pox5.calculateRewards([0n, 1n]), deployer);

  const firstBondRewards = bondTargetYieldPerCalculation({
    sats: aliceSbtc,
    targetRate,
  });
  expect(rov(pox5.getEarned(signer, 3n, 0n))).toBe(firstBondRewards);
  expect(rov(pox5.getEarned(signer, 3n, 1n))).toBe(1500n - firstBondRewards);
  expect(rov(pox5.getEarned(signer, 3n, null))).toBe(0n);
  expect(rov(pox5.getReserveBalance())).toBe(0n);
});

/**
 * Runs two overlapping active bond periods plus STX-only staking across two
 * signers, then claims each signer's bond and STX rewards in one call.
 */
test('concurrent bonds and stx-only rewards can be claimed together', () => {
  const signer1 = testSigner.identifier;
  const signer2Contract = deployTestSigner('concurrent-claim-signer-2');
  const signer2 = signer2Contract.identifier;
  const targetRate = 1200n;
  const minUstxRatio = 100n;
  const aliceSbtc = 100000n;
  const bobSbtc = 300000n;
  const stxStake = stxToUStx(50_000);

  registerSigner();

  txOk(
    pox5.setupBond({
      bondIndex: 0n,
      targetRate,
      stxValueRatio: 20n,
      minUstxRatio,
      earlyUnlockBytes: new Uint8Array(),
      allowlist: [{ maxSats: aliceSbtc, staker: alice }],
    }),
    deployer,
  );
  txOk(
    pox5.registerForBond({
      bondIndex: 0n,
      signerManager: signer1,
      amountUstx: rov(pox5.minUstxForSatsAmount(aliceSbtc, 20n, minUstxRatio)),
      btcLockup: err(aliceSbtc),
      signerCalldata: null,
    }),
    alice,
  );

  mineUntil(rov(pox5.bondPeriodToBurnHeight(0n)) + 1n);

  txOk(
    pox5.setupBond({
      bondIndex: 1n,
      targetRate,
      stxValueRatio: 10n,
      minUstxRatio,
      earlyUnlockBytes: new Uint8Array(),
      allowlist: [{ maxSats: bobSbtc, staker: bob }],
    }),
    deployer,
  );
  txOk(
    pox5.registerForBond({
      bondIndex: 1n,
      signerManager: signer2,
      amountUstx: rov(pox5.minUstxForSatsAmount(bobSbtc, 10n, minUstxRatio)),
      btcLockup: err(bobSbtc),
      signerCalldata: null,
    }),
    bob,
  );
  txOk(
    pox5.stake({
      signerManager: signer1,
      amountUstx: stxStake,
      numCycles: 6n,
      startBurnHt: simnet.burnBlockHeight,
      signerCalldata: null,
    }),
    charlie,
  );
  txOk(
    pox5.stake({
      signerManager: signer2,
      amountUstx: stxStake,
      numCycles: 6n,
      startBurnHt: simnet.burnBlockHeight,
      signerCalldata: null,
    }),
    dave,
  );

  txOk(
    sbtc.transfer({
      recipient: pox5.identifier,
      amount: 2000n,
      sender: deployer,
      memo: null,
    }),
    deployer,
  );

  mineUntil(rov(pox5.rewardCycleToBurnHeight(3n)) + HALF_CYCLE_LENGTH);
  txOk(pox5.calculateRewards([0n, 1n]), deployer);

  const firstBondRewards = bondTargetYieldPerCalculation({
    sats: aliceSbtc,
    targetRate,
  });
  const secondBondRewards = bondTargetYieldPerCalculation({
    sats: bobSbtc,
    targetRate,
  });
  const remainingRewards = 2000n - firstBondRewards - secondBondRewards;
  const stxRewardAmount = stxRewards(remainingRewards);
  const signerStxRewards = claimableRewards({
    rewards: stxRewardAmount,
    shares: stxStake,
    totalShares: stxStake * 2n,
  });

  expect(rov(pox5.getReserveBalance())).toBe(reserveRewards(remainingRewards));
  expect(rov(pox5.getEarned(signer1, 3n, 0n))).toBe(firstBondRewards);
  expect(rov(pox5.getEarned(signer2, 3n, 1n))).toBe(secondBondRewards);
  expect(rov(pox5.getEarned(signer1, 3n, null))).toBe(signerStxRewards);
  expect(rov(pox5.getEarned(signer2, 3n, null))).toBe(signerStxRewards);

  expect(
    txOk(testSigner.claimRewards([0n], 3n), deployer).value.totalRewards,
  ).toBe(firstBondRewards + signerStxRewards);
  expect(
    txOk(signer2Contract.claimRewards([1n], 3n), deployer).value.totalRewards,
  ).toBe(secondBondRewards + signerStxRewards);
  expect(rov(pox5.getEarned(signer1, 3n, 0n))).toBe(0n);
  expect(rov(pox5.getEarned(signer1, 3n, null))).toBe(0n);
  expect(rov(pox5.getEarned(signer2, 3n, 1n))).toBe(0n);
  expect(rov(pox5.getEarned(signer2, 3n, null))).toBe(0n);
});

test('stx-only stakers claim rewards after signer claims', () => {
  const signer = testSigner.identifier;
  const aliceStake = stxToUStx(50_000);
  const bobStake = stxToUStx(150_000);

  registerSigner();

  txOk(
    pox5.stake({
      signerManager: signer,
      amountUstx: aliceStake,
      numCycles: 2n,
      startBurnHt: simnet.burnBlockHeight,
      signerCalldata: null,
    }),
    alice,
  );
  txOk(
    pox5.stake({
      signerManager: signer,
      amountUstx: bobStake,
      numCycles: 2n,
      startBurnHt: simnet.burnBlockHeight,
      signerCalldata: null,
    }),
    bob,
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

  mineUntil(rov(pox5.rewardCycleToBurnHeight(1n)) + HALF_CYCLE_LENGTH);
  txOk(pox5.calculateRewards([]), deployer);

  const stakerRewards = stxRewards(1000n);
  const aliceRewards = claimableRewards({
    rewards: stakerRewards,
    shares: aliceStake,
    totalShares: aliceStake + bobStake,
  });
  const bobRewards = claimableRewards({
    rewards: stakerRewards,
    shares: bobStake,
    totalShares: aliceStake + bobStake,
  });

  txOk(testSigner.claimRewards([], 1n), deployer);

  expect(rov(testSigner.getEarnedStakerRewards(alice, 1n, null))).toBe(
    aliceRewards,
  );
  expect(rov(testSigner.getEarnedStakerRewards(bob, 1n, null))).toBe(
    bobRewards,
  );

  const aliceBalance = sbtcBalance(alice);
  const bobBalance = sbtcBalance(bob);

  const aliceClaim = txOk(testSigner.claimStakerRewards(1n, null), alice);
  const aliceTransfer = filterEvents(
    aliceClaim.events,
    CoreNodeEventType.FtTransferEvent,
  )[0]!;
  expect(aliceTransfer.data.sender).toBe(signer);
  expect(aliceTransfer.data.recipient).toBe(alice);
  expect(aliceTransfer.data.amount).toBe(aliceRewards.toString());
  expect(rov(testSigner.getEarnedStakerRewards(alice, 1n, null))).toBe(0n);

  txOk(testSigner.claimStakerRewards(1n, null), bob);
  expect(sbtcBalance(alice)).toBe(aliceBalance + aliceRewards);
  expect(sbtcBalance(bob)).toBe(bobBalance + bobRewards);
});

test('bond participants claim rewards after signer claims', () => {
  const signer = testSigner.identifier;
  const aliceSbtc = 100000n;
  const bobSbtc = 300000n;
  const targetRate = 1200n;

  registerSigner();

  txOk(
    pox5.setupBond({
      bondIndex: 0n,
      targetRate,
      stxValueRatio: 10n,
      minUstxRatio: 100n,
      earlyUnlockBytes: new Uint8Array(),
      allowlist: [
        { maxSats: aliceSbtc, staker: alice },
        { maxSats: bobSbtc, staker: bob },
      ],
    }),
    deployer,
  );
  txOk(
    pox5.registerForBond({
      bondIndex: 0n,
      signerManager: signer,
      amountUstx: rov(pox5.minUstxForSatsAmount(aliceSbtc, 10n, 100n)),
      btcLockup: err(aliceSbtc),
      signerCalldata: null,
    }),
    alice,
  );
  txOk(
    pox5.registerForBond({
      bondIndex: 0n,
      signerManager: signer,
      amountUstx: rov(pox5.minUstxForSatsAmount(bobSbtc, 10n, 100n)),
      btcLockup: err(bobSbtc),
      signerCalldata: null,
    }),
    bob,
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

  mineUntil(rov(pox5.rewardCycleToBurnHeight(1n)) + HALF_CYCLE_LENGTH);
  txOk(pox5.calculateRewards([0n]), deployer);
  txOk(testSigner.claimRewards([0n], 1n), deployer);

  const totalBondRewards = bondTargetYieldPerCalculation({
    sats: aliceSbtc + bobSbtc,
    targetRate,
  });
  const aliceRewards = claimableRewards({
    rewards: totalBondRewards,
    shares: aliceSbtc,
    totalShares: aliceSbtc + bobSbtc,
  });
  const bobRewards = claimableRewards({
    rewards: totalBondRewards,
    shares: bobSbtc,
    totalShares: aliceSbtc + bobSbtc,
  });

  expect(rov(testSigner.getEarnedStakerRewards(alice, 1n, 0n))).toBe(
    aliceRewards,
  );
  expect(rov(testSigner.getEarnedStakerRewards(bob, 1n, 0n))).toBe(bobRewards);

  const aliceBalance = sbtcBalance(alice);
  const bobBalance = sbtcBalance(bob);

  txOk(testSigner.claimStakerRewards(1n, 0n), alice);
  txOk(testSigner.claimStakerRewards(1n, 0n), bob);

  expect(sbtcBalance(alice)).toBe(aliceBalance + aliceRewards);
  expect(sbtcBalance(bob)).toBe(bobBalance + bobRewards);
  expect(rov(testSigner.getEarnedStakerRewards(alice, 1n, 0n))).toBe(0n);
  expect(rov(testSigner.getEarnedStakerRewards(bob, 1n, 0n))).toBe(0n);
});

test('bond participant keeps already claimed-to-signer rewards after changing signer', () => {
  const signer1 = testSigner.identifier;
  const signer2 = deployTestSigner('bond-staker-pending-signer-2').identifier;
  const aliceSbtc = 400000n;
  const targetRate = 1200n;

  registerSigner();

  txOk(
    pox5.setupBond({
      bondIndex: 0n,
      targetRate,
      stxValueRatio: 10n,
      minUstxRatio: 100n,
      earlyUnlockBytes: new Uint8Array(),
      allowlist: [{ maxSats: aliceSbtc, staker: alice }],
    }),
    deployer,
  );
  txOk(
    pox5.registerForBond({
      bondIndex: 0n,
      signerManager: signer1,
      amountUstx: stxToUStx(50_000),
      btcLockup: err(aliceSbtc),
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

  mineUntil(rov(pox5.rewardCycleToBurnHeight(1n)) + HALF_CYCLE_LENGTH);
  txOk(pox5.calculateRewards([0n]), deployer);
  txOk(testSigner.claimRewards([0n], 1n), deployer);

  const expectedRewards = bondTargetYieldPerCalculation({
    sats: aliceSbtc,
    targetRate,
  });
  expect(rov(testSigner.getEarnedStakerRewards(alice, 1n, 0n))).toBe(
    expectedRewards,
  );

  txOk(
    pox5.updateBondRegistration({
      signerManager: signer2,
      signerCalldata: null,
      oldSignerManager: signer1,
    }),
    alice,
  );

  expect(rov(testSigner.getEarnedStakerRewards(alice, 1n, 0n))).toBe(
    expectedRewards,
  );
});

// `announce-l1-early-exit` has two assertions that determine the outcome —
// the caller-identity check (auth, fires first) and the `is-l1-lock` check
// (bond type, fires second). The full (caller × bond-type) matrix is:
//
//   caller     │ sBTC bond                          │ L1 bond
//   ───────────┼────────────────────────────────────┼─────────────────────
//   non-staker │ ERR_UNAUTHORIZED                   │ ERR_UNAUTHORIZED
//   the staker │ ERR_CANNOT_ANNOUNCE_L1_EARLY_UNLOCK│ (ok ...) — success
//
// Only the sBTC-bond rows are reachable in unit tests: simnet's fake burn
// header hashes fail `register-for-bond`'s ERR_INVALID_BTC_HEADER check, so
// `is-l1-lock: true` is never observable here. The L1-bond rows are covered
// in the `stacks-node` integration test (`pox_5_integrations.rs`).

function setupBondForAllowlist(
  allowlist: { staker: string; maxSats: bigint }[],
) {
  txOk(
    pox5.setupBond({
      bondIndex: 0n,
      targetRate: 1200n,
      stxValueRatio: 10n,
      minUstxRatio: 100n,
      earlyUnlockBytes: new Uint8Array(),
      allowlist,
    }),
    deployer,
  );
}

test('sbtc bond: announce-l1-early-exit rejects a non-staker caller', () => {
  const signer = testSigner.identifier;
  const aliceSbtc = 100000n;

  registerSigner();
  setupBondForAllowlist([{ maxSats: aliceSbtc, staker: alice }]);
  txOk(
    pox5.registerForBond({
      bondIndex: 0n,
      signerManager: signer,
      amountUstx: stxToUStx(50_000),
      btcLockup: err(aliceSbtc),
      signerCalldata: null,
    }),
    alice,
  );

  const result = txErr(pox5.announceL1EarlyExit(alice, signer), bob);
  expect(result.value).toBe(errorCodes.ERR_UNAUTHORIZED);
  expect(rov(pox5.getStakerSharesStakedForCycle(alice, 1n, 0n, signer))).toBe(
    aliceSbtc,
  );
});

test('sbtc bond: announce-l1-early-exit rejects the staker', () => {
  const signer = testSigner.identifier;
  const aliceSbtc = 100000n;

  registerSigner();
  setupBondForAllowlist([{ maxSats: aliceSbtc, staker: alice }]);
  txOk(
    pox5.registerForBond({
      bondIndex: 0n,
      signerManager: signer,
      amountUstx: stxToUStx(50_000),
      btcLockup: err(aliceSbtc),
      signerCalldata: null,
    }),
    alice,
  );

  const earlyExit = txErr(pox5.announceL1EarlyExit(alice, signer), alice);
  expect(earlyExit.value).toBe(
    pox5.constants.eRR_CANNOT_ANNOUNCE_L1_EARLY_UNLOCK.value,
  );
  expect(rov(pox5.getStakerSharesStakedForCycle(alice, 1n, 0n, signer))).toBe(
    aliceSbtc,
  );
});

test('has-announced-l1-early-exit defaults to false', () => {
  registerSigner();
  setupBondForAllowlist([{ maxSats: 100000n, staker: alice }]);

  // No announcement has ever happened — the read-only must return false for
  // any (bond-index, staker) pair, including ones that don't exist.
  expect(rov(pox5.hasAnnouncedL1EarlyExit(0n, alice))).toBe(false);
  expect(rov(pox5.hasAnnouncedL1EarlyExit(0n, bob))).toBe(false);
  expect(rov(pox5.hasAnnouncedL1EarlyExit(999n, alice))).toBe(false);
});

test('update-bond-registration in the final bond cycle leaves no future shares', () => {
  const signer1 = testSigner.identifier;
  const signer2 = deployTestSigner(
    'bond-update-final-cycle-signer-2',
  ).identifier;
  const aliceSbtc = 100000n;

  registerSigner();

  txOk(
    pox5.setupBond({
      bondIndex: 0n,
      targetRate: 1200n,
      stxValueRatio: 10n,
      minUstxRatio: 100n,
      earlyUnlockBytes: new Uint8Array(),
      allowlist: [{ maxSats: aliceSbtc, staker: alice }],
    }),
    deployer,
  );
  txOk(
    pox5.registerForBond({
      bondIndex: 0n,
      signerManager: signer1,
      amountUstx: stxToUStx(50_000),
      btcLockup: err(aliceSbtc),
      signerCalldata: null,
    }),
    alice,
  );

  mineUntil(rov(pox5.rewardCycleToBurnHeight(12n)));

  txOk(
    pox5.updateBondRegistration({
      signerManager: signer2,
      oldSignerManager: signer1,
      signerCalldata: null,
    }),
    alice,
  );

  expect(rov(pox5.getSignerSharesStakedForCycle(signer2, 13n, 0n))).toBe(0n);
});

// Skipped: Simnet's burn header hashes aren't real, so most of the L1 paths
// can't be covered in unit tests. These will be tested in integration tests.
test.skip('l1 early exit prevents future bond rewards but leaves stx delegated', () => {
  const signer = testSigner.identifier;
  const aliceSats = 480000n;
  const aliceUstx = stxToUStx(50_000);

  registerSigner();

  txOk(
    pox5.setupBond({
      bondIndex: 0n,
      targetRate: 1200n,
      stxValueRatio: 10n,
      minUstxRatio: 100n,
      earlyUnlockBytes: new Uint8Array(),
      allowlist: [{ maxSats: aliceSats, staker: alice }],
    }),
    deployer,
  );
  txOk(
    pox5.registerForBond({
      bondIndex: 0n,
      signerManager: signer,
      amountUstx: aliceUstx,
      btcLockup: ok({
        outputs: [
          buildL1Lockup({ staker: alice, sats: aliceSats, bondIndex: 0n }),
        ],
        stakerUnlockBytes: new Uint8Array(),
      }),
      signerCalldata: null,
    }),
    alice,
  );

  txOk(pox5.announceL1EarlyExit(alice, signer), alice);
  txOk(
    sbtc.transfer({
      recipient: pox5.identifier,
      amount: 1200n,
      sender: deployer,
      memo: null,
    }),
    deployer,
  );

  mineUntil(rov(pox5.rewardCycleToBurnHeight(1n)) + HALF_CYCLE_LENGTH);
  txOk(pox5.calculateRewards([0n]), deployer);

  expect(rov(pox5.getEarned(signer, 1n, 0n))).toBe(0n);
  expect(rov(pox5.getSignerCycleMembership(alice, 1n))).toEqual({
    amountUstx: aliceUstx,
    signer,
  });
  expect(rov(pox5.getAmountDelegatedForSigner(signer, 1n))).toBe(aliceUstx);
});

// Skipped: Simnet's burn header hashes aren't real, so most of the L1 paths
// can't be covered in unit tests. These will be tested in integration tests.
test.skip('l1 early exit does not erase already accrued bond rewards', () => {
  const signer = testSigner.identifier;
  const aliceSats = 480000n;
  const targetRate = 1200n;

  registerSigner();

  txOk(
    pox5.setupBond({
      bondIndex: 0n,
      targetRate,
      stxValueRatio: 10n,
      minUstxRatio: 100n,
      earlyUnlockBytes: new Uint8Array(),
      allowlist: [{ maxSats: aliceSats, staker: alice }],
    }),
    deployer,
  );
  txOk(
    pox5.registerForBond({
      bondIndex: 0n,
      signerManager: signer,
      amountUstx: stxToUStx(50_000),
      btcLockup: ok({
        outputs: [
          buildL1Lockup({ staker: alice, sats: aliceSats, bondIndex: 0n }),
        ],
        stakerUnlockBytes: new Uint8Array(),
      }),
      signerCalldata: null,
    }),
    alice,
  );
  txOk(
    sbtc.transfer({
      recipient: pox5.identifier,
      amount: 1200n,
      sender: deployer,
      memo: null,
    }),
    deployer,
  );

  mineUntil(rov(pox5.rewardCycleToBurnHeight(1n)) + HALF_CYCLE_LENGTH);
  txOk(pox5.calculateRewards([0n]), deployer);

  const expectedRewards = bondTargetYieldPerCalculation({
    sats: aliceSats,
    targetRate,
  });
  expect(rov(pox5.getEarned(signer, 1n, 0n))).toBe(expectedRewards);
  txOk(pox5.announceL1EarlyExit(alice, signer), alice);

  expect(rov(pox5.getEarned(signer, 1n, 0n))).toBe(expectedRewards);
});

// TODO: Re-enabled once we can mock L1 proofs
test.skip('l1 early exit does not erase already accrued staker rewards', () => {
  const signer = testSigner.identifier;
  const aliceSats = 480000n;
  const targetRate = 1200n;

  registerSigner();

  txOk(
    pox5.setupBond({
      bondIndex: 0n,
      targetRate,
      stxValueRatio: 10n,
      minUstxRatio: 100n,
      earlyUnlockBytes: new Uint8Array(),
      allowlist: [{ maxSats: aliceSats, staker: alice }],
    }),
    deployer,
  );
  txOk(
    pox5.registerForBond({
      bondIndex: 0n,
      signerManager: signer,
      amountUstx: stxToUStx(50_000),
      btcLockup: ok({
        outputs: [
          buildL1Lockup({ staker: alice, sats: aliceSats, bondIndex: 0n }),
        ],
        stakerUnlockBytes: new Uint8Array(),
      }),
      signerCalldata: null,
    }),
    alice,
  );
  txOk(
    sbtc.transfer({
      recipient: pox5.identifier,
      amount: 1200n,
      sender: deployer,
      memo: null,
    }),
    deployer,
  );

  mineUntil(rov(pox5.rewardCycleToBurnHeight(1n)) + HALF_CYCLE_LENGTH);
  txOk(pox5.calculateRewards([0n]), deployer);

  txOk(pox5.announceL1EarlyExit(alice, signer), deployer);
  txOk(testSigner.claimRewards([0n], 1n), deployer);

  const expectedRewards = bondTargetYieldPerCalculation({
    sats: aliceSats,
    targetRate,
  });

  expect(rov(testSigner.getEarnedStakerRewards(alice, 1n, 0n))).toBe(
    expectedRewards,
  );
});

test('sbtc bond participant can partially unstake and only earns on remaining sats', () => {
  const signer = testSigner.identifier;
  const aliceSbtc = 480000n;
  const unstakedSbtc = 120000n;
  const targetRate = 1600n;

  registerSigner();

  txOk(
    pox5.setupBond({
      bondIndex: 0n,
      targetRate,
      stxValueRatio: 10n,
      minUstxRatio: 100n,
      earlyUnlockBytes: new Uint8Array(),
      allowlist: [{ maxSats: aliceSbtc, staker: alice }],
    }),
    deployer,
  );
  txOk(
    pox5.registerForBond({
      bondIndex: 0n,
      signerManager: signer,
      amountUstx: stxToUStx(50_000),
      btcLockup: err(aliceSbtc),
      signerCalldata: null,
    }),
    alice,
  );

  txOk(
    pox5.unstakeSbtc({
      signerManager: signer,
      amountToWithdrawalSats: unstakedSbtc,
    }),
    alice,
  );

  const remainingSbtc = aliceSbtc - unstakedSbtc;
  // The reduced sats must be reflected across every cycle of the bond
  // (bond-index 0 spans reward cycles [1, 13)), not just the first cycle.
  for (let cycle = 1n; cycle < 13n; cycle++) {
    expect(
      rov(pox5.getStakerSharesStakedForCycle(alice, cycle, 0n, signer)),
    ).toBe(remainingSbtc);
    expect(rov(pox5.getSignerSharesStakedForCycle(signer, cycle, 0n))).toBe(
      remainingSbtc,
    );
    expect(rov(pox5.getTotalSharesStakedForCycle(cycle, 0n))).toBe(
      remainingSbtc,
    );
  }
  expect(rov(pox5.getTotalSbtcStaked())).toBe(remainingSbtc);

  txOk(
    sbtc.transfer({
      recipient: pox5.identifier,
      amount: 1200n,
      sender: deployer,
      memo: null,
    }),
    deployer,
  );

  mineUntil(rov(pox5.rewardCycleToBurnHeight(1n)) + HALF_CYCLE_LENGTH);
  txOk(pox5.calculateRewards([0n]), deployer);

  expect(rov(pox5.getEarned(signer, 1n, 0n))).toBe(
    bondTargetYieldPerCalculation({ sats: remainingSbtc, targetRate }),
  );
});

test('sbtc unstake preserves already accrued rewards', () => {
  const signer = testSigner.identifier;
  const aliceSbtc = 480000n;
  const unstakedSbtc = 240000n;

  registerSigner();

  txOk(
    pox5.setupBond({
      bondIndex: 0n,
      targetRate: 1500n,
      stxValueRatio: 10n,
      minUstxRatio: 100n,
      earlyUnlockBytes: new Uint8Array(),
      allowlist: [{ maxSats: aliceSbtc, staker: alice }],
    }),
    deployer,
  );
  txOk(
    pox5.registerForBond({
      bondIndex: 0n,
      signerManager: signer,
      amountUstx: stxToUStx(50_000),
      btcLockup: err(aliceSbtc),
      signerCalldata: null,
    }),
    alice,
  );
  txOk(
    sbtc.transfer({
      recipient: pox5.identifier,
      amount: 1200n,
      sender: deployer,
      memo: null,
    }),
    deployer,
  );

  mineUntil(rov(pox5.rewardCycleToBurnHeight(1n)) + HALF_CYCLE_LENGTH);
  txOk(pox5.calculateRewards([0n]), deployer);
  expect(rov(pox5.getEarned(signer, 1n, 0n))).toBe(1200n);

  txOk(
    pox5.unstakeSbtc({
      signerManager: signer,
      amountToWithdrawalSats: unstakedSbtc,
    }),
    alice,
  );
  expect(rov(pox5.getEarned(signer, 1n, 0n))).toBe(1200n);

  txOk(
    sbtc.transfer({
      recipient: pox5.identifier,
      amount: 1200n,
      sender: deployer,
      memo: null,
    }),
    deployer,
  );
  mineUntil(rov(pox5.rewardCycleToBurnHeight(2n)));
  txOk(pox5.calculateRewards([0n]), deployer);

  expect(rov(pox5.getEarned(signer, 1n, 0n))).toBe(1920n);
});

test('sbtc full unstake preserves already accrued staker rewards', () => {
  const signer = testSigner.identifier;
  const aliceSbtc = 480000n;

  registerSigner();

  txOk(
    pox5.setupBond({
      bondIndex: 0n,
      targetRate: 1500n,
      stxValueRatio: 10n,
      minUstxRatio: 100n,
      earlyUnlockBytes: new Uint8Array(),
      allowlist: [{ maxSats: aliceSbtc, staker: alice }],
    }),
    deployer,
  );
  txOk(
    pox5.registerForBond({
      bondIndex: 0n,
      signerManager: signer,
      amountUstx: stxToUStx(50_000),
      btcLockup: err(aliceSbtc),
      signerCalldata: null,
    }),
    alice,
  );
  txOk(
    sbtc.transfer({
      recipient: pox5.identifier,
      amount: 1200n,
      sender: deployer,
      memo: null,
    }),
    deployer,
  );

  mineUntil(rov(pox5.rewardCycleToBurnHeight(1n)) + HALF_CYCLE_LENGTH);
  txOk(pox5.calculateRewards([0n]), deployer);
  txOk(testSigner.claimRewards([0n], 1n), deployer);

  txOk(
    pox5.unstakeSbtc({
      signerManager: signer,
      amountToWithdrawalSats: aliceSbtc,
    }),
    alice,
  );

  expect(rov(testSigner.getEarnedStakerRewards(alice, 1n, 0n))).toBe(1200n);
});

test('sbtc bond participant can fully unstake and stops earning bond rewards', () => {
  const signer = testSigner.identifier;
  const aliceSbtc = 480000n;

  registerSigner();

  txOk(
    pox5.setupBond({
      bondIndex: 0n,
      targetRate: 1200n,
      stxValueRatio: 10n,
      minUstxRatio: 100n,
      earlyUnlockBytes: new Uint8Array(),
      allowlist: [{ maxSats: aliceSbtc, staker: alice }],
    }),
    deployer,
  );
  txOk(
    pox5.registerForBond({
      bondIndex: 0n,
      signerManager: signer,
      amountUstx: stxToUStx(50_000),
      btcLockup: err(aliceSbtc),
      signerCalldata: null,
    }),
    alice,
  );

  txOk(
    pox5.unstakeSbtc({
      signerManager: signer,
      amountToWithdrawalSats: aliceSbtc,
    }),
    alice,
  );
  expect(rov(pox5.getStakerSharesStakedForCycle(alice, 1n, 0n, signer))).toBe(
    0n,
  );
  expect(rov(pox5.getTotalSbtcStaked())).toBe(0n);
  expect(rov(pox5.getAmountDelegatedForSigner(signer, 1n))).toBe(
    stxToUStx(50_000),
  );

  txOk(
    sbtc.transfer({
      recipient: pox5.identifier,
      amount: 1200n,
      sender: deployer,
      memo: null,
    }),
    deployer,
  );

  mineUntil(rov(pox5.rewardCycleToBurnHeight(1n)) + HALF_CYCLE_LENGTH);
  txOk(pox5.calculateRewards([0n]), deployer);

  expect(rov(pox5.getEarned(signer, 1n, 0n))).toBe(0n);
});

test('sbtc unstake rejects invalid signer and excess withdrawal', () => {
  const signer1 = testSigner.identifier;
  const signer2 = deployTestSigner('unstake-sbtc-invalid-signer-2').identifier;
  const aliceSbtc = 100000n;

  registerSigner();

  txOk(
    pox5.setupBond({
      bondIndex: 0n,
      targetRate: 1200n,
      stxValueRatio: 10n,
      minUstxRatio: 100n,
      earlyUnlockBytes: new Uint8Array(),
      allowlist: [{ maxSats: aliceSbtc, staker: alice }],
    }),
    deployer,
  );
  txOk(
    pox5.registerForBond({
      bondIndex: 0n,
      signerManager: signer1,
      amountUstx: stxToUStx(50_000),
      btcLockup: err(aliceSbtc),
      signerCalldata: null,
    }),
    alice,
  );

  expect(
    txErr(
      pox5.unstakeSbtc({
        signerManager: signer2,
        amountToWithdrawalSats: 1n,
      }),
      alice,
    ).value,
  ).toBe(errorCodes.ERR_INVALID_OLD_SIGNER_MANAGER);
  expect(
    txErr(
      pox5.unstakeSbtc({
        signerManager: signer1,
        amountToWithdrawalSats: aliceSbtc + 1n,
      }),
      alice,
    ).value,
  ).toBe(errorCodes.ERR_INVALID_UNSTAKE_SBTC_AMOUNT);
});

test('sbtc unstake returns withdrawn sats to the staker', () => {
  const signer = testSigner.identifier;
  const aliceSbtc = 100000n;
  const unstakedSbtc = 25000n;

  registerSigner();

  txOk(
    pox5.setupBond({
      bondIndex: 0n,
      targetRate: 1200n,
      stxValueRatio: 10n,
      minUstxRatio: 100n,
      earlyUnlockBytes: new Uint8Array(),
      allowlist: [{ maxSats: aliceSbtc, staker: alice }],
    }),
    deployer,
  );
  txOk(
    pox5.registerForBond({
      bondIndex: 0n,
      signerManager: signer,
      amountUstx: stxToUStx(50_000),
      btcLockup: err(aliceSbtc),
      signerCalldata: null,
    }),
    alice,
  );

  const aliceBalance = sbtcBalance(alice);
  const signerBalance = sbtcBalance(signer);
  const unstake = txOk(
    pox5.unstakeSbtc({
      signerManager: signer,
      amountToWithdrawalSats: unstakedSbtc,
    }),
    alice,
  );
  const [transferEvent] = filterEvents(
    unstake.events,
    CoreNodeEventType.FtTransferEvent,
  );

  expect(transferEvent.data.sender).toBe(pox5.identifier);
  expect(transferEvent.data.recipient).toBe(alice);
  expect(transferEvent.data.amount).toBe(unstakedSbtc.toString());
  expect(sbtcBalance(alice)).toBe(aliceBalance + unstakedSbtc);
  expect(sbtcBalance(signer)).toBe(signerBalance);
});

test('sbtc unstake reduces the per-bond total staked', () => {
  const signer = testSigner.identifier;
  const aliceSbtc = 100000n;
  const unstakedSbtc = 25000n;

  registerSigner();

  txOk(
    pox5.setupBond({
      bondIndex: 0n,
      targetRate: 1200n,
      stxValueRatio: 10n,
      minUstxRatio: 100n,
      earlyUnlockBytes: new Uint8Array(),
      allowlist: [{ maxSats: aliceSbtc, staker: alice }],
    }),
    deployer,
  );
  txOk(
    pox5.registerForBond({
      bondIndex: 0n,
      signerManager: signer,
      amountUstx: stxToUStx(50_000),
      btcLockup: err(aliceSbtc),
      signerCalldata: null,
    }),
    alice,
  );

  mineUntil(rov(pox5.rewardCycleToBurnHeight(2n)));

  expect(rov(pox5.getStakerSharesStakedForCycle(alice, 2n, 0n, signer))).toBe(
    aliceSbtc,
  );
  expect(rov(pox5.getTotalSbtcStakedForBond(0n))).toBe(aliceSbtc);

  txOk(
    pox5.unstakeSbtc({
      signerManager: signer,
      amountToWithdrawalSats: unstakedSbtc,
    }),
    alice,
  );

  expect(rov(pox5.getTotalSbtcStakedForBond(0n))).toBe(
    aliceSbtc - unstakedSbtc,
  );
  expect(rov(pox5.getStakerSharesStakedForCycle(alice, 2n, 0n, signer))).toBe(
    aliceSbtc - unstakedSbtc,
  );
});

/**
 * `unstake-sbtc` must work for a bond that has not started yet. This
 * test checks that all appropriate cycles are updated after unstaking.
 *
 * Concretely (cycle length 100, first-bond-cycle 1): bond-index 1 starts in
 * cycle 3 and ends in cycle 15. Unstaking in cycle 1 makes next-cycle 2 and
 * num-cycles = 15 - 2 = 13 > 12.
 */
test('sbtc bond participant can unstake before a later bond starts', () => {
  const signer = testSigner.identifier;
  const aliceSbtc = 100000n;
  const unstakedSbtc = 25000n;

  registerSigner();

  // bond-index 1 can only be set up once we're within 2 cycles of its start
  // (cycle 3), i.e. from cycle 1 onward.
  mineUntil(rov(pox5.rewardCycleToBurnHeight(1n)));
  expect(rov(pox5.currentPoxRewardCycle())).toBe(1n);

  txOk(
    pox5.setupBond({
      bondIndex: 1n,
      targetRate: 1200n,
      stxValueRatio: 10n,
      minUstxRatio: 100n,
      earlyUnlockBytes: new Uint8Array(),
      allowlist: [{ maxSats: aliceSbtc, staker: alice }],
    }),
    deployer,
  );
  txOk(
    pox5.registerForBond({
      bondIndex: 1n,
      signerManager: signer,
      amountUstx: stxToUStx(50_000),
      btcLockup: err(aliceSbtc),
      signerCalldata: null,
    }),
    alice,
  );

  const aliceBalance = sbtcBalance(alice);
  txOk(
    pox5.unstakeSbtc({
      signerManager: signer,
      amountToWithdrawalSats: unstakedSbtc,
    }),
    alice,
  );

  const remainingSbtc = aliceSbtc - unstakedSbtc;
  expect(sbtcBalance(alice)).toBe(aliceBalance + unstakedSbtc);
  // The remaining sats should be reflected across the bond's reward cycles
  // (cycle 3 is the bond's first reward cycle).
  expect(rov(pox5.getStakerSharesStakedForCycle(alice, 3n, 1n, signer))).toBe(
    remainingSbtc,
  );
  expect(rov(pox5.getTotalSbtcStaked())).toBe(remainingSbtc);
});

test('bond participant can update signer before bond starts', () => {
  const signer1 = testSigner.identifier;
  const signer2 = deployTestSigner(
    'bond-update-before-start-signer-2',
  ).identifier;
  const aliceSbtc = 100000n;
  const aliceUstx = stxToUStx(50_000);

  registerSigner();

  txOk(
    pox5.setupBond({
      bondIndex: 0n,
      targetRate: 1200n,
      stxValueRatio: 10n,
      minUstxRatio: 100n,
      earlyUnlockBytes: new Uint8Array(),
      allowlist: [{ maxSats: aliceSbtc, staker: alice }],
    }),
    deployer,
  );
  txOk(
    pox5.registerForBond({
      bondIndex: 0n,
      signerManager: signer1,
      amountUstx: aliceUstx,
      btcLockup: err(aliceSbtc),
      signerCalldata: null,
    }),
    alice,
  );

  txOk(
    pox5.updateBondRegistration({
      signerManager: signer2,
      signerCalldata: null,
      oldSignerManager: signer1,
    }),
    alice,
  );

  expect(rov(pox5.getSignerCycleMembership(alice, 1n))).toEqual({
    amountUstx: aliceUstx,
    signer: signer2,
  });
  expect(rov(pox5.getAmountDelegatedForSigner(signer1, 1n))).toBe(0n);
  expect(rov(pox5.getAmountDelegatedForSigner(signer2, 1n))).toBe(aliceUstx);
  expect(isSignerInCycle({ signer: signer1, cycle: 1n })).toBeFalsy();
  expect(isSignerInCycle({ signer: signer2, cycle: 1n })).toBeTruthy();

  // Because the update happened before the bond started, the cycle-scoped bond
  // sat shares must move entirely from signer1 to signer2 across all 12 bond
  // cycles (bond-index 0 spans reward cycles [1, 13)).
  for (let cycle = 1n; cycle < 13n; cycle++) {
    expect(
      rov(pox5.getStakerSharesStakedForCycle(alice, cycle, 0n, signer1)),
    ).toBe(0n);
    expect(rov(pox5.getSignerSharesStakedForCycle(signer1, cycle, 0n))).toBe(
      0n,
    );
    expect(
      rov(pox5.getStakerSharesStakedForCycle(alice, cycle, 0n, signer2)),
    ).toBe(aliceSbtc);
    expect(rov(pox5.getSignerSharesStakedForCycle(signer2, cycle, 0n))).toBe(
      aliceSbtc,
    );
    expect(rov(pox5.getTotalSharesStakedForCycle(cycle, 0n))).toBe(aliceSbtc);
  }
});

test('bond participant signer update changes signer set starting next cycle', () => {
  const signer1 = testSigner.identifier;
  const signer2 = deployTestSigner(
    'bond-update-mid-period-signer-2',
  ).identifier;
  const aliceSbtc = 100000n;
  const aliceUstx = stxToUStx(50_000);

  registerSigner();

  txOk(
    pox5.setupBond({
      bondIndex: 0n,
      targetRate: 1200n,
      stxValueRatio: 10n,
      minUstxRatio: 100n,
      earlyUnlockBytes: new Uint8Array(),
      allowlist: [{ maxSats: aliceSbtc, staker: alice }],
    }),
    deployer,
  );
  txOk(
    pox5.registerForBond({
      bondIndex: 0n,
      signerManager: signer1,
      amountUstx: aliceUstx,
      btcLockup: err(aliceSbtc),
      signerCalldata: null,
    }),
    alice,
  );

  expect(rov(pox5.getAmountDelegatedForSigner(signer1, 1n))).toBe(aliceUstx);
  expect(rov(pox5.getAmountDelegatedForSigner(signer1, 2n))).toBe(aliceUstx);
  expect(rov(pox5.getAmountDelegatedForSigner(signer2, 1n))).toBe(0n);
  expect(rov(pox5.getAmountDelegatedForSigner(signer2, 2n))).toBe(0n);
  expect(isSignerInCycle({ signer: signer1, cycle: 1n })).toBeTruthy();
  expect(isSignerInCycle({ signer: signer1, cycle: 2n })).toBeTruthy();
  expect(isSignerInCycle({ signer: signer2, cycle: 1n })).toBeFalsy();
  expect(isSignerInCycle({ signer: signer2, cycle: 2n })).toBeFalsy();

  mineUntil(rov(pox5.bondPeriodToBurnHeight(0n)) + 1n);

  txOk(
    pox5.updateBondRegistration({
      signerManager: signer2,
      signerCalldata: null,
      oldSignerManager: signer1,
    }),
    alice,
  );

  expect(rov(pox5.getSignerCycleMembership(alice, 1n))).toEqual({
    amountUstx: aliceUstx,
    signer: signer1,
  });
  expect(rov(pox5.getSignerCycleMembership(alice, 2n))).toEqual({
    amountUstx: aliceUstx,
    signer: signer2,
  });
  expect(rov(pox5.getSignerCycleMembership(alice, 3n))).toEqual({
    amountUstx: aliceUstx,
    signer: signer2,
  });
  expect(rov(pox5.getSignerCycleMembership(alice, 12n))).toEqual({
    amountUstx: aliceUstx,
    signer: signer2,
  });

  expect(rov(pox5.getAmountDelegatedForSigner(signer1, 1n))).toBe(aliceUstx);
  expect(rov(pox5.getAmountDelegatedForSigner(signer1, 2n))).toBe(0n);
  expect(rov(pox5.getAmountDelegatedForSigner(signer1, 3n))).toBe(0n);
  expect(rov(pox5.getAmountDelegatedForSigner(signer1, 12n))).toBe(0n);
  expect(rov(pox5.getAmountDelegatedForSigner(signer2, 2n))).toBe(aliceUstx);
  expect(rov(pox5.getAmountDelegatedForSigner(signer2, 3n))).toBe(aliceUstx);
  expect(rov(pox5.getAmountDelegatedForSigner(signer2, 12n))).toBe(aliceUstx);

  expect(rov(pox5.getUstxDelegatedForCycle(1n))).toBe(aliceUstx);
  expect(rov(pox5.getUstxDelegatedForCycle(2n))).toBe(aliceUstx);
  expect(rov(pox5.getUstxDelegatedForCycle(12n))).toBe(aliceUstx);

  expect(isSignerInCycle({ signer: signer1, cycle: 1n })).toBeTruthy();
  expect(isSignerInCycle({ signer: signer1, cycle: 2n })).toBeFalsy();
  expect(isSignerInCycle({ signer: signer1, cycle: 12n })).toBeFalsy();
  expect(isSignerInCycle({ signer: signer2, cycle: 1n })).toBeFalsy();
  expect(isSignerInCycle({ signer: signer2, cycle: 2n })).toBeTruthy();
  expect(isSignerInCycle({ signer: signer2, cycle: 12n })).toBeTruthy();
});

test('bond participant rewards follow updated signer', () => {
  const signer1 = testSigner.identifier;
  const signer2 = deployTestSigner('bond-update-reward-signer-2').identifier;
  const aliceSbtc = 400000n;

  registerSigner();

  txOk(
    pox5.setupBond({
      bondIndex: 0n,
      targetRate: 1500n,
      stxValueRatio: 10n,
      minUstxRatio: 100n,
      earlyUnlockBytes: new Uint8Array(),
      allowlist: [{ maxSats: aliceSbtc, staker: alice }],
    }),
    deployer,
  );
  txOk(
    pox5.registerForBond({
      bondIndex: 0n,
      signerManager: signer1,
      amountUstx: stxToUStx(50_000),
      btcLockup: err(aliceSbtc),
      signerCalldata: null,
    }),
    alice,
  );
  txOk(
    pox5.updateBondRegistration({
      signerManager: signer2,
      signerCalldata: null,
      oldSignerManager: signer1,
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

  mineUntil(rov(pox5.rewardCycleToBurnHeight(1n)) + HALF_CYCLE_LENGTH);
  txOk(pox5.calculateRewards([0n]), deployer);

  expect(rov(pox5.getEarned(signer1, 1n, 0n))).toBe(0n);
  expect(rov(pox5.getEarned(signer2, 1n, 0n))).toBe(1000n);
});

test('bond signer update preserves old signer rewards and sends future rewards to new signer', () => {
  const signer1 = testSigner.identifier;
  const signer2 = deployTestSigner('bond-update-accrued-signer-2').identifier;
  const aliceSbtc = 480000n;

  registerSigner();

  txOk(
    pox5.setupBond({
      bondIndex: 0n,
      targetRate: 1500n,
      stxValueRatio: 10n,
      minUstxRatio: 100n,
      earlyUnlockBytes: new Uint8Array(),
      allowlist: [{ maxSats: aliceSbtc, staker: alice }],
    }),
    deployer,
  );
  txOk(
    pox5.registerForBond({
      bondIndex: 0n,
      signerManager: signer1,
      amountUstx: stxToUStx(50_000),
      btcLockup: err(aliceSbtc),
      signerCalldata: null,
    }),
    alice,
  );
  txOk(
    sbtc.transfer({
      recipient: pox5.identifier,
      amount: 1200n,
      sender: deployer,
      memo: null,
    }),
    deployer,
  );

  mineUntil(rov(pox5.rewardCycleToBurnHeight(1n)) + HALF_CYCLE_LENGTH);
  txOk(pox5.calculateRewards([0n]), deployer);
  expect(rov(pox5.getEarned(signer1, 1n, 0n))).toBe(1200n);

  txOk(
    pox5.updateBondRegistration({
      signerManager: signer2,
      signerCalldata: null,
      oldSignerManager: signer1,
    }),
    alice,
  );
  expect(rov(pox5.getEarned(signer1, 1n, 0n))).toBe(1200n);
  expect(rov(pox5.getEarned(signer2, 1n, 0n))).toBe(0n);

  txOk(
    sbtc.transfer({
      recipient: pox5.identifier,
      amount: 1200n,
      sender: deployer,
      memo: null,
    }),
    deployer,
  );
  mineUntil(rov(pox5.rewardCycleToBurnHeight(2n)));
  txOk(pox5.calculateRewards([0n]), deployer);

  expect(rov(pox5.getEarned(signer1, 1n, 0n))).toBe(2400n);
  expect(rov(pox5.getEarned(signer2, 1n, 0n))).toBe(0n);
});

test('bond signer update keeps current-cycle uncrystallized rewards with old signer', () => {
  const signer1 = testSigner.identifier;
  const signer2 = deployTestSigner(
    'bond-update-current-cycle-signer-2',
  ).identifier;
  const aliceSbtc = 480000n;

  registerSigner();

  txOk(
    pox5.setupBond({
      bondIndex: 0n,
      targetRate: 1500n,
      stxValueRatio: 10n,
      minUstxRatio: 100n,
      earlyUnlockBytes: new Uint8Array(),
      allowlist: [{ maxSats: aliceSbtc, staker: alice }],
    }),
    deployer,
  );
  txOk(
    pox5.registerForBond({
      bondIndex: 0n,
      signerManager: signer1,
      amountUstx: stxToUStx(50_000),
      btcLockup: err(aliceSbtc),
      signerCalldata: null,
    }),
    alice,
  );

  mineUntil(rov(pox5.rewardCycleToBurnHeight(1n)) + 1n);
  txOk(
    pox5.updateBondRegistration({
      signerManager: signer2,
      signerCalldata: null,
      oldSignerManager: signer1,
    }),
    alice,
  );
  txOk(
    sbtc.transfer({
      recipient: pox5.identifier,
      amount: 1200n,
      sender: deployer,
      memo: null,
    }),
    deployer,
  );

  mineUntil(rov(pox5.rewardCycleToBurnHeight(1n)) + HALF_CYCLE_LENGTH);
  txOk(pox5.calculateRewards([0n]), deployer);

  expect(rov(pox5.getSignerCycleMembership(alice, 1n))).toEqual({
    amountUstx: stxToUStx(50_000),
    signer: signer1,
  });
  expect(rov(pox5.getSignerCycleMembership(alice, 2n))).toEqual({
    amountUstx: stxToUStx(50_000),
    signer: signer2,
  });
  expect(rov(pox5.getEarned(signer1, 1n, 0n))).toBe(1200n);
  expect(rov(pox5.getEarned(signer2, 1n, 0n))).toBe(0n);
});

test('bond staker can update signer and fully unstake sbtc in the same cycle', () => {
  const signer1 = testSigner.identifier;
  const signer2 = deployTestSigner(
    'bond-update-then-unstake-signer-2',
  ).identifier;
  const aliceSbtc = 480000n;

  registerSigner();

  txOk(
    pox5.setupBond({
      bondIndex: 0n,
      targetRate: 1500n,
      stxValueRatio: 10n,
      minUstxRatio: 100n,
      earlyUnlockBytes: new Uint8Array(),
      allowlist: [{ maxSats: aliceSbtc, staker: alice }],
    }),
    deployer,
  );
  txOk(
    pox5.registerForBond({
      bondIndex: 0n,
      signerManager: signer1,
      amountUstx: stxToUStx(50_000),
      btcLockup: err(aliceSbtc),
      signerCalldata: null,
    }),
    alice,
  );

  sbtcTransfer(1200n, deployer, pox5.identifier);
  mineUntil(rov(pox5.rewardCycleToBurnHeight(1n)) + 1n);
  txOk(
    pox5.updateBondRegistration({
      signerManager: signer2,
      oldSignerManager: signer1,
      signerCalldata: null,
    }),
    alice,
  );
  txOk(
    pox5.unstakeSbtc({
      signerManager: signer2,
      amountToWithdrawalSats: aliceSbtc,
    }),
    alice,
  );
  mineUntil(rov(pox5.rewardCycleToBurnHeight(1n)) + HALF_CYCLE_LENGTH);
  txOk(pox5.calculateRewards([0n]), deployer);

  expect(rov(pox5.getTotalSbtcStaked())).toBe(0n);
  expect(rov(pox5.getEarned(signer1, 1n, 0n))).toBe(0n);
  expect(rov(pox5.getEarned(signer2, 1n, 0n))).toBe(0n);
});

/**
 * Regression: changing signer for an active bond must not let the staker
 * double-collect already-distributed bond rewards on the new signer. Before
 * the fix, `update-bond-registration` did not settle the staker's per-token
 * snapshot for the new signer, so the new signer's `rpt-paid` defaulted to 0
 * while shares were copied over. The staker's earned-on-new-signer would
 * then equal `shares * (rpt-current - 0) / PRECISION` — a duplicate of the
 * rewards already accrued on the old signer.
 */
test('bond signer update does not duplicate staker rewards on new signer', () => {
  const signer1 = testSigner.identifier;
  const signer2Contract = deployTestSigner('bond-update-dup-signer-2');
  const signer2 = signer2Contract.identifier;
  const aliceSbtc = 480000n;

  registerSigner();

  txOk(
    pox5.setupBond({
      bondIndex: 0n,
      targetRate: 1500n,
      stxValueRatio: 10n,
      minUstxRatio: 100n,
      earlyUnlockBytes: new Uint8Array(),
      allowlist: [{ maxSats: aliceSbtc, staker: alice }],
    }),
    deployer,
  );
  txOk(
    pox5.registerForBond({
      bondIndex: 0n,
      signerManager: signer1,
      amountUstx: stxToUStx(50_000),
      btcLockup: err(aliceSbtc),
      signerCalldata: null,
    }),
    alice,
  );
  txOk(
    sbtc.transfer({
      recipient: pox5.identifier,
      amount: 1200n,
      sender: deployer,
      memo: null,
    }),
    deployer,
  );

  mineUntil(rov(pox5.rewardCycleToBurnHeight(1n)) + HALF_CYCLE_LENGTH);
  txOk(pox5.calculateRewards([0n]), deployer);

  txOk(
    pox5.updateBondRegistration({
      signerManager: signer2,
      signerCalldata: null,
      oldSignerManager: signer1,
    }),
    alice,
  );

  // Alice has already accrued the entire 1200 on signer1. Switching signers
  // before claiming should not create a phantom claimable balance on signer2.
  expect(rov(testSigner.getEarnedStakerRewards(alice, 1n, 0n))).toBe(1200n);
  expect(rov(signer2Contract.getEarnedStakerRewards(alice, 1n, 0n))).toBe(0n);
});

test('destination signer baseline is initialized when bond staker switches signers', () => {
  const bondIndex = 0n;
  const signerA = testSigner.identifier;
  const signerBContract = deployTestSigner('c4-destination-signer');
  const signerB = signerBContract.identifier;
  const attackerSats = 2_000_000n;
  const honestSats = 6_000_000n;

  registerSigner();

  txOk(
    pox5.setupBond({
      bondIndex,
      targetRate: 1200n,
      stxValueRatio: 10n,
      minUstxRatio: 100n,
      earlyUnlockBytes: new Uint8Array(),
      allowlist: [
        { maxSats: attackerSats, staker: alice },
        { maxSats: honestSats, staker: bob },
      ],
    }),
    deployer,
  );
  txOk(
    pox5.registerForBond({
      bondIndex,
      signerManager: signerB,
      amountUstx: stxToUStx(50_000),
      btcLockup: err(honestSats),
      signerCalldata: null,
    }),
    bob,
  );
  txOk(
    pox5.registerForBond({
      bondIndex,
      signerManager: signerA,
      amountUstx: stxToUStx(50_000),
      btcLockup: err(attackerSats),
      signerCalldata: null,
    }),
    alice,
  );

  sbtcTransfer(1_000_000_000n, deployer, pox5.identifier);
  mineUntil(rov(pox5.rewardCycleToBurnHeight(1n)) + HALF_CYCLE_LENGTH);
  txOk(pox5.calculateRewards([bondIndex]), deployer);

  const bondRewardsPerToken = rov(
    pox5.getRewardsPerTokenForCycle(1n, bondIndex),
  );
  expect(bondRewardsPerToken).toBeGreaterThan(0n);

  txOk(signerBContract.claimRewards([bondIndex], 1n), deployer);
  expect(
    rov(pox5.getSignerRewardsPerTokenForCycle(signerB, 1n, bondIndex)),
  ).toBe(bondRewardsPerToken);

  const exploitCredit =
    (attackerSats * bondRewardsPerToken) / pox5.constants.PRECISION;
  expect(exploitCredit).toBeGreaterThan(0n);
  expect(
    rov(signerBContract.getEarnedStakerRewards(alice, 1n, bondIndex)),
  ).toBe(0n);

  txOk(
    pox5.updateBondRegistration({
      signerManager: signerB,
      oldSignerManager: signerA,
      signerCalldata: null,
    }),
    alice,
  );

  expect(
    rov(pox5.getStakerSharesStakedForCycle(alice, 1n, bondIndex, signerB)),
  ).toBe(0n);
  expect(
    rov(pox5.getStakerSharesStakedForCycle(alice, 1n, bondIndex, signerA)),
  ).toBe(attackerSats);
  expect(
    rov(
      pox5.getStakerRewardsPerTokenSettledForCycle(
        signerB,
        1n,
        bondIndex,
        alice,
      ),
    ),
  ).toBe(bondRewardsPerToken);
  expect(
    rov(signerBContract.getEarnedStakerRewards(alice, 1n, bondIndex)),
  ).toBe(0n);
  expect(
    txErr(signerBContract.claimStakerRewards(1n, bondIndex), alice).value,
  ).toBe(testSignerErrors.ERR_NO_CLAIMABLE_REWARDS);
});

/**
 * Claims all available STX-only rewards, then verifies a second zero-reward
 * claim fails without resetting the signer's paid reward accounting.
 */
test('zero reward claim should not reset paid rewards', () => {
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

  mineUntil(rov(pox5.rewardCycleToBurnHeight(1n)) + HALF_CYCLE_LENGTH);
  txOk(pox5.calculateRewards([]), deployer);

  const expectedRewards = stxRewards(1000n);
  expect(rov(pox5.getEarned(signer, 1n, null))).toBe(expectedRewards);
  const claim = txOk(testSigner.claimRewards([], 1n), deployer);
  const [ftTransfer] = filterEvents(
    claim.events,
    CoreNodeEventType.FtTransferEvent,
  );
  expect(ftTransfer.data.sender).toBe(pox5.identifier);
  expect(ftTransfer.data.recipient).toBe(signer);
  expect(ftTransfer.data.amount).toBe(expectedRewards.toString());

  const zeroClaim = txErr(testSigner.claimRewards([], 1n), deployer);
  expect(zeroClaim.value).toBe(errorCodes.ERR_NO_CLAIMABLE_REWARDS);
});

test('signer can claim rewards accrued across multiple calculations', () => {
  const signer = testSigner.identifier;
  const stakeAmount = stxToUStx(50_000);

  registerSigner();
  txOk(
    pox5.stake({
      signerManager: signer,
      amountUstx: stakeAmount,
      numCycles: 3n,
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
  mineUntil(rov(pox5.rewardCycleToBurnHeight(1n)) + HALF_CYCLE_LENGTH);
  txOk(pox5.calculateRewards([]), deployer);

  txOk(
    sbtc.transfer({
      recipient: pox5.identifier,
      amount: 1000n,
      sender: deployer,
      memo: null,
    }),
    deployer,
  );
  mineUntil(rov(pox5.rewardCycleToBurnHeight(2n)));
  txOk(pox5.calculateRewards([]), deployer);

  const expectedRewards = stxRewards(2000n);
  expect(rov(pox5.getEarned(signer, 1n, null))).toBe(expectedRewards);
  expect(
    txOk(testSigner.claimRewards([], 1n), deployer).value.totalRewards,
  ).toBe(expectedRewards);
});

/** Scenario: waterfall distributions
 *
 * - Alice and Bob are in bond period 1
 * - Alice for 50k sats
 * - Bob for 100k sats
 *
 * - Charlie is stx-only staking for 14 cycles with 10k stx
 * - Dave is stx-only staking for 14 cycles with 5k stx
 */
test('scenario - waterfall distributions', () => {
  const signer = testSigner.identifier;
  registerSigner();

  const minUstxRatio = 100n; // 1%
  const stxValueRatio = 10n; // 10 ustx = 100 sat
  const targetRate = 1000n; // 10%
  const aliceSbtc = 50000n;
  const bobSbtc = 100000n;

  const totalSbtcPeriod1 = aliceSbtc + bobSbtc;
  const perRewardCalcYieldPeriod1 = bondTargetYieldPerCalculation({
    sats: totalSbtcPeriod1,
    targetRate,
  });

  txOk(
    pox5.setupBond({
      bondIndex: 0n,
      targetRate,
      stxValueRatio,
      minUstxRatio,
      earlyUnlockBytes: new Uint8Array(),
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

  const aliceUstx = rov(
    pox5.minUstxForSatsAmount(aliceSbtc, stxValueRatio, minUstxRatio),
  );

  txOk(
    pox5.registerForBond({
      bondIndex: 0n,
      signerManager: signer,
      amountUstx: aliceUstx,
      btcLockup: err(aliceSbtc),
      signerCalldata: null,
    }),
    alice,
  );

  const bobUstx = rov(
    pox5.minUstxForSatsAmount(bobSbtc, stxValueRatio, minUstxRatio),
  );
  // sanity check
  expect(bobUstx).toBeGreaterThan(0n);

  txOk(
    pox5.registerForBond({
      bondIndex: 0n,
      signerManager: signer,
      amountUstx: bobUstx,
      btcLockup: err(bobSbtc),
      signerCalldata: null,
    }),
    bob,
  );

  expect(rov(pox5.getTotalSbtcStakedForBond(0n))).toBe(aliceSbtc + bobSbtc);

  const charlieStake = stxToUStx(25_000);
  const daveStake = stxToUStx(50_000);

  // charlie stakes stx for 14 cycles
  txOk(
    pox5.stake({
      signerManager: signer,
      amountUstx: charlieStake,
      numCycles: 14n,
      startBurnHt: simnet.burnBlockHeight,
      signerCalldata: null,
    }),
    charlie,
  );

  // Signer should not have any reward shares yet!
  expect(rov(pox5.getSignerSharesStakedForCycle(signer, 1n, null))).toBe(0n);

  // dave stakes stx for 14 cycles
  txOk(
    pox5.stake({
      signerManager: signer,
      amountUstx: daveStake,
      numCycles: 14n,
      startBurnHt: simnet.burnBlockHeight,
      signerCalldata: null,
    }),
    dave,
  );

  // now, signer should have reward shares, since they're over the min ustx threshold
  expect(rov(pox5.getSignerSharesStakedForCycle(signer, 1n, null))).toBe(
    charlieStake + daveStake,
  );

  // verify shares state
  expect(rov(pox5.getTotalSharesStakedForCycle(1n, 0n))).toBe(
    aliceSbtc + bobSbtc,
  );
  expect(rov(pox5.getSignerSharesStakedForCycle(signer, 1n, 0n))).toBe(
    aliceSbtc + bobSbtc,
  );
  expect(rov(pox5.getTotalSharesStakedForCycle(1n, null))).toBe(
    charlieStake + daveStake,
  );
  expect(rov(pox5.getSignerSharesStakedForCycle(signer, 1n, null))).toBe(
    charlieStake + daveStake,
  );

  expect(rov(pox5.getAmountDelegatedForSigner(signer, 1n))).toBe(
    charlieStake + daveStake + aliceUstx + bobUstx,
  );

  // fast forward to start of cycle 1
  mineUntil(rov(pox5.rewardCycleToBurnHeight(1n)));

  // let's send enough rewards to cover the expected yield for period 1,
  // plus 100 sats for stakers
  const extra1 = 100n;

  txOk(
    sbtc.transfer({
      recipient: pox5.identifier,
      amount: perRewardCalcYieldPeriod1 + extra1,
      sender: deployer,
      memo: null,
    }),
    deployer,
  );

  expect(sbtcBalance(pox5.identifier)).toBe(
    perRewardCalcYieldPeriod1 + extra1 + aliceSbtc + bobSbtc,
  );

  mineUntil(rov(pox5.rewardCycleToBurnHeight(1n)) + HALF_CYCLE_LENGTH);

  expect(rov(pox5.currentDistributionCycle())).toBe(3n);
  expect(rov(pox5.distributionCycleToBurnHeight(3n))).toBe(
    rov(pox5.rewardCycleToBurnHeight(1n)) + HALF_CYCLE_LENGTH,
  );

  // cannot provide bonds that don't exist
  txErr(pox5.calculateRewards([1n]), deployer);

  // check state before writing new rewards state
  expect(rov(pox5.getRewards())).toBe(perRewardCalcYieldPeriod1 + extra1);

  // calculate rewards
  txOk(pox5.calculateRewards([0n]), deployer);

  // We expect that bond1 earned their full expected yield
  const rewardsPerToken = rov(pox5.getRewardsPerTokenForCycle(1n, 0n));
  expect(
    (rewardsPerToken * (aliceSbtc + bobSbtc)) / pox5.constants.PRECISION,
  ).toBe(perRewardCalcYieldPeriod1);

  // time of last calculation should be updated
  expect(rov(pox5.getLastRewardComputeHeight())).toBe(
    BigInt(simnet.burnBlockHeight - 1),
  );

  expect(rov(pox5.getReserveBalance())).toBe(reserveRewards(extra1));

  const rewardsPerUstx = rov(pox5.getRewardsPerTokenForCycle(1n, null));
  const totalStakedUstx = rov(
    pox5.getSignerSharesStakedForCycle(signer, 1n, null),
  );
  const rewardsForStxStakers = stxRewards(extra1);
  const claimableRewardsForStxStakers = claimableRewards({
    rewards: rewardsForStxStakers,
    shares: totalStakedUstx,
    totalShares: totalStakedUstx,
  });
  expect(totalStakedUstx).toBe(charlieStake + daveStake);
  // expect all extra rewards to be distributed to stx stakers
  expect(rewardsPerUstx).toBe(
    (rewardsForStxStakers * pox5.constants.PRECISION) / totalStakedUstx,
  );

  // we only have one signer, so they get all rewards
  expect(rov(pox5.getEarned(signer, 1n, null))).toBe(
    claimableRewardsForStxStakers,
  );
  expect(rov(pox5.getEarned(signer, 1n, 0n))).toBe(perRewardCalcYieldPeriod1);

  // cant call again until next distribution cycle
  txErr(pox5.calculateRewards([0n]), deployer);

  // give some new rewards
  const rewards2 = perRewardCalcYieldPeriod1 + extra1;
  txOk(
    sbtc.transfer({
      recipient: pox5.identifier,
      amount: rewards2,
      sender: deployer,
      memo: null,
    }),
    deployer,
  );

  // set up a new signer
  const signer2Contract = deployTestSigner('signer2');
  const signer2 = signer2Contract.identifier;

  // now emily stakes equal to charlie and dave stx
  const emilyStake = charlieStake + daveStake;
  txOk(
    pox5.stake({
      signerManager: signer2,
      amountUstx: emilyStake,
      numCycles: 14n,
      startBurnHt: simnet.burnBlockHeight,
      signerCalldata: null,
    }),
    emily,
  );

  expect(rov(pox5.getSignerSharesStakedForCycle(signer2, 2n, null))).toBe(
    emilyStake,
  );
  expect(rov(pox5.getSignerSharesStakedForCycle(signer2, 2n, null))).toBe(
    rov(pox5.getTotalSharesStakedForCycle(2n, null)) / 2n,
  );

  expect(rov(pox5.getNewRewards())).toBe(rewards2);

  // mine through next distribution cycle
  mineUntil(rov(pox5.rewardCycleToBurnHeight(2n)));

  txOk(pox5.calculateRewards([0n]), deployer);

  // now, signer 1 still is the only one who can claim rewards
  expect(rov(pox5.getEarned(signer, 1n, null))).toBe(
    claimableRewards({
      rewards: rewardsForStxStakers * 2n,
      shares: totalStakedUstx,
      totalShares: totalStakedUstx,
    }),
  );
  expect(rov(pox5.getEarned(signer, 1n, 0n))).toBe(
    perRewardCalcYieldPeriod1 * 2n,
  );
  expect(rov(pox5.getEarned(signer2, 1n, null))).toBe(0n);
  // no one has rewards for the next cycle yet
  expect(rov(pox5.getEarned(signer, 2n, null))).toBe(0n);

  const previousTotalRewards = rov(pox5.getLastAccountedRewardsOnly());
  const previousReserveBalance = rov(pox5.getReserveBalance());

  const extra2 = 1000n;
  txOk(
    sbtc.transfer({
      recipient: pox5.identifier,
      amount: perRewardCalcYieldPeriod1 + extra2,
      sender: deployer,
      memo: null,
    }),
    deployer,
  );

  mineUntil(rov(pox5.rewardCycleToBurnHeight(2n)) + HALF_CYCLE_LENGTH);

  txOk(pox5.calculateRewards([0n]), deployer);

  expect(rov(pox5.getLastAccountedRewardsOnly())).toBe(
    previousTotalRewards +
      perRewardCalcYieldPeriod1 +
      extra2 -
      (rov(pox5.getReserveBalance()) - previousReserveBalance),
  );

  // now, signer 2 should be able to claim the same
  // amount of rewards as signer 1
  expect(rov(pox5.getEarned(signer2, 2n, null))).toBe(
    rov(pox5.getEarned(signer, 2n, null)),
  );
  expect(rov(pox5.getEarned(signer, 1n, 0n))).toBe(
    perRewardCalcYieldPeriod1 * 2n,
  );
  expect(rov(pox5.getEarned(signer, 2n, 0n))).toBe(perRewardCalcYieldPeriod1);
  // new signer still can't claim for the next cycle, of course.
  expect(rov(pox5.getEarned(signer2, 1n, null))).toBe(0n);

  const signer2Claimable = rov(pox5.getEarned(signer2, 2n, null));
  const signer2Claim = txOk(signer2Contract.claimRewards([], 2n), deployer);
  const transferEvents = filterEvents(
    signer2Claim.events,
    CoreNodeEventType.FtTransferEvent,
  );
  expect(transferEvents).toHaveLength(1);
  expect(transferEvents[0]!.data.recipient).toBe(signer2);
  expect(transferEvents[0]!.data.amount).toBe(signer2Claimable.toString());
  expect(transferEvents[0]!.data.sender).toBe(pox5.identifier);
});

/**
 * Verifies that the active-bond inclusion check requires every active bond
 * period to be present, including setup bonds that have zero bonded sats.
 */
test('validating that all active bonds are included in a list at a given height', () => {
  function setupBond(bondIndex: bigint) {
    txOk(
      pox5.setupBond({
        bondIndex: bondIndex,
        targetRate: 1200n,
        stxValueRatio: 10n,
        minUstxRatio: 100n,
        earlyUnlockBytes: new Uint8Array(),
        allowlist: [{ maxSats: 100000n, staker: alice }],
      }),
      deployer,
    );
  }

  setupBond(0n);
  mineUntil(rov(pox5.bondPeriodToBurnHeight(0n)) + 1n);
  setupBond(1n);
  mineUntil(rov(pox5.bondPeriodToBurnHeight(1n)) + 1n);
  setupBond(2n);

  expect(rov(pox5.isBondActiveAtHeight(0n, 99n))).toBeFalsy();
  expect(rovOk(pox5.assertAllActiveBondsIncluded([], 99n))).toBeTruthy();

  expect(rov(pox5.isBondActiveAtHeight(0n, 150n))).toBeTruthy();
  expect(rov(pox5.isBondActiveAtHeight(1n, 150n))).toBeFalsy();
  expect(rovOk(pox5.assertAllActiveBondsIncluded([0n], 150n))).toBeTruthy();
  expect(rovOk(pox5.assertAllActiveBondsIncluded([0n, 1n], 150n))).toBeTruthy();
  expect(rovErr(pox5.assertAllActiveBondsIncluded([], 150n))).toBe(
    errorCodes.ERR_ACTIVE_BOND_NOT_INCLUDED,
  );

  expect(rov(pox5.isBondActiveAtHeight(0n, 350n))).toBeTruthy();
  expect(rov(pox5.isBondActiveAtHeight(1n, 350n))).toBeTruthy();
  expect(rov(pox5.isBondActiveAtHeight(2n, 350n))).toBeFalsy();
  expect(rovOk(pox5.assertAllActiveBondsIncluded([0n, 1n], 350n))).toBeTruthy();
  expect(rovErr(pox5.assertAllActiveBondsIncluded([0n], 350n))).toBe(
    errorCodes.ERR_ACTIVE_BOND_NOT_INCLUDED,
  );
  expect(rovErr(pox5.assertAllActiveBondsIncluded([1n], 350n))).toBe(
    errorCodes.ERR_ACTIVE_BOND_NOT_INCLUDED,
  );

  expect(rov(pox5.isBondActiveAtHeight(0n, 550n))).toBeTruthy();
  expect(rov(pox5.isBondActiveAtHeight(1n, 550n))).toBeTruthy();
  expect(rov(pox5.isBondActiveAtHeight(2n, 550n))).toBeTruthy();
  expect(
    rovOk(pox5.assertAllActiveBondsIncluded([0n, 1n, 2n], 550n)),
  ).toBeTruthy();
  expect(rovErr(pox5.assertAllActiveBondsIncluded([0n, 2n], 550n))).toBe(
    errorCodes.ERR_ACTIVE_BOND_NOT_INCLUDED,
  );
});

/**
 * Calling `update-bond-registration` with the same signer for old and new
 * should be a clean rejection.
 */
test('update-bond-registration is a no-op when old and new signer are the same', () => {
  const signer = testSigner.identifier;
  const aliceSbtc = 100000n;

  registerSigner();

  txOk(
    pox5.setupBond({
      bondIndex: 0n,
      targetRate: 1200n,
      stxValueRatio: 10n,
      minUstxRatio: 100n,
      earlyUnlockBytes: new Uint8Array(),
      allowlist: [{ maxSats: aliceSbtc, staker: alice }],
    }),
    deployer,
  );
  txOk(
    pox5.registerForBond({
      bondIndex: 0n,
      signerManager: signer,
      amountUstx: stxToUStx(50_000),
      btcLockup: err(aliceSbtc),
      signerCalldata: null,
    }),
    alice,
  );

  expect(rov(pox5.getSignerSharesStakedForCycle(signer, 1n, 0n))).toBe(
    aliceSbtc,
  );
  expect(rov(pox5.getStakerSharesStakedForCycle(alice, 1n, 0n, signer))).toBe(
    aliceSbtc,
  );

  const errUpdate = txErr(
    pox5.updateBondRegistration({
      signerManager: signer,
      oldSignerManager: signer,
      signerCalldata: null,
    }),
    alice,
  );
  expect(errUpdate.value).toBe(pox5Errors.ERR_UPDATE_BOND_SAME_SIGNER);

  // Shares must not have grown.
  expect(rov(pox5.getSignerSharesStakedForCycle(signer, 1n, 0n))).toBe(
    aliceSbtc,
  );
  expect(rov(pox5.getStakerSharesStakedForCycle(alice, 1n, 0n, signer))).toBe(
    aliceSbtc,
  );
});

/**
 * `register-for-bond` should reject participants once the bond period has
 * started.
 */
test('register-for-bond rejects registration after bond starts', () => {
  const signer = testSigner.identifier;
  const aliceSbtc = 100000n;

  registerSigner();

  txOk(
    pox5.setupBond({
      bondIndex: 0n,
      targetRate: 1200n,
      stxValueRatio: 10n,
      minUstxRatio: 100n,
      earlyUnlockBytes: new Uint8Array(),
      allowlist: [{ maxSats: aliceSbtc, staker: alice }],
    }),
    deployer,
  );

  // Move into the middle of the bond period (cycle 5 of 12).
  mineUntil(rov(pox5.rewardCycleToBurnHeight(5n)));

  // The bond has been live for several cycles. Registration into a past
  // cycle should fail.
  const register = txErr(
    pox5.registerForBond({
      bondIndex: 0n,
      signerManager: signer,
      amountUstx: stxToUStx(50_000),
      btcLockup: err(aliceSbtc),
      signerCalldata: null,
    }),
    alice,
  );
  expect(register.value).toBe(pox5Errors.ERR_BOND_ALREADY_STARTED);
});

test('register-for-bond rejects existing stx-only stakers', () => {
  const signer = testSigner.identifier;
  const aliceSbtc = 100000n;

  registerSigner();

  txOk(
    pox5.stake({
      signerManager: signer,
      amountUstx: stxToUStx(50_000),
      numCycles: 6n,
      startBurnHt: simnet.burnBlockHeight,
      signerCalldata: null,
    }),
    alice,
  );

  txOk(
    pox5.setupBond({
      bondIndex: 0n,
      targetRate: 1200n,
      stxValueRatio: 10n,
      minUstxRatio: 100n,
      earlyUnlockBytes: new Uint8Array(),
      allowlist: [{ maxSats: aliceSbtc, staker: alice }],
    }),
    deployer,
  );

  const register = txErr(
    pox5.registerForBond({
      bondIndex: 0n,
      signerManager: signer,
      amountUstx: stxToUStx(50_000),
      btcLockup: err(aliceSbtc),
      signerCalldata: null,
    }),
    alice,
  );
  expect(register.value).toEqual(pox5Errors.ERR_ALREADY_STAKED);
});

/**
 * Stake-to-bond rollover: an STX-only staker with a long stake can `unstake`
 * to shorten the term to the start of the next reward cycle, and then
 * immediately `register-for-bond` for a bond whose first cycle is at or
 * after that shortened term. The new gate allows non-overlapping rollover,
 * the node-side handler extends the existing STX lock (no fresh lock, no
 * release between stake and bond), and the staker-info entry is cleared so
 * the old stake can no longer be touched via `stake-update` / `unstake`.
 */
test('STX-only staker can unstake and roll into a bond on the same cycle', () => {
  const signer = testSigner.identifier;
  const stakeAmount = stxToUStx(50_000);
  const bondSbtc = 100000n;
  registerSigner({ caller: deployer });

  // Alice stakes STX-only with a long term: first=1, num=6, unlock cycle=7.
  txOk(
    pox5.stake({
      signerManager: signer,
      amountUstx: stakeAmount,
      numCycles: 6n,
      startBurnHt: simnet.burnBlockHeight,
      signerCalldata: null,
    }),
    alice,
  );

  // Move into cycle 1 — out of cycle 0's prepare phase, past setup-bond(1)'s
  // "too soon" gate, and after the stake's first cycle.
  mineUntil(rov(pox5.rewardCycleToBurnHeight(1n)));

  txOk(
    pox5.setupBond({
      bondIndex: 1n,
      targetRate: 1200n,
      stxValueRatio: 10n,
      minUstxRatio: 100n,
      earlyUnlockBytes: new Uint8Array(),
      allowlist: [{ maxSats: bondSbtc, staker: alice }],
    }),
    deployer,
  );

  // The active long stake (unlock cycle 7) overlaps bond 1 (first cycle 3),
  // so `register-for-bond` is rejected by the non-overlap gate.
  const overlapping = txErr(
    pox5.registerForBond({
      bondIndex: 1n,
      signerManager: signer,
      amountUstx: stakeAmount,
      btcLockup: err(bondSbtc),
      signerCalldata: null,
    }),
    alice,
  );
  expect(overlapping.value).toEqual(pox5Errors.ERR_ALREADY_STAKED);

  // `unstake` shortens the stake to unlock at the start of cycle 2 — now
  // strictly before bond 1's first cycle (3), so the rollover is allowed.
  txOk(pox5.unstake({ oldSignerManager: signer }), alice);

  // Same cycle as the unstake (no further mining): the new gate compares
  // the raw `staker-info` entry's unlock cycle against the new bond's first
  // cycle, so the rollover takes effect immediately.
  const register = txOk(
    pox5.registerForBond({
      bondIndex: 1n,
      signerManager: signer,
      amountUstx: stakeAmount,
      btcLockup: err(bondSbtc),
      signerCalldata: null,
    }),
    alice,
  );
  expect(register.value).toMatchObject({
    bondIndex: 1n,
    amountUstx: stakeAmount,
  });

  // The staker-info entry is cleared on rollover; bond membership is set.
  expect(rov(pox5.getStakerInfo(alice))).toBeNull();
  const membership = rov(pox5.getBondMembership(alice))!;
  expect(membership.bondIndex).toBe(1n);
  expect(membership.isL1Lock).toBe(false);

  // STX lock carried from the (truncated) stx-only stake onto bond 1 — the
  // lock never released across the stake → bond hand-off. Bond 1's unlock
  // is at `bond-period-to-burn-height(1 + 6) = bond-period-to-burn-height(7)`.
  const aliceLock = stxAccount(alice);
  expect(aliceLock.locked).toBe(stakeAmount);
  expect(aliceLock.unlockHeight).toBe(rov(pox5.bondPeriodToBurnHeight(7n)));
});

test('concurrent bonds with the same stx-value-ratio accept ascending bond-index order', () => {
  const signer = testSigner.identifier;
  const targetRate = 1200n;
  const minUstxRatio = 100n;
  const aliceSbtc = 100000n;
  const bobSbtc = 100000n;

  registerSigner();

  txOk(
    pox5.setupBond({
      bondIndex: 0n,
      targetRate,
      stxValueRatio: 10n,
      minUstxRatio,
      earlyUnlockBytes: new Uint8Array(),
      allowlist: [{ maxSats: aliceSbtc, staker: alice }],
    }),
    deployer,
  );
  txOk(
    pox5.registerForBond({
      bondIndex: 0n,
      signerManager: signer,
      amountUstx: rov(pox5.minUstxForSatsAmount(aliceSbtc, 10n, minUstxRatio)),
      btcLockup: err(aliceSbtc),
      signerCalldata: null,
    }),
    alice,
  );

  mineUntil(rov(pox5.bondPeriodToBurnHeight(0n)) + 1n);

  txOk(
    pox5.setupBond({
      bondIndex: 1n,
      targetRate,
      stxValueRatio: 10n,
      minUstxRatio,
      earlyUnlockBytes: new Uint8Array(),
      allowlist: [{ maxSats: bobSbtc, staker: bob }],
    }),
    deployer,
  );
  txOk(
    pox5.registerForBond({
      bondIndex: 1n,
      signerManager: signer,
      amountUstx: rov(pox5.minUstxForSatsAmount(bobSbtc, 10n, minUstxRatio)),
      btcLockup: err(bobSbtc),
      signerCalldata: null,
    }),
    bob,
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

  mineUntil(rov(pox5.rewardCycleToBurnHeight(3n)) + HALF_CYCLE_LENGTH);

  // Ascending bond-index order matches the comment in calculate-bond-rewards:
  // "the earlier bond period comes first".
  txOk(pox5.calculateRewards([0n, 1n]), deployer);
});

/**
 * Helper: register alice for an sBTC bond using the minimum amount of STX
 * required, and returning resulting events.
 */
function registerSbtcBondWithMinStx({
  bondIndex,
  signer,
  sbtcAmount,
  stxValueRatio,
  minUstxRatio,
  caller,
}: {
  bondIndex: bigint;
  signer: string;
  sbtcAmount: bigint;
  stxValueRatio: bigint;
  minUstxRatio: bigint;
  caller: string;
}) {
  const amountUstx = rov(
    pox5.minUstxForSatsAmount(sbtcAmount, stxValueRatio, minUstxRatio),
  );
  return txOk(
    pox5.registerForBond({
      bondIndex,
      signerManager: signer,
      amountUstx,
      btcLockup: err(sbtcAmount),
      signerCalldata: null,
    }),
    caller,
  ).events;
}

/**
 * Verify a staker can register for the next contiguous bond (index 6) during
 * bond 0's gap window, with the bond's sBTC carried forward (no net transfer
 * when the new amount equals the old), bond 0's reward shares preserved, and
 * the membership pointing at the new bond.
 */
test('register-for-bond rolls a staker forward into bond N+6 with equal sBTC (no net transfer)', () => {
  const signer = testSigner.identifier;
  const stxValueRatio = 10000000n;
  const minUstxRatio = 1000n;
  const sbtcAmount = 5000000n;
  registerSigner({ caller: deployer });

  txOk(
    pox5.setupBond({
      bondIndex: 0n,
      targetRate: 300n,
      stxValueRatio,
      minUstxRatio,
      earlyUnlockBytes: new Uint8Array(),
      allowlist: [{ maxSats: sbtcAmount, staker: alice }],
    }),
    deployer,
  );

  registerSbtcBondWithMinStx({
    bondIndex: 0n,
    signer,
    sbtcAmount,
    stxValueRatio,
    minUstxRatio,
    caller: alice,
  });

  // Capture the contract's sBTC custody after bond 0.
  const sbtcStakedAfterBond0 = rov(pox5.getTotalSbtcStaked());
  expect(sbtcStakedAfterBond0).toBe(sbtcAmount);

  // Mine into the gap before bond 6 starts: must be within BOND_GAP_CYCLES of
  // bond 6's start, and before it.
  mineUntil(rov(pox5.getBondL1UnlockHeight(0n)));

  txOk(
    pox5.setupBond({
      bondIndex: 6n,
      targetRate: 300n,
      stxValueRatio,
      minUstxRatio,
      earlyUnlockBytes: new Uint8Array(),
      allowlist: [{ maxSats: sbtcAmount, staker: alice }],
    }),
    deployer,
  );

  const aliceRollEvents = registerSbtcBondWithMinStx({
    bondIndex: 6n,
    signer,
    sbtcAmount,
    stxValueRatio,
    minUstxRatio,
    caller: alice,
  });

  // Equal sBTC means no net transfer at all.
  expect(
    filterEvents(aliceRollEvents, CoreNodeEventType.FtTransferEvent),
  ).toEqual([]);
  expect(rov(pox5.getTotalSbtcStaked())).toBe(sbtcAmount);

  // Membership has moved to bond 6, but bond 0's reward shares are preserved
  // (the staker keeps earning bond 0 rewards through its remaining cycles).
  const membership = rov(pox5.getBondMembership(alice))!;
  expect(membership.bondIndex).toBe(6n);
  expect(membership.isL1Lock).toBe(false);
  expect(rov(pox5.getStakerSharesStakedForCycle(alice, 12n, 0n, signer))).toBe(
    sbtcAmount,
  );
  expect(rov(pox5.getStakerSharesStakedForCycle(alice, 13n, 6n, signer))).toBe(
    sbtcAmount,
  );

  // STX lock is carried forward — same locked amount, but the unlock height
  // is rescheduled from bond 0's end to bond 6's end (`bond + 6 = 12`).
  const aliceLock = stxAccount(alice);
  expect(aliceLock.locked).toBe(
    rov(pox5.minUstxForSatsAmount(sbtcAmount, stxValueRatio, minUstxRatio)),
  );
  expect(aliceLock.unlockHeight).toBe(rov(pox5.bondPeriodToBurnHeight(12n)));
});

/**
 * Rolling into a larger sBTC bond pulls only the difference from the staker
 * and bumps `total-sbtc-staked` by the same delta. Bond 0's shares are
 * preserved.
 */
test('register-for-bond rolls forward and nets a larger sBTC amount from the staker', () => {
  const signer = testSigner.identifier;
  const stxValueRatio = 10000000n;
  const minUstxRatio = 1000n;
  const bond0Sbtc = 5000000n;
  const bond6Sbtc = 8000000n;
  registerSigner({ caller: deployer });

  txOk(
    pox5.setupBond({
      bondIndex: 0n,
      targetRate: 300n,
      stxValueRatio,
      minUstxRatio,
      earlyUnlockBytes: new Uint8Array(),
      allowlist: [{ maxSats: bond0Sbtc, staker: alice }],
    }),
    deployer,
  );
  registerSbtcBondWithMinStx({
    bondIndex: 0n,
    signer,
    sbtcAmount: bond0Sbtc,
    stxValueRatio,
    minUstxRatio,
    caller: alice,
  });

  mineUntil(rov(pox5.getBondL1UnlockHeight(0n)));

  txOk(
    pox5.setupBond({
      bondIndex: 6n,
      targetRate: 300n,
      stxValueRatio,
      minUstxRatio,
      earlyUnlockBytes: new Uint8Array(),
      allowlist: [{ maxSats: bond6Sbtc, staker: alice }],
    }),
    deployer,
  );

  const aliceRollEvents = registerSbtcBondWithMinStx({
    bondIndex: 6n,
    signer,
    sbtcAmount: bond6Sbtc,
    stxValueRatio,
    minUstxRatio,
    caller: alice,
  });

  const transfers = filterEvents(
    aliceRollEvents,
    CoreNodeEventType.FtTransferEvent,
  );
  expect(transfers.length).toBe(1);
  expect(transfers[0]!.data.sender).toBe(alice);
  expect(transfers[0]!.data.recipient).toBe(pox5.identifier);
  expect(transfers[0]!.data.amount).toBe((bond6Sbtc - bond0Sbtc).toString());
  expect(rov(pox5.getTotalSbtcStaked())).toBe(bond6Sbtc);
  expect(rov(pox5.getStakerSharesStakedForCycle(alice, 12n, 0n, signer))).toBe(
    bond0Sbtc,
  );
  expect(rov(pox5.getStakerSharesStakedForCycle(alice, 13n, 6n, signer))).toBe(
    bond6Sbtc,
  );

  // STX lock is rescheduled to bond 6's unlock; locked amount increases to
  // bond 6's `min-ustx-for-sats-amount` drawn from Alice's unlocked balance.
  const aliceLock = stxAccount(alice);
  expect(aliceLock.locked).toBe(
    rov(pox5.minUstxForSatsAmount(bond6Sbtc, stxValueRatio, minUstxRatio)),
  );
  expect(aliceLock.unlockHeight).toBe(rov(pox5.bondPeriodToBurnHeight(12n)));
});

/**
 * Rolling into a smaller sBTC bond refunds the difference to the staker and
 * decreases `total-sbtc-staked` by the same delta.
 */
test('register-for-bond rolls forward and refunds when the new sBTC amount is smaller', () => {
  const signer = testSigner.identifier;
  const stxValueRatio = 10000000n;
  const minUstxRatio = 1000n;
  const bond0Sbtc = 8000000n;
  const bond6Sbtc = 5000000n;
  registerSigner({ caller: deployer });

  txOk(
    pox5.setupBond({
      bondIndex: 0n,
      targetRate: 300n,
      stxValueRatio,
      minUstxRatio,
      earlyUnlockBytes: new Uint8Array(),
      allowlist: [{ maxSats: bond0Sbtc, staker: alice }],
    }),
    deployer,
  );
  registerSbtcBondWithMinStx({
    bondIndex: 0n,
    signer,
    sbtcAmount: bond0Sbtc,
    stxValueRatio,
    minUstxRatio,
    caller: alice,
  });

  mineUntil(rov(pox5.getBondL1UnlockHeight(0n)));

  txOk(
    pox5.setupBond({
      bondIndex: 6n,
      targetRate: 300n,
      stxValueRatio,
      minUstxRatio,
      earlyUnlockBytes: new Uint8Array(),
      allowlist: [{ maxSats: bond6Sbtc, staker: alice }],
    }),
    deployer,
  );

  const aliceRollEvents = registerSbtcBondWithMinStx({
    bondIndex: 6n,
    signer,
    sbtcAmount: bond6Sbtc,
    stxValueRatio,
    minUstxRatio,
    caller: alice,
  });

  const transfers = filterEvents(
    aliceRollEvents,
    CoreNodeEventType.FtTransferEvent,
  );
  expect(transfers.length).toBe(1);
  expect(transfers[0]!.data.sender).toBe(pox5.identifier);
  expect(transfers[0]!.data.recipient).toBe(alice);
  expect(transfers[0]!.data.amount).toBe((bond0Sbtc - bond6Sbtc).toString());
  expect(rov(pox5.getTotalSbtcStaked())).toBe(bond6Sbtc);

  // STX lock is reduced to bond 6's smaller `min-ustx-for-sats-amount` and
  // rescheduled; the freed STX returns to Alice's unlocked balance
  // (exercising `set_lock_v5`'s amount-down path).
  const aliceLock = stxAccount(alice);
  expect(aliceLock.locked).toBe(
    rov(pox5.minUstxForSatsAmount(bond6Sbtc, stxValueRatio, minUstxRatio)),
  );
  expect(aliceLock.unlockHeight).toBe(rov(pox5.bondPeriodToBurnHeight(12n)));
});

/**
 * Re-registering for a later bond after the old bond expires (without first
 * calling `unstake-sbtc`) properly rolls the sBTC forward via `roll-sbtc`, the
 * old bond's custodied sBTC is netted forward into the new bond, so
 * `total-sbtc-staked` matches what is recoverable via the new bond's
 * `unstake-sbtc`.
 */
test('register-for-bond after old bond expires nets sBTC forward (no stuck collateral)', () => {
  const signer = testSigner.identifier;
  const stxValueRatio = 10000000n;
  const minUstxRatio = 1000n;
  const sbtcAmount = 5000000n;
  registerSigner({ caller: deployer });

  txOk(
    pox5.setupBond({
      bondIndex: 0n,
      targetRate: 300n,
      stxValueRatio,
      minUstxRatio,
      earlyUnlockBytes: new Uint8Array(),
      allowlist: [{ maxSats: sbtcAmount, staker: alice }],
    }),
    deployer,
  );
  registerSbtcBondWithMinStx({
    bondIndex: 0n,
    signer,
    sbtcAmount,
    stxValueRatio,
    minUstxRatio,
    caller: alice,
  });

  const aliceSbtcAfterBond0 = sbtcBalance(alice);
  expect(rov(pox5.getTotalSbtcStaked())).toBe(sbtcAmount);

  // Mine past bond 0's full expiry: `get-bond-membership` now hides bond 0
  // (the helper returns `none`), but the raw `protocol-bond-memberships`
  // entry is still there — this is the exact precondition that orphaned
  // bond 0's sBTC under the old code.
  mineUntil(rov(pox5.bondPeriodToBurnHeight(6n)));
  expect(rov(pox5.getBondMembership(alice))).toBeNull();

  // Bond 7 setup window opens at `bondPeriodToBurnHeight(7) - 2 * L`, which
  // is at or before bond 0's expiry, so it's already open here.
  txOk(
    pox5.setupBond({
      bondIndex: 7n,
      targetRate: 300n,
      stxValueRatio,
      minUstxRatio,
      earlyUnlockBytes: new Uint8Array(),
      allowlist: [{ maxSats: sbtcAmount, staker: alice }],
    }),
    deployer,
  );

  const aliceRollEvents = registerSbtcBondWithMinStx({
    bondIndex: 7n,
    signer,
    sbtcAmount,
    stxValueRatio,
    minUstxRatio,
    caller: alice,
  });

  // Equal amounts → no transfer, custody unchanged, and bond 7's shares cover
  // the full physical sBTC.
  expect(
    filterEvents(aliceRollEvents, CoreNodeEventType.FtTransferEvent),
  ).toEqual([]);
  expect(rov(pox5.getTotalSbtcStaked())).toBe(sbtcAmount);

  const membership = rov(pox5.getBondMembership(alice))!;
  expect(membership.bondIndex).toBe(7n);

  // STX lock was carried forward to bond 7's unlock height (the bond
  // re-acquired no fresh lock — the existing bond 0 lock simply extends).
  //
  const bond7Unlock = rov(pox5.bondPeriodToBurnHeight(13n));
  expect(stxAccount(alice).unlockHeight).toBe(bond7Unlock);

  // Recover everything via the new bond's `unstake-sbtc`. Alice ends up with
  // her original sBTC balance restored and no sBTC stuck in the contract.
  txOk(
    pox5.unstakeSbtc({
      signerManager: signer,
      amountToWithdrawalSats: sbtcAmount,
    }),
    alice,
  );
  expect(sbtcBalance(alice)).toBe(aliceSbtcAfterBond0 + sbtcAmount);
  expect(rov(pox5.getTotalSbtcStaked())).toBe(0n);

  // `unstake-sbtc` only moves the bond's sBTC custody — the STX lock is
  // untouched. Alice is still locked through bond 7's unlock height even
  // though her sBTC backing is now 0.
  const lock = stxAccount(alice);
  expect(lock.locked).toBeGreaterThan(0n);
  expect(lock.unlockHeight).toBe(bond7Unlock);
});

/**
 * A rollover attempted before the old bond's L1 collateral would have
 * unlocked must be rejected. The rollover window opens at
 * `(get-bond-l1-unlock-height old)` (half a cycle before the old bond's end).
 */
test("register-for-bond rejects a rollover attempt before the old bond's L1 unlock window", () => {
  const signer = testSigner.identifier;
  const stxValueRatio = 10000000n;
  const minUstxRatio = 1000n;
  const sbtcAmount = 5000000n;
  registerSigner({ caller: deployer });

  txOk(
    pox5.setupBond({
      bondIndex: 0n,
      targetRate: 300n,
      stxValueRatio,
      minUstxRatio,
      earlyUnlockBytes: new Uint8Array(),
      allowlist: [{ maxSats: sbtcAmount, staker: alice }],
    }),
    deployer,
  );
  registerSbtcBondWithMinStx({
    bondIndex: 0n,
    signer,
    sbtcAmount,
    stxValueRatio,
    minUstxRatio,
    caller: alice,
  });

  // One block before bond 0's L1 unlock — still inside the old bond's term,
  // outside the rollover window. Bond 6's setup window has opened (cycles
  // C+10..C+12), so this is a real "too-early" rollover, not blocked by
  // `setup-bond` timing.
  const bond0L1Unlock = rov(pox5.getBondL1UnlockHeight(0n));
  mineUntil(bond0L1Unlock - 1n);

  txOk(
    pox5.setupBond({
      bondIndex: 6n,
      targetRate: 300n,
      stxValueRatio,
      minUstxRatio,
      earlyUnlockBytes: new Uint8Array(),
      allowlist: [{ maxSats: sbtcAmount, staker: alice }],
    }),
    deployer,
  );

  const tooEarly = txErr(
    pox5.registerForBond({
      bondIndex: 6n,
      signerManager: signer,
      amountUstx: rov(
        pox5.minUstxForSatsAmount(sbtcAmount, stxValueRatio, minUstxRatio),
      ),
      btcLockup: err(sbtcAmount),
      signerCalldata: null,
    }),
    alice,
  );
  expect(tooEarly.value).toEqual(pox5Errors.ERR_ROLLOVER_TOO_EARLY);

  // One block later — inside the L1 unlock window — the same call now
  // succeeds, confirming the gate opens exactly at the L1 unlock height.
  mineUntil(bond0L1Unlock);
  registerSbtcBondWithMinStx({
    bondIndex: 6n,
    signer,
    sbtcAmount,
    stxValueRatio,
    minUstxRatio,
    caller: alice,
  });
  expect(rov(pox5.getBondMembership(alice))!.bondIndex).toBe(6n);
});

/**
 * Bond → STX-only stake rollover: a staker can `stake` while still in
 * their bond's L1-unlock window. The contract clears the bond membership,
 * refunds the bond's sBTC custody (via `roll-sbtc(staker, X, 0)`), the
 * node-side handler extends the STX lock to the new stake's unlock height
 * (no release), and the staker's stx-only `staker-info` is set.
 */
test('stake rolls a bond participant forward into STX-only with sBTC refunded', () => {
  const signer = testSigner.identifier;
  const stxValueRatio = 10000000n;
  const minUstxRatio = 1000n;
  const sbtcAmount = 5000000n;
  registerSigner({ caller: deployer });

  txOk(
    pox5.setupBond({
      bondIndex: 0n,
      targetRate: 300n,
      stxValueRatio,
      minUstxRatio,
      earlyUnlockBytes: new Uint8Array(),
      allowlist: [{ maxSats: sbtcAmount, staker: alice }],
    }),
    deployer,
  );
  registerSbtcBondWithMinStx({
    bondIndex: 0n,
    signer,
    sbtcAmount,
    stxValueRatio,
    minUstxRatio,
    caller: alice,
  });

  // Mine into bond 0's L1 unlock window (the same window that opens the
  // bond-to-bond rollover gate).
  const bond0L1Unlock = rov(pox5.getBondL1UnlockHeight(0n));
  mineUntil(bond0L1Unlock);

  const aliceSbtcBefore = sbtcBalance(alice);
  const stakeAmount = stxToUStx(50_000);

  const stakeResult = txOk(
    pox5.stake({
      signerManager: signer,
      amountUstx: stakeAmount,
      numCycles: 4n,
      startBurnHt: simnet.burnBlockHeight,
      signerCalldata: null,
    }),
    alice,
  );
  expect(stakeResult.value).toMatchObject({
    staker: alice,
    amountUstx: stakeAmount,
  });

  // Bond membership cleared; staker-info now records the stx-only stake.
  expect(rov(pox5.getBondMembership(alice))).toBeNull();
  expect(rov(pox5.getStakerInfo(alice))).not.toBeNull();

  // sBTC: bond 0's full custody is refunded to Alice, `total-sbtc-staked`
  // drops to 0 (she's no longer in a bond).
  const refund = filterEvents(
    stakeResult.events,
    CoreNodeEventType.FtTransferEvent,
  );
  expect(refund.length).toBe(1);
  expect(refund[0]!.data.sender).toBe(pox5.identifier);
  expect(refund[0]!.data.recipient).toBe(alice);
  expect(refund[0]!.data.amount).toBe(sbtcAmount.toString());
  expect(sbtcBalance(alice)).toBe(aliceSbtcBefore + sbtcAmount);
  expect(rov(pox5.getTotalSbtcStaked())).toBe(0n);

  // STX lock carried from bond 0's unlock onto the new stake's unlock — the
  // lock never released even though sBTC was fully refunded. Stake's
  // `first-reward-cycle = current + 1 = 13`, `num-cycles = 4`, so
  // `unlock-cycle = 17`.
  const aliceLock = stxAccount(alice);
  expect(aliceLock.locked).toBe(stakeAmount);
  expect(aliceLock.unlockHeight).toBe(rov(pox5.rewardCycleToBurnHeight(17n)));
});

/**
 * Bond → STX-only stake rollover before the bond's L1 unlock window is
 * rejected, mirroring the bond-to-bond gate. Same `ERR_ROLLOVER_TOO_EARLY`
 * (u46) error code.
 */
test("stake rejects a bond rollover attempt before the bond's L1 unlock window", () => {
  const signer = testSigner.identifier;
  const stxValueRatio = 10000000n;
  const minUstxRatio = 1000n;
  const sbtcAmount = 5000000n;
  registerSigner({ caller: deployer });

  txOk(
    pox5.setupBond({
      bondIndex: 0n,
      targetRate: 300n,
      stxValueRatio,
      minUstxRatio,
      earlyUnlockBytes: new Uint8Array(),
      allowlist: [{ maxSats: sbtcAmount, staker: alice }],
    }),
    deployer,
  );
  registerSbtcBondWithMinStx({
    bondIndex: 0n,
    signer,
    sbtcAmount,
    stxValueRatio,
    minUstxRatio,
    caller: alice,
  });

  // One block before bond 0's L1 unlock — outside the rollover window.
  const bond0L1Unlock = rov(pox5.getBondL1UnlockHeight(0n));
  mineUntil(bond0L1Unlock - 1n);

  const tooEarly = txErr(
    pox5.stake({
      signerManager: signer,
      amountUstx: stxToUStx(50_000),
      numCycles: 4n,
      startBurnHt: simnet.burnBlockHeight,
      signerCalldata: null,
    }),
    alice,
  );
  expect(tooEarly.value).toEqual(pox5Errors.ERR_ROLLOVER_TOO_EARLY);

  // Mine one block into the window — same call now succeeds.
  mineUntil(bond0L1Unlock);
  txOk(
    pox5.stake({
      signerManager: signer,
      amountUstx: stxToUStx(50_000),
      numCycles: 4n,
      startBurnHt: simnet.burnBlockHeight,
      signerCalldata: null,
    }),
    alice,
  );
  expect(rov(pox5.getBondMembership(alice))).toBeNull();
  expect(rov(pox5.getStakerInfo(alice))).not.toBeNull();
});

/**
 * Anti-stuck-collateral analog of the `register-for-bond after old bond
 * expires nets sBTC forward` regression, but via `stake`: after a bond
 * expires naturally, calling `stake` rolls the staker out of the bond,
 * refunds the bond's sBTC custody, and lets the STX get locked fresh for
 * the new stx-only stake. Without the bond → stake rollover support, the
 * bond's sBTC would orphan in the contract.
 */
test('stake after bond expires refunds the sBTC and clears bond membership', () => {
  const signer = testSigner.identifier;
  const stxValueRatio = 10000000n;
  const minUstxRatio = 1000n;
  const sbtcAmount = 5000000n;
  registerSigner({ caller: deployer });

  txOk(
    pox5.setupBond({
      bondIndex: 0n,
      targetRate: 300n,
      stxValueRatio,
      minUstxRatio,
      earlyUnlockBytes: new Uint8Array(),
      allowlist: [{ maxSats: sbtcAmount, staker: alice }],
    }),
    deployer,
  );
  registerSbtcBondWithMinStx({
    bondIndex: 0n,
    signer,
    sbtcAmount,
    stxValueRatio,
    minUstxRatio,
    caller: alice,
  });

  const aliceSbtcAfterBond0 = sbtcBalance(alice);
  expect(rov(pox5.getTotalSbtcStaked())).toBe(sbtcAmount);

  // Bond 0 fully expires. `get-bond-membership` now hides bond 0, but the raw
  // map entry remains — without `roll-sbtc` the sBTC would orphan here.
  mineUntil(rov(pox5.bondPeriodToBurnHeight(6n)));
  expect(rov(pox5.getBondMembership(alice))).toBeNull();

  const stakeResult = txOk(
    pox5.stake({
      signerManager: signer,
      amountUstx: stxToUStx(50_000),
      numCycles: 4n,
      startBurnHt: simnet.burnBlockHeight,
      signerCalldata: null,
    }),
    alice,
  );
  expect(stakeResult.value).toMatchObject({ staker: alice });

  // The sBTC is fully refunded; the contract's custody drops to 0.
  const refund = filterEvents(
    stakeResult.events,
    CoreNodeEventType.FtTransferEvent,
  );
  expect(refund.length).toBe(1);
  expect(refund[0]!.data.sender).toBe(pox5.identifier);
  expect(refund[0]!.data.recipient).toBe(alice);
  expect(refund[0]!.data.amount).toBe(sbtcAmount.toString());
  expect(sbtcBalance(alice)).toBe(aliceSbtcAfterBond0 + sbtcAmount);
  expect(rov(pox5.getTotalSbtcStaked())).toBe(0n);

  // Bond membership cleared, staker-info now points at the new stx-only stake.
  expect(rov(pox5.getStakerInfo(alice))).not.toBeNull();
});

/**
 * Mirror of the `stake after bond expires` regression, but for the
 * stake → bond direction: after a stx-only stake expires naturally
 * (without `unstake`), the staker can `register-for-bond` for any later
 * bond. The raw `staker-info` map still has the (expired) entry, and the
 * non-overlap gate accepts it because `first + num` is in the past.
 */
test('register-for-bond after stx-only stake expires registers fresh on the new bond', () => {
  const signer = testSigner.identifier;
  const stxValueRatio = 10000000n;
  const minUstxRatio = 1000n;
  const sbtcAmount = 5000000n;
  const stakeAmount = stxToUStx(50_000);
  registerSigner({ caller: deployer });

  txOk(
    pox5.stake({
      signerManager: signer,
      amountUstx: stakeAmount,
      numCycles: 1n,
      startBurnHt: simnet.burnBlockHeight,
      signerCalldata: null,
    }),
    alice,
  );

  // Mine past the stake's term: with `numCycles: 1` and current cycle 0, the
  // stake covers cycle [1, 2) and ends at cycle 2.
  mineUntil(rov(pox5.rewardCycleToBurnHeight(2n)));
  expect(rov(pox5.getStakerInfo(alice))).toBeNull();

  // setup-bond 1
  txOk(
    pox5.setupBond({
      bondIndex: 1n,
      targetRate: 1200n,
      stxValueRatio,
      minUstxRatio,
      earlyUnlockBytes: new Uint8Array(),
      allowlist: [{ maxSats: sbtcAmount, staker: alice }],
    }),
    deployer,
  );
  registerSbtcBondWithMinStx({
    bondIndex: 1n,
    signer,
    sbtcAmount,
    stxValueRatio,
    minUstxRatio,
    caller: alice,
  });

  // staker-info entry cleared on rollover; bond 1 membership set.
  expect(rov(pox5.getStakerInfo(alice))).toBeNull();
  const membership = rov(pox5.getBondMembership(alice))!;
  expect(membership.bondIndex).toBe(1n);

  // Stake's lock was released at cycle 2 (its natural unlock), so
  // register-for-bond(1) takes the fresh-lock path and locks Alice's STX
  // for bond 1's term — unlock at `bond-period-to-burn-height(1 + 6)`.
  const aliceLock = stxAccount(alice);
  expect(aliceLock.locked).toBe(
    rov(pox5.minUstxForSatsAmount(sbtcAmount, stxValueRatio, minUstxRatio)),
  );
  expect(aliceLock.unlockHeight).toBe(rov(pox5.bondPeriodToBurnHeight(7n)));
});

/**
 * The L1-unlock-window check and the prepare-phase check overlap toward the
 * very end of the bond's last cycle: the prepare phase begins inside the
 * rollover window. A `register-for-bond` issued inside both must surface as
 * `ERR_STAKE_IN_PREPARE_PHASE`, not as `ok` (and not as
 * `ERR_ROLLOVER_TOO_EARLY` since we're past the L1 unlock).
 */
test("register-for-bond is rejected with ERR_STAKE_IN_PREPARE_PHASE inside the bond's prepare phase", () => {
  const signer = testSigner.identifier;
  const stxValueRatio = 10000000n;
  const minUstxRatio = 1000n;
  const sbtcAmount = 5000000n;
  registerSigner({ caller: deployer });

  txOk(
    pox5.setupBond({
      bondIndex: 0n,
      targetRate: 300n,
      stxValueRatio,
      minUstxRatio,
      earlyUnlockBytes: new Uint8Array(),
      allowlist: [{ maxSats: sbtcAmount, staker: alice }],
    }),
    deployer,
  );
  registerSbtcBondWithMinStx({
    bondIndex: 0n,
    signer,
    sbtcAmount,
    stxValueRatio,
    minUstxRatio,
    caller: alice,
  });

  // Bond 6 setup must happen before we enter cycle 12's prepare phase,
  // since `setup-bond` runs no prepare-phase gate but `register-for-bond`
  // does. Run setup while still well inside the L1 window.
  mineUntil(rov(pox5.getBondL1UnlockHeight(0n)));
  txOk(
    pox5.setupBond({
      bondIndex: 6n,
      targetRate: 300n,
      stxValueRatio,
      minUstxRatio,
      earlyUnlockBytes: new Uint8Array(),
      allowlist: [{ maxSats: sbtcAmount, staker: alice }],
    }),
    deployer,
  );

  // Mine into cycle 12's prepare phase. Still inside the L1 window
  // (`>= getBondL1UnlockHeight(0)`) and bond 6 hasn't started yet
  // (`< bondPeriodToBurnHeight(6)`), so neither the rollover-window gate nor
  // `ERR_BOND_ALREADY_STARTED` fires — only the prepare-phase gate should.
  mineUntil(rov(pox5.bondPeriodToBurnHeight(6n)) - 5n);
  const inPrepare = txErr(
    pox5.registerForBond({
      bondIndex: 6n,
      signerManager: signer,
      amountUstx: rov(
        pox5.minUstxForSatsAmount(sbtcAmount, stxValueRatio, minUstxRatio),
      ),
      btcLockup: err(sbtcAmount),
      signerCalldata: null,
    }),
    alice,
  );
  expect(inPrepare.value).toEqual(pox5Errors.ERR_STAKE_IN_PREPARE_PHASE);
});

/**
 * Re-registering for the SAME (still-active) bond is still rejected, as is
 * registering for an overlapping bond. The relaxed gate only opens for
 * non-overlapping later bonds. The non-overlap check fires before the
 * L1-window check, so this surfaces as the more specific
 * `ERR_ALREADY_REGISTERED` rather than `ERR_ROLLOVER_TOO_EARLY`.
 */
test('register-for-bond still rejects a duplicate registration for the same or overlapping bond', () => {
  const signer = testSigner.identifier;
  const stxValueRatio = 10000000n;
  const minUstxRatio = 1000n;
  const sbtcAmount = 5000000n;
  registerSigner({ caller: deployer });

  txOk(
    pox5.setupBond({
      bondIndex: 0n,
      targetRate: 300n,
      stxValueRatio,
      minUstxRatio,
      earlyUnlockBytes: new Uint8Array(),
      allowlist: [{ maxSats: sbtcAmount, staker: alice }],
    }),
    deployer,
  );
  registerSbtcBondWithMinStx({
    bondIndex: 0n,
    signer,
    sbtcAmount,
    stxValueRatio,
    minUstxRatio,
    caller: alice,
  });

  const dup = txErr(
    pox5.registerForBond({
      bondIndex: 0n,
      signerManager: signer,
      amountUstx: rov(
        pox5.minUstxForSatsAmount(sbtcAmount, stxValueRatio, minUstxRatio),
      ),
      btcLockup: err(sbtcAmount),
      signerCalldata: null,
    }),
    alice,
  );
  expect(dup.value).toEqual(pox5Errors.ERR_ALREADY_REGISTERED);

  // Advance into bond 1's setup-bond window, then set up bond 1 with Alice
  // allowlisted. Bond 1 starts at cycle 3 and bond 0 doesn't end until cycle
  // 13, so registering for it would overlap bond 0's term and must be rejected
  // with `ERR_ALREADY_REGISTERED`.
  mineUntil(rov(pox5.rewardCycleToBurnHeight(1n)));
  txOk(
    pox5.setupBond({
      bondIndex: 1n,
      targetRate: 300n,
      stxValueRatio,
      minUstxRatio,
      earlyUnlockBytes: new Uint8Array(),
      allowlist: [{ maxSats: sbtcAmount, staker: alice }],
    }),
    deployer,
  );
  const overlap = txErr(
    pox5.registerForBond({
      bondIndex: 1n,
      signerManager: signer,
      amountUstx: rov(
        pox5.minUstxForSatsAmount(sbtcAmount, stxValueRatio, minUstxRatio),
      ),
      btcLockup: err(sbtcAmount),
      signerCalldata: null,
    }),
    alice,
  );
  expect(overlap.value).toEqual(pox5Errors.ERR_ALREADY_REGISTERED);
});

test('is-in-prepare-phase triggers near the end of the reward cycle', () => {
  // We are at the very end of cycle 0 (one block before cycle 1).
  const lastBlockOfCycle0 = rov(pox5.rewardCycleToBurnHeight(1n)) - 1n;
  mineUntil(lastBlockOfCycle0);
  expect(rov(pox5.currentPoxRewardCycle())).toBe(0n);
  expect(rov(pox5.isInPreparePhase(0n))).toBe(true);
});

test('unstake is rejected when called during the prepare phase', () => {
  const signer = testSigner.identifier;
  registerSigner();
  txOk(
    pox5.stake({
      signerManager: signer,
      amountUstx: stxToUStx(50_000),
      numCycles: 2n,
      startBurnHt: simnet.burnBlockHeight,
      signerCalldata: null,
    }),
    alice,
  );
  const lastBlockOfCycle0 = rov(pox5.rewardCycleToBurnHeight(1n)) - 1n;
  mineUntil(lastBlockOfCycle0);
  const result = txErr(pox5.unstake(signer), alice);
  expect(result.value).toBe(errorCodes.ERR_UNSTAKE_IN_PREPARE_PHASE);
});

/**
 * Regression for stacks-network/stacks-core#7295. `unstake-sbtc` mutates
 * next-cycle bond / signer shares, and the next-cycle signer set is frozen
 * during the current cycle's prepare phase. The other share-mutating
 * entry-points (`stake`, `stake-update`, `register-for-bond`,
 * `update-bond-registration`) all gate on `verify-not-prepare-phase`;
 * `unstake-sbtc` previously side-stepped it. After the fix it returns
 * `ERR_STAKE_IN_PREPARE_PHASE` mid-prepare and succeeds once the next
 * cycle starts.
 */
test('unstake-sbtc is rejected during the prepare phase', () => {
  const signer = testSigner.identifier;
  const aliceSbtc = 100000n;
  const unstakeAmount = 40000n;

  registerSigner();
  setupBondForAllowlist([{ maxSats: aliceSbtc, staker: alice }]);
  txOk(
    pox5.registerForBond({
      bondIndex: 0n,
      signerManager: signer,
      amountUstx: stxToUStx(50_000),
      btcLockup: err(aliceSbtc),
      signerCalldata: null,
    }),
    alice,
  );

  // Cycle 0 prepare phase begins at (cycle-1-start - 10). Land mid-prepare.
  mineUntil(rov(pox5.rewardCycleToBurnHeight(1n)) - 9n);
  expect(rov(pox5.isInPreparePhase(rov(pox5.currentPoxRewardCycle())))).toBe(
    true,
  );

  expect(
    txErr(
      pox5.unstakeSbtc({
        signerManager: signer,
        amountToWithdrawalSats: unstakeAmount,
      }),
      alice,
    ).value,
  ).toBe(pox5Errors.ERR_STAKE_IN_PREPARE_PHASE);

  // Crossing into the next cycle clears the prepare phase: the same call
  // now succeeds, confirming the guard was the sole blocker.
  mineUntil(rov(pox5.rewardCycleToBurnHeight(1n)));
  expect(rov(pox5.isInPreparePhase(rov(pox5.currentPoxRewardCycle())))).toBe(
    false,
  );
  txOk(
    pox5.unstakeSbtc({
      signerManager: signer,
      amountToWithdrawalSats: unstakeAmount,
    }),
    alice,
  );
});

/**
 * Regression for stacks-network/stacks-core#7295. `announce-l1-early-exit`
 * also mutates next-cycle bond / signer shares (zeros the staker's
 * `amount-sats`, debits `protocol-bonds-total-staked`, and rewrites the
 * per-cycle bond-share maps via `remove-staker-from-bond-cycles`), so it
 * must reject during the current cycle's prepare phase too. Simnet can't
 * register a real L1-lock bond (fake burn header hashes fail
 * `ERR_INVALID_BTC_HEADER`), so we exercise the guard on an sBTC bond:
 * pre-fix the call falls through to `ERR_CANNOT_ANNOUNCE_L1_EARLY_UNLOCK`
 * at the `is-l1-lock` assertion; post-fix the prepare-phase guard fires
 * first.
 */
test('announce-l1-early-exit is rejected during the prepare phase', () => {
  const signer = testSigner.identifier;
  const aliceSbtc = 100000n;

  registerSigner();
  setupBondForAllowlist([{ maxSats: aliceSbtc, staker: alice }]);
  txOk(
    pox5.registerForBond({
      bondIndex: 0n,
      signerManager: signer,
      amountUstx: stxToUStx(50_000),
      btcLockup: err(aliceSbtc),
      signerCalldata: null,
    }),
    alice,
  );

  mineUntil(rov(pox5.rewardCycleToBurnHeight(1n)) - 9n);
  expect(rov(pox5.isInPreparePhase(rov(pox5.currentPoxRewardCycle())))).toBe(
    true,
  );

  expect(txErr(pox5.announceL1EarlyExit(alice, signer), alice).value).toBe(
    pox5Errors.ERR_STAKE_IN_PREPARE_PHASE,
  );
});

/**
 * After the bond period ends, an sBTC bond participant should still be able to
 * retrieve their locked sBTC.
 */
test('sbtc bond participant can recover sbtc after bond ends', () => {
  const signer = testSigner.identifier;
  const aliceSbtc = 100000n;

  registerSigner();

  txOk(
    pox5.setupBond({
      bondIndex: 0n,
      targetRate: 1200n,
      stxValueRatio: 10n,
      minUstxRatio: 100n,
      earlyUnlockBytes: new Uint8Array(),
      allowlist: [{ maxSats: aliceSbtc, staker: alice }],
    }),
    deployer,
  );
  txOk(
    pox5.registerForBond({
      bondIndex: 0n,
      signerManager: signer,
      amountUstx: stxToUStx(50_000),
      btcLockup: err(aliceSbtc),
      signerCalldata: null,
    }),
    alice,
  );

  // Mine past the end of the bond period (12 cycles after bond start).
  const bondEndCycle =
    rov(pox5.bondPeriodToBurnHeight(0n)) +
    pox5.constants.BOND_LENGTH_CYCLES * REWARD_CYCLE_LENGTH;
  mineUntil(bondEndCycle + 1n);

  const aliceBalance = sbtcBalance(alice);
  txOk(
    pox5.unstakeSbtc({
      signerManager: signer,
      amountToWithdrawalSats: aliceSbtc,
    }),
    alice,
  );
  expect(sbtcBalance(alice)).toBe(aliceBalance + aliceSbtc);
});

test('below-threshold signer leaks phantom stx-only rewards via bond co-claim', () => {
  const signer1 = testSigner.identifier;
  const signer2 = deployTestSigner('phantom-bond-signer-2').identifier;
  const bobSbtc = 400_000n;
  const targetRate = 1200n;

  registerSigner();

  // Bond 0 with bob as the lone participant on signer1. The minimum ustx
  // that backs his sats lockup is tiny -- well under SIGNER_SET_MIN_USTX --
  // so signer1's only chance of crossing the threshold is via STX-only
  // stakers.
  txOk(
    pox5.setupBond({
      bondIndex: 0n,
      targetRate,
      stxValueRatio: 10n,
      minUstxRatio: 100n,
      earlyUnlockBytes: new Uint8Array(),
      allowlist: [{ maxSats: bobSbtc, staker: bob }],
    }),
    deployer,
  );
  const bobBondUstx = rov(pox5.minUstxForSatsAmount(bobSbtc, 10n, 100n));
  txOk(
    pox5.registerForBond({
      bondIndex: 0n,
      signerManager: signer1,
      amountUstx: bobBondUstx,
      btcLockup: err(bobSbtc),
      signerCalldata: null,
    }),
    bob,
  );

  // Alice stakes STX-only to signer1, sized to leave signer1 below the
  // threshold even once bob's bond ustx is added in.
  const aliceStake = stxToUStx(40_000);
  expect(aliceStake + bobBondUstx).toBeLessThan(
    pox5.constants.SIGNER_SET_MIN_USTX,
  );
  txOk(
    pox5.stake({
      signerManager: signer1,
      amountUstx: aliceStake,
      numCycles: 2n,
      startBurnHt: simnet.burnBlockHeight,
      signerCalldata: null,
    }),
    alice,
  );

  // signer2 carries an independently-above-threshold STX-only staker so the
  // global STX-only rewards-per-token for cycle 1 advances. Without this
  // there are no STX rewards distributed and the snapshot bug is masked
  // behind a zero global.
  txOk(
    pox5.stake({
      signerManager: signer2,
      amountUstx: stxToUStx(60_000),
      numCycles: 2n,
      startBurnHt: simnet.burnBlockHeight,
      signerCalldata: null,
    }),
    charlie,
  );

  expect(isSignerInCycle({ signer: signer1, cycle: 1n })).toBe(false);
  expect(isSignerInCycle({ signer: signer2, cycle: 1n })).toBe(true);
  expect(rov(pox5.getSignerSharesStakedForCycle(signer1, 1n, null))).toBe(0n);

  // Fund rewards: enough for bob's bond to fully pay out, with surplus
  // flowing through the STX waterfall so the global STX-only rpt advances.
  sbtcTransfer(1000n, deployer, pox5.identifier);
  mineUntil(rov(pox5.rewardCycleToBurnHeight(1n)) + HALF_CYCLE_LENGTH);
  txOk(pox5.calculateRewards([0n]), deployer);

  // Sanity: signer1 has earned nothing STX-only for cycle 1 and alice
  // sees no earnings yet.
  expect(rov(pox5.getEarned(signer1, 1n, null))).toBe(0n);
  expect(rov(testSigner.getEarnedStakerRewards(alice, 1n, null))).toBe(0n);

  // Trigger the bond claim. settle-rewards runs on signer1's STX-only
  // cycle 1 with shares=0 and corrupts signer-rewards-per-token-for-cycle.
  txOk(testSigner.claimRewards([0n], 1n), deployer);

  // signer1's STX-only earnings remain 0 -- it never contributed.
  expect(rov(pox5.getEarned(signer1, 1n, null))).toBe(0n);

  // Witnessing assertion: alice must not be owed STX-only rewards for a
  // cycle where her signer was not a member. Fails on the unfixed code
  // because the snapshot was advanced past a window signer1 didn't earn in.
  expect(rov(testSigner.getEarnedStakerRewards(alice, 1n, null))).toBe(0n);
});

/**
 * Test against a scenario where an orphaned staker keeps phantom rewards when co-staker changes signer.
 *
 * In that case, the orphaned staker should not keep phantom rewards.
 */
test('orphaned staker does not keep phantom rewards when co-staker changes signer', () => {
  const signer1 = testSigner.identifier;
  const signer2 = deployTestSigner('phantom-signer-2').identifier;
  const aliceStake = stxToUStx(60_000);
  const bobStake = stxToUStx(40_000);

  registerSigner();

  txOk(
    pox5.stake({
      signerManager: signer1,
      amountUstx: aliceStake,
      numCycles: 6n,
      startBurnHt: simnet.burnBlockHeight,
      signerCalldata: null,
    }),
    alice,
  );
  txOk(
    pox5.stake({
      signerManager: signer1,
      amountUstx: bobStake,
      numCycles: 6n,
      startBurnHt: simnet.burnBlockHeight,
      signerCalldata: null,
    }),
    bob,
  );

  // Alice moves to signer2 (still above min), dropping signer1 below the min
  // for cycle 2+. signer2 staying in the set keeps the cycle-2 rpt advancing.
  txOk(
    pox5.stakeUpdate({
      signerManager: signer2,
      oldSignerManager: signer1,
      cyclesToExtend: 0n,
      amountIncrease: 0n,
      signerCalldata: null,
    }),
    alice,
  );

  expect(isSignerInCycle({ signer: signer1, cycle: 2n })).toBe(false);
  expect(rov(pox5.getSignerSharesStakedForCycle(signer1, 2n, null))).toBe(0n);

  sbtcTransfer(1000n, deployer, pox5.identifier);
  mineUntil(rov(pox5.rewardCycleToBurnHeight(2n)) + HALF_CYCLE_LENGTH);
  txOk(pox5.calculateRewards([]), deployer);

  // signer1 received nothing for cycle 2, so its stakers can be owed nothing.
  expect(rov(pox5.getEarned(signer1, 2n, null))).toBe(0n);
  expect(rov(testSigner.getEarnedStakerRewards(bob, 2n, null))).toBe(0n);
});

/**
 * When a co-staker unstakes, which puts that signer below the minimum,
 * the orphaned staker should not keep phantom rewards.
 */
test('orphaned staker does not keep phantom rewards after co-staker unstakes', () => {
  const signer1 = testSigner.identifier;
  const signer2 = deployTestSigner('siphon-signer-2').identifier;

  registerSigner();

  // signer1: alice (60k) + bob (40k) — above min together, bob alone is below.
  txOk(
    pox5.stake({
      signerManager: signer1,
      amountUstx: stxToUStx(60_000),
      numCycles: 6n,
      startBurnHt: simnet.burnBlockHeight,
      signerCalldata: null,
    }),
    alice,
  );
  txOk(
    pox5.stake({
      signerManager: signer1,
      amountUstx: stxToUStx(40_000),
      numCycles: 6n,
      startBurnHt: simnet.burnBlockHeight,
      signerCalldata: null,
    }),
    bob,
  );
  // signer2: carol (80k) — independently above min, keeps cycle 2 rpt advancing.
  txOk(
    pox5.stake({
      signerManager: signer2,
      amountUstx: stxToUStx(80_000),
      numCycles: 6n,
      startBurnHt: simnet.burnBlockHeight,
      signerCalldata: null,
    }),
    charlie,
  );

  // Alice unstakes — dropping signer1 (only bob, 40k) below the min for cycle 2+.
  txOk(pox5.unstake(signer1), alice);
  expect(isSignerInCycle({ signer: signer1, cycle: 2n })).toBe(false);
  expect(rov(pox5.getSignerSharesStakedForCycle(signer1, 2n, null))).toBe(0n);

  sbtcTransfer(1000n, deployer, pox5.identifier);
  mineUntil(rov(pox5.rewardCycleToBurnHeight(2n)) + HALF_CYCLE_LENGTH);
  txOk(pox5.calculateRewards([]), deployer);

  const signer1Earned = rov(pox5.getEarned(signer1, 2n, null));
  expect(signer1Earned).toBe(0n);

  // Bob is orphaned on the now-sub-min signer1. He must not be owed rewards
  // that signer1 never received.
  expect(
    rov(testSigner.getEarnedStakerRewards(bob, 2n, null)),
  ).toBeLessThanOrEqual(signer1Earned);
});

test('orphaned staker does not gain stx rewards when below-min signer claims bond rewards', () => {
  const signer1 = testSigner.identifier;
  const signer2 = deployTestSigner('orphan-bond-claim-signer-2').identifier;
  const aliceStake = stxToUStx(60_000);
  const bobStake = stxToUStx(40_000);
  const signer2Stake = stxToUStx(80_000);
  const charlieSbtc = 250000n;
  const targetRate = 10000n;

  registerSigner();

  txOk(
    pox5.setupBond({
      bondIndex: 0n,
      targetRate,
      stxValueRatio: 1n,
      minUstxRatio: 1n,
      earlyUnlockBytes: new Uint8Array(),
      allowlist: [{ maxSats: charlieSbtc, staker: charlie }],
    }),
    deployer,
  );
  txOk(
    pox5.registerForBond({
      bondIndex: 0n,
      signerManager: signer1,
      amountUstx: 1n,
      btcLockup: err(charlieSbtc),
      signerCalldata: null,
    }),
    charlie,
  );
  txOk(
    pox5.stake({
      signerManager: signer1,
      amountUstx: aliceStake,
      numCycles: 6n,
      startBurnHt: simnet.burnBlockHeight,
      signerCalldata: null,
    }),
    alice,
  );
  txOk(
    pox5.stake({
      signerManager: signer1,
      amountUstx: bobStake,
      numCycles: 6n,
      startBurnHt: simnet.burnBlockHeight,
      signerCalldata: null,
    }),
    bob,
  );
  txOk(
    pox5.stake({
      signerManager: signer2,
      amountUstx: signer2Stake,
      numCycles: 6n,
      startBurnHt: simnet.burnBlockHeight,
      signerCalldata: null,
    }),
    dave,
  );

  txOk(pox5.unstake(signer1), alice);
  expect(isSignerInCycle({ signer: signer1, cycle: 1n })).toBe(false);
  expect(rov(pox5.getSignerSharesStakedForCycle(signer1, 1n, null))).toBe(0n);
  expect(rov(pox5.getStakerSharesStakedForCycle(bob, 1n, null, signer1))).toBe(
    bobStake,
  );

  sbtcTransfer(10000n, deployer, pox5.identifier);
  mineUntil(rov(pox5.rewardCycleToBurnHeight(1n)) + HALF_CYCLE_LENGTH);
  txOk(pox5.calculateRewards([0n]), deployer);

  expect(rov(pox5.getEarned(signer1, 1n, null))).toBe(0n);
  expect(rov(pox5.getEarned(signer1, 1n, 0n))).toBe(
    bondTargetYieldPerCalculation({ sats: charlieSbtc, targetRate }),
  );

  txOk(testSigner.claimRewards([0n], 1n), deployer);

  expect(rov(testSigner.getEarnedStakerRewards(bob, 1n, null))).toBe(0n);
});

test('below-min signer can later distribute legitimate stx rewards after crossing threshold', () => {
  const signer1 = testSigner.identifier;
  const signer2 = deployTestSigner('orphan-rejoin-signer-2').identifier;
  const aliceStake = stxToUStx(60_000);
  const bobStake = stxToUStx(40_000);
  const daveStake = stxToUStx(10_000);
  const signer2Stake = stxToUStx(80_000);
  const charlieSbtc = 250000n;
  const targetRate = 10000n;

  registerSigner();

  txOk(
    pox5.setupBond({
      bondIndex: 0n,
      targetRate,
      stxValueRatio: 1n,
      minUstxRatio: 1n,
      earlyUnlockBytes: new Uint8Array(),
      allowlist: [{ maxSats: charlieSbtc, staker: charlie }],
    }),
    deployer,
  );
  txOk(
    pox5.registerForBond({
      bondIndex: 0n,
      signerManager: signer1,
      amountUstx: 1n,
      btcLockup: err(charlieSbtc),
      signerCalldata: null,
    }),
    charlie,
  );
  txOk(
    pox5.stake({
      signerManager: signer1,
      amountUstx: aliceStake,
      numCycles: 6n,
      startBurnHt: simnet.burnBlockHeight,
      signerCalldata: null,
    }),
    alice,
  );
  txOk(
    pox5.stake({
      signerManager: signer1,
      amountUstx: bobStake,
      numCycles: 6n,
      startBurnHt: simnet.burnBlockHeight,
      signerCalldata: null,
    }),
    bob,
  );
  txOk(
    pox5.stake({
      signerManager: signer2,
      amountUstx: signer2Stake,
      numCycles: 6n,
      startBurnHt: simnet.burnBlockHeight,
      signerCalldata: null,
    }),
    emily,
  );

  txOk(pox5.unstake(signer1), alice);
  sbtcTransfer(10000n, deployer, pox5.identifier);
  mineUntil(rov(pox5.rewardCycleToBurnHeight(1n)) + HALF_CYCLE_LENGTH);
  txOk(pox5.calculateRewards([0n]), deployer);
  txOk(testSigner.claimRewards([0n], 1n), deployer);

  expect(rov(pox5.getEarned(signer1, 1n, null))).toBe(0n);
  expect(rov(testSigner.getEarnedStakerRewards(bob, 1n, null))).toBe(0n);

  txOk(
    pox5.stake({
      signerManager: signer1,
      amountUstx: daveStake,
      numCycles: 2n,
      startBurnHt: simnet.burnBlockHeight,
      signerCalldata: null,
    }),
    dave,
  );
  expect(isSignerInCycle({ signer: signer1, cycle: 2n })).toBe(true);

  const cycle2ExtraRewards = 1000n;
  const cycle2BondRewards = bondTargetYieldPerCalculation({
    sats: charlieSbtc,
    targetRate,
  });
  sbtcTransfer(
    cycle2BondRewards + cycle2ExtraRewards,
    deployer,
    pox5.identifier,
  );
  mineUntil(rov(pox5.rewardCycleToBurnHeight(2n)) + HALF_CYCLE_LENGTH);
  txOk(pox5.calculateRewards([0n]), deployer);
  txOk(testSigner.claimRewards([0n], 2n), deployer);

  expect(rov(testSigner.getEarnedStakerRewards(bob, 2n, null))).toBe(
    claimableRewards({
      rewards: stxRewards(cycle2ExtraRewards),
      shares: bobStake,
      totalShares: bobStake + daveStake + signer2Stake,
    }),
  );
});

/**
 * Reject calls to `stake`, `stake-update`, `register-for-bond`, and
 * `update-bond-registration` when in the prepare phase of the current reward
 * cycle, since the signer and staker sets are frozen during this time.
 */
test('stake/register/update reject during the prepare phase', () => {
  const signer = testSigner.identifier;
  registerSigner();
  // Second signer used as the new signer for stake-update /
  // update-bond-registration switches.
  const testSigner2 = deployTestSigner('test-signer-2');
  const signer2 = testSigner2.identifier;

  // Pre-stake alice and pre-register bob so stake-update and
  // update-bond-registration have existing memberships to mutate. Charlie and
  // dave stay fresh so they can exercise stake and register-for-bond; dave is
  // allowlisted on bond 0 so the during-prepare attempt reaches the guard
  // rather than tripping ERR_NOT_ALLOWLISTED in the let bindings.
  txOk(
    pox5.setupBond({
      bondIndex: 0n,
      targetRate: 1200n,
      stxValueRatio: 10n,
      minUstxRatio: 100n,
      earlyUnlockBytes: new Uint8Array(),
      allowlist: [
        { maxSats: 100000n, staker: bob },
        { maxSats: 100000n, staker: dave },
      ],
    }),
    deployer,
  );
  txOk(
    pox5.stake({
      signerManager: signer,
      amountUstx: stxToUStx(50_000),
      numCycles: 4n,
      startBurnHt: simnet.burnBlockHeight,
      signerCalldata: null,
    }),
    alice,
  );
  txOk(
    pox5.registerForBond({
      bondIndex: 0n,
      signerManager: signer,
      amountUstx: stxToUStx(50_000),
      btcLockup: err(100000n),
      signerCalldata: null,
    }),
    bob,
  );

  // Cycle 0 prepare phase begins at height 90 (cycle-1-start - 10).
  mineUntil(rov(pox5.rewardCycleToBurnHeight(1n)) - 9n);
  expect(rov(pox5.isInPreparePhase(rov(pox5.currentPoxRewardCycle())))).toBe(
    true,
  );

  // stake during prepare phase -> ERR_STAKE_IN_PREPARE_PHASE
  expect(
    txErr(
      pox5.stake({
        signerManager: signer,
        amountUstx: stxToUStx(50_000),
        numCycles: 2n,
        startBurnHt: simnet.burnBlockHeight,
        signerCalldata: null,
      }),
      charlie,
    ).value,
  ).toBe(pox5Errors.ERR_STAKE_IN_PREPARE_PHASE);

  // stake-update during prepare phase -> ERR_STAKE_IN_PREPARE_PHASE
  expect(
    txErr(
      pox5.stakeUpdate({
        signerManager: signer2,
        oldSignerManager: signer,
        cyclesToExtend: 1n,
        amountIncrease: 0n,
        signerCalldata: null,
      }),
      alice,
    ).value,
  ).toBe(pox5Errors.ERR_STAKE_IN_PREPARE_PHASE);

  // register-for-bond during prepare phase -> ERR_STAKE_IN_PREPARE_PHASE
  expect(
    txErr(
      pox5.registerForBond({
        bondIndex: 0n,
        signerManager: signer,
        amountUstx: stxToUStx(50_000),
        btcLockup: err(100000n),
        signerCalldata: null,
      }),
      dave,
    ).value,
  ).toBe(pox5Errors.ERR_STAKE_IN_PREPARE_PHASE);

  // update-bond-registration during prepare phase -> ERR_STAKE_IN_PREPARE_PHASE
  expect(
    txErr(
      pox5.updateBondRegistration({
        signerManager: signer2,
        oldSignerManager: signer,
        signerCalldata: null,
      }),
      bob,
    ).value,
  ).toBe(pox5Errors.ERR_STAKE_IN_PREPARE_PHASE);

  // Crossing into the next cycle clears prepare phase; all four functions
  // succeed, confirming the prepare-phase guard was the sole blocker. Bond 0
  // has now started, so a fresh bond 1 (which setup-bond can only configure
  // once we're within 2 cycles of its start) is used for dave's success path.
  mineUntil(rov(pox5.rewardCycleToBurnHeight(1n)));
  expect(rov(pox5.isInPreparePhase(rov(pox5.currentPoxRewardCycle())))).toBe(
    false,
  );
  txOk(
    pox5.setupBond({
      bondIndex: 1n,
      targetRate: 1200n,
      stxValueRatio: 10n,
      minUstxRatio: 100n,
      earlyUnlockBytes: new Uint8Array(),
      allowlist: [{ maxSats: 100000n, staker: dave }],
    }),
    deployer,
  );
  txOk(
    pox5.stake({
      signerManager: signer,
      amountUstx: stxToUStx(50_000),
      numCycles: 2n,
      startBurnHt: simnet.burnBlockHeight,
      signerCalldata: null,
    }),
    charlie,
  );
  txOk(
    pox5.stakeUpdate({
      signerManager: signer2,
      oldSignerManager: signer,
      cyclesToExtend: 1n,
      amountIncrease: 0n,
      signerCalldata: null,
    }),
    alice,
  );
  txOk(
    pox5.registerForBond({
      bondIndex: 1n,
      signerManager: signer,
      amountUstx: stxToUStx(50_000),
      btcLockup: err(100000n),
      signerCalldata: null,
    }),
    dave,
  );
  txOk(
    pox5.updateBondRegistration({
      signerManager: signer2,
      oldSignerManager: signer,
      signerCalldata: null,
    }),
    bob,
  );
});

/**
 * `transfer-from-reserve` is private and never called from within the contract;
 * it exists only for the node to invoke as part of consensus (via the SIP
 * process), so it is exercised here directly. It should debit the reserve
 * balance and move the corresponding sBTC out of the pox-5 contract to the
 * recipient.
 */
test('transfer-from-reserve debits the reserve and pays the recipient', () => {
  const signer1 = testSigner.identifier;
  const signer2 = deployTestSigner('reserve-transfer-signer-2').identifier;
  const stakeAmount = stxToUStx(50_000);

  registerSigner();

  txOk(
    pox5.stake({
      signerManager: signer1,
      amountUstx: stakeAmount,
      numCycles: 2n,
      startBurnHt: simnet.burnBlockHeight,
      signerCalldata: null,
    }),
    alice,
  );
  txOk(
    pox5.stake({
      signerManager: signer2,
      amountUstx: stakeAmount,
      numCycles: 2n,
      startBurnHt: simnet.burnBlockHeight,
      signerCalldata: null,
    }),
    bob,
  );

  // Fund the contract with sBTC and run a reward calculation so the reserve
  // takes its cut.
  txOk(
    sbtc.transfer({
      recipient: pox5.identifier,
      amount: 1000n,
      sender: deployer,
      memo: null,
    }),
    deployer,
  );
  mineUntil(rov(pox5.rewardCycleToBurnHeight(1n)) + HALF_CYCLE_LENGTH);
  txOk(pox5.calculateRewards([]), deployer);

  const reserve = reserveRewards(1000n);
  expect(rov(pox5.getReserveBalance())).toBe(reserve);

  const charlieBalanceBefore = sbtcBalance(charlie);
  const contractBalanceBefore = sbtcBalance(pox5.identifier);

  const transfer = txOk(
    pox5.transferFromReserve({ amount: reserve, recipient: charlie }),
    deployer,
  );
  expect(transfer.value).toBe(true);

  // The reserve is fully drained.
  expect(rov(pox5.getReserveBalance())).toBe(0n);

  // sBTC moved from the contract to the recipient.
  expect(sbtcBalance(charlie)).toBe(charlieBalanceBefore + reserve);
  expect(sbtcBalance(pox5.identifier)).toBe(contractBalanceBefore - reserve);

  const transferEvent = filterEvents(
    transfer.events,
    CoreNodeEventType.FtTransferEvent,
  )[0]!;
  expect(transferEvent.data.sender).toBe(pox5.identifier);
  expect(transferEvent.data.recipient).toBe(charlie);
  expect(transferEvent.data.amount).toBe(reserve.toString());
});

test('transfer-from-reserve fails when amount exceeds the reserve balance', () => {
  // A freshly-initialized pox-5 has an empty reserve.
  expect(rov(pox5.getReserveBalance())).toBe(0n);

  const transfer = txErr(
    pox5.transferFromReserve({ amount: 1n, recipient: charlie }),
    deployer,
  );
  expect(transfer.value).toBe(pox5Errors.ERR_INSUFFICIENT_RESERVE_BALANCE);
  expect(rov(pox5.getReserveBalance())).toBe(0n);
});

test('stake locks STX in simnet', () => {
  registerSignerManager();

  const staker = simnet.getAccounts().get('wallet_1')!;
  const stakeAmount = 1_000_000_000_000n;
  const startBurnHt = simnet.burnBlockHeight;

  const { result: stake } = simnet.callPublicFn(
    'ST000000000000000000002AMW42H.pox-5',
    'stake',
    [
      Cl.contractPrincipal(simnet.deployer, 'signer-manager'),
      Cl.uint(stakeAmount),
      Cl.uint(1),
      Cl.uint(startBurnHt),
      Cl.none(),
    ],
    staker,
  );

  expect(stake).toBeOk(expect.anything());

  expect(stxAccount(staker).locked).toBe(stakeAmount);
});
