import {
  CoreNodeEventType,
  err,
  extractErrors,
  isResponse,
  ok,
  projectFactory,
} from '@clarigen/core';
import { accounts, project } from '../clarigen-types';
import { beforeEach, expect, test } from 'vitest';
import { filterEvents, rov, rovErr, rovOk, txErr, txOk } from '@clarigen/test';
import { mineUntil, stxToUStx } from '../test-helpers';
import {
  deployTestSigner,
  errorCodes,
  expectAllSignersHaveKeys,
  getAllStakers,
  isStakerInCycle,
  registerSigner,
  sbtc,
  sbtcBalance,
  testSigner,
  testSignerErrors,
  pox5,
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
      earlyUnlockSigners: new Uint8Array(),
      earlyUnlockAdmin: deployer,
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

  const aliceInfo = rov(pox5.getBondMembership(alice))!;
  expect(aliceInfo).toEqual({
    amountUstx: minAmountUstx,
    bondIndex: 0n,
    isL1Lock: false,
    signer,
  });
  expect(rov(pox5.getStakerSharesStakedForCycle(alice, 0n, true, signer))).toBe(
    sbtcAmount,
  );
  expect(
    rov(pox5.getStakerSharesStakedForCycle(alice, 0n, false, signer)),
  ).toBe(0n);

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

  expect(rov(pox5.getStakerSharesStakedForCycle(bob, 0n, true, signer))).toBe(
    bobAllowance!,
  );
  expect(rov(pox5.getStakerSharesStakedForCycle(bob, 0n, false, signer))).toBe(
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

  txOk(
    pox5.stake({
      signerManager: signer,
      amountUstx: aliceAmount,
      numCycles: 2n,
      startBurnHt: simnet.burnBlockHeight,
      signerCalldata: null,
    }),
    alice,
  );
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
  expect(
    rov(pox5.getStakerSharesStakedForCycle(alice, 1n, false, signer)),
  ).toBe(aliceAmount);
  expect(rov(pox5.getStakerSharesStakedForCycle(alice, 1n, true, signer))).toBe(
    0n,
  );
  expect(rov(pox5.getAmountDelegatedForSigner({ signer, cycle: 2n }))).toBe(
    aliceAmount,
  );
  expect(
    rov(pox5.getStakerSharesStakedForCycle(alice, 2n, false, signer)),
  ).toBe(aliceAmount);
  expect(rov(pox5.getStakerInfo(alice))).toEqual({
    amountUstx: aliceAmount,
    firstRewardCycle: 1n,
    numCycles: 2n,
    signer,
  });

  expect(isStakerInCycle({ staker: signer, cycle: 1n })).toBeFalsy();
  expect(isStakerInCycle({ staker: signer, cycle: 2n })).toBeFalsy();

  txOk(
    pox5.stake({
      signerManager: signer,
      amountUstx: bobAmount,
      numCycles: 3n,
      startBurnHt: simnet.burnBlockHeight,
      signerCalldata: null,
    }),
    bob,
  );

  expect(rov(pox5.getAmountDelegatedForSigner({ signer, cycle: 1n }))).toBe(
    aliceAmount + bobAmount,
  );
  expect(rov(pox5.getAmountDelegatedForSigner({ signer, cycle: 2n }))).toBe(
    aliceAmount + bobAmount,
  );
  expect(rov(pox5.getAmountDelegatedForSigner({ signer, cycle: 3n }))).toBe(
    bobAmount,
  );
  expect(rov(pox5.getStakerSharesStakedForCycle(bob, 1n, false, signer))).toBe(
    bobAmount,
  );

  expect(rov(pox5.getStakerInfo(bob))).toEqual({
    amountUstx: bobAmount,
    firstRewardCycle: 1n,
    numCycles: 3n,
    signer,
  });

  expectAllSignersHaveKeys();

  expect(isStakerInCycle({ staker: signer, cycle: 1n })).toBeFalsy();
  expect(isStakerInCycle({ staker: signer, cycle: 2n })).toBeFalsy();
  expect(isStakerInCycle({ staker: signer, cycle: 3n })).toBeFalsy();

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
  expect(isStakerInCycle({ staker: signer, cycle: 1n })).toBeTruthy();
  expect(isStakerInCycle({ staker: signer, cycle: 2n })).toBeTruthy();
  expect(isStakerInCycle({ staker: signer, cycle: 3n })).toBeFalsy();
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

  mineUntil(rov(pox5.rewardCycleToUnlockHeight(1n)));

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
    rov(pox5.getStakerSharesStakedForCycle(alice, 1n, false, signer1)),
  ).toBe(aliceAmount);
  expect(
    rov(
      pox5.getStakerSharesStakedForCycle(
        alice,
        1n,
        false,
        testSigner2.identifier,
      ),
    ),
  ).toBe(0n);
  expect(
    rov(
      pox5.getStakerSharesStakedForCycle(
        alice,
        2n,
        false,
        testSigner2.identifier,
      ),
    ),
  ).toBe(aliceAmount + 10_000n);
  expect(
    rov(pox5.getStakerSharesStakedForCycle(alice, 2n, false, signer1)),
  ).toBe(0n);

  // signer1 should be removed from the signer set
  expect(isStakerInCycle({ staker: signer1, cycle: 1n })).toBeTruthy();
  expect(isStakerInCycle({ staker: signer1, cycle: 2n })).toBeFalsy();
  expect(isStakerInCycle({ staker: signer1, cycle: 3n })).toBeFalsy();

  // testSigner2 should be added to the signer set from 2-4
  expect(
    isStakerInCycle({ staker: testSigner2.identifier, cycle: 1n }),
  ).toBeFalsy();
  expect(
    isStakerInCycle({ staker: testSigner2.identifier, cycle: 2n }),
  ).toBeTruthy();
  expect(
    isStakerInCycle({ staker: testSigner2.identifier, cycle: 3n }),
  ).toBeTruthy();
  expect(
    isStakerInCycle({ staker: testSigner2.identifier, cycle: 4n }),
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

  mineUntil(rov(pox5.rewardCycleToUnlockHeight(1n)));

  txOk(pox5.unstake({ oldSignerManager: signer }), alice);
  expect(rov(pox5.getStakerInfo(alice))).toEqual({
    amountUstx: aliceAmount,
    firstRewardCycle: 1n,
    numCycles: 1n,
    signer,
  });

  expect(isStakerInCycle({ staker: signer, cycle: 1n })).toBeTruthy();
  expect(isStakerInCycle({ staker: signer, cycle: 2n })).toBeFalsy();
  expect(isStakerInCycle({ staker: signer, cycle: 3n })).toBeFalsy();

  expect(getAllStakers().length).toBe(0);

  mineUntil(rov(pox5.rewardCycleToUnlockHeight(2n)));

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
  expect(rov(pox5.getEarned(signer1, 1n, false))).toBe(
    claimableRewards({
      rewards: stxRewards(1000n),
      shares: stakeAmount,
      totalShares: stakeAmount * 2n,
    }),
  );
  expect(rov(pox5.getEarned(signer2, 1n, false))).toBe(
    claimableRewards({
      rewards: stxRewards(1000n),
      shares: stakeAmount,
      totalShares: stakeAmount * 2n,
    }),
  );
});

/**
 * Distributes one bond period's rewards across two signer managers by their
 * bonded sats share, with no residual rewards for reserve or STX-only stakers.
 */
test('bond rewards split across signers by staked sats', () => {
  const signer1 = testSigner.identifier;
  const signer2 = deployTestSigner('bond-reward-signer-2').identifier;
  const aliceSbtc = 100000n;
  const bobSbtc = 300000n;

  registerSigner();

  txOk(
    pox5.setupBond({
      bondIndex: 0n,
      targetRate: 1200n,
      stxValueRatio: 10n,
      minUstxRatio: 100n,
      earlyUnlockSigners: new Uint8Array(),
      earlyUnlockAdmin: deployer,
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

  expect(rov(pox5.getEarned(signer1, 0n, true))).toBe(250n);
  expect(rov(pox5.getEarned(signer2, 0n, true))).toBe(750n);
  expect(rov(pox5.getReserveBalance())).toBe(0n);
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
      earlyUnlockSigners: new Uint8Array(),
      earlyUnlockAdmin: deployer,
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

  expect(rov(pox5.getEarned(signer, 0n, true))).toBe(400n);
  expect(rov(pox5.getEarned(signer, 1n, false))).toBe(0n);
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
      earlyUnlockSigners: new Uint8Array(),
      earlyUnlockAdmin: deployer,
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
      earlyUnlockSigners: new Uint8Array(),
      earlyUnlockAdmin: deployer,
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

  expect(rov(pox5.getEarned(signer, 0n, true))).toBe(1000n);
  expect(rov(pox5.getEarned(signer, 1n, true))).toBe(500n);
  expect(rov(pox5.getEarned(signer, 3n, false))).toBe(0n);
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
      earlyUnlockSigners: new Uint8Array(),
      earlyUnlockAdmin: deployer,
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
      earlyUnlockSigners: new Uint8Array(),
      earlyUnlockAdmin: deployer,
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

  const stxRewardAmount = stxRewards(1000n);
  const signerStxRewards = claimableRewards({
    rewards: stxRewardAmount,
    shares: stxStake,
    totalShares: stxStake * 2n,
  });

  expect(rov(pox5.getReserveBalance())).toBe(reserveRewards(1000n));
  expect(rov(pox5.getEarned(signer1, 0n, true))).toBe(250n);
  expect(rov(pox5.getEarned(signer2, 1n, true))).toBe(750n);
  expect(rov(pox5.getEarned(signer1, 3n, false))).toBe(signerStxRewards);
  expect(rov(pox5.getEarned(signer2, 3n, false))).toBe(signerStxRewards);

  expect(
    txOk(testSigner.claimRewards([0n], 3n), deployer).value.totalRewards,
  ).toBe(250n + signerStxRewards);
  expect(
    txOk(signer2Contract.claimRewards([1n], 3n), deployer).value.totalRewards,
  ).toBe(750n + signerStxRewards);
  expect(rov(pox5.getEarned(signer1, 0n, true))).toBe(0n);
  expect(rov(pox5.getEarned(signer1, 3n, false))).toBe(0n);
  expect(rov(pox5.getEarned(signer2, 1n, true))).toBe(0n);
  expect(rov(pox5.getEarned(signer2, 3n, false))).toBe(0n);
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

  expect(rov(testSigner.getEarnedStakerRewards(alice, 1n, false))).toBe(0n);

  txOk(testSigner.claimRewards([], 1n), deployer);

  expect(rov(testSigner.getEarnedStakerRewards(alice, 1n, false))).toBe(
    aliceRewards,
  );
  expect(rov(testSigner.getEarnedStakerRewards(bob, 1n, false))).toBe(
    bobRewards,
  );

  const aliceBalance = sbtcBalance(alice);
  const bobBalance = sbtcBalance(bob);

  const aliceClaim = txOk(testSigner.claimStakerRewards(1n, false), alice);
  const aliceTransfer = filterEvents(
    aliceClaim.events,
    CoreNodeEventType.FtTransferEvent,
  )[0]!;
  expect(aliceTransfer.data.sender).toBe(signer);
  expect(aliceTransfer.data.recipient).toBe(alice);
  expect(aliceTransfer.data.amount).toBe(aliceRewards.toString());
  expect(rov(testSigner.getEarnedStakerRewards(alice, 1n, false))).toBe(0n);

  txOk(testSigner.claimStakerRewards(1n, false), bob);
  expect(sbtcBalance(alice)).toBe(aliceBalance + aliceRewards);
  expect(sbtcBalance(bob)).toBe(bobBalance + bobRewards);
});

test('bond participants claim rewards after signer claims', () => {
  const signer = testSigner.identifier;
  const aliceSbtc = 100000n;
  const bobSbtc = 300000n;

  registerSigner();

  txOk(
    pox5.setupBond({
      bondIndex: 0n,
      targetRate: 1200n,
      stxValueRatio: 10n,
      minUstxRatio: 100n,
      earlyUnlockSigners: new Uint8Array(),
      earlyUnlockAdmin: deployer,
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

  expect(rov(testSigner.getEarnedStakerRewards(alice, 0n, true))).toBe(250n);
  expect(rov(testSigner.getEarnedStakerRewards(bob, 0n, true))).toBe(750n);

  const aliceBalance = sbtcBalance(alice);
  const bobBalance = sbtcBalance(bob);

  txOk(testSigner.claimStakerRewards(0n, true), alice);
  txOk(testSigner.claimStakerRewards(0n, true), bob);

  expect(sbtcBalance(alice)).toBe(aliceBalance + 250n);
  expect(sbtcBalance(bob)).toBe(bobBalance + 750n);
  expect(rov(testSigner.getEarnedStakerRewards(alice, 0n, true))).toBe(0n);
  expect(rov(testSigner.getEarnedStakerRewards(bob, 0n, true))).toBe(0n);
});

test('bond participant keeps already claimed-to-signer rewards after changing signer', () => {
  const signer1 = testSigner.identifier;
  const signer2 = deployTestSigner('bond-staker-pending-signer-2').identifier;
  const aliceSbtc = 400000n;

  registerSigner();

  txOk(
    pox5.setupBond({
      bondIndex: 0n,
      targetRate: 1200n,
      stxValueRatio: 10n,
      minUstxRatio: 100n,
      earlyUnlockSigners: new Uint8Array(),
      earlyUnlockAdmin: deployer,
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

  expect(rov(testSigner.getEarnedStakerRewards(alice, 0n, true))).toBe(1000n);

  txOk(
    pox5.updateBondRegistration({
      signerManager: signer2,
      signerCalldata: null,
      oldSignerManager: signer1,
    }),
    alice,
  );

  expect(rov(testSigner.getEarnedStakerRewards(alice, 0n, true))).toBe(1000n);
});

test('only early unlock admin can announce l1 early exit', () => {
  const signer = testSigner.identifier;
  const aliceSats = 100000n;
  const aliceUstx = stxToUStx(50_000);

  registerSigner();

  txOk(
    pox5.setupBond({
      bondIndex: 0n,
      targetRate: 1200n,
      stxValueRatio: 10n,
      minUstxRatio: 100n,
      earlyUnlockSigners: new Uint8Array(),
      earlyUnlockAdmin: deployer,
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
          {
            amount: aliceSats,
            txid: new Uint8Array(32),
            outputIndex: 0n,
            header: new Uint8Array(80),
            leafHashes: [],
            txCount: 0n,
            txIndex: 0n,
            height: 0n,
            tx: new Uint8Array(1000),
          },
        ],
        unlockBytes: new Uint8Array(),
      }),
      signerCalldata: null,
    }),
    alice,
  );

  const unauthorized = txErr(pox5.announceL1EarlyExit(alice, signer), bob);
  expect(unauthorized.value).toBe(errorCodes.ERR_UNAUTHORIZED);

  txOk(pox5.announceL1EarlyExit(alice, signer), deployer);
  expect(rov(pox5.getStakerSharesStakedForCycle(alice, 0n, true, signer))).toBe(
    0n,
  );
  expect(rov(pox5.getSignerSharesStakedForCycle(signer, 0n, true))).toBe(0n);
  expect(rov(pox5.getTotalSharesStakedForCycle(0n, true))).toBe(0n);
  expect(rov(pox5.getAmountDelegatedForSigner(signer, 1n))).toBe(aliceUstx);
  expect(isStakerInCycle({ staker: signer, cycle: 1n })).toBeTruthy();
});

test('cannot announce l1 early exit for sbtc bond participant', () => {
  const signer = testSigner.identifier;
  const aliceSbtc = 100000n;

  registerSigner();

  txOk(
    pox5.setupBond({
      bondIndex: 0n,
      targetRate: 1200n,
      stxValueRatio: 10n,
      minUstxRatio: 100n,
      earlyUnlockSigners: new Uint8Array(),
      earlyUnlockAdmin: deployer,
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

  const earlyExit = txErr(pox5.announceL1EarlyExit(alice, signer), deployer);
  expect(earlyExit.value).toBe(
    pox5.constants.eRR_CANNOT_ANNOUNCE_L1_EARLY_UNLOCK.value,
  );
  expect(rov(pox5.getStakerSharesStakedForCycle(alice, 0n, true, signer))).toBe(
    aliceSbtc,
  );
});

test('l1 early exit prevents future bond rewards but leaves stx delegated', () => {
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
      earlyUnlockSigners: new Uint8Array(),
      earlyUnlockAdmin: deployer,
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
          {
            amount: aliceSats,
            txid: new Uint8Array(32),
            outputIndex: 0n,
            header: new Uint8Array(80),
            leafHashes: [],
            txCount: 0n,
            txIndex: 0n,
            height: 0n,
            tx: new Uint8Array(1000),
          },
        ],
        unlockBytes: new Uint8Array(),
      }),
      signerCalldata: null,
    }),
    alice,
  );

  txOk(pox5.announceL1EarlyExit(alice, signer), deployer);
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

  expect(rov(pox5.getEarned(signer, 0n, true))).toBe(0n);
  expect(rov(pox5.getSignerCycleMembership(alice, 1n))).toEqual({
    amountUstx: aliceUstx,
    signer,
  });
  expect(rov(pox5.getAmountDelegatedForSigner(signer, 1n))).toBe(aliceUstx);
});

test('l1 early exit does not erase already accrued bond rewards', () => {
  const signer = testSigner.identifier;
  const aliceSats = 480000n;

  registerSigner();

  txOk(
    pox5.setupBond({
      bondIndex: 0n,
      targetRate: 1200n,
      stxValueRatio: 10n,
      minUstxRatio: 100n,
      earlyUnlockSigners: new Uint8Array(),
      earlyUnlockAdmin: deployer,
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
          {
            amount: aliceSats,
            txid: new Uint8Array(32),
            outputIndex: 0n,
            header: new Uint8Array(80),
            leafHashes: [],
            txCount: 0n,
            txIndex: 0n,
            height: 0n,
            tx: new Uint8Array(1000),
          },
        ],
        unlockBytes: new Uint8Array(),
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

  expect(rov(pox5.getEarned(signer, 0n, true))).toBe(1200n);
  txOk(pox5.announceL1EarlyExit(alice, signer), deployer);

  expect(rov(pox5.getEarned(signer, 0n, true))).toBe(1200n);
});

test('sbtc bond participant can partially unstake and only earns on remaining sats', () => {
  const signer = testSigner.identifier;
  const aliceSbtc = 480000n;
  const unstakedSbtc = 120000n;

  registerSigner();

  txOk(
    pox5.setupBond({
      bondIndex: 0n,
      targetRate: 1200n,
      stxValueRatio: 10n,
      minUstxRatio: 100n,
      earlyUnlockSigners: new Uint8Array(),
      earlyUnlockAdmin: deployer,
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
  expect(rov(pox5.getStakerSharesStakedForCycle(alice, 0n, true, signer))).toBe(
    remainingSbtc,
  );
  expect(rov(pox5.getSignerSharesStakedForCycle(signer, 0n, true))).toBe(
    remainingSbtc,
  );
  expect(rov(pox5.getTotalSharesStakedForCycle(0n, true))).toBe(remainingSbtc);
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

  expect(rov(pox5.getEarned(signer, 0n, true))).toBe(900n);
});

test('sbtc unstake preserves already accrued rewards', () => {
  const signer = testSigner.identifier;
  const aliceSbtc = 480000n;
  const unstakedSbtc = 240000n;

  registerSigner();

  txOk(
    pox5.setupBond({
      bondIndex: 0n,
      targetRate: 1200n,
      stxValueRatio: 10n,
      minUstxRatio: 100n,
      earlyUnlockSigners: new Uint8Array(),
      earlyUnlockAdmin: deployer,
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
  expect(rov(pox5.getEarned(signer, 0n, true))).toBe(1200n);

  txOk(
    pox5.unstakeSbtc({
      signerManager: signer,
      amountToWithdrawalSats: unstakedSbtc,
    }),
    alice,
  );
  expect(rov(pox5.getEarned(signer, 0n, true))).toBe(1200n);

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

  expect(rov(pox5.getEarned(signer, 0n, true))).toBe(1800n);
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
      earlyUnlockSigners: new Uint8Array(),
      earlyUnlockAdmin: deployer,
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
  expect(rov(pox5.getStakerSharesStakedForCycle(alice, 0n, true, signer))).toBe(
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

  expect(rov(pox5.getEarned(signer, 0n, true))).toBe(0n);
});

test('sbtc unstake rejects invalid signer, l1 bonds, and excess withdrawal', () => {
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
      earlyUnlockSigners: new Uint8Array(),
      earlyUnlockAdmin: deployer,
      allowlist: [
        { maxSats: aliceSbtc, staker: alice },
        { maxSats: aliceSbtc, staker: bob },
      ],
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
  const headerHash = simnet.runSnippet(
    `(get-burn-block-info? header-hash u${simnet.burnBlockHeight})`,
  );
  const isInRegtest = simnet.runSnippet(`is-in-regtest`);
  console.log('headerHash', headerHash);
  console.log('isInRegtest', isInRegtest);
  txOk(
    pox5.registerForBond({
      bondIndex: 0n,
      signerManager: signer1,
      amountUstx: stxToUStx(50_000),
      btcLockup: ok({
        outputs: [
          {
            amount: aliceSbtc,
            txid: new Uint8Array(32),
            outputIndex: 0n,
            header: new Uint8Array(80),
            leafHashes: [],
            txCount: 0n,
            txIndex: 0n,
            height: 0n,
            tx: new Uint8Array(1000),
          },
        ],
        unlockBytes: new Uint8Array(),
      }),
      signerCalldata: null,
    }),
    bob,
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
  expect(
    txErr(
      pox5.unstakeSbtc({
        signerManager: signer1,
        amountToWithdrawalSats: 1n,
      }),
      bob,
    ).value,
  ).toBe(errorCodes.ERR_CANNOT_UNSTAKE_SBTC);
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
      earlyUnlockSigners: new Uint8Array(),
      earlyUnlockAdmin: deployer,
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
      earlyUnlockSigners: new Uint8Array(),
      earlyUnlockAdmin: deployer,
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
  expect(isStakerInCycle({ staker: signer1, cycle: 1n })).toBeFalsy();
  expect(isStakerInCycle({ staker: signer2, cycle: 1n })).toBeTruthy();
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
      earlyUnlockSigners: new Uint8Array(),
      earlyUnlockAdmin: deployer,
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
  expect(isStakerInCycle({ staker: signer1, cycle: 1n })).toBeTruthy();
  expect(isStakerInCycle({ staker: signer1, cycle: 2n })).toBeTruthy();
  expect(isStakerInCycle({ staker: signer2, cycle: 1n })).toBeFalsy();
  expect(isStakerInCycle({ staker: signer2, cycle: 2n })).toBeFalsy();

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

  expect(isStakerInCycle({ staker: signer1, cycle: 1n })).toBeTruthy();
  expect(isStakerInCycle({ staker: signer1, cycle: 2n })).toBeFalsy();
  expect(isStakerInCycle({ staker: signer1, cycle: 12n })).toBeFalsy();
  expect(isStakerInCycle({ staker: signer2, cycle: 1n })).toBeFalsy();
  expect(isStakerInCycle({ staker: signer2, cycle: 2n })).toBeTruthy();
  expect(isStakerInCycle({ staker: signer2, cycle: 12n })).toBeTruthy();
});

test('bond participant rewards follow updated signer', () => {
  const signer1 = testSigner.identifier;
  const signer2 = deployTestSigner('bond-update-reward-signer-2').identifier;
  const aliceSbtc = 400000n;

  registerSigner();

  txOk(
    pox5.setupBond({
      bondIndex: 0n,
      targetRate: 1200n,
      stxValueRatio: 10n,
      minUstxRatio: 100n,
      earlyUnlockSigners: new Uint8Array(),
      earlyUnlockAdmin: deployer,
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

  expect(rov(pox5.getEarned(signer1, 0n, true))).toBe(0n);
  expect(rov(pox5.getEarned(signer2, 0n, true))).toBe(1000n);
});

test('bond signer update preserves old signer rewards and sends future rewards to new signer', () => {
  const signer1 = testSigner.identifier;
  const signer2 = deployTestSigner('bond-update-accrued-signer-2').identifier;
  const aliceSbtc = 480000n;

  registerSigner();

  txOk(
    pox5.setupBond({
      bondIndex: 0n,
      targetRate: 1200n,
      stxValueRatio: 10n,
      minUstxRatio: 100n,
      earlyUnlockSigners: new Uint8Array(),
      earlyUnlockAdmin: deployer,
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
  expect(rov(pox5.getEarned(signer1, 0n, true))).toBe(1200n);

  txOk(
    pox5.updateBondRegistration({
      signerManager: signer2,
      signerCalldata: null,
      oldSignerManager: signer1,
    }),
    alice,
  );
  expect(rov(pox5.getEarned(signer1, 0n, true))).toBe(1200n);
  expect(rov(pox5.getEarned(signer2, 0n, true))).toBe(0n);

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

  expect(rov(pox5.getEarned(signer1, 0n, true))).toBe(1200n);
  expect(rov(pox5.getEarned(signer2, 0n, true))).toBe(1200n);
});

test('stakers cannot claim before signer receives rewards', () => {
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

  const claim = txErr(testSigner.claimStakerRewards(1n, false), alice);
  expect(claim.value).toBe(testSignerErrors.ERR_NO_CLAIMABLE_REWARDS);
  expect(rov(testSigner.getEarnedStakerRewards(alice, 1n, false))).toBe(0n);
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
  expect(rov(pox5.getEarned(signer, 1n, false))).toBe(expectedRewards);
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
  const expectedYieldPeriod1 = (totalSbtcPeriod1 * targetRate) / 10000n;
  const perCycleYieldPeriod1 = expectedYieldPeriod1 / 24n; // 24 reward cycles per year
  const perRewardCalcYieldPeriod1 = perCycleYieldPeriod1 / 2n; // 2 calculations per cycle
  console.log('test params', {
    totalSbtcPeriod1,
    expectedYieldPeriod1,
    perCycleYieldPeriod1,
    perRewardCalcYieldPeriod1,
  });

  txOk(
    pox5.setupBond({
      bondIndex: 0n,
      targetRate,
      stxValueRatio,
      minUstxRatio,
      earlyUnlockSigners: new Uint8Array(),
      earlyUnlockAdmin: deployer,
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

  expect(rov(pox5.getTotalSbtcStaked(0n))).toBe(aliceSbtc + bobSbtc);

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
  expect(rov(pox5.getSignerSharesStakedForCycle(signer, 1n, false))).toBe(0n);

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
  expect(rov(pox5.getSignerSharesStakedForCycle(signer, 1n, false))).toBe(
    charlieStake + daveStake,
  );

  // verify shares state
  expect(rov(pox5.getTotalSharesStakedForCycle(0n, true))).toBe(
    aliceSbtc + bobSbtc,
  );
  expect(rov(pox5.getSignerSharesStakedForCycle(signer, 0n, true))).toBe(
    aliceSbtc + bobSbtc,
  );
  expect(rov(pox5.getTotalSharesStakedForCycle(1n, false))).toBe(
    charlieStake + daveStake,
  );
  expect(rov(pox5.getSignerSharesStakedForCycle(signer, 1n, false))).toBe(
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
  const rewardsPerToken = rov(pox5.getRewardsPerTokenForCycle(0n, true));
  expect(
    (rewardsPerToken * (aliceSbtc + bobSbtc)) / pox5.constants.PRECISION,
  ).toBe(perRewardCalcYieldPeriod1);

  // time of last calculation should be updated
  expect(rov(pox5.getLastRewardComputeHeight())).toBe(
    BigInt(simnet.burnBlockHeight - 1),
  );

  expect(rov(pox5.getReserveBalance())).toBe(reserveRewards(extra1));

  const rewardsPerUstx = rov(pox5.getRewardsPerTokenForCycle(1n, false));
  const totalStakedUstx = rov(
    pox5.getSignerSharesStakedForCycle(signer, 1n, false),
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
  expect(rov(pox5.getEarned(signer, 1n, false))).toBe(
    claimableRewardsForStxStakers,
  );
  expect(rov(pox5.getEarned(signer, 0n, true))).toBe(perRewardCalcYieldPeriod1);

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

  expect(rov(pox5.getSignerSharesStakedForCycle(signer2, 2n, false))).toBe(
    emilyStake,
  );
  expect(rov(pox5.getSignerSharesStakedForCycle(signer2, 2n, false))).toBe(
    rov(pox5.getTotalSharesStakedForCycle(2n, false)) / 2n,
  );

  expect(rov(pox5.getNewRewards())).toBe(rewards2);

  // mine through next distribution cycle
  mineUntil(rov(pox5.rewardCycleToBurnHeight(2n)));

  txOk(pox5.calculateRewards([0n]), deployer);

  // now, signer 1 still is the only one who can claim rewards
  expect(rov(pox5.getEarned(signer, 1n, false))).toBe(
    claimableRewards({
      rewards: rewardsForStxStakers * 2n,
      shares: totalStakedUstx,
      totalShares: totalStakedUstx,
    }),
  );
  expect(rov(pox5.getEarned(signer, 0n, true))).toBe(
    perRewardCalcYieldPeriod1 * 2n,
  );
  expect(rov(pox5.getEarned(signer2, 1n, false))).toBe(0n);
  // no one has rewards for the next cycle yet
  expect(rov(pox5.getEarned(signer, 2n, false))).toBe(0n);

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
  expect(rov(pox5.getEarned(signer2, 2n, false))).toBe(
    rov(pox5.getEarned(signer, 2n, false)),
  );
  expect(rov(pox5.getEarned(signer, 0n, true))).toBe(
    perRewardCalcYieldPeriod1 * 3n,
  );
  // new signer still can't claim for the next cycle, of course.
  expect(rov(pox5.getEarned(signer2, 1n, false))).toBe(0n);

  const signer2Claimable = rov(pox5.getEarned(signer2, 2n, false));
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
        earlyUnlockSigners: new Uint8Array(),
        earlyUnlockAdmin: deployer,
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
