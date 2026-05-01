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
import { mineUntil, stxToUStx } from '../test-helpers';
import {
  deployTestSigner,
  expectAllSignersHaveKeys,
  getAllStakers,
  isStakerInCycle,
  registerSigner,
  sbtc,
  sbtcBalance,
  testSigner,
} from './pox-5-helpers';

const contracts = projectFactory(project, 'simnet');
const pox5 = contracts.pox5;

const pox5Errors = extractErrors(pox5);

const deployer = accounts.deployer.address;
const alice = accounts.wallet_1.address;
const bob = accounts.wallet_2.address;
const charlie = accounts.wallet_3.address;
const dave = accounts.wallet_4.address;
const emily = accounts.wallet_5.address;

const REWARD_CYCLE_LENGTH = 100n;
const HALF_CYCLE_LENGTH = REWARD_CYCLE_LENGTH / 2n;

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

// helper for generating the list literal for max cycle iterations
test.skip('can output the list literal for max cycle iterations', () => {
  const nums: string[] = [];
  for (let i = 0; i < pox5.constants.MAX_NUM_CYCLES; i++) {
    nums.push(`u${i}`);
  }
  console.log(`(list ${nums.join(' ')})`);
});

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
    amountSats: sbtcAmount,
    amountUstx: minAmountUstx,
    bondIndex: 0n,
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
  expect(rov(pox5.getAmountDelegatedForSigner({ signer, cycle: 2n }))).toBe(
    aliceAmount,
  );
  expect(rov(pox5.getStakerInfo(alice))).toEqual({
    amountUstx: aliceAmount,
    firstRewardCycle: 1n,
    numCycles: 2n,
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

  expect(rov(pox5.getStakerInfo(bob))).toEqual({
    amountUstx: bobAmount,
    firstRewardCycle: 1n,
    numCycles: 3n,
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
      amountIncrease: 0n,
      cyclesToExtend: 1n,
      signerCalldata: null,
    }),
    alice,
  );

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

  txOk(pox5.unstake(), alice);
  expect(rov(pox5.getStakerInfo(alice))).toEqual({
    amountUstx: aliceAmount,
    firstRewardCycle: 1n,
    numCycles: 1n,
  });

  expect(isStakerInCycle({ staker: signer, cycle: 1n })).toBeTruthy();
  expect(isStakerInCycle({ staker: signer, cycle: 2n })).toBeFalsy();
  expect(isStakerInCycle({ staker: signer, cycle: 3n })).toBeFalsy();

  expect(getAllStakers().length).toBe(0);

  mineUntil(rov(pox5.rewardCycleToUnlockHeight(2n)));

  // `getStakerInfo` should return `none` because it's expired
  expect(rov(pox5.getStakerInfo(alice))).toBeNull();
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

  expect(rov(pox5.getTotalSatsStaked(0n))).toBe(aliceSbtc + bobSbtc);

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
    contracts.sbtcToken.transfer({
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

  // reserve balance should be 10% of the extra
  expect(rov(pox5.getReserveBalance())).toBe(
    (extra1 * pox5.constants.RESERVE_RATIO) / 10000n,
  );

  const rewardsPerUstx = rov(pox5.getRewardsPerTokenForCycle(1n, false));
  const totalStakedUstx = rov(
    pox5.getSignerSharesStakedForCycle(signer, 1n, false),
  );
  const rewardsForStxStakers = extra1 - rov(pox5.getReserveBalance());
  expect(totalStakedUstx).toBe(charlieStake + daveStake);
  // expect all extra rewards to be distributed to stx stakers
  expect(rewardsPerUstx).toBe(
    (rewardsForStxStakers * pox5.constants.PRECISION) / totalStakedUstx,
  );

  // we only have one signer, so they get all rewards
  expect(rov(pox5.getClaimableRewards(signer, 1n, false))).toBe(
    rewardsForStxStakers,
  );
  expect(rov(pox5.getClaimableRewards(signer, 0n, true))).toBe(
    perRewardCalcYieldPeriod1,
  );

  // cant call again until next distribution cycle
  txErr(pox5.calculateRewards([0n]), deployer);

  // give some new rewards
  const rewards2 = perRewardCalcYieldPeriod1 + extra1;
  txOk(
    contracts.sbtcToken.transfer({
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
  expect(rov(pox5.getClaimableRewards(signer, 1n, false))).toBe(
    rewardsForStxStakers * 2n,
  );
  expect(rov(pox5.getClaimableRewards(signer, 0n, true))).toBe(
    perRewardCalcYieldPeriod1 * 2n,
  );
  expect(rov(pox5.getClaimableRewards(signer2, 1n, false))).toBe(0n);
  // no one has rewards for the next cycle yet
  expect(rov(pox5.getClaimableRewards(signer, 2n, false))).toBe(0n);

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
  expect(rov(pox5.getClaimableRewards(signer2, 2n, false))).toBe(
    rov(pox5.getClaimableRewards(signer, 2n, false)),
  );
  expect(rov(pox5.getClaimableRewards(signer, 0n, true))).toBe(
    perRewardCalcYieldPeriod1 * 3n,
  );
  // new signer still can't claim for the next cycle, of course.
  expect(rov(pox5.getClaimableRewards(signer2, 1n, false))).toBe(0n);

  const signer2Claimable = rov(pox5.getClaimableRewards(signer2, 2n, false));
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
