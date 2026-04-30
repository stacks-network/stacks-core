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
  testSigner,
} from './pox-5-helpers';

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
      pox5.getCurrentAmountStakedForSigner({
        signer,
        cycle: 1n,
      }),
    ),
  ).toBe(aliceAmount);
  expect(rov(pox5.getCurrentAmountStakedForSigner({ signer, cycle: 2n }))).toBe(
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

  expect(rov(pox5.getCurrentAmountStakedForSigner({ signer, cycle: 1n }))).toBe(
    aliceAmount + bobAmount,
  );
  expect(rov(pox5.getCurrentAmountStakedForSigner({ signer, cycle: 2n }))).toBe(
    aliceAmount + bobAmount,
  );
  expect(rov(pox5.getCurrentAmountStakedForSigner({ signer, cycle: 3n }))).toBe(
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

  expect(rov(pox5.getCurrentAmountStakedForSigner({ signer, cycle: 1n }))).toBe(
    aliceAmount + bobAmount + charlieAmount,
  );
  expect(rov(pox5.getCurrentAmountStakedForSigner({ signer, cycle: 2n }))).toBe(
    aliceAmount + bobAmount + charlieAmount,
  );
  expect(rov(pox5.getCurrentAmountStakedForSigner({ signer, cycle: 3n }))).toBe(
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
