import { accounts } from '../clarigen-types';
import { assertErr, assertOk, rov, txErr, txOk } from '@clarigen/test';
import { test, expect, describe, beforeEach } from 'vitest';
import {
  mineUntil,
  randomPoxAddress,
  randomStacksAddress,
} from '../test-helpers';
import { hex } from '@scure/base';
import * as BTC from '@scure/btc-signer';
import {
  serializeLockupScript,
  pox5,
  errorCodes,
  testPool,
} from './pox-5-helpers';
import { randomBytes } from '@stacks/transactions';
import { inspect } from 'node:util';

const deployer = accounts.deployer.address;
const alice = accounts.wallet_1.address;
// const bob = accounts.wallet_2.address;
// const charlie = accounts.wallet_3.address;
// const dave = accounts.wallet_4.address;

function getAllStackers() {
  const nextCycle = rov(pox5.currentPoxRewardCycle()) + 1n;
  return getAllStackersForCycle(nextCycle);
}

function getAllStackersForCycle(cycle: bigint) {
  const first = rov(pox5.getStakerSetFirstItemForCycle(cycle));
  let stackers: string[] = [];
  let cur: string | null = first;
  if (cur) stackers.push(cur);
  while (cur) {
    const item = rov(pox5.getStakerSetNextItemForCycle(cur, cycle));
    if (item) stackers.push(item);
    cur = item;
  }
  return stackers;
}

function getAllStackerInfos() {
  return getAllStackers()
    .map((stacker) => rov(pox5.getStakerInfo(stacker)))
    .filter((info) => info !== null);
}

describe('staking', () => {
  beforeEach(() => {
    txOk(
      pox5.setBurnchainParameters({
        firstBurnHeight: 0n,
        prepareCycleLength: 10n,
        rewardCycleLength: 100n,
        beginPox5RewardCycle: 0n,
      }),
      deployer,
    );
  });
  test('staking adds a stacker to the linked list', () => {
    const stacker = alice;
    const numCycles = 4;
    const unlockBytes = randomBytes(255);
    const signerKey = randomBytes(33);
    const result = txOk(
      pox5.stake({
        amountUstx: 1000000,
        poxAddr: randomPoxAddress(),
        signerKey,
        maxAmount: 1000000,
        authId: 0,
        signerSig: randomBytes(65),
        startBurnHt: simnet.burnBlockHeight,
        numCycles,
        unlockBytes,
      }),
      stacker,
    );
    expect(result.value.unlockBurnHeight).toBe(450n);
    const allStackers = getAllStackerInfos();
    expect(allStackers).toHaveLength(1);
    const info = allStackers[0];
    expect(info.amountUstx).toBe(1000000n);
    assertErr(info.poolOrSoloInfo);
    expect(info.poolOrSoloInfo.value.poxAddr.version).toStrictEqual(
      Uint8Array.from([0x01]),
    );
    expect(info.poolOrSoloInfo.value.signerKey).toStrictEqual(signerKey);

    expect(info.firstRewardCycle).toBe(1n);
    expect(info.numCycles).toBe(4n);
    expect(info.unlockBytes).toStrictEqual(unlockBytes);
    expect(result.value.unlockCycle).toBe(4n);
    const startCycle = 1;
    for (let i = 0; i < numCycles; i++) {
      const stackers = getAllStackersForCycle(BigInt(startCycle + i));
      expect(stackers).toHaveLength(1);
      expect(stackers[0]).toBe(stacker);
    }
    expect(
      rov(pox5.getStakerSetItemForCycle({ staker: stacker, cycle: 0n })),
    ).toBeNull();
  });

  test(`can stake for ${pox5.constants.MAX_NUM_CYCLES} cycles`, () => {
    const staker = alice;
    const maxCycles = pox5.constants.MAX_NUM_CYCLES;
    const numCycles = maxCycles;
    const result = txOk(
      pox5.stake({
        amountUstx: 1000000,
        poxAddr: randomPoxAddress(),
        signerKey: randomBytes(33),
        maxAmount: 1000000,
        authId: 0,
        signerSig: randomBytes(65),
        startBurnHt: simnet.burnBlockHeight,
        numCycles,
        unlockBytes: randomBytes(255),
      }),
      staker,
    );
    if (result.costs) {
      console.log(
        'Costs to stake for max cycles:\n',
        inspect(result.costs, { depth: null }),
      );
    }
    const { unlockCycle } = result.value;
    expect(unlockCycle).toBe(maxCycles);
    expect(numCycles).toBe(maxCycles);
    const startCycle = 1;
    for (let i = 0; i < numCycles; i++) {
      const stackers = getAllStackersForCycle(BigInt(startCycle + i));
      expect(stackers).toHaveLength(1);
      expect(stackers[0]).toBe(staker);
    }
    expect(
      rov(pox5.getStakerSetItemForCycle({ staker, cycle: 0n })),
    ).toBeNull();
  });

  test(`cannot stake for ${pox5.constants.MAX_NUM_CYCLES + 1n} cycles`, () => {
    const staker = alice;
    const numCycles = pox5.constants.MAX_NUM_CYCLES + 1n;
    const result = txErr(
      pox5.stake({
        amountUstx: 1000000,
        poxAddr: randomPoxAddress(),
        signerKey: randomBytes(33),
        maxAmount: 1000000,
        authId: 0,
        signerSig: randomBytes(65),
        startBurnHt: simnet.burnBlockHeight,
        numCycles,
        unlockBytes: randomBytes(255),
      }),
      staker,
    );
    expect(result.value).toEqual(errorCodes.ERR_INVALID_NUM_CYCLES);
  });

  test('can re-stake after stake is expired', () => {
    const staker = alice;
    const numCycles = 1;
    txOk(
      pox5.stake({
        amountUstx: 1000000,
        poxAddr: randomPoxAddress(),
        signerKey: randomBytes(33),
        maxAmount: 1000000,
        authId: 0,
        signerSig: randomBytes(65),
        startBurnHt: simnet.burnBlockHeight,
        numCycles,
        unlockBytes: randomBytes(255),
      }),
      staker,
    );

    mineUntil(rov(pox5.rewardCycleToUnlockHeight(2n)));

    const result = txOk(
      pox5.stake({
        amountUstx: 1000000,
        poxAddr: randomPoxAddress(),
        signerKey: randomBytes(33),
        maxAmount: 1000000,
        authId: 1,
        signerSig: randomBytes(65),
        startBurnHt: simnet.burnBlockHeight,
        numCycles,
        unlockBytes: randomBytes(255),
      }),
      staker,
    );
    expect(result.value.unlockCycle).toBe(3n);
  });

  describe('extending stake', () => {
    test('can extend stake with longer unlock height', () => {
      const stacker = alice;
      const poxAddr = randomPoxAddress();
      const signerKey = randomBytes(33);
      const signerSig = randomBytes(65);
      const unlockBytes = randomBytes(255);
      const firstNumCycles = 1;
      const secondNumCycles = 1;

      const stakeReceipt = txOk(
        pox5.stake({
          amountUstx: 1000000,
          poxAddr,
          signerKey,
          maxAmount: 1000000,
          authId: 0,
          signerSig,
          startBurnHt: simnet.burnBlockHeight,
          numCycles: firstNumCycles,
          unlockBytes,
        }),
        stacker,
      );
      expect(stakeReceipt.value.unlockCycle).toBe(1n);

      mineUntil(stakeReceipt.value.unlockBurnHeight);

      const extendReceipt = txOk(
        pox5.stakeExtend({
          amountUstx: 1000000,
          numCycles: secondNumCycles,
          poxAddr,
          signerKey,
          signerSig,
          maxAmount: 1000000,
          authId: 0,
          unlockBytes,
        }),
        stacker,
      );
      expect(extendReceipt.value.unlockCycle).toBe(2n);

      const stakerInfo = rov(pox5.getStakerInfo(stacker))!;
      expect(stakerInfo.firstRewardCycle).toBe(2n);
      expect(stakerInfo.numCycles).toBe(1n);
    });
  });

  describe('pool-based staking', () => {
    test('can register a pool', () => {
      const owner = accounts.deployer.address;
      const signerKey = randomBytes(33);
      const poxAddr = randomPoxAddress();
      const result = txOk(
        pox5.registerPool({
          poolOwner: testPool.identifier,
          signerKey,
          poxAddr,
          signerSig: randomBytes(65),
          authId: 0,
        }),
        owner,
      );
      expect(result.value.owner).toBe(testPool.identifier);
      expect(result.value.signerKey).toStrictEqual(signerKey);
      expect(result.value.poxAddr).toStrictEqual(poxAddr);
      const pool = rov(pox5.getPoolInfo(testPool.identifier));
      expect(pool).toBeDefined();
      expect(pool?.signerKey).toStrictEqual(signerKey);
      expect(pool?.poxAddr).toStrictEqual(poxAddr);
    });

    test('can stake to a pool', () => {
      const poxAddr = randomPoxAddress();
      const signerKey = randomBytes(33);
      const signerSig = randomBytes(65);
      const unlockBytes = randomBytes(255);
      const numCycles = 1;
      txOk(
        pox5.registerPool({
          poolOwner: testPool.identifier,
          signerKey,
          poxAddr,
          signerSig,
          authId: 0,
        }),
        deployer,
      );
      const receipt = txOk(
        pox5.stakePooled({
          poolOwner: testPool.identifier,
          amountUstx: 1000000,
          numCycles,
          unlockBytes,
          startBurnHt: simnet.burnBlockHeight,
        }),
        alice,
      );
      expect(receipt.value.stacker).toBe(alice);

      const stakerInfo = rov(pox5.getStakerInfo(alice))!;
      assertOk(stakerInfo.poolOrSoloInfo);
      expect(stakerInfo.poolOrSoloInfo.value).toBe(testPool.identifier);

      expect(
        rov(
          pox5.getStakerSetItemForCycle({
            staker: alice,
            cycle: 1n,
          }),
        ),
      ).not.toBeNull();
    });
  });
});

describe('cycle-based linked list', () => {
  const stackers = [
    randomStacksAddress(),
    randomStacksAddress(),
    randomStacksAddress(),
    randomStacksAddress(),
    randomStacksAddress(),
  ];
  const cycle = 1n;

  test('can add multiple stackers to the linked list', () => {
    for (const stacker of stackers) {
      txOk(pox5.addStakerToSetForCycle(stacker, cycle), deployer);
    }
    const lastItem = rov(pox5.getStakerSetLastItemForCycle(cycle));
    expect(lastItem).toBe(stackers.at(-1));
    expect(rov(pox5.getStakerSetFirstItemForCycle(cycle))).toBe(stackers[0]);
    const allStackers = getAllStackersForCycle(cycle);
    expect(allStackers).toEqual(stackers);
  });
});

describe('calculating l1 unlock height', () => {
  test('scenario 1', () => {
    txOk(
      pox5.setBurnchainParameters({
        firstBurnHeight: 0n,
        prepareCycleLength: 10n,
        rewardCycleLength: 100n,
        beginPox5RewardCycle: 0n,
      }),
      deployer,
    );
    expect(rov(pox5.rewardCycleToUnlockHeight(1n))).toBe(150n);
  });

  test('scenario 2', () => {
    txOk(
      pox5.setBurnchainParameters({
        firstBurnHeight: 0n,
        prepareCycleLength: 10n,
        rewardCycleLength: 2100n,
        beginPox5RewardCycle: 0n,
      }),
      deployer,
    );
    expect(rov(pox5.rewardCycleToUnlockHeight(2))).toBe(5250n);
  });
});
