import { accounts } from '../clarigen-types';
import { rov, txErr, txOk } from '@clarigen/test';
import { test, expect, describe, beforeEach } from 'vitest';
import {
  mineUntil,
  randomPoxAddress,
  randomStacksAddress,
} from '../test-helpers';
import { hex } from '@scure/base';
import * as BTC from '@scure/btc-signer';
import { serializeLockupScript, pox5, errorCodes } from './pox-5-helpers';
import { randomBytes } from '@stacks/transactions';
import { inspect } from 'node:util';

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
      accounts.deployer.address,
    );
  });
  test('staking adds a stacker to the linked list', () => {
    const stacker = accounts.wallet_1.address;
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
    expect(info.poxAddr.version).toStrictEqual(Uint8Array.from([0x01]));
    expect(info.signerKey).toStrictEqual(signerKey);

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
    const staker = accounts.wallet_1.address;
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
    const staker = accounts.wallet_1.address;
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

  describe('extending stake', () => {
    test('can extend stake with longer unlock height', () => {
      const stacker = accounts.wallet_1.address;
      const secondUnlock = 250n;
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
        pox5.extendStake({
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
      txOk(
        pox5.addStakerToSetForCycle(stacker, cycle),
        accounts.deployer.address,
      );
    }
    const lastItem = rov(pox5.getStakerSetLastItemForCycle(cycle));
    expect(lastItem).toBe(stackers.at(-1));
    expect(rov(pox5.getStakerSetFirstItemForCycle(cycle))).toBe(stackers[0]);
    const allStackers = getAllStackersForCycle(cycle);
    expect(allStackers).toEqual(stackers);
  });

  test('can remove a non-last item from the linked list', () => {
    for (const stacker of stackers) {
      txOk(
        pox5.addStakerToSetForCycle(stacker, cycle),
        accounts.deployer.address,
      );
    }
    const toRemove = stackers[1]!;
    txOk(
      pox5.removeStackerFromSetForCycle(toRemove, cycle),
      accounts.deployer.address,
    );
    const allStackers = getAllStackersForCycle(cycle);
    expect(allStackers).toEqual(stackers.filter((s) => s !== toRemove));
    expect(rov(pox5.getStakerSetNextItemForCycle(stackers[0]!, cycle))).toBe(
      stackers[2]!,
    );
    expect(
      rov(pox5.getStakerSetPrevItemForCycle(stackers[2]!, cycle)),
    ).not.toBe(toRemove);
    expect(rov(pox5.getStakerSetPrevItemForCycle(stackers[2]!, cycle))).toBe(
      stackers[0]!,
    );
    expect(rov(pox5.getStakerSetPrevItemForCycle(toRemove, cycle))).toBe(null);
    expect(rov(pox5.getStakerSetNextItemForCycle(toRemove, cycle))).toBe(null);
  });

  test('can remove the last item from the linked list', () => {
    for (const stacker of stackers) {
      txOk(
        pox5.addStakerToSetForCycle(stacker, cycle),
        accounts.deployer.address,
      );
    }
    const toRemove = stackers.at(-1)!;
    const newLast = stackers.at(-2)!;
    txOk(
      pox5.removeStackerFromSetForCycle(toRemove, cycle),
      accounts.deployer.address,
    );
    const allStackers = getAllStackersForCycle(cycle);
    expect(allStackers).toEqual(stackers.filter((s) => s !== toRemove));
    expect(rov(pox5.getStakerSetLastItemForCycle(cycle))).toBe(newLast);
    expect(rov(pox5.getStakerSetFirstItemForCycle(cycle))).toBe(stackers[0]!);
    expect(rov(pox5.getStakerSetNextItemForCycle(newLast, cycle))).toBe(null);
    expect(rov(pox5.getStakerSetPrevItemForCycle(newLast, cycle))).toBe(
      stackers.at(-3),
    );
    expect(rov(pox5.getStakerSetPrevItemForCycle(toRemove, cycle))).toBe(null);
    expect(rov(pox5.getStakerSetNextItemForCycle(toRemove, cycle))).toBe(null);
  });

  test('can remove the first item from the linked list', () => {
    for (const stacker of stackers) {
      txOk(
        pox5.addStakerToSetForCycle(stacker, cycle),
        accounts.deployer.address,
      );
    }
    const toRemove = stackers[0]!;
    const newFirst = stackers[1]!;
    txOk(
      pox5.removeStackerFromSetForCycle(toRemove, cycle),
      accounts.deployer.address,
    );
    const allStackers = getAllStackersForCycle(cycle);
    expect(allStackers).toEqual(stackers.filter((s) => s !== toRemove));
    expect(rov(pox5.getStakerSetFirstItemForCycle(cycle))).toBe(newFirst);
    expect(rov(pox5.getStakerSetLastItemForCycle(cycle))).toBe(
      stackers.at(-1)!,
    );
    expect(rov(pox5.getStakerSetNextItemForCycle(newFirst, cycle))).toBe(
      stackers[2]!,
    );
    expect(rov(pox5.getStakerSetPrevItemForCycle(newFirst, cycle))).toBe(null);
    expect(rov(pox5.getStakerSetPrevItemForCycle(toRemove, cycle))).toBe(null);
    expect(rov(pox5.getStakerSetNextItemForCycle(toRemove, cycle))).toBe(null);
  });

  test('cannot add a stacker that is already in the linked list', () => {
    txOk(
      pox5.addStakerToSetForCycle(stackers[0]!, cycle),
      accounts.deployer.address,
    );
    const result = txErr(
      pox5.addStakerToSetForCycle(stackers[0]!, cycle),
      accounts.deployer.address,
    );
    expect(result.value).toEqual(errorCodes.ERR_ALREADY_STAKED);
  });

  test('cannot remove a stacker that is not in the linked list', () => {
    const result = txErr(
      pox5.removeStackerFromSetForCycle(stackers[0]!, cycle),
      accounts.deployer.address,
    );
    expect(result.value).toEqual(errorCodes.ERR_NOT_STAKED);
  });
});

describe('constructing lockup scripts', () => {
  test('can get the byte for a u8', () => {
    const n = 123;
    const expected = BTC.ScriptNum().encode(BigInt(n));
    const buff = rov(pox5.uintToBuffLe(n));
    expect(hex.encode(buff)).toStrictEqual(hex.encode(expected));
  });

  test('can construct a lockup script', () => {
    const stacker = 'STAPZXVFZRPKHRK4MAVR9WV1EZAZA157K6E20SBW';
    const unlockBurnHeight = 1_000_000n;
    const unlockBytes = hex.decode(
      '76a914de9db0e31c16b05c0b2d5be612fb3c5a6c41a25188ac',
    );
    const lockupScriptJs = serializeLockupScript({
      stacker,
      unlockBurnHeight,
      unlockBytes,
    });
    const lockupScript = rov(
      pox5.constructUnlockScript({
        stacker,
        unlockBurnHeight: BTC.ScriptNum().encode(unlockBurnHeight),
        unlockBytes,
      }),
    );
    expect(hex.encode(lockupScript)).toStrictEqual(hex.encode(lockupScriptJs));
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
      accounts.deployer.address,
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
      accounts.deployer.address,
    );
    expect(rov(pox5.rewardCycleToUnlockHeight(2))).toBe(5250n);
  });
});
