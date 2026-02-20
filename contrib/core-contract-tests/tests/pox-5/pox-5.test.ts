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

function getAllStackers() {
  const first = rov(pox5.getStackerSetFirstItem());
  let stackers: string[] = [];
  let cur: string | null = first;
  if (cur) stackers.push(cur);
  while (cur) {
    const item = rov(pox5.getStackerSetNextItem(cur));
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

describe('staking', () => {
  test('staking adds a stacker to the linked list', () => {
    const stacker = accounts.wallet_1.address;
    const unlockBurnHeight = 1_000_000n;
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
        unlockBurnHeight,
        unlockBytes,
      }),
      stacker,
    );
    expect(result.value.unlockBurnHeight).toBe(unlockBurnHeight);
    const allStackers = getAllStackerInfos();
    expect(allStackers).toHaveLength(1);
    const info = allStackers[0];
    expect(info.amountUstx).toBe(1000000n);
    expect(info.poxAddr.version).toStrictEqual(Uint8Array.from([0x01]));
    expect(info.signerKey).toStrictEqual(signerKey);

    expect(info.unlockBurnHeight).toBe(unlockBurnHeight);
    expect(info.unlockBytes).toStrictEqual(unlockBytes);
  });

  test('cannot unstake before the unlock height', () => {
    const unlockHeight = 2000n;

    txOk(
      pox5.stake({
        amountUstx: 1000000,
        poxAddr: randomPoxAddress(),
        signerKey: randomBytes(33),
        maxAmount: 1000000,
        authId: 0,
        signerSig: randomBytes(65),
        startBurnHt: simnet.burnBlockHeight,
        unlockBurnHeight: unlockHeight,
        unlockBytes: randomBytes(255),
      }),
      accounts.wallet_1.address,
    );

    simnet.mineEmptyBlocks(Number(unlockHeight) - simnet.burnBlockHeight);

    const failure = txErr(pox5.unstake(), accounts.wallet_1.address);

    expect(failure.value).toEqual(errorCodes.ERR_NOT_UNLOCKED);
  });

  test('can unstake after the end of their unlock cycle', () => {
    const unlockHeight = 250n;

    txOk(
      pox5.stake({
        amountUstx: 1000000,
        poxAddr: randomPoxAddress(),
        signerKey: randomBytes(33),
        maxAmount: 1000000,
        authId: 0,
        signerSig: randomBytes(65),
        startBurnHt: simnet.burnBlockHeight,
        unlockBurnHeight: unlockHeight,
        unlockBytes: randomBytes(255),
      }),
      accounts.wallet_1.address,
    );

    mineUntil(300n);

    txOk(pox5.unstake(), accounts.wallet_1.address);

    expect(rov(pox5.getStakerInfo(accounts.wallet_1.address))).toBe(null);

    const allStackers = getAllStackers();
    expect(allStackers).toHaveLength(0);
  });

  describe('extending stake', () => {
    test('cannot extend stake with shorter unlock height', () => {
      const stacker = accounts.wallet_1.address;
      const firstUnlock = 1_000_000n;
      const secondUnlock = 999_999n;
      const poxAddr = randomPoxAddress();
      const signerKey = randomBytes(33);
      const signerSig = randomBytes(65);
      const unlockBytes = randomBytes(255);

      txOk(
        pox5.stake({
          amountUstx: 1000000,
          poxAddr,
          signerKey,
          maxAmount: 1000000,
          authId: 0,
          signerSig,
          startBurnHt: simnet.burnBlockHeight,
          unlockBurnHeight: firstUnlock,
          unlockBytes,
        }),
        stacker,
      );

      simnet.mineEmptyBlocks(100);
      const result = txErr(
        pox5.extendStake({
          unlockBurnHeight: secondUnlock,
          poxAddr,
          signerKey,
          signerSig,
          maxAmount: 1000000,
          authId: 0,
          unlockBytes,
        }),
        stacker,
      );
      expect(result.value).toEqual(
        errorCodes.ERR_INVALID_UNLOCK_HEIGHT_TOO_SOON,
      );
    });

    test('can extend stake with longer unlock height', () => {
      const stacker = accounts.wallet_1.address;
      const firstUnlock = 150n;
      const secondUnlock = 250n;
      const poxAddr = randomPoxAddress();
      const signerKey = randomBytes(33);
      const signerSig = randomBytes(65);
      const unlockBytes = randomBytes(255);

      txOk(
        pox5.stake({
          amountUstx: 1000000,
          poxAddr,
          signerKey,
          maxAmount: 1000000,
          authId: 0,
          signerSig,
          startBurnHt: simnet.burnBlockHeight,
          unlockBurnHeight: firstUnlock,
          unlockBytes,
        }),
        stacker,
      );

      mineUntil(200n);

      txOk(
        pox5.extendStake({
          unlockBurnHeight: secondUnlock,
          poxAddr,
          signerKey,
          signerSig,
          maxAmount: 1000000,
          authId: 0,
          unlockBytes,
        }),
        stacker,
      );

      const stakerInfo = rov(pox5.getStakerInfo(stacker))!;
      expect(stakerInfo.unlockBurnHeight).toBe(secondUnlock);
    });
  });
});

describe('linked list', () => {
  const stackers = [
    randomStacksAddress(),
    randomStacksAddress(),
    randomStacksAddress(),
    randomStacksAddress(),
    randomStacksAddress(),
  ];
  test('can add multiple stackers to the linked list', () => {
    for (const stacker of stackers) {
      txOk(pox5.addStackerToSet(stacker), accounts.deployer.address);
    }
    const lastItem = rov(pox5.getStackerSetLastItem());
    expect(lastItem).toBe(stackers.at(-1));
    expect(rov(pox5.getStackerSetFirstItem())).toBe(stackers[0]);
    const allStackers = getAllStackers();
    expect(allStackers).toEqual(stackers);
  });

  test('can remove a non-last item from the linked list', () => {
    for (const stacker of stackers) {
      txOk(pox5.addStackerToSet(stacker), accounts.deployer.address);
    }
    const toRemove = stackers[1]!;
    txOk(pox5.removeStackerFromSet(toRemove), accounts.deployer.address);
    const allStackers = getAllStackers();
    expect(allStackers).toEqual(stackers.filter((s) => s !== toRemove));
    expect(rov(pox5.getStackerSetNextItem(stackers[0]!))).toBe(stackers[2]!);
    expect(rov(pox5.getStackerSetPrevItem(stackers[2]!))).not.toBe(toRemove);
    expect(rov(pox5.getStackerSetPrevItem(stackers[2]!))).toBe(stackers[0]!);
    expect(rov(pox5.getStackerSetPrevItem(toRemove))).toBe(null);
    expect(rov(pox5.getStackerSetNextItem(toRemove))).toBe(null);
  });

  test('can remove the last item from the linked list', () => {
    for (const stacker of stackers) {
      txOk(pox5.addStackerToSet(stacker), accounts.deployer.address);
    }
    const toRemove = stackers.at(-1)!;
    const newLast = stackers.at(-2)!;
    txOk(pox5.removeStackerFromSet(toRemove), accounts.deployer.address);
    const allStackers = getAllStackers();
    expect(allStackers).toEqual(stackers.filter((s) => s !== toRemove));
    expect(rov(pox5.getStackerSetLastItem())).toBe(newLast);
    expect(rov(pox5.getStackerSetFirstItem())).toBe(stackers[0]!);
    expect(rov(pox5.getStackerSetNextItem(newLast))).toBe(null);
    expect(rov(pox5.getStackerSetPrevItem(newLast))).toBe(stackers.at(-3));
    expect(rov(pox5.getStackerSetPrevItem(toRemove))).toBe(null);
    expect(rov(pox5.getStackerSetNextItem(toRemove))).toBe(null);
  });

  test('can remove the first item from the linked list', () => {
    for (const stacker of stackers) {
      txOk(pox5.addStackerToSet(stacker), accounts.deployer.address);
    }
    const toRemove = stackers[0]!;
    const newFirst = stackers[1]!;
    txOk(pox5.removeStackerFromSet(toRemove), accounts.deployer.address);
    const allStackers = getAllStackers();
    expect(allStackers).toEqual(stackers.filter((s) => s !== toRemove));
    expect(rov(pox5.getStackerSetFirstItem())).toBe(newFirst);
    expect(rov(pox5.getStackerSetLastItem())).toBe(stackers.at(-1)!);
    expect(rov(pox5.getStackerSetNextItem(newFirst))).toBe(stackers[2]!);
    expect(rov(pox5.getStackerSetPrevItem(newFirst))).toBe(null);
    expect(rov(pox5.getStackerSetPrevItem(toRemove))).toBe(null);
    expect(rov(pox5.getStackerSetNextItem(toRemove))).toBe(null);
  });

  test('cannot add a stacker that is already in the linked list', () => {
    txOk(pox5.addStackerToSet(stackers[0]!), accounts.deployer.address);
    const result = txErr(
      pox5.addStackerToSet(stackers[0]!),
      accounts.deployer.address,
    );
    expect(result.value).toEqual(errorCodes.ERR_ALREADY_STAKED);
  });

  test('cannot remove a stacker that is not in the linked list', () => {
    const result = txErr(
      pox5.removeStackerFromSet(stackers[0]!),
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
