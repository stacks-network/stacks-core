import { accounts } from '../clarigen-types';
import {
  assertErr,
  assertOk,
  rov,
  rovErr,
  rovOk,
  txErr,
  txOk,
} from '@clarigen/test';
import { test, expect, describe, beforeEach } from 'vitest';
import {
  mineUntil,
  randomPoxAddress,
  randomSecretKey,
  randomStacksAddress,
} from '../test-helpers';
import {
  pox5,
  pox5Indirect,
  errorCodes,
  testPool,
  createSignerKeyGrant,
  setupSigner,
  registerPool,
  signPerTransactionAuth,
  signerAddress,
  signSignerKeyGrant,
  serializeLockupScript,
} from './pox-5-helpers';
import { randomBytes } from '@stacks/transactions';
import { inspect } from 'node:util';
import { secp256k1 } from '@noble/curves/secp256k1.js';
import { hex } from '@scure/base';

const deployer = accounts.deployer.address;
const alice = accounts.wallet_1.address;
const bob = accounts.wallet_2.address;

const minAmount = pox5.constants.MIN_STACKING_AMOUNT;

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
    const signerSk = randomSecretKey();
    const unlockBytes = randomBytes(255);
    const signerKey = secp256k1.getPublicKey(signerSk, true);
    createSignerKeyGrant({
      staker: stacker,
      signerSk: signerSk,
      poxAddr: null,
      authId: 0n,
    });
    const result = txOk(
      pox5.stake({
        amountUstx: minAmount,
        poxAddr: randomPoxAddress(),
        signerKey,
        maxAmount: minAmount,
        authId: 0,
        signerSig: null,
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
    expect(info.amountUstx).toBe(minAmount);
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

  test('cannot stake for less than the minimum amount', () => {
    const staker = alice;
    const { signerKey } = setupSigner(staker);
    const amount = minAmount - 1n;
    const result = txErr(
      pox5.stake({
        amountUstx: amount,
        poxAddr: randomPoxAddress(),
        signerKey,
        maxAmount: minAmount,
        authId: 0,
        signerSig: null,
        startBurnHt: simnet.burnBlockHeight,
        numCycles: 1,
        unlockBytes: randomBytes(255),
      }),
      staker,
    );
    expect(result.value).toEqual(errorCodes.ERR_INVALID_AMOUNT);
  });

  test('cannot pooled stake for less than the minimum amount', () => {
    registerPool({ caller: deployer });
    const staker = alice;
    const amount = minAmount - 1n;
    const result = txErr(
      pox5.stakePooled({
        amountUstx: amount,
        numCycles: 1,
        unlockBytes: randomBytes(255),
        startBurnHt: simnet.burnBlockHeight,
        poolOwner: testPool.identifier,
      }),
      staker,
    );
    expect(result.value).toEqual(errorCodes.ERR_INVALID_AMOUNT);
  });

  test(`can stake for ${pox5.constants.MAX_NUM_CYCLES} cycles`, () => {
    const staker = alice;
    const { signerKey } = setupSigner(staker);
    const maxCycles = pox5.constants.MAX_NUM_CYCLES;
    const numCycles = maxCycles;
    const result = txOk(
      pox5.stake({
        amountUstx: minAmount,
        poxAddr: randomPoxAddress(),
        signerKey,
        maxAmount: minAmount,
        authId: 0,
        signerSig: null,
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
    const { signerKey } = setupSigner(staker);
    const numCycles = pox5.constants.MAX_NUM_CYCLES + 1n;
    const result = txErr(
      pox5.stake({
        amountUstx: minAmount,
        poxAddr: randomPoxAddress(),
        signerKey,
        maxAmount: minAmount,
        authId: 0,
        signerSig: null,
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
    const { signerKey } = setupSigner(staker);
    const numCycles = 1;
    txOk(
      pox5.stake({
        amountUstx: minAmount,
        poxAddr: randomPoxAddress(),
        signerKey,
        maxAmount: minAmount,
        authId: 0,
        signerSig: null,
        startBurnHt: simnet.burnBlockHeight,
        numCycles,
        unlockBytes: randomBytes(255),
      }),
      staker,
    );

    mineUntil(rov(pox5.rewardCycleToUnlockHeight(2n)));

    const result = txOk(
      pox5.stake({
        amountUstx: minAmount,
        poxAddr: randomPoxAddress(),
        signerKey,
        maxAmount: minAmount,
        authId: 1,
        signerSig: null,
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
      const { signerKey } = setupSigner(stacker);
      const poxAddr = randomPoxAddress();
      const unlockBytes = randomBytes(255);
      const firstNumCycles = 1;
      const secondNumCycles = 1;

      const stakeReceipt = txOk(
        pox5.stake({
          amountUstx: minAmount,
          poxAddr,
          signerKey,
          maxAmount: minAmount,
          authId: 0,
          signerSig: null,
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
          amountUstx: minAmount,
          numCycles: secondNumCycles,
          poxAddr,
          signerKey,
          signerSig: null,
          maxAmount: minAmount,
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

    test('cannot extend stake before the final cycle', () => {
      const stacker = alice;
      const { signerKey } = setupSigner(stacker);
      txOk(
        pox5.stake({
          amountUstx: minAmount,
          poxAddr: randomPoxAddress(),
          signerKey,
          maxAmount: minAmount,
          authId: 0,
          signerSig: null,
          startBurnHt: simnet.burnBlockHeight,
          numCycles: 2,
          unlockBytes: randomBytes(255),
        }),
        stacker,
      );

      const result = txErr(
        pox5.stakeExtend({
          amountUstx: minAmount,
          poxAddr: randomPoxAddress(),
          signerKey,
          maxAmount: minAmount,
          authId: 1,
          signerSig: null,
          numCycles: 1,
          unlockBytes: randomBytes(255),
        }),
        stacker,
      );
      expect(result.value).toEqual(errorCodes.ERR_CANNOT_EXTEND);
    });

    test('can switch from pooled to solo via stake-extend', () => {
      registerPool({ caller: deployer });

      const pooledStake = txOk(
        pox5.stakePooled({
          poolOwner: testPool.identifier,
          amountUstx: minAmount,
          numCycles: 1,
          unlockBytes: randomBytes(255),
          startBurnHt: simnet.burnBlockHeight,
        }),
        alice,
      );
      assertOk(pooledStake.value.poolOrSoloInfo);
      expect(pooledStake.value.poolOrSoloInfo.value).toBe(testPool.identifier);

      mineUntil(pooledStake.value.unlockBurnHeight);

      const nextPoxAddr = randomPoxAddress();
      const { signerKey: nextSignerKey } = setupSigner(alice);
      const nextUnlockBytes = randomBytes(683);
      const extendReceipt = txOk(
        pox5.stakeExtend({
          amountUstx: 2000000,
          poxAddr: nextPoxAddr,
          signerKey: nextSignerKey,
          signerSig: null,
          maxAmount: 2000000,
          authId: 1,
          numCycles: 2,
          unlockBytes: nextUnlockBytes,
        }),
        alice,
      );

      assertErr(extendReceipt.value.poolOrSoloInfo);
      expect(extendReceipt.value.poolOrSoloInfo.value.poxAddr).toStrictEqual(
        nextPoxAddr,
      );
      expect(extendReceipt.value.poolOrSoloInfo.value.signerKey).toStrictEqual(
        nextSignerKey,
      );

      const stakerInfo = rov(pox5.getStakerInfo(alice))!;
      expect(stakerInfo.amountUstx).toBe(2000000n);
      expect(stakerInfo.firstRewardCycle).toBe(2n);
      expect(stakerInfo.numCycles).toBe(2n);
      expect(stakerInfo.unlockBytes).toStrictEqual(nextUnlockBytes);
      assertErr(stakerInfo.poolOrSoloInfo);
      expect(stakerInfo.poolOrSoloInfo.value.poxAddr).toStrictEqual(
        nextPoxAddr,
      );
      expect(stakerInfo.poolOrSoloInfo.value.signerKey).toStrictEqual(
        nextSignerKey,
      );
    });
  });

  describe('updating stake', () => {
    test('can update a solo stake amount and signer metadata', () => {
      const { signerKey: initialSignerKey } = setupSigner(alice);
      const initialUnlockBytes = randomBytes(255);
      txOk(
        pox5.stake({
          amountUstx: minAmount,
          poxAddr: randomPoxAddress(),
          signerKey: initialSignerKey,
          maxAmount: minAmount,
          authId: 0,
          signerSig: null,
          startBurnHt: simnet.burnBlockHeight,
          numCycles: 2,
          unlockBytes: initialUnlockBytes,
        }),
        alice,
      );

      const nextPoxAddr = randomPoxAddress();
      const { signerKey: nextSignerKey } = setupSigner(alice);
      const receipt = txOk(
        pox5.stakeUpdate({
          amountUstxIncrease: 250000,
          poxAddr: nextPoxAddr,
          signerKey: nextSignerKey,
          signerSig: null,
          authId: 1,
          maxAmount: minAmount,
        }),
        alice,
      );

      expect(receipt.value.amountUstx).toBe(minAmount + 250000n);
      assertErr(receipt.value.poolOrSoloInfo);
      expect(receipt.value.poolOrSoloInfo.value.poxAddr).toStrictEqual(
        nextPoxAddr,
      );
      expect(receipt.value.poolOrSoloInfo.value.signerKey).toStrictEqual(
        nextSignerKey,
      );

      const stakerInfo = rov(pox5.getStakerInfo(alice))!;
      expect(stakerInfo.amountUstx).toBe(minAmount + 250000n);
      expect(stakerInfo.firstRewardCycle).toBe(1n);
      expect(stakerInfo.numCycles).toBe(2n);
      expect(stakerInfo.unlockBytes).toStrictEqual(initialUnlockBytes);
      assertErr(stakerInfo.poolOrSoloInfo);
      expect(stakerInfo.poolOrSoloInfo.value.poxAddr).toStrictEqual(
        nextPoxAddr,
      );
      expect(stakerInfo.poolOrSoloInfo.value.signerKey).toStrictEqual(
        nextSignerKey,
      );
    });

    test('can switch from solo to pooled via stake-update-pooled', () => {
      const { signerKey } = setupSigner(alice);
      const initialUnlockBytes = randomBytes(255);
      txOk(
        pox5.stake({
          amountUstx: minAmount,
          poxAddr: randomPoxAddress(),
          signerKey,
          maxAmount: minAmount,
          authId: 0,
          signerSig: null,
          startBurnHt: simnet.burnBlockHeight,
          numCycles: 2,
          unlockBytes: initialUnlockBytes,
        }),
        alice,
      );

      registerPool({ caller: deployer });

      const receipt = txOk(
        pox5.stakeUpdatePooled({
          poolOwner: testPool.identifier,
          amountUstxIncrease: 500000,
        }),
        alice,
      );

      expect(receipt.value.amountUstx).toBe(minAmount + 500000n);
      assertOk(receipt.value.poolOrSoloInfo);
      expect(receipt.value.poolOrSoloInfo.value).toBe(testPool.identifier);

      const stakerInfo = rov(pox5.getStakerInfo(alice))!;
      expect(stakerInfo.amountUstx).toBe(minAmount + 500000n);
      expect(stakerInfo.unlockBytes).toStrictEqual(initialUnlockBytes);
      assertOk(stakerInfo.poolOrSoloInfo);
      expect(stakerInfo.poolOrSoloInfo.value).toBe(testPool.identifier);
    });

    test('can switch from pooled to solo via stake-update', () => {
      registerPool({ caller: deployer });

      txOk(
        pox5.stakePooled({
          poolOwner: testPool.identifier,
          amountUstx: minAmount,
          numCycles: 2,
          unlockBytes: randomBytes(255),
          startBurnHt: simnet.burnBlockHeight,
        }),
        alice,
      );

      const nextPoxAddr = randomPoxAddress();
      const { signerKey: nextSignerKey } = setupSigner(alice);
      const receipt = txOk(
        pox5.stakeUpdate({
          amountUstxIncrease: 250000,
          poxAddr: nextPoxAddr,
          signerKey: nextSignerKey,
          signerSig: null,
          authId: 1,
          maxAmount: minAmount,
        }),
        alice,
      );

      expect(receipt.value.amountUstx).toBe(minAmount + 250000n);
      assertErr(receipt.value.poolOrSoloInfo);
      expect(receipt.value.poolOrSoloInfo.value.poxAddr).toStrictEqual(
        nextPoxAddr,
      );
      expect(receipt.value.poolOrSoloInfo.value.signerKey).toStrictEqual(
        nextSignerKey,
      );

      const stakerInfo = rov(pox5.getStakerInfo(alice))!;
      expect(stakerInfo.amountUstx).toBe(minAmount + 250000n);
      assertErr(stakerInfo.poolOrSoloInfo);
      expect(stakerInfo.poolOrSoloInfo.value.poxAddr).toStrictEqual(
        nextPoxAddr,
      );
      expect(stakerInfo.poolOrSoloInfo.value.signerKey).toStrictEqual(
        nextSignerKey,
      );
    });

    test('cannot call stake-update with zero increase', () => {
      const { signerKey } = setupSigner(alice);
      txOk(
        pox5.stake({
          amountUstx: minAmount,
          poxAddr: randomPoxAddress(),
          signerKey,
          maxAmount: minAmount,
          authId: 0,
          signerSig: null,
          startBurnHt: simnet.burnBlockHeight,
          numCycles: 2,
          unlockBytes: randomBytes(255),
        }),
        alice,
      );

      const result = txErr(
        pox5.stakeUpdate({
          amountUstxIncrease: 0,
          poxAddr: randomPoxAddress(),
          signerKey,
          signerSig: null,
          authId: 1,
          maxAmount: minAmount,
        }),
        alice,
      );

      expect(result.value).toEqual(errorCodes.ERR_INVALID_AMOUNT);
    });

    test('cannot call stake-update-pooled with an unregistered pool', () => {
      const { signerKey } = setupSigner(alice);
      txOk(
        pox5.stake({
          amountUstx: minAmount,
          poxAddr: randomPoxAddress(),
          signerKey,
          maxAmount: minAmount,
          authId: 0,
          signerSig: null,
          startBurnHt: simnet.burnBlockHeight,
          numCycles: 2,
          unlockBytes: randomBytes(255),
        }),
        alice,
      );

      const result = txErr(
        pox5.stakeUpdatePooled({
          poolOwner: testPool.identifier,
          amountUstxIncrease: 1,
        }),
        alice,
      );

      expect(result.value).toEqual(errorCodes.ERR_POOL_NOT_FOUND);
    });

    test('stake-update should preserve the current unlock cycle', () => {
      const { signerKey } = setupSigner(alice);
      const initialStake = txOk(
        pox5.stake({
          amountUstx: minAmount,
          poxAddr: randomPoxAddress(),
          signerKey,
          maxAmount: minAmount,
          authId: 0,
          signerSig: null,
          startBurnHt: simnet.burnBlockHeight,
          numCycles: 1,
          unlockBytes: randomBytes(255),
        }),
        alice,
      );

      const { signerKey: updateSignerKey } = setupSigner(alice);
      const receipt = txOk(
        pox5.stakeUpdate({
          amountUstxIncrease: 1,
          poxAddr: randomPoxAddress(),
          signerKey: updateSignerKey,
          signerSig: null,
          authId: 1,
          maxAmount: minAmount,
        }),
        alice,
      );

      expect(receipt.value.unlockCycle).toBe(initialStake.value.unlockCycle);
      expect(receipt.value.unlockBurnHeight).toBe(
        initialStake.value.unlockBurnHeight,
      );
    });
  });

  describe('pool-based staking', () => {
    test('cannot stake to an unregistered pool', () => {
      const result = txErr(
        pox5.stakePooled({
          poolOwner: testPool.identifier,
          amountUstx: minAmount,
          numCycles: 1,
          unlockBytes: randomBytes(255),
          startBurnHt: simnet.burnBlockHeight,
        }),
        alice,
      );

      expect(result.value).toEqual(errorCodes.ERR_POOL_NOT_FOUND);
    });

    test('can register a pool', () => {
      const { signerKey, poxAddr } = registerPool({ caller: deployer });
      const pool = rov(pox5.getPoolInfo(testPool.identifier));
      expect(pool).toBeDefined();
      expect(pool?.signerKey).toStrictEqual(signerKey);
      expect(pool?.poxAddr).toStrictEqual(poxAddr);
    });

    test('can stake to a pool', () => {
      registerPool({ caller: deployer });
      const unlockBytes = randomBytes(255);
      const receipt = txOk(
        pox5.stakePooled({
          poolOwner: testPool.identifier,
          amountUstx: minAmount,
          numCycles: 1,
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

    test('can switch from solo to pooled via stake-extend-pooled', () => {
      const { signerKey } = setupSigner(alice);
      const soloStake = txOk(
        pox5.stake({
          amountUstx: minAmount,
          poxAddr: randomPoxAddress(),
          signerKey,
          maxAmount: minAmount,
          authId: 0,
          signerSig: null,
          startBurnHt: simnet.burnBlockHeight,
          numCycles: 1,
          unlockBytes: randomBytes(255),
        }),
        alice,
      );

      registerPool({ caller: deployer });

      mineUntil(soloStake.value.unlockBurnHeight);

      const nextUnlockBytes = randomBytes(683);
      const receipt = txOk(
        pox5.stakeExtendPooled({
          poolOwner: testPool.identifier,
          amountUstx: 1250000,
          numCycles: 2,
          unlockBytes: nextUnlockBytes,
        }),
        alice,
      );

      assertOk(receipt.value.poolOrSoloInfo);
      expect(receipt.value.poolOrSoloInfo.value).toBe(testPool.identifier);
      expect(receipt.value.amountUstx).toBe(1250000n);

      const stakerInfo = rov(pox5.getStakerInfo(alice))!;
      expect(stakerInfo.amountUstx).toBe(1250000n);
      expect(stakerInfo.firstRewardCycle).toBe(2n);
      expect(stakerInfo.numCycles).toBe(2n);
      expect(stakerInfo.unlockBytes).toStrictEqual(nextUnlockBytes);
      assertOk(stakerInfo.poolOrSoloInfo);
      expect(stakerInfo.poolOrSoloInfo.value).toBe(testPool.identifier);
    });

    test('cannot call stake-extend-pooled before the final cycle', () => {
      registerPool({ caller: deployer });

      txOk(
        pox5.stakePooled({
          poolOwner: testPool.identifier,
          amountUstx: minAmount,
          numCycles: 2,
          unlockBytes: randomBytes(255),
          startBurnHt: simnet.burnBlockHeight,
        }),
        alice,
      );

      const result = txErr(
        pox5.stakeExtendPooled({
          poolOwner: testPool.identifier,
          amountUstx: minAmount,
          numCycles: 1,
          unlockBytes: randomBytes(255),
        }),
        alice,
      );

      expect(result.value).toEqual(errorCodes.ERR_CANNOT_EXTEND);
    });

    test('register-pool validates pox-addr', () => {
      const { signerKey } = setupSigner(deployer);
      const result = txErr(
        pox5.registerPool({
          poolOwner: testPool.identifier,
          signerKey,
          poxAddr: {
            version: Uint8Array.from([0x07]),
            hashbytes: randomBytes(32),
          },
        }),
        deployer,
      );

      expect(result.value).toEqual(errorCodes.ERR_INVALID_POX_ADDRESS);
    });
  });
});

describe('signer key grants', () => {
  test('grant with pox-addr constraint verifies matching address', () => {
    const signerSk = randomSecretKey();
    const signerKey = secp256k1.getPublicKey(signerSk, true);
    const poxAddr = randomPoxAddress();

    createSignerKeyGrant({ staker: alice, signerSk, poxAddr, authId: 0n });

    expect(
      rovOk(pox5.verifySignerKeyGrant({ staker: alice, signerKey, poxAddr })),
    ).toBe(true);
  });

  test('grant with pox-addr constraint rejects mismatched address', () => {
    const signerSk = randomSecretKey();
    const signerKey = secp256k1.getPublicKey(signerSk, true);
    const grantAddr = randomPoxAddress();

    createSignerKeyGrant({
      staker: alice,
      signerSk,
      poxAddr: grantAddr,
      authId: 0n,
    });

    const differentAddr = randomPoxAddress();
    const result = rovErr(
      pox5.verifySignerKeyGrant({
        staker: alice,
        signerKey,
        poxAddr: differentAddr,
      }),
    );
    expect(result).toEqual(errorCodes.ERR_SIGNER_KEY_GRANT_POX_ADDR_MISMATCH);
  });

  test('grant with no pox-addr constraint (none) allows any address', () => {
    const signerSk = randomSecretKey();
    const signerKey = secp256k1.getPublicKey(signerSk, true);

    createSignerKeyGrant({
      staker: alice,
      signerSk,
      poxAddr: null,
      authId: 0n,
    });

    expect(
      rovOk(
        pox5.verifySignerKeyGrant({
          staker: alice,
          signerKey,
          poxAddr: randomPoxAddress(),
        }),
      ),
    ).toBe(true);
  });

  test('cannot replay the same auth-id', () => {
    const signerSk = randomSecretKey();
    const signerKey = secp256k1.getPublicKey(signerSk, true);

    createSignerKeyGrant({
      staker: alice,
      signerSk,
      poxAddr: null,
      authId: 0n,
    });

    const signature = signSignerKeyGrant({
      staker: alice,
      poxAddr: null,
      authId: 0n,
      signerSk,
    });
    const result = txErr(
      pox5.grantSignerKey({
        signerKey,
        staker: alice,
        poxAddr: null,
        authId: 0n,
        signerSig: signature,
      }),
      deployer,
    );
    expect(result.value).toEqual(errorCodes.ERR_SIGNER_KEY_GRANT_USED);
  });

  test('re-granting with a new auth-id overwrites the previous grant', () => {
    const signerSk = randomSecretKey();
    const signerKey = secp256k1.getPublicKey(signerSk, true);
    const firstAddr = randomPoxAddress();
    const secondAddr = randomPoxAddress();

    createSignerKeyGrant({
      staker: alice,
      signerSk,
      poxAddr: firstAddr,
      authId: 0n,
    });
    createSignerKeyGrant({
      staker: alice,
      signerSk,
      poxAddr: secondAddr,
      authId: 1n,
    });

    // old address no longer works
    rovErr(
      pox5.verifySignerKeyGrant({
        staker: alice,
        signerKey,
        poxAddr: firstAddr,
      }),
    );

    // new address works
    expect(
      rovOk(
        pox5.verifySignerKeyGrant({
          staker: alice,
          signerKey,
          poxAddr: secondAddr,
        }),
      ),
    ).toBe(true);
  });

  test('grant with wrong signer key fails signature check', () => {
    const signerSk = randomSecretKey();
    const wrongKey = secp256k1.getPublicKey(randomSecretKey(), true);

    const signature = signSignerKeyGrant({
      staker: alice,
      poxAddr: null,
      authId: 0n,
      signerSk,
    });
    const result = txErr(
      pox5.grantSignerKey({
        signerKey: wrongKey,
        staker: alice,
        poxAddr: null,
        authId: 0n,
        signerSig: signature,
      }),
      deployer,
    );
    expect(result.value).toEqual(errorCodes.ERR_INVALID_SIGNATURE_PUBKEY);
  });

  test('verify-signer-key-grant fails when no grant exists', () => {
    const signerKey = secp256k1.getPublicKey(randomSecretKey(), true);
    const result = rovErr(
      pox5.verifySignerKeyGrant({
        staker: alice,
        signerKey,
        poxAddr: randomPoxAddress(),
      }),
    );
    expect(result).toEqual(errorCodes.ERR_SIGNER_KEY_GRANT_NOT_FOUND);
  });

  describe('revoking grants', () => {
    test('signer can revoke a grant', () => {
      const signerSk = randomSecretKey();
      const signerKey = secp256k1.getPublicKey(signerSk, true);
      const addr = signerAddress(signerKey);

      createSignerKeyGrant({
        staker: alice,
        signerSk,
        poxAddr: null,
        authId: 0n,
      });

      const result = txOk(
        pox5.revokeSignerGrant({ staker: alice, signerKey }),
        addr,
      );
      expect(result.value).toBe(true);

      // grant no longer valid
      const verify = rovErr(
        pox5.verifySignerKeyGrant({
          staker: alice,
          signerKey,
          poxAddr: randomPoxAddress(),
        }),
      );
      expect(verify).toEqual(errorCodes.ERR_SIGNER_KEY_GRANT_NOT_FOUND);
    });

    test('revoke returns false when grant does not exist', () => {
      const signerSk = randomSecretKey();
      const signerKey = secp256k1.getPublicKey(signerSk, true);
      const addr = signerAddress(signerKey);

      const result = txOk(
        pox5.revokeSignerGrant({ staker: alice, signerKey }),
        addr,
      );
      expect(result.value).toBe(false);
    });

    test('non-signer cannot revoke a grant', () => {
      const signerSk = randomSecretKey();
      const signerKey = secp256k1.getPublicKey(signerSk, true);

      createSignerKeyGrant({
        staker: alice,
        signerSk,
        poxAddr: null,
        authId: 0n,
      });

      // alice is not the signer, so she can't revoke
      const result = txErr(
        pox5.revokeSignerGrant({ staker: alice, signerKey }),
        alice,
      );
      expect(result.value).toEqual(errorCodes.ERR_NOT_ALLOWED);
    });

    test('revoked grant cannot be used for staking', () => {
      const signerSk = randomSecretKey();
      const signerKey = secp256k1.getPublicKey(signerSk, true);
      const addr = signerAddress(signerKey);

      createSignerKeyGrant({
        staker: alice,
        signerSk,
        poxAddr: null,
        authId: 0n,
      });

      txOk(pox5.revokeSignerGrant({ staker: alice, signerKey }), addr);

      const result = txErr(
        pox5.stake({
          amountUstx: minAmount,
          poxAddr: randomPoxAddress(),
          signerKey,
          maxAmount: minAmount,
          authId: 0,
          signerSig: null,
          startBurnHt: simnet.burnBlockHeight,
          numCycles: 1,
          unlockBytes: randomBytes(255),
        }),
        alice,
      );
      expect(result.value).toEqual(errorCodes.ERR_SIGNER_KEY_GRANT_NOT_FOUND);
    });

    test('can re-grant after revocation with new auth-id', () => {
      const signerSk = randomSecretKey();
      const signerKey = secp256k1.getPublicKey(signerSk, true);
      const addr = signerAddress(signerKey);

      createSignerKeyGrant({
        staker: alice,
        signerSk,
        poxAddr: null,
        authId: 0n,
      });
      txOk(pox5.revokeSignerGrant({ staker: alice, signerKey }), addr);

      // re-grant with a different auth-id
      createSignerKeyGrant({
        staker: alice,
        signerSk,
        poxAddr: null,
        authId: 1n,
      });

      expect(
        rovOk(
          pox5.verifySignerKeyGrant({
            staker: alice,
            signerKey,
            poxAddr: randomPoxAddress(),
          }),
        ),
      ).toBe(true);
    });
  });

  describe('one signer key, multiple stakers', () => {
    test('signer can authorize multiple stakers independently', () => {
      const signerSk = randomSecretKey();
      const signerKey = secp256k1.getPublicKey(signerSk, true);

      createSignerKeyGrant({
        staker: alice,
        signerSk,
        poxAddr: null,
        authId: 0n,
      });
      createSignerKeyGrant({
        staker: bob,
        signerSk,
        poxAddr: null,
        authId: 1n,
      });

      expect(
        rovOk(
          pox5.verifySignerKeyGrant({
            staker: alice,
            signerKey,
            poxAddr: randomPoxAddress(),
          }),
        ),
      ).toBe(true);
      expect(
        rovOk(
          pox5.verifySignerKeyGrant({
            staker: bob,
            signerKey,
            poxAddr: randomPoxAddress(),
          }),
        ),
      ).toBe(true);
    });
  });
});

describe('per-transaction signer signatures', () => {
  test('can stake with a per-transaction signature', () => {
    const signerSk = randomSecretKey();
    const signerKey = secp256k1.getPublicKey(signerSk, true);
    const poxAddr = randomPoxAddress();
    const rewardCycle = rov(pox5.currentPoxRewardCycle());

    const signerSig = signPerTransactionAuth({
      signerSk,
      poxAddr,
      rewardCycle,
      topic: 'stake',
      period: 1,
      maxAmount: minAmount,
      authId: 0n,
    });

    const result = txOk(
      pox5.stake({
        amountUstx: minAmount,
        poxAddr,
        signerKey,
        maxAmount: minAmount,
        authId: 0,
        signerSig,
        startBurnHt: simnet.burnBlockHeight,
        numCycles: 1,
        unlockBytes: randomBytes(255),
      }),
      alice,
    );
    expect(result.value.stacker).toBe(alice);
  });

  test('per-transaction sig cannot be reused', () => {
    const signerSk = randomSecretKey();
    const signerKey = secp256k1.getPublicKey(signerSk, true);
    const poxAddr = randomPoxAddress();
    const rewardCycle = rov(pox5.currentPoxRewardCycle());

    const signerSig = signPerTransactionAuth({
      signerSk,
      poxAddr,
      rewardCycle,
      topic: 'stake',
      period: 1,
      maxAmount: minAmount,
      authId: 0n,
    });

    // alice uses the sig
    txOk(
      pox5.stake({
        amountUstx: minAmount,
        poxAddr,
        signerKey,
        maxAmount: minAmount,
        authId: 0,
        signerSig,
        startBurnHt: simnet.burnBlockHeight,
        numCycles: 1,
        unlockBytes: randomBytes(255),
      }),
      alice,
    );

    // bob tries to reuse the same sig in the same cycle
    const result = txErr(
      pox5.stake({
        amountUstx: minAmount,
        poxAddr,
        signerKey,
        maxAmount: minAmount,
        authId: 0,
        signerSig,
        startBurnHt: simnet.burnBlockHeight,
        numCycles: 1,
        unlockBytes: randomBytes(255),
      }),
      bob,
    );
    expect(result.value).toEqual(errorCodes.ERR_SIGNER_AUTH_USED);
  });

  test('rejects signature with wrong topic', () => {
    const signerSk = randomSecretKey();
    const signerKey = secp256k1.getPublicKey(signerSk, true);
    const poxAddr = randomPoxAddress();
    const rewardCycle = rov(pox5.currentPoxRewardCycle());

    // sign for "stake-extend" but use for "stake"
    const signerSig = signPerTransactionAuth({
      signerSk,
      poxAddr,
      rewardCycle,
      topic: 'stake-extend',
      period: 1,
      maxAmount: minAmount,
      authId: 0n,
    });

    const result = txErr(
      pox5.stake({
        amountUstx: minAmount,
        poxAddr,
        signerKey,
        maxAmount: minAmount,
        authId: 0,
        signerSig,
        startBurnHt: simnet.burnBlockHeight,
        numCycles: 1,
        unlockBytes: randomBytes(255),
      }),
      alice,
    );
    expect(result.value).toEqual(errorCodes.ERR_INVALID_SIGNATURE_PUBKEY);
  });

  test('rejects when amount exceeds max-amount', () => {
    const signerSk = randomSecretKey();
    const signerKey = secp256k1.getPublicKey(signerSk, true);
    const poxAddr = randomPoxAddress();
    const rewardCycle = rov(pox5.currentPoxRewardCycle());

    const tooLowMax = minAmount - 1n;
    const signerSig = signPerTransactionAuth({
      signerSk,
      poxAddr,
      rewardCycle,
      topic: 'stake',
      period: 1,
      maxAmount: tooLowMax,
      authId: 0n,
    });

    const result = txErr(
      pox5.stake({
        amountUstx: minAmount,
        poxAddr,
        signerKey,
        maxAmount: tooLowMax,
        authId: 0,
        signerSig,
        startBurnHt: simnet.burnBlockHeight,
        numCycles: 1,
        unlockBytes: randomBytes(255),
      }),
      alice,
    );
    expect(result.value).toEqual(errorCodes.ERR_SIGNER_AUTH_AMOUNT_TOO_HIGH);
  });

  test('rejects signature with wrong pox-addr', () => {
    const signerSk = randomSecretKey();
    const signerKey = secp256k1.getPublicKey(signerSk, true);
    const signedAddr = randomPoxAddress();
    const differentAddr = randomPoxAddress();
    const rewardCycle = rov(pox5.currentPoxRewardCycle());

    const signerSig = signPerTransactionAuth({
      signerSk,
      poxAddr: signedAddr,
      rewardCycle,
      topic: 'stake',
      period: 1,
      maxAmount: minAmount,
      authId: 0n,
    });

    const result = txErr(
      pox5.stake({
        amountUstx: minAmount,
        poxAddr: differentAddr,
        signerKey,
        maxAmount: minAmount,
        authId: 0,
        signerSig,
        startBurnHt: simnet.burnBlockHeight,
        numCycles: 1,
        unlockBytes: randomBytes(255),
      }),
      alice,
    );
    expect(result.value).toEqual(errorCodes.ERR_INVALID_SIGNATURE_PUBKEY);
  });

  test('can use per-transaction sig for stake-extend', () => {
    const signerSk = randomSecretKey();
    const signerKey = secp256k1.getPublicKey(signerSk, true);
    const poxAddr = randomPoxAddress();

    // initial stake with permanent grant
    createSignerKeyGrant({
      staker: alice,
      signerSk,
      poxAddr: null,
      authId: 0n,
    });
    const stakeResult = txOk(
      pox5.stake({
        amountUstx: minAmount,
        poxAddr,
        signerKey,
        maxAmount: minAmount,
        authId: 0,
        signerSig: null,
        startBurnHt: simnet.burnBlockHeight,
        numCycles: 1,
        unlockBytes: randomBytes(255),
      }),
      alice,
    );

    mineUntil(stakeResult.value.unlockBurnHeight);

    const rewardCycle = rov(pox5.currentPoxRewardCycle());
    const signerSig = signPerTransactionAuth({
      signerSk,
      poxAddr,
      rewardCycle,
      topic: 'stake-extend',
      period: 2,
      maxAmount: minAmount,
      authId: 1n,
    });

    const result = txOk(
      pox5.stakeExtend({
        amountUstx: minAmount,
        poxAddr,
        signerKey,
        signerSig,
        maxAmount: minAmount,
        authId: 1,
        numCycles: 2,
        unlockBytes: randomBytes(255),
      }),
      alice,
    );
    expect(result.value.numCycles).toBe(2n);
  });

  test('can use per-transaction sig for stake-update', () => {
    const { signerKey } = setupSigner(alice);
    const poxAddr = randomPoxAddress();
    txOk(
      pox5.stake({
        amountUstx: minAmount,
        poxAddr,
        signerKey,
        maxAmount: minAmount,
        authId: 0,
        signerSig: null,
        startBurnHt: simnet.burnBlockHeight,
        numCycles: 2,
        unlockBytes: randomBytes(255),
      }),
      alice,
    );

    const newSignerSk = randomSecretKey();
    const newSignerKey = secp256k1.getPublicKey(newSignerSk, true);
    const newPoxAddr = randomPoxAddress();
    const rewardCycle = rov(pox5.currentPoxRewardCycle());

    // The period for stake-update = unlock_cycle - current_cycle
    // unlock_cycle = first_reward_cycle(1) + num_cycles(2) - 1 = 2
    // cycles_remaining = 2 - 0 = 2
    const signerSigCorrect = signPerTransactionAuth({
      signerSk: newSignerSk,
      poxAddr: newPoxAddr,
      rewardCycle,
      topic: 'stake-update',
      period: 2,
      maxAmount: minAmount,
      authId: 1n,
    });

    const result = txOk(
      pox5.stakeUpdate({
        amountUstxIncrease: 1,
        poxAddr: newPoxAddr,
        signerKey: newSignerKey,
        signerSig: signerSigCorrect,
        maxAmount: minAmount,
        authId: 1,
      }),
      alice,
    );
    expect(result.value.amountUstx).toBe(minAmount + 1n);
  });

  test('permanent grant and per-tx sig are independent paths', () => {
    const signerSk = randomSecretKey();
    const signerKey = secp256k1.getPublicKey(signerSk, true);
    const poxAddr = randomPoxAddress();

    // grant exists but we use per-tx sig instead
    createSignerKeyGrant({
      staker: alice,
      signerSk,
      poxAddr: null,
      authId: 0n,
    });

    const rewardCycle = rov(pox5.currentPoxRewardCycle());
    const signerSig = signPerTransactionAuth({
      signerSk,
      poxAddr,
      rewardCycle,
      topic: 'stake',
      period: 1,
      maxAmount: minAmount,
      authId: 1n,
    });

    const result = txOk(
      pox5.stake({
        amountUstx: minAmount,
        poxAddr,
        signerKey,
        maxAmount: minAmount,
        authId: 1,
        signerSig,
        startBurnHt: simnet.burnBlockHeight,
        numCycles: 1,
        unlockBytes: randomBytes(255),
      }),
      alice,
    );
    expect(result.value.stacker).toBe(alice);
  });

  test('staking without grant or signature fails', () => {
    const signerKey = secp256k1.getPublicKey(randomSecretKey(), true);

    const result = txErr(
      pox5.stake({
        amountUstx: minAmount,
        poxAddr: randomPoxAddress(),
        signerKey,
        maxAmount: minAmount,
        authId: 0,
        signerSig: null,
        startBurnHt: simnet.burnBlockHeight,
        numCycles: 1,
        unlockBytes: randomBytes(255),
      }),
      alice,
    );
    expect(result.value).toEqual(errorCodes.ERR_SIGNER_KEY_GRANT_NOT_FOUND);
  });

  test('register-pool requires a permanent grant (no sig path)', () => {
    const signerKey = secp256k1.getPublicKey(randomSecretKey(), true);

    const result = txErr(
      pox5.registerPool({
        poolOwner: testPool.identifier,
        signerKey,
        poxAddr: randomPoxAddress(),
      }),
      deployer,
    );
    expect(result.value).toEqual(errorCodes.ERR_SIGNER_KEY_GRANT_NOT_FOUND);
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

test('can create the correct output script for a timelock', () => {
  // ---- Timelock output script ----,
  // script: 16051ab3c07a68e5c485f50274b21b2bafc7aa7738bd447503e80300b175,
  // stacker_sk: 14edc0a0a9322ccc8f1563b4df783b0730d3740bf06abe872816d89bfefeadf301,
  // stacker_addr: ST2SW0YK8WQ28BX82EJS1PAXFRYN7EE5X8HHEJPXM,
  // unlock_height: 1000,
  // unlock_height_bytes: e80300
  // unlock_bytes: deadbeef
  const outputScript = serializeLockupScript({
    stacker: 'ST2SW0YK8WQ28BX82EJS1PAXFRYN7EE5X8HHEJPXM',
    unlockBurnHeight: 1000n,
    unlockBytes: new Uint8Array([0xde, 0xad, 0xbe, 0xef]),
  });
  expect(hex.encode(outputScript)).toBe(
    '16051ab3c07a68e5c485f50274b21b2bafc7aa7738bd447502e803b17504deadbeef',
  );
});

test('pox-addr cannot have an empty version byte', () => {
  const result = rovErr(
    pox5.checkPoxAddr({
      poxAddr: {
        version: new Uint8Array([0]),
        hashbytes: new Uint8Array([0]),
      },
    }),
  );
  expect(result).toEqual(errorCodes.ERR_INVALID_POX_ADDRESS);
});

describe('contract-caller allowance', () => {
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

  const wrapper = pox5Indirect.identifier;

  test('stake via wrapper fails without allowance, succeeds with allowance', () => {
    const { signerKey } = setupSigner(alice);
    const poxAddr = randomPoxAddress();

    const result = txErr(
      pox5Indirect.stake({
        amountUstx: minAmount,
        poxAddr,
        signerKey,
        maxAmount: minAmount,
        authId: 0,
        signerSig: null,
        startBurnHt: simnet.burnBlockHeight,
        numCycles: 1,
        unlockBytes: randomBytes(255),
      }),
      alice,
    );
    expect(result.value).toEqual(errorCodes.ERR_PERMISSION_DENIED);

    txOk(
      pox5.allowContractCaller({ caller: wrapper, untilBurnHt: null }),
      alice,
    );

    const ok = txOk(
      pox5Indirect.stake({
        amountUstx: minAmount,
        poxAddr,
        signerKey,
        maxAmount: minAmount,
        authId: 0,
        signerSig: null,
        startBurnHt: simnet.burnBlockHeight,
        numCycles: 1,
        unlockBytes: randomBytes(255),
      }),
      alice,
    );
    expect(ok.value.stacker).toBe(alice);
  });

  test('stake-pooled via wrapper fails without allowance, succeeds with allowance', () => {
    registerPool({ caller: deployer });

    const result = txErr(
      pox5Indirect.stakePooled({
        poolOwner: testPool.identifier,
        amountUstx: minAmount,
        numCycles: 1,
        unlockBytes: randomBytes(255),
        startBurnHt: simnet.burnBlockHeight,
      }),
      alice,
    );
    expect(result.value).toEqual(errorCodes.ERR_PERMISSION_DENIED);

    txOk(
      pox5.allowContractCaller({ caller: wrapper, untilBurnHt: null }),
      alice,
    );

    const ok = txOk(
      pox5Indirect.stakePooled({
        poolOwner: testPool.identifier,
        amountUstx: minAmount,
        numCycles: 1,
        unlockBytes: randomBytes(255),
        startBurnHt: simnet.burnBlockHeight,
      }),
      alice,
    );
    expect(ok.value.stacker).toBe(alice);
  });

  test('stake-extend via wrapper fails without allowance, succeeds with allowance', () => {
    const { signerKey } = setupSigner(alice);
    const poxAddr = randomPoxAddress();
    const unlockBytes = randomBytes(255);

    const stakeResult = txOk(
      pox5.stake({
        amountUstx: minAmount,
        poxAddr,
        signerKey,
        maxAmount: minAmount,
        authId: 0,
        signerSig: null,
        startBurnHt: simnet.burnBlockHeight,
        numCycles: 1,
        unlockBytes,
      }),
      alice,
    );
    mineUntil(stakeResult.value.unlockBurnHeight);

    const result = txErr(
      pox5Indirect.stakeExtend({
        amountUstx: minAmount,
        poxAddr,
        signerKey,
        signerSig: null,
        maxAmount: minAmount,
        authId: 1,
        numCycles: 1,
        unlockBytes,
      }),
      alice,
    );
    expect(result.value).toEqual(errorCodes.ERR_PERMISSION_DENIED);

    txOk(
      pox5.allowContractCaller({ caller: wrapper, untilBurnHt: null }),
      alice,
    );

    const ok = txOk(
      pox5Indirect.stakeExtend({
        amountUstx: minAmount,
        poxAddr,
        signerKey,
        signerSig: null,
        maxAmount: minAmount,
        authId: 1,
        numCycles: 1,
        unlockBytes,
      }),
      alice,
    );
    expect(ok.value.stacker).toBe(alice);
  });

  test('stake-extend-pooled via wrapper fails without allowance, succeeds with allowance', () => {
    registerPool({ caller: deployer });

    const stakeResult = txOk(
      pox5.stakePooled({
        poolOwner: testPool.identifier,
        amountUstx: minAmount,
        numCycles: 1,
        unlockBytes: randomBytes(255),
        startBurnHt: simnet.burnBlockHeight,
      }),
      alice,
    );
    mineUntil(stakeResult.value.unlockBurnHeight);

    const result = txErr(
      pox5Indirect.stakeExtendPooled({
        poolOwner: testPool.identifier,
        amountUstx: minAmount,
        numCycles: 1,
        unlockBytes: randomBytes(255),
      }),
      alice,
    );
    expect(result.value).toEqual(errorCodes.ERR_PERMISSION_DENIED);

    txOk(
      pox5.allowContractCaller({ caller: wrapper, untilBurnHt: null }),
      alice,
    );

    const ok = txOk(
      pox5Indirect.stakeExtendPooled({
        poolOwner: testPool.identifier,
        amountUstx: minAmount,
        numCycles: 1,
        unlockBytes: randomBytes(255),
      }),
      alice,
    );
    expect(ok.value.stacker).toBe(alice);
  });

  test('stake-update via wrapper fails without allowance, succeeds with allowance', () => {
    const { signerKey } = setupSigner(alice);
    txOk(
      pox5.stake({
        amountUstx: minAmount,
        poxAddr: randomPoxAddress(),
        signerKey,
        maxAmount: minAmount,
        authId: 0,
        signerSig: null,
        startBurnHt: simnet.burnBlockHeight,
        numCycles: 2,
        unlockBytes: randomBytes(255),
      }),
      alice,
    );

    const { signerKey: newSignerKey } = setupSigner(alice);
    const newPoxAddr = randomPoxAddress();

    const result = txErr(
      pox5Indirect.stakeUpdate({
        amountUstxIncrease: 1,
        poxAddr: newPoxAddr,
        signerKey: newSignerKey,
        signerSig: null,
        maxAmount: minAmount,
        authId: 1,
      }),
      alice,
    );
    expect(result.value).toEqual(errorCodes.ERR_PERMISSION_DENIED);

    txOk(
      pox5.allowContractCaller({ caller: wrapper, untilBurnHt: null }),
      alice,
    );

    const ok = txOk(
      pox5Indirect.stakeUpdate({
        amountUstxIncrease: 1,
        poxAddr: newPoxAddr,
        signerKey: newSignerKey,
        signerSig: null,
        maxAmount: minAmount,
        authId: 1,
      }),
      alice,
    );
    expect(ok.value.amountUstx).toBe(minAmount + 1n);
  });

  test('stake-update-pooled via wrapper fails without allowance, succeeds with allowance', () => {
    registerPool({ caller: deployer });
    txOk(
      pox5.stakePooled({
        poolOwner: testPool.identifier,
        amountUstx: minAmount,
        numCycles: 2,
        unlockBytes: randomBytes(255),
        startBurnHt: simnet.burnBlockHeight,
      }),
      alice,
    );

    const result = txErr(
      pox5Indirect.stakeUpdatePooled({
        poolOwner: testPool.identifier,
        amountUstxIncrease: 1,
      }),
      alice,
    );
    expect(result.value).toEqual(errorCodes.ERR_PERMISSION_DENIED);

    txOk(
      pox5.allowContractCaller({ caller: wrapper, untilBurnHt: null }),
      alice,
    );

    const ok = txOk(
      pox5Indirect.stakeUpdatePooled({
        poolOwner: testPool.identifier,
        amountUstxIncrease: 1,
      }),
      alice,
    );
    expect(ok.value.amountUstx).toBe(minAmount + 1n);
  });

  test('register-pool via wrapper fails without allowance, succeeds with allowance', () => {
    const { signerKey } = setupSigner(deployer);
    const poxAddr = randomPoxAddress();

    const result = txErr(
      pox5Indirect.registerPool({
        poolOwner: testPool.identifier,
        signerKey,
        poxAddr,
        signerSig: new Uint8Array(65),
        authId: 0,
      }),
      deployer,
    );
    expect(result.value).toEqual(errorCodes.ERR_PERMISSION_DENIED);

    txOk(
      pox5.allowContractCaller({ caller: wrapper, untilBurnHt: null }),
      deployer,
    );

    const ok = txOk(
      pox5Indirect.registerPool({
        poolOwner: testPool.identifier,
        signerKey,
        poxAddr,
        signerSig: new Uint8Array(65),
        authId: 0,
      }),
      deployer,
    );
    expect(ok.value.owner).toBe(testPool.identifier);
  });

  test('revoke-signer-grant via wrapper fails without allowance, succeeds with allowance', () => {
    const signerSk = randomSecretKey();
    const signerKey = secp256k1.getPublicKey(signerSk, true);
    const addr = signerAddress(signerKey);

    createSignerKeyGrant({
      staker: alice,
      signerSk,
      poxAddr: null,
      authId: 0n,
    });

    const result = txErr(
      pox5Indirect.revokeSignerGrant({ staker: alice, signerKey }),
      addr,
    );
    expect(result.value).toEqual(errorCodes.ERR_PERMISSION_DENIED);

    txOk(
      pox5.allowContractCaller({ caller: wrapper, untilBurnHt: null }),
      addr,
    );

    const ok = txOk(
      pox5Indirect.revokeSignerGrant({ staker: alice, signerKey }),
      addr,
    );
    expect(ok.value).toBe(true);
  });

  test('allowance with expiration: stake then stake-update via wrapper', () => {
    const { signerKey } = setupSigner(alice);
    const poxAddr = randomPoxAddress();

    // Allow the wrapper until burn height 50
    txOk(pox5.allowContractCaller({ caller: wrapper, untilBurnHt: 50 }), alice);

    txOk(
      pox5Indirect.stake({
        amountUstx: minAmount,
        poxAddr,
        signerKey,
        maxAmount: minAmount,
        authId: 0,
        signerSig: null,
        startBurnHt: simnet.burnBlockHeight,
        numCycles: 2,
        unlockBytes: randomBytes(255),
      }),
      alice,
    );

    // stake-update also works before expiration
    const { signerKey: newSignerKey } = setupSigner(alice);
    txOk(
      pox5Indirect.stakeUpdate({
        amountUstxIncrease: 1,
        poxAddr,
        signerKey: newSignerKey,
        signerSig: null,
        maxAmount: minAmount,
        authId: 1,
      }),
      alice,
    );

    // Mine past the expiration
    mineUntil(51);

    // Now stake-update via wrapper should fail
    const { signerKey: anotherSignerKey } = setupSigner(alice);
    const result = txErr(
      pox5Indirect.stakeUpdate({
        amountUstxIncrease: 1,
        poxAddr,
        signerKey: anotherSignerKey,
        signerSig: null,
        maxAmount: minAmount,
        authId: 2,
      }),
      alice,
    );
    expect(result.value).toEqual(errorCodes.ERR_PERMISSION_DENIED);
  });
});
