import { beforeEach, expect, test } from 'vitest';
import {
  signerManager,
  signerManagerErrors,
  pox5,
  initPox5,
  registerSignerManager,
  deployTestSigner,
  sbtc,
  sbtcBalance,
} from './pox-5-helpers';
import { filterEvents, rov, txErr, txOk } from '@clarigen/test';
import { hex } from '@scure/base';
import { accounts, project } from '../clarigen-types';
import { mineUntil, randomPoxAddress, stxToUStx } from '../test-helpers';
import { Cl, serializeCV } from '@stacks/transactions';
import {
  CoreNodeEventType,
  cvToValue,
  err,
  projectFactory,
} from '@clarigen/core';

const contracts = projectFactory(project, 'simnet');
const sbtcRegistry = contracts.sbtcRegistry;

const REWARD_CYCLE_LENGTH = 100n;
const HALF_CYCLE_LENGTH = REWARD_CYCLE_LENGTH / 2n;
const BASIS_POINTS = 10000n;

const deployer = accounts.deployer.address;
const alice = accounts.wallet_1.address;
const bob = accounts.wallet_2.address;
const charlie = accounts.wallet_3.address;
const dave = accounts.wallet_4.address;
const emily = accounts.wallet_5.address;

beforeEach(() => {
  initPox5();
  registerSignerManager();
});

function reserveRewards(rewards: bigint) {
  return (rewards * pox5.constants.RESERVE_RATIO) / BASIS_POINTS;
}

function stxRewards(rewards: bigint) {
  return rewards - reserveRewards(rewards);
}

function setupTwoStakers() {
  const stake = stxToUStx(50_000);
  txOk(
    pox5.stake({
      signerManager: signerManager.identifier,
      amountUstx: stake,
      numCycles: 2n,
      startBurnHt: simnet.burnBlockHeight,
      signerCalldata: null,
    }),
    alice,
  );
  txOk(
    pox5.stake({
      signerManager: signerManager.identifier,
      amountUstx: stake,
      numCycles: 2n,
      startBurnHt: simnet.burnBlockHeight,
      signerCalldata: null,
    }),
    bob,
  );
}

function setupStaker(staker: string, signerCalldata: Uint8Array | null = null) {
  txOk(
    pox5.stake({
      signerManager: signerManager.identifier,
      amountUstx: stxToUStx(50_000),
      numCycles: 2n,
      startBurnHt: simnet.burnBlockHeight,
      signerCalldata,
    }),
    staker,
  );
}

function calculateAndClaimSignerRewards(rewards: bigint, height: bigint) {
  txOk(
    sbtc.transfer({
      recipient: pox5.identifier,
      amount: rewards,
      sender: deployer,
      memo: null,
    }),
    deployer,
  );
  mineUntil(height);
  txOk(pox5.calculateRewards([]), deployer);
  txOk(signerManager.claimRewards([], 1n), deployer);
}

function makePoxAddrCalldata(
  { maxFee }: { maxFee: bigint } = { maxFee: 100n },
) {
  const poxAddr = randomPoxAddress();
  return {
    poxAddr,
    maxFee,
    calldata: hex.decode(
      serializeCV(
        Cl.tuple({
          'pox-addr': Cl.tuple({
            version: Cl.buffer(poxAddr.version),
            hashbytes: Cl.buffer(poxAddr.hashbytes),
          }),
          'max-fee': Cl.uint(maxFee),
        }),
      ),
    ),
  };
}

test('validate-stake! errors when not called by the pox-5 contract', () => {
  // Calling the callback directly (contract-caller is a standard principal,
  // not .pox-5) must be rejected.
  const { calldata } = makePoxAddrCalldata();
  expect(
    txErr(
      signerManager.validateStake_x({
        staker: alice,
        firstIndex: 0n,
        numIndexes: 1n,
        amountUstx: stxToUStx(50_000),
        amountSats: 0n,
        isBond: false,
        signerCalldata: calldata,
      }),
      alice,
    ).value,
  ).toBe(signerManagerErrors.ERR_UNAUTHORIZED_CALLER);

  // The rejected call must not have written a pox-addr for the staker.
  expect(rov(signerManager.getPoxAddr(alice))).toBeNull();
});

test('a third party cannot hijack a staker pox-addr via a direct validate-stake! call', () => {
  // Alice legitimately stakes through pox-5 with no L1 pox-addr.
  setupStaker(alice);
  expect(rov(signerManager.getPoxAddr(alice))).toBeNull();

  // Bob attempts to register his own pox-addr against Alice's principal by
  // invoking the callback directly. This would redirect Alice's L1 rewards
  // to Bob's BTC address if the guard were missing.
  const { calldata } = makePoxAddrCalldata();
  expect(
    txErr(
      signerManager.validateStake_x({
        staker: alice,
        firstIndex: 0n,
        numIndexes: 1n,
        amountUstx: stxToUStx(50_000),
        amountSats: 0n,
        isBond: false,
        signerCalldata: calldata,
      }),
      bob,
    ).value,
  ).toBe(signerManagerErrors.ERR_UNAUTHORIZED_CALLER);
  expect(rov(signerManager.getPoxAddr(alice))).toBeNull();
});

test('signers have pox-addr saved from calldata when provided', () => {
  const { poxAddr, calldata, maxFee } = makePoxAddrCalldata();
  txOk(
    pox5.stake({
      signerManager: signerManager.identifier,
      amountUstx: 100000000n,
      numCycles: 1n,
      startBurnHt: simnet.burnBlockHeight,
      signerCalldata: calldata,
    }),
    alice,
  );
  expect(rov(signerManager.getPoxAddr(alice))?.poxAddr).toEqual(poxAddr);
  expect(rov(signerManager.getPoxAddr(alice))?.maxFee).toEqual(maxFee);
});

test('only admins can update fees and fees cannot exceed max bips', () => {
  expect(txErr(signerManager.updateFees(1000n), alice).value).toBe(
    signerManagerErrors.ERR_UNAUTHORIZED_ADMIN,
  );
  expect(txErr(signerManager.updateFees(10001n), deployer).value).toBe(
    signerManagerErrors.ERR_INVALID_FEES_BIPS,
  );
  txOk(signerManager.updateFees(10000n), deployer);
});

test('fees are deducted from newly earned staker rewards', () => {
  const rewards = 2000n;
  const grossPerStaker = stxRewards(rewards) / 2n;
  const fee = grossPerStaker / 10n;

  txOk(signerManager.updateFees(1000n), deployer);
  setupTwoStakers();
  calculateAndClaimSignerRewards(
    rewards,
    rov(pox5.rewardCycleToBurnHeight(1n)) + HALF_CYCLE_LENGTH,
  );

  expect(rov(signerManager.getEarnedStakerRewards(alice, 1n, null))).toEqual({
    earned: grossPerStaker - fee,
    fees: fee,
  });
  expect(rov(signerManager.getEarnedStakerRewards(bob, 1n, null))).toEqual({
    earned: grossPerStaker - fee,
    fees: fee,
  });
});

test('claiming staker rewards transfers net rewards after fees', () => {
  const rewards = 2000n;
  const grossPerStaker = stxRewards(rewards) / 2n;
  const netRewards = grossPerStaker - grossPerStaker / 10n;

  txOk(signerManager.updateFees(1000n), deployer);
  setupTwoStakers();
  calculateAndClaimSignerRewards(
    rewards,
    rov(pox5.rewardCycleToBurnHeight(1n)) + HALF_CYCLE_LENGTH,
  );

  const aliceBalance = sbtcBalance(alice);
  const claim = txOk(signerManager.claimStakerRewards(alice, 1n, null), alice);
  const [transfer] = filterEvents(
    claim.events,
    CoreNodeEventType.FtTransferEvent,
  );
  const [printEvent] = filterEvents(
    claim.events,
    CoreNodeEventType.ContractEvent,
  );
  const printData = cvToValue<{
    topic: string;
    amountSats: bigint;
    l1Withdrawal: null;
    staker: string;
    rewardCycle: bigint;
    bondIndex: null;
  }>(printEvent.data.value);

  expect(transfer.data.sender).toBe(signerManager.identifier);
  expect(transfer.data.recipient).toBe(alice);
  expect(transfer.data.amount).toBe(netRewards.toString());
  expect(printData).toEqual({
    topic: 'claim-staker-rewards',
    amountSats: netRewards,
    l1Withdrawal: null,
    staker: alice,
    rewardCycle: 1n,
    bondIndex: null,
  });
  expect(sbtcBalance(alice)).toBe(aliceBalance + netRewards);
  expect(rov(signerManager.getEarnedStakerRewards(alice, 1n, null))).toEqual({
    earned: 0n,
    fees: 0n,
  });
});

test('bond rewards remain claimable from old signer after staker changes signers', () => {
  const bondIndex = 0n;
  const aliceSats = 480000n;
  const rewards = 1200n;
  const signer2 = deployTestSigner(
    'bond-update-manager-claim-signer-2',
  ).identifier;

  txOk(
    pox5.setupBond({
      bondIndex,
      targetRate: 1500n,
      stxValueRatio: 10n,
      minUstxRatio: 100n,
      earlyUnlockBytes: new Uint8Array(),
      earlyUnlockAdmin: deployer,
      allowlist: [{ maxSats: aliceSats, staker: alice }],
    }),
    deployer,
  );
  txOk(
    pox5.registerForBond({
      bondIndex,
      signerManager: signerManager.identifier,
      amountUstx: stxToUStx(50_000),
      btcLockup: err(aliceSats),
      signerCalldata: null,
    }),
    alice,
  );
  txOk(
    sbtc.transfer({
      recipient: pox5.identifier,
      amount: rewards,
      sender: deployer,
      memo: null,
    }),
    deployer,
  );

  mineUntil(rov(pox5.rewardCycleToBurnHeight(1n)) + HALF_CYCLE_LENGTH);
  txOk(pox5.calculateRewards([bondIndex]), deployer);

  txOk(
    pox5.updateBondRegistration({
      signerManager: signer2,
      oldSignerManager: signerManager.identifier,
      signerCalldata: null,
    }),
    alice,
  );
  expect(
    rov(
      pox5.getStakerSharesStakedForCycle(
        alice,
        true,
        bondIndex,
        signerManager.identifier,
      ),
    ),
  ).toBe(0n);
  expect(
    rov(
      pox5.getStakerUnclaimedRewardsForCycle(
        signerManager.identifier,
        true,
        bondIndex,
        alice,
      ),
    ),
  ).toBe(rewards);

  txOk(signerManager.claimRewards([bondIndex], 1n), deployer);

  const aliceBalance = sbtcBalance(alice);
  txOk(signerManager.claimStakerRewards(alice, true, bondIndex), alice);
  expect(sbtcBalance(alice)).toBe(aliceBalance + rewards);
  expect(
    rov(signerManager.getEarnedStakerRewards(alice, true, bondIndex)),
  ).toEqual({
    earned: 0n,
    fees: 0n,
  });
});

test('claiming staker rewards with pox-addr initiates a withdrawal request', () => {
  const rewards = 2000n;
  const grossPerStaker = stxRewards(rewards) / 2n;
  const maxFee = 100n;
  const { poxAddr, calldata } = makePoxAddrCalldata({ maxFee });

  setupStaker(alice, calldata);
  setupStaker(bob);
  calculateAndClaimSignerRewards(
    rewards,
    rov(pox5.rewardCycleToBurnHeight(1n)) + HALF_CYCLE_LENGTH,
  );

  const aliceBalance = sbtcBalance(alice);
  const claim = txOk(signerManager.claimStakerRewards(alice, 1n, null), bob);
  const transfers = filterEvents(
    claim.events,
    CoreNodeEventType.FtTransferEvent,
  );
  const printEvent = filterEvents(
    claim.events,
    CoreNodeEventType.ContractEvent,
  ).at(1)!;
  const printData = cvToValue<{
    topic: string;
    amountSats: bigint;
    l1Withdrawal: {
      poxAddr: { version: Uint8Array; hashbytes: Uint8Array };
      amount: bigint;
      maxFee: bigint;
      withdrawalRequest: bigint;
    };
    staker: string;
    rewardCycle: bigint;
    bondIndex: null;
  }>(printEvent.data.value);

  expect(transfers).toHaveLength(0);
  expect(sbtcBalance(alice)).toBe(aliceBalance);
  expect(printData).toEqual({
    topic: 'claim-staker-rewards',
    amountSats: grossPerStaker,
    l1Withdrawal: {
      poxAddr,
      amount: grossPerStaker - maxFee,
      maxFee,
      withdrawalRequest: 1n,
    },
    staker: alice,
    rewardCycle: 1n,
    bondIndex: null,
  });
  const withdrawalRequest = rov(sbtcRegistry.getWithdrawalRequest(1n))!;
  expect(withdrawalRequest.amount).toBe(grossPerStaker - maxFee);
  expect(withdrawalRequest.maxFee).toBe(maxFee);
  expect(withdrawalRequest.recipient).toStrictEqual(poxAddr);
  expect(withdrawalRequest.sender).toBe(signerManager.identifier);
  expect(withdrawalRequest.status).toBe(null);
  expect(rov(signerManager.getWithdrawalRequestStaker(1n))).toBe(alice);
  expect(rov(signerManager.getEarnedStakerRewards(alice, 1n, null))).toEqual({
    earned: 0n,
    fees: 0n,
  });
});

test('claiming all rewards with pox-addr leaves room for withdrawal max-fee', () => {
  const rewards = 2000n;
  const earned = stxRewards(rewards);
  const maxFee = 100n;
  const { calldata } = makePoxAddrCalldata({ maxFee });

  setupStaker(alice, calldata);
  calculateAndClaimSignerRewards(
    rewards,
    rov(pox5.rewardCycleToBurnHeight(1n)) + HALF_CYCLE_LENGTH,
  );

  const claim = txOk(signerManager.claimStakerRewards(alice, 1n, null), bob);

  expect(claim.value).toBe(earned);
});

test('claiming staker rewards with pox-addr errors when earned is less than max-fee', () => {
  const rewards = 600n;
  const earned = stxRewards(rewards);
  const maxFee = earned + 1n;
  const { calldata } = makePoxAddrCalldata({ maxFee });

  setupStaker(alice, calldata);
  calculateAndClaimSignerRewards(
    rewards,
    rov(pox5.rewardCycleToBurnHeight(1n)) + HALF_CYCLE_LENGTH,
  );

  expect(
    txErr(signerManager.claimStakerRewards(alice, 1n, null), bob).value,
  ).toBe(signerManagerErrors.ERR_NO_CLAIMABLE_REWARDS);
});

test('fee changes apply to all uncrystallized rewards', () => {
  const rewards = 2000n;
  const grossAfterTwoCalculations = stxRewards(rewards * 2n) / 2n;

  txOk(signerManager.updateFees(1000n), deployer);
  setupTwoStakers();
  calculateAndClaimSignerRewards(
    rewards,
    rov(pox5.rewardCycleToBurnHeight(1n)) + HALF_CYCLE_LENGTH,
  );
  expect(rov(signerManager.getEarnedStakerRewards(alice, 1n, null))).toEqual({
    earned: 765n,
    fees: 85n,
  });

  txOk(signerManager.updateFees(5000n), deployer);
  calculateAndClaimSignerRewards(
    rewards,
    rov(pox5.rewardCycleToBurnHeight(2n)),
  );

  expect(rov(signerManager.getEarnedStakerRewards(alice, 1n, null))).toEqual({
    earned: grossAfterTwoCalculations / 2n,
    fees: grossAfterTwoCalculations / 2n,
  });
});

test('already claimed rewards are not affected by later fee changes', () => {
  const rewards = 2000n;

  txOk(signerManager.updateFees(1000n), deployer);
  setupTwoStakers();
  calculateAndClaimSignerRewards(
    rewards,
    rov(pox5.rewardCycleToBurnHeight(1n)) + HALF_CYCLE_LENGTH,
  );

  const aliceBalance = sbtcBalance(alice);
  txOk(signerManager.claimStakerRewards(alice, 1n, null), alice);

  txOk(signerManager.updateFees(5000n), deployer);
  calculateAndClaimSignerRewards(
    rewards,
    rov(pox5.rewardCycleToBurnHeight(2n)),
  );

  expect(rov(signerManager.getEarnedStakerRewards(alice, 1n, null))).toEqual({
    earned: 425n,
    fees: 425n,
  });
  txOk(signerManager.claimStakerRewards(alice, 1n, null), alice);
  expect(sbtcBalance(alice)).toBe(aliceBalance + 765n + 425n);
});
