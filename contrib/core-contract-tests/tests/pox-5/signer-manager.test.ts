import { beforeEach, expect, test } from 'vitest';
import {
  signerManager,
  signerManagerErrors,
  pox5,
  initPox5,
  registerSignerManager,
  sbtc,
  sbtcBalance,
} from './pox-5-helpers';
import { filterEvents, rov, txErr, txOk } from '@clarigen/test';
import { hex } from '@scure/base';
import { accounts } from '../clarigen-types';
import { mineUntil, randomPoxAddress, stxToUStx } from '../test-helpers';
import { Cl, serializeCV } from '@stacks/transactions';
import { CoreNodeEventType } from '@clarigen/core';

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

function makePoxAddrCalldata() {
  const poxAddr = randomPoxAddress();
  return {
    poxAddr,
    calldata: hex.decode(
      serializeCV(
        Cl.tuple({
          version: Cl.buffer(poxAddr.version),
          hashbytes: Cl.buffer(poxAddr.hashbytes),
        }),
      ),
    ),
  };
}

test('signers have pox-addr saved from calldata when provided', () => {
  const { poxAddr, calldata } = makePoxAddrCalldata();
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
  expect(rov(signerManager.getPoxAddr(alice))).toEqual(poxAddr);
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

  expect(rov(signerManager.getEarnedStakerRewards(alice, 1n, false))).toEqual({
    earned: grossPerStaker - fee,
    fees: fee,
  });
  expect(rov(signerManager.getEarnedStakerRewards(bob, 1n, false))).toEqual({
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
  const claim = txOk(signerManager.claimStakerRewards(1n, false), alice);
  const [transfer] = filterEvents(
    claim.events,
    CoreNodeEventType.FtTransferEvent,
  );

  expect(transfer.data.sender).toBe(signerManager.identifier);
  expect(transfer.data.recipient).toBe(alice);
  expect(transfer.data.amount).toBe(netRewards.toString());
  expect(sbtcBalance(alice)).toBe(aliceBalance + netRewards);
  expect(rov(signerManager.getEarnedStakerRewards(alice, 1n, false))).toEqual({
    earned: 0n,
    fees: 0n,
  });
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
  expect(rov(signerManager.getEarnedStakerRewards(alice, 1n, false))).toEqual({
    earned: 765n,
    fees: 85n,
  });

  txOk(signerManager.updateFees(5000n), deployer);
  calculateAndClaimSignerRewards(rewards, rov(pox5.rewardCycleToBurnHeight(2n)));

  expect(rov(signerManager.getEarnedStakerRewards(alice, 1n, false))).toEqual({
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
  txOk(signerManager.claimStakerRewards(1n, false), alice);

  txOk(signerManager.updateFees(5000n), deployer);
  calculateAndClaimSignerRewards(rewards, rov(pox5.rewardCycleToBurnHeight(2n)));

  expect(rov(signerManager.getEarnedStakerRewards(alice, 1n, false))).toEqual({
    earned: 425n,
    fees: 425n,
  });
  txOk(signerManager.claimStakerRewards(1n, false), alice);
  expect(sbtcBalance(alice)).toBe(aliceBalance + 765n + 425n);
});
