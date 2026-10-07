import fc from 'fast-check';
import type { Model, Real, StakerState } from './types';
import {
  assertSignerCycleMembership,
  assertSignerDelegationForCycle,
  assertStakerLock,
  assertStakerSharesForCycle,
  assertTotalDelegatedForCycle,
  currentRewardCycle,
  getWalletNameByAddress,
  isInPreparePhase,
  isStakerActive,
  logCommand,
  modelRemoveStakerFromCycles,
  refreshModel,
  rewardCycleToBurnHeight,
} from './utils';
import { proxyUnstakeOk } from '../pox-5-helpers';
import { rov } from '@clarigen/test';
import { expect } from 'vitest';

/** Unstake through a forwarding proxy contract. */
export const UnstakeViaContractCaller = (accounts: Real['accounts']) =>
  fc
    .record({
      sender: fc.constantFrom(...Object.values(accounts).map((x) => x.address)),
    })
    .map((r) => ({
      check: (model: Readonly<Model>) =>
        isStakerActive(model, r.sender) && !isInPreparePhase(model),
      run: (model: Model, real: Real) => {
        refreshModel(model, real);

        // Arrange

        const bitcoinHeightBefore = real.network.burnBlockHeight;
        const stacksHeightBefore = real.network.stacksBlockHeight;
        const prev = model.stakers.get(r.sender)!;
        const currentCycle = currentRewardCycle(model);
        const expectedUnlockCycle = currentCycle + 1n;
        const expectedUnlockBurnHeight = rewardCycleToBurnHeight(
          model,
          expectedUnlockCycle,
        );
        const expectedNumCycles = expectedUnlockCycle - prev.firstRewardCycle;
        const stakerInfoBefore = rov(
          real.contracts.pox5.getStakerInfo(r.sender),
        );
        const newStakerState: StakerState = {
          amountUstx: prev.amountUstx,
          firstRewardCycle: prev.firstRewardCycle,
          numCycles: expectedNumCycles,
          unlockBurnHeight: expectedUnlockBurnHeight,
          unlockCycle: expectedUnlockCycle,
          signer: prev.signer,
        };
        const prevUnlockCycle = prev.firstRewardCycle + prev.numCycles;
        const firstRemovedCycle = currentCycle + 1n;
        const lastRemovedCycle = prevUnlockCycle - 1n;

        // Act

        const receipt = proxyUnstakeOk({
          sender: r.sender,
          oldSignerManager: prev.signer,
        });

        // Update model

        modelRemoveStakerFromCycles(
          model,
          r.sender,
          firstRemovedCycle,
          prevUnlockCycle - currentCycle - 1n,
        );
        model.stakers.set(r.sender, newStakerState);

        // Assert

        expect(stakerInfoBefore).toEqual({
          amountUstx: prev.amountUstx,
          firstRewardCycle: prev.firstRewardCycle,
          numCycles: prev.numCycles,
          signer: prev.signer,
        });
        expect(receipt.value.unlockCycle).toBe(expectedUnlockCycle);
        expect(receipt.value.unlockBurnHeight).toBe(expectedUnlockBurnHeight);
        expect(receipt.value.firstRewardCycle).toBe(prev.firstRewardCycle);
        expect(receipt.value.amountUstx).toBe(prev.amountUstx);
        expect(receipt.value.staker).toBe(r.sender);
        expect(rov(real.contracts.pox5.getStakerInfo(r.sender))).toEqual({
          amountUstx: prev.amountUstx,
          firstRewardCycle: prev.firstRewardCycle,
          numCycles: expectedNumCycles,
          signer: prev.signer,
        });
        assertStakerLock(model, real, r.sender);
        if (firstRemovedCycle <= lastRemovedCycle) {
          assertSignerDelegationForCycle(
            model,
            real,
            firstRemovedCycle,
            prev.signer,
          );
          assertSignerCycleMembership(model, real, firstRemovedCycle, r.sender);
          assertTotalDelegatedForCycle(model, real, firstRemovedCycle);
          assertStakerSharesForCycle(
            model,
            real,
            firstRemovedCycle,
            r.sender,
            prev.signer,
          );

          assertSignerDelegationForCycle(
            model,
            real,
            lastRemovedCycle,
            prev.signer,
          );
          assertSignerCycleMembership(model, real, lastRemovedCycle, r.sender);
          assertTotalDelegatedForCycle(model, real, lastRemovedCycle);
          assertStakerSharesForCycle(
            model,
            real,
            lastRemovedCycle,
            r.sender,
            prev.signer,
          );
        }

        logCommand({
          sender: getWalletNameByAddress(r.sender),
          action: 'unstake-proxy',
          value: `unlockCycle: ${expectedUnlockCycle}`,
          bitcoinHeightBefore,
          stacksHeightBefore,
        });
      },
      toString: () => `unstake-proxy(${getWalletNameByAddress(r.sender)})`,
    }));
