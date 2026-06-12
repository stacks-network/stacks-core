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
  trackCommandRun,
} from './utils';
import { rov, txOk } from '@clarigen/test';
import { expect } from 'vitest';

export const Unstake = (accounts: Real['accounts']) =>
  fc
    .record({
      sender: fc.constantFrom(...Object.values(accounts).map((x) => x.address)),
    })
    .map((r) => ({
      check: (model: Readonly<Model>) =>
        isStakerActive(model, r.sender) && !isInPreparePhase(model),
      run: (model: Model, real: Real) => {
        refreshModel(model, real);
        trackCommandRun(model, 'unstake');

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
        // Contract sets num-cycles = (current+1) - first-reward-cycle. The
        // active-staker precondition keeps this non-negative; it is 0 only
        // when the stake has not started yet (current < first-reward-cycle).
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
        // Boundaries of the contract's removed range [current+1, prev-unlock).
        // Empty when the staker is already at its last locked cycle.
        const prevUnlockCycle = prev.firstRewardCycle + prev.numCycles;
        const firstRemovedCycle = currentCycle + 1n;
        const lastRemovedCycle = prevUnlockCycle - 1n;

        // Act
        const receipt = txOk(
          real.contracts.pox5.unstake({ oldSignerManager: prev.signer }),
          r.sender,
        );

        // Update model

        // Replay the contract's removal across [current+1, prev-unlock) before
        // the asserts, so they compare against the committed mirror. An empty
        // range is a no-op.
        modelRemoveStakerFromCycles(
          model,
          r.sender,
          firstRemovedCycle,
          prevUnlockCycle - currentCycle - 1n,
        );
        model.stakers.set(r.sender, newStakerState);

        // Assert

        // Pre-state matched the model's record.
        expect(stakerInfoBefore).toEqual({
          amountUstx: prev.amountUstx,
          firstRewardCycle: prev.firstRewardCycle,
          numCycles: prev.numCycles,
          signer: prev.signer,
        });
        // Receipt reports the new shortened-lock end.
        expect(receipt.value.unlockCycle).toBe(expectedUnlockCycle);
        expect(receipt.value.unlockBurnHeight).toBe(expectedUnlockBurnHeight);
        expect(receipt.value.firstRewardCycle).toBe(prev.firstRewardCycle);
        expect(receipt.value.amountUstx).toBe(prev.amountUstx);
        expect(receipt.value.staker).toBe(r.sender);
        // staker-info still exists with the shortened num-cycles. Even when
        // expectedNumCycles is 0 (stake not started, first > current),
        // get-staker-info returns Some: its filter is first + num <= current,
        // which fails here since first > current.
        expect(rov(real.contracts.pox5.getStakerInfo(r.sender))).toEqual({
          amountUstx: prev.amountUstx,
          firstRewardCycle: prev.firstRewardCycle,
          numCycles: expectedNumCycles,
          signer: prev.signer,
        });
        // Still locked at the same amount; only the unlock burn height moves
        // earlier, to the next cycle.
        assertStakerLock(model, real, r.sender);
        // Per-cycle invariants at the first and last removed cycles, where the
        // staker no longer contributes after the Act. Skipped when the removed
        // range is empty (staker was at its last locked cycle).
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
          action: 'unstake',
          value: `unlockCycle: ${expectedUnlockCycle}`,
          bitcoinHeightBefore,
          stacksHeightBefore,
        });
      },
      toString: () => `unstake(${getWalletNameByAddress(r.sender)})`,
    }));
