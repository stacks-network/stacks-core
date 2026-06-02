import fc from 'fast-check';
import type { Model, Real, StakerState } from './types';
import {
  assertSignerCycleMembership,
  assertSignerDelegationForCycle,
  assertStakerSharesForCycle,
  assertTotalDelegatedForCycle,
  currentRewardCycle,
  getWalletNameByAddress,
  isInPreparePhase,
  isStakerActive,
  logCommand,
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
        const expectedUnlockBurnHeight =
          rewardCycleToBurnHeight(model, expectedUnlockCycle) +
          model.rewardCycleLength / 2n;
        // Contract sets `num-cycles = unlock-cycle - first-reward-cycle`
        // where `unlock-cycle = current-cycle + 1`. With the precondition
        // `current-cycle < unlockCycle` (i.e., lock not yet expired), this is
        // always ≥ 0; equals 0 only when current-cycle < first-reward-cycle,
        // i.e., the stake hasn't started yet (still in the cycle before its
        // first reward cycle).
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
        const after = new Map(model.stakers);
        after.set(r.sender, newStakerState);
        // The contract removes the staker from cycles [current+1, prev-unlock).
        // First/last cycle of that removed range; skip the quartet if empty
        // (staker was already at its last locked cycle and there's nothing to
        // remove from the future).
        const prevUnlockCycle = prev.firstRewardCycle + prev.numCycles;
        const firstRemovedCycle = currentCycle + 1n;
        const lastRemovedCycle = prevUnlockCycle - 1n;

        // Act
        const receipt = txOk(
          real.contracts.pox5.unstake({ oldSignerManager: prev.signer }),
          r.sender,
        );

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
        // staker-info still exists with the shortened num-cycles. Note that
        // even when expectedNumCycles is 0 (lock had not started yet:
        // firstRewardCycle > currentCycle), `get-staker-info` still returns
        // Some because its filter is `first + num <= current` and
        // `first + 0 = first > current` in that case.
        expect(rov(real.contracts.pox5.getStakerInfo(r.sender))).toEqual({
          amountUstx: prev.amountUstx,
          firstRewardCycle: prev.firstRewardCycle,
          numCycles: expectedNumCycles,
          signer: prev.signer,
        });
        // Per-cycle invariants at the first and last removed cycles. After
        // the Act the staker should no longer contribute to any of the
        // unconditional-write maps for those cycles. Skipped when the
        // removed range is empty (staker was at the last locked cycle).
        if (firstRemovedCycle <= lastRemovedCycle) {
          assertSignerDelegationForCycle(
            after,
            real,
            firstRemovedCycle,
            prev.signer,
          );
          assertSignerCycleMembership(after, real, firstRemovedCycle, r.sender);
          assertTotalDelegatedForCycle(after, real, firstRemovedCycle);
          assertStakerSharesForCycle(
            after,
            real,
            firstRemovedCycle,
            r.sender,
            prev.signer,
          );

          assertSignerDelegationForCycle(
            after,
            real,
            lastRemovedCycle,
            prev.signer,
          );
          assertSignerCycleMembership(after, real, lastRemovedCycle, r.sender);
          assertTotalDelegatedForCycle(after, real, lastRemovedCycle);
          assertStakerSharesForCycle(
            after,
            real,
            lastRemovedCycle,
            r.sender,
            prev.signer,
          );
        }

        // Update model
        model.stakers.set(r.sender, newStakerState);

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
