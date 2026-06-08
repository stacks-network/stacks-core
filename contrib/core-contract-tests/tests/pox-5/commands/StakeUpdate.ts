import fc from 'fast-check';
import type { Model, Real, StakerState } from './types';
import {
  assertSignerCycleMembership,
  assertSignerDelegationForCycle,
  assertStakerSharesForCycle,
  assertTotalDelegatedForCycle,
  currentRewardCycle,
  getWalletNameByAddress,
  isStakerActive,
  logCommand,
  modelAddStakerToCycles,
  modelRemoveStakerFromCycles,
  refreshModel,
  rewardCycleToBurnHeight,
  trackCommandRun,
} from './utils';
import { rov, txOk } from '@clarigen/test';
import { expect } from 'vitest';

export const StakeUpdate = (accounts: Real['accounts']) =>
  fc
    .record({
      sender: fc.constantFrom(...Object.values(accounts).map((x) => x.address)),
      cyclesToExtend: fc.bigInt({ min: 1n, max: 12n }),
      amountIncrease: fc.bigInt({ min: 0n, max: 1000000000000n }),
      signerIndex: fc.nat(),
    })
    .map((r) => {
      let pickedSigner: string | undefined;
      return {
        // Gate so the resulting internal num-cycles
        //   (new-unlock-cycle - current-cycle - 1)
        // stays within the contract's [1, 96] band; otherwise stake-update
        // would always reject with ERR_INVALID_NUM_CYCLES.
        check: (model: Readonly<Model>) => {
          if (model.signers.size === 0) return false;
          if (!isStakerActive(model, r.sender)) return false;
          const prev = model.stakers.get(r.sender)!;
          const prevUnlockCycle = prev.firstRewardCycle + prev.numCycles;
          const newUnlockCycle = prevUnlockCycle + r.cyclesToExtend;
          const internalNumCycles =
            newUnlockCycle - currentRewardCycle(model) - 1n;
          return internalNumCycles >= 1n && internalNumCycles <= 96n;
        },
        run: (model: Model, real: Real) => {
          refreshModel(model, real);
          trackCommandRun(model, 'stake-update');

          // Arrange
          const registered = Array.from(model.signers.keys());
          const newSigner = registered[r.signerIndex % registered.length];
          pickedSigner = newSigner;
          const bitcoinHeightBefore = real.network.burnBlockHeight;
          const stacksHeightBefore = real.network.stacksBlockHeight;
          const currentCycle = currentRewardCycle(model);
          const prev = model.stakers.get(r.sender)!;
          const prevUnlockCycle = prev.firstRewardCycle + prev.numCycles;
          const expectedUnlockCycle = prevUnlockCycle + r.cyclesToExtend;
          const expectedUnlockBurnHeight =
            rewardCycleToBurnHeight(model, expectedUnlockCycle) +
            model.rewardCycleLength / 2n;
          const expectedAmountUstx = prev.amountUstx + r.amountIncrease;
          // Contract preserves the original first-reward-cycle in staker-info
          // and bumps num-cycles by cyclesToExtend.
          const expectedNumCycles = prev.numCycles + r.cyclesToExtend;
          const stakerInfoBefore = rov(
            real.contracts.pox5.getStakerInfo(r.sender),
          );
          const newStakerState: StakerState = {
            amountUstx: expectedAmountUstx,
            firstRewardCycle: prev.firstRewardCycle,
            numCycles: expectedNumCycles,
            unlockBurnHeight: expectedUnlockBurnHeight,
            unlockCycle: expectedUnlockCycle,
            signer: newSigner,
          };
          // Boundary cycles of the Act's affected range. The contract removes
          // the staker from [current+1, prev-unlock) and re-adds across
          // [current+1, new-unlock); with `cyclesToExtend >= 1` the new range
          // always extends past the old, so first=current+1, last=new-unlock-1
          // covers both ends of the affected band.
          const firstAffectedCycle = currentCycle + 1n;
          const lastAffectedCycle = expectedUnlockCycle - 1n;

          // Act
          const receipt = txOk(
            real.contracts.pox5.stakeUpdate({
              signerManager: newSigner,
              oldSignerManager: prev.signer,
              cyclesToExtend: r.cyclesToExtend,
              amountIncrease: r.amountIncrease,
              signerCalldata: null,
            }),
            r.sender,
          );

          // Update model

          // Replay the contract's remove-then-add across the affected cycles,
          // then commit the staker record. The remove reads the stored
          // (pre-update) memberships, so amount/signer changes net out per
          // cycle exactly as the contract computes them. Done before the
          // per-cycle asserts so they compare against the committed mirror.
          modelRemoveStakerFromCycles(
            model,
            r.sender,
            firstAffectedCycle,
            prevUnlockCycle - currentCycle - 1n,
          );
          modelAddStakerToCycles(
            model,
            r.sender,
            newSigner,
            firstAffectedCycle,
            expectedUnlockCycle - currentCycle - 1n,
            expectedAmountUstx,
          );
          model.stakers.set(r.sender, newStakerState);

          // Assert

          // Pre-state: contract's view matched the model's pre-update record.
          expect(stakerInfoBefore).toEqual({
            amountUstx: prev.amountUstx,
            firstRewardCycle: prev.firstRewardCycle,
            numCycles: prev.numCycles,
            signer: prev.signer,
          });
          // Receipt reflects the recomputed unlock cycle and new amount/signer.
          expect(receipt.value.unlockCycle).toBe(expectedUnlockCycle);
          expect(receipt.value.unlockBurnHeight).toBe(expectedUnlockBurnHeight);
          expect(receipt.value.prevUnlockHeight).toBe(prevUnlockCycle);
          expect(receipt.value.amountUstx).toBe(expectedAmountUstx);
          expect(receipt.value.signer).toBe(newSigner);
          expect(receipt.value.staker).toBe(r.sender);
          // Post-state staker-info matches the updated record.
          expect(rov(real.contracts.pox5.getStakerInfo(r.sender))).toEqual({
            amountUstx: expectedAmountUstx,
            firstRewardCycle: prev.firstRewardCycle,
            numCycles: expectedNumCycles,
            signer: newSigner,
          });
          // Per-cycle invariants at the first and last affected cycles.
          assertSignerDelegationForCycle(
            model,
            real,
            firstAffectedCycle,
            newSigner,
          );
          assertSignerCycleMembership(
            model,
            real,
            firstAffectedCycle,
            r.sender,
          );
          assertTotalDelegatedForCycle(model, real, firstAffectedCycle);
          assertStakerSharesForCycle(
            model,
            real,
            firstAffectedCycle,
            r.sender,
            newSigner,
          );

          assertSignerDelegationForCycle(
            model,
            real,
            lastAffectedCycle,
            newSigner,
          );
          assertSignerCycleMembership(model, real, lastAffectedCycle, r.sender);
          assertTotalDelegatedForCycle(model, real, lastAffectedCycle);
          assertStakerSharesForCycle(
            model,
            real,
            lastAffectedCycle,
            r.sender,
            newSigner,
          );

          logCommand({
            sender: getWalletNameByAddress(r.sender),
            action: 'stake-update',
            value: `extend: ${r.cyclesToExtend} +ustx: ${r.amountIncrease} signer: ${newSigner}`,
            bitcoinHeightBefore,
            stacksHeightBefore,
          });
        },
        toString: () =>
          `stake-update(${getWalletNameByAddress(r.sender)}, +${r.cyclesToExtend}c, +${r.amountIncrease}u${pickedSigner ? `, ${pickedSigner.split('.').pop()}` : ''})`,
      };
    });
