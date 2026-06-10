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

/**
 * Pure lock extension: `stake-update` with `amountIncrease = 0` and the
 * staker's current signer for both signer-manager args, varying only
 * `cyclesToExtend`. Guarantees the extend-only path (amount and signer
 * unchanged) is exercised; StakeUpdate covers the amount/signer-change paths.
 */
export const StakeExtend = (accounts: Real['accounts']) =>
  fc
    .record({
      sender: fc.constantFrom(...Object.values(accounts).map((x) => x.address)),
      cyclesToExtend: fc.bigInt({ min: 1n, max: 12n }),
    })
    .map((r) => {
      let pickedSigner: string | undefined;
      return {
        // Keep the resulting internal num-cycles (new-unlock - current - 1) in
        // the contract's [1, 96] band, else stake-update rejects.
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
          trackCommandRun(model, 'stake-extend');

          // Arrange
          const bitcoinHeightBefore = real.network.burnBlockHeight;
          const stacksHeightBefore = real.network.stacksBlockHeight;
          const currentCycle = currentRewardCycle(model);
          const prev = model.stakers.get(r.sender)!;
          // Extend-only: reuse the staker's signer for both args; capture it for toString.
          const signer = prev.signer;
          pickedSigner = signer;
          const prevUnlockCycle = prev.firstRewardCycle + prev.numCycles;
          const expectedUnlockCycle = prevUnlockCycle + r.cyclesToExtend;
          const expectedUnlockBurnHeight =
            rewardCycleToBurnHeight(model, expectedUnlockCycle) +
            model.rewardCycleLength / 2n;
          // Extend-only: amount unchanged (amountIncrease = 0).
          const expectedAmountUstx = prev.amountUstx;
          // Contract keeps first-reward-cycle, bumps num-cycles by cyclesToExtend.
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
            signer,
          };
          // Boundaries of the affected range: remove [current+1, prev-unlock),
          // re-add [current+1, new-unlock). cyclesToExtend >= 1 so the new
          // range extends past the old; first=current+1, last=new-unlock-1.
          const firstAffectedCycle = currentCycle + 1n;
          const lastAffectedCycle = expectedUnlockCycle - 1n;

          // Act
          const receipt = txOk(
            real.contracts.pox5.stakeUpdate({
              signerManager: signer,
              oldSignerManager: signer,
              cyclesToExtend: r.cyclesToExtend,
              amountIncrease: 0n,
              signerCalldata: null,
            }),
            r.sender,
          );

          // Update model

          // Replay the contract's remove-then-add over the affected cycles,
          // then commit. Amount and signer unchanged, so each existing cycle
          // nets back to the same value, just extended further out. Before the
          // asserts so they compare against the committed mirror.
          modelRemoveStakerFromCycles(
            model,
            r.sender,
            firstAffectedCycle,
            prevUnlockCycle - currentCycle - 1n,
          );
          modelAddStakerToCycles(
            model,
            r.sender,
            signer,
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
          // Receipt reflects the new unlock cycle; amount and signer unchanged.
          expect(receipt.value.unlockCycle).toBe(expectedUnlockCycle);
          expect(receipt.value.unlockBurnHeight).toBe(expectedUnlockBurnHeight);
          expect(receipt.value.prevUnlockHeight).toBe(prevUnlockCycle);
          expect(receipt.value.amountUstx).toBe(expectedAmountUstx);
          expect(receipt.value.signer).toBe(signer);
          expect(receipt.value.staker).toBe(r.sender);
          // Post-state staker-info matches the updated record.
          expect(rov(real.contracts.pox5.getStakerInfo(r.sender))).toEqual({
            amountUstx: expectedAmountUstx,
            firstRewardCycle: prev.firstRewardCycle,
            numCycles: expectedNumCycles,
            signer,
          });
          // Lock now reflects the extended unlock height at the same amount.
          assertStakerLock(model, real, r.sender);
          // Per-cycle invariants at the first and last affected cycles.
          assertSignerDelegationForCycle(
            model,
            real,
            firstAffectedCycle,
            signer,
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
            signer,
          );

          assertSignerDelegationForCycle(
            model,
            real,
            lastAffectedCycle,
            signer,
          );
          assertSignerCycleMembership(model, real, lastAffectedCycle, r.sender);
          assertTotalDelegatedForCycle(model, real, lastAffectedCycle);
          assertStakerSharesForCycle(
            model,
            real,
            lastAffectedCycle,
            r.sender,
            signer,
          );

          logCommand({
            sender: getWalletNameByAddress(r.sender),
            action: 'stake-extend',
            value: `extend: ${r.cyclesToExtend} signer: ${signer}`,
            bitcoinHeightBefore,
            stacksHeightBefore,
          });
        },
        toString: () =>
          `stake-extend(${getWalletNameByAddress(r.sender)}, +${r.cyclesToExtend}c${pickedSigner ? `, ${pickedSigner.split('.').pop()}` : ''})`,
      };
    });
