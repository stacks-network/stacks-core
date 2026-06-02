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
  refreshModel,
  rewardCycleToBurnHeight,
  trackCommandRun,
} from './utils';
import { rov, txOk } from '@clarigen/test';
import { expect } from 'vitest';

export const Stake = (accounts: Real['accounts']) =>
  fc
    .record({
      sender: fc.constantFrom(...Object.values(accounts).map((x) => x.address)),
      // Wider than the baseline [1e6, 1e7] so single stakers can cross
      // SIGNER_SET_MIN_USTX (5e10) and exercise threshold-crossing paths.
      amountUstx: fc.bigInt({ min: 1000000n, max: 1000000000000n }),
      // Full contract-supported lock range, bigint to compose with cycle math.
      numCycles: fc.bigInt({ min: 1n, max: 96n }),
      signerIndex: fc.nat(),
    })
    .map((r) => {
      let pickedSigner: string | undefined;
      return {
        check: (model: Readonly<Model>) =>
          model.signers.size > 0 && !isStakerActive(model, r.sender),
        run: (model: Model, real: Real) => {
          refreshModel(model, real);
          trackCommandRun(model, 'stake');

          // Arrange
          const registered = Array.from(model.signers);
          const signer = registered[r.signerIndex % registered.length];
          pickedSigner = signer;
          const bitcoinHeightBefore = real.network.burnBlockHeight;
          const stacksHeightBefore = real.network.stacksBlockHeight;
          const expectedFirstStakedRewardCycle = currentRewardCycle(model) + 1n;
          const expectedUnlockCycle =
            expectedFirstStakedRewardCycle + r.numCycles;
          const expectedUnlockBurnHeight =
            rewardCycleToBurnHeight(model, expectedUnlockCycle) +
            model.rewardCycleLength / 2n;
          const stakerInfoBefore = rov(
            real.contracts.pox5.getStakerInfo(r.sender),
          );
          const newStakerState: StakerState = {
            amountUstx: r.amountUstx,
            firstRewardCycle: expectedFirstStakedRewardCycle,
            numCycles: r.numCycles,
            unlockBurnHeight: expectedUnlockBurnHeight,
            unlockCycle: expectedUnlockCycle,
            signer,
          };
          const after = new Map(model.stakers);
          after.set(r.sender, newStakerState);
          const firstLockedCycle = expectedFirstStakedRewardCycle;
          const lastLockedCycle =
            expectedFirstStakedRewardCycle + r.numCycles - 1n;

          // Act
          const receipt = txOk(
            real.contracts.pox5.stake({
              signerManager: signer,
              amountUstx: r.amountUstx,
              numCycles: r.numCycles,
              startBurnHt: real.network.burnBlockHeight,
              signerCalldata: null,
            }),
            r.sender,
          );

          // Assert
          expect(stakerInfoBefore).toBeNull();
          expect(receipt.value.firstRewardCycle).toBe(
            expectedFirstStakedRewardCycle,
          );
          expect(receipt.value.unlockCycle).toBe(expectedUnlockCycle);
          expect(receipt.value.unlockBurnHeight).toBe(expectedUnlockBurnHeight);
          expect(receipt.value.signer).toBe(signer);
          expect(receipt.value.staker).toBe(r.sender);
          expect(receipt.value.amountUstx).toBe(r.amountUstx);
          expect(rov(real.contracts.pox5.getStakerInfo(r.sender))).toEqual({
            amountUstx: r.amountUstx,
            firstRewardCycle: expectedFirstStakedRewardCycle,
            numCycles: r.numCycles,
            signer,
          });
          // Per-cycle invariants at the staker's first and last locked
          // cycles.
          assertSignerDelegationForCycle(after, real, firstLockedCycle, signer);
          assertSignerCycleMembership(after, real, firstLockedCycle, r.sender);
          assertTotalDelegatedForCycle(after, real, firstLockedCycle);
          assertStakerSharesForCycle(
            after,
            real,
            firstLockedCycle,
            r.sender,
            signer,
          );

          assertSignerDelegationForCycle(after, real, lastLockedCycle, signer);
          assertSignerCycleMembership(after, real, lastLockedCycle, r.sender);
          assertTotalDelegatedForCycle(after, real, lastLockedCycle);
          assertStakerSharesForCycle(
            after,
            real,
            lastLockedCycle,
            r.sender,
            signer,
          );

          // Update model
          model.stakers.set(r.sender, newStakerState);

          logCommand({
            sender: getWalletNameByAddress(r.sender),
            action: 'stake',
            value: `amount: ${r.amountUstx} cycles: ${r.numCycles} signer: ${signer}`,
            bitcoinHeightBefore,
            stacksHeightBefore,
          });
        },
        toString: () =>
          `stake(${getWalletNameByAddress(r.sender)}, ${r.amountUstx}, ${r.numCycles}${pickedSigner ? `, ${pickedSigner.split('.').pop()}` : ''})`,
      };
    });
