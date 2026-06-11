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
  grantedSigners,
  isInPreparePhase,
  isStakerActive,
  logCommand,
  modelAddStakerToCycles,
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
          // Only signers with a live grant can accept a new stake; revoke
          // blocks it. The run picks from these.
          grantedSigners(model).length > 0 &&
          !isStakerActive(model, r.sender) &&
          // stake reverts with ERR_STAKE_IN_PREPARE_PHASE in the prepare phase.
          !isInPreparePhase(model),
        run: (model: Model, real: Real) => {
          refreshModel(model, real);
          trackCommandRun(model, 'stake');

          // Arrange
          const registered = grantedSigners(model);
          const signer = registered[r.signerIndex % registered.length];
          pickedSigner = signer;
          const bitcoinHeightBefore = real.network.burnBlockHeight;
          const stacksHeightBefore = real.network.stacksBlockHeight;
          const expectedFirstStakedRewardCycle = currentRewardCycle(model) + 1n;
          const expectedUnlockCycle =
            expectedFirstStakedRewardCycle + r.numCycles;
          const expectedUnlockBurnHeight = rewardCycleToBurnHeight(
            model,
            expectedUnlockCycle,
          );
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

          // Update model

          // Replay the contract's per-cycle writes across
          // [firstLockedCycle, +numCycles) before the asserts, so they compare
          // against the committed mirror and stay in lockstep if one throws.
          model.stakers.set(r.sender, newStakerState);
          modelAddStakerToCycles(
            model,
            r.sender,
            signer,
            firstLockedCycle,
            r.numCycles,
            r.amountUstx,
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
          // Lock has started: amount locked until the unlock burn height.
          assertStakerLock(model, real, r.sender);
          // Per-cycle invariants at the staker's first and last locked cycles.
          assertSignerDelegationForCycle(model, real, firstLockedCycle, signer);
          assertSignerCycleMembership(model, real, firstLockedCycle, r.sender);
          assertTotalDelegatedForCycle(model, real, firstLockedCycle);
          assertStakerSharesForCycle(
            model,
            real,
            firstLockedCycle,
            r.sender,
            signer,
          );

          assertSignerDelegationForCycle(model, real, lastLockedCycle, signer);
          assertSignerCycleMembership(model, real, lastLockedCycle, r.sender);
          assertTotalDelegatedForCycle(model, real, lastLockedCycle);
          assertStakerSharesForCycle(
            model,
            real,
            lastLockedCycle,
            r.sender,
            signer,
          );

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
