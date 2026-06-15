import fc from 'fast-check';
import type { Model, Real, StakerState } from './types';
import {
  assertSignerCycleMembership,
  assertSignerDelegationForCycle,
  assertStakerLock,
  assertStakerSharesForCycle,
  assertTotalDelegatedForCycle,
  candidateSignerIds,
  currentRewardCycle,
  getWalletNameByAddress,
  grantedSigners,
  isContractCallerAllowed,
  isInPreparePhase,
  isStakerActive,
  logCommand,
  modelAddStakerToCycles,
  refreshModel,
  rewardCycleToBurnHeight,
  trackCommandRun,
} from './utils';
import { proxyStakeOk } from '../pox-5-helpers';
import { rov } from '@clarigen/test';
import { expect } from 'vitest';

/**
 * The same state transition as Stake, but the call enters pox-5 through the
 * proxy contract. This proves a live allowance authorizes `contract-caller`.
 */
export const StakeViaContractCaller = (accounts: Real['accounts']) =>
  fc
    .record({
      sender: fc.constantFrom(...Object.values(accounts).map((x) => x.address)),
      amountUstx: fc.bigInt({ min: 1000000n, max: 1000000000000n }),
      numCycles: fc.bigInt({ min: 1n, max: 96n }),
      signer: fc.constantFrom(...candidateSignerIds),
    })
    .map((r) => ({
      check: (model: Readonly<Model>) =>
        isContractCallerAllowed(model, r.sender) &&
        grantedSigners(model).includes(r.signer) &&
        !isStakerActive(model, r.sender) &&
        !model.bondMemberships.has(r.sender) &&
        !isInPreparePhase(model),
      run: (model: Model, real: Real) => {
        refreshModel(model, real);
        trackCommandRun(model, 'stake_proxy');

        // Arrange

        const signer = r.signer;
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

        const receipt = proxyStakeOk({
          sender: r.sender,
          signerManager: signer,
          amountUstx: r.amountUstx,
          numCycles: r.numCycles,
          startBurnHeight: real.network.burnBlockHeight,
        });

        // Update model

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
        assertStakerLock(model, real, r.sender);
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
          action: 'stake-proxy',
          value: `amount: ${r.amountUstx} cycles: ${r.numCycles} signer: ${signer}`,
          bitcoinHeightBefore,
          stacksHeightBefore,
        });
      },
      toString: () =>
        `stake-proxy(${getWalletNameByAddress(r.sender)}, ${r.amountUstx}, ${r.numCycles}, ${r.signer.split('.').pop()})`,
    }));
