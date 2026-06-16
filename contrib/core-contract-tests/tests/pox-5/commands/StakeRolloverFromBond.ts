import fc from 'fast-check';
import type { Model, Real, StakerState } from './types';
import {
  assertSignerCycleMembership,
  assertSignerDelegationForCycle,
  assertStakerLock,
  assertStakerSharesForCycle,
  assertTotalDelegatedForCycle,
  bondEndCycle,
  bondRolloverUnlockHeight,
  candidateSignerIds,
  currentRewardCycle,
  getWalletNameByAddress,
  grantedSigners,
  isInPreparePhase,
  logCommand,
  modelAddStakerToCycles,
  refreshModel,
  rewardCycleToBurnHeight,
  trackCommandRun,
} from './utils';
import { rov, txOk } from '@clarigen/test';
import { expect } from 'vitest';
import { sbtcBalance } from '../pox-5-helpers';

/**
 * Roll an ending bond membership into a STX-only stake. The existing bond term
 * no longer overlaps the new stake, the L1 unlock window is open, and stake
 * deletes the bond membership after refunding any custodied sBTC.
 */
export const StakeRolloverFromBond = (accounts: Real['accounts']) =>
  fc
    .record({
      sender: fc.constantFrom(...Object.values(accounts).map((x) => x.address)),
      numCycles: fc.bigInt({ min: 1n, max: 96n }),
      signer: fc.constantFrom(...candidateSignerIds),
    })
    .map((r) => ({
      check: (model: Readonly<Model>) => {
        const membership = model.bondMemberships.get(r.sender);
        return (
          membership !== undefined &&
          currentRewardCycle(model) + 1n >=
            bondEndCycle(model, membership.bondIndex) &&
          model.burnBlockHeight >=
            bondRolloverUnlockHeight(model, membership.bondIndex) &&
          !model.stakers.has(r.sender) &&
          !isInPreparePhase(model) &&
          grantedSigners(model).includes(r.signer)
        );
      },
      run: (model: Model, real: Real) => {
        refreshModel(model, real);
        trackCommandRun(model, 'stake_rollover_from_bond');

        // Arrange

        const bitcoinHeightBefore = real.network.burnBlockHeight;
        const stacksHeightBefore = real.network.stacksBlockHeight;
        const membership = model.bondMemberships.get(r.sender)!;
        const oldSbtc = membership.isL1Lock ? 0n : membership.amountSats;
        const balanceBefore = model.sbtcBalances.get(r.sender) ?? 0n;
        const contractBalanceBefore = model.contractSbtcBalance;
        const totalSbtcBefore = model.totalSbtcStaked;
        const membershipBefore = rov(
          real.contracts.pox5.getBondMembership(r.sender),
        );
        const firstRewardCycle = currentRewardCycle(model) + 1n;
        const unlockCycle = firstRewardCycle + r.numCycles;
        const unlockBurnHeight = rewardCycleToBurnHeight(model, unlockCycle);
        const amountUstx = membership.amountUstx;
        const stakerState: StakerState = {
          amountUstx,
          firstRewardCycle,
          numCycles: r.numCycles,
          unlockBurnHeight,
          unlockCycle,
          signer: r.signer,
        };
        const lastLockedCycle = unlockCycle - 1n;

        // Act

        const receipt = txOk(
          real.contracts.pox5.stake({
            signerManager: r.signer,
            amountUstx,
            numCycles: r.numCycles,
            startBurnHt: real.network.burnBlockHeight,
            signerCalldata: null,
          }),
          r.sender,
        );

        // Update model

        model.bondMemberships.delete(r.sender);
        model.sbtcBalances.set(r.sender, balanceBefore + oldSbtc);
        model.contractSbtcBalance = contractBalanceBefore - oldSbtc;
        model.totalSbtcStaked = totalSbtcBefore - oldSbtc;
        model.stakers.set(r.sender, stakerState);
        modelAddStakerToCycles(
          model,
          r.sender,
          r.signer,
          firstRewardCycle,
          r.numCycles,
          amountUstx,
        );

        // Assert

        // The public getter hides expired memberships, but the stake entry
        // point intentionally reads the raw map so stale ending bonds can still
        // roll over. If the bond is still active, the getter exposes it.
        if (
          currentRewardCycle(model) < bondEndCycle(model, membership.bondIndex)
        ) {
          expect(membershipBefore).toEqual(membership);
        }
        expect(receipt.value.firstRewardCycle).toBe(firstRewardCycle);
        expect(receipt.value.unlockCycle).toBe(unlockCycle);
        expect(receipt.value.unlockBurnHeight).toBe(unlockBurnHeight);
        expect(receipt.value.amountUstx).toBe(amountUstx);
        expect(receipt.value.signer).toBe(r.signer);
        expect(rov(real.contracts.pox5.getBondMembership(r.sender))).toBeNull();
        expect(rov(real.contracts.pox5.getStakerInfo(r.sender))).toEqual({
          amountUstx,
          firstRewardCycle,
          numCycles: r.numCycles,
          signer: r.signer,
        });
        expect(sbtcBalance(r.sender)).toBe(balanceBefore + oldSbtc);
        expect(rov(real.contracts.pox5.getTotalSbtcStaked())).toBe(
          model.totalSbtcStaked,
        );
        assertStakerLock(model, real, r.sender);

        assertSignerDelegationForCycle(model, real, firstRewardCycle, r.signer);
        assertSignerCycleMembership(model, real, firstRewardCycle, r.sender);
        assertTotalDelegatedForCycle(model, real, firstRewardCycle);
        assertStakerSharesForCycle(
          model,
          real,
          firstRewardCycle,
          r.sender,
          r.signer,
        );

        assertSignerDelegationForCycle(model, real, lastLockedCycle, r.signer);
        assertSignerCycleMembership(model, real, lastLockedCycle, r.sender);
        assertTotalDelegatedForCycle(model, real, lastLockedCycle);
        assertStakerSharesForCycle(
          model,
          real,
          lastLockedCycle,
          r.sender,
          r.signer,
        );

        logCommand({
          sender: getWalletNameByAddress(r.sender),
          action: 'stake-rollover-from-bond',
          value: `bond ${membership.bondIndex}`,
          bitcoinHeightBefore,
          stacksHeightBefore,
        });
      },
      toString: () =>
        `stake-rollover-from-bond(${getWalletNameByAddress(
          r.sender,
        )}, ${r.signer.split('.').pop()})`,
    }));
