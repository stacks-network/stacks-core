import fc from 'fast-check';
import type { Model, Real } from './types';
import {
  getWalletNameByAddress,
  logCommand,
  refreshModel,
  rewardsCalculationHeight,
  rewardsStxCycle,
  sortedActiveBonds,
} from './utils';
import { rov, txErr } from '@clarigen/test';
import { errorCodes } from '../pox-5-helpers';
import { expect } from 'vitest';

/**
 * calculate-rewards with one active bond left out of `bond-periods`. The
 * inclusion check runs before any distribution, finds the missing bond, and
 * reverts with ERR_ACTIVE_BOND_NOT_INCLUDED, mutating nothing.
 */
export const CalculateRewardsErrActiveBondNotIncluded = (
  accounts: Real['accounts'],
) =>
  fc
    .record({
      sender: fc.constantFrom(...Object.values(accounts).map((x) => x.address)),
      // Which active bond to drop from the otherwise-correct list.
      dropIndex: fc.nat(),
    })
    .map((r) => ({
      // A new half-cycle has closed and at least one bond is active to omit.
      check: (model: Readonly<Model>) =>
        rewardsCalculationHeight(model) > model.lastRewardComputeHeight &&
        sortedActiveBonds(model, rewardsCalculationHeight(model)).length > 0,
      run: (model: Model, real: Real) => {
        refreshModel(model, real);

        // Arrange

        const bitcoinHeightBefore = real.network.burnBlockHeight;
        const stacksHeightBefore = real.network.stacksBlockHeight;
        const calcHeight = rewardsCalculationHeight(model);
        const stxCycle = rewardsStxCycle(model);
        const active = sortedActiveBonds(model, calcHeight);
        const dropped = active[r.dropIndex % active.length];
        const bondPeriods = active.filter((b) => b !== dropped);
        const computeBefore = rov(
          real.contracts.pox5.getLastRewardComputeHeight(),
        );
        const accountedBefore = rov(
          real.contracts.pox5.getLastAccountedRewardsOnly(),
        );
        const rewardsBefore = rov(real.contracts.pox5.getRewards());
        const rptNoneBefore = rov(
          real.contracts.pox5.getRewardsPerTokenForCycle(stxCycle, null),
        );

        // Act

        const receipt = txErr(
          real.contracts.pox5.calculateRewards({ bondPeriods }),
          r.sender,
        );

        // Assert

        expect(receipt.value).toBe(errorCodes.ERR_ACTIVE_BOND_NOT_INCLUDED);
        expect(rov(real.contracts.pox5.getLastRewardComputeHeight())).toBe(
          computeBefore,
        );
        expect(rov(real.contracts.pox5.getLastAccountedRewardsOnly())).toBe(
          accountedBefore,
        );
        expect(rov(real.contracts.pox5.getRewards())).toBe(rewardsBefore);
        expect(
          rov(real.contracts.pox5.getRewardsPerTokenForCycle(stxCycle, null)),
        ).toBe(rptNoneBefore);

        logCommand({
          sender: getWalletNameByAddress(r.sender),
          action: 'calculate-rewards-err-active-bond-not-included',
          value: `dropped ${dropped}`,
          error: 'ERR_ACTIVE_BOND_NOT_INCLUDED',
          bitcoinHeightBefore,
          stacksHeightBefore,
        });
      },
      toString: () =>
        `calculate-rewards-err-active-bond-not-included(${getWalletNameByAddress(
          r.sender,
        )})`,
    }));
