import fc from 'fast-check';
import type { Model, Real } from './types';
import {
  getWalletNameByAddress,
  logCommand,
  refreshModel,
  rewardsCalculationHeight,
  rewardsStxCycle,
  sortedActiveBonds,
  trackCommandRun,
} from './utils';
import { rov, txErr } from '@clarigen/test';
import { errorCodes } from '../pox-5-helpers';
import { expect } from 'vitest';

/**
 * calculate-rewards with all active bonds present but in reversed order. The
 * inclusion check passes, then the distribution fold rejects the first
 * out-of-order bond with ERR_INVALID_BOND_PERIOD_ORDERING. The abort reverts
 * any per-bond writes the fold made first, so nothing mutates.
 */
export const CalculateRewardsErrInvalidOrdering = (
  accounts: Real['accounts'],
) =>
  fc
    .record({
      sender: fc.constantFrom(...Object.values(accounts).map((x) => x.address)),
    })
    .map((r) => ({
      // Two or more active bonds, so reversing their order always breaks the
      // ratio-descending, index-ascending rule.
      check: (model: Readonly<Model>) =>
        rewardsCalculationHeight(model) > model.lastRewardComputeHeight &&
        sortedActiveBonds(model, rewardsCalculationHeight(model)).length >= 2,
      run: (model: Model, real: Real) => {
        refreshModel(model, real);
        trackCommandRun(model, 'calculate-rewards_err_invalid_ordering');

        // Arrange

        const bitcoinHeightBefore = real.network.burnBlockHeight;
        const stacksHeightBefore = real.network.stacksBlockHeight;
        const calcHeight = rewardsCalculationHeight(model);
        const stxCycle = rewardsStxCycle(model);
        const bondPeriods = sortedActiveBonds(model, calcHeight).reverse();
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
        const rptFirstBefore = rov(
          real.contracts.pox5.getRewardsPerTokenForCycle(
            stxCycle,
            bondPeriods[0],
          ),
        );

        // Act

        const receipt = txErr(
          real.contracts.pox5.calculateRewards({ bondPeriods }),
          r.sender,
        );

        // Assert

        expect(receipt.value).toBe(errorCodes.ERR_INVALID_BOND_PERIOD_ORDERING);
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
        // The first bond's accumulator is written before the abort, so the
        // revert must leave it untouched.
        expect(
          rov(
            real.contracts.pox5.getRewardsPerTokenForCycle(
              stxCycle,
              bondPeriods[0],
            ),
          ),
        ).toBe(rptFirstBefore);

        logCommand({
          sender: getWalletNameByAddress(r.sender),
          action: 'calculate-rewards-err-invalid-ordering',
          error: 'ERR_INVALID_BOND_PERIOD_ORDERING',
          bitcoinHeightBefore,
          stacksHeightBefore,
        });
      },
      toString: () =>
        `calculate-rewards-err-invalid-ordering(${getWalletNameByAddress(
          r.sender,
        )})`,
    }));
