import fc from 'fast-check';
import type { Model, Real } from './types';
import {
  getWalletNameByAddress,
  logCommand,
  refreshModel,
  rewardsCalculationHeight,
  rewardsStxCycle,
} from './utils';
import { rov, txErr } from '@clarigen/test';
import { errorCodes } from '../pox-5-helpers';
import { expect } from 'vitest';

/**
 * calculate-rewards rerun within a distribution cycle whose rewards were
 * already computed. The snapshot height has not advanced past the last
 * compute, so the call reverts with ERR_DISTRIBUTION_ALREADY_COMPUTED before
 * touching any bond, and mutates nothing.
 */
export const CalculateRewardsErrAlreadyComputed = (
  accounts: Real['accounts'],
) =>
  fc
    .record({
      sender: fc.constantFrom(...Object.values(accounts).map((x) => x.address)),
    })
    .map((r) => ({
      // A distribution already ran at the current snapshot height; no new
      // half-cycle has closed to lift it.
      check: (model: Readonly<Model>) =>
        model.lastRewardComputeHeight > 0n &&
        rewardsCalculationHeight(model) <= model.lastRewardComputeHeight,
      run: (model: Model, real: Real) => {
        refreshModel(model, real);

        // Arrange

        const bitcoinHeightBefore = real.network.burnBlockHeight;
        const stacksHeightBefore = real.network.stacksBlockHeight;
        const stxCycle = rewardsStxCycle(model);
        const computeBefore = rov(
          real.contracts.pox5.getLastRewardComputeHeight(),
        );
        const accountedBefore = rov(
          real.contracts.pox5.getLastAccountedRewardsOnly(),
        );
        const rewardsBefore = rov(real.contracts.pox5.getRewards());
        const newRewardsBefore = rov(real.contracts.pox5.getNewRewards());
        const rptNoneBefore = rov(
          real.contracts.pox5.getRewardsPerTokenForCycle(stxCycle, null),
        );

        // Act

        const receipt = txErr(
          real.contracts.pox5.calculateRewards({ bondPeriods: [] }),
          r.sender,
        );

        // Assert

        expect(receipt.value).toBe(
          errorCodes.ERR_DISTRIBUTION_ALREADY_COMPUTED,
        );
        expect(rov(real.contracts.pox5.getLastRewardComputeHeight())).toBe(
          computeBefore,
        );
        expect(rov(real.contracts.pox5.getLastAccountedRewardsOnly())).toBe(
          accountedBefore,
        );
        expect(rov(real.contracts.pox5.getRewards())).toBe(rewardsBefore);
        expect(rov(real.contracts.pox5.getNewRewards())).toBe(newRewardsBefore);
        expect(
          rov(real.contracts.pox5.getRewardsPerTokenForCycle(stxCycle, null)),
        ).toBe(rptNoneBefore);

        logCommand({
          sender: getWalletNameByAddress(r.sender),
          action: 'calculate-rewards-err-already-computed',
          error: 'ERR_DISTRIBUTION_ALREADY_COMPUTED',
          bitcoinHeightBefore,
          stacksHeightBefore,
        });
      },
      toString: () =>
        `calculate-rewards-err-already-computed(${getWalletNameByAddress(
          r.sender,
        )})`,
    }));
