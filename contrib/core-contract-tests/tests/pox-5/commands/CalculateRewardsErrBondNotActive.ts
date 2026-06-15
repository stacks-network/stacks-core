import fc from 'fast-check';
import type { Model, Real } from './types';
import {
  activeBondsAtHeight,
  getWalletNameByAddress,
  logCommand,
  refreshModel,
  rewardsCalculationHeight,
  rewardsStxCycle,
  sortBondsForRewards,
  trackCommandRun,
} from './utils';
import { rov, txErr } from '@clarigen/test';
import { errorCodes } from '../pox-5-helpers';
import { expect } from 'vitest';

/**
 * calculate-rewards listing an existing bond that is not active at the
 * snapshot height, slotted into correct ratio order alongside the active
 * bonds. The inclusion and ordering checks pass, then the fold reaches the
 * inactive bond and reverts with ERR_BOND_NOT_ACTIVE. Its accumulator is
 * written just before the abort, so the revert must leave it untouched.
 */
export const CalculateRewardsErrBondNotActive = (accounts: Real['accounts']) =>
  fc
    .record({
      sender: fc.constantFrom(...Object.values(accounts).map((x) => x.address)),
      // Which set-up-but-inactive bond to wrongly include.
      bondPick: fc.nat(),
    })
    .map((r) => {
      const inactiveBonds = (model: Readonly<Model>, height: bigint) => {
        const active = new Set(activeBondsAtHeight(model, height));
        return [...model.bonds.keys()].filter((b) => !active.has(b));
      };
      return {
        // A new half-cycle has closed, some set-up bond is inactive now, and
        // fewer than six bonds are active. `bond-periods` is a `(list 6 uint)`,
        // so active plus the one wrong bond must still fit within six.
        check: (model: Readonly<Model>) => {
          const height = rewardsCalculationHeight(model);
          return (
            height > model.lastRewardComputeHeight &&
            activeBondsAtHeight(model, height).length < 6 &&
            inactiveBonds(model, height).length > 0
          );
        },
        run: (model: Model, real: Real) => {
          refreshModel(model, real);
          trackCommandRun(model, 'calculate-rewards_err_bond_not_active');

          // Arrange

          const bitcoinHeightBefore = real.network.burnBlockHeight;
          const stacksHeightBefore = real.network.stacksBlockHeight;
          const calcHeight = rewardsCalculationHeight(model);
          const stxCycle = rewardsStxCycle(model);
          const inactive = inactiveBonds(model, calcHeight);
          const wrongBond = inactive[r.bondPick % inactive.length];
          const bondPeriods = sortBondsForRewards(model, [
            ...activeBondsAtHeight(model, calcHeight),
            wrongBond,
          ]);
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
          const rptWrongBefore = rov(
            real.contracts.pox5.getRewardsPerTokenForCycle(stxCycle, wrongBond),
          );

          // Act

          const receipt = txErr(
            real.contracts.pox5.calculateRewards({ bondPeriods }),
            r.sender,
          );

          // Assert

          expect(receipt.value).toBe(errorCodes.ERR_BOND_NOT_ACTIVE);
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
          expect(
            rov(
              real.contracts.pox5.getRewardsPerTokenForCycle(
                stxCycle,
                wrongBond,
              ),
            ),
          ).toBe(rptWrongBefore);

          logCommand({
            sender: getWalletNameByAddress(r.sender),
            action: 'calculate-rewards-err-bond-not-active',
            value: `bond ${wrongBond}`,
            error: 'ERR_BOND_NOT_ACTIVE',
            bitcoinHeightBefore,
            stacksHeightBefore,
          });
        },
        toString: () =>
          `calculate-rewards-err-bond-not-active(${getWalletNameByAddress(
            r.sender,
          )})`,
      };
    });
