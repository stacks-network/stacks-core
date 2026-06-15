import fc from 'fast-check';
import type { Model, Real } from './types';
import {
  claimableStakerNone,
  getWalletNameByAddress,
  logCommand,
  modelEarnedStaker,
  refreshModel,
  signerRewardKey,
  stakerRewardKey,
  trackCommandRun,
} from './utils';
import { rov, txOk } from '@clarigen/test';
import { sbtcBalance, testSignerHandle } from '../pox-5-helpers';
import { expect } from 'vitest';

/**
 * A staker claims its share of a signer's already-claimed pool reward for a
 * cycle. Earns against the signer snapshot frozen when the signer claimed,
 * then the signer manager pays the staker in sBTC. Driven through the signer
 * manager's claim-staker-rewards wrapper, with the staker as tx-sender.
 */
export const ClaimStakerRewards = () =>
  fc
    .record({
      pick: fc.nat(),
    })
    .map((r) => {
      let pickedStaker: string | undefined;
      let pickedCycle: bigint | undefined;
      return {
        // Some staker has a positive balance under a signer that already
        // claimed and still holds the sBTC to pay it.
        check: (model: Readonly<Model>) =>
          claimableStakerNone(model).length > 0,
        run: (model: Model, real: Real) => {
          refreshModel(model, real);
          trackCommandRun(model, 'claim-staker-rewards');

          // Arrange

          const bitcoinHeightBefore = real.network.burnBlockHeight;
          const stacksHeightBefore = real.network.stacksBlockHeight;
          const candidates = claimableStakerNone(model);
          const { signer, cycle, staker } =
            candidates[r.pick % candidates.length];
          pickedStaker = staker;
          pickedCycle = cycle;
          const key = stakerRewardKey(cycle, null, signer, staker);
          const signerRpt =
            model.signerRewardsPerTokenForCycle.get(
              signerRewardKey(cycle, null, signer),
            ) ?? 0n;
          const earned = modelEarnedStaker(model, signer, cycle, null, staker);
          const stakerSbtcBefore = sbtcBalance(staker);
          const signerSbtcBefore = sbtcBalance(signer);

          // Act

          const receipt = txOk(
            testSignerHandle(signer).claimStakerRewards({
              rewardCycle: cycle,
              bondIndex: null,
            }),
            staker,
          );

          // Update model
          model.stakerRewardsPerTokenSettled.set(key, signerRpt);
          model.stakerUnclaimedRewards.set(key, 0n);
          model.sbtcBalances.set(signer, signerSbtcBefore - earned);
          model.sbtcBalances.set(staker, stakerSbtcBefore + earned);

          // Assert

          expect(receipt.value).toBe(earned);
          // The staker's snapshot now sits at the signer's, balance zeroed.
          expect(
            rov(
              real.contracts.pox5.getStakerUnclaimedRewardsForCycle(
                signer,
                cycle,
                null,
                staker,
              ),
            ),
          ).toBe(0n);
          expect(
            rov(
              real.contracts.pox5.getStakerRewardsPerTokenSettledForCycle(
                signer,
                cycle,
                null,
                staker,
              ),
            ),
          ).toBe(signerRpt);
          // sBTC moved from the signer manager to the staker.
          expect(sbtcBalance(staker)).toBe(stakerSbtcBefore + earned);
          expect(sbtcBalance(signer)).toBe(signerSbtcBefore - earned);

          logCommand({
            sender: getWalletNameByAddress(staker),
            action: 'claim-staker-rewards',
            value: `${signer.split('.').pop()} cycle ${cycle} earned ${earned}`,
            bitcoinHeightBefore,
            stacksHeightBefore,
          });
        },
        toString: () =>
          `claim-staker-rewards(${getWalletNameByAddress(
            pickedStaker ?? '?',
          )}, cycle ${pickedCycle ?? '?'})`,
      };
    });
