import fc from 'fast-check';
import type { Model, Real } from './types';
import {
  claimableNonePool,
  getWalletNameByAddress,
  logCommand,
  modelEarnedSigner,
  modelGetNewRewards,
  modelGetRewards,
  refreshModel,
  rptKey,
  signerRewardKey,
} from './utils';
import { rov, txOk } from '@clarigen/test';
import { sbtcBalance, testSignerHandle } from '../pox-5-helpers';
import { expect } from 'vitest';

/**
 * A signer manager claims its stx-staker pool rewards for a past cycle. Settles
 * the none pool with no bonds, pays the earned sBTC to the signer manager, and
 * snapshots its accumulator so the same cycle yields nothing until the next
 * distribution. Driven through the signer manager's claim-rewards wrapper, so
 * the contract sees the caller as the signer.
 */
export const ClaimRewards = (accounts: Real['accounts']) =>
  fc
    .record({
      caller: fc.constantFrom(...Object.values(accounts).map((x) => x.address)),
      pick: fc.nat(),
    })
    .map((r) => {
      let pickedSigner: string | undefined;
      let pickedCycle: bigint | undefined;
      return {
        // Some signer has a positive none-pool balance to claim.
        check: (model: Readonly<Model>) => claimableNonePool(model).length > 0,
        run: (model: Model, real: Real) => {
          refreshModel(model, real);

          // Arrange

          const bitcoinHeightBefore = real.network.burnBlockHeight;
          const stacksHeightBefore = real.network.stacksBlockHeight;
          const candidates = claimableNonePool(model);
          const { signer, cycle } = candidates[r.pick % candidates.length];
          pickedSigner = signer;
          pickedCycle = cycle;
          const key = signerRewardKey(cycle, null, signer);
          const rptNone =
            model.rewardsPerTokenForCycle.get(rptKey(cycle, null)) ?? 0n;
          const earned = modelEarnedSigner(model, signer, cycle, null);
          const signerSbtcBefore = sbtcBalance(signer);

          // Act

          const receipt = txOk(
            testSignerHandle(signer).claimRewards({
              bondPeriods: [],
              rewardCycle: cycle,
            }),
            r.caller,
          );

          // Update model

          model.signerRewardsPerTokenSettled.set(key, rptNone);
          model.signerRewardsPerTokenForCycle.set(key, rptNone);
          model.signerUnclaimedRewards.set(key, 0n);
          model.lastAccountedRewardsOnly -= earned;
          model.contractSbtcBalance -= earned;
          model.sbtcBalances.set(signer, signerSbtcBefore + earned);

          // Assert

          // Receipt: all of it is none-pool reward, no bonds.
          expect(receipt.value.totalRewards).toBe(earned);
          expect(receipt.value.stxRewards.earned).toBe(earned);
          expect(receipt.value.stxRewards.rewardsPerToken).toBe(rptNone);
          expect(receipt.value.bondTotals).toBe(0n);
          expect(receipt.value.bondRewards).toEqual([]);
          // The signer's none-pool snapshot now sits at the accumulator, and its
          // pending balance is zeroed.
          expect(
            rov(
              real.contracts.pox5.getSignerUnclaimedRewardsForCycle(
                signer,
                cycle,
                null,
              ),
            ),
          ).toBe(0n);
          expect(
            rov(
              real.contracts.pox5.getSignerRewardsPerTokenSettledForCycle(
                signer,
                cycle,
                null,
              ),
            ),
          ).toBe(rptNone);
          expect(
            rov(
              real.contracts.pox5.getSignerRewardsPerTokenForCycle(
                signer,
                cycle,
                null,
              ),
            ),
          ).toBe(rptNone);
          // sBTC moved from the contract to the signer manager.
          expect(sbtcBalance(signer)).toBe(signerSbtcBefore + earned);
          expect(rov(real.contracts.pox5.getRewards())).toBe(
            modelGetRewards(model),
          );
          expect(rov(real.contracts.pox5.getNewRewards())).toBe(
            modelGetNewRewards(model),
          );

          logCommand({
            sender: getWalletNameByAddress(r.caller),
            action: 'claim-rewards',
            value: `${signer.split('.').pop()} cycle ${cycle} earned ${earned}`,
            bitcoinHeightBefore,
            stacksHeightBefore,
          });
        },
        toString: () =>
          `claim-rewards(${pickedSigner?.split('.').pop() ?? '?'}, cycle ${
            pickedCycle ?? '?'
          })`,
      };
    });
