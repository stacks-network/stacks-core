import fc from 'fast-check';
import type { Model, Real } from './types';
import {
  candidateSignerIds,
  currentRewardCycle,
  getWalletNameByAddress,
  logCommand,
  modelEarnedSigner,
  refreshModel,
  trackCommandRun,
} from './utils';
import { rov, txErr } from '@clarigen/test';
import { errorCodes, sbtcBalance, testSignerHandle } from '../pox-5-helpers';
import { expect } from 'vitest';

/**
 * A signer manager claims a cycle where nothing is owed. With no bonds listed
 * and a zero none-pool balance, the total is zero, so the call reverts with
 * ERR_NO_CLAIMABLE_REWARDS and mutates nothing.
 */
export const ClaimRewardsErrNoClaimable = (accounts: Real['accounts']) =>
  fc
    .record({
      caller: fc.constantFrom(...Object.values(accounts).map((x) => x.address)),
      signer: fc.constantFrom(...candidateSignerIds),
    })
    .map((r) => ({
      // A deployed signer whose none-pool balance at the current cycle is zero.
      check: (model: Readonly<Model>) =>
        model.deployedSigners.has(r.signer) &&
        modelEarnedSigner(model, r.signer, currentRewardCycle(model), null) ===
          0n,
      run: (model: Model, real: Real) => {
        refreshModel(model, real);
        trackCommandRun(model, 'claim-rewards_err_no_claimable');

        // Arrange

        const bitcoinHeightBefore = real.network.burnBlockHeight;
        const stacksHeightBefore = real.network.stacksBlockHeight;
        const cycle = currentRewardCycle(model);
        const settledBefore = rov(
          real.contracts.pox5.getSignerRewardsPerTokenSettledForCycle(
            r.signer,
            cycle,
            null,
          ),
        );
        const accountedBefore = rov(
          real.contracts.pox5.getLastAccountedRewardsOnly(),
        );
        const rewardsBefore = rov(real.contracts.pox5.getRewards());
        const signerSbtcBefore = sbtcBalance(r.signer);

        // Act

        const receipt = txErr(
          testSignerHandle(r.signer).claimRewards({
            bondPeriods: [],
            rewardCycle: cycle,
          }),
          r.caller,
        );

        // Assert

        expect(receipt.value).toBe(errorCodes.ERR_NO_CLAIMABLE_REWARDS);
        expect(
          rov(
            real.contracts.pox5.getSignerRewardsPerTokenSettledForCycle(
              r.signer,
              cycle,
              null,
            ),
          ),
        ).toBe(settledBefore);
        expect(rov(real.contracts.pox5.getLastAccountedRewardsOnly())).toBe(
          accountedBefore,
        );
        expect(rov(real.contracts.pox5.getRewards())).toBe(rewardsBefore);
        expect(sbtcBalance(r.signer)).toBe(signerSbtcBefore);

        logCommand({
          sender: getWalletNameByAddress(r.caller),
          action: 'claim-rewards-err-no-claimable',
          value: `${r.signer.split('.').pop()} cycle ${cycle}`,
          error: 'ERR_NO_CLAIMABLE_REWARDS',
          bitcoinHeightBefore,
          stacksHeightBefore,
        });
      },
      toString: () =>
        `claim-rewards-err-no-claimable(${r.signer.split('.').pop()})`,
    }));
