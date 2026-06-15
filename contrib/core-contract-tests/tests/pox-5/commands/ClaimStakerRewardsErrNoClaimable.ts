import fc from 'fast-check';
import type { Model, Real } from './types';
import {
  candidateSignerIds,
  currentRewardCycle,
  getWalletNameByAddress,
  logCommand,
  modelEarnedStaker,
  refreshModel,
  trackCommandRun,
} from './utils';
import { rov, txErr } from '@clarigen/test';
import {
  sbtcBalance,
  signerErrorCodes,
  testSignerHandle,
} from '../pox-5-helpers';
import { expect } from 'vitest';

/**
 * A staker claims a cycle where nothing is owed under a signer. The wrapper
 * settles, finds a zero balance, and reverts with ERR_NO_CLAIMABLE_REWARDS;
 * the revert undoes the inner settle, so nothing mutates.
 */
export const ClaimStakerRewardsErrNoClaimable = (accounts: Real['accounts']) =>
  fc
    .record({
      staker: fc.constantFrom(...Object.values(accounts).map((x) => x.address)),
      signer: fc.constantFrom(...candidateSignerIds),
    })
    .map((r) => ({
      // A deployed signer under which the staker has a zero none-pool balance
      // this cycle (true for almost every pair, since claimable state is rare).
      check: (model: Readonly<Model>) =>
        model.deployedSigners.has(r.signer) &&
        modelEarnedStaker(
          model,
          r.signer,
          currentRewardCycle(model),
          null,
          r.staker,
        ) === 0n,
      run: (model: Model, real: Real) => {
        refreshModel(model, real);
        trackCommandRun(model, 'claim-staker-rewards_err_no_claimable');

        // Arrange

        const bitcoinHeightBefore = real.network.burnBlockHeight;
        const stacksHeightBefore = real.network.stacksBlockHeight;
        const cycle = currentRewardCycle(model);
        const settledBefore = rov(
          real.contracts.pox5.getStakerRewardsPerTokenSettledForCycle(
            r.signer,
            cycle,
            null,
            r.staker,
          ),
        );
        const stakerSbtcBefore = sbtcBalance(r.staker);
        const signerSbtcBefore = sbtcBalance(r.signer);

        // Act

        const receipt = txErr(
          testSignerHandle(r.signer).claimStakerRewards({
            rewardCycle: cycle,
            bondIndex: null,
          }),
          r.staker,
        );

        // Assert

        expect(receipt.value).toBe(signerErrorCodes.ERR_NO_CLAIMABLE_REWARDS);
        expect(
          rov(
            real.contracts.pox5.getStakerRewardsPerTokenSettledForCycle(
              r.signer,
              cycle,
              null,
              r.staker,
            ),
          ),
        ).toBe(settledBefore);
        expect(sbtcBalance(r.staker)).toBe(stakerSbtcBefore);
        expect(sbtcBalance(r.signer)).toBe(signerSbtcBefore);

        logCommand({
          sender: getWalletNameByAddress(r.staker),
          action: 'claim-staker-rewards-err-no-claimable',
          value: `${r.signer.split('.').pop()} cycle ${cycle}`,
          error: 'ERR_NO_CLAIMABLE_REWARDS',
          bitcoinHeightBefore,
          stacksHeightBefore,
        });
      },
      toString: () =>
        `claim-staker-rewards-err-no-claimable(${getWalletNameByAddress(
          r.staker,
        )})`,
    }));
